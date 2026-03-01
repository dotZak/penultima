# Python — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Python"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

CPython's compiler and runtime architecture is accurately described at the surface level by the council, but several technically significant gaps and a handful of factual imprecisions affect the depth and precision of the analysis. The three primary gaps are: (1) the tiered compilation architecture — bytecode interpreter → specializing adaptive interpreter → µop intermediate representation → copy-and-patch JIT — is described at a level that obscures why JIT gains are modest compared to PyPy and why this ceiling is unlikely to move dramatically in the near term; (2) the central role of C extension GIL release during computation is consistently underemphasized, distorting the actual impact of the GIL on Python's dominant use cases; and (3) PEP 683 (immortal objects, Python 3.12) and PEP 684 (per-interpreter GIL, Python 3.12) are entirely absent, omitting a significant concurrency development path that sits between the old GIL model and the fully free-threaded model.

The council's treatment of the free-threaded build (PEP 703) is directionally accurate but carries one unverified claim — the detractor's "~20% memory overhead" figure for the free-threaded build — that appears without a primary source and does not match the research brief's more conservative characterization. The performance benchmark data is generally accurate, but the JIT's architectural limitations (no cross-function inlining, no escape analysis, no integer unboxing) are not explained, leaving the council's performance section unable to account for the gap between current JIT gains (~5–8%) and PyPy's tracing JIT gains (2.8–18×). These gaps matter most for Section 12's design lessons: the story of why you cannot JIT a reference-counted dynamic object system to competitive performance without a major architectural commitment is the most important compiler-level lesson Python offers language designers, and the council only gestures at it.

The treatment of asyncio's runtime model is the strongest area — multiple council members accurately describe the colored-function problem, the selector-based event loop's inability to do truly non-blocking file I/O, and the adoption lag for structured concurrency. The detractor's reference to asyncio's P99 latency benchmark requires a methodological caveat (the 2020 Paterson data may not generalize to current runtimes), but the underlying mechanism described — event loop starvation from CPU-intensive coroutines — is technically correct.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- The reference counting + cyclic GC combination is correctly described by all five council members. The characterization of reference counting as providing deterministic destruction in the simple (non-cyclic) case is accurate [DEVGUIDE-GC].
- Per-object overhead figures (28 bytes for a Python `int` vs. 8 bytes for a C `int64`) are accurate and properly sourced [RESEARCH-BRIEF][DEVGUIDE-MEMORY].
- `obmalloc` as CPython's slab-allocator for small objects (≤512 bytes) and its consequence of holding freed memory in a private heap rather than returning it to the OS is correctly stated across the realist, practitioner, and detractor documents [DEVGUIDE-MEMORY].
- The connection between GIL existence and reference counting thread-safety is accurately stated by the realist: "The Global Interpreter Lock exists partly because CPython's reference counting is not thread-safe." This is the causal relationship, not a coincidence [PEP-703].
- Free-threaded single-threaded performance overhead (5–10% on x86-64 Linux, ~1% on macOS aarch64) is correctly cited by the apologist and realist [PYTHON-FREE-THREADING]. The research brief confirms these figures.

**Corrections needed:**

- **The detractor's memory overhead figure for the free-threaded build is unverified.** The detractor states the free-threaded build "carries a ~20% memory overhead versus the GIL build" without citing a primary source. The Python free-threading documentation acknowledges higher memory consumption from biased reference counting's per-thread structures, but no publicly available pyperformance or CPython benchmark result documents a 20% memory increase as a reliable baseline. The apologist's and realist's texts omit this figure entirely. Without a source, this claim should not survive to the consensus report.

- **The cyclic GC's generational structure is understated.** All council members describe the cyclic GC as "supplemental" but do not mention that it was reorganized in Python 3.12 to include a "permanent generation" for immortal objects (PEP 683). The research brief describes the GC as "4 generations (1 young + 2 old + 1 permanent)" [RESEARCH-BRIEF], reflecting the immortalization update. Omitting this conflates the Python 3.11-and-earlier GC model with the current model.

**Additional context:**

**Object immortalization (PEP 683, Python 3.12) is central to free-threading and missing from the council's analysis.** Before PEP 703 could be implemented, PEP 683 was required: it introduced a mechanism for marking Python objects as "immortal," meaning their reference counts are never modified. Immortal objects include small integers (−5 through 256), `None`, `True`, `False`, and interned strings. Because immortal objects' reference counts never change, threads never need to write-coordinate around them, eliminating the most frequent source of reference count contention in a concurrent Python program. Without immortalization, the free-threaded reference counting scheme would produce cache coherence traffic on every attribute access. The biased reference counting approach in PEP 703 builds directly on PEP 683's foundation: each thread can modify its own "biased" copy of a reference count without acquiring a cross-thread lock, with periodic synchronization only for objects accessed from multiple threads. This architecture is why the single-threaded overhead is 5–10% rather than 20–40% (the penalty measured for earlier naive fine-grained locking attempts) [PEP-703].

The council describes the free-threading technical approach — biased reference counting, immortalization, deferred reference counting — but does so without explaining *why* each technique is necessary or how they compose. For language design purposes, the lesson is that removing a pervasive global lock from a reference-counted object system requires co-designing three separate mechanisms simultaneously; any single technique in isolation is insufficient.

**Memory fragmentation and long-lived process behavior** is a runtime consequence that the practitioner correctly identifies but that deserves explicit compiler-level annotation: CPython's `obmalloc` arena structure means that memory freed by the GC does not become available for reuse by non-Python allocations (e.g., native libraries loaded after a large Python allocation) and may not return to the OS even after the Python object graph shrinks significantly. This is not a bug — it is a deliberate trade-off for allocation speed — but it has production implications for long-running services that need predictable memory footprint [DEVGUIDE-MEMORY].

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- The tripartite concurrency model (threading/asyncio/multiprocessing) and its workload-specific applicability is accurately described by the practitioner and realist. Each model is correctly characterized for its appropriate use case.
- The GIL's release during I/O operations enabling effective I/O-bound threading is correctly stated across multiple council members.
- The "colored function" problem for async/await — that async functions cannot be called from sync contexts without bridging — is technically accurate and properly attributed to the fundamental property of cooperative scheduling.
- The free-threaded adoption barrier — only ~17% of top PyPI packages with C extension modules provided free-threaded wheels as of mid-2025, causing silent GIL re-enablement — is accurately cited from the Python Language Summit [PYFOUND-FREETHREADED-2025].
- asyncio's `TaskGroup` arriving in Python 3.11 as structured concurrency, five years after `trio`'s nursery model, is accurately documented [PYTHON-311-RELEASE].
- The detractor's citation of David Beazley's 2010 demonstration of GIL contention producing 2× *slowdown* (not speedup) on a quad-core machine for a CPU-bound workload is an accurate and important historical data point [BEAZLEY-GIL-2010].

**Corrections needed:**

- **asyncio's file I/O limitation requires mechanism clarification.** The detractor correctly states that "asyncio does not support asynchronous filesystem I/O" and that `io_uring` has been available since 2019. This is accurate, but the mechanism is understated in a way that could mislead. asyncio's event loop is selector-based (using `epoll`/`kqueue`/`select`), which works for sockets, pipes, and other file-descriptor-based I/O that the OS can report as "ready" without blocking. Regular filesystem files are always considered "ready" by the OS, so `asyncio` cannot do truly non-blocking file reads using the selector mechanism. The actual implementation uses `ThreadPoolExecutor` to offload file I/O to threads that block, then signals completion back to the event loop — a functional workaround, not a genuine async I/O path. `io_uring`'s availability since 2019 makes this a design choice, not an OS constraint, as of that date. No council member explains the selector-based architecture that produces this limitation.

- **The Cal Paterson async P99 benchmark requires methodological context.** The detractor cites "sync frameworks achieved 31–42ms P99, while async frameworks showed 75–364ms P99" [PATERSON-ASYNC-2020]. This is from a 2020 benchmark. The underlying mechanism — event loop starvation by CPU-intensive coroutines between `await` points — is real and correctly identified. However, the specific numbers are from 2020 and predate `asyncio.TaskGroup` (3.11), the 25% speedup in 3.11, and the uvloop performance improvements. The mechanism claim stands; the specific numbers should not be presented as current without noting the vintage.

- **The apologist's claim that "colored functions" apply equally to Kotlin coroutines is imprecise.** The claim that "the colored function criticism applies to JavaScript Promises, Kotlin coroutines, and Rust's async/await" is directionally correct but Kotlin is a borderline case: Kotlin coroutines can be transparently dispatched on the JVM thread pool without explicit color annotation at the call site for most common patterns, and kotlinx.coroutines' `runBlocking` bridge is more ergonomic than Python's equivalent. This does not invalidate the core point about cooperative scheduling, but the council should not present Kotlin as an equivalent case.

**Additional context:**

**PEP 684 (per-interpreter GIL, Python 3.12) is missing entirely from all council documents.** PEP 684 introduced a per-interpreter GIL, allowing multiple sub-interpreters within a single Python process to run in parallel on separate threads, each with their own GIL. Python 3.13 made this accessible via the `concurrent.interpreters` module (PEP 734). This is a third path between the original single-GIL model and the fully free-threaded model: it provides CPU-bound parallelism with lower per-worker overhead than `multiprocessing` (no process fork, shared memory without serialization overhead for Python objects that are immutable), while not requiring C extensions to be thread-safe [PEP-684]. The practical limitation — sub-interpreters cannot share mutable Python objects directly — is real, but for workloads where data is immutable or naturally partitioned (parallel data processing, web request handling), this is a viable path. No council member mentions it, which understates Python's concurrency options as of Python 3.13.

**C extension GIL release during computation is the most underemphasized runtime behavior in the council.** The single most important mitigating fact about the GIL for Python's actual dominant use cases — scientific computing and ML — is that C extensions release the GIL during long-running computation. NumPy matrix operations, SciPy algorithms, and PyTorch tensor operations all release the GIL before entering their compute loops and reacquire it only when returning to Python. This means that in a typical ML training workload, Python threads *can* achieve parallel CPU utilization for the heavy computation, because the computation runs outside the GIL. The GIL's constraint is on *Python bytecode execution*, not on C extension execution. The council's framing — that the GIL "prevents more than one thread from executing Python bytecode at a time" — is technically accurate but practically misleading for understanding Python's ML performance profile, where the bytecode fraction of execution time is small.

**The asyncio executor model for blocking operations** — `asyncio.to_thread()` and `loop.run_in_executor()` — is described by the practitioner but not analyzed at the runtime level. These APIs offload a callable to a thread pool and await the result, allowing the event loop to continue processing other coroutines. The runtime implication: each such call acquires the GIL on the thread pool thread, which means that CPU-intensive work offloaded this way is still subject to GIL serialization with other Python-level computation. The only GIL-free path for CPU-intensive work in async Python remains C extensions that release the GIL before computation. This architectural interaction between asyncio, thread pools, and the GIL is not described by any council member.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- The CLBG benchmark comparison figures (up to ~90× slower than Java, ~44-90× range across different benchmarks) are drawn from published Computer Language Benchmarks Game data and are accurate for CPython executing pure Python code [CLBG].
- The pyperformance cumulative improvement figure (50–60% from Python 3.10 to 3.14) is accurate and correctly sourced from CPython release notes [PYTHON-311-RELEASE][PYTHON-312-RELEASE][PYTHON-313-RELEASE][PYTHON-314-RELEASE].
- The JIT compiler (PEP 744) using a copy-and-patch technique is accurately described. The characterization of 5–8% gains from the JIT is accurate per available data [PEP-744][PYTHON-314-RELEASE].
- PyPy's 2.8–18× speedup over CPython on CPU-bound benchmarks, with its C extension compatibility trade-off, is accurately stated [PYPY-PERFORMANCE].
- CPython startup time of 20–50ms for a bare invocation is accurate per the research brief [RESEARCH-BRIEF].
- The argument that web workloads are I/O-bound and thus less affected by CPython's per-bytecode overhead is structurally correct and consistently well-articulated by the realist and practitioner.

**Corrections needed:**

- **The Faster CPython "2–5× goal" framing needs precision.** The detractor presents the 50–60% cumulative improvement as "below the stated goal" of 2–5×. This framing requires clarification: the stated goal in Microsoft's announcement was 2× over five years [MS-FASTER-CPYTHON], and the team appears to be approximately on track through 2025 (1.5–1.6× after four years). Some individual Python 3.11 benchmarks already showed 2× improvement for specific workloads (e.g., function call-heavy code). Presenting the project as missing its goal is misleading if the multi-year trajectory is considered. The council should state that the project is at the lower bound of its goal range as of 2025 without implying failure.

- **The detractor's "Grinberg found the JIT produced no significant performance gains for recursive code" requires context.** This is an accurate reference to a specific benchmark [GRINBERG-PY314-2025], but it needs a mechanism explanation: the copy-and-patch JIT's current architecture does not unbox Python integers into machine integers, which means recursive computations over Python integers (like Fibonacci) do not benefit from JIT because the bottleneck is the boxing/unboxing overhead the JIT cannot eliminate. This is a specific architectural limitation, not evidence that the JIT is broadly ineffective. The council should distinguish between "JIT does not help for integer-boxing-bottlenecked workloads" and "JIT does not help" — the latter is false.

- **PyPy's startup overhead is unaddressed by the council.** The apologist correctly notes PyPy's 2.8–18× speedup but does not mention that PyPy has *significantly higher* startup time than CPython due to JIT warmup overhead. The research brief explicitly notes: "PyPy startup time: Significantly higher than CPython (JIT warmup overhead), making PyPy less suited for short-lived scripts" [RESEARCH-BRIEF]. This is material because it means PyPy is not a viable alternative for serverless/short-lived invocations — the exact context where CPython's own startup time is a bottleneck. The council's performance treatment should explicitly note this constraint.

**Additional context:**

**The tiered compilation architecture is the key to understanding why CPython's JIT gains are modest and why the ceiling exists.** CPython 3.13–3.14's execution path involves three tiers:
1. **Tier 1 (specializing adaptive interpreter):** PEP 659's bytecode specialization tracks type information at runtime and replaces polymorphic bytecode instructions with type-specific fast paths (e.g., `LOAD_ATTR` becomes `LOAD_ATTR_MODULE` when the attribute is on a known module). This is where the bulk of the 25% Python 3.11 speedup came from.
2. **Tier 2 (µop IR):** Hot tier-1 traces are translated into a lower-level intermediate representation of micro-operations, enabling optimization passes that bytecode cannot express.
3. **Tier 3 (copy-and-patch JIT):** The µop trace is compiled to native code by copying pre-compiled machine code templates for each µop and patching addresses and values at runtime [PEP-744].

The architectural ceiling is at tier 1 and 2: the specializing interpreter cannot *infer* types — it can only observe them and speculate. When type speculation fails (a "deoptimization"), the interpreter falls back to the generic bytecode path. More fundamentally, **CPython's object model requires that every Python object remain a Python object**: integers cannot be unboxed into machine integers across call boundaries without breaking Python's semantics (an `int` must behave like a Python `int` everywhere). This prevents the class of optimization that makes V8, LuaJIT, and PyPy fast — replacing Python object operations with primitive machine operations. Until Python adds a mechanism (e.g., JIT-internal unboxing with escape analysis) to prove that an integer will not escape as a Python object, the JIT cannot eliminate boxing overhead for numeric computation. None of the council members explain this architectural constraint, which is why the "why does the JIT achieve only 5–8%?" question is left unanswered.

**PyPy's tracing JIT can outperform CPython's copy-and-patch JIT because it does cross-function inlining and escape analysis.** PyPy's JIT observes entire execution traces, including function call sequences, and can inline callees into the trace. It can prove that an intermediate `int` result is never exposed as a Python object and represent it as an unboxed C integer. CPython's current JIT operates within a single trace segment without cross-function inlining. This is a principled architectural difference, not a maturity gap: the copy-and-patch technique is explicitly designed to avoid a runtime LLVM dependency (which would increase startup time and binary size), trading optimization depth for deployment simplicity [PEP-744]. Whether this trade-off was correct is a legitimate language design question the council does not engage with.

**The pyperformance benchmark suite's composition affects interpretation of improvement numbers.** The pyperformance suite is heavily weighted toward "real-world Python programs" (JSON parsing, template rendering, regex) as opposed to algorithmic benchmarks (n-body, spectral norm). A 50–60% improvement on pyperformance may imply a smaller improvement on compute-intensive workloads and a larger improvement on I/O-structured ones. The council should note that the CLBG benchmarks (showing 44–90× slowdowns) measure algorithmic computation while pyperformance measures workflow throughput — they are not contradictory but they measure different things.

---

### Other Sections (Compiler/Runtime-Relevant Issues)

**Section 2 (Type System) — Annotation evaluation semantics are a runtime concern:**

The historian and detractor correctly document the PEP 563 reversal. An important compiler/runtime dimension missing from the analysis: PEP 563's `from __future__ import annotations` changed annotation evaluation from *eager* (annotations evaluated at import time, producing Python objects) to *lazy* (annotations stored as string literals). This change broke libraries that used `typing.get_type_hints()` for runtime annotation inspection, because the string literals required a `globalns`/`localns` resolution context to evaluate. PEP 649, the accepted replacement, uses a different mechanism: annotations are stored as *descriptor objects* that evaluate lazily on first access, preserving both forward reference resolution and runtime annotation access. The runtime implication — that annotation evaluation now involves a descriptor protocol call rather than a direct attribute access — is not discussed by the council. For language designers, this illustrates that any annotation system used at both static-check time and runtime must specify the runtime semantics carefully; an omission here becomes a behavioral contract violation downstream.

**Section 10 (Interoperability) — The C extension ABI instability:**

The detractor and practitioner correctly identify the C extension compatibility challenge for free-threaded CPython. An additional technical nuance: CPython's C extension API has two variants — the "stable ABI" (PEP 384), which provides a subset of the API with a guaranteed compatibility window across multiple Python versions, and the full API, which may change between minor versions. Most performance-critical extensions (NumPy, Pandas) use the full API because the stable ABI's limited type access prevents the optimizations they require. This means that PyPI binary wheel distributions must be built per-Python-version (e.g., `cp311-`, `cp312-`, `cp313-`), contributing to the supply chain and distribution complexity the council's ecosystem section discusses. The free-threaded build adds a second dimension to this matrix (`cp313t-` for free-threaded builds), multiplying the build matrix.

**Section 2 (Type System) — Type checking is not compiler enforcement:**

The apologist's framing that Python's type system "provides safety guarantees" is imprecise from a runtime perspective. Python's type annotations are not enforced by CPython at runtime. A function annotated `def f(x: int) -> str:` will accept any Python object as `x` and return any Python object as its value; the annotations are metadata, not contracts. Type checking is performed entirely by external tools (mypy, pyright) at development time, not by CPython at execution time. The `beartype` and `typeguard` libraries optionally add runtime enforcement, but these are opt-in additions, not part of CPython's standard execution path. Any claim that Python's type annotations "prevent" type errors at runtime — rather than at type-check time — should be corrected in the consensus report.

---

## Implications for Language Design

**1. Reference-counted dynamic object systems have a hard ceiling for JIT optimization that requires architectural commitment to overcome.**

CPython's experience demonstrates that a reference-counted object system with dynamic types is difficult to JIT-compile to competitive performance because the JIT cannot legally unbox objects without escape analysis, and the reference count protocol prevents many standard alias analysis techniques. PyPy addresses this by building its JIT from scratch over an object model designed for JIT friendliness (RPython). CPython's approach of layering a JIT on an existing C implementation achieves modest gains (5–8%) rather than transformative ones (2–18×). Language designers who require high-performance CPU-bound execution should design their object representation with JIT-ability in mind from the start — either by using value types that can be unboxed, or by designing a reference counting protocol that permits deferred updates (as PEP 703 does with biased reference counting). Retrofitting a JIT onto an object model designed for interpreted execution is an order-of-magnitude harder than designing for JIT from the start.

**2. Removing a pervasive global lock from a reference-counted system requires co-designing multiple techniques simultaneously, not just removing the lock.**

CPython's GIL removal required three co-designed mechanisms: immortalization (PEP 683) to eliminate reference count traffic for common objects, biased reference counting (PEP 703) to allow per-thread reference count updates without cross-thread synchronization, and deferred reference counting to batch GIL-independent reference count updates. Each mechanism is insufficient without the others. Language designers implementing reference counting in a concurrent context should treat these mechanisms as a package, not as incremental additions. The 25-year timeline between identifying the GIL as a problem and resolving it reflects both the genuine difficulty of this co-design challenge and the organizational difficulty of making a change that required touching nearly every part of the runtime.

**3. A selector-based async event loop cannot do truly non-blocking file I/O on Linux; this is an architectural commitment with a decade-long ecosystem consequence.**

asyncio's event loop uses `epoll`/`kqueue` selectors, which work for sockets and pipes but not regular files (which the OS always reports as ready). This means any async program that does file I/O must use thread pools for it, creating a hybrid async/thread execution model that is more complex than either pure async or pure threads. `io_uring` on Linux provides a genuine async I/O submission API that could address this, but retrofitting asyncio to use `io_uring` would require changes across the event loop internals. Language designers building async I/O systems should choose between a selector-based model (simple, portable, excludes file I/O) and a submission-queue-based model (`io_uring` on Linux, IOCP on Windows) at design time; mixing them produces operational complexity. This decision should be explicit, not implicit.

**4. Per-interpreter parallelism (PEP 684) as a middle path between GIL and full free-threading reveals a design principle for concurrent runtime design.**

CPython's per-interpreter GIL (PEP 684) demonstrates a middle path that language designers often overlook: rather than a single global lock or full shared-memory threading, sub-interpreter isolation (each interpreter with its own GIL and heap) enables CPU-bound parallelism for workloads that are naturally data-parallel without requiring full thread-safety of the object model. The trade-off — sub-interpreters cannot share mutable objects — is appropriate for many real workloads (request handling, data transformation, ML inference). This pattern generalizes: for concurrent systems with high isolation requirements, multiple separate runtimes within a process may be more appropriate than shared-state threading, and the language runtime should be designed to support this from the start.

**5. The tiered interpreter/JIT architecture (specializing → µops → native) is a viable path to incremental performance improvement for an existing bytecode VM, with explicit optimization ceilings at each tier.**

CPython's three-tier architecture (PEP 659 specialization → µop IR → PEP 744 JIT) demonstrates how a mature bytecode VM can be incrementally evolved toward JIT compilation without a full rewrite. This architecture provides clear performance gains at each tier (bulk of gains from tier 1 specialization, incremental from tier 2/3) and allows each tier to be shipped independently. The tradeoff is that the highest optimization gains (cross-function inlining, escape analysis, integer unboxing) require capabilities that only tier 3 can provide, and those capabilities are architecturally blocked by the object model. Language designers should understand which performance tier their language will rely on, and ensure the object model does not structurally prevent that tier's key optimizations.

**6. The ecosystem's C extension dependency creates a long-tail adoption barrier for any runtime improvement that changes the calling convention.**

The free-threaded build's adoption challenge — 83% of top PyPI extensions without free-threaded wheels 12 months after the feature shipped — demonstrates that any runtime improvement requiring C extension changes will face multi-year ecosystem lag. The bottleneck is the long tail of extensions that are maintained by small teams without resources to rebuild and validate for a new runtime mode. Language designers should design runtime improvements to be backward-compatible with existing extension binaries where possible, or provide automated tools to update extensions. Changes that require manual audit and reconstruction will propagate slowly in large package ecosystems regardless of their technical quality.

---

## References

[DEVGUIDE-GC] Python Developer's Guide. "Garbage Collector Design." https://devguide.python.org/internals/garbage-collector/

[DEVGUIDE-MEMORY] Python Developer's Guide. "Memory Management." https://devguide.python.org/internals/memory-management/

[PEP-659] Shannon, M. "PEP 659 – Specializing Adaptive Interpreter." https://peps.python.org/pep-0659/

[PEP-683] Shannon, M. "PEP 683 – Immortal Objects." https://peps.python.org/pep-0683/

[PEP-684] Wang, E., Shannon, M. "PEP 684 – A Per-Interpreter GIL." https://peps.python.org/pep-0684/

[PEP-703] Shannon, M. "PEP 703 – Making the Global Interpreter Lock Optional in CPython." Accepted 2023. https://peps.python.org/pep-0703/

[PEP-734] Wang, E. "PEP 734 – Multiple Interpreters in the stdlib." https://peps.python.org/pep-0734/

[PEP-744] Coppola, B. "PEP 744 – JIT Compilation." https://peps.python.org/pep-0744/

[PEP-779] "PEP 779 – Criteria for supported status for free-threaded Python." https://peps.python.org/pep-0779/

[PEP-384] Loewis, M. "PEP 384 – Defining a Stable ABI." https://peps.python.org/pep-0384/

[PEP-649] Hastings, L. "PEP 649 – Deferred Evaluation Of Annotations Using Descriptors." https://peps.python.org/pep-0649/

[PYTHON-FREE-THREADING] Python Documentation. "Python support for free threading." https://docs.python.org/3/howto/free-threading-python.html

[PYTHON-311-RELEASE] Python Software Foundation. "What's New In Python 3.11." https://docs.python.org/3/whatsnew/3.11.html

[PYTHON-312-RELEASE] Python Software Foundation. "What's New In Python 3.12." https://docs.python.org/3/whatsnew/3.12.html

[PYTHON-313-RELEASE] Python Software Foundation. "What's New In Python 3.13." https://docs.python.org/3/whatsnew/3.13.html

[PYTHON-314-RELEASE] Python Software Foundation. "What's New In Python 3.14." https://docs.python.org/3/whatsnew/3.14.html

[MS-FASTER-CPYTHON] Microsoft. "A Team at Microsoft is Helping Make Python Faster." October 2022. https://devblogs.microsoft.com/python/python-311-faster-cpython-team/

[PYPY-PERFORMANCE] PyPy Project. "Performance." https://www.pypy.org/performance.html

[CLBG] Computer Language Benchmarks Game. https://benchmarksgame-team.pages.debian.net/benchmarksgame/

[PYFOUND-FREETHREADED-2025] Python Software Foundation / Python Language Summit. "Free-threaded Python adoption status." Python Language Summit, June 2025.

[BEAZLEY-GIL-2010] Beazley, D. "Understanding the Python GIL." PyCon 2010. https://www.dabeaz.com/python/UnderstandingGIL.pdf

[NYSTROM-COLORS-2015] Nystrom, B. "What Color is Your Function?" Bob Nystrom's Blog, 2015. https://journal.stuffwithstuff.com/2015/02/26/color-your-functions/

[GRINBERG-PY314-2025] Grinberg, M. "Python 3.14 Benchmark Analysis." 2025.

[PATERSON-ASYNC-2020] Paterson, C. "Async Python is not faster." Cal Paterson's Blog, 2020.

[RESEARCH-BRIEF] "Python — Research Brief." Penultima project. research/tier1/python/research-brief.md, 2026-02-27.
