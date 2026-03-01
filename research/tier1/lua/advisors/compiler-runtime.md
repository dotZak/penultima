# Lua — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Lua"
agent: "claude-agent"
date: "2026-02-28"
```

---

## Summary

The five council perspectives on Lua are broadly technically accurate, but several important qualifications are warranted. The most significant area requiring correction concerns the GC incremental model: multiple council members describe Lua as having an "incremental garbage collector since 5.1," which is true but misleading — only the *minor* collection cycle was incremental before Lua 5.5; *major* cycles remained stop-the-world through 5.4. The full incremental model arrived only in Lua 5.5 (December 2025) and this distinction matters substantially for real-time applications. Several other runtime-level subtleties — particularly the `pcall`/`longjmp` incompatibility with C++ RAII, the precise scope of LuaJIT's FFI performance benefit, and the bounded applicability of the "coroutines eliminate data races" claim — deserve clarification.

The council's performance narrative is largely correct but needs one important structural note: the Computer Language Benchmarks Game (CLBG) excludes LuaJIT, so the "five slowest interpreted languages" characterization applies only to PUC-Lua and should not be interpreted as characterizing Lua's full performance range. The LuaJIT benchmarks place Lua in an entirely different performance category. This is not a minor technical footnote — it is the central runtime design tension in the Lua ecosystem: two implementations with significantly different performance characteristics and different language-version compatibility, with no convergence path.

The council's treatment of coroutines is accurate about what they do but occasionally conflates the Lua primitive with the OpenResty deployment architecture built on top of it. Standard PUC-Lua without a non-blocking I/O event loop provides cooperative concurrency but not scalable concurrency. That distinction has implications for how language designers should interpret Lua as a data point.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **Tri-color mark-and-sweep algorithm**: Confirmed by the reference manual and the implementation paper [LUA5-IMPL]. The tri-color marking (white/gray/black) is what enables incremental collection — the mutator and collector can interleave because the invariant is maintained across interruptions.

- **Generational GC history**: All five council members accurately recount the generational GC trajectory: added experimentally in 5.2, removed in 5.3 (identified as having poor performance characteristics under certain allocation patterns), reintroduced in a corrected form in 5.4 [LWN-5.4]. This is one of the few areas where the Lua team demonstrably reversed course based on empirical evidence, and the council correctly identifies it as such.

- **To-be-closed variables (`<close>`, 5.4+)**: The `<close>` attribute on local variables, triggering the `__close` metamethod on scope exit (including error exits via `pcall`), is accurately described. This is a genuine RAII mechanism at the Lua level [LWN-5.4].

- **Pure Lua memory safety**: Pure Lua code (not embedding or extension code) is memory-safe by construction. There is no pointer arithmetic, no buffer allocation accessible from Lua-level code, and no way to create dangling references through Lua operations. The CVEs in the research brief are all in the C implementation (parser, GC internals, runtime functions), not in the Lua language model.

- **Binary footprint**: The approximately 278 KB (complete Lua 5.4 with stdlib) and under 150 KB (core only) figures from [LTN001] are credible and consistent with the design mandate.

**Corrections needed:**

- **The "incremental GC since 5.1" precision problem**: Multiple council members state or imply that Lua has had a fully incremental GC since version 5.1. This is imprecise in a way that matters for real-time applications. What Lua 5.1 introduced was an incremental *minor* collection cycle — the collector runs in small steps interleaved with program execution, advancing through the tri-color traversal across multiple mutator steps. However, *major* collection cycles (the full tri-color sweep of the entire heap) were **stop-the-world through Lua 5.4**. The Lua 5.5 release notes document explicitly that "incremental major garbage collections" are new in 5.5 [PHORONIX-5.5, LUA-MANUAL-5.5]. Game studios managing GC during frame boundaries were therefore managing a partially-incremental collector for much of Lua's history — the long pauses they encounter in production are major cycles, not minor ones. Council members presenting Lua 5.1-era GC as fully incremental overstate the guarantee.

- **C++ embedding and `pcall`/`longjmp` incompatibility**: The detractor mentions this; the other council members do not, despite it being a genuine implementation-level correctness hazard. The `lua_pcall` C API function uses `longjmp` (or `setjmp`/`longjmp`) to implement Lua's error-catching mechanism when compiled for C. When Lua is embedded in C++ code, `longjmp` bypasses C++ stack unwinding, meaning destructors for C++ objects allocated between the `lua_pcall` callsite and the error site are not invoked. The result is that RAII resources managed by C++ (file handles, mutex locks, smart pointers) can leak when a Lua error propagates through C++ code. The correct mitigation is to compile Lua as C++ (using `luaconf.h`'s `LUAI_THROW`/`LUAI_TRY` macros) or to wrap all `lua_call` sites in C++ `try`/`catch`. This is well-known in the embedding community but represents a real correctness concern that none of the apologist, realist, historian, or practitioner perspectives flag explicitly.

- **String interning memory implications**: The research brief correctly notes that all Lua strings are interned, enabling O(1) equality. What none of the council members note is the memory implication: the intern table holds references to every distinct string in the program, preventing GC of strings as long as any live string with the same content exists. In workloads generating many unique string keys (e.g., log processing, template rendering with unique identifiers), the intern table can grow substantially. This is a runtime tradeoff that language designers should be aware of when evaluating Lua's string model.

**Additional context:**

- **Finalizer execution timing**: Several council members describe `__gc` metamethods as being "called before reclamation." More precisely, `__gc` is called in the *next* GC cycle after the object becomes unreachable, not immediately. An object found unreachable in cycle N has its finalizer called during cycle N+1, and the object is actually reclaimed in cycle N+2. This two-cycle lag is required by the tri-color invariant and means finalizers should not rely on external resources being available promptly after last reference release.

- **`collectgarbage()` API and control granularity**: The three-parameter GC control interface (pause, step-multiplier, step-size) is documented in the reference manual [LUA-MANUAL-5.4] but has no ergonomic tooling equivalent to the JVM's GC logging or GC analyzers. The parameters are expressed in percentages and relative units that require empirical tuning rather than first-principles calculation. The detractor's characterization of them as "opaque knobs" is fair in the sense that there is no widely-used profiling workflow analogous to JVM GC analysis.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **One coroutine executes at a time**: Correct. The Lua VM has no preemption mechanism; a coroutine runs until it explicitly calls `coroutine.yield()`, encounters I/O that yields it through framework infrastructure, or finishes. There is no OS-level threading behind coroutines.

- **No shared Lua heap across Lua states**: When multiple Lua states are created (one per OS thread), they have fully independent heaps. Lua values (tables, strings, functions, closures, coroutines) cannot be passed between states; communication requires marshaling through C or serialization. The "share nothing" model is a deliberate design choice consistent with the embedding philosophy.

- **Multiple Lua states eliminate data races by design**: For the specific case of multiple Lua states in separate OS threads, this is accurate. There is no mechanism to create a Lua-level data race between them because there is no shared Lua state.

- **OpenResty architecture**: The characterization of OpenResty's request-per-coroutine model — each HTTP request mapped to a coroutine, I/O yields to Nginx's event loop — is accurate [OR-DOCS]. The model produces high concurrency for I/O-bound workloads without OS-thread overhead.

- **`coroutine.close()` in 5.4**: Accurate. Added in 5.4 to force-close suspended coroutines and trigger associated `__close` metamethods [LWN-5.4].

**Corrections needed:**

- **"Coroutines eliminate data races by construction" — scope limitation**: The apologist and practitioner perspectives express that Lua's coroutine model eliminates data races. This is accurate *within a single Lua state*, where only one coroutine runs at a time. But applications running multiple Lua states in separate OS threads can have races in:
  - Shared C-level global state (C extensions that do not protect globals)
  - Shared C data structures accessed by C functions callable from multiple states
  - The Lua allocator if a custom allocator is shared without synchronization

  Pure Lua code with a single state has no races by construction. The broader claim requires qualification.

- **"Cannot yield across C boundary" — underemphasized**: Multiple council members correctly note that coroutines cannot yield across C API calls that don't support yielding. This is more significant than the council acknowledges. Any C function registered as a Lua C function (using the `lua_CFunction` signature) cannot use `coroutine.yield()` in the standard form — it must use the `lua_yieldk` continuation mechanism (added in Lua 5.2) if it wants to be yieldable. This means that a large proportion of Lua C extensions — those written before 5.2 or those that do not explicitly implement continuations — are non-yieldable, which blocks use of coroutines across those function boundaries. In OpenResty, this is managed by the `lua-resty-*` library ecosystem, which wraps blocking system calls in yieldable form. But a standard PUC-Lua program calling any blocking I/O through an old C binding cannot yield cooperatively. The practitioner notes this as "colored coroutines" but the full runtime implication (that the yieldability constraint propagates through the entire call stack) deserves explicit treatment.

- **OpenResty scalability is architecture, not intrinsic Lua**: The detractor correctly identifies this. A PUC-Lua coroutine executing `io.read()` blocks the entire OS thread for the duration of the syscall. The scalability of OpenResty comes from Nginx's event-driven I/O model providing non-blocking I/O operations that are wired to yield coroutines when they would block. This is infrastructure built *around* Lua coroutines, not a property of coroutines themselves. A language designer evaluating Lua's concurrency model should distinguish: (a) the coroutine primitive, which is a cooperative concurrency mechanism; and (b) the OpenResty deployment pattern, which provides scalable I/O concurrency by pairing that primitive with an event loop. These are separable contributions.

**Additional context:**

- **LuaJIT coroutine behavior differences**: LuaJIT implements Lua 5.1 coroutine semantics. The 5.2 fix that made `pcall` yieldable inside coroutines does not apply to LuaJIT. This means code written against PUC-Lua 5.2+ that relies on `pcall` inside coroutines will need modification or compatibility shims for LuaJIT. Given that OpenResty uses LuaJIT, this is a practical concern in production OpenResty code.

- **Coroutine memory cost**: The research brief notes that "creating thousands of coroutines is practical" [LTN001]. This is accurate — each Lua coroutine allocates a new Lua thread object (a `lua_State`) with a small initial stack. The default stack size is 20 C-level function slots, which translates to a small heap allocation. At the Lua level, coroutines are much lighter than OS threads (no kernel stack, no TLS, no page table overhead). For comparison, an OS thread typically requires 64 KB to 8 MB of stack allocation; a Lua coroutine's initial allocation is on the order of kilobytes.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **PUC-Lua benchmark data**: The 3.27–3.69 seconds versus C's 0.78–0.81 seconds on the CPU-intensive loop benchmark from [BENCH-LANGUAGE] is correctly cited. The approximately 4× gap is reproducible and consistent with expectations for an interpreted register-based VM without JIT.

- **Lua 5.4 40% speedup**: The 40% improvement on the Lua benchmark suite is documented by [PHORONIX-5.4] and corroborated by [LWN-5.4]. The improvement came from multiple changes including to-be-closed variable implementation, GC improvements, and interpreter optimization.

- **LuaJIT near-C performance**: The 0.81 second result for LuaJIT versus 0.78–0.81 seconds for GCC C on the CPU-intensive loop [BENCH-LANGUAGE] is credible for this class of workload. The [EKLAUSMEIER] 2021 comparison supporting "competitive with Java and V8" is also consistent with LuaJIT's performance characteristics on numerical workloads.

- **Startup time advantage**: Sub-millisecond startup for PUC-Lua is accurate and consequential for CLI tools, embedded initialization, and serverless cold-starts. LuaJIT has slightly higher startup due to JIT machinery, but remains fast relative to Python (50–200 ms), Ruby (100–400 ms), or Node.js (50–100 ms) startup.

- **CLBG categorization of PUC-Lua**: Placing standard PUC-Lua among the five slowest interpreted languages [ARXIV-ENERGY] is accurate and appropriately qualified when council members note this does not apply to LuaJIT.

**Corrections needed:**

- **CLBG excludes LuaJIT — this must be stated clearly**: The Computer Language Benchmarks Game results place PUC-Lua among the slowest interpreted languages. LuaJIT is *not included* in the primary CLBG benchmark suite. Several council members note this; however, statements like "Lua is among the five slowest interpreted languages" without qualification are technically wrong if the intended subject is "the Lua language" rather than "the PUC-Lua implementation." Language designers reading these materials should understand that benchmark suite characterizations are implementation-specific, not language-specific. For Lua this distinction is unusually important because the two major implementations differ by 4× on the same workload.

- **"40% faster" scope qualification**: The 40% improvement is measured on the Lua benchmark suite — a specific set of microbenchmarks maintained by the Lua team. The improvement may not generalize uniformly across all workloads. The research brief appropriately cites this as "on 64-bit macOS" [PHORONIX-5.4]. No systematic measurement of improvement across diverse real-world workloads (e.g., game logic, template rendering, network packet processing) was cited by any council member.

- **LuaJIT trace-based JIT performance on non-numerical workloads**: Multiple council members characterize LuaJIT as achieving "near-C performance." This is accurate for CPU-bound numerical workloads that JIT-compile well. For string-heavy workloads, allocation-heavy workloads, or code with many indirect jumps (dispatch-heavy interpreter-style code), LuaJIT's trace-based approach produces narrower speedups because trace formation depends on identifying hot straight-line paths. The [NAACL-2025] paper noted in the research brief documents LuaJIT as slower than optimized C for string-heavy workloads. This qualification is absent from the apologist and historian perspectives.

- **LuaJIT trace compilation "degrades gracefully" — needs precision**: The claim that LuaJIT "degrades gracefully when traces are not formed" is accurate but underspecified. When a trace cannot be compiled (due to blacklisted operations, side exits exceeding threshold, or NYI — Not Yet Implemented — bytecodes), LuaJIT falls back to its fast interpreter. The fast interpreter itself is faster than PUC-Lua's VM. However, code that repeatedly triggers trace abandonment can experience overhead from trace recording attempts. The "degradation" is not always smooth.

- **LuaJIT FFI performance scope**: Several council members describe the LuaJIT FFI as "eliminating C function call overhead." More precisely: LuaJIT FFI allows JIT-compiled code to call C functions defined via `ffi.cdef` *directly*, bypassing the standard Lua C API stack protocol (which involves pushing and popping values through `lua_State`). When the call site is within a JIT-compiled trace, this achieves near-zero calling overhead compared to the `lua_call` mechanism. However, this optimization only applies when (a) the code is JIT-compiled, (b) the FFI call is within the compiled trace, and (c) the called function does not contain operations that cause trace exit. When the JIT is not active for a given code path, FFI calls still carry interpreter-overhead costs. The FFI benefit is a JIT-specific optimization, not a general property of LuaJIT.

**Additional context:**

- **Register-based VM context**: Lua 5.0's switch from stack-based to register-based VM (documented in [LUA5-IMPL]) reduced instruction count by approximately 47% on typical programs and improved cache behavior. This is a well-validated design decision that the historian and practitioner correctly characterize. For a language designer, the lesson is that register-based VMs reduce dispatch overhead relative to stack-based VMs at the cost of a more complex code generator — a tradeoff that favors execution speed over implementation simplicity in the compiler, but that Lua managed while keeping the overall implementation small.

- **Single-pass compilation architecture**: Lua's compiler produces bytecode in a single pass without constructing an explicit AST in memory (the code generator is driven directly by the parser). This is documented in [LUA5-IMPL]. This design explains the fast compilation speed but constrains the possible optimizations — single-pass compilation cannot perform global dataflow analysis, escape analysis, or optimizations requiring backward analysis. The Lua VM makes no attempt at these; the JIT story (LuaJIT) handles optimization at runtime. For language designers, this represents a deliberate choice: fast cold starts and simple implementation at the cost of giving up ahead-of-time optimization opportunities.

- **GC performance as first-class constraint for game use**: Game development is Lua's dominant domain, and game frame timing imposes hard latency constraints (typically 16 ms per frame at 60 FPS). Incremental minor cycles in 5.1–5.4 reduced *minor* GC pause to manageable levels, but major GC cycles could produce spikes well above frame budget. The Lua 5.5 full-incremental major GC [PHORONIX-5.5] directly addresses the remaining pause source for game use cases. This evolution — from stop-the-world to partially incremental to fully incremental over seven versions — is an important data point for how real-time GC requirements drive language evolution.

---

### Other Sections (Compiler/Runtime-Relevant Flags)

**Section 1 (Identity and Intent): Register-based VM claim**
The claim that Lua uses a register-based VM since version 5.0 is accurate and well-sourced [LUA5-IMPL]. The distinction from stack-based VMs is correctly characterized by the historian and practitioner.

**Section 2 (Type System): Runtime coercions**
The string-to-number coercion (`"10" + 5 == 15`) mentioned by multiple council members is a runtime operation, not a compile-time transformation. It has a performance cost — every arithmetic operation on a string value must detect the string type, attempt the coercion via `tonumber()`, and raise a runtime error on failure. In hot loops, this coercion cost is non-negligible. The apologist does not flag this cost; the detractor correctly identifies implicit coercions as a source of runtime surprises. From a compiler perspective, the coercion also prevents meaningful static type inference, contributing to the difficulty of producing optimized code from Lua source.

**Section 10 (Interoperability): LuaJIT FFI and the C API contrast**
The distinction between the standard Lua C API (stack-based, portable, present in all implementations) and the LuaJIT FFI (direct binding, JIT-friendly, LuaJIT-only) is correctly noted in the practitioner and realist perspectives. However, the interoperability section should emphasize that choosing LuaJIT FFI for performance locks the codebase to LuaJIT — FFI-based bindings are not compatible with PUC-Lua or Luau. This creates a fragmentation risk: a codebase optimized using LuaJIT FFI cannot be migrated to PUC-Lua 5.5 without rewriting its C bindings.

**Section 11 (Governance): LuaJIT maintenance risk**
The practical consequence for runtime behavior: LuaJIT's frozen-at-5.1 status means any Lua 5.2+ language feature (yieldable pcall inside coroutines, integer subtypes, bitwise operators as language syntax, `goto`, to-be-closed variables, `coroutine.close`) is unavailable to LuaJIT users. This is not just a feature gap — it is a runtime behavioral difference. Code using integer arithmetic under Lua 5.3+ semantics (where `//` is integer division and `3/2 == 1`) will behave differently under LuaJIT 5.1 semantics (where all numbers are doubles and `3/2 == 1.5`). Applications requiring both LuaJIT performance and Lua 5.3+ semantics have no supported path as of February 2026.

---

## Implications for Language Design

**1. Staged GC incremental refinement requires explicit scope labeling.** Lua's GC story from 5.1 to 5.5 illustrates a common error: claiming "incremental GC" when only part of the collection cycle is incremental. Real-time guarantees require incremental behavior across *all* GC phases, including major collections. Language designers adding incremental GC should specify precisely which phases are incremental, at what granularity, and with what worst-case bounds. Marketing "incremental" to users before the guarantee is complete invites misplaced confidence and correctness failures at runtime.

**2. The `longjmp`-based error mechanism is incompatible with C++ RAII at the embedding boundary.** Any scripting language embedded in C++ that uses `longjmp` for error propagation will have a correctness hazard at C/C++ interop boundaries. The correct design choice is to provide a compile-time switch between `longjmp` and exception-based error transport, which Lua does via `luaconf.h` but does not document prominently. A new language targeting C++ embedding should default to exception-based error transport from the outset, or design the embedding API to never allow Lua errors to propagate through C++ call frames without interception.

**3. JIT implementations must track their source language version or create permanent fragmentation.** LuaJIT's frozen-at-5.1 status is the defining ecosystem problem for Lua in 2026. LuaJIT 2.1 was released in 2016 targeting Lua 5.1; nine years and three Lua major versions later, there is no JIT-compiled Lua 5.3, 5.4, or 5.5. The lesson for language designers: if a JIT implementation becomes production-critical (as LuaJIT did via OpenResty and Cloudflare), it must be given a concrete versioning relationship with the specification — either by design (JIT is co-maintained with the VM) or by funding commitment. A JIT that diverges from the specification is worse than no JIT, because it creates permanent user base fragmentation.

**4. Single-pass compilation is viable but forecloses ahead-of-time optimization.** Lua's single-pass bytecode compiler delivers fast startup and a simple implementation, but cannot perform dataflow analysis, escape analysis, or devirtualization. These optimizations are deferred to the JIT (if used). For language designers, this suggests a separation: single-pass compilation is appropriate for scripting contexts where cold-start matters; any performance-critical optimization path should be the JIT layer. Architecturally, Lua validates the two-tier approach — fast interpreter for moderate workloads, JIT for hot code — as a viable division of concerns.

**5. Cooperative concurrency requires explicit yield points at the I/O layer.** Lua's coroutine model produces scalable concurrency in OpenResty because Nginx provides non-blocking I/O that yields coroutines. Absent that infrastructure layer, a Lua coroutine calling a blocking C function blocks the entire OS thread. Language designers adding cooperative concurrency as a core feature should simultaneously specify how blocking operations are handled — either by banning them from coroutine context (e.g., using Rust-style async coloring) or by providing a runtime I/O layer that converts blocking calls to yield points. Providing the coroutine primitive without the I/O layer produces a model that requires external infrastructure to be useful.

**6. Interning all strings has memory implications that should be profiled at scale.** Lua's O(1) string equality is useful and the implementation is clean. But the interning table acts as a GC root that accumulates all distinct strings, including transient ones not yet collected. For workloads producing many unique strings (log correlation IDs, request identifiers, unique keys), the intern table prevents prompt collection. Language designers using interning should consider bounded interning (intern only short strings, or intern only strings below a hash-collision threshold) or weak-reference interning that allows GC of strings with no other live references.

**7. Benchmark suite selection defines what "performance improvement" means.** Lua 5.4's "40% speedup" was measured on the Lua benchmark suite — a set of microbenchmarks biased toward compute-intensive numerical code. A 40% improvement on a benchmark suite designed by the language team is not the same as a 40% improvement on production workloads. Language designers claiming performance improvements should (a) specify the benchmark suite, (b) characterize what workload class it represents, and (c) conduct measurements on representative real-world programs in addition to micro-benchmarks.

---

## References

[LUA5-IMPL] Ierusalimschy, R., de Figueiredo, L.H., Celes, W. "The implementation of Lua 5.0." *Journal of Universal Computer Science*, 2005. https://www.lua.org/doc/jucs05.pdf

[LUA-MANUAL-5.4] Ierusalimschy, R. et al. "Lua 5.4 Reference Manual." lua.org. https://www.lua.org/manual/5.4/manual.html

[LUA-MANUAL-5.5] Ierusalimschy, R. et al. "Lua 5.5 Reference Manual." lua.org. https://www.lua.org/manual/5.5/manual.html

[LUA-VERSIONS] "Lua: version history." lua.org. https://www.lua.org/versions.html

[LWN-5.4] LWN.net. "What's new in Lua 5.4." December 2020. https://lwn.net/Articles/826134/

[PHORONIX-5.4] Larabel, M. "Lua 5.4 released with new garbage collection mode, warning system." Phoronix, June 2020. https://www.phoronix.com/news/Lua-5.4-Released

[PHORONIX-5.5] Larabel, M. "Lua 5.5 released with declarations for global variables, garbage collection improvements." Phoronix, December 2025. https://www.phoronix.com/news/Lua-5.5-Released

[HOPL-2007] Ierusalimschy, R., de Figueiredo, L.H., Celes, W. "The evolution of Lua." *Proceedings of the third ACM SIGPLAN conference on History of Programming Languages (HOPL III)*. ACM, June 2007. https://www.lua.org/doc/hopl.pdf

[LTN001] Ierusalimschy, R. "Lua Technical Note 1: Minimal Lua 5.1 Installation." lua.org. https://www.lua.org/notes/ltn001.html

[OR-DOCS] OpenResty documentation. https://openresty.org/en/lua-nginx-module.html

[LUAJIT-PERF] LuaJIT performance page. https://luajit.org/performance.html

[BENCH-LANGUAGE] DNS/benchmark-language. GitHub (informal community benchmark). https://github.com/DNS/benchmark-language

[ARXIV-ENERGY] "It's Not Easy Being Green: On the Energy Efficiency of Programming Languages." arXiv, October 2024. https://arxiv.org/html/2410.05460v1

[EKLAUSMEIER] Klausmeier, E. "Performance Comparison C vs. Java vs. Javascript vs. LuaJIT vs. PyPy vs. PHP vs. Python vs. Perl." July 2021. https://eklausmeier.goip.de/blog/2021/07-13-performance-comparison-c-vs-java-vs-javascript-vs-luajit-vs-pypy-vs-php-vs-python-vs-perl

[NAACL-2025] MojoBench paper (ACL Anthology, NAACL 2025 findings). References LuaJIT in performance comparisons. https://aclanthology.org/2025.findings-naacl.230/

[COROUTINES-PAPER] de Moura, A.L., Ierusalimschy, R. "Revisiting Coroutines." *ACM Transactions on Programming Languages and Systems*, 2009. https://www.inf.puc-rio.br/~roberto/docs/MCC15-04.pdf

[LUAJIT-COMPAT] Hacker News discussion: "Isn't LuaJIT stuck on Lua 5.1, and no longer in development?" https://news.ycombinator.com/item?id=15650546

[GC-PAPER] "Understanding Lua's Garbage Collection." arXiv:2005.13057, May 2020. https://arxiv.org/pdf/2005.13057

[PIL] Ierusalimschy, R. *Programming in Lua*, 4th ed. Lua.org, 2016. https://www.lua.org/pil/
