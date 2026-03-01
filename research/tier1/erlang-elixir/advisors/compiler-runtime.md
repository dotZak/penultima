# Erlang/Elixir — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Erlang/Elixir"
agent: "claude-agent"
date: "2026-03-01"
```

---

## Summary

The council's five perspectives collectively present an accurate and well-evidenced account of the BEAM's core technical properties. The per-process GC model, process scheduling via reduction counting, the role of OTP supervision, and the JIT introduction via BeamAsm are all described consistently and with appropriate citations. Importantly, the documents do not engage in the most common form of BEAM overclaim — asserting soft-real-time guarantees stronger than the implementation delivers or claiming "zero latency" concurrency.

That said, several compiler and runtime claims require correction or significant qualification. The most consequential is the characterization of BeamAsm as a JIT compiler in the traditional sense: it is not a profile-guided adaptive optimizer like JVM HotSpot or V8, but rather a load-time ahead-of-time native code compiler. This distinction matters because the kind of optimization BeamAsm can perform is fundamentally different from adaptive JITs, and claims about its potential ceiling should be scoped accordingly. A second cluster of issues involves comparison framing: the "2,000× lighter than OS processes" figure comparing BEAM processes to OS *processes* rather than OS *threads*, the Stressgrid busy-wait benchmark data from 2019 applied to contemporary BEAM schedulers, and the use of the k-nucleotide microbenchmark as a proxy for "network protocol string processing" performance. A third issue is a technical imprecision in the Elixir compilation pipeline description and an oversimplification of the BEAM GC algorithm characterization.

For language designers, the BEAM reveals important lessons about the costs and benefits of per-agent isolation at the runtime level. The system achieves predictable tail latency and structural data-race elimination through isolation, but pays a message-copying tax, lacks native backpressure primitives, and exposes a categorical safety exception at every language boundary (NIFs). These trade-offs are not inherent to actor-model concurrency in general — they are specific choices the BEAM makes — and understanding their implementation causes illuminates which properties can be replicated with different design decisions.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- Per-process heap isolation: every BEAM process has a private stack and heap. GC of one process does not pause other processes. This is confirmed by ERTS documentation and is the mechanistic explanation for the BEAM's soft-real-time latency characteristics [ERLANG-GC-DOC].
- The 64-byte binary threshold: sub-binaries of 64 bytes or fewer ("heap binaries") are stored on the process heap. Binaries exceeding 64 bytes ("refc binaries") are stored in a shared binary heap outside individual process heaps, passed by reference between processes rather than copied. This is consistent across all five council documents and matches the ERTS documentation [ERLANG-GC-DOC].
- Message-passing copy cost: inter-process messages require deep-copying all data except large binaries, which transfer by reference. The cost scales with message size. The detractor's emphasis on this as a design constraint for data-intensive architectures is well-founded.
- Refc binary fragmentation and the "reference accumulation" hazard in middleman processes are accurately described by the detractor, with appropriate sourcing to "Erlang in Anger" [ERL-IN-ANGER]. This is a documented operational reality, not a theoretical concern.
- The mailbox overflow hazard — no built-in backpressure at the process level — is correctly described across the realist, practitioner, and detractor documents. The practitioner's recommendation to use GenStage or Broadway as library-level solutions is accurate [DASHBIT-10YRS].
- The comparative latency advantage versus JVM: the claim that BEAM avoids stop-the-world GC pauses that affect all concurrent work simultaneously is accurate. Individual process GC pause duration is bounded by that process's heap size, not the total application heap. This produces lower tail latency under concurrent load than shared-heap collectors [ERLANG-GC-DOC].

**Corrections needed:**

1. **"Cheney's algorithm" is an oversimplification** (research brief, cited by apologist and realist by reference). The BEAM GC uses a generational copying scheme: a young heap collected by minor GC (copying live objects into the old heap), an old heap collected less frequently by major GC, and a separate shared binary heap for refc binaries [ERLANG-GC-DOC]. Cheney's algorithm specifically refers to a two-space semi-space copying collector — a simpler, non-generational scheme. The BEAM's actual collector is more sophisticated. This imprecision propagates through documents that cite the research brief; the advisor recommends correcting the research brief description to "generational copying collector" rather than "Cheney's algorithm."

2. **Go GC comparison is overstated by the apologist.** The apologist groups JVM, .NET CLR, CPython, and V8 alongside Go as shared-heap runtimes with equivalent stop-the-world GC concerns. This is misleading. Go's GC has been substantially refined through concurrent mark-and-sweep with very short stop-the-world phases (typically well under 1 ms in modern versions). The BEAM's advantage over Go is not primarily that Go has long pauses — Go's pauses are brief — but that Go's GC must still pause *all* goroutines simultaneously when scanning stacks, while BEAM GC is completely per-process. The realist is more accurate in qualifying Go's STW pauses as "brief." Language designers should understand the distinction: the BEAM's advantage is pause *isolation* (one process pauses, others continue), not solely pause *duration*.

**Additional context:**

The shared binary heap introduces a reference-counting dimension to what is otherwise a tracing GC system. This hybrid means the BEAM has two distinct GC strategies in operation simultaneously: tracing (for process heaps) and reference counting (for large binaries). The interaction between these two strategies creates the refc binary accumulation hazard: a process heap trace will collect the reference to a large binary, but the large binary itself is only freed when its reference count drops to zero. Middleman processes that copy binary references into their heap without consuming the data can hold live references indefinitely, preventing reclamation even when the original producer and consumer have finished. This is a genuine memory management pitfall that the council documents correctly identify, but the underlying mechanism (the dual-strategy hybrid) is not fully explained in any single document. The practitioner's operational rule — "keep messages small, route by identifier rather than content" — is the correct mitigation, but the explanation of *why* this matters would benefit from the dual-strategy framing.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- Reduction-based preemptive scheduling: each process is allocated approximately 2,000 reductions per scheduling timeslice; the scheduler preempts based on reduction count, not wall-clock time. This ensures no process can starve others by running compute-intensive code in a tight loop — the scheduler will preempt after approximately 2,000 "steps" regardless. This is accurately described across the research brief and council documents [BEAM-BOOK].
- One scheduler per CPU core (configurable): the BEAM runs one scheduler thread per logical CPU core by default, enabling true parallelism on multicore hardware. Work-stealing between schedulers is used when one scheduler's run queue is empty [BEAM-BOOK].
- Process creation in microseconds at approximately 2 KB initial heap: the research brief states "approximately 300 words initial heap" (approximately 2 KB on 64-bit systems), consistent with ERTS documentation. Measured process creation time is in the microsecond range [BEAM-BOOK].
- No function coloring: the claim that BEAM avoids the async/await "function coloring" problem (per Nystrom's "What Color Is Your Function?") is accurate at the surface. BEAM processes are all synchronous; concurrency is expressed by spawning processes rather than annotating call sites [HN-COLORED].
- Full-mesh topology scaling limit: the claim that the default BEAM distribution topology (fully meshed nodes) scales "comfortably to tens of nodes, not hundreds" is accurate. The connection count grows as N×(N-1)/2; at 100 nodes that is 4,950 connections. The research brief, realist, and historian all correctly identify this as a hard architectural constraint for large deployments [DIST-ERLANG].
- Distribution security defaults: inter-node communication in clear text by default, with MD5-based challenge-response for authentication, is accurately described by the detractor with appropriate sourcing [MONGOOSE-SECURITY]. The TLS distribution option (`inet_tls_dist`) is available but not the default, and this matters for any multi-datacenter deployment.

**Corrections needed:**

3. **"2,000× lighter than OS processes" comparison target is misleading** (research brief [BEAM-VS-JVM], apologist). This figure compares BEAM processes to OS *processes*, not OS *threads*. OS processes carry a multi-megabyte address space overhead; OS threads have a much smaller per-thread cost (default stack of 512 KB–1 MB on Linux). The more relevant comparison for concurrent programming is BEAM processes versus OS threads, against which the advantage is smaller (roughly 100–500×, comparable to Go goroutines vs. OS threads). BEAM processes are most analogous to green threads, goroutines, or virtual threads (Java 21+) — not to OS processes. Claiming a 2,000× advantage over OS processes is technically accurate for that specific comparison but creates a misleading impression about the advantage over other lightweight concurrency primitives. Future documents should compare to OS threads or goroutines to provide a meaningful competitive framing.

4. **The detractor's Stressgrid 56% busy-wait figure is potentially dated** [STRESSGRID-BEAMCPU]. This measurement was taken in 2019 against OTP 21/22 era BEAM schedulers. The BEAM scheduler has configurable busy-wait behavior via the `+sbwt`, `+sbwtdcpu`, and `+sbwtdio` flags. Since OTP 22, the default busy-wait behavior has been tuned toward lower power consumption while maintaining latency targets. The economic argument the detractor builds from this figure — "a BEAM application that maintains 20% higher CPU usage than an equivalent Go application to achieve the same latency profile costs 20% more to run" — may not hold for modern OTP configurations, particularly when scheduler sleep is enabled (`+sbwt none`). The advisor recommends either updating this citation with more recent measurements or qualifying the figure explicitly as pre-OTP-22 data.

5. **The "function coloring" advantage is real but the detractor's reframing is also partially accurate.** The detractor correctly observes that while BEAM does not require `async`/`await` annotations on function signatures, the conceptual distinction between "code running in the current process" and "code running in another process" still requires programmer awareness — it is implicit rather than explicit, and the consequence of making the wrong call (blocking the caller's process, overloading a GenServer mailbox, introducing a process-spanning latency dependency) is the same class of problem as colored functions but harder to detect. The apologist and realist undercount this. Language designers building on the actor model should be aware that removing syntactic coloring does not remove the underlying semantic distinction; it removes its visibility.

**Additional context:**

The reduction-counting scheduler deserves more technical attention than it receives in the council documents. BEAM's preemptive scheduling without OS thread interrupts is implemented entirely in software: the BEAM JIT (BeamAsm) emits reduction-decrement instructions at key points in generated code (function calls, loops, message sends). This means the scheduling granularity is bounded by the longest non-preemption point in the generated native code, which is typically a single function call. A tight loop with no function calls will not be preempted until the loop exits, because reduction decrements only occur at call boundaries. In practice, compiled Erlang/Elixir code avoids such pathological cases through tail-call optimization (recursive calls generate call-site reductions), but NIFs bypass this entirely — a NIF that runs for longer than approximately 1 ms should use dirty schedulers (`ERL_NIF_DIRTY_JOB_CPU_BOUND`) precisely because NIFs do not emit reductions and therefore cannot be preempted. The council documents describe this constraint only for NIFs without explaining the underlying scheduling mechanism, which matters for understanding the full concurrency picture.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- BeamAsm performance improvements: approximately 50% more work per unit time on the estone benchmark suite, 30–130% improvement on JSON benchmarks (average ~70%), 30–50% more messages/second in RabbitMQ [BEAMJIT-BLOG]. These figures are sourced to a primary Erlang Solutions benchmark report and appear consistent across documents.
- BEAM vs. Go for CPU-intensive computation: Go achieves 2–3× faster execution than BEAM [INDEX-DEV-COMPARISON]. This is consistent with independent measurements and reflects the JIT capability difference described below.
- BEAM vs. optimized C: BEAM is 5–20× slower for compute-bound benchmarks [BENCHMARKS-GAME]. This range is accurate and well-grounded; the variance reflects workload-specific factors.
- Message-passing-heavy workloads show minimal JIT benefit: correctly stated in research brief, realist, and practitioner documents. This is a critical nuance — BeamAsm improves computation within processes but does not reduce the per-message copy cost between processes.
- Elixir v1.19 compilation speedup of up to 4×; v1.20 an additional 2× [ELIXIR-119] [ELIXIR-120]. These are cited from primary sources (elixir-lang.org release blog posts).
- BEAM startup time of 1–3 seconds for fully-featured OTP applications: accurate and important for serverless deployment context [practitioner].
- WhatsApp 2 million concurrent TCP connections per server [WHATSAPP-HIGHSCAL] and Discord 5 million concurrent users on 400–500 nodes [DISCORD-ELIXIR]: these are sourced to credible primary and secondary sources respectively and are the most frequently cited evidence of BEAM's concurrency scale in production. The realist correctly notes that the WhatsApp figure required FreeBSD kernel tuning.

**Corrections needed:**

6. **BeamAsm is not a traditional JIT compiler** — this is the most significant compiler characterization error in the council documents, present implicitly across all five. All documents refer to BeamAsm as a "JIT" (Just-In-Time compiler), which is not technically wrong but is seriously misleading compared to what the JIT term implies based on HotSpot, V8, or LuaJIT.

   BeamAsm compiles BEAM bytecode modules to native machine code **at module load time**, generating x86_64 (and ARM64) instructions using the AsmJit library. It does this for the entire module, all at once, before any of the code runs. It does **not** profile the running program and selectively recompile hot paths. It does **not** use runtime type feedback to generate speculative optimizations. It does **not** deoptimize and recompile when runtime conditions invalidate assumptions.

   By contrast, HotSpot's JIT works in tiers: interpret cold code, profile it, compile hot paths with C1 (client compiler), then use profiling data to recompile with C2 (server compiler) using speculative optimizations. V8 similarly uses a pipeline from Ignition interpreter through Maglev to Turbofan, with profile-guided optimization at each tier.

   OTP 25 added type-based optimizations, but these are derived from compiler-inferred type information stored in BEAM files (a compile-time analysis), **not** from runtime profiling. The information flows from the Erlang compiler to BeamAsm as static annotations, not as runtime observations.

   The practical consequence: BeamAsm's optimization ceiling is limited to what can be determined statically from the BEAM bytecode at load time. It cannot, for example, devirtualize a function call that turns out to always call the same callee at runtime (profile-guided devirtualization). It cannot generate type-specialized fast paths based on observed runtime type distributions. This explains why BeamAsm yields a 50% improvement over the interpreter rather than the 2–5× improvements typical of mature adaptive JITs on appropriate workloads — the optimization strategies available to a load-time compiler without profiling data are fundamentally more limited.

   For language design analysis: this distinction matters when evaluating whether future BEAM performance improvements could close the gap with Go or native code. Closing that gap would require adding runtime profiling infrastructure — a substantially larger engineering investment than BeamAsm represented.

7. **The detractor's use of the k-nucleotide benchmark to argue about "network protocol string processing" performance is a misapplication of the benchmark** [BENCHMARKS-GAME-ERLANG]. The k-nucleotide benchmark (334× slower than Node.js in cited figures) involves counting nucleotide frequency patterns in DNA sequences — a bioinformatics workload dominated by hash table operations over strings drawn from a four-character alphabet. This is a very specific computational pattern that is particularly disadvantageous for dynamically typed functional languages due to the immutable data structure copying involved in hash table updates. It is not a proxy for general string manipulation or network protocol parsing. HTTP header parsing, JSON tokenization, or binary protocol framing are qualitatively different operations that the BEAM handles at competitive speeds (as evidenced by Phoenix's TechEmpower benchmark results). The advisor recommends removing or recontextualizing this claim, as it misleads about BEAM performance in its actual production domain.

8. **The estone "170% improvement in pattern matching" claim needs contextual scope** (apologist, research brief [BEAMJIT-BLOG]). This figure is a sub-benchmark result from the estone suite — a synthetic Erlang benchmark whose pattern matching sub-test was specifically favorable to BeamAsm's native code generation for comparison arms. Citing a 170% improvement in a sub-benchmark without noting it is a micro-benchmark sub-test creates an inflated impression of overall pattern-matching improvement in real programs. The overall estone result (approximately 50% improvement) is the more representative figure. This is not a fabricated claim, but the scoping should be made explicit.

**Additional context:**

The TechEmpower Web Framework Benchmarks (Round 22–23 data) are notably absent from all five council perspectives despite being directly relevant to assessing Phoenix's performance in its primary deployment domain. Phoenix ranks in the upper-mid tier of TechEmpower's "Plaintext" and "JSON" categories — significantly faster than Node.js/Express, Django, or Rails, but well below Rust-based frameworks and some JVM-based frameworks like Vert.x. This is important context for the performance discussion: BEAM is not competitive with native-compiled languages for throughput, but it is competitive with or superior to other managed-runtime languages in its primary deployment domain (web applications, real-time message routing). Including TechEmpower data would substantially strengthen the performance analysis by grounding it in production-representative workloads rather than relying solely on compute-intensive CLBG benchmarks and anecdotal production case studies.

The practitioner document correctly identifies the fundamental segmentation: high-concurrency I/O-bound workloads (BEAM's home territory), CPU-intensive workloads (BEAM's weakness). The practitioner is also accurate that the JIT improvement is weakest for the workloads where BEAM is most commonly deployed. This nuance deserves emphasis: BeamAsm's benefits are concentrated in the compute dimension, while BEAM's deployment value proposition is concentrated in the concurrency dimension. The two improvements are partly orthogonal.

---

### Other Sections (Compiler/Runtime Relevance)

**Section 2: Type System — compiler enforcement accuracy**

The council documents contain one significant overclaim and one evidentiary gap:

- **Overclaim (apologist):** The apologist states that Elixir's evolving type system will "provide compile-time type guarantees that emerge from the existing code as written." As of v1.20-rc, the system emits compile-time *warnings*, not compilation *errors*, for type violations. This is a deliberate design decision (backward compatibility, gradual adoption) documented in the elixir-lang.org release posts [ELIXIR-118] [ELIXIR-120]. Calling warnings "guarantees" conflates two different levels of enforcement. A guarantee means the violation cannot be deployed; a warning means it can. For language design analysis — particularly for safety-critical applications — this distinction matters. The consensus report should characterize the current system as "inference-based compile-time warnings" and note that error-level enforcement may be introduced in future versions.

- **Evidentiary gap (historian, detractor):** The claim that the 1997 Marlow-Wadler type system attempt for Erlang failed because it "could only type-check a subset of the language, with major gaps including inter-process message types" is described entirely via a secondary source [ERLANG-SOLUTIONS-TYPING], an Erlang Solutions blog post. The historian cites "[MARLOW-WADLER-1997]" as a reference key, but this citation does not appear in the historian's reference list — only the Erlang Solutions blog post appears. The original paper ("Practical Subtyping for Erlang" by Marlow and Wadler, proceedings of the 1997 ACM International Conference on Functional Programming) should be cited directly if this claim is retained. Using secondary sources to describe the limitations of primary research weakens the evidentiary basis and risks mischaracterizing the original paper's scope.

- **Accurate:** All documents correctly describe Erlang's `-spec` annotations as optional metadata not enforced by the compiler. Dialyzer's success-typing approach (no false positives, high false negatives) is accurately described with appropriate citations [DIALYZER-LYSE]. The inter-process message typing gap — messages between processes remain dynamically typed even as the within-process type system matures — is correctly identified as a fundamental limitation by the realist and detractor.

**Section 10: Interoperability — NIF implementation accuracy**

- **Potentially imprecise (detractor):** The detractor's claim that dirty NIFs "block garbage collection of the calling process indefinitely" [ERL-NIF-DOC] requires nuance. When a process calls a dirty NIF, it is suspended on a dirty scheduler thread. A suspended process's heap cannot be collected until the process resumes. However, "indefinitely" is misleading for normal operation: the blocking is bounded by the NIF returning or the VM halting. The more accurate characterization is that a dirty NIF that runs for a long time delays GC of the calling process for that duration, which can be significant (seconds to minutes for truly long-running NIFs), not literally forever. The concern is real and the detractor's broader point — that NIFs undermine BEAM's fault-isolation model — is correct, but "indefinitely" overstates the specific GC blocking claim.

- **Accurate:** All documents correctly identify that NIF crashes terminate the entire VM. The official OTP documentation is quoted directly by the detractor: "If a native function does not behave well, the whole VM will misbehave. A native function that crashes will crash the whole VM" [ERL-NIF-DOC]. This is the single most important safety caveat about the BEAM's concurrency model and deserves prominent placement.

- **Accurate:** The Rustler (Rust-based NIF framework) and Zigler (Zig-based) alternatives reduce but do not eliminate NIF memory risk — a panic in Rust via Rustler can still crash the BEAM. This is correctly characterized in the realist and practitioner documents.

**Section 6: Ecosystem — Elixir compilation pipeline description**

- **Minor technical imprecision (research brief):** The research brief describes Elixir's compilation pipeline as "Elixir source → Erlang AST → BEAM bytecode." The actual pipeline is: Elixir source → Elixir AST (macro-expanded) → Core Erlang (the OTP compiler's intermediate representation) → BEAM bytecode. Elixir does not generate Erlang surface syntax (the Erlang AST as it appears in .erl files) as an intermediate step; it generates Core Erlang directly, bypassing the Erlang parser. This matters for understanding Elixir's compilation characteristics, particularly the macro-expansion cascade the detractor identifies: the macro-expansion phase occurs within Elixir's own compiler pass before Core Erlang generation, which is why changing a macro-defining module can invalidate the Core Erlang for many dependent modules.

---

## Implications for Language Design

The BEAM's compiler and runtime architecture reveals several design trade-offs with implications for any language designer working on concurrent, fault-tolerant systems.

**1. Per-agent GC isolation is achievable but requires committing to message copying.**

The BEAM achieves stop-the-world-free garbage collection by giving each process its own heap. The price is that any data shared between processes must be copied (for small data) or reference-counted in a shared area (for large binaries). This is not a necessary trade-off — shared heap runtimes can also achieve very short GC pauses through concurrent GC techniques (Go, modern JVM) — but BEAM's approach makes the isolation guarantee stronger and simpler to reason about. Designers choosing between per-agent heaps and shared heaps should understand that per-agent heaps eliminate cross-agent GC interference at the cost of allocation overhead in high-message-passing systems, and that the 64-byte threshold for shared binary storage is an engineering parameter, not a fundamental design constant. An alternative design might use different thresholds or provide more granular control.

**2. Load-time native compilation without profiling is significantly simpler than adaptive JIT but leaves optimization on the table.**

BeamAsm demonstrates that replacing interpretation with load-time native code generation is achievable incrementally (BEAM bytecode remains the portable distribution format; BeamAsm is a backend, not a new compilation target). The 50% performance improvement from this change represents gains achievable without the complexity of profiling infrastructure. However, closing the remaining gap with adaptive JITs (HotSpot, V8) requires profiling-guided optimization — substantially more engineering complexity, particularly speculative optimization with deoptimization, profile-guided inlining, and type specialization. Designers should understand the two-phase nature of managed language performance engineering: the first phase (interpretation → load-time native compilation) is tractable; the second phase (load-time compilation → adaptive JIT) requires qualitatively different infrastructure investment.

**3. Concurrency without backpressure primitives shifts the complexity to library design.**

BEAM's actor model, without built-in backpressure, produces the pattern observed across the council documents: the GenStage/Broadway library layer was necessary to provide what the runtime does not. This is a recurring tension in systems design — keeping the core minimal and composable versus providing essential guardrails in the core. BEAM's lack of native backpressure is consistent with its "mechanism without policy" philosophy, but the practical consequence is that every new team must discover and adopt the backpressure library layer independently. Language designers should consider whether backpressure is essential enough to a concurrent system's correctness to belong in the primitive set rather than the standard library.

**4. The fault isolation guarantee is categorical at language boundaries.**

BEAM's process isolation provides a complete abstraction inside the language boundary: no shared mutable state, no data races, structural fault containment. But this guarantee is entirely voided at the NIF boundary. Any NIF in any dependency — including transitive dependencies — introduces the possibility of whole-VM crashes. This is the fundamental tension of managed runtime interoperability with native code: the isolation guarantee cannot survive the boundary, because the boundary is implemented in code that operates outside the isolation mechanism. Designers building managed runtimes that promise isolation should either (a) provide a safe interop layer that cannot violate the guarantee (WASM sandboxing), (b) separate the runtime into a process hierarchy where FFI code runs in a separate OS process (Erlang Port model), or (c) be explicit that the isolation guarantee is conditional on no native code. The BEAM chooses option (c) for NIFs and option (b) for Ports, but option (b)'s performance overhead drives production systems toward option (c). This trade-off has no clean resolution; it is inherent to managed runtime design.

**5. Reduction-based preemptive scheduling in native code requires compiler cooperation.**

BEAM's preemptive scheduling works without OS thread interruption because the native code generator (BeamAsm) emits reduction-decrement instructions at known preemption points (call boundaries). This means the compiler and the scheduler are co-designed — the scheduler's correctness depends on the compiler's cooperation. Any extension that bypasses the compiler's code generation (NIFs) must explicitly cooperate with the scheduler (dirty schedulers for long-running operations) or break preemptibility. Designers of concurrent systems should be aware that software preemption requires either compiler cooperation or hardware interrupt-based preemption; there is no "free" preemptibility that works transparently with arbitrary code.

---

## References

[ARMSTRONG-2007] Armstrong, J. "A History of Erlang." Proceedings of the Third ACM SIGPLAN Conference on History of Programming Languages (HOPL III), 2007. https://dl.acm.org/doi/10.1145/1238844.1238850

[BEAM-BOOK] Happi, E., Larsson, H. and Gustafsson, J. "The BEAM Book." GitHub: happi/theBeamBook. https://github.com/happi/theBeamBook

[BEAMJIT-BLOG] "Performance testing the JIT compiler for the BEAM VM." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/performance-testing-the-jit-compiler-for-the-beam-vm/

[BENCHMARKS-GAME] "Computer Language Benchmarks Game." benchmarksgame-team.pages.debian.net. https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html

[BENCHMARKS-GAME-ERLANG] Computer Language Benchmarks Game: Erlang results. https://benchmarksgame-team.pages.debian.net/benchmarksgame/measurements/erlang.html

[DASHBIT-10YRS] Valim, J. "10 years(-ish) of Elixir." Dashbit Blog. https://dashbit.co/blog/ten-years-ish-of-elixir

[DIALYZER-LYSE] Hébert, F. "Type Specifications and Erlang." Learn You Some Erlang. https://learnyousomeerlang.com/dialyzer

[DISCORD-ELIXIR] DeBenedetto, S. "Real time communication at scale with Elixir at Discord." elixir-lang.org blog, October 8, 2020. http://elixir-lang.org/blog/2020/10/08/real-time-communication-at-scale-with-elixir-at-discord/

[DIST-ERLANG] "Distributed Erlang." Erlang/OTP Documentation. https://www.erlang.org/doc/reference_manual/distributed

[ELIXIR-118] "Elixir v1.18 released: type checking of calls, LSP listeners, built-in JSON, and more." elixir-lang.org, December 19, 2024. http://elixir-lang.org/blog/2024/12/19/elixir-v1-18-0-released/

[ELIXIR-119] "Elixir v1.19 released: enhanced type checking and up to 4x faster compilation for large projects." elixir-lang.org, October 16, 2025. http://elixir-lang.org/blog/2025/10/16/elixir-v1-19-0-released/

[ELIXIR-120] "Elixir v1.20.0-rc: type inference of all constructs." elixir-lang.org, January 9, 2026. http://elixir-lang.org/blog/2026/01/09/type-inference-of-all-and-next-15/

[ELIXIR-TYPES-PAPER] Castagna, G., Dognin, G., and Valim, J. "A Type System for Elixir." arXiv:2306.06391. June 2023. https://arxiv.org/abs/2306.06391

[ERL-IN-ANGER] Hébert, F. "Erlang in Anger." https://www.erlang-in-anger.com/

[ERL-NIF-DOC] "erl_nif — The Erlang NIF Library." Erlang/OTP ERTS Documentation. https://www.erlang.org/doc/man/erl_nif.html

[ERLANG-GC-DOC] "Erlang Garbage Collector." Erlang System Documentation, ERTS. https://www.erlang.org/doc/apps/erts/garbagecollection

[ERLANG-SOLUTIONS-TYPING] "Type-checking Erlang and Elixir." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/type-checking-erlang-and-elixir/

[HN-COLORED] Hacker News discussion on function coloring in Erlang. https://news.ycombinator.com/item?id=28914506

[INDEX-DEV-COMPARISON] "Erlang vs Elixir vs Go for Backend Development." index.dev. https://www.index.dev/skill-vs-skill/backend-elixir-vs-erlang-vs-go

[MONGOOSE-SECURITY] "Erlang Distribution Protocol Security." MongooseIM/mongooseim project documentation. Referenced in security discussions.

[NIF-INTEROP] Leopardi, A. "Using C from Elixir with NIFs." https://andrealeopardi.com/posts/using-c-from-elixir-with-nifs/

[OTP-28-HIGHLIGHTS] "Erlang/OTP 28 Highlights." erlang.org, May 20, 2025. https://www.erlang.org/blog/highlights-otp-28/

[STRESSGRID-BEAMCPU] "Erlang vs. Go vs. Node.js: Schedulers and CPU Efficiency." Stressgrid Blog, 2019. (Note: data is from 2019 OTP 21/22 era; verify against current OTP 27/28 scheduler behavior.)

[WHATSAPP-HIGHSCAL] "How WhatsApp Grew to Nearly 500 Million Users, 11,000 cores, and 70 Million Messages a Second." High Scalability. https://highscalability.com/how-whatsapp-grew-to-nearly-500-million-users-11000-cores-an/
