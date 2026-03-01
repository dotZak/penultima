# OCaml — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "OCaml"
agent: "claude-agent"
date: "2026-02-28"
```

---

## Summary

OCaml's compiler and runtime represent a mature, carefully engineered stack with a few persistent architectural tensions. The foundational claims — generational GC, native-code compilation via `ocamlopt`, bytecode fallback via `ocamlc`, SC-DRF memory model for OCaml 5 — are broadly accurate across the five council perspectives. The GC design for functional programming allocation patterns is genuinely well-suited: minor-heap copying collection efficiently handles the high allocation rates of functional code, and the major-heap design provides bounded pause times in typical operation.

The most technically significant correction concerns the **boxing model and Flambda claims**. Several council members overstate Flambda's ability to close the C performance gap; Flambda addresses inlining and closure allocation overhead, not the boxing overhead that is the primary driver of the 2–5x C gap. Separately, the detractor's description of boxing as affecting "virtually all values in a polymorphic context" needs precision: OCaml's native `int` is stored as a tagged integer (unboxed), and float arrays have historically had special unboxed treatment. Pervasive boxing is real and costly, but the description of its scope requires technical nuance.

The OCaml 5 concurrency picture is accurately described in its broad strokes — Domains 1:1 to OS threads, SC-DRF memory model, effects as a direct-style concurrency primitive — but benefits from additional runtime-level context. Domain spawn creates OS threads (not lightweight fibers), making Domainslib's thread pool abstraction essential for fine-grained parallelism. Effect handler performance characteristics (overhead for high-frequency effects) and the interaction between Lwt and OCaml 5 domains are implementation details the council does not address but practitioners will encounter.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **GC architecture description**: All five council members correctly describe the generational GC as a copying minor heap (nursery) plus incremental/concurrent major heap. The characterization that minor collection is proportional to live data (not allocated data) is technically accurate for a copying collector — dead objects incur no scanning cost.
- **Best-fit allocator in OCaml 4.10**: Correctly cited across multiple perspectives [OCAMLPRO-BESTFIT]. This was a meaningful improvement for large-heap programs.
- **OCaml 5 per-domain minor heaps**: Correctly described. Each domain has an independent minor heap; the shared major heap uses concurrent collection. This design enables true parallelism by eliminating contention on minor GC.
- **Memory safety guarantees**: The "no use-after-free, no buffer overflows in safe code, no uninitialized reads" characterization is accurate for code that stays within the safe subset [TARIDES-MEMSAFETY].
- **Write barrier requirement**: The research brief notes the write barrier for generational correctness. No council member details this overhead, but the apologist's claim that the GC's design is "exactly right" for functional workloads implicitly accounts for it.
- **Escape hatch (`Obj` module)**: All council members accurately note that `Obj` bypasses type safety and GC correctness, and that its use is discouraged in application code.

**Corrections needed:**

1. **Boxing model precision**: The detractor claims "virtually all values in a polymorphic context are boxed — they live on the heap as tagged pointers, not on the stack as flat values" [detractor.md §3]. This overstates the boxing scope. OCaml uses a **tagged integer representation**: values with the lowest bit set to 1 are immediate integers (unboxed). OCaml's native `int` type is 63 bits on 64-bit platforms and is not heap-allocated. The `None` constructor for `'a option` is also represented as the integer 0 (unboxed). Float arrays have received special unboxed treatment since early OCaml versions. The boxing overhead is real and significant for polymorphic data structures, but characterizing it as affecting "virtually all values" misrepresents a runtime that carefully optimizes the integer and option cases.

2. **OCaml 5 GC compaction timeline**: The detractor states "major compaction is stop-the-world and unbounded in duration" [detractor.md §3]. This is correct as stated — but the council as a whole does not clearly flag a critical timeline detail: **GC compaction was absent from OCaml 5.0 and 5.1**, restored only in OCaml 5.2.0 (May 2024) [TARIDES-52]. The OCaml 5.0 and 5.1 releases could not compact the major heap at all, leaving early adopters with no recourse for heap fragmentation over time. The practitioner comes closest to noting this ("compaction restored in 5.2") but none frames it as the significant regression it was.

3. **Apologist's "verifiable correctness properties" for the OCaml 5 GC**: The apologist claims the OCaml 5 GC has "verifiable correctness properties" [apologist.md §3]. This overstates the shipped state. OCaml 5.0 and 5.1 shipped with documented performance regressions and memory-leak bugs in the new GC that required two subsequent release cycles to fix [OCAML-RELEASES]. The theoretical correctness of the SC-DRF memory model specification is well-founded [MULTICORE-CONC-PARALLELISM], but conflating specification correctness with implementation correctness is misleading.

4. **Detractor's OxCaml motivation**: The detractor claims "a language whose primary industrial user must fork it to reduce GC latency has a GC design problem" [detractor.md §3]. This is partially fair but oversimplified. OxCaml's "local modes" and stack allocation are primarily motivated by the **linearity/data-race-freedom system** being developed under the "Oxidizing OCaml" research program [JANESTREET-OXIDIZING], not by GC latency alone. Stack allocation reduces GC pressure as a consequence of the linearity system rather than as its primary objective. The framing elides the distinction.

**Additional context (compiler/runtime):**

- **Write barrier overhead for mutable operations**: OCaml's generational GC requires a write barrier on every mutable field assignment to track cross-generation pointers (the "remembered set"). In OCaml 5, domain-local writes require different handling than cross-domain writes. Programs that are heavily mutable (e.g., in-place data structure updates) pay a higher write barrier cost than programs that primarily allocate and discard values. This is not discussed by any council member but is relevant for practitioners evaluating OCaml for mutable-heavy workloads.

- **OCaml 5 concurrent major GC**: In OCaml 5, the major GC uses a **concurrent mark phase** that runs in parallel with the mutator (the OCaml program itself), not merely an incremental approach. The mark phase interleaves with mutation; a stop-the-world phase only occurs for certain synchronization points. This is architecturally distinct from OCaml 4's "incremental" major GC (which ran incrementally during allocation but still paused the single thread). The distinction matters for understanding pause time guarantees.

- **Spacetime profiler deprecation**: The Spacetime heap profiler, which provided allocation site-level memory profiling in OCaml 4.x, was deprecated and removed in OCaml 5. The research brief notes this [RESEARCH-BRIEF], but no council member flags it. For memory-intensive OCaml programs migrating to 5.x, the loss of Spacetime is a real tooling regression. `Magic-Trace` (Jane Street) and external tools via `perf` partly fill the gap, but no direct Spacetime replacement exists in stable OCaml 5.x as of early 2026.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **Domains 1:1 to OS threads**: All council members correctly describe that `Domain.spawn` creates an OS thread with a 1:1 mapping. This is accurate and an important distinction from Go's M:N scheduler.
- **SC-DRF memory model**: Multiple council members accurately state that OCaml 5 programs with data races are "semantically undefined but not memory-unsafe" and that data-race-free programs see sequentially consistent behavior [MULTICORE-CONC-PARALLELISM]. This is the correct description of the OCaml 5 memory model.
- **Effect handlers as direct-style concurrency**: The apologist and practitioner correctly describe that effect handlers avoid "colored functions" — effectful functions have the same type signature as pure functions, and effects can be handled at any call-stack level [INFOQ-OCAML5].
- **TSan in OCaml 5.2**: Correctly cited by multiple council members [TARIDES-52]. The qualification that TSan is a testing tool (not a correctness guarantee) is appropriately noted by the realist and practitioner.
- **Domainslib work-stealing**: Correctly described as providing parallel task pools with `parallel_for`, `parallel_scan`, and async/await semantics [PARALLEL-TUTORIAL].
- **Library fragmentation (Lwt/Async/Eio)**: Accurately characterized. The three incompatible concurrency substrates impose real ecosystem costs.
- **Effect handlers not typed**: The detractor correctly identifies that effects are not reflected in the type system as of OCaml 5.4 [detractor.md §4]. A function performing effects is indistinguishable from a pure function at the type level.

**Corrections needed:**

1. **Apologist's OCaml vs. Go concurrency comparison**: The apologist claims that Go's use of goroutines "for both" parallelism and concurrency makes it "difficult to reason separately about parallelism and concurrency" [apologist.md §4]. This mischaracterizes Go's design. Go's M:N scheduler maps goroutines onto OS threads; goroutines are primarily a **concurrency** primitive, and the runtime handles parallelism transparently. The design goal is to abstract both under one primitive for ergonomics, not to confuse their distinction. The apologist's point — that OCaml's explicit separation of Domains (parallelism) and fibers/effects (concurrency) is architecturally cleaner — may be valid, but the Go comparison is imprecise.

2. **"Effects can be caught and handled at any level, with full access to the continuation" — runtime caveat**: The apologist's description of effect handlers is mechanistically correct [apologist.md §4]. However, since effects are currently untyped, an effectful function called in a context where no handler is installed for its effects will **raise a runtime error** (`Effect.Unhandled`), not a compile-time error. The "full access to the continuation" claim is accurate, but the runtime failure mode for unhandled effects is not acknowledged. Programmers accustomed to Haskell's statically-tracked IO monad will find this a meaningful safety regression.

3. **"Performance regression target of less than 3% for single-threaded code was met"** (historian): This claim from the "Retrofitting Parallelism onto OCaml" paper [ICFP-RETRO-2020] refers to the design goal as specified in the research. The deployed OCaml 5.0 did not fully meet this goal: the release notes for 5.0 acknowledged performance differences, and 5.1 specifically included "performance regression fixes" [OCAML-RELEASES]. The historian correctly qualifies this ("in practice, OCaml 5.0 and 5.1 shipped with performance regressions"), but the framing as an implied success obscures that the regression fixes required two release cycles.

4. **Detractor's "typed effects as theoretically compelling"**: The detractor argues that untyped effects fail to deliver "the safety guarantees that make effects theoretically compelling" [detractor.md §4]. This is a fair criticism of the current state, but the framing ignores that typed effects (as in Koka, Effekt, or Frank) impose significant programmer burden — effect variables must be threaded through type signatures much like monadic types. The tradeoff between typed-effect safety and ergonomic overhead is genuine and not resolved by any current mainstream language. Characterizing the untyped approach as simply inferior elides this.

**Additional context (compiler/runtime):**

- **Domain spawn is not lightweight**: `Domain.spawn` creates a native OS thread. This imposes OS-level overhead (stack allocation, thread context, kernel interaction) that makes it unsuitable for fine-grained parallelism without a thread pool abstraction. Domainslib's `Task.pool` and `Task.async`/`Task.await` provide this pool model [PARALLEL-TUTORIAL]. Practitioners who use raw `Domain.spawn` for each parallel task in a loop will encounter significant performance problems. This implementation detail affects how Domains should be presented to programmers evaluating OCaml's parallelism story.

- **Lwt and OCaml 5 domain safety**: Lwt's internal state (notably its global scheduler and promise queues) was designed for single-threaded cooperative execution. Using Lwt across multiple OCaml 5 domains without careful synchronization is not safe. As of early 2026, Lwt is available for OCaml 5 but is intended to run on a single domain; multi-domain Lwt use requires explicit external synchronization. No council member addresses this constraint, which is important for teams migrating OCaml 4 Lwt codebases to OCaml 5.

- **Effect handler overhead**: OCaml 5 effect handlers are implemented by capturing portions of the call stack as a **continuation**. The overhead of a handled effect is higher than a function call — benchmarks from early OCaml 5 publications indicate that shallow effects (those handled in a nearby frame) have low overhead, while deep effects (those traversing many stack frames to reach the handler) have higher overhead. For I/O-bound programs where effects are infrequent, this is immaterial; for high-frequency effect use (tight loops with per-iteration effects), the overhead matters. The `Eio` library's design accounts for this by using effects for scheduling events rather than for every I/O operation.

- **Eio's fiber scheduler**: `Eio`'s fibers are implemented on top of effect handlers within a single domain. Multiple fibers within one domain cooperate via the effects-based scheduler; parallelism requires combining Eio's fiber-level concurrency with Domain-level parallelism (each domain runs its own Eio event loop). This composition model is correct and documented but requires understanding of the layering. The practitioner's description is accurate, but the implementation detail helps explain why Eio cannot simply be dropped into a multi-domain program without the surrounding domain infrastructure.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **"Second tier" benchmark position**: The CLBG data showing OCaml typically 2–5x slower than C, competitive with Java and C#, and substantially faster than Python/Ruby/JavaScript is well-evidenced [CLBG-OCAML, CLBG-C-VS-OCAML]. All council members cite this correctly.
- **No JIT implications**: The absence of a JIT compiler is correctly described as producing predictable latency (no warmup, no JIT recompilation pauses) at the cost of not enabling runtime specialization for polymorphic hot paths. Both the realist and historian correctly identify this tradeoff.
- **Flambda tradeoff (compilation time for runtime performance)**: The basic description — opt-in `-O2`/`-O3` flag enabling aggressive inlining and specialization at the cost of longer compilation times — is accurate [REAL-WORLD-OCAML-BACKEND].
- **Bytecode 2–8x slower than native**: Accurately stated and supported by evidence [OCAML-NATIVE-VS-BYTE]. The characterization of the ZINC bytecode interpreter as "remarkably performant for an interpreter without a JIT" is historically grounded [ZINC-1990].
- **Fast startup for native executables**: Correct. Native OCaml binaries load and initialize in milliseconds. No JVM startup, no Python interpreter, no Node.js module resolution phase.
- **1.2–2x memory overhead vs. C**: Correctly cited from CLBG data [CLBG-C-VS-OCAML] and accurately attributed to GC overhead and boxing. This is a structural cost of automatic memory management in a language with parametric polymorphism.
- **Flambda improving development vs. release build workflow**: The practitioner correctly notes the practical workflow: development builds use standard `ocamlopt`; release builds use Flambda [practitioner.md §9]. This is accurate.

**Corrections needed:**

1. **Apologist's "Flambda closes a significant fraction of the performance gap with C"**: The apologist claims Flambda "closes a significant fraction of the performance gap with C on compute-bound workloads" [apologist.md §9]. This is an overstatement. Flambda's optimizations target **inlining overhead** (eliminating unnecessary closure allocations for higher-order functions) and **cross-module specialization** — genuinely useful improvements for OCaml's functional idiom. However, Flambda does not address the **boxing overhead** (heap allocation for polymorphic values) or **GC costs** (minor and major collection), which are the primary drivers of the 2–5x gap vs. C. Realistic Flambda improvements on compute-heavy workloads are typically 10–30%, not the 50–100%+ that would be needed to "close a significant fraction" of a 2–5x gap. Jane Street's OxCaml, which targets boxing via local allocations and stack allocation, is the approach actually aimed at that gap — and it remains experimental.

2. **Flambda 1 vs. Flambda 2 conflation**: All council members refer to "Flambda" as a single entity. As of 2026, there are in practice two distinct implementations: **Flambda 1** (the original optimizer, in stable OCaml since 4.03) and **Flambda 2** (a substantially redesigned optimizer developed primarily by Jane Street, available in OxCaml and approaching upstream readiness). Flambda 2 has different optimization capabilities, different compilation time characteristics, and better support for unboxing. The council's discussion of Flambda implicitly refers to Flambda 1 in stable OCaml. The distinction matters for understanding where the optimization story is heading [JANESTREET-OXCAML].

3. **Detractor's claim that "Rust's compiler achieves significant optimization without requiring a separate optimizer mode at such cost"**: The detractor implies that Rust avoids Flambda's compilation overhead problem [detractor.md §9]. This comparison is imprecise. Rust's release-mode compilation (`--release`) also imposes substantially longer compile times than debug mode via LLVM's optimization pipeline. The experience is similar in principle — slow optimized builds vs. fast unoptimized builds — though Rust's tooling (Cargo's profile system) integrates this more smoothly.

**Additional context (compiler/runtime):**

- **Auto-vectorization absence**: The OCaml native compiler does not auto-vectorize loops. GCC and Clang can automatically generate SIMD instructions (SSE2, AVX, AVX-512) for vectorizable loops; `ocamlopt` cannot. This is a meaningful performance limitation for numerical computing. Programs that process arrays of floats or integers in loops leave SIMD performance on the table. OxCaml is exploring SIMD intrinsics [JANESTREET-OXCAML], but this capability does not exist in stable OCaml as of 2026. This partially explains why Ahrefs and Jane Street occasionally use C libraries for performance-critical numerical inner loops rather than pure OCaml.

- **Native backend calling convention**: The OCaml native compiler uses its own calling convention for OCaml-to-OCaml calls, distinct from the C ABI (System V ABI on x86-64). This enables optimizations specific to OCaml's calling patterns (e.g., tail call optimization, compact stack frames) but means every C FFI call crosses a calling convention boundary at a wrapper function. This boundary overhead is small per call but matters for high-frequency FFI use. No council member discusses calling convention costs.

- **Allocation cost model**: OCaml's minor heap allocation is essentially **pointer-bump allocation** — allocating in the nursery is nearly as cheap as stack allocation in C. The cost model differs structurally from C's `malloc`: individual allocations are cheaper, but periodic minor GC collection is required to reclaim the nursery. For allocation-heavy workloads (many small, short-lived values), this makes OCaml's allocation costs competitive with C's stack allocation — the key benchmark factor is not allocation speed per call but overall throughput including GC. The council's discussion of "GC overhead" would benefit from distinguishing allocation cost from collection cost.

- **Register allocator quality**: The OCaml native backend uses a **graph-coloring register allocator**, which is theoretically sound but less aggressive than LLVM's allocator (which uses several auxiliary passes). LLVM's allocator tends to produce tighter code for register-heavy computations. This contributes modestly to the performance gap vs. C/Rust. The gap is not attributable solely to GC and boxing.

---

### Other Sections (Compiler/Runtime Issues)

**Section 2: Type System**

The council correctly identifies that OCaml's Hindley-Milner inference is sound — type checking provides guarantees that enable **no-overhead polymorphism in monomorphic contexts** (the compiler knows the concrete type and can generate specialized code without runtime dispatch). One runtime-level detail worth preserving: the `option` type's `None` value is represented as the tagged integer `0` — a genuine unboxed optimization. `Some x` is represented as a heap-allocated block. This means the common "check for None" pattern is an integer comparison with no indirection, which is a pleasant runtime property arising from the type representation design.

**Section 5: Error Handling**

Multiple council members correctly state that OCaml exceptions impose **zero overhead on the success path**. This is accurate at the runtime level — OCaml exceptions use a setjmp/longjmp-like mechanism (specifically, a linked list of exception handlers stored in a thread-local variable, not the C `setjmp` facility directly). An exception frame is pushed when entering a `try ... with`, and popped on normal exit. This imposes a small constant overhead per `try` entry/exit, but **no per-operation overhead in the exception-free execution path**. This is distinct from Java's try-catch semantics (which impose overhead even without exceptions in some JVM implementations). The council's characterization is accurate and the compiler/runtime mechanism supports it.

**Section 6: Ecosystem and Tooling**

The **Spacetime heap profiler deprecation** is not flagged by any council member and deserves note. Spacetime provided allocation-site attribution for heap profiling in OCaml 4.x — a uniquely useful capability for understanding GC pressure. In OCaml 5, Spacetime was removed as part of the multicore GC redesign [RESEARCH-BRIEF]. The gap is partly filled by `perf`-based allocation sampling on Linux and Jane Street's `Magic-Trace`, but neither provides the allocation-site resolution that Spacetime offered. Teams migrating from OCaml 4 and relying on Spacetime for GC tuning should be aware of this regression.

**Section 10: Interoperability**

The detractor and practitioner provide the most technically accurate descriptions of the C FFI protocol. The **`CAMLparam`/`CAMLlocal`/`CAMLreturn` requirement** — that every OCaml value touched in a C stub must be registered as a GC root before any call that might trigger GC — is correctly described [detractor.md §10, practitioner.md §10]. One additional runtime-level detail not mentioned: in OCaml 5 with multiple domains, a **C function called from one domain may interleave with GC activity on another domain's minor heap**. C stubs that hold pointers to OCaml values across any OCaml call must account for this — the requirements are stricter in multi-domain programs than in single-domain OCaml 4. Teams porting OCaml 4 C stubs to OCaml 5 domains should audit stubs for multi-domain safety, not just existing GC-root protocols.

---

## Implications for Language Design

**1. Specify your memory model before shipping parallelism, not after.**

OCaml's SC-DRF memory model was specified formally (via the "Retrofitting Parallelism onto OCaml" research) before OCaml 5.0 shipped [ICFP-RETRO-2020]. Java's memory model, by contrast, was informally specified in the original language specification and required a decade of academic work (Manson et al., POPL 2005) to formalize correctly. The lesson: once a language ships a concurrent runtime, the memory model is effectively frozen by whatever behavior programs depend on. Specifying the model precisely before first release, even if the implementation temporarily falls short, establishes the right contract. OCaml 5's SC-DRF guarantee gives programmers a precise correctness target; Java's early lack of a formal model left programs in an undefined behavior regime for years.

**2. Deferring parallelism until the GC is ready imposes ecosystem fragmentation costs that persist beyond the fix.**

OCaml's 26-year gap between first release and true shared-memory parallelism was driven by the difficulty of designing a multicore-safe GC for a high-allocation-rate functional language. The technical justification was sound. But the ecosystem consequence was the development of multiple incompatible concurrency libraries (Lwt, Async, Eio) that will coexist for years after the underlying limitation was removed [INFOQ-OCAML5]. Language designers who anticipate parallelism requirements should architect the GC for concurrent collection from the start — even if the initial release is single-threaded — rather than retrofitting multicore safety later. The engineering cost of a concurrent GC upfront is high; the ecosystem fragmentation cost of deferral is potentially higher.

**3. Effect handlers provide better concurrency ergonomics than monadic I/O but require typed effect tracking to deliver full safety guarantees.**

OCaml's untyped effects represent a pragmatic first step: they deliver the "no colored functions" ergonomic benefit of direct-style async programming while deferring the complexity of typed effect tracking. This is a reasonable staging decision — typed effects can be added later without breaking the programming model. However, the current state imposes a real safety cost: unhandled effects produce runtime errors rather than compile-time errors. Language designers adopting effect handlers should treat typed effects as a goal from the outset even if initial implementations ship untyped, and should provide clear upgrade paths as typing is added.

**4. A binary optimization switch (no-optimization vs. expensive optimizer) reflects a compiler architecture limitation.**

OCaml's Flambda vs. non-Flambda dichotomy — where standard `ocamlopt` is adequate for development and Flambda provides meaningful but expensive improvement for release builds — suggests a compiler architecture that lacks a smooth optimization spectrum. LLVM's optimization pipeline, by contrast, provides genuinely incremental cost at `-O1`, `-O2`, and `-O3`. Language designers building compilers from scratch should target a smooth optimization curve: each optimization level should provide proportional benefit at proportional cost, not binary mode-switching with dramatically different compilation times.

**5. The boxing model is the primary performance ceiling for statically compiled GC'd languages with parametric polymorphism.**

OCaml's 2–5x performance gap vs. C is driven less by GC overhead and more by the **boxing of polymorphic values**, which prevents the compiler from generating cache-friendly, flat data structures and limits auto-vectorization. The approaches for resolving this are known: monomorphization (Rust, C++ templates), JIT specialization (JVM, V8), or explicit mode/annotation-based unboxing (OxCaml's local modes, Haskell's UNPACK pragmas). A language targeting both polymorphism and performance should make one of these choices explicitly at design time rather than retrofitting it. OCaml's path — GC'd parametric polymorphism as the default, unboxing experiments as the fork — demonstrates the cost of not making the choice upfront.

**6. A sound static native compiler with a GC optimized for the target language's allocation patterns can match JIT-compiled languages without JIT complexity.**

The CLBG data shows OCaml competitive with Java and C# on many benchmarks, despite Java and C# having had enormous JIT engineering investment. OCaml achieves this through a combination of: a well-designed static compiler (`ocamlopt`), a GC tuned for functional-language allocation patterns (many short-lived values, efficient nursery collection), and predictable execution with no warmup. Language designers who require predictable low-latency performance — where JIT warmup, recompilation pauses, and JIT deoptimization spikes are unacceptable — can achieve competitive throughput via careful static compilation and GC design without JIT complexity. The key is that the GC must be optimized for the allocation profile the language actually produces.

---

## References

[OCAML-GC-DOCS] "Understanding the Garbage Collector." OCaml Documentation. https://ocaml.org/docs/garbage-collector (accessed February 2026)

[OCAMLPRO-BESTFIT] "An In-Depth Look at OCaml's new 'Best-fit' Garbage Collector Strategy." OCamlPro Blog, March 2020. https://ocamlpro.com/blog/2020_03_23_in_depth_look_at_best_fit_gc/

[MULTICORE-CONC-PARALLELISM] "Concurrency and parallelism design notes." ocaml-multicore Wiki, GitHub. https://github.com/ocaml-multicore/ocaml-multicore/wiki/Concurrency-and-parallelism-design-notes

[INFOQ-OCAML5] "OCaml 5 Brings Support for Concurrency and Shared Memory Parallelism." InfoQ, December 2022. https://www.infoq.com/news/2022/12/ocaml-5-concurrency-parallelism/

[TARIDES-52] "The OCaml 5.2 Release: Features and Fixes!" Tarides Blog, May 2024. https://tarides.com/blog/2024-05-15-the-ocaml-5-2-release-features-and-fixes/

[OCAML-RELEASES] "OCaml Releases." ocaml.org. https://ocaml.org/releases (accessed February 2026)

[JANESTREET-OXCAML] "Introducing OxCaml." Jane Street Blog, June 2025. https://blog.janestreet.com/introducing-oxcaml/

[JANESTREET-OXIDIZING] "Oxidizing OCaml: Data Race Freedom." Jane Street Blog. https://blog.janestreet.com/oxidizing-ocaml-parallelism/

[REAL-WORLD-OCAML-BACKEND] "The Compiler Backend: Bytecode and Native code — Real World OCaml." https://dev.realworldocaml.org/compiler-backend.html (accessed February 2026)

[CLBG-OCAML] "OCaml performance measurements (Benchmarks Game)." https://benchmarksgame-team.pages.debian.net/benchmarksgame/measurements/ocaml.html

[CLBG-C-VS-OCAML] "C clang vs OCaml — Which programs are fastest? (Benchmarks Game)." https://benchmarksgame-team.pages.debian.net/benchmarksgame/fastest/clang-ocaml.html

[OCAML-NATIVE-VS-BYTE] "OCaml performance — native code vs byte code." Ivan Zderadicka, Ivanovo Blog. https://zderadicka.eu/ocaml-performance-native-code-vs-byte-code/

[TARIDES-MEMSAFETY] "OCaml: Memory Safety and Beyond." Tarides Blog, December 2023. https://tarides.com/blog/2023-12-14-ocaml-memory-safety-and-beyond/

[ICFP-RETRO-2020] Sivaramakrishnan, K.C. et al. "Retrofitting Parallelism onto OCaml." ICFP 2020 (Distinguished Paper). https://dl.acm.org/doi/10.1145/3408995

[PLDI-EFFECTS-2021] Sivaramakrishnan, K.C. et al. "Retrofitting Effect Handlers onto OCaml." PLDI 2021. https://dl.acm.org/doi/10.1145/3453483.3454039

[ZINC-1990] Leroy, X. "The ZINC experiment: An Economical Implementation of the ML Language." INRIA Technical Report, 1990. https://inria.hal.science/inria-00070049

[PARALLEL-TUTORIAL] "A tutorial on parallel programming in OCaml 5." OCaml Discourse. https://discuss.ocaml.org/t/a-tutorial-on-parallel-programming-in-ocaml-5/9896

[TARIDES-WASM] "WebAssembly Support for OCaml: Introducing Wasm_of_Ocaml." Tarides Blog, November 2023. https://tarides.com/blog/2023-11-01-webassembly-support-for-ocaml-introducing-wasm-of-ocaml/

[CVEDETAILS-OCAML] "Ocaml: Security vulnerabilities, CVEs." CVEdetails. https://www.cvedetails.com/vulnerability-list/vendor_id-10213/Ocaml.html (accessed February 2026)

[OCAML-ERROR-DOCS] "Error Handling." OCaml Documentation. https://ocaml.org/docs/error-handling (accessed February 2026)

[TARIDES-JOURNEY-2023] "The journey of the Multicore OCaml project." Tarides Blog, 2023. (referenced in historian.md §4 as source for project timeline)
