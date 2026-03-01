# Haskell — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Haskell"
agent: "claude-agent"
date: "2026-02-28"
```

---

## Summary

The Haskell council has produced technically grounded perspectives on the compiler and runtime, and the factual baseline from the research brief is largely accurate. The council converges on the right high-level conclusions: lazy evaluation introduces systematic memory overhead, GHC's M:N threading model is a genuine engineering achievement, and compile-time performance is a meaningful productivity cost. What the council underweights is the *implementation-level* explanation for why these properties exist, which is where language designers can extract the most transferable lessons.

Three areas require sharpening. First, the council correctly identifies space leaks but does not fully explain the thunk-closure heap model that makes them inevitable: every unevaluated expression is a heap-allocated object, and the GC cannot reclaim it until evaluation forces it. This is a design-level commitment with deep runtime consequences, not merely a programmers-forgetting-to-use-foldl' problem. Second, the M:N scheduler is uniformly praised, but a factual error in the research brief (and reproduced in council perspectives) mischaracterizes the default capability count: programs run on a single capability unless the programmer explicitly enables parallelism via `+RTS -N`. Third, the optimization pipeline's opacity — the reason 42% of practitioners cannot reason about performance — traces to specific compiler mechanisms (inlining thresholds and fusion eligibility) that the council names but does not mechanically explain. Naming these mechanisms makes the design lesson generalizable.

One cross-section flag: the council's treatment of LinearTypes as a current safety mechanism (Section 2) overstates its maturity. GHC 9.0 introduced LinearTypes as explicitly experimental with unstable syntax. Language designers should not treat this as a deployed resource-safety feature comparable to Rust's borrow checker.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

All five council members correctly characterize the safety properties of the pure fragment: no buffer overflows (no pointer arithmetic available to pure code), no null pointer dereferences (optionality expressed via `Maybe` with type-enforced handling), no use-after-free (GC manages all pure values), and no data races on immutable values (simultaneous reads always safe). These are categorical guarantees, not probabilistic reductions, and the council is right to present them as such [HASKELL-98-PREFACE; GHC-MEMORY-WIKI].

The GC architecture description is accurate. GHC uses a generational collector with a nursery (~512KB by default, configurable with `-A`) and major collections that traverse older generations [GHC-RTS-EZYANG]. The practitioner correctly identifies the key tuning parameters (`-A`, `-G`, `-qn`) and accurately notes that GC tuning for latency-sensitive services requires RTS expertise that most teams lack.

The 3–5x memory consumption gap versus C clang, cited from Benchmarks Game data [BENCHMARKS-GAME-GHC-CLANG], is correctly cited across all five perspectives with appropriate attribution.

The FFI boundary analysis is accurate: every council member correctly identifies that Haskell's memory safety guarantees terminate at the C FFI boundary, and that Foreign.Marshal.Alloc and Storable shift manual memory management responsibility back to the programmer [HASKELL-FFI-RWH].

Standard Chartered's adoption of Mu — a strict variant of Haskell for their multi-million-line production codebase — is accurately cited by the detractor as evidence that lazy-by-default is unsuitable at large scale [SEROKELL-SC].

**Corrections needed:**

The council consistently characterizes space leaks as a bug-category or a programmer discipline failure. From a compiler perspective, this framing understates how deep the mechanism runs. In GHC's runtime, every unevaluated expression is a *heap-allocated thunk object* — a closure containing a code pointer and its free variables. This is not an implementation choice made for laziness; it is the defining characteristic of the lazy evaluation strategy. The heap must hold all deferred computations as first-class objects until they are demanded. Accordingly, the memory cost of laziness is not correctable by discipline alone: even a strict Haskell programmer using `foldl'` and `BangPatterns` is writing code that is compiled against an RTS fundamentally designed around heap-allocated thunks. The overhead is structural.

A related point the council does not make explicit: GHC's GC cannot use read barriers or write barriers for *pure* (immutable) data. This is actually a performance *advantage* over Java's generational GC — Java must maintain remembered sets via write barriers on every pointer store, because mutable objects in old generations can point to young generation objects. In GHC, pure values cannot be mutated after allocation, so no write barrier is needed for them. The only write barriers in GHC are for mutable cells (`IORef`, `MVar`, `TVar`). This means GHC's GC can be faster than Java's per collection, even though Haskell allocates more objects overall. The council does not mention this advantage.

The detractor's claim that "GC pauses are inherent" and Haskell is "inappropriate for latency-sensitive applications without substantial RTS tuning" is accurate in the general case, but should be qualified: GHC's incremental GC options (`-I` flag, parallel minor GC with `-qn`) can substantially reduce worst-case pause times for latency-sensitive services. The detractor frames this as a hard limitation when it is a solvable problem with moderate engineering investment.

**Additional context:**

The indirection object mechanism is relevant to the memory consumption discussion: after a thunk is evaluated, GHC overwrites its header with an *indirection* pointing to the computed value. The original thunk memory is then collectable, but until the GC runs, both the indirection and the value coexist. Profiling with `-prof -hT` (heap profile by type) visualizes these indirections and thunks and is the primary diagnostic tool for space leak investigation — the practitioner's account of profiling friction is accurate.

The `String = [Char]` representation is an architectural decision with runtime consequences: each character is a heap-allocated `Char` object linked via a spine of `(:)` constructors. The practitioner correctly identifies that production Haskell immediately reaches for `text` (for UTF-16 encoded text) and `bytestring` (for binary data), but the reason is not just API preference — it is that `[Char]` incurs pointer indirection and GC overhead proportional to string length. This is a case where the standard library's default representation is a compile-time and runtime liability simultaneously.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

The M:N threading architecture is correctly described. GHC's lightweight green threads (Haskell threads) are scheduled onto OS threads called Capabilities (also called Haskell Execution Contexts, HECs). The research brief and council perspectives correctly note that each Capability has its own nursery, can run one Haskell thread at a time, and that blocking safe FFI calls trigger OS-thread provisioning to keep the Capability unblocked [GHC-SCHEDULER-EZYANG; GHC-CONCURRENT-GUIDE]. This is accurate and important: it is what prevents blocking I/O calls from stalling the entire runtime.

The STM correctness properties are accurately stated by all council members: `atomically` provides all-or-nothing semantics over `TVar`s, automatic retry on conflict, and composability via sequential bind and `orElse` [HASKELL-WIKI-STM]. The apologist's observation that STM composability is impossible with mutex-based programming — composing two lock-acquire operations risks deadlock without globally consistent lock ordering — is correct and is the core of STM's value proposition.

The async exception mechanism — `throwTo`, `mask`, `uninterruptibleMask`, `bracket` — is accurately described as sharp-edged and expert-level. The practitioner correctly identifies that code that appears pure can be interrupted mid-operation by an asynchronous exception, requiring explicit masking in resource-management code. This is a genuine runtime complexity that the research brief accurately characterizes as "distinctive and often surprising" [RWH-ERROR].

The sparks/parallelism advisory nature is correctly and consistently noted by the realist and practitioner: sparks are hints to the runtime's work-stealing scheduler, not guaranteed parallelism. This makes them unreliable for performance-critical parallel workloads.

The detractor's observation that FFI-heavy programs may inadvertently create large numbers of OS threads (one per concurrent blocking safe FFI call) is accurate and under-discussed in the community.

**Corrections needed:**

The research brief states that the number of Capabilities "defaults to number of CPU cores" [GHC-CONCURRENT-GUIDE]. The practitioner correctly contradicts this: GHC-compiled programs default to *one* Capability (single-threaded execution mode) unless the programmer explicitly enables parallelism via `+RTS -N` at runtime or sets capabilities programmatically with `GHC.Conc.setNumCapabilities` [GHC-CONCURRENT-GUIDE]. The `-N` flag *without* an argument defaults to the number of CPU cores, but passing no RTS flags defaults to 1. This distinction is the source of the "leaving hardware on the table" footgun the practitioner correctly identifies. The research brief's phrasing should be read as describing what `-N` alone does, not what the default is when no RTS flags are passed.

The apologist's description of structured concurrency is accurate but the claim that the `async` library "anticipated patterns that Swift Concurrency and Kotlin coroutines later formalized" requires contextual precision. The `async` library provides structured concurrency via the `withAsync` pattern (coupling task lifecycle to a lexical scope). This was indeed prior to Swift Concurrency (Swift 5.5, 2021) and Kotlin's structured concurrency formalizations. The underlying idea of scoped thread cancellation predates Haskell — it appears in Erlang's supervision trees — but the `async` library's formulation as a Haskell library is genuinely influential.

**Additional context:**

The STM implementation mechanism is worth making explicit for language designers. GHC's STM uses optimistic concurrency control: a transaction logs all `TVar` reads and planned `TVar` writes in a thread-local transaction log. At commit time, the runtime validates that all read `TVar`s are still at their logged values (using compare-and-swap) and, if so, atomically applies the writes. If validation fails, the transaction log is discarded and the transaction body is re-executed from scratch. This has implications:

1. Transaction bodies may execute multiple times — they should not have observable side effects. An IO action inside `atomically` is a type error in standard Haskell (`STM` and `IO` are separate monads), which correctly prevents this.
2. Transaction bodies that touch many `TVar`s have larger logs and higher validation costs.
3. Long-running transactions under high contention can livelock (repeatedly fail validation and retry). The `check` and `retry` primitives provide blocking retry (waiting for a `TVar` to change before retrying), which addresses spin-retry but not livelock from external modification.

The preemption mechanism for Haskell threads is worth naming: GHC's scheduler uses POSIX signals (specifically `SIGALRM` via a periodic timer) to preempt Haskell threads at safe points. The timer fires approximately every 20ms by default. This is fundamentally different from Go's approach (cooperative yields at function call sites and memory allocation points), which produces more predictable preemption timing. GHC's signal-based approach can be interrupted at more arbitrary points, which contributes to the complexity of async exception handling — an async exception can arrive at any safe point, not only at explicit yield points.

The detractor's claim that "no structured concurrency in the language" is technically correct: structured concurrency is not a language primitive in Haskell, only a library pattern. However, the practical consequence is less severe than the framing suggests: `async` is effectively a standard library for concurrent Haskell (used by default in most professional codebases), and the Haskell Foundation has encouraged treating `async` patterns as the idiomatic approach. The gap is real but not as severe as comparable situations in languages where structured concurrency alternatives are genuinely fragmented.

---

### Section 9: Performance Characteristics

**Accurate claims:**

The Benchmarks Game figures are accurately cited across all perspectives: GHC runs 1.1x–4.3x slower than C clang on the tested benchmarks, with 3–5x higher memory consumption [BENCHMARKS-GAME-GHC-CLANG]. The research brief correctly qualifies these as figures for well-optimized GHC code compiled with `-O2`; naïve Haskell performs worse. All council members correctly reproduce this qualification.

The compilation speed characterization is accurate and well-sourced [PARSONSMATT-FAST; SUMTYPEOFWAY-ITERATION]. The specific mechanism — superlinear scaling with module size — is correctly named. The practitioner correctly identifies that type family evaluation and type class constraint resolution are major contributors to compile-time cost.

The LLVM backend tradeoff (faster generated code at the cost of longer compile times) is correctly described by both the apologist and practitioner. The observation that most teams use the native code generator in development and evaluate LLVM for performance-critical paths is sound practical advice [GHC-SOONER].

The practitioner's description of GHC's fusion mechanism (eliminating intermediate data structures in streaming pipelines) is accurate: list fusion via `build`/`foldr` and `Data.Text`'s stream fusion eliminate intermediate allocations between composed transformations, allowing pipeline code to approach hand-optimized loop performance.

Meta's Sigma system processing over 1 million requests per second is cited consistently and is the right production-scale evidence for GHC's concurrent throughput capability [SEROKELL-META].

**Corrections needed:**

The apologist claims the LLVM backend provides "10–30% performance improvement in compute-heavy paths." This is a rough estimate without specific supporting evidence in the research brief. Actual LLVM vs. native code generator differences vary substantially by workload — benchmark-game-style numeric kernels can see 15–40% improvements due to LLVM's vectorization (using SIMD instructions), while code dominated by allocation and GC is unlikely to see meaningful improvement from the backend choice. The 10–30% figure is defensible as a rough estimate for compute-heavy pure code but should not be cited as a data-backed range without a source. Language designers should understand that the native code generator is a custom backend with limited instruction selection, while the LLVM backend leverages decades of LLVM optimization and instruction scheduling work.

The realist's claim that GHC's simplifier "can dramatically change performance based on small code changes" is correct, but the mechanism should be named: the critical variable is GHC's *inlining threshold*. GHC's inliner estimates the size of a function's "unfolding" (what it would look like inlined) and inlines it at call sites if the estimated size is below a threshold. `INLINE` and `NOINLINE` pragmas force or suppress this. When a small change to a function body pushes its estimated size across an inlining threshold, the function may stop being inlined, which can prevent downstream optimizations (including fusion and common-subexpression elimination) from firing. This is why "the compiler often produces faster code than the programmer expects" but also why small refactors can produce large performance regressions. A language designed for performance predictability should provide programmers with explicit control over these thresholds, or make the inlining decisions visible in the compilation output.

**Additional context:**

The `GHC.Exts.Addr#`, `Int#`, `Double#` unboxed types are the key mechanism for achieving C-comparable performance on numeric code. GHC's standard integer type (`Int`) is a boxed, heap-allocated object with a pointer to a machine word. Unboxed integers (`Int#`) are machine words directly — no heap allocation, no pointer indirection. The worker/wrapper transformation automatically introduces unboxing for strict function arguments when the optimizer can determine that the box is never shared — this is how a Haskell function on `Int` values can compile to code as efficient as the equivalent C function on `int`. The practitioner correctly identifies that switching to unboxed types (and avoiding `String`) is part of the "expert-level tuning" for benchmark performance, but does not explain that the worker/wrapper transformation automates this for strict functions. When the transformation fires reliably, naive Haskell code on strict integers approaches C performance without explicit annotation.

The practitioner correctly notes that profiling Haskell programs requires compiling with `-prof` flags that produce binaries with different performance characteristics than production builds. This is a genuine limitation with an implementation explanation: the profiling infrastructure adds per-closure cost-centre annotations and a shadow stack for attribution, which alters both the performance profile and GHC's optimization decisions (some optimizations are disabled under profiling to preserve accurate attribution). Go's `pprof` can be attached to a running production binary; GHC's profiling requires a separate build artifact. The eventlog (`-eventlog` flag) is a lower-overhead alternative for concurrency and GC analysis that works with release builds, but does not provide cost-centre-level attribution.

The startup time issue (GHC executables have non-trivial startup costs from RTS initialization [GHC-RTS-EZYANG]) is correctly identified. The RTS initialization includes: heap allocation setup, capability initialization, signal handler installation, and GHC's internal statistics state. For serverless and CLI tool contexts, this is operationally significant. The JavaScript and WebAssembly backends introduced in GHC 9.6 have different startup characteristics (browser JS environments amortize startup differently), but these backends are not yet suitable for production latency-sensitive deployments.

---

### Other Sections (compiler/runtime issues)

**Section 2: Type System — LinearTypes maturity**

The council (historian and apologist particularly) mentions `LinearTypes` as part of GHC's type system and in some cases implies it is a deployed resource-safety feature comparable in maturity to the rest of the type system. This is a significant overstatement of the current state. The research brief accurately notes that LinearTypes was "shipped experimentally in GHC 9.0 (2020)" with the GHC documentation explicitly warning "expect bugs, warts, and bad error messages; everything down to the syntax is subject to change" [GHC-LINEAR-TYPES]. As of GHC 9.14.1 (February 2026), LinearTypes remains in the extension ecosystem without a stability guarantee. Production codebases should not rely on LinearTypes for resource-safety invariants, and language designers should not cite Haskell's linear types as a proven deployment of linear type theory. The feature is research-oriented and instructive as a proof of concept, not a production mechanism.

The compile-time cost of advanced type system features is not discussed by the council but is significant. Type family evaluation, class instance resolution for deeply-nested constraint hierarchies, and GADTs all increase type-checking time substantially. The "superlinear scaling with module size" that the research brief identifies for compilation is driven partly by these type system costs. Language designers who adopt rich type systems (type families, higher-kinded types, GADTs) should anticipate that type inference and checking will dominate compilation time for sufficiently complex programs.

**Section 6: Ecosystem and Tooling — HLS coupling**

The detractor correctly identifies that HLS requires a precisely matching GHC version and that incompatible combinations fail entirely. The compiler-level explanation: HLS depends on GHC's internal API (the `ghc` library), which is explicitly not a stable interface. Each GHC release may change type signatures, module structure, or semantics of internal APIs without backward compatibility guarantees. HLS must therefore be rebuilt and tested against each new GHC version. This is a structural toolchain fragility, not a quality issue with HLS's engineering. The practical consequence for language designers is that building rich IDE integration on top of an unstable compiler API creates permanent maintenance overhead. Languages that ship a stable, documented compiler API (even a limited one) reduce this coupling dramatically.

**Section 10: Interoperability — `safe` vs `unsafe` FFI**

The apologist correctly identifies the `safe`/`unsafe` FFI modifier distinction and characterizes it as a design virtue: "Haskell's FFI design forces the programmer to choose, and documents the consequences of each choice" [HASKELL-FFI-RWH]. The compiler-level detail that strengthens this claim: `unsafe` FFI calls bypass GHC's scheduler and run on the current OS thread without yielding, which is faster but means the current Capability is blocked for the duration of the call. `safe` FFI calls allow GHC's scheduler to run on another OS thread, supporting concurrent Haskell thread execution during the foreign call. The `unsafe` mode is appropriate for short, non-blocking C calls (e.g., calling a math function); `safe` mode is required for calls that may block (e.g., a syscall). Incorrect use of `unsafe` for a blocking call stalls the entire Capability, preventing other Haskell threads from running. This distinction is compiler-enforced only in the sense that the programmer must choose — GHC does not analyze call duration or blocking behavior. It is documentation-enforced safety rather than type-enforced safety.

---

## Implications for Language Design

The Haskell runtime reveals six design lessons that are directly applicable to language designers:

**1. Lazy-by-default is an evaluation strategy that requires the entire runtime system to be designed around deferred computation — there is no cheap way to add laziness selectively later.**

GHC's heap model (every expression is a potential thunk, every thunk is a heap-allocated object, the GC cannot reclaim unevaluated computations) exists because lazy evaluation is the foundational commitment of the runtime. The space leak problem, the memory consumption overhead, and the performance opacity are not incidental — they are consequences of this architectural choice. Languages that want lazy sequences or lazy streams should provide them as an explicit data structure (like Rust's `impl Iterator` or Haskell's `Data.List.Lazy`) rather than making all evaluation lazy. Mixing lazy and strict evaluation at the term level (rather than the type level) creates a runtime that serves neither model well.

**2. M:N green thread schedulers deliver high-concurrency scalability, but only if parallelism is opt-in rather than opt-out — and that default must be prominently communicated.**

GHC's scheduler is genuinely sophisticated and GHC's green threads are a proven approach to high-concurrency server workloads. But the default of 1 Capability (single-threaded execution) means that programs silently leave multi-core hardware unused unless the programmer takes explicit action. Go addressed this by defaulting to `GOMAXPROCS = NumCPU` from Go 1.5 onward. Language designers implementing M:N threading should either default to all cores (Go's approach) or make the setting explicit at program startup (requiring acknowledgment rather than inference from a missing flag). Invisible defaults that cap hardware utilization are a reliability risk as deployment environments change.

**3. Software Transactional Memory composability requires a clear runtime implementation model — the retry semantics have performance consequences that users must understand.**

GHC's STM using an optimistic log-based commit protocol is an elegant design, but it means transaction bodies can execute multiple times and that validation cost scales with transaction log size. Language designers adopting STM should document these semantics explicitly and provide tooling to detect high-retry scenarios. The underlying lesson is not "don't use STM" — Meta's Sigma system demonstrates it works at scale — but that STM performance is workload-sensitive in a way that mutex-based locking is not. STM excels when contention is low; it degrades predictably when contention is high. Designers who adopt STM should pair it with profiling visibility into retry rates.

**4. Compiler optimization pipelines that produce dramatically different code from small source changes require programmer-visible optimization status tooling.**

GHC's inliner, fusion rules, and worker/wrapper transformation collectively determine whether Haskell programs run at C-like speed or at interpreted-Python-like speed. The problem is not that these optimizations are wrong but that their triggering conditions are invisible during development. The `42% of practitioners cannot reason about performance` finding is a direct consequence of invisible compiler decisions. Language designers who adopt aggressive optimizing compilers should invest in tooling that shows programmers when key optimizations (inlining, fusion, unboxing) are firing or not firing. GHC's `-ddump-simpl` and `-ddump-rule-firings` flags provide this information but require expert interpretation. A language that surfaces this information in an IDE or in annotated compiler output would significantly lower the performance reasoning burden.

**5. The GC write-barrier asymmetry between mutable and immutable data is a performance advantage worth designing for explicitly.**

Haskell's immutability-by-default means that GHC's generational GC requires write barriers only for explicit mutable cells (`IORef`, `MVar`, `TVar`). Java's GC requires write barriers for all reference-type field writes because any object can be mutated at any time. The consequence is that GHC's GC can scan young-generation roots faster than Java's for equivalent working sets, despite Haskell allocating more objects. Language designers who use generational GC should explicitly design their mutability model to minimize write-barrier overhead — making mutation opt-in (rather than default) directly reduces GC overhead, independent of correctness benefits.

**6. Compiler API stability is a load-bearing infrastructure decision for the IDE ecosystem — an unstable internal API creates permanent maintenance overhead for all tooling built on it.**

GHC's `ghc` library (the compiler's internal API) is not a stable interface, and HLS must be rebuilt against each GHC release because of this. This creates the recurring situation where a new GHC version releases without HLS support, forcing developers to choose between new language features and IDE functionality. Languages that want a rich IDE ecosystem should define a minimum stable compiler API — covering name resolution, type information, and error reporting — as a first-class specification artifact maintained with the same backward-compatibility discipline as the language itself. Rust's `rust-analyzer` benefits from a more cooperative relationship with the Rust compiler team; Go's `gopls` uses Go's `go/types` package which has stable documented semantics. The lesson from Haskell's HLS fragility is that IDE tooling should not depend on implementation-internal compiler APIs.

---

## References

[GHC-RTS-EZYANG] Ezyang, E. "Anatomy of a Haskell Runtime." http://blog.ezyang.com/2011/04/anatomy-of-a-haskell-runtime/ — primary source for GHC nursery size, generational GC architecture, capability model.

[GHC-MEMORY-WIKI] GHC Developer Wiki. "Memory Management." https://ghc.haskell.org/trac/ghc/wiki/Commentary/Rts/Storage/HeapObjects — thunk representation, indirection objects, GC interaction.

[GHC-CONCURRENT-GUIDE] GHC User's Guide. "Concurrent and Parallel Haskell." https://downloads.haskell.org/ghc/latest/docs/users_guide/parallel.html — capabilities, RTS flags, safe/unsafe FFI.

[GHC-SCHEDULER-EZYANG] Ezyang, E. "The GHC Scheduler." http://blog.ezyang.com/2013/01/the-ghc-scheduler/ — M:N threading, capability model, preemption mechanism.

[HASKELL-WIKI-STM] HaskellWiki. "Software Transactional Memory." https://wiki.haskell.org/Software_transactional_memory — STM primitives, retry semantics, composability.

[BENCHMARKS-GAME-GHC-CLANG] Benchmarks Game. GHC vs. C clang results. https://benchmarksgame-team.pages.debian.net/benchmarksgame/fastest/haskell-gcc.html — hardware: Ubuntu 24.04, x86-64, Intel i5-3330 quad-core, 3.0 GHz, 15.8 GiB RAM.

[GHC-PIPELINE-MEDIUM] "GHC Compilation Pipeline." https://medium.com/@zw3rk/a-haskell-compiler-tutorial-part-1-5 — pipeline stages: parsing, renaming, typechecking, desugaring, Core, STG, C--, native/LLVM backends.

[GHC-SOONER] GHC User's Guide. "Optimisation." https://downloads.haskell.org/ghc/latest/docs/users_guide/using-optimisation.html — -O vs. -O2 distinction, LLVM backend flag.

[GHC-LINEAR-TYPES] GHC User's Guide. "Linear Types." https://downloads.haskell.org/ghc/latest/docs/users_guide/exts/linear_types.html — explicit stability warning; introduced GHC 9.0.

[GHC-9.4-RELEASED] GHC Blog. "GHC 9.4.1 Released." https://www.haskell.org/ghc/blog/20220808-ghc-9.4.1-released.html — structured diagnostic API, incremental compilation improvements.

[GHC-9.6-NOTES] GHC Blog. "GHC 9.6.1 Released." https://www.haskell.org/ghc/blog/20230310-ghc-9.6.1-released.html — WebAssembly and JavaScript backends.

[GHC-SAFE-HASKELL] GHC User's Guide. "Safe Haskell." https://downloads.haskell.org/ghc/latest/docs/users_guide/safe_haskell.html — Safe/Trustworthy/Unsafe pragma system.

[HASKELL-FFI-RWH] Sullivan, O'Sullivan, Stewart, Goerzen. *Real World Haskell*, Chapter 17: "Foreign Function Interface." O'Reilly, 2008. http://book.realworldhaskell.org/read/interfacing-with-c-the-ffi.html — Storable, Foreign.Marshal.Alloc, safe/unsafe modifier semantics.

[PARSONSMATT-FAST] Parsons, M. "Keeping Compilation Fast." https://www.parsonsmatt.org/2019/11/27/keeping_compilation_fast.html — superlinear compilation scaling, module size strategies.

[SUMTYPEOFWAY-ITERATION] "Measuring GHC's compilation times." https://www.sumtypeofway.com/posts/fast-iteration-with-haskell.html — industry practitioner account of compilation speed as productivity concern.

[SEROKELL-META] Serokell. "Haskell in Industry: Meta." https://serokell.io/blog/haskell-in-industry — Sigma system at 1M+ requests/second, Haxl automatic parallelism.

[SEROKELL-SC] Serokell. "Haskell in Industry: Standard Chartered." https://serokell.io/blog/haskell-in-industry — Mu strict Haskell variant, 5M+ line codebase.

[HASKELL-SURVEY-2022] "State of Haskell Survey 2022." https://taylor.fausak.me/2022/11/18/haskell-survey-results/ — performance reasoning (42%), satisfaction (79%), tooling adoption figures.

[HSEC-2024-0003] Haskell Security Response Team. "HSEC-2024-0003: process library Windows command injection." https://github.com/haskell/security-advisories/blob/main/advisories/hackage/process/HSEC-2024-0003.md — CVSS 9.8, CVE-2024-3566.

[HASKELL-98-PREFACE] Jones, S.P. et al. "Haskell 98 Language and Libraries: The Revised Report — Preface." 2003. https://www.haskell.org/onlinereport/preface-jfp.html

[GHC-EXTENSIONS-CTRL] GHC User's Guide. "Language options." https://downloads.haskell.org/ghc/latest/docs/users_guide/exts/control.html — GHC2021, GHC2024 editions.

[ENDOFLIFE-GHC] GHC LTS policy. https://endoflife.date/ghc — GHC 9.14.1 first LTS release, two-year support minimum.

[RWH-ERROR] Sullivan, O'Sullivan et al. *Real World Haskell*, Chapter 19: "Error Handling." — runtime exception model vs. type-based model.

[UNSAFE-HASKELL-PENN] University of Pennsylvania CIS 552. "Unsafe Haskell." https://www.cis.upenn.edu/~cis1940/spring13/lectures/unsafe.html — unsafePerformIO, unsafeCoerce, unsafe FFI imports.
