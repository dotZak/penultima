# Mojo — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Mojo"
agent: "claude-sonnet-4-6"
date: "2026-02-26"
schema_version: "1.1"
```

---

## Summary

Mojo's compiler and runtime design is technically serious and built on a genuine infrastructure investment — MLIR, co-designed by the language's own creator [MOJO-VISION]. The core mechanisms being described across the council are real: ASAP destruction is a well-defined semantic (sub-expression liveness, not scope-exit), the argument conventions (read/mut/owned/out) are correctly understood to be compiler-enforced contracts, and the GPU compilation story via MLIR/KGEN is verifiably working at a level competitive with CUDA for memory-bound kernels [WACCPD2025]. The council perspectives are largely accurate on these points, and the single independent peer-reviewed benchmark — from Oak Ridge National Laboratory — gives the performance claims a credible anchor that vendor numbers alone do not.

Two areas require substantial correction or amplification that the council underweights. First, the compiler's correctness guarantees are less settled than the clean semantic descriptions imply. ASAP destruction requires sub-expression liveness analysis that is non-trivially harder to implement correctly than scope-based drop elaboration, and no independent formal verification of Mojo's borrow checker has been published [MOJO-CVE]. Documented SIGSEGV-level compiler crashes [GH-2513] and parser failures [GH-1295] are not merely tooling inconveniences — they are evidence that a young compiler has not yet been hardened by the volume of adversarial input that stabilizes compilation reliability. Second, the performance narrative conflates three distinct data sources — a methodologically flawed first-party microbenchmark, a credible peer-reviewed kernel study, and entirely unverified inference serving claims — without clearly separating them. Language designers assessing Mojo's performance story need to know which evidence is load-bearing.

The concurrency situation is correctly identified across council members as the most significant gap: no `Send`/`Sync` equivalent, no stabilized async model, no structured concurrency, all deferred post-1.0. From a compiler perspective, the deeper issue is that the GPU execution model and the CPU execution model require fundamentally different compiler representations for concurrency, and Mojo has invested in the GPU side first. The correctness of the GPU synchronization model (barriers, warp-level operations, KGEN code generation) is backed by the ORNL study but has not been independently assessed for correctness guarantees — only for performance parity with CUDA. Whether MLIR's GPU lowering path produces correct synchronization in all cases, not just fast results on tested kernels, is an open question.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- ASAP (As Soon As Possible) destruction semantics are correctly described across all five council members: values are destroyed at the last point of use within a sub-expression, not at end-of-scope as in Rust [MOJO-LIFECYCLE]. The realist's formulation is the most precise: in `a+b+c+d`, intermediate values are destroyed before the expression completes.
- The four argument conventions (read, mut, owned, out) are accurately presented as compiler-enforced contracts over how values cross function boundaries [MOJO-OWNERSHIP]. The practitioner correctly notes the rename from `inout` to `mut` in the 0.x series as a usability iteration.
- The claimed mitigations — buffer overflows, use-after-free, double-free — are correct for safe code going through the borrow checker. These map to CWEs that the design explicitly addresses: CWE-120, CWE-416, CWE-415 [MOJO-CVE].
- The Python interoperability boundary as a safety gap is correctly identified by the detractor, practitioner, and realist: the CPython runtime uses reference counting with GC assistance, which is fundamentally incompatible with ASAP destruction at the language boundary [MOJO-PYTHON].
- Linear types (v0.26.1) as an extension for explicit resource management is accurately characterized by the historian and realist [MOJO-CHANGELOG].

**Corrections needed:**

- **Borrow checker maturity is understated.** The detractor notes that "there are no documented formal verification results for Mojo's ownership rules" and that the checker is less than two years old, but does not fully explain why this matters at the implementation level. Rust's borrow checker underwent substantial reformalization with Non-Lexical Lifetimes (NLL, stabilized 2018) and is undergoing further formalization via the Polonius project — both motivated by discovering that earlier implementations were either too conservative or had unsoundness edge cases [RUST-NLL]. Mojo's borrow checker is pre-NLL-equivalent: the formal properties of its lifetime inference algorithm have not been published or independently reviewed.
- **ASAP destruction requires sub-expression liveness analysis, which is harder to implement correctly than scope-based drop elaboration.** Scope-based destructors (C++ RAII, Rust drop elaboration) insert drops at well-defined points — end of block. Sub-expression-level ASAP destruction requires the compiler to perform precise liveness analysis at the expression level, determine the last use point of each intermediate value within complex expressions, and insert destructor calls at those points. A bug in this analysis — underestimating the last-use point — produces use-after-free in safe code. An overestimate produces resource leaks. Neither failure mode is catchable by the borrow checker itself, since the borrow checker operates downstream of the liveness analysis. This is not hypothetical: documented SIGSEGV-level compiler crashes [GH-2513] in Mojo's 0.x series suggest the compiler has encountered liveness-related code generation failures in practice. No council member addresses this implementation-level risk clearly.
- **"Hybrid bounds checking" is mentioned in the evidence file [MOJO-CVE] but absent from council discussions.** The claim that Mojo uses a combination of compile-time array analysis and configurable runtime bounds validation needs scrutiny. Compile-time bounds check elimination is correct only when the optimizer can statically prove index bounds — for complex index expressions or data-dependent accesses, this is undecidable in the general case. A conservative bounds-check eliminator is sound but generates slower code; an aggressive eliminator may eliminate necessary checks. No council member addresses how Mojo's bounds check elimination policy is configured or how its correctness is validated.
- **The safety claim for linear types is overstated by the apologist.** Linear types (types where destruction must be explicit) provide stronger resource management invariants, but "explicit destruction" still depends on the developer writing the destructor call. The compiler verifies that destruction happens; it cannot verify that the destruction is semantically correct (e.g., that a network connection is flushed before closure). The practitioner correctly notes this is "the right design choice" but does not distinguish compile-time safety (destruction happens) from semantic correctness (destruction is correct).

**Additional context:**

The relationship between ASAP destruction and the compiler's intermediate representation is worth documenting for language designers. ASAP destruction is implemented by the compiler inserting destructor calls at precisely the last-use point as determined by liveness analysis. In MLIR, this corresponds to inserting `__del__` equivalent calls into the MLIR dialect operations before lowering. The correctness of this insertion depends on the MLIR lowering preserving liveness structure — specifically, that an MLIR optimization pass does not reorder operations in a way that moves a destructor before the last genuine use. Standard MLIR optimization passes (e.g., dead code elimination, common subexpression elimination) must be aware of destructor side effects to preserve correctness. This is a known correctness concern in languages with sub-expression destructors, but it has not been formally addressed in Mojo's published documentation.

The detractor's point about no Miri or AddressSanitizer equivalent is technically significant beyond the tooling observation. Rust's ASAN and Miri can detect unsafe-block violations at runtime during testing. Without equivalent tools, unsafe code in Mojo can only be validated through code review and correctness arguments — meaning that bugs in UnsafePointer usage will only surface in production or through crash reports, not during development. For a language targeting AI infrastructure where unsafe code is likely to appear in performance-critical inner loops, this tooling gap is a real risk vector.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- The GPU concurrency model is correctly described as the language's genuine differentiator: GPU compute kernels targeting NVIDIA (CUDA), AMD (HIP/ROCm), and Apple Silicon hardware via MLIR/KGEN, with barrier synchronization and warp-level operations [ARXIV-MOJO-SC25]. The ORNL peer-reviewed study confirms this capability is production-quality for memory-bound kernels.
- The absence of compile-time data race prevention equivalent to Rust's `Send`/`Sync` trait system is accurately stated by all council members who address concurrency. The realist's formulation is precise: the borrow checker provides exclusivity within its scope, but this does not generalize to concurrent thread execution [MOJO-CVE].
- The CPU async model's incompleteness is accurately documented: `async`/`await` keywords exist, but the model is explicitly listed as a post-1.0, Phase 2 goal on the roadmap [MOJO-ROADMAP, MOJO-1-0-PATH]. The practitioner correctly warns practitioners not to build concurrent server-side systems in Mojo today.
- The function coloring problem (async/sync divide) is correctly identified as present and unsolved in the current language.

**Corrections needed:**

- **The GPU compilation pipeline is described at a level of abstraction that elides important correctness questions.** Council members correctly describe that Mojo GPU kernels compile through MLIR/KGEN to CUDA/ROCm targets. But the compilation pipeline has multiple stages with correctness implications: Mojo source → Mojo-level MLIR dialect → optimization passes → NVVM IR (for NVIDIA) or ROCDL IR (for AMD) → PTX/LLVM GPU IR → CUDA compiler / ROCm compiler. At the ROCDL lowering stage for AMD, the WACCPD 2025 paper documents performance gaps for atomic operations [WACCPD2025]. From a compiler perspective, this is not merely a "performance gap" — it indicates that the MLIR-to-ROCDL lowering strategy for atomics is not yet at parity with hand-tuned HIP code. For developers writing kernels that depend on atomics (e.g., reduction operations, histogram construction, scatter-gather patterns common in sparse attention mechanisms), this is a functional correctness-vs-performance concern, not merely a benchmark footnote.
- **The claim that GPU synchronization is correct is verified for performance but not for correctness in adversarial cases.** The ORNL study demonstrates that Mojo kernels produce correct results on tested workloads and are competitive in performance. But correctness on benchmarked workloads does not certify that the synchronization model handles all race conditions correctly. CUDA's memory consistency model includes both intra-warp consistency and inter-block consistency, and expressing these correctly requires the compiler to insert the right memory fence operations at the right points. Whether Mojo's MLIR GPU lowering correctly models all synchronization patterns — not just the ones in benchmark kernels — has not been independently assessed.
- **The work-queue thread pool's runtime semantics are described without clarity on whether they constitute a stable API surface.** Multiple council members mention that "a work-queue thread pool underlies the runtime." This is documented in Mojo's early technical writing, but the runtime's public API surface (how developers interact with the thread pool, how work is scheduled, how cancellation is handled) is not stabilized. This matters for compiler-level analysis: if the runtime primitives are not stabilized, the compiler's ability to reason about async code's execution model is also unstabilized. Developers using `async`/`await` in early 2026 Mojo are using a combination of unstabilized language semantics and unstabilized runtime primitives.

**Additional context:**

The apologist makes a technically accurate and underappreciated point about typed errors and GPU semantics. Traditional exception mechanisms based on stack unwinding are incompatible with GPU execution: GPU kernels execute as massively parallel warps without a traditional call stack that can be unwound. Mojo's typed errors, which compile to alternate return values with no stack unwinding [MOJO-CHANGELOG], are not just a "zero-cost" performance optimization — they are a requirement for GPU correctness. A language with traditional exceptions could not compile error-propagating code to run in GPU kernels without either (a) disallowing exceptions in kernel code entirely (CUDA C++ approach) or (b) providing a separate error model for GPU code. Mojo's unification of the error model across CPU and GPU execution is a genuine design achievement that the council, aside from the apologist and historian, does not sufficiently credit.

The detractor makes a valid point about Triton's integration into `torch.compile()`. From a compiler perspective, Triton's advantage is that it operates within Python's existing compilation infrastructure — as a backend for PyTorch's JIT compiler — which means its integration with the broader AI training stack is zero-migration-cost. Mojo requires a language-level migration. The compiler-level question this raises: is Mojo's approach of building a new language with a MLIR-based compiler the right architectural choice compared to building better GPU-targeting extensions within an existing compiler framework? The honest answer is that Triton and Mojo are targeting different points in the optimization space: Triton targets NVIDIA hardware within PyTorch; Mojo targets portable multi-hardware compilation with a full language. Whether the broader target justifies the adoption cost is a legitimate architectural debate, not a question with a clear answer.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- The 35,000x Mandelbrot benchmark is correctly characterized as methodologically indefensible for language-to-language comparison by all council members who address it. The benchmarks evidence file [BENCHMARKS-PILOT] documents the critical context: the baseline is unoptimized CPython without NumPy; the Mojo version is fully optimized with static typing, SIMD, and MLIR compilation; the algorithm is maximally suited to SIMD vectorization. With NumPy as the baseline, the gap narrows to approximately 50–300x.
- The ORNL WACCPD 2025 peer-reviewed paper is correctly cited as the only independent performance benchmark as of early 2026, and its nuanced finding — competitive with CUDA/HIP for memory-bound kernels, gaps on AMD for atomic operations and compute-bound fast-math [WACCPD2025] — is accurately reported.
- Mojo's absence from the Computer Language Benchmarks Game and TechEmpower Framework Benchmarks is correctly noted as a significant gap for cross-language performance comparison [BENCHMARKS-PILOT].
- The explanation that Mojo's performance derives from three sources — static typing, MLIR-compiled native code, and explicit SIMD primitives — is accurate [BENCHMARKS-PILOT].

**Corrections needed:**

- **"12x faster than Python without optimization attempts" is ambiguous in a way no council member resolves.** The benchmarks file [BENCHMARKS-PILOT] attributes this to "the difference between interpreted dynamic typing and compiled static typing on representative numerical workloads." But "representative numerical workloads" is not specified. If the baseline includes NumPy (which most production Python numerical code uses), 12x would be remarkable and worth serious attention. If the baseline is pure CPython without NumPy, 12x is the expected speedup from static compilation and is not surprising. The claim's meaning depends entirely on the baseline, and Modular has not published the benchmark methodology for this specific figure. Council members treat "12x" as approximately correct without questioning what it is 12x faster than — a significant omission for a compiler-level analysis.
- **The Llama 3 inference claim (15–48% faster token generation) is structurally different from the kernel benchmarks and should not be cited in the same breath.** The ORNL study measures individual kernel performance. The Llama 3 inference claim measures end-to-end systems performance: model loading, memory allocation, kernel dispatch, quantization, batching, and network I/O all contribute. These two measures cannot be directly compared, and the sources are different in quality: the ORNL study is independent and peer-reviewed; the Llama 3 inference claim is first-party from Modular [BENCHMARKS-PILOT]. Several council members cite both in Section 9 without adequately distinguishing their evidential weight.
- **The "toolchain maturity" discussion underestimates the compiler maturity gap for non-GPU workloads.** The detractor notes that "optimization maturity is lower than GCC/Clang (which have 30+ years of development)." This is accurate but understated for a compiler assessment. GCC's GIMPLE optimization framework and LLVM's LLVM IR optimization passes embody decades of work specifically targeting loop analysis, alias analysis, vectorization, and inlining heuristics tuned against large bodies of real code. Mojo's MLIR-based optimizer is approximately 3–4 years old in terms of optimization passes that target Mojo-specific abstractions. For GPU kernel workloads where the performance bottleneck is memory bandwidth (which MLIR handles well), this maturity gap matters less. For general CPU workloads involving complex control flow, string processing, or data structures — domains where classic compiler optimizations matter most — the gap between Mojo's optimizer and GCC/Clang is likely to be measurable, and no independent benchmarks have assessed it.

**Additional context:**

Mojo's parametric code generation model deserves clearer explanation in the performance context, as it is a structural compiler-level advantage over both C++ templates and Python generics. When a developer writes `SIMD[DType.float32, 8]`, Mojo generates a specialized code path at compile time via MLIR parametric instantiation. Unlike C++ templates, which are text-expansion based and can produce large compiled binaries with redundant code, MLIR's parametric representation enables sharing of IR structure with specialization at the lowering stage. Unlike Python generics, there is no runtime dispatch overhead. This means that Mojo's performance for parametric numerical code (the dominant pattern in AI kernel development) is a genuine compiler-level advantage — not just static typing over dynamic typing, but a different code generation strategy. The council members describe this capability but do not explain why it is architecturally distinctive.

AOT versus JIT compilation modes (`mojo build` vs. `mojo run`) are mentioned by the practitioner but not analyzed for performance implications. AOT compilation allows link-time optimization (LTO) — the compiler can optimize across module boundaries, inline across compilation units, and perform global dead code elimination. JIT compilation adds startup latency but enables interactive development and can theoretically perform profile-guided optimization (PGO) based on runtime data. The performance benchmarks that Modular publishes do not distinguish which compilation mode was used, and the characteristics differ enough that this matters for performance comparison. No independent measurements of Mojo's AOT vs. JIT compilation speed or output quality have been published as of early 2026.

The evidence that compiler instability (SIGSEGV crashes [GH-2513], parser crashes [GH-1295], REPL failures [GH-712]) exists is relevant to performance claims because it constrains the optimizer's ability to apply aggressive transformations. Mature compilers apply aggressive optimizations only after those optimizations have been validated against large corpora of real code. A compiler that crashes on edge cases is a compiler that has not yet encountered the long tail of program patterns that motivate conservative optimization heuristics. This means reported performance figures may not be reproducible on production code with different program patterns than the benchmarked examples.

---

### Other Sections (compiler/runtime-relevant)

**Section 1: Identity and Intent — Compilation model positioning:**

The apologist and detractor debate the "N language problem" — whether Mojo genuinely replaces Python, C++, CUDA, and Triton. From a compiler perspective, this debate has a structural answer: Mojo's MLIR foundation makes the multi-target claim more credible than any single-target approach would be, but each new hardware target requires a new MLIR lowering pass that must be implemented and validated. The 2025 additions of NVIDIA Blackwell and AMD MI355X support [BENCHMARKS-PILOT] demonstrate that the lowering infrastructure scales to new hardware faster than LLVM-based approaches. But each new lowering pass introduces potential for correctness issues, and the growing list of targets increases the compiler's test matrix combinatorially. The N-language problem is more tractable with MLIR than without it; it is not solved.

**Section 7: Error Handling — GPU error model correctness:**

Typed errors (v0.26.1, compiling to alternate return values with no stack unwinding) [MOJO-CHANGELOG] are correctly described as a GPU compatibility requirement by the apologist and historian. There is a compiler-level constraint worth making explicit: in a language that unifies CPU and GPU code paths, the compiler must ensure that error propagation is handled consistently across CPU/GPU boundaries. If a GPU kernel returns a typed error, the host CPU code that launched the kernel must correctly receive and propagate that error. The mechanism for this (return value from kernel launch, not exception propagation) requires the compiler to generate different calling conventions for kernel invocations than for regular function calls. Whether Mojo's current compiler handles all error propagation paths across CPU/GPU boundaries correctly has not been independently verified.

**Section 6: Ecosystem and Tooling — Compiler stability:**

The documented compiler crashes (SIGSEGV regressions across minor versions [GH-2513], parser crashes on specific inputs [GH-1295], REPL crashes on matrix operations [GH-712]) are compiler correctness failures, not tooling inconveniences. A production-quality compiler should not SIGSEGV on legal input — that is the compiler's failure, not the developer's. The reported frequency of these issues in Mojo's 0.x series is consistent with a compiler that has not yet been exercised on the scale of input diversity that matures a compiler. This observation contextualizes the performance claims: a compiler that crashes on edge cases has not yet been battle-hardened by the adversarial inputs that trigger optimization bugs. The first performance regressions in Mojo's optimizer are likely to surface as the ecosystem grows.

**Section 8: Interoperability — CPython execution speed:**

The practitioner makes a critical point about the Python interoperability layer that deserves amplification: "Python code running via the interop layer runs through CPython at CPython speed. Not through MLIR." This is a compiler-level architectural boundary that the language's Python-superset framing can obscure. When a Mojo program calls a Python library function, that call exits the MLIR compilation pipeline entirely and enters CPython's interpreted bytecode execution. The Mojo compiler cannot optimize across this boundary, cannot inline Python functions, and cannot apply MLIR optimization passes to mixed Mojo/Python code. The performance benefit of Mojo strictly applies only to code compiled through the MLIR pipeline — `fn` functions with static types in Mojo-native code [MOJO-PYTHON]. This boundary is not merely a performance constraint; it also means the borrow checker's safety guarantees do not extend to code running through CPython.

---

## Implications for Language Design

**1. Sub-expression destruction versus scope-based destruction: compiler complexity versus expressive power.**

ASAP destruction at the sub-expression level is semantically richer than scope-based RAII — it releases resources earlier, potentially improving cache behavior and reducing peak memory usage in high-pressure numerical workloads. But it imposes a higher correctness burden on the compiler: liveness analysis at the expression level is more complex than drop elaboration at scope exit, and bugs in liveness analysis produce use-after-free in otherwise safe code. Language designers should evaluate whether the performance benefit of ASAP destruction is measurably significant for their target workloads before accepting this additional compiler complexity. Rust's model — scope-based destruction with NLL for lifetime flexibility — may represent the right tradeoff for general-purpose languages. ASAP destruction may be the right tradeoff for languages targeting memory-pressure-sensitive AI kernel workloads specifically.

**2. Heterogeneous compilation requires multi-level IR, but multi-level IR amplifies compiler complexity.**

MLIR's multi-level approach — preserving high-level structure through progressive lowering to hardware-specific targets — is architecturally correct for heterogeneous AI hardware. A language that targets CPUs, NVIDIA GPUs, AMD GPUs, and Apple Silicon simultaneously cannot do so correctly through a single-level IR (like LLVM's) without losing the high-level structure that enables hardware-specific optimization. MLIR solves this structural problem. However, multi-level IR amplifies the number of compiler components that must be correct: each abstraction level has its own invariants, each lowering pass must preserve those invariants, and bugs at any level can produce incorrect or unsafe code at the hardware level. Language designers targeting heterogeneous hardware should plan for significantly higher compiler engineering investment than single-target compilation requires — not just because of hardware diversity, but because the IR must be correct at every level.

**3. GPU execution semantics impose non-negotiable constraints on language semantics.**

Three language features that seem orthogonal to GPU execution turn out to be GPU-incompatible and require separate handling: traditional exception mechanisms (stack unwinding), garbage collection (pause unpredictability and pointer indirection), and recursive polymorphism (vtable dispatch). Mojo addresses exceptions via typed errors with no stack unwinding, avoids GC via ownership, and avoids polymorphism overhead via parametric specialization. These are not arbitrary design choices — they are the minimum adaptations a language must make if GPU kernel authorship is a first-class goal. Language designers targeting AI hardware should treat GPU execution semantics as design constraints from the start, not as optimizations to add later.

**4. Compiler-first language development creates correctness risks that emerge late.**

Mojo has prioritized implementing features first and formalizing their semantics second, which is the typical approach for industry-driven language development. This creates a specific pattern of risk: features that work correctly on common input patterns may have edge cases with incorrect semantics that are only discovered when the compiler encounters new program structures. The borrow checker, the ASAP destruction model, and the GPU synchronization model all have formal properties that have not been published or independently verified. Language designers should be aware that this pattern — implement first, formalize later — tends to produce stable happy-path behavior and unstable edge-case behavior. The transition from "works on our benchmarks" to "works in production" typically surfaces these edge cases at scale.

**5. Safety boundary documentation is a compiler responsibility, not just a developer responsibility.**

Mojo's safety model has clearly defined boundaries: the borrow checker enforces safety within Mojo's type system; `UnsafePointer` exits the safe system; Python FFI calls exit the compiled system. These boundaries are correctly identified in the documentation. But from a compiler perspective, boundary documentation is insufficient — the compiler should ideally make crossing these boundaries visible in a way that tools can analyze. Rust's `unsafe` block model enables sanitizers (Miri, ASAN) to specifically instrument code in unsafe regions. Without equivalent boundary-aware tooling in Mojo, the safety boundary is a documented concept rather than a compiler-enforced constraint. Language designers should treat safety boundary tooling as a first-class requirement, not a post-release addition.

---

## References

- [MOJO-CVE] Evidence file: `evidence/cve-data/mojo.md` — Mojo CVE pattern summary and theoretical vulnerability surface
- [BENCHMARKS-PILOT] Evidence file: `evidence/benchmarks/pilot-languages.md` — Pilot language performance benchmark reference
- [MOJO-OWNERSHIP] Modular Inc. Mojo Manual: Value Ownership. https://docs.modular.com/mojo/manual/values/
- [MOJO-LIFECYCLE] Modular Inc. Mojo Manual: Value Lifecycle. https://docs.modular.com/mojo/manual/lifecycle/
- [MOJO-PYTHON] Modular Inc. Mojo Manual: Python Interoperability. https://docs.modular.com/mojo/manual/python/
- [MOJO-ROADMAP] Modular Inc. Mojo Language Roadmap. https://docs.modular.com/mojo/roadmap/
- [MOJO-1-0-PATH] Modular Inc. The Path to Mojo 1.0. https://docs.modular.com/mojo/roadmap#the-path-to-mojo-10
- [MOJO-CHANGELOG] Modular Inc. Mojo Changelog. https://docs.modular.com/mojo/changelog/
- [MOJO-VISION] Modular Inc. Why Mojo. https://docs.modular.com/mojo/why-mojo/
- [WACCPD2025] Jain et al. "Mojo: MLIR-based Performance-Portable HPC Science Kernels on GPUs for the Python Ecosystem." WACCPD 2025 (Best Paper). SC '25 Workshops Proceedings. ACM. https://dl.acm.org/doi/10.1145/3731599.3767573; arXiv preprint: https://arxiv.org/abs/2509.21039
- [ARXIV-MOJO-SC25] Jain et al. arXiv preprint (same paper as WACCPD2025). https://arxiv.org/abs/2509.21039
- [RUST-NLL] Matsakis, N. "Non-Lexical Lifetimes." Rust RFC 2094. https://rust-lang.github.io/rfcs/2094-nll.html
- [GH-2513] Mojo GitHub issue #2513: SIGSEGV regression across minor versions. https://github.com/modularml/mojo/issues/2513
- [GH-1295] Mojo GitHub issue #1295: Parser crash on specific input. https://github.com/modularml/mojo/issues/1295
- [GH-712] Mojo GitHub issue #712: REPL crash on matrix operations. https://github.com/modularml/mojo/issues/712
- [MLIR-CGO] Lattner, C. et al. "MLIR: Scaling Compiler Infrastructure for Domain Specific Computation." CGO 2021. IEEE. https://ieeexplore.ieee.org/document/9370308
