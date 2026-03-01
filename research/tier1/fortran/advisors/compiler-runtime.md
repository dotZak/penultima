# Fortran — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Fortran"
agent: "claude-sonnet-4-6"
date: "2026-02-28"
schema_version: "1.1"
```

---

## Summary

Fortran's compiler and runtime profile is unusually coherent for a language of its age: the core design decisions that made the original 1957 compiler competitive with hand-written assembly are still present and still functional in 2026. Restricted array aliasing, column-major storage aligned to BLAS access patterns, INTENT-annotated subroutine arguments, and ahead-of-time compilation to native machine code are all principled choices that remain valid. The council's claims about these mechanisms are largely accurate and well-sourced.

The primary compiler/runtime concerns this review raises are threefold. First, the memory model chapter from multiple council members overstates the safety guarantee of `ALLOCATABLE` arrays in two specific ways: the auto-deallocation guarantee does not extend to module-level or `SAVE`-attributed allocatables, and the "no leaks from allocatables" claim is invalidated when `POINTER` variables alias into allocatable storage. These are not cosmetic corrections — the failure modes occur in real production code. Second, the council's treatment of `DO CONCURRENT` consistently elides the critical distinction between a constraint declaration (what the programmer asserts) and a parallelism guarantee (what the compiler is obligated to provide). This distinction matters enormously for portability assessments. Third, the compiler ecosystem is in genuine transition: Intel ifort (deprecated 2024, discontinued 2025) was the performance reference for decades of Intel-CPU HPC code, and neither ifx nor LLVM Flang has yet established equivalent production credibility. The council acknowledges this fragmentation but does not fully develop its implications for performance claims.

This review also surfaces a compiler-level issue that no council member addressed: Fortran module file (`.mod`) format is not standardized across compiler implementations, making pre-compiled library distribution across compiler toolchains impossible. This constraint has significant practical consequences for the ecosystem section's optimistic tooling claims.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **ALLOCATABLE arrays provide scope-based automatic deallocation for local variables.** All five council members correctly characterize the fundamental behavior: an `ALLOCATABLE` local variable is automatically deallocated when it goes out of scope, eliminating a common class of manual-management memory leaks [FORTRAN-LANG-ALLOC]. This is accurate for procedure-local allocatables with default automatic storage.

- **ALLOCATABLE arrays guarantee contiguous storage.** This is not incidental — the contiguity guarantee enables compilers to generate cache-optimal sequential access patterns and simplifies vectorization analysis. No equivalent guarantee exists for `POINTER` targets [FORTRAN2018-STANDARD].

- **POINTER arithmetic is restricted relative to C.** Fortran `POINTER` variables cannot be incremented to traverse memory, cannot be cast to different types through arithmetic, and are confined to point at data of their declared type with compatible attributes. The apologist's claim that the attack surface is smaller than C is well-grounded. The Phrack analysis cited [PHRACK-FORTRAN] is real and appropriately caveated.

- **Bounds checking is a compiler flag, not a runtime guarantee.** Every council member correctly states that the Fortran standard does not mandate runtime bounds checking, that out-of-bounds access is undefined behavior producing either silent wrong results or crashes, and that enabling bounds checking (e.g., `gfortran -fcheck=bounds`) imposes measurable runtime overhead. This accurately mirrors C's behavior and correctly characterizes Fortran as memory-unsafe per CISA/NSA guidance [MEMORY-SAFETY-WIKI].

- **Column-major storage is intentionally aligned to BLAS/LAPACK access patterns.** The apologist and realist correctly argue that column-major ordering is not an arbitrary historical artifact but a deliberate match to how dense matrix operations traverse memory in BLAS — column by column, not row by row. Libraries written in Fortran assumed this layout. The cache-efficiency argument for column access in column-major storage is valid [BLAS-LAPACK-REF].

**Corrections needed:**

- **The "no memory leaks possible with allocatable arrays" claim is overstated.** The research brief states this claim and the apologist echoes it. It is accurate only in the narrow case of allocatable variables with no `POINTER` aliases pointing into them. If a `POINTER` variable is associated with an allocatable array and the allocatable subsequently goes out of scope and is deallocated, the pointer becomes dangling — and the runtime does not trap this. Conversely, if a `POINTER` variable is associated with heap storage that is referenced from an allocatable, the allocatable's deallocation does not transitively clean up the pointer. In production Fortran code mixing both features (a common situation in object-oriented modern Fortran with derived types containing both allocatable components and pointer components), leaks and dangling references remain possible. The claim should be qualified to: "allocatable arrays used in isolation, without `POINTER` aliases, cannot produce dangling references through the allocatable mechanism."

- **Auto-deallocation of allocatables does not apply to module-level or SAVE-attributed variables.** Module-level allocatable variables and any allocatable declared with the `SAVE` attribute persist for the lifetime of the program, not the lifetime of the declaring scope. This is a significant exception that no council member clearly flags. Scientific programs frequently place large working arrays in modules for shared access across procedures. Those arrays do not auto-deallocate at any natural scope boundary — they must be explicitly deallocated, or they leak for the program's lifetime. This is an important nuance for programs doing repeated simulation runs within a single executable (e.g., ensemble runs), where module-level allocatables from a prior run may not have been deallocated before the next run begins.

- **The bounds-checking overhead figure deserves explicit quantification.** The practitioner notes bounds checking is "disabled in production due to significant runtime overhead" without quantifying what "significant" means. For tight numerical loops iterating over large arrays — the dominant workload in HPC Fortran — enabling `-fcheck=bounds` on GFortran or `-check bounds` on ifx typically introduces 10–50% runtime overhead for compute-bound kernels [INTEL-FORTRAN-FLAGS]. This range explains the HPC community's persistent decision to disable it in production. It also represents a genuine design tradeoff that language designers should understand: mandatory safety checking at these overhead levels would be incompatible with Fortran's performance contract.

**Additional context:**

- **The CHARACTER interoperability issue is a hidden memory layout problem.** No council member discusses the hidden length argument convention for Fortran `CHARACTER` parameters. When a Fortran subroutine accepts a `CHARACTER` argument, Fortran's default calling convention passes a hidden character length value after the visible argument list. C callers do not provide this argument, creating a silent ABI mismatch. This is not fixed by the `ISO_C_BINDING` module alone — interoperating CHARACTER across the Fortran/C boundary requires `BIND(C)` on the procedure and use of `CHARACTER(KIND=C_CHAR)` arrays, which changes the semantics. This is a runtime-level issue that is frequently encountered in practice and not adequately covered in the council's interoperability discussion [FORTRAN2018-STANDARD].

- **COMMON block type punning creates aliasing the Fortran aliasing model cannot reason about.** The practitioner correctly notes that `COMMON` blocks create global aliasing with no type checking. What deserves additional precision: the Fortran non-aliasing model (the optimization basis for Fortran's performance advantage over C) implicitly assumes that references to distinct named variables do not alias. `COMMON` blocks violate this assumption at scale when mismatched type declarations access the same storage. The compiler's optimization analysis is compromised in exactly the code that most benefits from Fortran's aliasing freedom. Modern compilers cannot easily detect this class of aliasing at compile time because `COMMON` declarations in different compilation units are resolved at link time.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **Coarrays are standardized but not fully implemented across the ecosystem.** Every council member correctly identifies that Fortran 2008 introduced coarrays and Fortran 2018 significantly extended them with teams, events, and collective subroutines [FORTRANWIKI-STANDARDS], and that compiler support remained incomplete as of 2024 with Intel ifx having the most complete implementation [INTEL-COARRAY]. The 16-year implementation gap (2008 standardization to incomplete implementations in 2024) is accurately characterized and an important data point.

- **FORALL's semantic design was counter-productive.** The historian accurately describes the critical mistake: `FORALL` required full right-hand-side evaluation before any assignment, mandating intermediate temporaries and an implicit barrier after each statement. This was not "parallel DO" semantics — it was whole-array assignment semantics with loop-syntax notation. Compilers could not fuse consecutive `FORALL` statements or eliminate temporaries; the resulting code was often slower than equivalent `DO` loops. The declaration of obsolescence in Fortran 2018 (23 years post-introduction) is correctly documented, and the continued availability as non-obsolescent-just-deprecated code is a valid concern for readers of legacy code [FORALL-HISTORY].

- **DO CONCURRENT is a constraint declaration, not a parallelism primitive.** The realist and practitioner correctly characterize `DO CONCURRENT` as a hint to the compiler rather than a guarantee of parallelism. The standard's semantic contract is: the programmer asserts that iterations have no dependencies, and the compiler is permitted (but not required) to exploit this for vectorization, parallelization, or GPU offload. This is an accurate representation of the standard's text.

- **MPI dominates practical distributed parallelism in production HPC Fortran.** The practitioner's "MPI is reality; everything else is qualifier" framing is accurate as a description of production deployment patterns. MPI's dominance is not merely historical inertia — it reflects decades of performance tuning, comprehensive vendor support on every major HPC platform, extensive debugged production experience, and a large labor market of programmers trained on the model. Coarrays' theoretical advantages have not overcome this installed base after 16 years of standardization.

**Corrections needed:**

- **GFortran coarrays require an external library, not just the compiler.** No council member states this clearly enough: GFortran single-image coarray code compiles natively, but *multi-image* coarray execution on GFortran requires OpenCoarrays (`libcaf_mpi`), an external runtime library not bundled with GFortran. OpenCoarrays implements coarray communication by mapping it to MPI calls at runtime. This means GFortran coarray programs, when run in multi-image mode, have MPI as a runtime dependency — the supposedly "native language parallelism" is, at the runtime level, implemented via the same external library standard that coarrays were designed to complement or replace. This is a significant architectural nuance. It also means portability of multi-image coarray programs on GFortran requires OpenCoarrays to be installed, versioned, and tested at the HPC site, adding a dependency management burden that the council's framing underplays [OPENCOARRAYS-GITHUB].

- **DO CONCURRENT GPU execution via `-stdpar=gpu` is a compiler extension, not a standard feature.** The apologist's discussion and the research brief both describe NVIDIA nvfortran's ability to target GPU execution from `DO CONCURRENT` loops via `-stdpar=gpu`. This is accurate but should be more precisely categorized: `-stdpar=gpu` is a compiler-specific extension to the Fortran standard, not a portable Fortran feature. A program written with the expectation that `DO CONCURRENT` targets GPU execution on one compiler will execute serially on GFortran, ifx, or LLVM Flang without warning. The portability gap between the standard's intent (compiler may exploit independence) and the extended behavior (NVIDIA compiler will offload to GPU) is not merely semantic — it creates a class of programs that are correct and fast on one compiler/system and silent underperformers on all others. This is a meaningful portability hazard.

- **The DO CONCURRENT `REDUCE` clause correction.** Multiple council members refer to this feature as "REDUCTION" (matching OpenMP terminology). The Fortran 2023 standard introduced locality specifiers including `REDUCE`, not `REDUCTION`, for `DO CONCURRENT` loops [FORTRAN2023-STANDARD]. The terminology distinction matters for practitioners searching compiler documentation and standard text.

**Additional context:**

- **OpenMP and OpenACC GPU offload fragmentation is more severe than the council acknowledges.** The practitioner correctly identifies the three-way split (OpenACC for NVIDIA, OpenMP target for Intel/AMD, CUDA Fortran for maximal NVIDIA expressiveness), but the compiler support matrix deserves sharper delineation. As of early 2026: Intel ifx supports OpenMP GPU offload to Intel GPUs but does not support OpenACC; NVIDIA nvfortran supports both OpenACC and OpenMP offload to NVIDIA GPUs, with OpenACC being more mature; GFortran supports OpenMP offload experimentally with significantly less vendor optimization investment than the vendor compilers; LLVM Flang's GPU offload support is less mature than all three vendor compilers. There is no single open-source compiler path that provides production-quality GPU acceleration across hardware vendors. This is a toolchain fragmentation pattern that language designers should recognize as a risk of leaving GPU execution as a compiler-extension domain.

- **Coarray runtime semantics require careful analysis of `SYNC ALL` placement.** Coarray programs that use `A[img]` cross-image accesses without properly bracketed synchronization (`SYNC ALL`, `SYNC IMAGES`, or event-based synchronization) have data races that the Fortran standard classifies as undefined behavior. Unlike OpenMP's data race detection tools (e.g., ThreadSanitizer-based analysis), coarray race detection tooling is minimal. Intel Inspector has limited coarray support; there is no equivalent of Helgrind for coarray programs. Programs that run correctly on 2 images may fail silently on 64 or 1024 images due to timing-dependent synchronization bugs. This runtime verification gap is significant for the "safety" framing the apologist offers for coarray semantics relative to raw MPI.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **Fortran consistently ranks in the top tier on numerically intensive CLBG benchmarks.** The computer language benchmarks game consistently places well-optimized Fortran alongside C, C++, and Rust for compute-bound numerical tasks (mandelbrot, spectral-norm, n-body, matrix multiplication) with performance differences in single-digit percentages [FORTRANWIKI-CLBG]. This is an accurately sourced claim. The mechanisms are identifiable: restricted aliasing model, ELEMENTAL vectorization, array intrinsics that map directly to SIMD instruction sequences, and column-major layout that matches BLAS memory access patterns.

- **The optimization flag dependency is real and significant.** The practitioner's observation that the difference between `-O0` (debug) and `-O3 -march=native -funroll-loops` (aggressive optimization) can be 2–5× for numerical kernels is accurate and important [INTEL-FORTRAN-FLAGS]. This is not Fortran-specific, but Fortran's performance claims are almost always implicitly stated with aggressive optimization assumed. Benchmarks at `-O0` would not place Fortran in the top tier; CLBG implementations are compiled with high optimization levels. This optimization-dependency should be made explicit whenever performance comparisons are cited.

- **LLVM Flang has a performance gap relative to GFortran on compilation speed.** The research brief's figure of approximately 23% slower compile-time than GFortran and approximately 48% slower than Classic Flang is accurately sourced and consistently cited [LINARO-FLANG]. This is a real gap with real operational consequences: HPC workflows with large codebases (millions of lines of Fortran) experience this cost on every build. The qualification that LLVM Flang is the future of the open-source toolchain (backed by NVIDIA, AMD, Arm, and US DOE national laboratories) does not change the present deployment reality.

- **Intel ifort discontinuation creates performance regression risk for existing codebases.** Intel ifort (classic, C++ frontend) was deprecated in the 2024 oneAPI release and discontinued in the 2025 release. Sites with codebases tuned for ifort's optimization passes — auto-vectorization heuristics, loop fusion patterns, profile-guided optimization profiles — face a migration to ifx (LLVM backend, different optimization heuristics) that may require extensive performance retesting and re-tuning. This is not hypothetical: national laboratory and aerospace teams are managing this migration actively in 2025–2026.

- **Restricted pointer aliasing is the primary mechanism enabling Fortran's optimization advantage.** The practitioners correctly identify this. Fortran's specification restricts which memory locations two references may alias: two array dummy arguments with `INTENT(IN)` and `INTENT(OUT)` on the same call are assumed non-aliasing by the compiler. C compilers cannot safely assume this without explicit `restrict` annotation, which is often omitted. The optimization consequence is real: loop transformation, register allocation, and hoisting analyses in Fortran compilers can proceed with fewer conservative guards than in C compilers processing equivalent code.

**Corrections needed:**

- **The LLVM Flang performance figures require clarification between compile-time and runtime code quality.** The ~23% figure cited in the research brief and echoed by the realist and practitioner refers to *compilation speed* — how fast the compiler processes Fortran source into object files — not the *runtime performance* of the generated code. Runtime code quality from LLVM Flang is a separate question: LLVM's optimization passes produce competitive code for many benchmarks, though specific workloads may differ from GFortran's GCC-based optimization. The council conflates compilation speed (slower in Flang) and generated code quality (competitive or potentially superior as LLVM matures) — these are distinct concerns for practitioners evaluating whether to adopt Flang for production use.

- **GPU performance claims require stronger qualification about data transfer overhead.** The apologist cites NVIDIA's report of 4× speedup on A100 GPU for OpenACC-accelerated Fortran and treats this as demonstrating that "GPU acceleration is working and improving" [NVIDIA-HPC-SDK]. The practitioner correctly notes the caveat: GPU speedup is sensitive to data movement between CPU host memory and GPU device memory. For computation-dominated kernels with infrequent host-device transfer, 4× is achievable. For workloads with frequent host-device transfers or memory-bound access patterns on the GPU, the achieved speedup can fall well below this figure. The practitioner's description of data movement as "the primary cognitive burden" and the need for profiling to diagnose whether a GPU program is compute-bound or transfer-bound is accurate. Performance claims citing GPU speedup ratios without specifying data transfer characteristics should be treated as upper-bound estimates.

- **"Zero runtime overhead" for compiled Fortran requires qualification.** The apologist describes Fortran's compilation model as having "zero runtime overhead" because there is no JVM, no interpreter, no GC warmup. This is accurate in the narrow sense: there is no managed runtime system. However, Fortran programs do have runtime overhead from several sources: bounds checking when enabled, coarray runtime (libcaf_mpi or equivalent) initialization for multi-image programs, OpenMP thread pool initialization and synchronization for `!$OMP PARALLEL` regions, and dynamic memory management through `ALLOCATE`/`DEALLOCATE`. For single-image, non-OpenMP programs with no dynamic allocation, the "zero overhead" claim is approximately accurate. The claim should not be generalized to all Fortran programs.

**Additional context:**

- **BLAS/LAPACK performance claims should distinguish language-level from library-level contributions.** The apologist and practitioner correctly note that Fortran's column-major storage aligns with BLAS/LAPACK access patterns. What deserves precision: modern BLAS implementations (OpenBLAS, Intel MKL, BLIS) are hand-tuned assembly for specific microarchitectures; the performance of calling `DGEMM` is attributable primarily to these assembly kernels, not to Fortran language features. Fortran's advantage is that calling BLAS from Fortran avoids column/row-major transposition overhead that languages using row-major storage must absorb. This is a real and meaningful performance benefit, but it is categorically different from Fortran-compiled numerical code outperforming C-compiled numerical code on a non-BLAS workload. Both claims are sometimes made in proximity; they have different mechanisms and different generalizability.

- **`ELEMENTAL` functions and auto-vectorization reliability.** The practitioner's claim that `ELEMENTAL` functions and array intrinsics "more reliably vectorize across compiler versions and optimization levels" than equivalent loop code is generally accurate but deserves a precision note: whether a given ELEMENTAL function successfully vectorizes depends on the function's body, the target architecture's vector instruction set (SSE2, AVX-512, SVE), and the compiler's version and vectorization capabilities. A poorly written ELEMENTAL body with conditional branches or non-vectorizable calls will not auto-vectorize regardless of the ELEMENTAL declaration. ELEMENTAL is a necessary but not sufficient condition for vectorization; it informs the compiler that vectorization is semantically valid, but the compiler still performs feasibility analysis on the function body.

---

### Other Sections (Compiler/Runtime-Relevant Issues)

**Section 2: Type System — Module File Format Incompatibility**

No council member addresses a significant compiler-level consequence of Fortran's module system: Fortran `.mod` files are not standardized at the binary level. Each compiler generates its own proprietary module file format. GFortran's `.mod` files cannot be consumed by ifx; ifx's cannot be consumed by LLVM Flang or GFortran. This means that a compiled Fortran library — even one adhering perfectly to the Fortran standard — cannot be distributed as a pre-compiled binary for use across different compilers. Every site must compile library dependencies from source with their specific compiler. This constraint shapes the ecosystem (fpm compiles dependencies from source rather than distributing binaries) and limits Fortran's ability to build a binary-distribution package ecosystem comparable to compiled language systems that standardize ABI. Language designers should recognize module system binary compatibility as a necessary component of ecosystem design, not solely a syntactic/semantic question.

**Section 2: Type System — INTENT Attribute Enforcement Scope**

The council members (particularly the practitioner and apologist) describe `INTENT(IN)`, `INTENT(OUT)`, and `INTENT(INOUT)` attributes as providing optimization information and safety guarantees. This is accurate at the call site in the procedure's own body: the compiler will diagnose attempts to modify an `INTENT(IN)` argument as errors. However, `INTENT` enforcement applies only when the procedure's interface is explicit (the call is within a module, uses an `INTERFACE` block, or calls a contained procedure). When calling a procedure through an implicit interface (still common in legacy code), the compiler cannot enforce `INTENT` constraints on the caller side, cannot verify that actual and dummy arguments are compatible, and cannot apply the optimization assumptions safely. The safety and optimization value of `INTENT` is therefore contingent on modern Fortran style (explicit interfaces via modules) and degrades silently in legacy code using implicit interfaces. This is a specification-versus-implementation gap that the council's Section 2 discussion does not clearly articulate.

**Section 6: Ecosystem — Build System and Module Dependency Ordering**

The council's ecosystem section correctly identifies fpm (Fortran Package Manager) as the emerging standard for new projects and CMake as dominant for existing large codebases. One compiler/runtime-relevant issue not mentioned: Fortran module dependencies create a build ordering problem more complex than C/C++ header dependencies. Because a module `A` that `USE`s module `B` requires `B`'s `.mod` file to be present before `A` can be compiled, build systems must correctly compute and respect module dependency order across compilation units. CMake has had evolving and sometimes incorrect Fortran module dependency tracking; older versions have well-documented bugs causing incorrect parallel build failures or missing recompilation. GFortran generates `.mod` files only on successful compilation; ifx generates them even on partial compilation, creating different dependency-tracking behavior. Developers encountering "module not found" errors during parallel builds are often experiencing build system failures, not code problems, but the error messages do not make this clear.

**Section 10: Interoperability — Column-Major Mismatch as Runtime Bug Factory**

The council consistently identifies column-major vs. row-major as "a footgun" and "persistent source of bugs." What deserves sharper compiler/runtime framing: this class of bug is entirely undetectable by Fortran's type system or C's type system. A Fortran `REAL(KIND=8), DIMENSION(M,N)` array and a C `double[M][N]` array are indistinguishable at the type level once passed across the boundary — both are pointers to `M*N` doubles. The transposition error produces valid floating-point numbers with incorrect values: no type error, no bounds violation, no runtime trap. Static analysis cannot catch it without semantic understanding of the intended matrix semantics. The only detection mechanisms are numerical validation against known results or careful code review of every C↔Fortran array-passing boundary. For a language whose primary domain is numerical correctness, this is a serious and systematically undetectable failure class.

---

## Implications for Language Design

The Fortran case reveals seven compiler and runtime design lessons with broad applicability:

**1. Scope-based resource management is superior to manual lifetime management, and partial implementation is worse than none.** Fortran's `ALLOCATABLE` system demonstrates clearly that scoped automatic deallocation eliminates the dominant class of memory leaks for the language's primary use pattern (large arrays with procedure-bounded lifetimes). But the coexistence of `POINTER` (manual lifetime, no scope-based cleanup) in the same language means programmers must reason about two memory models simultaneously. A new language should provide a single, consistent memory management model rather than a safe subset alongside an unsafe escape hatch — the escape hatch accumulates in codebases wherever the safe subset is insufficient, and the two models' interactions create failure modes neither would have in isolation.

**2. Standardizing a feature before adequate implementation readiness creates adoption barriers that may become permanent.** Fortran coarrays were standardized in 2008. In 2024, 16 years later, compiler support remained incomplete, multi-image GFortran required an external library (OpenCoarrays), and MPI — the external library coarrays were intended to complement or replace — continued to dominate production HPC. Language standards work that advances specification ahead of implementation creates a gap that incumbent solutions fill permanently. Language designers should treat reference implementation availability, not specification text, as the threshold for feature readiness.

**3. Language-level parallelism assertions without enforcement guarantees create portability failure modes.** `DO CONCURRENT`'s design — programmer asserts independence, compiler may or may not exploit — produces programs that are fast on one compiler (NVIDIA nvfortran with `-stdpar=gpu`) and silent serial on others. For a feature intended to simplify parallel programming, this behavior is counterproductive: users who write `DO CONCURRENT` expecting GPU execution will encounter no error message and potentially catastrophic performance degradation when running on a different compiler. Language-level parallelism constructs should either guarantee their contract or provide a diagnostic when the contract cannot be fulfilled. Silent best-effort behavior in performance-critical contexts is not acceptable.

**4. Aliasing restrictions as a first-class language design choice enable optimization that permissive pointer models cannot access.** Fortran's non-aliasing rules (arrays cannot alias through normal assignment, dummy arguments are assumed non-aliasing under standard usage) allow compilers to perform loop transformations, register allocation, and hoisting that C compilers conservatively decline. C's `restrict` annotation attempts to reclaim some of this optimization space but is rarely used in practice. A language that wants to guarantee performance optimization opportunities in its numerical core should design aliasing restrictions in from the beginning, not try to recover them through annotations. The mechanism must be pervasive and enforced, not optional.

**5. Module binary interface standardization is a necessary precondition for healthy package ecosystems.** Fortran's non-standardized `.mod` file format means no binary package distribution across compiler toolchains — every dependency must be compiled from source. This adds build complexity, slows adoption of shared libraries, and creates a practical barrier to ecosystem growth. Languages that intend to support rich third-party libraries must define a stable, compiler-independent binary module interface alongside the language standard. ABI specification is not an afterthought — it is foundational to whether a packaging ecosystem can form.

**6. Backward compatibility mechanisms that prevent removal create perpetual implementation burden.** `COMMON` blocks and `EQUIVALENCE` were identified as design mistakes, declared obsolescent in Fortran 90, and finally removed from the standard in Fortran 2023 — 57 years after their introduction. Compilers continue to support them as extensions because removing support would break a significant fraction of existing code. The Fortran case demonstrates that "obsolescence" — which marks features as deprecated without removing them — is an insufficient mechanism for actually retiring problematic language features. Language designers should plan for both obsolescence and actual removal, with defined timelines, and should consider migration tooling as a prerequisite for successful feature retirement.

**7. Memory layout incompatibilities at language boundaries are systematically undetectable and disproportionately dangerous.** Column-major vs. row-major array layout mismatch between Fortran and C produces numerically incorrect results that pass type checking, bounds checking, and compilation without error. For Fortran — a language whose entire value proposition is numerical correctness — this class of silent wrong-answer bug is particularly damaging. Languages that define interoperability with other languages must address memory layout compatibility at the specification level, not leave it as a programmer responsibility documented in a footnote. The ISO_C_BINDING module reduces some interoperability friction but does not solve the layout problem.

---

## References

[FORTRAN2018-STANDARD] ISO/IEC 1539-1:2018, "Information technology — Programming languages — Fortran — Part 1: Base language." International Organization for Standardization, 2018.

[FORTRAN2023-STANDARD] ISO/IEC 1539-1:2023, "Information technology — Programming languages — Fortran." International Organization for Standardization, 2023. Includes removal of COMMON/EQUIVALENCE and addition of DO CONCURRENT REDUCE locality clause.

[FORTRANWIKI-STANDARDS] Fortran-Lang community, "Fortran Standards History." fortran-lang.org. Covers FORTRAN I (1957) through Fortran 2023.

[FORTRANWIKI-CLBG] Computer Language Benchmarks Game, fortran implementations. benchmarksgame-team.pages.debian.net. Accessed February 2026.

[FORTRAN-LANG-ALLOC] Fortran-Lang, "Allocatable arrays." fortran-lang.org/learn/best_practices/allocatable_arrays.

[BLAS-LAPACK-REF] Lawson, C.L., Hanson, R.J., Kincaid, D., Krogh, F.T. "Basic Linear Algebra Subprograms for FORTRAN Usage." ACM Transactions on Mathematical Software, 5(3), 1979. Original BLAS design in Fortran with column-major storage assumed.

[INTEL-COARRAY] Intel, "Coarray Features in Intel Fortran Compiler." Intel Developer Zone documentation, oneAPI 2025 release. Documents Fortran 2018 coarray support status in ifx.

[INTEL-FORTRAN-FLAGS] Intel, "Intel Fortran Compiler Classic and Intel Fortran Compiler Developer Guide and Reference." oneAPI 2024 release. Optimization flag reference including -O0 through -O3, -march equivalents, and bounds-checking overhead.

[OPENCOARRAYS-GITHUB] OpenCoarrays project, github.com/sourceryinstitute/OpenCoarrays. Multi-image coarray runtime for GFortran using MPI backend.

[COARRAYS-SOURCEFORGE] Numrich, R.W. and Reid, J. "Co-array Fortran for parallel programming." ACM SIGPLAN Fortran Forum, 17(2), 1998. Original coarray design paper.

[FORALL-HISTORY] High Performance Fortran Forum. "High Performance Fortran Language Specification, Version 1.0." Rice University, May 1993. Original FORALL semantics; subsequently adopted into Fortran 95.

[LINARO-FLANG] Linaro, LLVM Flang Performance Benchmarks. linaro.org, 2024. ~23% compile-time overhead vs. GFortran, ~48% vs. Classic Flang.

[NVIDIA-HPC-SDK] NVIDIA, "NVIDIA HPC SDK Documentation." developer.nvidia.com/hpc-sdk. OpenACC performance reports and DO CONCURRENT -stdpar extension.

[NVIDIA-DO-CONCURRENT] Romero, J. et al. "Fortran DO CONCURRENT GPU Offloading." NVIDIA technical blog, 2023. Documents -stdpar=gpu as compiler extension.

[MEMORY-SAFETY-WIKI] CISA/NSA, "The Case for Memory Safe Roadmaps." Cybersecurity and Infrastructure Security Agency, 2023. Classifies C and Fortran as memory-unsafe languages.

[PHRACK-FORTRAN] Phrack Magazine, "Exploiting Fortran." Phrack #69, 2010. Documents Fortran memory safety attack surface relative to C.

[FORTRAN-LANG-ALLOC] Fortran-Lang, "Fortran Best Practices: Allocatable Arrays." fortran-lang.org, 2024.

[IBM-HISTORY-FORTRAN] IBM Corporation, "The IBM Mathematical Formula Translating System: FORTRAN." Programmer's Reference Manual, 1957. Primary source for original design goals and claims.

[BACKUS-HISTORY-1978] Backus, J. "The History of FORTRAN I, II, and III." In Wexelblat, R.L. (ed.), *History of Programming Languages*, ACM, 1978, pp. 25–74.
