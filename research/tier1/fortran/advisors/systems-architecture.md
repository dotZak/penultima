# Fortran — Systems Architecture Advisor Review

```yaml
role: advisor-systems-architecture
language: "Fortran"
agent: "claude-sonnet-4-6"
date: "2026-02-28"
```

---

## Summary

Fortran's systems-architecture profile is that of a language designed for a deployment context that no longer fully exists — the sealed-off institutional computing environment — and maintained by a governance structure calibrated for geological-timescale stability. For the narrow but critical workload of compute-intensive numerical simulation on HPC clusters, the architecture holds up remarkably well: compiled to native code, well-matched to BLAS/LAPACK access patterns, and supported by a set of institutional stakeholders (DOE national laboratories, NVIDIA, AMD, Arm) who need Fortran working to sell hardware. For anything outside that narrow band — large-team software engineering, modern CI/CD integration, binary library distribution, polyglot service architectures — the structural gaps are significant and many are unlikely to close.

The council perspectives collectively capture Fortran's domain strength and its ecosystem evolution honestly. What they underweight, from a systems-architecture lens, are the second-order effects: the build infrastructure fragmentation created by the non-standardized `.mod` file format, the CI/CD integration void in HPC development culture, the compiler transition risk that the ifort → ifx migration represents for production numerical correctness, and the generics absence as a large-codebase maintainability hazard. These are not auxiliary concerns — they are the day-to-day reality of engineering teams maintaining half-million-line Fortran codebases.

The 10-year outlook for systems built on Fortran today is cautiously positive for organizations embedded in the DOE/NASA/ECMWF ecosystem where Fortran is the institutional norm, and substantially more uncertain for organizations that are not. The language has genuine institutional backing, exceptional backward compatibility, and no credible replacement for its core workload. But the talent pool is shrinking, the ecosystem's binary distribution story remains incoherent, and the governance process has no mechanism to respond to unilateral vendor decisions (such as Intel's ifort discontinuation) that affect production systems globally.

---

## Section-by-Section Review

### Section 6: Ecosystem and Tooling

**Accurate claims:**
- All council members correctly identify fpm as a genuine improvement over the pre-2020 build chaos (custom Makefiles, Autotools, incompatible CMake conventions), and accurately note that large HPC projects (WRF, CESM, VASP) remain on CMake or Makefiles. This is the central tension: fpm serves new projects; existing production codebases have no migration incentive.
- The detractor's identification of the `.mod` file non-portability problem is technically accurate and important [FORTRANWIKI-MOD] [INTEL-MOD-COMPAT]. This is the most underappreciated systems-architecture constraint in the ecosystem: Fortran module files are compiler-specific and compiler-version-specific, making binary library distribution essentially impossible. A library compiled with GFortran 13 cannot provide module interfaces to a project compiled with Intel ifx without rebuilding from source.
- The realist and practitioner correctly characterize the LLVM Flang ~23% performance gap as a live production concern [LINARO-FLANG]. This is not an abstract future risk — HPC centers that need to validate numerical results before deploying new compilers face a genuine regression.
- The historian's account of ecosystem fragmentation as structural (institutional computing culture + standards body focused on specification, not tooling) accurately explains why the gap persisted so long. This is not community failure; it is the predictable outcome of a governance model designed for a pre-open-source institutional computing world.

**Corrections needed:**
- The apologist's framing that LLVM Flang's emergence places Fortran in "the same kind of heterogeneous computing future that C/C++ has via Clang" [apologist, §6] overstates current readiness. Clang is a production replacement for GCC in most contexts; LLVM Flang is not yet a production replacement for GFortran or ifx. The ~23% performance gap and continuing gaps in standard compliance (particularly around newer features) mean practitioners must validate per-workload before deploying Flang in production. The trajectory is correct; the present state is not interchangeable with Clang's maturity.
- The apologist's argument that "the thin ecosystem is appropriate for the domain" partially misidentifies what the domain actually needs. The package count problem (no PyPI equivalent) is indeed less critical for numerical HPC work. But the *binary distribution* problem — the inability to ship compiled Fortran libraries that work across compiler toolchains — is a structural bottleneck that affects every institution sharing code. Appropriateness of a thin ecosystem is true; appropriateness of a non-portable binary interface is not.

**Additional context (systems architecture perspective):**

*The CI/CD integration void.* The council perspectives largely omit a systems-architecture concern that affects every large Fortran project: Fortran HPC codes are difficult to integrate with standard CI/CD pipelines. Testing MPI-parallel code at production scale requires HPC cluster resources — typically dozens to hundreds of nodes — that standard CI runners (GitHub Actions, GitLab CI) cannot provide. The result is a bifurcated quality assurance picture: unit tests and small-scale integration tests run on CI, but the large-scale runs that expose subtle numerical issues, memory bugs activated by specific problem sizes, and MPI communication patterns that only appear at scale are run on-cluster, often manually, often infrequently. This is not a Fortran-specific problem, but Fortran's domain concentration in MPI-parallel HPC makes it especially acute. There is no standard solution; projects use institution-specific job submission scripts that are not reproducible across sites.

*The `.mod` non-portability problem at distribution scale.* The detractor identifies this correctly, but the full architectural consequence deserves elaboration. In a large scientific collaboration where institutes A, B, and C each maintain components of a shared physics model, binary distribution of compiled Fortran modules requires:
1. Agreeing on a common compiler and compiler version across all sites
2. Rebuilding shared libraries whenever the compiler is upgraded
3. Maintaining separate compiled artifacts per compiler × version combination for heterogeneous collaborations

No other major compiled language with a significant library ecosystem has this limitation in 2026. C and C++ have stable ABIs on major platforms. Rust's `crate` format includes sufficient metadata for cross-version interoperability. Fortran has none of these properties for its module interface format. Source-only distribution is the de facto standard, which means every downstream user must build every dependency — a build-time cost that scales unfavorably with dependency count.

*The CMake Fortran module dependency fragility.* The practitioner mentions CMake's module dependency tracking being fragile [practitioner, §6]. This is a chronic operational problem at scale. CMake must discover `.mod` file dependencies at configuration time and regenerate them on incremental rebuilds. When a module interface changes — adding a subroutine, changing an argument type — CMake sometimes fails to propagate the rebuild requirement correctly, producing silent link errors or subtly incorrect behavior. Large Fortran codebases with deep module dependency chains are particularly exposed. The workaround (clean rebuilds after interface changes) is reliable but expensive at scale: rebuilding a 500K-line HPC code from scratch on a typical developer workstation takes tens of minutes. The operational cost is real and recurring.

---

### Section 10: Interoperability

**Accurate claims:**
- All council perspectives correctly identify ISO_C_BINDING (Fortran 2003) as a genuine standardization achievement and accurately note that Fortran/C interoperability before 2003 was convention-based and fragile [FORTRANWIKI-STANDARDS]. The historian's observation that this transformed Fortran from a language that "happened to call C" to one that "could standardly call C" is apt.
- The column-major/row-major mismatch at Fortran/C and Fortran/Python boundaries is correctly characterized by all council members as a recurring bug factory. The detractor's identification of the silent wrong-result risk — passing a C-order NumPy array to a Fortran subroutine expecting Fortran order silently transposes the matrix — is accurate and significant. There is no language-level enforcement; the correctness burden falls entirely on the programmer at every boundary crossing.
- The practitioner's characterization of MPI interoperability as Fortran's strongest interoperability story is accurate [practitioner, §10]. MPI is language-agnostic at the wire level, the Fortran MPI bindings are mature and production-proven at extreme scale, and the pattern of polyglot MPI jobs (Python preprocessing → Fortran compute kernels → C++ I/O) is increasingly common and works well.
- The detractor's identification of the no-standard-ABI, symbol-mangling-variation problem [detractor, §10] is accurate. Trailing underscore conventions differ between compilers; CHARACTER argument hidden length-passing conventions differ; structure alignment may differ. These are not edge cases — they are the first thing an HPC practitioner encounters when trying to link a Fortran library against code compiled with a different toolchain.

**Corrections needed:**
- The apologist's characterization of BLAS/LAPACK bindings as Fortran's "deepest interoperability achievement" [apologist, §10] requires qualification in the systems-architecture context. The claim is historically accurate — Fortran defined the API — but operationally, the actual interoperability is accomplished through C wrappers in all modern high-performance implementations (MKL, OpenBLAS, BLIS). When Python/NumPy calls BLAS, it is typically calling a C function with Fortran-compatible calling convention, not a Fortran symbol directly. The interoperability success belongs to the API definition, not to ongoing Fortran-native interoperability. This distinction matters for understanding what Fortran's actual role is in modern polyglot scientific stacks.
- The apologist's characterization of the column-major/row-major boundary as a "known interoperability challenge" that is "not because of a design error" [apologist, §10] is technically accurate but may understate the operational impact. The argument that it reflects physical access patterns rather than design error is valid; but from a systems-architecture perspective, the consequence — that every multidimensional array crossing a Fortran/C or Fortran/Python boundary requires explicit attention to storage order, with no enforcement — is a persistent source of production bugs in large polyglot codebases. Correctness-by-convention at every interface crossing is a maintenance hazard that scales poorly with team size and code age.

**Additional context (systems architecture perspective):**

*The polyglot architecture pattern.* Modern HPC codebases are not single-language. The dominant production pattern for large scientific simulations is: Python (workflow orchestration, data preprocessing, visualization) → C/C++ (I/O subsystems, file format handling) → Fortran (compute-intensive physics kernels). Fortran's architectural role in this pattern is as the bottom-layer kernel language, not the system-wide language. This is a sustainable role but a constrained one: it means Fortran code must present clean C-compatible interfaces (via ISO_C_BINDING) to be accessible from Python or C++, and that any state shared across the boundary must be carefully managed for column/row ordering. Systems architects building new HPC software stacks should understand that Fortran interoperability works best at this bottom-layer kernel role and degrades with any attempt to use it for orchestration, data interchange, or interface-heavy integration.

*f2py limitations at scale.* The practitioner notes that f2py (NumPy's Fortran-to-Python wrapper generator) "works reliably for simple cases" and "fails or requires hand-annotation for complex cases" [practitioner, §10]. This limitation becomes significant at the scale of large scientific libraries. LAPACK's Python wrappers (scipy.linalg) work because the LAPACK interface is simple (scalars, arrays, simple structs); a more complex Fortran library with derived types, allocatable arguments, optional arguments, and module-level state is substantially harder to wrap. Production use of f2py at scale typically requires maintaining a thin C wrapper layer between Python and the complex Fortran, which adds an additional maintenance burden and another conversion layer.

*The Fortran/Python integration direction asymmetry.* The council focuses on calling Fortran from Python, which is the dominant direction in HPC workflows. The reverse — calling Python from Fortran, or passing Python objects to Fortran routines — is practically impossible without C as an intermediary layer. This asymmetry shapes architectural choices: Fortran code can be wrapped and called from Python, but Fortran cannot participate in Python-native data structures, callbacks, or object models. Systems built on this architecture must ensure that the interface between the Python and Fortran layers is thin, well-defined, and stable, because refactoring it is expensive.

---

### Section 11: Governance and Evolution

**Accurate claims:**
- The backward compatibility record is accurately characterized by all council members as exceptional. The detractor's qualification that "removed from the standard" does not mean "compilers stop supporting it" [detractor, §11] is accurate and important for understanding what the governance model actually delivers: not feature removal but feature de-emphasis.
- The historian's documentation of the Fortran 90 standardization saga (13 years from FORTRAN 77 to Fortran 90; ISO WG5 overriding the US national body process to force completion) [historian, §11] is accurate and revealing. The governance process has historically been slow enough to require external pressure to complete.
- The realist and practitioner correctly identify that the coarray adoption lag illustrates a key governance gap: standardization does not create compiler implementations, and the gap between "in the standard" (2008) and "mature in production compilers" (late 2020s) represents at least a 15-year lag for a core concurrency feature [realist, §11].
- The detractor's identification of J3's INCITS fee structure as a governance participation barrier [detractor, §11] is documented [J3-HOME]. Individual researchers and small academic groups are structurally disadvantaged relative to commercial compiler vendors.

**Corrections needed:**
- The apologist's characterization of Fortran 2023 "removing" features like COMMON and EQUIVALENCE [apologist, §11] should be qualified. The detractor correctly notes that these features are removed from the standard but that compilers continue to support them. For a systems architect assessing upgrade cost, the practical consequence of "standard removal" in Fortran is close to zero in the short term: existing code continues to compile, and large-scale HPC programs using these features face no forced migration timeline. This is the right policy for the domain, but characterizing it as "removal" overstates the cleanup achieved.
- The realist's statement that "governance is effectively controlled by whoever funds the compilers" [realist, §11] is directionally accurate but slightly overstated. The J3/WG5 consensus process does give compiler vendors disproportionate influence (they have the most to lose from standard changes that require implementation work), but the process has also overridden vendor preferences on several features. The more precise characterization is that governance is constrained by whatever compiler vendors are willing to implement, since a standardized but unimplemented feature has no practical value.

**Additional context (systems architecture perspective):**

*The ifort discontinuation as a governance case study.* Intel's discontinuation of the classic ifort compiler in the oneAPI 2025 release [INTEL-IFX-2025] is the most operationally significant governance event of the past five years, and the council treatment understates its systems-level impact. Production HPC centers that relied on ifort had built their performance-tuned workflows around ifort's specific optimization behaviors: auto-vectorization heuristics, loop fusion decisions, profile-guided optimization profiles. Migrating to ifx requires:
1. Revalidating numerical results (different optimization choices can produce different floating-point rounding behaviors)
2. Re-tuning performance-critical compiler flag combinations
3. Rebuilding and re-linking all libraries that shipped as ifort-compiled binaries
4. Updating build systems that referenced ifort-specific flags

The J3/WG5 governance process had no mechanism to prevent or slow this migration. Intel made a product decision; the entire ecosystem dependent on ifort must respond. For a governance model premised on stability and backward compatibility, this is a significant structural gap: the most consequential changes to the production landscape can be made unilaterally by commercial vendors, outside the committee process entirely.

*The fortran-lang parallel governance track: sustainability risk.* The historian and practitioner both credit the fortran-lang community (founded 2020) with materially improving the practical ecosystem. The systems-architecture concern is sustainability. The fortran-lang core contributors are a small group of scientist-programmers who maintain fpm, stdlib, and fortls in time carved out from their primary employment. The precedent from other volunteer-maintained scientific computing projects (e.g., numpy's near-collapse before NumFOCUS support) suggests this is a live risk. Unlike NumPy, fortran-lang does not appear to have a formal fiscal sponsor or an endowment. A 2–3 year window of contributor attrition could set the ecosystem back significantly. For organizations making 10-year architectural bets on Fortran, the sustainability of the community tooling layer should be explicitly assessed.

*Generics absence as a large-codebase maintenance hazard.* The council correctly notes that parametric generics are absent from Fortran and expected in Fortran 202Y (~2028 at earliest). What the council underweights is the maintenance cost at large-codebase scale. In a 500K+ line HPC physics code that uses both REAL(32) and REAL(64) precision variants, the absence of generics typically produces duplicated code paths: `subroutine foo_r4(...)` and `subroutine foo_r8(...)` with nearly identical bodies, dispatched through generic interface blocks. This duplication is not a hypothetical — it is the standard pattern in production codes like GROMACS and WRF [WRF-FORTRAN-MEDIUM]. Keeping the two precision variants in sync is a sustained maintenance burden; subtle divergences between them — an optimization in the r8 version not propagated to r4, a bug fix in one branch not applied to the other — are a known source of correctness issues in large Fortran codebases. The 202Y generics proposal is the highest-priority structural improvement from a large-codebase maintainability perspective, and the current ~2028 timeline means current systems will carry this burden for at least another 3–5 years.

---

### Other Sections (systems-architecture concerns)

**Section 4: Concurrency and Parallelism — competing model proliferation.**

The three primary Fortran concurrency mechanisms — MPI (distributed memory), OpenMP (shared memory), and coarrays (standardized PGAS model) — are not alternatives but a layered stack. Large production HPC codes typically use MPI for inter-node communication, OpenMP for intra-node thread parallelism, and potentially OpenACC or DO CONCURRENT for GPU offload. The result is programs with three or four distinct concurrency models that developers must understand simultaneously. This creates significant team-scale cognitive load: a new developer joining a major climate model must understand MPI communicator topology, OpenMP thread scoping rules, and coarray image management before they can safely modify the concurrent portions of the code. The mental models for each mechanism are substantially different, and bugs at the intersection of two models (e.g., MPI communication in a routine called from within an OpenMP parallel region) are notoriously difficult to diagnose.

From a systems-architecture perspective, DO CONCURRENT deserves particular attention as a reliability risk: it is a programmer assertion (these loop iterations are independent) with no compiler verification. A programmer who incorrectly asserts independence gets silent wrong results, not a compilation error. The optimization payoff is real, but the risk-to-benefit assessment for safety-critical or scientifically critical code should include the cost of silent incorrectness when the assertion is violated.

**Section 8: Developer Experience — team-scale onboarding.**

The practitioner perspective correctly identifies the two populations (domain scientists, software engineers) and the distinct onboarding challenges. The systems-architecture concern that neither the practitioner nor any other council member fully quantifies is the onboarding cliff for mixed-era codebases. An engineer joining a WRF or CESM development team encounters code written across five decades — FORTRAN 77 fixed-form kernels from the 1980s, Fortran 90 module refactors from the 2000s, OpenMP additions from the 2010s, GPU offload experiments from the 2020s — with no layer separation and often no documentation distinguishing which era's conventions apply in which file. This is not legacy code in the ordinary sense; it is geologically layered code where the rules change depending on when the file was written. Getting to productive contribution in a codebase like this is a 6–12 month process in practice, not the weeks that a well-documented modern codebase requires. The systems-architecture consequence is that team scaling is difficult: the ramp-up cost per new team member is high, which limits how many new engineers a Fortran HPC team can effectively absorb per year.

**Section 9: Performance — the LLVM Flang compiler transition risk.**

The production compiler landscape is in active transition. ifort is discontinued; GFortran's optimization characteristics differ from ifort's; LLVM Flang is the stated forward path but carries a ~23% performance gap. For production HPC codes that run millions of CPU-hours per year, a 23% runtime regression from a compiler change is not acceptable without validation and possible code-level tuning. The systems-architecture concern is that the transition from ifort to ifx/Flang is not a drop-in migration: it requires performance validation per workload, potentially re-tuning numerical correctness criteria (floating-point results may differ at the last significant bit), and rebuilding performance benchmarks from scratch. HPC centers typically do not have engineering bandwidth to validate a new compiler before their allocations expire. The operational risk window for the compiler transition is real and currently open.

---

## Implications for Language Design

**1. Binary module portability must be designed in from the start, not retrofitted.**

Fortran's non-standard `.mod` file format has created a structural constraint on library distribution that 70 years of standardization has not resolved [FORTRANWIKI-MOD]. The consequence is that the entire Fortran ecosystem operates on source-only distribution: every user builds every dependency, every compilation chain must be monolithic with respect to compiler and version, and binary library sharing across institutions is impractical. Languages that design a stable, standardized module interface format from the beginning — as Rust's `.rlib` format and C's header/ABI model do, however imperfectly — avoid this constraint entirely. The lesson for language designers: module interface portability is an explicit design requirement, not a consequence of getting everything else right. Defer it, and the ecosystem will work around it in ways that calcify into permanent structural limitations.

**2. Governance velocity should be matched to the language's adoption phase, not its legacy phase.**

Fortran's 5-year standards cycle was calibrated to the needs of its large installed base — stability, backward compatibility, multi-stakeholder consensus. This calibration made sense when Fortran was dominant. In 2026, when Fortran must compete for new scientific projects against Python+NumPy, Julia, and Rust, the same 5-year cycle creates a competitive disadvantage: features the community urgently needs (generics, better string handling, structured error propagation) arrive in 2028–2030, while competing languages iterate annually or semi-annually. The lesson: a language governance model that served the language at scale may become an adoption barrier when the language needs to attract new users. Governance should have a mechanism for distinguishing between stability-critical core changes (where slow consensus is appropriate) and ecosystem-building improvements (where faster iteration is warranted).

**3. Vendor unilateral decisions are governance events regardless of committee structure.**

The ifort discontinuation [INTEL-IFX-2025] demonstrates that for a language dependent on commercial compiler implementations, the most consequential changes to the production landscape occur outside the formal governance process. The J3/WG5 committee can standardize language features carefully and maintain backward compatibility commitments — but it cannot prevent a major vendor from discontinuing a compiler that the entire community depends on. Language designers should design governance models that include mechanisms for responding to vendor-ecosystem disruptions: emergency maintenance arrangements, transition funding, or explicit policies about minimum compiler support lifecycles. A language whose governance only covers the standard, not the implementation ecosystem, has a structural blind spot for its most operationally significant risks.

**4. HPC-scale CI/CD integration is an unsolved ecosystem problem with serious correctness implications.**

Fortran's domain concentration in MPI-parallel HPC creates a testing infrastructure gap that has no standard solution. Testing parallel Fortran codes at scale — to catch bugs that only manifest with specific process counts, problem sizes, or communication patterns — requires HPC cluster resources that standard CI/CD environments cannot provide. The result is that large Fortran codes are tested less thoroughly than their critical role warrants: unit tests run on CI, but integration tests at production scale run infrequently and manually. Language designers targeting HPC or other resource-intensive domains should treat CI/CD integration as a first-class design concern, not an afterthought. This includes considering: lightweight simulation environments for parallel testing, tiered testing strategies that capture most bugs without full-scale resources, and tooling that makes it easier to parameterize and script large-scale validation runs.

**5. The "appropriate for the domain" argument is a useful but dangerous design heuristic.**

Multiple council perspectives defend Fortran's ecosystem limitations (thin package registry, source-only distribution, no binary ABI) as appropriate for the scientific computing domain's actual needs. This argument has merit for some limitations, but it has also served as a rationalization for allowing structural deficits to persist. The absence of a package manager for 63 years was not domain-appropriate; it was ecosystem neglect that a 2020 volunteer effort had to partially address. The `.mod` non-portability is not domain-appropriate; it is a genuine barrier to cross-institutional collaboration that would be solved if anyone had solved it. Language designers should be skeptical of "appropriate for the domain" reasoning when it is used to justify deficits that competing languages or tools have solved in their own ecosystems. The question is not "does this deficit feel appropriate?" but "does this deficit impose a real operational cost that a plausible solution would eliminate?"

**6. Dual-timescale codebases — combining modern and legacy language features — require explicit migration tooling to remain maintainable.**

Fortran's backward compatibility has created codebases that are stratigraphic records of programming practice across five decades. This is not unique to Fortran — COBOL and C face similar dynamics — but Fortran's domain concentration in validated scientific code makes the migration particularly slow: correctness validation of a physics kernel is expensive, so migration proceeds only when forced. The practical consequence is codebases where FORTRAN 77 fixed-form subroutines from 1988 are called by Fortran 90 modules written in 2001, themselves called by Fortran 2018 procedures written in 2022. Understanding the full behavioral contract of any interface requires knowing which decade its conventions come from. Language designers who commit to strong backward compatibility should plan for this outcome and provide: migration tooling (automated modernization, linter flags for legacy idioms), documentation that distinguishes current best practice from legacy support, and governance processes that actively reduce the legacy surface over time rather than indefinitely accumulating it.

---

## References

[FORTRANWIKI-MOD] Fortran Wiki. "Modules and Submodules." https://fortranwiki.org/fortran/show/Modules. Accessed 2026-02-28.

[INTEL-MOD-COMPAT] Intel. "Intel Fortran Compiler Module File Compatibility." Intel oneAPI Documentation. https://www.intel.com/content/www/us/en/docs/fortran-compiler/developer-guide-reference/. Accessed 2026-02-28.

[FORTRAN-ABI-YARCHIVE] Yarchive.net. "Fortran ABI." https://yarchive.net/comp/fortran_abi.html. Accessed 2026-02-28.

[LINARO-FLANG] Linaro. "LLVM Flang Performance vs. GFortran (2024)." Benchmark data cited in research brief. [LINARO-FLANG]

[INTEL-IFX-2025] Intel. "Intel Fortran Compiler Classic (ifort) Discontinued." oneAPI 2025.0 Release Notes. https://www.intel.com/content/www/us/en/developer/articles/release-notes/oneapi-fortran-compiler-release-notes.html. Accessed 2026-02-28.

[LLVM-FLANG-2025] LLVM Project. "Flang (flang-new renamed to flang in LLVM 20, March 2025)." https://flang.llvm.org/. Accessed 2026-02-28.

[FPM-HOME] fortran-lang. "Fortran Package Manager (fpm)." https://fpm.fortran-lang.org/. Accessed 2026-02-28.

[FPM-2024] fortran-lang. "fpm 0.13.0 release." https://github.com/fortran-lang/fpm/releases. Accessed 2026-02-28.

[ARXIV-TOOLING-2021] Čertík, O., Curcic, M., et al. "Toward Modern Fortran Tooling and a Thriving Developer Community." arXiv:2109.07382. 2021.

[J3-HOME] J3 Fortran Committee. https://j3-fortran.org/. Accessed 2026-02-28.

[WG5-HOME] ISO/IEC JTC1/SC22/WG5 — Fortran. https://wg5-fortran.org/. Accessed 2026-02-28.

[FORTRANWIKI-STANDARDS] Fortran Wiki. "Fortran Standards." https://fortranwiki.org/fortran/show/Standards. Accessed 2026-02-28.

[BLAS-LAPACK-REF] Netlib. "BLAS and LAPACK." https://www.netlib.org/lapack/. Accessed 2026-02-28.

[WRF-FORTRAN-MEDIUM] Curcic, M. "What's the future of Fortran?" Medium / Towards Data Science. Cited in research brief. [WRF-FORTRAN-MEDIUM]

[NASA-FORTRAN-2015] Markus, A. "pFUnit: A Unit Testing Framework for Fortran." NASA Technical Reports. 2015.

[ECP-FLANG] US Department of Energy Exascale Computing Project. "LLVM Flang development funding." https://www.exascaleproject.org/. Accessed 2026-02-28.

[OLCF-OVERVIEW-2024] Oak Ridge Leadership Computing Facility. "Fortran ISO_C_BINDING and Assumed-Rank Arrays." OLCF Training Materials. 2024.

[BACKWARD-COMPAT-DEGENERATE] Metcalf, M., Reid, J., Cohen, M. *Modern Fortran Explained: Incorporating Fortran 2018*. Oxford University Press, 2018. (Backward compatibility discussion.)

[STDLIB-GITHUB] fortran-lang. "fortran-lang/stdlib." GitHub. https://github.com/fortran-lang/stdlib. Accessed 2026-02-28.

[MEMORY-SAFETY-WIKI] Wikipedia. "Memory safety." https://en.wikipedia.org/wiki/Memory_safety. (Re: CISA/NSA CWE-1399 classification.) Accessed 2026-02-28.

[PHRACK-FORTRAN] Phrack Magazine. "Exploiting Fortran." Issue 67, 2010. http://phrack.org/issues/67/. Accessed 2026-02-28.

[NVIDIA-HPC-SDK] NVIDIA. "NVIDIA HPC SDK Documentation." https://docs.nvidia.com/hpc-sdk/. Accessed 2026-02-28.
