# Fortran — Detractor Perspective

```yaml
role: detractor
language: "Fortran"
agent: "claude-agent"
date: "2026-02-28"
```

---

## 1. Identity and Intent

Fortran's identity problem begins with its creator. In 1977, John Backus accepted the ACM Turing Award for inventing FORTRAN and used the occasion to denounce the paradigm he had created. His lecture, "Can Programming Be Liberated from the von Neumann Style?", argued that "the assignment statement is the von Neumann bottleneck of programming languages and keeps us thinking in word-at-a-time terms in much the same way the computer's bottleneck does" [BACKUS-TURING-1978]. Contemporaries described the lecture as "sometimes viewed as Backus's apology for creating Fortran" [BACKUS-TURING-NOTE]. When a language's designer publicly repudiates the paradigm he established — at the most prestigious ceremony in computer science — this is not a footnote. It is a central data point.

The intent behind Fortran was reasonable and contextually appropriate: in 1954, IBM needed to reduce programmer costs and time spent debugging on IBM 704 hardware. Backus and his team designed a language for a specific machine at a specific moment [IBM-HISTORY-FORTRAN]. The problem is that the decisions made for that machine — for the IBM 704's accumulator registers, for 1950s memory constraints, for 6-character identifier limits, for fixed 72-column punch card formatting — were locked into the first formal standard in 1966, and have cast their shadow over every subsequent revision [FORTRANWIKI-STANDARDS].

This is the defining structural failure of Fortran's identity: it was designed as a tool for 1954 and standardized as a permanent specification in 1966. The 1966 standardization did not merely codify best practices; it codified hardware-specific implementation accidents. IMPLICIT typing existed because programmers at IBM were used to it. Fixed-form source existed because punch cards had 80 columns. `COMMON` blocks existed because FORTRAN II (1958) needed shared memory between separately compiled subroutines and the designers did not yet know how to do it better. Each of these decisions became a backward-compatibility commitment that survives — in compiler extensions if not the standard — to this day.

To be fair: the bet Fortran made in 1957 — that compiled high-level code could match hand-written assembly — was radical and was won. That achievement legitimized the entire concept of high-level programming languages. Without Fortran, the trajectory of computing would be different, probably worse. But winning a bet in 1957 does not mean the winning architecture should be operated unchanged in 2026. The case for Fortran's continued relevance is largely not "this language is well-designed" but rather "the codebases written in this language would cost billions to replace." Lock-in masquerading as success is the central illusion of Fortran's identity.

The 2020 community revival (fortran-lang.org, fpm, stdlib) is real and admirable as grassroots engineering. But it is a rescue operation, not a vindication. A language healthy enough to stand on its own merits does not need volunteers to build in 2020 what it should have had by 1990.

---

## 2. Type System

Fortran's type system is a patchwork of seven decades of accretion, with each generation of features layered atop a foundation that was never redesigned to support them. The result is a type system that is simultaneously too restrictive (no algebraic data types, no parametric generics, no meaningful inference) and too permissive (IMPLICIT typing, legacy KIND confusion, escape hatches that abandon type safety entirely).

### The IMPLICIT Typing Problem

The most damaging default in Fortran's history is IMPLICIT typing: the rule that undeclared variables whose names begin with I, J, K, L, M, N are automatically typed INTEGER, and all others are REAL [INTEL-IMPLICIT-TYPING]. This rule dates to FORTRAN I and was never removed from the standard; it was only made suppressible via `IMPLICIT NONE`. Consider what this means: every Fortran program that omits `IMPLICIT NONE` silently reinterprets typos as new variables. A misspelling of `total` as `totla` creates a fresh `REAL` variable rather than a compilation error. This is not a historical curiosity — it remains the default behavior of conforming Fortran compilers today, meaning new Fortran code compiled without `IMPLICIT NONE` silently does the wrong thing for any undeclared variable.

The community has fully acknowledged this. The fortran-lang.org "Gotchas" page leads with implicit typing as the primary pitfall [FORTRAN-LANG-GOTCHAS]. A J3 issue tracker proposal to eliminate implicit typing notes broad community agreement that it "is a terrible 'feature' that should never be used" [J3-IMPLICIT-ISSUE]. Yet 67 years after FORTRAN I, the feature remains in the standard, enabled by default, because removing it would break backward compatibility. The lesson for language designers is not subtle: if your language's most dangerous default requires a magic incantation (`IMPLICIT NONE`) to suppress, you have institutionalized a footgun that every beginner must be explicitly warned about.

### KIND System Portability Failures

Fortran's KIND system — the mechanism for specifying the precision and size of numeric types — is broken by design. The language standard does not specify which KIND numbers correspond to which storage sizes. `INTEGER(KIND=4)` means 4-byte integers on most modern compilers, but the standard explicitly does not require this [GCC-KIND-PARAMS]. A compiler could legally assign KIND=37 to its 4-byte integer type. As a consequence, every large Fortran codebase that uses literal KIND numbers (`INTEGER*4`, `REAL*8`, `INTEGER(KIND=4)`) is technically non-portable, even if it happens to run on most common compilers [PORTABILITY-KIND-NARKIVE].

The portable solution — using `SELECTED_INT_KIND`, `SELECTED_REAL_KIND`, or the named constants (`INT32`, `REAL64`) from `ISO_FORTRAN_ENV` — was not standardized until Fortran 2003. This means there are decades of HPC code written with non-portable KIND literals, code that happens to work on the small set of compilers used in practice but could fail on any compiler that chose different KIND values. The research brief's "Proposed and Rejected Features" section does not even mention this — the KIND portability problem is so endemic that it barely registers as a design issue any more. That normalization of a broken feature is itself revealing.

### No Algebraic Data Types, No Sum Types

Fortran 2003 added object-oriented features — type extension, type-bound procedures, `CLASS(T)` polymorphism — but these additions did not add tagged unions or discriminated types. There is no way in Fortran to express "this value is either an integer or an error, and the compiler enforces that you check which before using it." The research brief confirms: "Fortran has no tagged union, variant, or Rust-style enum with data" [RESEARCH-BRIEF]. The Fortran 2023 enumeration types provide named integer constants, not discriminated unions.

This matters enormously for error handling (discussed in Section 5) and for generic data structure design. Without sum types, you cannot write type-safe optional values, type-safe result types, or type-safe event unions. You can approximate these with derived types containing a discriminant INTEGER field and several components, but the compiler does not help you: there is no exhaustiveness checking, no automatic dispatch, no guarantee that code reading the discriminant handles every case. The OOP features were grafted onto a type system that was designed for numerical computation and lacks the primitives for modern type-safe programming.

### No Parametric Generics

Fortran still has no parametric generics. The workarounds are:
- **Elemental procedures**: operate on any rank of array, but only for procedures, not data structures
- **Generic interfaces**: overload a name to dispatch to kind-specific implementations, requiring separate implementations for REAL32, REAL64, REAL128, etc.
- **`CLASS(*)`** (unlimited polymorphism): accepts any type but abandons static type dispatch entirely

A template/generic feature proposal is "under active discussion for the post-2023 standard" — Fortran 202Y [J3-HOME]. This means that in 2026, 69 years after FORTRAN I, Fortran's users are still waiting for parametric generics. The cost has been enormous: every numerical library that needs to work on multiple precisions must duplicate its code. The LAPACK codebase, for instance, maintains separate `S` (REAL), `D` (DOUBLE PRECISION), `C` (COMPLEX), and `Z` (DOUBLE COMPLEX) prefixed versions of every routine — four copies of the same algorithm with different type substitutions, all maintained in parallel. Parametric generics would eliminate this maintenance burden entirely. After 69 years, "we're working on it" is not a reassuring answer.

---

## 3. Memory Model

Fortran is classified as a memory-unsafe language by CISA/NSA guidance [MEMORY-SAFETY-WIKI]. This is the correct classification, and the euphemisms commonly deployed to soften it deserve scrutiny.

### Bounds Checking: Unsafe by Default in All Production Builds

The most consequential memory safety failure is the default. Array bounds checking is available in every major Fortran compiler, but it is disabled by default in production builds. The rationale is performance: bounds checking imposes overhead on the numerical kernels that Fortran is used for. So in production, accessing `A(1000)` in a 100-element array silently reads memory at an unpredictable location, potentially producing silently wrong scientific results, potentially corrupting memory, potentially crashing. The compiler flag exists (`gfortran -fcheck=bounds`, `ifx -check bounds`) but must be explicitly requested [FORTRAN-DISCOURSE-BOUNDS].

This is not a trivial problem for scientific computing. Silent wrong answers are in some ways worse than crashes: a segfault tells you something went wrong; a subtly wrong atmospheric model result may not be caught for months, if at all. The defense that "bounds checking is available as a flag" is true but insufficient. A language design that makes unsafe behavior the default, and safety the opt-in, has the wrong default.

### POINTER: A Footgun in Conservative Packaging

Fortran pointers are not C pointers — they cannot perform arbitrary arithmetic, which reduces (but does not eliminate) their danger. But they introduce four specific failure modes:
1. **Undefined initial status**: A declared `POINTER` variable has undefined association status until explicitly nullified. Calling `ASSOCIATED(ptr)` on an uninitialized pointer is undefined behavior — the result is meaningless [RESEARCH-BRIEF].
2. **Memory leaks**: Pointers to allocated memory must be explicitly deallocated; there is no scope-based cleanup for pointer targets (unlike `ALLOCATABLE`).
3. **Dangling pointers**: Pointing a Fortran pointer at a variable that later goes out of scope creates a dangling reference with no compiler detection.
4. **Aliasing bugs**: Multiple pointers can legally refer to the same storage; code that assumes non-aliasing will compute silently wrong results.

The conservative restriction on pointer arithmetic is a genuine improvement over C. But the association status problem — that `POINTER` variables require `NULLIFY` before they can be safely queried — is a design flaw that a language with better defaults (Rust's ownership model, even C++'s `nullptr`-initialized smart pointers) would not have.

### COMMON and EQUIVALENCE: Type Safety Violations Standardized

For decades, the Fortran standard contained `COMMON` blocks and `EQUIVALENCE`, two features that deliberately circumvent the type system. `COMMON` blocks allow disparate subroutines to share named memory regions with no type checking — a subroutine can declare `COMMON /BLOCK/ A, B` as integers while another sees the same memory as reals. `EQUIVALENCE` allows two variables of different types to overlap in storage, treating the same bytes as different types simultaneously.

These features were declared obsolescent in Fortran 90 (a full 35 years after their introduction) and finally removed from the Fortran 2023 standard [FORTRANWIKI-F2023]. "Removed from the standard" is the committee's polite way of saying what the research brief acknowledges: "compilers continue to support them as extensions to maintain backward compatibility" [RESEARCH-BRIEF]. The practical impact of removal is therefore limited — any codebase using `COMMON` blocks today can be expected to compile with any major compiler for the foreseeable future. The entire HPC codebase written in FORTRAN 77 idioms between 1966 and 1990 remains compilable and is regularly compiled.

### Column-Major Storage: A Perpetual Interface Bug Factory

Fortran stores multidimensional arrays in column-major order (first index varies fastest), the opposite of C's row-major convention [RESEARCH-BRIEF]. This is not wrong — it is simply different. But its implications for correctness are severe: any Fortran code that passes arrays to C libraries, to Python (NumPy defaults to row-major), or to any other language must either explicitly transpose data or carefully reason about which axis is contiguous. Getting this wrong produces silently wrong results, not errors. The long coexistence of Fortran and C in HPC codebases means this correctness burden recurs at every language boundary, in every codebase, for every developer who joins the project.

---

## 4. Concurrency and Parallelism

Fortran's concurrency story is a fragmented experiment that illustrates what happens when a language committee standardizes features that are not yet well understood, implements them without the ecosystem support to make them useful, and then watches developers ignore them in favor of external libraries.

### FORALL: A Spectacular 23-Year Failure

`FORALL` was introduced in Fortran 95 with the stated goal of enabling compilers to automatically parallelize and vectorize array assignments. It failed. The semantics were misunderstood by nearly everyone who used it: programmers expected `FORALL` to behave like a parallel `DO` loop, but it actually executes each statement in its body for all active indices before advancing to the next statement — a sequence of array assignments, not a parallel loop [FORALL-INTEL-DISCUSSION]. This semantic mismatch meant that `FORALL` constructs were harder for compilers to optimize (due to more restrictive dependencies) and harder for programmers to reason about (due to counterintuitive execution semantics) than ordinary `DO` loops.

After 23 years in the standard — from Fortran 95 (1997) to Fortran 2018 (2018) — `FORALL` was declared obsolescent and displaced by `DO CONCURRENT` [FORTRANWIKI-STANDARDS]. Obsolescent, not removed: `FORALL` is still legal Fortran, still compilable, still in millions of lines of HPC code. A language design lesson worth naming explicitly: when a feature fails, the Fortran governance model cannot actually remove it. The obsolescence mechanism is a warning label that does not prevent use. The feature remains a trap for new developers reading old code indefinitely.

### Coarrays: Standardized Before Ready

Coarrays were standardized in Fortran 2008 as a native parallel programming model. By 2024 — sixteen years after standardization — compiler support for the full Fortran 2018 coarray specification "was still maturing" [RESEARCH-BRIEF], with Intel ifx having the most complete implementation. This is a pattern of standardization ahead of implementation readiness: the standard exists, but actual use requires choosing a compiler based on coarray support, and mixing compilers (already impossible due to ABI and .mod file incompatibility) becomes even more fraught.

Coarray adoption is low relative to MPI+OpenMP in practice. The HPC community has decades of experience, tooling, and libraries built on MPI. Coarrays are theoretically cleaner but require compiler support that has been "maturing" for a decade and a half. The new parallel model was added to the language without the ecosystem necessary to make developers actually switch.

### Three Parallel Models That Don't Compose

A Fortran HPC program today uses three distinct parallel programming models:
1. **MPI**: for distributed-memory inter-node communication. Not part of the language; a C library with Fortran bindings. Correctness guarantees are entirely the programmer's responsibility.
2. **OpenMP**: for shared-memory intra-node thread parallelism. Not part of the language; compiler directive (`!$OMP`) pragmas that are silently ignored by compilers without OpenMP support.
3. **Coarrays**: native PGAS-based parallelism. Part of the language but with immature tooling and low adoption.

These models cannot easily be composed: combining MPI and OpenMP requires careful management of which threads interact with MPI communicators. Adding coarrays to an MPI program introduces complexity around synchronization and memory visibility that each model handles differently. The language provides no abstractions that unify these models or help programmers reason about their interaction. "Fortran HPC code" in practice means code that uses all three models with no language-level guardrails at any boundary between them.

### `DO CONCURRENT` Is a Hint, Not a Guarantee

`DO CONCURRENT` informs the compiler that loop iterations have no data dependencies, enabling vectorization and parallelization. But it does not create threads, does not guarantee parallelism, and does not provide any verification that the declared independence is actually true — an incorrect `DO CONCURRENT` annotation produces silently wrong results just as an incorrect `!$OMP PARALLEL DO` can. The feature is a programmer assertion, not a compiler-verified contract. The analogous issue exists in OpenMP, but at least OpenMP is explicit about being directive-based. `DO CONCURRENT` looks like a language feature while behaving like a pragma.

---

## 5. Error Handling

Fortran's error handling model is the most structurally defective aspect of the language, and it is the one most likely to cost scientists and engineers correctness in production. After 69 years, Fortran still has no exception handling, no result type, and no standardized error propagation mechanism across call boundaries.

### The `IOSTAT` Pattern: Silent Failure at Scale

The primary error handling mechanism for I/O operations is the `IOSTAT=` specifier, which returns 0 on success and a positive integer on failure. The `STAT=` specifier serves the same function for memory allocation and deallocation. Consider what this means in practice: if a programmer forgets to include `IOSTAT=stat` in a `READ` or `WRITE` statement and an I/O error occurs, the program either terminates (for certain fatal errors) or silently continues with undefined state, depending on the compiler and runtime. The language provides no mechanism to force error checking — the specifier is optional [FORTRAN-WIKIBOOKS-ERR].

Compare this to languages that make error handling mandatory: Rust's `Result<T, E>` type cannot be ignored without an explicit `unwrap()` or `?` that makes the choice visible. Go's multiple return values for errors are at least visible at the call site, even if ignorable. Fortran's `IOSTAT=` is not even required to be present. This is an error-handling model that trusts programmers to remember to check for errors at every call site, consistently, across decades-old codebases maintained by rotating teams of researchers. That trust is regularly violated.

### No Error Propagation Mechanism

There is no standardized mechanism for propagating errors across call boundaries in Fortran. If a subroutine detects an error condition, it can:
- Terminate the program (STOP, ERROR STOP)
- Set an intent(out) integer argument and return
- Print an error message and return with a sentinel value

None of these propagates cleanly. A caller of a subroutine that sets an error status must itself handle that status and propagate it to its own caller, and so on through the call stack. In practice, this means either: (a) programs terminate on any error (making them brittle and unusable for production batch runs where partial recovery is essential), or (b) programmers pass `IOSTAT`-style status arguments manually up the call stack (creating verbose, boilerplate-heavy code that is frequently omitted). Third-party libraries like `errstat` exist to address this gap [ERRSTAT-GITHUB], but a fundamental limitation that requires a third-party library to work around is a fundamental limitation.

### IEEE Exception Handling: Theoretically Available, Rarely Sufficient

Fortran 2003 added the `IEEE_ARITHMETIC`, `IEEE_EXCEPTIONS`, and `IEEE_FEATURES` modules for handling floating-point exceptional conditions (divide-by-zero, overflow, underflow, invalid operation). These modules provide real functionality, but they address only the specific domain of floating-point exceptions and require explicit halting mode configuration that must be set before use. The IEEE exception model is not integrated with the rest of Fortran's error handling — you cannot use `IEEE_EXCEPTIONS` to propagate an allocation failure or an I/O error. The result is two separate error-handling vocabularies that cover different exception classes and cannot be unified.

### The Structural Impossibility of Retrofitting Error Handling

This is genuinely structural, not fixable. The research brief notes that "community proposals have been discussed in J3 but not adopted" for native exception handling [RESEARCH-BRIEF]. The reason it has not been adopted — and will not be — is backward compatibility. Introducing `try`/`catch` semantics or mandatory result types into Fortran would require retrofitting the millions of existing library and application call sites to handle or propagate errors in a new way. Every existing BLAS, LAPACK, and MPI subroutine signature would need to change. The backward-compatibility commitment that defines Fortran governance makes this impossible.

This is the canonical illustration of why design decisions in programming languages compound: the absence of error handling in FORTRAN I created an ecosystem where every library was designed around the absence of error handling, making the error handling problem harder to fix with each passing year. By 2026, the problem is unfixable without breaking everything. Language designers should understand that no error model is a permanent error model.

---

## 6. Ecosystem and Tooling

### Sixty-Three Years Without a Package Manager

fpm (Fortran Package Manager) was created in 2020 [FPM-HOME]. FORTRAN I shipped in 1957. For 63 years, Fortran had no standard package manager. The consequences are visible in every HPC codebase: custom Makefiles, Autotools configurations, CMake scripts of varying quality, bespoke build systems. Each major scientific code (WRF, VASP, CESM, CP2K) has its own build infrastructure that developers must learn to use before they can contribute. The ecosystem fragmentation that a package manager prevents was allowed to compound for six decades.

When fpm arrived, it was a genuine improvement — but it arrived into an ecosystem that had already built its infrastructure in every other way. Large HPC codes with years of CMake investment will not migrate to fpm. The nascent fpm registry has no security infrastructure (signing, advisories, vulnerability scanning) [RESEARCH-BRIEF]. The community's own 2021 paper acknowledged the pre-fpm situation as a genuine problem requiring community intervention [ARXIV-TOOLING-2021].

### The Standard Library That Isn't

Fortran's intrinsic library is reasonably complete for numerical operations but conspicuously absent of general-purpose utilities: no hash maps, no standard sorting, no string split/join/regex, no file-system utilities, no networking, no JSON/XML parsing [RESEARCH-BRIEF]. The `fortran-lang/stdlib` project (funded and developed by volunteers since 2020) addresses some of these gaps. But `stdlib` is not part of the ISO standard. A user of `stdlib` is depending on a community project, not on a language specification. There are no guarantees of API stability, no formal backwards compatibility commitment, and no standardization of behavior across implementations.

The standard library gap matters for portability: if you write a Fortran program that uses `stdlib`'s hash map, you have a dependency that is not part of the language and that another user may not have installed. The language has outsourced its general-purpose utility story to a volunteer project that has been active for six years.

### The Major Fortran Libraries Are Not Fortran

BLAS (Basic Linear Algebra Subprograms) and LAPACK (Linear Algebra PACKage) are the foundational libraries of numerical computing, and they are reference-implemented in Fortran. But the implementations actually used in production — Intel MKL, OpenBLAS, BLIS — are predominantly written in C and hand-coded assembly, with Fortran-compatible interfaces [BLAS-LAPACK-REF]. The reference Fortran implementations are correct but slow; the fast implementations are in other languages.

Similarly, NetCDF, HDF5, and FFTW — the major I/O and FFT libraries used by Fortran HPC codes — are C libraries with Fortran bindings. The Fortran ecosystem's major libraries are, at the implementation level, largely C. Fortran's practical role in this ecosystem is often the calling code, not the library code.

### The .mod File Problem: No Portability Between Compilers

Fortran module files (`.mod`) are the mechanism for separate compilation of modules. They are not standardized. Each compiler generates its own binary format; GFortran `.mod` files cannot be used with Intel ifx, and neither can be used with LLVM Flang [FORTRANWIKI-MOD]. This is not an implementation detail — it is a fundamental limitation of the ecosystem: a Fortran library distributed as compiled `.mod` files is usable only by the same compiler (and often the same compiler version) that built it [INTEL-MOD-COMPAT].

The practical consequence is that Fortran libraries must either be distributed as source code (requiring users to build them) or distributed with pre-compiled modules for each supported compiler/version combination. This fractures the distribution model: a Fortran library must be tested and built for GFortran, Intel ifx, LLVM Flang, NVIDIA nvfortran, and Cray/HPE separately. There is no standard ABI [FORTRAN-ABI-YARCHIVE]. The comparison to C is instructive: C's lack of a standard ABI is a genuine problem, but C at least has standardized header files. Fortran has neither standard module file format nor standard ABI.

### No Standard Preprocessor

Fortran has no standard preprocessor. Codebases that need conditional compilation (for different platforms, compiler capabilities, or build configurations) use the C preprocessor (`cpp`) invoked via compiler flags [RESEARCH-BRIEF]. This creates a dependency on a C tool for a language that ostensibly does not require C, produces portability issues (the C preprocessor tokenizes differently than Fortran source), and means that Fortran's build tooling is effectively a superset of C's build tooling even for programs that never call C.

---

## 7. Security Profile

Fortran is not an internet-facing language and its typical deployment environment (HPC clusters with controlled access) limits its practical attack surface. That mitigating context should be acknowledged. But mitigating deployment context is not the same as a good security profile, and language designers should not take Fortran's security situation as a model.

### Memory Safety: The CISA/NSA Classification Is Correct

CISA and NSA guidelines classify Fortran as a memory-unsafe language [MEMORY-SAFETY-WIKI]. The specific risks are:
- **Out-of-bounds array access**: Legal when bounds checking is disabled (the production default). Produces undefined behavior: silently wrong results, memory corruption, or crash.
- **Undefined pointer association status**: Querying an uninitialized `POINTER` via `ASSOCIATED()` is undefined behavior.
- **Memory leaks via POINTER**: Pointer targets must be explicitly deallocated; the language provides no scope-based safety net for them.
- **COMMON/EQUIVALENCE type confusion**: Deliberately overlapping storage of different types in the same memory [RESEARCH-BRIEF].

The 2010 Phrack article documenting techniques for exploiting Fortran memory corruption (buffer overflows, pointer abuse) established that Fortran programs are exploitable under the right access conditions [PHRACK-FORTRAN]. The access conditions (physical or network access to HPC clusters) are different from web service attack conditions, but nation-state actors and research thieves do target HPC systems.

### Supply Chain: Zero Security Infrastructure

The Fortran ecosystem has no supply chain security infrastructure whatsoever. No package signing, no advisory database, no automatic vulnerability scanning, no verified release mechanism. Legacy scientific codes distribute as tarballs from institutional servers with no cryptographic verification. The fpm registry is nascent and lacks even the basic security features of PyPI, npm, or crates.io [RESEARCH-BRIEF].

This is less dangerous than it sounds because the user base is small and specialized, and Fortran code rarely processes untrusted external input. But the argument that "we don't need security infrastructure because we're a niche language used in controlled environments" is exactly the argument that gets HPC centers compromised. The supply chain for HPC tools (compilers, runtime libraries, numerical packages) is a meaningful attack surface, and Fortran has invested nothing in defending it.

### Compiler CVEs: A Pattern Worth Noting

The Intel Fortran Compiler CVE record is dominated by Uncontrolled Search Path (CWE-427) vulnerabilities: CVE-2024-28881 and CVE-2022-38136 both describe local privilege escalation via uncontrolled search path in the installer and compiler binaries [NVD-CVE-2024-28881] [NVD-CVE-2022-38136]. This is not a language-level vulnerability pattern, but it reflects the security posture of the ecosystem's most important commercial compiler: the tool that HPC centers rely on for production builds has been publishing local-privilege-escalation CVEs in recent years. The security hygiene of the toolchain matters for any language.

---

## 8. Developer Experience

Fortran's developer experience problem is not primarily about syntax or ergonomics. It is about the weight of history that every new Fortran developer must carry.

### The Legacy Learning Burden

To work effectively with Fortran in an HPC environment, a developer must learn:
1. **Modern Fortran (90+)**: modules, allocatables, OOP, coarrays, `DO CONCURRENT`
2. **FORTRAN 77 idioms**: fixed-form source, `COMMON` blocks, `EQUIVALENCE`, `GOTO`, `CONTINUE`, 6-character identifier limits, `DATA` statements — because every major HPC codebase contains decades of FORTRAN 77 code
3. **Legacy KIND conventions**: `INTEGER*4`, `REAL*8` notation (non-standard but ubiquitous)
4. **Multiple concurrency models**: MPI, OpenMP, and possibly coarrays — three different programming models with different mental models

A new developer inheriting a CESM or WRF codebase does not start with modern Fortran. They start with files that contain `IMPLICIT REAL (A-H,O-Z)`, labeled `DO` loops terminated with `CONTINUE`, `COMMON /BLKDAT/ A, B, C`, and undeclared variables. The language is nominally modern Fortran 2018, but the codebases are a stratigraphic record of 60 years of practice. Modern Fortran's improvements are real; the question is whether a developer who spends 70% of their time reading FORTRAN 77 code benefits from them.

### Invisibility in Tooling and AI Assistance

Fortran does not appear in the Stack Overflow Annual Developer Survey results for 2024 or 2025 — it is below the reporting threshold [SO-SURVEY-2024]. This invisibility has compounding consequences. Stack Overflow's question database for Fortran is sparse; when a developer encounters an unusual error, the chance of finding a relevant Stack Overflow answer is lower than for any mainstream language. AI coding assistants (GitHub Copilot, Claude, ChatGPT) train primarily on code available in public repositories; Fortran's lower density in that corpus means AI suggestions for Fortran code are less reliable, less idiomatic, and more prone to hallucinating non-existent intrinsics or invalid syntax.

The research brief notes that the Fortran community has discussed AI-assisted code modernization (FORTRAN 77 → modern Fortran) as a use case [RESEARCH-BRIEF]. This is a genuinely interesting application. But the practical experience is that AI tools make more errors with Fortran than with Python, TypeScript, or Rust — precisely because the training corpus is smaller. A language whose developer experience depends partly on AI assistance has a disadvantage proportional to its AI tooling quality.

### Fixed-Form Source: Still Legal

Fixed-form source format — 72-column line width, column 6 for continuation character, columns 1-5 for labels — is still a valid Fortran source format in the 2023 standard. Any conforming Fortran compiler must accept it. Any Fortran developer working on legacy code must be able to read and write it. The 72-column limit was set by punch card width in the 1950s. It remains legal in 2026.

Free-form source was added in Fortran 90 (1991). After 35 years of free-form availability, the old format is not removed. It will not be removed as long as any significant codebase uses it, which will be indefinitely. This is what backward compatibility maximalism produces: artifacts of IBM 704 punch card hardware that any conforming Fortran compiler must continue to support.

### Cognitive Overhead of the Type/Kind Interaction

For scientific computing, the interaction between Fortran's type system and its KIND mechanism imposes significant cognitive overhead. Should a programmer use `REAL(8)`, `REAL(KIND=8)`, `DOUBLE PRECISION`, `REAL(KIND=REAL64)`, or `REAL(wp)` (where `wp` is a locally-defined working precision parameter)? All of these may produce the same result on common compilers, but `REAL(8)` and `REAL(KIND=8)` are technically non-portable, `DOUBLE PRECISION` is portable but cannot be parameterized, and `REAL(KIND=REAL64)` requires an `ISO_FORTRAN_ENV` USE statement [FORTRAN-LANG-TYPES]. The "correct" answer (use `REAL(wp)` where `wp` is defined via `SELECTED_REAL_KIND`) is not how most HPC code is actually written. New developers learn the wrong idioms from existing code, use non-portable KIND literals, and produce code that happens to work but is technically incorrect.

---

## 9. Performance Characteristics

Fortran's performance story is genuinely strong for the specific workloads it was designed for: dense numerical computation, array operations, cache-friendly linear algebra. Disputing this would be dishonest. But the performance narrative that Fortran advocates present deserves some critical examination.

### The Narrow Band of Performance Excellence

Fortran's performance advantage over languages like Python (without NumPy) or Julia (for certain workloads) is real. But Fortran's performance relative to C and C++ for compute-bound numerical code is not a gap — it is parity. The Computer Language Benchmarks Game places Fortran in the top tier alongside C, C++, Rust, and Ada for numerically intensive benchmarks [FORTRANWIKI-CLBG]. Parity with C on numerical kernels is excellent. But the CLBG disclaimer is instructive: "more popular languages enjoy higher scores in large part because the implementations have been highly tuned" [CLBG-HOME]. Fortran's CLBG implementations are well-tuned by HPC practitioners; the metric reflects human optimization effort as much as language potential.

Outside the narrow band of dense linear algebra, Fortran's performance characteristics are not competitive:
- **String processing**: Fortran's string handling is slow, with fixed-length character arrays and primitive dynamic string support [RESEARCH-BRIEF]
- **I/O throughput**: Fortran's formatted I/O is slower than binary I/O and "generally uncompetitive with C for high-throughput I/O" [RESEARCH-BRIEF]
- **General-purpose computation**: For anything that is not numerical computation, the language's lack of efficient data structures (no hash maps in the standard library) and poor string performance make it a poor choice

### LLVM Flang's 23% Performance Gap

The new LLVM Flang compiler — the open-source future of Fortran compilation, backed by NVIDIA, AMD, Arm, and US National Laboratories — performs approximately 23% slower than GFortran as of 2024 benchmarks, and 48% slower than Classic Flang [LINARO-FLANG]. This is a significant gap for a community that has chosen LLVM Flang as the forward path. Classic Flang is being phased out in favor of LLVM Flang; Intel's ifort (historically the highest-performing Fortran compiler for Intel architectures) was discontinued in 2024 [INTEL-IFX-2025]. The ecosystem is in transition, and the transition's primary compiler is measurably slower than its predecessor.

### `DO CONCURRENT` as a Compiler Hint

`DO CONCURRENT` is annotated in Fortran documentation as enabling vectorization and parallelization, but it creates no threads and provides no guarantees. The compiler may exploit the declared independence for optimization, or it may not. NVIDIA's nvfortran can target GPU execution via `-stdpar=gpu` [NVIDIA-DO-CONCURRENT], but this is a compiler extension, not standard behavior. The standard defines `DO CONCURRENT` as a programmer assertion; the quality of the optimization depends entirely on the compiler. Code that uses `DO CONCURRENT` expecting GPU execution and runs on a compiler without `-stdpar` support will execute serially with no warning.

---

## 10. Interoperability

### No Standard ABI, No Standard Module Format

Fortran's interoperability between different Fortran compilers is minimal. The `.mod` file format — the mechanism for sharing compiled module interfaces — is compiler-specific and compiler-version-specific [FORTRANWIKI-MOD] [INTEL-MOD-COMPAT]. There is no standard ABI [FORTRAN-ABI-YARCHIVE]. Symbol mangling conventions differ: some compilers append one trailing underscore to symbol names, some append two, some append none. Calling conventions for passing CHARACTER arguments (which carry hidden length arguments) differ between compilers.

The practical consequence: a scientific software package compiled with GFortran cannot be linked against a library built with Intel ifx without recompiling the library from source. In a world where HPC centers offer multiple compilers and scientists collaborate across institutions using different toolchains, this is a constant source of friction. There is no Fortran equivalent of C's header files that can be shared across compiler implementations.

### C Interoperability: 47 Years in the Making

`ISO_C_BINDING`, the standardized mechanism for calling C from Fortran and vice versa, was introduced in Fortran 2003 (published 2004) [RESEARCH-BRIEF]. This is 47 years after FORTRAN I. For nearly five decades, the dominant language for systems programming and the dominant language for numerical HPC computation had no standardized interoperability mechanism. Codebases requiring Fortran-C interoperability before 2003 used non-standard, compiler-specific conventions that differed in calling convention, argument passing, and name mangling.

`ISO_C_BINDING` is a genuine contribution and a model for how to standardize foreign function interfaces. But the 47-year delay left a deep scar: large bodies of HPC code that interface with C libraries do so via pre-standard mechanisms that are technically non-portable, and those conventions are baked into production code that cannot be easily changed.

### String Interoperability: An Ongoing Tax

Character handling at the Fortran-C boundary remains genuinely painful. Fortran `CHARACTER(LEN=N)` arrays carry length information separately from the data; C strings are null-terminated. When calling C from Fortran or vice versa, the programmer must explicitly manage both representations: Fortran passes string length as a hidden extra argument that C functions must account for, or must use `C_CHAR` arrays with explicit null termination [ISO-C-BINDING-NOTE]. Every Fortran program that does string I/O via a C library pays this cognitive tax at every string-handling call site.

### NumPy/Python Integration: Column-Major Meets Row-Major

The most common modern use case for Fortran interoperability is calling Fortran routines from Python (via NumPy, SciPy, or f2py). NumPy defaults to row-major (C) order; Fortran uses column-major. `f2py` handles this by allowing the user to specify `order='F'` for Fortran-order NumPy arrays, but code that forgets this detail — or that passes a C-order array to a Fortran routine expecting Fortran-order — silently computes with a transposed matrix. The correctness burden of column-major/row-major mismatch falls entirely on the developer at every boundary crossing, with no language-level enforcement.

---

## 11. Governance and Evolution

### The Obsolescence Mechanism Is Not Removal

Fortran's governance model uses a multi-step obsolescence process: declare a feature obsolescent (with warnings); in a later standard, remove it from the normative text. FORTRAN 77 features declared obsolescent in Fortran 90 — including `COMMON` blocks, `EQUIVALENCE`, arithmetic `IF`, `GOTO` assigned form — were finally "removed" from Fortran 2023. The scare quotes are warranted: "removed from the standard" means "compilers are no longer required to support it." It does not mean compilers stop supporting it. Every major Fortran compiler continues to support these features as extensions [RESEARCH-BRIEF]. The practical difference between "obsolescent" and "removed" is: one generates a warning and the other might not, depending on compiler settings.

The governance consequence is that bad features in Fortran are effectively permanent. FORALL was in the standard from 1997 to 2018 — 21 years — before being declared obsolescent. It was never experimentally removed, never gated behind a flag, never given a deprecation timeline with a hard deadline. It is still in millions of lines of HPC code, still needs to be understood by developers reading legacy code, and will be compilable indefinitely. A language governance model that cannot actually remove failed features accumulates them; the standard eventually becomes a museum of failed experiments that language designers must work around.

### The 5-Year Cycle Is Slow for Addressing Problems

Fortran operates on approximately a 5-year revision cycle: Fortran 2018 (2018), Fortran 2023 (2023), Fortran 202Y (anticipated ~2028) [RESEARCH-BRIEF]. This cadence is reasonable for a language targeting stability, but it means that a known problem — say, the absence of parametric generics — cannot be addressed faster than the cycle allows. A proposal for generics discussed today would not enter the standard before 2028 at the earliest, and not be broadly implemented before 2030 or later. For a feature that has been missing for 73 years, the 5-year cycle compounds the delay.

### J3 Governance Is Not Open to All

J3 (the US national body for Fortran standardization) operates under the International Committee for Information Technology Standards (INCITS), which charges membership fees. Full participation in J3 — including voting on proposals — requires paying INCITS fees, which effectively restricts governance to corporate and institutional participants who can fund that membership [J3-HOME]. Community voices from individual researchers, small academic groups, and volunteer contributors are structurally disadvantaged relative to corporate participants (Intel, NVIDIA, AMD) whose commercial interests in Fortran compiler development may not align with the broader scientific community's interests.

The fortran-lang.org volunteer community has built genuine community infrastructure (fpm, stdlib, fortls, the fortran-lang.discourse forum) precisely because the formal standards process does not move quickly enough or responsively enough to address ecosystem needs. This is admirable community engineering. It is also evidence of a governance gap.

### The Bus Factor Problem

Fortran's open-source ecosystem has a significant concentration risk. GFortran is the primary free compiler, maintained as part of GCC. The fortran-lang ecosystem (fpm, stdlib, fortls) depends heavily on a small number of core contributors. The research brief notes that the 2020 community revival was driven by "Ondřej Čertík, Milan Curcic and others" [RESEARCH-BRIEF]. The "and others" in a small volunteer community represents a real bus factor risk: if the small number of core maintainers of fpm or stdlib move to other projects (as technical contributors routinely do), the community infrastructure that has been built since 2020 is at risk.

---

## 12. Synthesis and Assessment

### Greatest Strengths

Fortran does some things genuinely well. Its array semantics are native to the language in a way that C's are not, and its elemental/reduction intrinsics make vectorization-friendly code easier to write than in most alternatives. The column-major storage layout, while a portability burden at language boundaries, is optimal for BLAS/LAPACK access patterns. The ALLOCATABLE array mechanism — automatic deallocation at scope exit, contiguous memory layout, no memory leaks — is a better memory management story for dense arrays than anything C offers natively. IEEE arithmetic support is comprehensive and well-standardized. For the specific, narrow workload of dense numerical linear algebra on HPC clusters, Fortran remains competitive.

### Greatest Weaknesses

The structural weaknesses are cumulative and mutually reinforcing:

1. **No error handling after 69 years** — not fixable without breaking backward compatibility
2. **Memory-unsafe by default** — bounds checking off in production, undefined pointer status
3. **No parametric generics after 69 years** — code duplication across numeric kinds is the permanent workaround
4. **IMPLICIT typing as the default** — a footgun that every beginner must be explicitly warned about
5. **Non-portable KIND literals** — non-standard conventions ubiquitous in practice
6. **No standard ABI, no standard module format** — mixing compilers is impossible; library distribution is fragmented
7. **Governance cannot actually remove failed features** — FORALL remained 21 years after failing; COMMON blocks 57 years after becoming a bad practice
8. **Ecosystem built outside the standard** — the package manager, standard library, and language server that modern development requires were built by volunteers starting in 2020, not by the standards body

### Lessons for Language Design

The following lessons are derived from Fortran's specific failures and apply generically to any new language design:

**Lesson 1: The wrong default is permanent.**
Implicit typing seemed reasonable in 1957 and produced decades of subtle bugs. `IMPLICIT NONE` was the workaround, not the fix. Design correct defaults from the beginning; the cost of changing them after adoption is prohibitive. Any language feature that practitioners universally suppress via a workaround is a design failure that will never be corrected.

**Lesson 2: Error handling must be designed before shipping.**
Fortran launched without exception handling in 1957 and still does not have it in 2026. The absence is now structurally unfixable: too many call sites, too many library interfaces, too much backward-compatibility baggage to retrofit. Every year without a proper error model makes the absence harder to fix. Design your error model in the first version, before the ecosystem builds around its absence.

**Lesson 3: Standardize your module format and ABI early.**
Fortran's `.mod` file format was never standardized. The consequence is that different compilers produce incompatible module files, which means libraries cannot be shared across compiler implementations, which fragments the ecosystem into per-compiler silos. C header files are plain text and work everywhere; Fortran module files are binary and work only with the specific compiler version that produced them. A language that wants to support library distribution must standardize its interface format.

**Lesson 4: Package management is a language concern, not an afterthought.**
Fortran went 63 years without a standard package manager. The resulting fragmentation (custom Makefiles, Autotools, CMake, SCons, bespoke systems) imposed maintenance burdens that no amount of later package management can fully repair. Consider package management as a first-class design concern from the start. Rust launched Cargo with the language; the ecosystem benefited immediately.

**Lesson 5: Generics must be first-class from day one.**
The absence of parametric generics in Fortran has forced six decades of code duplication across numeric precision variants. LAPACK maintains four separate implementations of every routine for different precisions. Generic interfaces that overload a name over kind-specific implementations are a maintenance fiction, not a language solution. Any language that performs numerical computation needs parametric generics to avoid combinatorial explosion of precision variants.

**Lesson 6: Features that cannot be removed will be used forever.**
The FORALL construct failed within a few years of its introduction (Fortran 95, 1997) but was not declared obsolescent until Fortran 2018 — 21 years of a failed feature in the standard. It was never removed and never will be, because code that uses it continues to compile. A governance model that lacks the authority to actually remove features will accumulate them; the standard becomes a museum. Design a deprecation process that ends in actual removal, with a timeline, and honor it.

**Lesson 7: Backward compatibility maximalism prevents the evolution the language needs.**
Every revision of Fortran has been constrained by the commitment that the previous standard is a valid subset. This commitment preserved IMPLICIT typing, COMMON blocks, fixed-form source, ERR= branches, FORALL, and dozens of other features that practitioners universally avoid. The cost of backward compatibility is not free — it is paid in cognitive overhead for every developer who must understand the language's history to understand existing code, in ecosystem fragmentation, and in the impossibility of fixing fundamental design mistakes. There is a case for backward compatibility; the case for backward compatibility maximalism is weaker.

**Lesson 8: Ecosystem health requires investment, not volunteer rescue operations.**
Fortran's modern tooling (fpm, stdlib, fortls) was built by volunteers starting in 2020, 63 years after the language shipped. The fact that this rescue operation succeeded says something admirable about the community. It says nothing good about a standards process that allowed the language to go six decades without basic developer infrastructure. Languages succeed or fail based on their ecosystems; standards bodies that treat ecosystem tooling as out-of-scope are abdicating a responsibility that volunteers will either pick up at great cost or not at all.

**Lesson 9: Invisible communities are dying communities.**
Fortran is absent from major developer surveys because its practitioners are systematically underrepresented in the platforms those surveys use. But invisibility in developer communities has consequences: less Stack Overflow coverage, weaker AI tooling support, fewer new developers, steeper learning curves for those who do enter. A language whose community is invisible to the mainstream tooling ecosystem is isolated from the cross-pollination of ideas, the influx of new contributors, and the feedback loops that keep a language healthy. Design for community visibility: make it easy for practitioners to participate in mainstream developer forums, conferences, and discussions.

**Lesson 10: Lock-in is not success.**
The primary reason Fortran is still used for climate modeling and numerical weather prediction is not that it is the best language for those tasks; it is that the existing codebases were written in Fortran and would cost billions to rewrite. This is the sunk cost fallacy institutionalized at the ecosystem scale. It sustains Fortran's usage numbers, but it does not mean that a new climate modeling code starting today would choose Fortran over Julia, Python, or C++. Language designers should design for genuine adoption — for reasons users can freely articulate — rather than designing systems that trap users in place. A language that survives through switching costs rather than comparative advantage is not a role model.

### Dissenting Views

**Dissent 1 — The 69-year argument**
The detractor perspective risks anachronism: judging a language designed in 1954 by standards that did not exist until decades later. No 1954 language has parametric generics, algebraic data types, or result types; those concepts did not exist. The more interesting question is whether Fortran's evolution since 1990 has been adequate, and a reasonable case can be made that Fortran 90's overhaul was genuinely transformative. The apologist would note that the language did evolve substantially, even if not fast enough by some measures.

**Dissent 2 — The deployment context matters**
The memory safety critique loses some force in context. Fortran HPC programs run on cluster systems with controlled access, compile-time-known array sizes, and thoroughly tested code. The CISA/NSA classification is correct but potentially misleading about actual risk: the meaningful memory-safety vulnerabilities have occurred in internet-facing C and C++ code, not in climate models running on ORNL clusters. The security argument is real but should be proportionate.

**Dissent 3 — The community revival is genuine**
The pessimistic reading of the 2020 community revival as a "rescue operation" undervalues what has been achieved: fpm, stdlib, fortls, and fortran-lang.org represent real infrastructure that has materially improved the developer experience. The fact that it required community effort rather than standards-body effort is a governance critique (valid), but it does not diminish the outcome. Fortran in 2026 has a better developer experience than Fortran in 2015, and that improvement is real.

---

## References

[BACKUS-TURING-1978] Backus, John. "Can Programming Be Liberated from the von Neumann Style? A Functional Style and Its Algebra of Programs." 1977 ACM Turing Award Lecture, published Communications of the ACM 21(8), 1978. https://worrydream.com/refs/Backus_1978_-_Can_Programming_Be_Liberated_from_the_von_Neumann_Style.pdf.

[BACKUS-TURING-NOTE] Norman, Andrew. "John Backus's Turing Award Lecture." Tufts University CS. https://www.cs.tufts.edu/~nr/backus-lecture.html.

[IBM-HISTORY-FORTRAN] IBM. "Fortran." IBM History. https://www.ibm.com/history/fortran. Accessed 2026-02-28.

[FORTRANWIKI-STANDARDS] Fortran Wiki. "Standards." https://fortranwiki.org/fortran/show/Standards.

[FORTRANWIKI-F2023] Fortran Wiki. "Fortran 2023." https://fortranwiki.org/fortran/show/Fortran+2023.

[FORTRANWIKI-CLBG] Fortran Wiki. "Computer Language Benchmarks Game." https://fortranwiki.org/fortran/show/Computer+Language+Benchmarks+Game.

[INTEL-IMPLICIT-TYPING] Intel. "Implicit Typing Rules." Intel Fortran Compiler Developer Guide, 2023-1. https://www.intel.com/content/www/us/en/docs/fortran-compiler/developer-guide-reference/2023-1/implicit-typing-rules.html.

[J3-IMPLICIT-ISSUE] GitHub. "Eliminate implicit typing · Issue #90 · j3-fortran/fortran_proposals." https://github.com/j3-fortran/fortran_proposals/issues/90.

[FORTRAN-LANG-GOTCHAS] fortran-lang.org. "Gotchas — Fortran Programming Language." https://fortran-lang.org/learn/quickstart/gotchas/.

[GCC-KIND-PARAMS] GNU. "KIND Type Parameters." The GNU Fortran Compiler. https://gcc.gnu.org/onlinedocs/gfortran/KIND-Type-Parameters.html.

[PORTABILITY-KIND-NARKIVE] comp.lang.fortran. "Portability and kind problems." https://comp.lang.fortran.narkive.com/xixuanXX/portability-and-kind-problems.

[FORTRAN-LANG-TYPES] fortran-lang.org. "Types and kinds — Fortran Programming Language." https://fortran-lang.org/learn/intrinsics/type/.

[MEMORY-SAFETY-WIKI] Wikipedia. "Memory safety." https://en.wikipedia.org/wiki/Memory_safety.

[RESEARCH-BRIEF] Penultima Project. "Fortran — Research Brief." research/tier1/fortran/research-brief.md. 2026-02-28.

[FORTRAN-DISCOURSE-BOUNDS] Fortran Discourse. "Array Bounds Checking - Standard Behavior?" https://fortran-lang.discourse.group/t/array-bounds-checking-standard-behavior/5782.

[PHRACK-FORTRAN] Phrack Magazine. "Exploiting Memory Corruptions in Fortran Programs Under Unix." Phrack Issue 67. http://phrack.org/issues/67/11.html.

[FORTRAN-WIKIBOOKS-ERR] Wikibooks. "Fortran/error handling." https://en.wikibooks.org/wiki/Fortran/error_handling.

[ERRSTAT-GITHUB] GitHub. "degawa/errstat: error status and message handling library for Modern Fortran." https://github.com/degawa/errstat.

[FORALL-INTEL-DISCUSSION] Intel Community. "Forall and Do Concurrent." https://community.intel.com/t5/Intel-Fortran-Compiler/Forall-and-Do-Concurrent/td-p/777990.

[FORALL-OBSOLESCENT] comp.lang.fortran (narkive). "obsolescent forall." https://comp.lang.fortran.narkive.com/V72Rbm3T/obsolescent-forall.

[COARRAYS-SOURCEFORGE] Coarrays.sourceforge.io. "Parallel programming with Fortran 2008 and 2018 coarrays." https://coarrays.sourceforge.io/doc.html.

[FPM-HOME] Fortran Package Manager. https://fpm.fortran-lang.org/.

[ARXIV-TOOLING-2021] Čertík, Ondřej et al. "Toward Modern Fortran Tooling and a Thriving Developer Community." arXiv:2109.07382, September 2021. https://arxiv.org/abs/2109.07382.

[BLAS-LAPACK-REF] UCSC AMS 209. "External Libraries for Scientific Computing." https://users.soe.ucsc.edu/~dongwook/wp-content/uploads/2016/ams209/lectureNote/_build/html/chapters/chapt02/ch02_fortran_blas_lapack.html.

[FORTRANWIKI-MOD] Fortran Wiki. "Compiler .MOD files." https://fortranwiki.org/fortran/show/Compiler+.MOD+files.

[INTEL-MOD-COMPAT] Intel Community. "Intel® Fortran Compiler Module .mod Files Version Compatibility, Part 1 of 2." https://community.intel.com/t5/Blogs/Tech-Innovation/Tools/Intel-Fortran-Compiler-Module-mod-Files-Version-Compatibility/post/1600674.

[FORTRAN-ABI-YARCHIVE] Yarchive. "Fortran ABI (Robert Corbett)." https://yarchive.net/comp/fortran_abi.html.

[NVD-CVE-2024-28881] NIST NVD. "CVE-2024-28881." Intel Security Advisory INTEL-SA-01173. https://nvd.nist.gov/vuln/detail/CVE-2024-28881.

[NVD-CVE-2022-38136] NIST NVD. "CVE-2022-38136." https://nvd.nist.gov/vuln/detail/CVE-2022-38136.

[SO-SURVEY-2024] Stack Overflow. "Stack Overflow Annual Developer Survey 2024." https://survey.stackoverflow.co/2024/.

[LINARO-FLANG] Linaro. "Comparing LLVM Flang with other Fortran compilers." https://www.linaro.org/blog/comparing-llvm-flang-with-other-fortran-compilers/.

[INTEL-IFX-2025] Intel. "Intel® Fortran Compiler for oneAPI Release Notes 2025." https://www.intel.com/content/www/us/en/developer/articles/release-notes/fortran-compiler/2025.html.

[NVIDIA-DO-CONCURRENT] NVIDIA Technical Blog. "Accelerating Fortran DO CONCURRENT with GPUs and the NVIDIA HPC SDK." https://developer.nvidia.com/blog/accelerating-fortran-do-concurrent-with-gpus-and-the-nvidia-hpc-sdk/.

[CLBG-HOME] The Computer Language Benchmarks Game. https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html.

[ISO-C-BINDING-NOTE] fortran-lang.org. "Derived Types — Fortran Programming Language." https://fortran-lang.org/learn/quickstart/derived_types/. (Includes discussion of ISO_C_BINDING interoperability implications.)

[J3-HOME] INCITS/Fortran (J3). "J3 Fortran — Home." https://j3-fortran.org/.
