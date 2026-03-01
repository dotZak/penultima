# Fortran — Pedagogy Advisor Review

```yaml
role: advisor-pedagogy
language: "Fortran"
agent: "claude-sonnet-4-6"
date: "2026-02-28"
```

---

## Summary

Fortran's pedagogy story is fundamentally shaped by a fact that no council member states with full sharpness: it was never designed to be learned. It was designed to be used by people who already knew mathematics. The original audience in 1957 was mathematical scientists who wrote in assembly; Backus's goal was to let them write closer to what they already knew — formula notation — while a compiler handled the translation to machine code [IBM-HISTORY-FORTRAN]. That design orientation — toward expression for domain experts, not accessibility for general learners — has persisted into 2026 in ways that are both Fortran's strength and its defining constraint.

For its actual user population — computational physicists, atmospheric scientists, aerospace engineers, numerical analysts — modern Fortran (90 onward) is substantially more learnable than the council documents sometimes suggest, and substantially harder than they sometimes imply. The mathematical array syntax, the intrinsic functions mirroring linear algebra notation, and the strongly typed numeric foundations genuinely serve scientists who think in matrices and eigenvalues. These learners encounter one primary difficulty: the bifurcation between modern Fortran idiom and the FORTRAN 77 legacy they will encounter in production code the moment they join a research group or HPC center. That bifurcation — not the language itself — is the principal learning burden for contemporary Fortran practitioners.

Several pedagogy-relevant claims in the council documents require scrutiny or supplementation. The "comparable to Python and MATLAB" learning curve claim is supported by a single blog post rather than empirical study, and it understates the onboarding cost of implicit typing, 1-based indexing, KIND parameter verbosity, and the dual fixed-form/free-form source convention. Conversely, the IOSTAT error handling pattern is underrated as teachable — it is more explicit and locally checkable than C's errno side channel, even if it fails to compose. The most serious pedagogy failure — disabled bounds checking in production compilers producing silent wrong results — is mentioned by the realist but underemphasized across the council. And the AI coding assistant gap is flagged by the realist but treated as a footnote; by 2026 it is a first-class learnability concern that deserves central placement.

---

## Section-by-Section Review

### Section 8: Developer Experience

**Accurate claims:**

The council is broadly correct that the fortran-lang.org initiative (launched 2020) has meaningfully improved the modern Fortran development experience. The VS Code + Modern Fortran extension + fortls language server combination provides syntax highlighting, linting, completion, and Go-to-Definition for developers who set it up correctly [VSCODE-FORTRAN]. The "Toward Modern Fortran Tooling" paper [ARXIV-TOOLING-2021] is appropriately cited as the inflection point where the community formally diagnosed and began addressing its tooling deficit. The Fortran Package Manager (fpm) genuinely simplifies dependency and build management for new projects, solving a problem that previously had no standard answer.

The practitioner is correct that Fortran is largely a language of necessity and inheritance rather than voluntary selection. This has a direct pedagogy implication: the motivational precondition for learning is already present (domain experts who need the tool to do their scientific work), which makes learnability comparisons to general-purpose languages somewhat misleading. A physicist forced to learn Fortran for their dissertation research has stronger motivation than a developer casually evaluating language options.

The realist's frank assessment of AI tool support — "below average," reflecting thin training corpus — is accurate and important. GitHub Copilot, Claude, and ChatGPT complete and explain Fortran code with lower fidelity than they do Python, JavaScript, or even Rust. The fortran-lang community has discussed AI-assisted FORTRAN 77 to modern Fortran translation as a use case [RESEARCH-BRIEF], which is suggestive of the actual ceiling: AI assistance is useful for modernization tasks, not as a real-time copilot.

**Corrections needed:**

The "comparable to Python and MATLAB for scientific computing" learning curve claim — repeated by the apologist, realist, and research brief — traces to a single Medium blog post [HOLMAN-MEDIUM]. This is not a peer-reviewed study, not a systematic survey of learner outcomes, and not a controlled comparison. Python consistently ranks as the most learnable first language in multiple developer surveys [SO-SURVEY-2025]; to claim equivalence with modern Fortran requires significantly stronger evidence than one practitioner's blog post. The claim may be approximately true for scientists doing pure numerical work (writing matrix algorithms, not building software systems), but the citation should be flagged as insufficient for a factual claim at this scope.

Several specific learnability frictions are absent from the council's Section 8 discussions:

*1-based array indexing.* Fortran arrays are 1-indexed by default (`A(1)` is the first element), with optional lower bounds (`A(0:9)` or even `A(-5:5)`). Virtually every modern language a new Fortran learner is likely to have used previously — Python, C, C++, Java, JavaScript, MATLAB (partially) — uses 0-based or 1-based indexing differently. The mismatch is a persistent source of off-by-one errors that are non-obvious to beginners. None of the council members address this.

*Case insensitivity.* Fortran is case-insensitive (`INTEGER`, `integer`, and `Integer` are the same). This is a holdover from the punch-card era that creates two problems: it removes a convention that developers from other languages use to carry semantic information (types vs. variables vs. constants), and it creates style inconsistency in team codebases where no single convention is enforced by the compiler. The apologist does not address this; the detractor mentions it; none analyze it as a learnability factor.

*The fixed-form vs. free-form split.* The research brief and practitioner note that learners must be prepared to work with both fixed-form FORTRAN 77 (72-column restriction, columns 1-5 for labels, column 6 for continuation, columns 7-72 for code) and modern free-form Fortran. But the council does not adequately convey how disorienting this is for new practitioners: there is no compiler mode switch that tells you which one you're reading. A newcomer encountering a production codebase that mixes fixed-form legacy files with modern free-form wrappers faces a meta-challenge before any domain content.

**Additional context:**

The error message quality gap deserves specific evidence that no council member provides. GFortran's error messages are well-regarded in the HPC community for compile-time diagnostics but produce runtime errors that require experience to interpret. A bounds violation with bounds checking enabled (`-fcheck=bounds`) typically produces output like:

```
At line 47 of file solver.f90
Fortran runtime error: Array bound mismatch for dimension 1 of array 'a' (12/15)
```

This is decipherable but provides no stack trace, no context about what the calling code was attempting, and no actionable suggestion. Python's tracebacks and Rust's compile-time error messages represent the modern standard for pedagogically useful diagnostics. Fortran's runtime messages lag both, and — critically — they are only available when bounds checking is enabled, which most HPC code does not do in production.

The community friendliness of the Fortran Discourse (fortran-lang.org) is genuine and should receive credit. The community is small (relative to Python or JavaScript), knowledgeable, and welcoming of newcomers. Stack Overflow Fortran coverage is sparser than for mainstream languages — approximately 30,000 Fortran-tagged questions versus Python's 2.2 million [SO-SURVEY-2024] — but the questions that exist tend to be answered. For a niche specialist language, this is adequate if not ideal.

---

### Section 2: Type System (Learnability)

**Accurate claims:**

The council is correct that implicit typing (`IMPLICIT` rule: undeclared variables beginning with `I` through `N` default to `INTEGER`, others to `REAL`) is the most consequential historical footgun in Fortran's design, and that `IMPLICIT NONE` is an effective mitigation that modern Fortran style mandates. The apologist's framing — "a context-appropriate default that became a maintenance hazard as programs grew" — is historically accurate [BACKUS-HISTORY-1978]. The realist and detractor correctly note that legacy codebases predate `IMPLICIT NONE` and that learners encounter this rule in production code before they may know to look for it.

Arrays as first-class language objects — whole-array operations, array sections (`A(2:10:2)`), elemental intrinsics — are correctly identified as a learnability advantage for the target population. Physicists and engineers who think about problems in terms of vectors and matrices find Fortran's array semantics more natural than C's pointer-plus-stride model or Python's list-of-lists. The realist appropriately notes this is not merely syntactic sugar but semantics that compilers exploit for auto-vectorization [RESEARCH-BRIEF].

The intrinsic functions (`MATMUL`, `DOT_PRODUCT`, `TRANSPOSE`, `RESHAPE`, `SPREAD`, `PACK`, `UNPACK`) mirror the mathematical vocabulary of the target audience. A climate scientist writing a matrix multiply writes `C = MATMUL(A, B)`, not an explicit loop nest or a call to an opaque BLAS routine (though BLAS calls may still appear for performance-critical inner loops). This alignment between language vocabulary and domain vocabulary is a genuine learnability advantage over lower-level alternatives.

**Corrections needed:**

The council does not adequately analyze the KIND parameter system as a learnability challenge. Fortran's KIND mechanism for specifying numeric precision — the correct way to write a double-precision real — has at least four syntactically valid forms in common use:

```fortran
REAL(KIND=8) :: x           ! Non-portable, compiler-dependent
REAL(8) :: x                ! Same problem, more concise
REAL(KIND=KIND(1.0D0)) :: x ! Portable but verbose
USE iso_fortran_env
REAL(REAL64) :: x           ! Portable, modern, recommended
```

A learner reading documentation, tutorials, StackOverflow answers, and production code will encounter all four forms. The iso_fortran_env module constants (`REAL32`, `REAL64`, `REAL128`, `INT32`, `INT64`) are the correct modern approach, but this is not obvious from language syntax alone. No council member analyzes the pedagogical cost of this fragmentation — the cognitive load of understanding four equivalent ways to declare a double-precision variable, none of which is syntactically self-explanatory.

The absence of generics (parametric polymorphism) is correctly noted by the realist as a limitation, but the learnability cost is understated. When Fortran programmers need to write code that works for both single and double precision, they typically use `SELECTED_REAL_KIND` macros or write duplicate procedures. The correct pattern involves `GENERIC` interfaces (Fortran 90+) mapping to separate type-specific implementations. This is teachable but requires understanding the full module/interface system before addressing what would be a one-line type parameter in Rust or Java generics. The pedagogical cliff here is real.

**Additional context:**

The case-insensitivity of Fortran identifiers (including intrinsic function names and keywords) deserves explicit learnability analysis. Fortran compilers treat `real`, `REAL`, and `Real` as identical. This has two effects:

1. **Lower initial barrier**: scientists writing mathematical code do not need to remember casing rules. MATLAB and early BASIC had similar conventions, and Fortran's target audience often transitioned from those environments.

2. **Higher long-term cost**: modern development tools (editors, version control, search tools, AI assistants) treat identifiers case-sensitively by default. Code review tools, grep, and AI completion all assume case carries information. Mixed-case Fortran codebases are common — some developers write in ALL-CAPS (FORTRAN 77 convention), others in lowercase (modern convention), others in mixed case for readability. No compiler enforces consistency, and style guides are team-dependent.

The 1-based indexing convention, while natural to mathematicians (matrix element A_{ij} maps directly to `A(i,j)`), creates friction specifically at the boundary with other languages and tools. HDF5 files read with Python's h5py library use 0-based indexing; Fortran reads the same files with 1-based indexing. Array indices passed between Fortran and C via FFI require adjustment. These boundary errors are a common source of off-by-one bugs in mixed-language scientific codebases and represent a learnability cost that cannot be dismissed as pure legacy.

---

### Section 5: Error Handling (Teachability)

**Accurate claims:**

The apologist's assessment that the `IOSTAT`/`STAT`/`ERRMSG` pattern is more transparent than C's `errno`-plus-return-value approach is pedagogically defensible. In Fortran:

```fortran
OPEN(UNIT=10, FILE='data.txt', IOSTAT=ios, IOMSG=msg)
IF (ios /= 0) THEN
    WRITE(*,*) 'Error opening file: ', TRIM(msg)
    STOP
END IF
```

The success status (`ios`) and human-readable message (`msg`) are named outputs attached to the operation. A learner can see where errors come from, what happened, and what string to print. C's `fopen()` returning NULL plus `errno` side-channel mutation plus `strerror()` is genuinely harder to teach correctly. On this specific comparison, the apologist is right.

The IEEE exception handling (Fortran 2003+) is correctly identified as sophisticated and domain-appropriate. Computational scientists care about divide-by-zero, overflow, and NaN propagation at a granularity that general-purpose exception handling does not support. Being able to save and restore the floating-point environment, enable and disable specific exception flags, and query post-hoc whether exceptions occurred is valuable for numerical debugging [FORTRAN-WIKIBOOKS-ERR].

**Corrections needed:**

The council substantially underemphasizes the most serious teachability failure in Fortran's error model: **bounds checking is disabled by default in production compilers**, meaning out-of-bounds array accesses produce silent wrong results rather than caught errors.

This is pedagogically catastrophic in a specific way. A student writing a numerical method — an iterative solver, a finite difference scheme, a matrix factorization — who makes an indexing error will get wrong numbers, not an error. Wrong numbers in scientific code are not obviously wrong: they may look plausible, they may converge to a wrong solution, they may produce output files that look reasonable until validated against a reference solution. The feedback loop between the error and its detection is delayed, potentially by days of computation or months of validation work.

The correct developer practice is to enable bounds checking during development and testing (`-fcheck=bounds` in GFortran, `-CB` or `-check bounds` in Intel), then disable for production runs. But this requires knowing to do it, knowing how compiler flags work, and maintaining the discipline to test with bounds checking enabled. Beginners rarely learn this practice before encountering their first bounds-related wrong-result bug. None of the council members present this as the primary teachability failure it is; the realist notes it in passing.

Error propagation across deep call stacks is correctly identified as a limitation — threading `STAT`/`ERRMSG` through every intermediate procedure level is tedious and error-prone (easy to forget). The council is accurate here. What is underemphasized is that this pattern is also not consistently modeled in standard library routines or in widely-circulated teaching examples. A beginner learning from textbook examples or HPC center tutorials often sees correct IOSTAT handling in top-level I/O and nowhere else, internalizing the pattern incompletely.

**Additional context:**

The teachability of Fortran's error handling differs fundamentally between two populations: HPC programmers learning numerical code, and software engineers encountering Fortran for the first time. For the first group, IOSTAT/STAT is a known pattern taught explicitly in HPC training courses at national laboratories. For the second group — a Python or Java developer asked to maintain or extend a Fortran library — the pattern is entirely alien, there is no `try`/`except` or `Result<T,E>`, and the discovery that array bounds violations default to silent corruption is alarming.

This population difference matters for pedagogy because Fortran's user base is demographically shifting. As senior Fortran practitioners retire, their successors are increasingly domain scientists who learned Python first and Fortran second. For this population, the error handling model requires unlearning Python's exception-by-default behavior and learning an explicit manual pattern. The absence of any mechanism analogous to Python's `assert` (meaningful in debug builds, stripped in optimized ones) or Rust's `debug_assert!` macro is a specific gap: Fortran's bounds checking is an all-or-nothing compiler switch, not a language-level assertion.

---

### Section 1: Identity and Intent (Accessibility Goals)

**Accurate claims:**

The historian and apologist are correct that Fortran's original intent was not accessibility in the modern pedagogical sense. Backus's goal was explicit: allow mathematical scientists to write programs in formula notation while the compiler produced code competitive with hand-written assembly [IBM-HISTORY-FORTRAN]. The target user was not a beginning programmer but an existing expert (physicist, engineer, mathematician) who was spending too much time debugging assembly. The pedagogical bet was: "can we lower the cognitive burden for experts?" not "can we make programming accessible to non-experts?"

The realist is correct that in 2026, Fortran's identity as an HPC/scientific computing language is stable and coherent — it serves a defined constituency — but has not broadened meaningfully in decades [RESEARCH-BRIEF]. This is not a design failure given the original scope; it is an honest assessment of what the language optimizes for.

**Corrections needed:**

The council documents conflate "accessible for its target audience" with "accessible" without qualification. This distinction matters for pedagogy evaluation: Fortran is probably among the most accessible languages for a physicist learning to write numerical code, and among the least accessible for a web developer, data scientist using modern Python, or student whose first language was Java. Accessibility is always relative to the learner's starting point and goal.

The historian notes the Backus Turing Award lecture as a data point about the original designer repudiating the paradigm [BACKUS-TURING-1978], but does not analyze what this implies for pedagogy. The implication is interesting: the inventor himself, by 1977, thought that programming languages organized around assignment statements were conceptually wrong. This critique applies to Fortran at least as strongly as to any other imperative language. That Fortran has persisted and thrived despite this judgment reflects domain pragmatism — the language works for what scientists need — not vindication of the paradigm.

**Additional context:**

The stated 1957 design goal — produce a language "so attractive that users will ignore objections" [IBM-HISTORY-FORTRAN] — is pedagogically revealing. Backus knew his audience was resistant. Scientists were skeptical that a compiler could close the performance gap; the appeal had to be sufficiently compelling to overcome professional resistance to a new tool. This framing — make it compelling enough to overcome skepticism — is different from "make it easy to learn." Fortran succeeded at the former; it was not designed to achieve the latter, and should not be evaluated as if it were.

The absence of Fortran from major developer surveys (Stack Overflow 2024–2025, JetBrains 2024–2025) [SO-SURVEY-2024; JETBRAINS-2025] reflects the language's domain concentration rather than irrelevance, but it has a secondary pedagogical consequence: there is almost no systematic data on Fortran learner demographics, time-to-productivity, or satisfaction. The HPC training community has self-assessments; no peer-reviewed research on Fortran learning outcomes appears in the council documents. This means the council's assessments of learnability are largely practitioner judgment, not measured outcomes.

---

### Other Sections (Pedagogy-Relevant Flags)

#### Section 4: Concurrency and Parallelism

Fortran's concurrency model presents a two-track pedagogy problem. The language-native mechanism — coarrays (Fortran 2008+) — is sophisticated but has a high conceptual entry cost. A coarray program requires understanding the notion of "image" (parallel execution unit), "codimension" notation (`REAL :: A(100)[*]`), image synchronization (`SYNC ALL`, `SYNC IMAGES`), and the asynchronous communication model. This is not a beginner topic, and the unusual bracket notation for codimensions creates visual noise for readers unfamiliar with the convention.

The de facto standard for HPC parallelism — OpenMP — is a separate annotation system applied to Fortran via directives (`!$OMP PARALLEL DO`). A learner of Fortran in an HPC context must learn two systems: Fortran the language, and OpenMP or MPI as external parallelism layers. These are taught separately in HPC training curricula (national laboratory courses typically have separate Fortran, OpenMP, and MPI tracks). The council documents note this layered complexity; the pedagogy implication is that the full HPC Fortran skill set requires approximately three separate learning investments, not one.

`DO CONCURRENT` (Fortran 2008, extended in Fortran 2018) is more teachable: it declares that a loop's iterations are independent and may be parallelized. It requires no external libraries and is syntactically simple. Its pedagogical advantage is that it communicates programmer intent (parallelism-safe iteration) while remaining portable without MPI or OpenMP. Its limitation — it does not guarantee actual parallelization, only permits it — should be taught explicitly to prevent the false assumption that `DO CONCURRENT` equals automatic speedup.

#### Section 6: Ecosystem and Tooling

The module system's compilation-ordering requirement creates non-obvious onboarding friction. Fortran modules must be compiled before any unit that `USE`s them. In a project without a build system, this requires the developer to understand and manually manage compilation order — a task that fpm automates but that appears immediately when working with GFortran directly or examining Makefile-based legacy projects. This is not an intrinsic language complexity but an extrinsic build complexity that surprises developers accustomed to languages where import/include order is managed by the toolchain.

The absence of a standard library for common data structures (dynamic arrays, hash maps, linked lists, trees) is a recurring onboarding friction. A scientific computing learner who wants to build a simulation with a growing list of particles must either implement their own resizable array, use a third-party library (stdlib, via fortran-lang), or work around the limitation with pre-allocated over-sized arrays. The lack of built-in containers is particularly confusing for learners who come from Python (batteries included) or Java (java.util). This is flagged in [ARXIV-TOOLING-2021] and correctly noted by multiple council members; its specific pedagogical consequence — learners spending time implementing infrastructure rather than learning the domain — deserves emphasis.

The FORMAT statement for I/O formatting is one of Fortran's most syntactically idiosyncratic features. A moderately complex WRITE statement with a labeled FORMAT:

```fortran
WRITE(6, 100) x, y, z
100 FORMAT(3F12.6)
```

requires the learner to understand: unit numbers (6 = standard output, a legacy convention), label-based code reference (format labels are line numbers from the punch card era), and format descriptors (`F12.6` = fixed-point, 12 characters wide, 6 decimal places). The modern inline format (`WRITE(*,'(3F12.6)') x, y, z`) is cleaner but both forms appear in real code. The FORMAT descriptor language is a mini-language within Fortran, learned separately from the rest of the language, and not analogous to anything in modern languages. It is a historical artifact that creates a non-trivial learnability cliff for I/O operations.

---

## Implications for Language Design

The Fortran experience surfaces eight pedagogy lessons that generalize to language design:

**1. Defaults must be learnable, not just convenient for experts.**
Implicit typing was expedient for 1957 expert programmers writing short programs. It became a teaching failure as programs grew, bugs became harder to track, and new programmers encountered the rule without knowing to look for it. A variable name typo creates a new variable of the wrong type with no error — the worst possible behavior for a beginner. `IMPLICIT NONE` works as a mitigation, but it requires knowing the footgun exists before you've been shot. Language designers should evaluate defaults by asking: "What happens when a beginner makes a mistake that this default was designed to make convenient for experts?" If the answer is "silent wrong behavior," the default is pedagogically wrong regardless of its convenience for experts.

**2. Silent wrong results are more dangerous pedagogically than caught errors.**
Fortran's disabled bounds checking in production, implicit typing, and some floating-point corner cases share a failure mode: the program compiles, runs, and produces plausible-looking wrong answers. This is categorically more damaging for learning than a caught error with a clear message, because the diagnostic signal is absent. A language that fails loudly — Rust's compile-time memory safety errors, Python's exception tracebacks — teaches by interruption. A language that fails silently teaches nothing and can actively mislead. Language designers should prefer loud, early failures at every layer of the development cycle (compile time > test time > early runtime) over silent failures at any stage.

**3. A language bifurcated between legacy and modern idiom imposes invisible onboarding costs.**
A contemporary Fortran practitioner must learn two languages: modern Fortran (free-form, module-based, explicit typing, modern control flow) and FORTRAN 77 (fixed-form, column-restricted, implicit typing, COMMON blocks, labeled FORMAT statements, GOTO). There is no clean separation: production codebases intermix them, compilers accept both, and tutorials are written for the modern idiom while production code uses the legacy one. This bifurcation has no good analog in other common languages. Language evolution that makes old idioms deprecated-but-legal forces each new generation of learners to learn both the intended idiom and the historical one to read existing code. Effective language design either provides clean migration paths (breaking changes that remove old idioms entirely, as Python 3 did with Python 2) or accepts the onboarding cost and invests in tooling that clearly signals which idiom a piece of code uses.

**4. AI training corpus density is now a first-class learnability factor.**
In 2026, a significant fraction of programming learning happens through interaction with AI coding assistants (GitHub Copilot, Claude, ChatGPT). The quality of AI assistance is proportional to the volume and quality of code in training corpora. Fortran is present in training corpora but at lower density than Python, JavaScript, Java, or Rust. The result: AI-generated Fortran code is more likely to be incorrect, mix modern and legacy idioms inconsistently, use deprecated features, or apply conventions from other languages incorrectly. For beginners who rely on AI assistance to scaffold their learning — asking "how do I write a matrix multiply in Fortran?" and trusting the answer — this is a learnability gap that compounds over time as AI tools become standard practice. Language communities designing or revitalizing languages in 2026 must explicitly think about training corpus quality as a learnability investment, including open-sourcing idiomatic code examples and contributing to AI evaluation benchmarks.

**5. Domain-specific learnability must be distinguished from general learnability.**
Fortran is substantially easier to learn for a physicist with matrix algebra background than for a web developer with JavaScript experience. The array syntax, intrinsic functions, and numeric type system map directly onto what scientists already know. Evaluating Fortran's learnability without specifying the learner population produces misleading results. Language designers targeting specialized domains — scientific computing, financial modeling, embedded systems — should explicitly define their target learner profile and optimize for that profile's existing mental models, rather than either optimizing for general accessibility or ignoring learnability entirely. A language that serves its target domain's expert practitioners well may appear difficult to outsiders without this being a design failure.

**6. Syntactic artifacts from historical interfaces persist as cognitive load.**
Fortran's fixed-form source format (72-column restriction, continuation markers, label columns) was designed for punch cards and paper tape. It persists in legacy codebases and must be understood by anyone who maintains them. The FORMAT statement mini-language was designed for teletype output. Case insensitivity is a holdover from an era when uppercase-only terminals were standard. These are not merely aesthetic quirks; they represent cognitive load that has no pedagogical payoff — it conveys no information relevant to the problem being solved and no transferable skill applicable outside the Fortran context. Language designers can learn from this: interface-specific conventions embedded in language syntax become permanent cognitive load as interfaces change. Prefer surface syntax that is interface-agnostic wherever possible.

**7. Error message quality is a teaching interface that compounds over the language's lifetime.**
Early languages set error message standards before the field understood their pedagogical value. Fortran's compiler error messages are adequate for experienced developers and inadequate for beginners — they are accurate but not actionable, correct but not contextual. The languages designed with error messages as a first-class concern (Rust, Elm, recent versions of Java) demonstrate that this is a design choice, not a technical constraint. The lesson is that error messages are the language's teaching interface, and their quality directly determines how fast beginners learn from mistakes. A language designed today should treat error message quality as a feature requirement from day one, with the same priority as runtime performance, because the cost of poor error messages is paid continuously by every learner.

**8. The lack of systematic learner outcome data makes learnability assessment circular.**
For Fortran — and for most specialist languages — claims about learnability are largely practitioner testimony rather than measured outcomes. "Comparable to Python and MATLAB for scientific computing" [HOLMAN-MEDIUM] is a practitioner's impression, not a controlled study. Language designers who want to make evidence-based claims about their language's learnability need to invest in measurement: time-to-first-working-program, error-to-fix cycles, concept retention studies, diverse-population accessibility evaluations. The absence of this data for Fortran means that pedagogy debates in the community are conducted by anecdote. Language communities that systematically measure learner outcomes — as some programming education research communities do — can identify and fix learnability failures before they calcify into "known issues."

---

## References

[IBM-HISTORY-FORTRAN] IBM. "The FORTRAN Automatic Coding System." IBM Corporation. (Cited for original design goals and team context.)

[BACKUS-HISTORY-1978] Backus, J. "The History of FORTRAN I, II, and III." ACM SIGPLAN Notices 13(8), 1978. (Primary source for design decisions and team composition.)

[BACKUS-TURING-1978] Backus, J. "Can Programming Be Liberated from the von Neumann Style? A Functional Style and Its Algebra of Programs." Communications of the ACM 21(8), 1978. (Turing Award lecture; primary source for designer's retrospective critique.)

[BACKUS-TURING-NOTE] Cited in detractor perspective as characterization of the Turing lecture. (Secondary attribution — original characterization source unspecified in council documents.)

[ARXIV-TOOLING-2021] Čertík, O. et al. "Toward Modern Fortran Tooling and a Thriving Developer Community." arXiv:2109.07382, 2021. (Cited for tooling gap diagnosis and fortran-lang initiative context.)

[HOLMAN-MEDIUM] Holman, M. "Modern Fortran: Why It's Not Dead Yet." Medium, 2023 (approx.). (Cited for learning curve comparison claim; note: blog post, not peer-reviewed.)

[FORTRANWIKI-STANDARDS] Fortran Wiki. "Fortran Standards History." fortranwiki.org. (For standard evolution timeline.)

[FORTRAN-LANG] fortran-lang.org. "Learn Fortran." fortran-lang.org/learn/. (For community learning resources.)

[VSCODE-FORTRAN] Modern Fortran Extension for VS Code. marketplace.visualstudio.com. (For IDE tooling assessment.)

[FORTRAN-WIKIBOOKS-ERR] Wikibooks. "Fortran/Fortran File I/O and Error Handling." en.wikibooks.org. (For IOSTAT/ERRMSG pattern documentation.)

[RESEARCH-BRIEF] Fortran Research Brief. research/tier1/fortran/research-brief.md. (Factual baseline for this review.)

[SO-SURVEY-2024] Stack Overflow Annual Developer Survey 2024. survey.stackoverflow.co/2024/. (For language prevalence context; Fortran not listed separately.)

[SO-SURVEY-2025] Stack Overflow Annual Developer Survey 2025. survey.stackoverflow.co/2025/. (For language prevalence and learnability context.)

[JETBRAINS-2025] JetBrains State of Developer Ecosystem 2025. devecosystem-2025.jetbrains.com. (For language adoption context; Fortran not listed separately.)

[DEVSURVEYS-EVIDENCE] Developer Survey Aggregation, evidence/surveys/developer-surveys.md. (Cross-language survey baseline; Fortran not covered in major surveys.)
