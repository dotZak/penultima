# C — Detractor Perspective

```yaml
role: detractor
language: "C"
agent: "claude-sonnet-4-6"
date: "2026-02-26"
schema_version: "1.1"
```

---

## 1. Identity and Intent

The research brief opens with Ritchie's own self-assessment: "C is quirky, flawed, and an enormous success" [RITCHIE-1993]. This sentence is frequently quoted for its candor, but the emphasis almost always lands on "enormous success." For a language analysis aimed at extracting design lessons, the weight belongs on "quirky, flawed." The success is not in dispute; the flaws are the information.

C was designed to solve a specific problem in 1972: replace assembly language for Unix kernel development on a PDP-11 with scarce RAM. The WG14 charter articulates the "spirit of C" as: "Trust the programmer; Don't prevent the programmer from doing what needs to be done; Keep the language small and simple" [WG14-N2611]. This philosophy was appropriate for its moment — a small team of expert programmers, a single operating system target, hardware with no memory protection, and a security threat model that did not include adversarial network input. None of these conditions apply to C in 2026.

The "trust the programmer" principle has no symmetric counterpart. C trusts the programmer to do everything correctly and provides no mechanism to enforce that trust. A language philosophy that treats safety guarantees as paternalistic interference is a design philosophy that systematically shifts the cost of programmer error from the compiler to the end user — and in modern contexts, to attack surface exposure.

The design goal of portability deserves scrutiny. Ritchie acknowledged that "C was not originally designed with portability as a prime goal" [RITCHIE-1993]. Portability was retrofitted via standardization, and the mechanism chosen — *undefined behavior* for cases where implementations diverged — created a third rail that runs through the entire language. The original design did not anticipate that portability and safety would conflict; five decades later, undefined behavior is the primary mechanism by which C security vulnerabilities are created and exploited.

The charter's Principle 13 — "No invention, without exception" [WG14-N2611] — is the governance expression of this problem. WG14 requires prior implementation experience before adopting features. For safety features this is circular: no implementation adopts an unstandarized safety mechanism, so WG14 cannot standardize it. `defer` was rejected from C23 on these grounds and redirected to a Technical Specification with no binding timeline [WG14-DEFER]. Memory safety at the language level has been discussed for over a decade and remains outside the standard.

A language designed by experts for experts, in an era before networked adversaries, should not be faulted for not anticipating the internet. C should be faulted — and the lesson extracted — for its governance structure and philosophical commitments that prevent it from evolving toward safety even when the cost of not doing so is quantified in billions of dollars of damage annually.

---

## 2. Type System

C's type system is described in the research brief as "static, weak, manifest" [C-STD-SPEC]. The "static" part is accurate and valuable. The "weak" part is the problem, and the brief understates how structurally weak it is.

**Implicit conversions as a bug factory.** C's integer promotion and conversion rules are a source of subtle bugs that experienced programmers still routinely misunderstand. Signed-to-unsigned conversion can silently make a negative number into a large positive number, turning a safety check into its opposite. A function that checks `if (len < 0)` before calling `memcpy(dst, src, len)` is silently broken when `len` is declared `unsigned` — the check compiles without warning and the condition is always false. This is not an exotic edge case; it is listed in CERT C coding standards [CERT-C-INT] and appears in production CVEs regularly, including CWE-190 which comprises 10–15% of C memory safety CVEs [CVE-DOC-C].

**Strict aliasing: a "feature" the ecosystem refuses to use.** C's strict aliasing rules allow the compiler to assume that pointers of different types do not alias the same memory, enabling optimizations that can silently discard safety checks or produce incorrect behavior when code does type-punning through pointer casts. This is not a theoretical concern. John Regehr, a leading researcher in C undefined behavior, states: "A lot of C code is broken under strict aliasing" [REGEHR-ALIASING-2016]. The Linux kernel builds with `-fno-strict-aliasing` — accepting a performance regression — because strict aliasing violations are pervasive in kernel code that uses union-based networking structures. Firefox added `-fno-strict-aliasing` for the same reason [REGEHR-ALIASING-2016]. When major projects must disable a language rule to avoid incorrect behavior, that rule is evidence of a design failure.

**No null safety.** Null pointer dereference is undefined behavior that C neither prevents at compile time nor detects at runtime. The type system contains no equivalent of Rust's `Option<T>`, Kotlin's nullable types, or Swift's optionals — no mechanism to distinguish "this pointer may be null" from "this pointer is guaranteed non-null." The programmer must track nullability as a cognitive invariant. Failure to do so produces CVEs; many of the use-after-free vulnerabilities in the CWE-416 category (15–20% of memory safety CVEs [CVE-DOC-C]) begin with incorrect null assumptions.

**No generics.** The absence of generics forces C programmers into one of two patterns: void-pointer containers (with complete loss of type safety at the use site) or macro-expanded pseudo-generics (with no type checking and documented hygiene failures [GCC-PITFALLS]). C11's `_Generic` is a dispatch mechanism, not a generics system — it selects among existing concrete implementations, not type-parameterized abstractions. The practical result is that any reusable data structure in C operates either through untyped pointers or through code duplication.

**What the type system genuinely provides.** The static typing does catch real errors at compile time, and the type discipline is sufficient to enable good compiler optimization. This is not a trivial benefit. The point is that the type system provides classification without safety — it tells you what something is supposed to be, but provides no enforcement of that claim across casts, conversions, or pointer arithmetic.

The lesson for language designers: a type system that classifies without enforcing provides a false sense of safety. Classification and enforcement must be unified if the type system is to prevent errors rather than merely name them.

---

## 3. Memory Model

This is the section where the argument against C's design has the strongest empirical support. The numbers are not in dispute:

- 70% of CVEs addressed by Microsoft annually are memory safety issues, predominantly from C and C++ codebases [MSRC-2019].
- 70% of severe security bugs in Chrome are memory safety issues [GOOGLE-ANDROID-2024].
- Android's memory safety CVEs were 76% of total CVEs in 2019; after four years of Rust adoption they dropped to 24% — a 68% reduction [GOOGLE-ANDROID-2024].
- The White House, NSA, CISA, FBI, and cybersecurity agencies from Australia, Canada, New Zealand, and the United Kingdom have collectively issued guidance calling for migration away from C and C++ [ONCD-2024, NSA-CISA-2025, CISA-ROADMAPS-2023].

This is not criticism from language enthusiasts. It is a finding from the security operations teams of the world's largest software organizations, and from the national security establishments of seven countries.

**What C provides:** No memory safety guarantees whatsoever at the language level. The standard defines accessing freed memory, overflowing a buffer, dereferencing null, and data races as undefined behavior — which means the language neither detects these errors nor specifies their consequences. The compiler is free to assume they do not occur and optimize accordingly, which is how security checks get compiled away [WANG-STACK-2013, CVE-2009-1897].

**The tooling answer is not an answer.** The research brief correctly documents the compensating tooling: AddressSanitizer (2–3x runtime overhead), MemorySanitizer, Valgrind (3–13x overhead), clang-tidy, Coverity, cppcheck [ASAN-COMPARISON]. These tools are valuable. They are not an answer to the question of language design, because they operate only in development — they cannot run in production without unacceptable overhead, and they cannot statically guarantee absence of the errors they detect. ASan detects heap buffer overflows at runtime when they happen to be exercised during testing. It does not guarantee their absence. The STACK study found 161 confirmed bugs in Linux and PostgreSQL that no dynamic tool would find because the errors manifested as code the compiler silently deleted [WANG-STACK-2013].

**The structural critique.** Manual memory management transfers responsibility from the language to the programmer for every allocation site, every deallocation site, every pointer lifetime, and every ownership decision — in a language with no ownership type system to help track these invariants. This is not a matter of programmer skill. The USENIX Security 2016 study by Jana et al. applied static analysis to 867,000 lines of C code from four SSL/TLS libraries written by expert developers; it found 102 error-handling bugs, of which 53 led to security flaws [JANA-EPEX-2016]. The FSE 2017 ErrDoc study analyzed 13 million lines of C code and confirmed error handling bugs are high-frequency and recurrent even in mature projects [TIAN-ERRDOC-2017]. Expert programmers, writing security-critical code, under public scrutiny, still produce memory safety bugs at scale.

**C23 and checked arithmetic.** C23 added `<stdckdint.h>` (checked integer arithmetic) and `memset_explicit()` [C23-WIKI]. These are welcome additions. They do not change the fundamental model: the programmer must opt in to checking, manually, at every operation site. The default remains unchecked.

The lesson: designing a systems language without memory safety guarantees is choosing to place the entire burden of correct memory management on every programmer, on every day, in every line of code that touches memory. The empirical cost of this choice is now measured in decades of CVEs and government security mandates.

---

## 4. Concurrency and Parallelism

C's concurrency story is one of belated standardization, optional features no one uses, and fundamental guarantees that remain unenforceable.

**Threading standardized 38 years after the language.** C was created circa 1972. `<threads.h>` was standardized in C11, ratified in 2011 — 39 years later [C11-WIKI]. More critically, `<threads.h>` was made *optional*: if an implementation defines `__STDC_NO_THREADS__`, it need not provide threading at all and remain conformant [C11-WIKI]. glibc, the dominant C library on Linux, did not implement `<threads.h>` until glibc 2.28 in 2018 — seven years after standardization. As of 2026, `<threads.h>` is absent from macOS, FreeBSD, NetBSD, OpenBSD, and other major platforms.

The practical consequence is that portable C code requiring threads cannot use the standard threading API. It must use pthreads (POSIX-only, not portable to Windows) or Win32 threads (Windows-only) or an abstraction library (not standard). A feature standardized in 2011 remains unusable for portable programming in 2026.

**Data races are undefined behavior.** The C11 memory model specifies that a program containing a data race has undefined behavior [C-STD-SPEC]. This is strictly worse than Java's approach of defining race semantics for volatile variables. C gives compilers license to assume races cannot occur, then generate code that silently produces incorrect behavior when they do. Vafeiadis et al. (POPL 2015) demonstrated that standard compiler optimizations assumed correct by engineers are formally invalid under the C11 memory model — the model has the "out-of-thin-air" problem and lacks monotonicity [VAFEIADIS-2015]. The standard describing C's concurrency model contains correctness problems that researchers have formally proven.

**The race condition latency problem.** Dirty COW (CVE-2016-5195) is a race condition in the Linux kernel's copy-on-write mechanism. The vulnerability existed from Linux 2.6.22 (September 2007) to 4.8.3 (October 2016) — nine years [CVE-2016-5195]. Linus Torvalds acknowledged he had attempted to fix the underlying race eleven years earlier. Race conditions in C code are exceptionally difficult to detect because they are timing-dependent and may not manifest under testing conditions. No language-level mechanism in C makes races detectable or preventable.

**No structured concurrency, no async.** C has no concept of structured task lifetimes, no cancellation mechanism, and no async/await model. Asynchronous I/O requires callbacks and event loops, implemented via platform-specific APIs (libuv, libevent, IOCP) with no language-level support. This is not merely ergonomic — it means every C program managing concurrent state is implementing its own ad-hoc concurrency model, with attendant opportunity for error.

**Credit where due.** The atomic operations in `<stdatomic.h>` are well-designed for what they do, and the memory ordering model (relaxed, acquire, release, seq_cst) maps correctly to hardware models. For expert-level lock-free programming these primitives are correct tools. The problem is that they require expert-level understanding of memory ordering to use correctly, provide no safety guarantees if misused, and remain optional in the standard.

---

## 5. Error Handling

C's error handling model was designed for a world without exceptions, without result types, and without composable error propagation. By any modern measure, it fails on all three criteria.

**The errno design is architecturally flawed.** `errno` is a thread-local integer variable set by library functions to indicate the type of error that occurred [C-STD-SPEC]. The caller must read it before any subsequent library call that might overwrite it. The `strerror()` function for converting errno codes to human-readable messages is not thread-safe in its base form; `strerror_r` exists but has divergent signatures between POSIX and glibc [LWN-ERRNO]. This design communicates error state through an implicit side channel — it is a global variable dressed up as per-thread state, and its semantic requirements (check immediately, before any other call) are not expressible or enforceable at the language level.

**Return codes are ignored at scale.** CWE-252 (Unchecked Return Value) is a perennial top-25 software weakness [CWE-252]. The mechanism enabling it is structural: C has no equivalent to Rust's `#[must_use]` at the language level; the `[[nodiscard]]` attribute arrived in C23 [C23-WIKI] and only produces a warning (compilers may not enable it by default). The research evidence quantifies the prevalence:

- Jana et al. (USENIX Security 2016) applied static analysis to 867,000 lines of C from four SSL/TLS libraries written by security experts and found 102 error-handling bugs, at least 53 of which led to security flaws breaking SSL/TLS guarantees [JANA-EPEX-2016].
- Tian et al. (FSE 2017) analyzed 13 million lines of C across 30,000 commits from six open-source projects and found error handling bugs are high-frequency and recurring across all projects studied [TIAN-ERRDOC-2017].

These are not amateur codebases. OpenSSL and the projects studied by ErrDoc are among the most scrutinized C code in existence. If expert developers writing security-critical code still produce error-handling bugs at this rate, the cause is the language model, not developer carelessness.

**Composability is absent.** Error propagation in C requires a check at every call site: `if (result < 0) { handle error; }`. There is no `?` operator, no monadic composition, no automatic propagation. A call chain of ten functions each of which can fail requires ten explicit checks, each of which can be omitted without compiler warning (pre-C23) and with only a warning in C23. Libraries have no consistent approach to error representation — some use return codes, some use errno, some use output parameters, some use a mix. This inconsistency compounds the checking burden.

**setjmp/longjmp is not a solution.** The `setjmp`/`longjmp` mechanism provides non-local jumps, used in some codebases for exception-like control flow [C-STD-SPEC]. It bypasses all cleanup, including C++ destructors and manual `free()` calls that would otherwise run. Its use requires that the programmer manually track all resources that need cleanup on non-local exit — exactly the problem it is supposed to solve, unresolved. CERT C coding standards classify misuse of `setjmp`/`longjmp` as a distinct vulnerability class.

**Annex K's failure is evidence.** The C11 standard included Annex K (Bounds-Checking Interfaces), which provided safer string functions (`strcpy_s`, `strcat_s`, etc.) that required the caller to pass buffer sizes and handled errors through a runtime-constraint handler. N1967 (2015) surveyed implementations: Microsoft's implementation was non-conforming, glibc rejected it repeatedly, no open-source distribution shipped it [N1967]. The proposal to remove it was made in 2015; it remains in C23 as dead letter. A safety extension sat in the standard for 13 years without a single viable conforming implementation. This is what the C ecosystem does when confronted with APIs that make error handling mandatory: it ignores them.

---

## 6. Ecosystem and Tooling

The ecosystem argument for C is "it has everything you need, just distributed." This is true in the same sense that a hardware store is a good place to build a house — all the materials are there, but nothing is assembled for you.

**Package management is not a solved problem.** vcpkg has approximately 2,700 packages; Conan Center has 1,765 recipes [VCPKG-STATS, CONAN-STATS]. For comparison, npm has approximately 2.5 million packages and PyPI has approximately 500,000. The disparity is not because C needs fewer packages — it is because C's distribution pattern (system libraries, vendored source, platform packages) predates centralized package registries and has never converged to one. This matters for security: npm audit, cargo audit, and pip's dependency scanning tools provide automated vulnerability disclosure across the dependency graph. No equivalent exists for C. When a vulnerability is discovered in a C library, tracking down which projects use it requires manual effort across OS package managers, git submodules, and vendored copies.

**Build system fragmentation is a real cost.** CMake is used by approximately 83% of C/C++ projects [CPP-DEVOPS-2024], but "dominant" is not "universal." GNU Make, Meson, Autotools, and custom build systems each represent meaningful fractions of the ecosystem. CMake's CMakeLists.txt syntax is widely criticized as non-composable and difficult to understand; Autotools is in decline but still present in legacy codebases with notoriously arcane M4 macro syntax. The absence of a language-standard build tool means every project's build is a potential onboarding barrier.

**Testing has no standard framework.** The research brief lists Unity, cmocka, Check, CUnit, Criterion — no single dominant framework, no built-in testing support, and no usage-share data [BRIEF-TESTING]. For comparison, Go ships with `testing` in the standard library; Rust ships with a built-in test runner; Python's `unittest` is in the standard library. The absence of a testing standard in C means testing culture and tooling are idiosyncratic per-project — onboarding developers to test C code is harder than onboarding them to test in languages where the testing convention is standardized.

**The Annex K failure is also an ecosystem story.** The bounds-checking interfaces were designed by the same ecosystem that was supposed to adopt them. Microsoft proposed them, Microsoft did not implement them. glibc was supposed to implement them, glibc refused. OpenBSD, FreeBSD, the Linux distributions — none shipped them. This is evidence that the C ecosystem, when presented with a safety mechanism that requires slightly different API design, will collectively reject it over a multi-decade period [N1967].

**What the tooling story gets right.** clangd is a high-quality language server; clang-tidy provides 300+ real checks; ASan/TSan/MSan are industry-leading dynamic analysis tools; Coverity and PVS-Studio provide serious static analysis [CLANGD-DOC, ASAN-COMPARISON]. These tools are genuine strengths. The limitation is that they are compensatory — they exist because the language itself does not catch these errors.

---

## 7. Security Profile

The security case against C is the most empirically grounded section of this analysis. The data comes from adversaries (CVE databases), defenders (MSRC, Google Security), and governments (NSA, CISA, White House).

**The core finding, stated plainly.** Memory safety vulnerabilities constitute approximately 70% of annual CVEs at Microsoft, predominantly from C and C++ code [MSRC-2019]. The same 70% figure was independently derived by Google for Chrome [GOOGLE-ANDROID-2024]. In 2019, 76% of Android's security vulnerabilities were memory safety issues [GOOGLE-ANDROID-2024]. The CWE Top 25 for 2024 places memory-related weaknesses at approximately 26% of the total danger score, and notes these weaknesses are "largely restricted to languages with direct memory access (primarily C and C++)" [CWE-TOP25-2024]. These are not disputed figures.

**Undefined behavior as a vulnerability amplifier.** The STACK study (Wang et al., SOSP 2013 Best Paper) introduced the concept of "optimization-unstable code" — code that is silently discarded by the compiler because it assumes the absence of undefined behavior [WANG-STACK-2013]. The tool found 161 confirmed bugs in the Linux kernel and PostgreSQL where security-relevant checks were compiled away. CERT Advisory VU#162289 (2008) documented GCC silently discarding wraparound checks because the compiler treated pointer overflow as a provable impossibility [CERT-VU162289]. CVE-2009-1897 documented GCC compiling away a null pointer check in the Linux kernel TUN driver after the pointer had been dereferenced — a classic UB-exploitation pattern [CVE-2009-1897]. In each case, the programmer wrote correct-looking defensive code; the compiler deleted it.

**Canonical incidents, with root causes.**

- **Heartbleed (CVE-2014-0160):** OpenSSL's heartbeat extension used user-supplied `payload_length` as the argument to `memcpy` without bounds checking. Approximately 17% of all secure web servers were vulnerable at disclosure [HEARTBLEED-WIKI]. Root cause: C provides no mechanism to validate that a length passed to `memcpy` is within the bounds of the source buffer.

- **Dirty COW (CVE-2016-5195):** Race condition in Linux kernel's copy-on-write mechanism, allowing local privilege escalation. Present for nine years before discovery [CVE-2016-5195]. Root cause: C provides no mechanism to detect or prevent data races at compile time or runtime.

- **Baron Samedit (CVE-2021-3156):** Sudo heap buffer overflow introduced in July 2011, present for ten years before Qualys disclosed it in January 2021 [CVE-2021-3156]. Root cause: classic null-termination string manipulation bug — the language's string model requires explicit null tracking with no built-in length validation.

- **EternalBlue (CVE-2017-0144):** SMBv1 vulnerability in Windows (C codebase), weaponized by WannaCry (May 2017) and NotPetya (June 2017), causing billions of dollars in damages [ETERNALBLUE-WIKI].

These are not rare edge cases. They are examples drawn from the most-scrutinized C codebases in the world — the Linux kernel, OpenSSL, sudo, Windows — by expert developers who are nonetheless producing memory safety vulnerabilities at scale.

**The government verdict.** Between 2022 and 2024, five separate government documents explicitly identified C and C++ as sources of unacceptable security risk:

1. NSA "Software Memory Safety" (November 2022): recommends against C and C++ [NSA-MEMSAFE-2022].
2. White House National Cybersecurity Strategy (February 2023): calls for migration to memory-safe languages [WHITE-HOUSE-2023].
3. CISA/NSA/FBI + 5 international agencies, "The Case for Memory Safe Roadmaps" (December 2023): calls on C-suite executives to publish migration roadmaps [CISA-ROADMAPS-2023].
4. White House ONCD, "Back to the Building Blocks" (February 2024): "For thirty-five years, memory safety vulnerabilities have plagued the digital ecosystem" [ONCD-2024].
5. NSA/CISA "Memory Safe Languages" joint guidance (June 2025): recommends that new products be developed in memory-safe languages and existing products publish memory safety roadmaps by end of 2025 [NSA-CISA-2025].

This is not a fringe academic critique. The national security establishments of eight countries have formally assessed C and concluded its memory safety profile is incompatible with secure software development at scale.

**Supply chain.** C has no centralized package registry and therefore no systematic vulnerability disclosure mechanism across the dependency graph. When a vulnerability is discovered in a widely-vendored C library, tracking affected downstream projects requires manual effort. This is a structural gap that is not resolvable without coordinated ecosystem change — which C's distribution model resists.

---

## 8. Developer Experience

The developer experience of C is often romanticized as lean and powerful. It is lean. The power comes with costs that are difficult to quantify in surveys but visible in CVE databases.

**The undefined behavior trap.** The most insidious aspect of C's developer experience is that programs can appear to work correctly in development and then silently misbehave in production. The STACK study showed that security checks can be compiled away at higher optimization levels — code that passes all tests at `-O0` may have critical checks eliminated at `-O2` [WANG-STACK-2013]. Russ Cox documents a case where Clang optimizes away an entire loop when a variable is uninitialized, with no warning; signed overflow causes a compiler to assume `x+100` can never be less than `x`, deleting a bounds check [COX-UB-2023]. This is not a compiler bug — this is correct behavior under the C standard. The developer experience includes a class of failures that are invisible to testing and only manifest under specific optimization conditions.

**Learning curve: simple syntax, treacherous semantics.** C's syntax is genuinely simple, and this is a real virtue for initial acquisition. The trap is that the simple syntax conceals semantic complexity that takes years to master. Pointer arithmetic, strict aliasing, integer promotion rules, undefined behavior classification, POSIX API semantics — none of this is visible in the syntax. A developer who has written C for two years may write code that is subtly undefined in ways they will not discover until a specific compiler version on a specific target architecture exposes the behavior. This gap between apparent and actual mastery is unusual among languages; most languages' semantic complexity is at least surfaced by the type system.

**Salary data is a poor proxy for importance.** The research brief reports the average U.S. base salary for C developers at $76,304 — the lowest among the four pilot languages studied [DEV-SURVEYS-DOC]. This is a paradox: C developers maintain the foundational infrastructure on which the entire software ecosystem runs, and they earn less in survey averages than PHP developers. This reflects survey bias and market segmentation (embedded systems, lower-cost geographic regions) rather than the true value of C expertise. However, it also suggests that C expertise is not scarce in the way that would be expected if the language required rare skill — which conflicts with the claim that C is hard to use correctly.

**Community culture lacks safety conventions.** Unlike Rust, which has formalized unsafe boundaries, or Go, which mandates error handling patterns through convention enforced by tooling, C's community has no dominant convention for managing memory, ownership, or error handling. The Linux kernel coding style mandates indentation and naming but does not mandate error handling patterns [KERNEL-STYLE]. MISRA C exists for safety-critical domains [MISRA-WIKI] but is an external standard, not a language community norm. CERT C exists for secure coding but adoption is self-selected. The absence of a strong community-level safety convention means that C codebases vary enormously in safety discipline, and good practices from one codebase do not automatically transfer.

**Satisfaction is unmeasured — and this is telling.** The research brief notes that C does not appear in Stack Overflow's "most loved" or "most dreaded" categories, and that no C-specific satisfaction data exists [DEV-SURVEYS-DOC]. The absence is attributed to survey methodology, which is correct. But it also means there is no systematic data on whether C developers find the language pleasant to work in. The survey gap is a gap in evidence, not evidence of satisfaction.

---

## 9. Performance Characteristics

This is the section where C's case is strongest, and I will be brief about it.

C is the de facto performance baseline. The Computer Language Benchmarks Game consistently places C at or near the top of algorithmic performance, with near-zero runtime overhead, no GC pauses, no JIT warmup, and direct hardware access [BENCHMARKS-DOC]. For workloads where every cycle matters — cryptographic operations, codec implementations, operating system kernels, real-time embedded systems — C remains the reference. Rust has shown that memory safety and C-level performance are not incompatible, but C got there first and has the deeper toolchain maturity.

The qualification that must be noted: performance is not free. The cost of C's performance model is not paid at compile time or at runtime — it is paid in developer hours spent on memory debugging, in the security patches applied to memory safety vulnerabilities, and in the fuzzing infrastructure deployed to find bugs that safe languages would prevent. These costs are real but rarely appear in benchmark comparisons.

Compiler optimization deserves specific note: GCC and Clang achieve C's benchmark dominance partly by exploiting undefined behavior as an optimization opportunity [COX-UB-2023]. When the compiler assumes signed overflow cannot occur, it can eliminate bounds checks and loop-iteration guards. This means C's performance numbers are partly dependent on the same mechanism that enables security vulnerabilities. The performance and the danger come from the same design decision.

---

## 10. Interoperability

C is the universal ABI. Every language ecosystem that interoperates with native code does so via C-compatible calling conventions. Python's CPython, Ruby's CRuby, Lua, Java via JNI, Rust's `extern "C"`, Go's `cgo` — all cross the FFI boundary through C. This is a genuine, structural strength that no other language matches.

The interoperability story is good enough that I will not manufacture criticisms of it. The C ABI is stable, well-understood, universally supported, and the de facto standard for cross-language native code integration. This is the right design.

Two qualifications: First, the FFI boundary is a documented source of vulnerabilities in otherwise-safe languages. When a Rust or Go program calls into a C library, the memory safety guarantees of Rust or Go stop at that boundary. Vulnerabilities in C libraries surface as vulnerabilities in the programs that embed them, regardless of the embedding language's safety properties. Second, C has no standard mechanism for structured data interchange — no built-in JSON, protobuf, or serialization format. These are provided by third-party libraries with no standardized selection.

---

## 11. Governance and Evolution

C's governance is characterized by intentional conservatism. The WG14 charter is explicit: decisions require prior implementation experience [WG14-N2611]. The committee moves on 6–12 year cycles. The philosophy is stability above all else. For a language this widely deployed, stability has real value.

The problem is that the same conservatism that protects existing code prevents the language from addressing its most serious structural flaws.

**The `defer` story.** A scope-based cleanup mechanism for C would directly address the most common pattern behind resource leaks and use-after-free bugs: failing to call `free()` or close resources on error paths. N2895 proposed `defer` for C23. WG14 rejected it under Principle 13 ("No invention, without exception") because prior implementation experience was insufficient — circular reasoning when the feature cannot accumulate implementation experience without being in the standard [WG14-DEFER]. It was redirected to a Technical Specification targeting C2Y (2029 or 2030). A safety feature for a 57-year-old language awaits a decade-plus standardization timeline.

**The Annex K failure is the governance case study.** Annex K (bounds-checking string functions) was included in C11 in 2011. N1967 (2015) surveyed implementations and found: Microsoft's implementation non-conforming, glibc rejected it repeatedly, no major open-source distribution shipped it [N1967]. The proposal to remove it was made in 2015. It remains in C23 as unimplemented optional text. For 13 years, a safety extension sat in the C standard with zero viable conforming implementations. The committee that standardized it did not implement it. The dominant library for the dominant platform rejected it. This is not a marginal failure — it is a systemic demonstration that WG14's process for adopting safety extensions is disconnected from ecosystem reality.

**The Memory Safety Study Group.** WG14 now has a Memory Safety Study Group, chaired by Martin Uecker [WG14-MEETINGS]. This is a positive development. It is also approximately 50 years late: the first buffer overflow exploit was documented in the 1972 Anderson Report, and the Morris Worm exploited `gets()` in 1988. The Study Group was formed not because WG14 identified the problem, but because government agencies told software manufacturers to fix it [NSA-CISA-2025, ONCD-2024].

**Multiple implementations and dialect fragmentation.** GCC implements GNU C (`gnu11`, `gnu17`) with extensions beyond ISO C, including statement expressions, nested functions, and flexible array member behaviors [LINUX-LOC]. The Linux kernel uses GNU C explicitly and relies on GCC-specific extensions. MSVC historically refused to implement C99 for over a decade, creating a practical split where Windows C development remained on C89 while the rest of the world moved forward [BRIEF-MSVC-GAP]. This dialect fragmentation is not an accidental failure — it is the predictable result of a standardization process that moves too slowly for the ecosystem to wait.

**Bus factor.** WG14's process is institutionally robust — no individual's departure would stop the standards process. The implementation ecosystem is more concentrated: GCC, Clang, and MSVC together cover the vast majority of production C compilation. The Linux kernel's specific dependence on GCC extensions means that if GCC's direction diverged significantly from the kernel's needs, one of the world's most critical codebases would face a genuine toolchain crisis.

---

## 12. Synthesis and Assessment

### Greatest Strengths

1. **Performance as the reference baseline.** C remains the benchmark against which all other languages measure runtime performance. For workloads where performance is the primary constraint, C has no peer except C++ and (increasingly) Rust.

2. **Universal ABI and interoperability.** Every language ecosystem interoperates with native code through C. This is an irreplaceable structural position that took decades to establish and cannot be replicated quickly.

3. **Minimal footprint and deterministic behavior.** No GC, no runtime, no VM. C produces small, predictable executables suitable for embedded and resource-constrained environments. This is the correct design for the domains C targets.

4. **Proven longevity.** Code written in the 1970s compiles today. This is a remarkable backward-compatibility achievement with real value for long-lived infrastructure.

### Greatest Weaknesses

1. **Memory safety: no language-level guarantees, catastrophic empirical consequences.** Approximately 70% of the security vulnerabilities in major C codebases are memory safety issues that the language neither prevents nor detects. This is not a fixable implementation problem — it is a consequence of the design philosophy that manual memory management, undefined behavior, and "trust the programmer" are the correct defaults. The empirical record spanning five decades contradicts this.

2. **Undefined behavior as a hidden semantic layer.** UB is not merely undefined — it is exploited by compilers in ways that surprise developers, delete safety checks, and create security vulnerabilities that no amount of testing can reliably surface. The interaction between UB and compiler optimization is not a bug; it is specified behavior that is nonetheless incompatible with writing correct secure code at scale.

3. **Error handling with no composition and no enforcement.** The return-code/errno model is non-composable, routinely ignored (at empirically documented rates), and architecturally structured to reward path-of-least-resistance coding (no check) over correct coding (check and handle). There is no language mechanism that makes correct error handling the default.

4. **Concurrency model: late, optional, and formally defective.** Threading standardized 39 years after the language, made optional, not implemented for years after standardization, and the resulting memory model contains formal correctness problems. Race conditions are undefined behavior with no detection mechanism.

5. **Governance that cannot correct structural mistakes.** The "No invention" principle and consensus requirement produce a standardization process that cannot adopt safety improvements at a rate comparable to the discovery of new vulnerability classes. Annex K — the clearest attempt to address C's most chronic vulnerability class — was rejected by the ecosystem over 13 years. `defer`, which would address a clear resource management pattern, has been deferred past 2029.

### Lessons for Language Design

1. **"Trust the programmer" is not a safety philosophy — it is the absence of one.** Language designers who adopt this principle are choosing to export the entire cost of programmer error to users, operators, and security researchers. The empirical cost of this choice is now quantified across multiple major software organizations and national security agencies. New languages should distinguish between "don't paternalize style" (reasonable) and "provide no safety guarantees" (not reasonable for a production language).

2. **Undefined behavior as an optimization mechanism is a design mistake.** C's UB exploited for performance generates real vulnerabilities that testing cannot reliably detect. A language that makes the correct behavior of security checks dependent on which compiler optimizations are enabled has made a design error. Languages that need UB for performance should at minimum make it syntactically explicit (cf. Rust's `unsafe` blocks) and should not use it for cases where it silently deletes defensive code.

3. **Optional safety features are ineffective safety features.** Annex K proved this conclusively over 13 years. If a safety mechanism can be ignored by implementers and skipped by users without consequence, it will be. Safety features that are not defaults are, in practice, not features. Language designers should make the safe path the default path, not an opt-in.

4. **Late standardization of concurrent primitives creates ecosystem fragmentation that persists for decades.** C's lack of concurrency standardization until C11 (2011) meant that every platform and project developed its own threading model. Ecosystem fragmentation in threading creates portability barriers that are still present in 2026. Languages designed for concurrent use cases should include concurrency primitives in the language or standard library from the beginning, not as retrofits.

5. **Error handling models that allow easy omission will see widespread omission.** The empirical literature on C error handling (CWE-252, Jana et al., Tian et al.) demonstrates that even expert developers writing security-critical code routinely fail to check error returns in C. The language mechanism — a warning-less dropped return value — makes the wrong choice the easy choice. Language designers should invert this: make unchecked errors a compile error, not a warning, and provide syntactic support (cf. `?` in Rust, `try` in Swift) for the common case of propagating errors up the call chain.

---

## References

[RITCHIE-1993] Ritchie, Dennis M. "The Development of the C Language." HOPL-II. ACM SIGPLAN Notices 28(3), 1993.

[KR-1978] Kernighan, Brian W. and Ritchie, Dennis M. *The C Programming Language*, 1st edition. Prentice Hall, 1978.

[WG14-N2611] Keaton, David. "C23 Charter." WG14 Document N2611, November 2020. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n2611.htm

[WG14-DEFER] WG14 Document N2895 (defer proposal) and related TS discussion. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n2895.htm

[WG14-MEETINGS] WG14 meeting records and study group information. https://www.open-std.org/jtc1/sc22/wg14/www/meetings

[C-STD-SPEC] ISO/IEC 9899:2024 (C23). International Standard for C.

[C11-WIKI] Wikipedia. "C11 (C standard revision)." https://en.wikipedia.org/wiki/C11_(C_standard_revision)

[C23-WIKI] Wikipedia. "C23 (C standard revision)." https://en.wikipedia.org/wiki/C23_(C_standard_revision)

[CVE-DOC-C] "CVE Pattern Summary: C Programming Language." Evidence repository, February 2026. `evidence/cve-data/c.md`

[DEV-SURVEYS-DOC] "Cross-Language Developer Survey Aggregation." Evidence repository, February 2026. `evidence/surveys/developer-surveys.md`

[BENCHMARKS-DOC] "Performance Benchmark Reference: Pilot Languages." Evidence repository, February 2026. `evidence/benchmarks/pilot-languages.md`

[MSRC-2019] Miller, Matt. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center / BlueHat IL 2019. https://msrc.microsoft.com/blog/2019/07/a-proactive-approach-to-more-secure-code/

[GOOGLE-ANDROID-2024] Google Security Blog. "Eliminating Memory Safety Vulnerabilities at the Source." September 2024. https://security.googleblog.com/2024/09/eliminating-memory-safety-vulnerabilities-Android.html

[NSA-MEMSAFE-2022] NSA. "Software Memory Safety." CSI document, November 2022. https://media.defense.gov/2022/Nov/10/2003112742/-1/-1/0/CSI_SOFTWARE_MEMORY_SAFETY.PDF

[WHITE-HOUSE-2023] The White House. "National Cybersecurity Strategy." February 2023. https://www.whitehouse.gov/wp-content/uploads/2023/03/National-Cybersecurity-Strategy-2023.pdf

[CISA-ROADMAPS-2023] CISA/NSA/FBI et al. "The Case for Memory Safe Roadmaps." December 2023. https://www.cisa.gov/sites/default/files/2023-12/The-Case-for-Memory-Safe-Roadmaps-508c.pdf

[ONCD-2024] White House ONCD. "Back to the Building Blocks: A Path Toward Secure and Measurable Software." February 26, 2024. https://bidenwhitehouse.archives.gov/wp-content/uploads/2024/02/Final-ONCD-Technical-Report.pdf

[NSA-CISA-2025] NSA/CISA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://www.cisa.gov/news-events/alerts/2025/06/24/new-guidance-released-reducing-memory-related-vulnerabilities

[CWE-TOP25-2024] MITRE. "CWE Top 25 Most Dangerous Software Weaknesses — 2024." https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html

[CWE-252] MITRE. "CWE-252: Unchecked Return Value." https://cwe.mitre.org/data/definitions/252.html

[WANG-STACK-2013] Wang, Xi; Zeldovich, Nickolai; Kaashoek, M. Frans; Solar-Lezama, Armando. "Towards Optimization-Safe Systems: Analyzing the Impact of Undefined Behavior." SOSP 2013 (Best Paper). https://people.csail.mit.edu/nickolai/papers/wang-stack.pdf

[CERT-VU162289] CERT Advisory VU#162289. "C Compilers May Silently Discard Some Wraparound Checks." April 2008. https://www.kb.cert.org/vuls/id/162289

[CVE-2009-1897] NVD. CVE-2009-1897: Linux kernel TUN driver null pointer check compiled away. https://www.cvedetails.com/cve/CVE-2009-1897/

[DIETZ-2012] Dietz, Will; Li, Peng; Regehr, John; Adve, Vikram. "Understanding Integer Overflow in C/C++." ICSE 2012 (ACM SIGSOFT Distinguished Paper). https://users.cs.utah.edu/~regehr/papers/overflow12.pdf

[COX-UB-2023] Cox, Russ. "C and C++ Prioritize Performance over Correctness." August 2023. https://research.swtch.com/ub

[REGEHR-ALIASING-2016] Regehr, John. "The Strict Aliasing Situation is Pretty Bad." Embedded in Academia, 2016. https://blog.regehr.org/archives/1307

[JANA-EPEX-2016] Jana, Suman; Kang, Yuan; Roth, Samuel; Ray, Baishakhi. "Automatically Detecting Error Handling Bugs Using Error Specifications." USENIX Security 2016. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/jana

[TIAN-ERRDOC-2017] Tian, Yuchi et al. "Automatically Diagnosing and Repairing Error Handling Bugs in C." FSE 2017 (Best Paper). https://yuchi1989.github.io/papers/fse17-ErrDoc.pdf

[N1967] O'Donell, Carlos; Sebor, Martin. "Field Experience With Annex K — Bounds Checking Interfaces." WG14 Document N1967, September 2015. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1967.htm

[CVE-2016-5195] NVD. CVE-2016-5195: Dirty COW — race condition in Linux kernel copy-on-write. https://dirtycow.ninja/

[VAFEIADIS-2015] Vafeiadis, Viktor et al. "Common Compiler Optimisations are Invalid in the C11 Memory Model." POPL 2015. https://fzn.fr/readings/c11comp.pdf

[HEARTBLEED-WIKI] Wikipedia. "Heartbleed." https://en.wikipedia.org/wiki/Heartbleed

[ETERNALBLUE-WIKI] Wikipedia. "EternalBlue." https://en.wikipedia.org/wiki/EternalBlue

[CVE-2021-3156] Qualys. "CVE-2021-3156: Heap-Based Buffer Overflow in Sudo (Baron Samedit)." January 2021. https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit

[LWN-ERRNO] LWN.net. "Time To Get Rid Of errno." 2015. https://lwn.net/Articles/655134/

[CERT-C-INT] SEI CERT C Coding Standard, Integer rules. https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=87152052

[GCC-PITFALLS] GCC documentation. "Macro Pitfalls." https://gcc.gnu.org/onlinedocs/cpp/Macro-Pitfalls.html

[COSSACK-MACROS] Cossack Labs. "Auditable Macros in C Code." https://www.cossacklabs.com/blog/macros-in-crypto-c-code/

[ASAN-COMPARISON] Red Hat. "Memory Error Checking in C and C++: Comparing Sanitizers and Valgrind." 2021. https://developers.redhat.com/blog/2021/05/05/memory-error-checking-in-c-and-c-comparing-sanitizers-and-valgrind

[VCPKG-STATS] vcpkg GitHub repository and release notes. https://github.com/microsoft/vcpkg

[CONAN-STATS] Conan Center. https://conan.io — "C++ Packages in 2024." Philips Technology Blog. https://medium.com/philips-technology-blog/c-packages-in-2024-179ab0baf9ab

[CPP-DEVOPS-2024] "Breaking Down the 2024 Survey Results." Modern C++ DevOps. https://moderncppdevops.com/2024-survey-results/

[CLANGD-DOC] LLVM clangd project. https://clangd.llvm.org/

[LINUX-LOC] "Linux Kernel Surpasses 40 Million Lines of Code." Stackscale, January 2025. https://www.stackscale.com/blog/linux-kernel-surpasses-40-million-lines-code/

[KERNEL-STYLE] Linux Kernel Coding Style. https://docs.kernel.org/process/coding-style.html

[MISRA-WIKI] Wikipedia. "MISRA C." https://en.wikipedia.org/wiki/MISRA_C

[BRIEF-TESTING] C Research Brief, Testing section. `research/tier1/c/research-brief.md`
