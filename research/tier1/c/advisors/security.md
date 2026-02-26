# C — Security Advisor Review

```yaml
role: advisor-security
language: "C"
agent: "claude-sonnet-4-6"
date: "2026-02-26"
schema_version: "1.1"
```

---

## Summary

The C council's security analysis is broadly accurate and better-evidenced than most comparative language security assessments. All five perspectives correctly ground their claims in NVD/CWE data, published incident records, and government guidance. The core finding — that C's memory safety profile is structurally weak and that this weakness is an inherent consequence of language design, not merely developer error — is defensible and well-supported. The practitioner, realist, and detractor perspectives are the strongest on security; the historian perspective appropriately contextualizes origins without excusing the present; the apologist makes several claims that require qualification or correction.

Two findings from the council documents deserve particular emphasis for the synthesizing agent. First, the Android memory-safety migration data cited by the detractor — that Android's share of memory safety CVEs fell from 76% in 2019 to 24% after Rust adoption in new components — is the strongest empirical counter-argument to the normalization objection [GOOGLE-ANDROID-2024]. It demonstrates that the vulnerability surplus in C codebases is attributable to language choice, not merely to codebase size or scrutiny level. Second, the detractor's citation of Vafeiadis et al. (POPL 2015) — showing that standard compiler optimizations are not provably correct under the C11 memory model — should inform the concurrency section of any synthesis; the formal foundation of C's concurrency semantics has unresolved theoretical problems, not merely implementation gaps [VAFEIADIS-2015].

Several specific corrections and additions are warranted: the [GOOGLE-ANDROID-2024] citation key conflates Chrome and Android data from different sources and years; the apologist's claim about MISRA C's "strong security track record" is unsubstantiated; the EternalBlue-as-NSA-development attribution is officially unconfirmed; and the council's treatment of severity distribution (all CVEs are not equally severe) is absent, which weakens the normalization discussion. No perspective discusses Control Flow Integrity (CFI) as a mitigation, TOCTOU as a concurrency security class, or the practical exploitation shift from stack-based to heap-based vulnerabilities after widespread ASLR and stack canary adoption.

---

## Section-by-Section Review

### Section 7: Security Profile

#### Accurate Claims

**The 70% Microsoft MSRC figure.** All five perspectives cite approximately 70% of Microsoft's annual CVEs as memory safety issues [MSRC-2019]. This figure is accurate, reproducible from the cited source, and — critically — persistent across years. The evidence file notes it appears in both the 2019 MSRC blog post and a November 2025 Windows Security Report [CVE-DOC-C]. A figure that holds across a six-year span is a structural finding, not a snapshot. The practitioner, realist, and detractor are correct to treat it as a baseline fact rather than a contestable claim.

**The five dominant vulnerability classes and approximate proportions.** Buffer overflow (CWE-120/119) at 25–30%, use-after-free (CWE-416) at 15–20%, integer overflow (CWE-190/191) at 10–15%, format string (CWE-134) at 5–10%, and double-free/resource deallocation (CWE-415/772) at 5–10% are consistent with NVD data and the CWE Top 25 [CVE-DOC-C, CWE-TOP25-2024]. The council is correct that these are not exotic or rare — they are predictable consequences of specific language properties, and that causal attribution is correct.

**The STACK study mechanism (UB as vulnerability amplifier).** The detractor's citation of Wang et al. (SOSP 2013) is accurate: the study demonstrated that in Linux and PostgreSQL, compilers silently eliminated security-relevant checks because those checks implied undefined behavior — 161 confirmed bugs [WANG-STACK-2013]. CERT Advisory VU#162289 (2008) and CVE-2009-1897 (GCC null pointer check removal in the Linux kernel TUN driver) are real, verifiable incidents that demonstrate the same mechanism [CERT-VU162289-2008, CVE-2009-1897]. These are not theoretical — they are documented cases where the compiler's correct interpretation of C semantics deleted the programmer's correct-looking defensive code. This mechanism should be a central finding in any synthesis, not a footnote.

**Heartbleed root cause.** All perspectives describe Heartbleed (CVE-2014-0160) correctly: the vulnerability arose from using user-supplied `payload_length` as the argument to `memcpy` without bounds-checking. The root cause is precisely a C-level property: the language provides no mechanism to validate that a length argument passed to `memcpy` is within the source buffer's bounds. The "17% of TLS servers" estimate [HEARTBLEED-WIKI] is widely cited and reasonable. The practitioner's characterization — "not a freak accident; it was C's error handling model plus C's memory model interacting exactly as designed" — is the correct framing.

**Baron Samedit (CVE-2021-3156).** The detractor correctly identifies this as a heap buffer overflow in sudo, introduced July 2011, disclosed January 2021, persisting a decade across one of the most scrutinized command-line security tools in Unix [CVE-2021-3156]. Root cause: mishandling of backslash escape sequences in null-terminated string processing — a classic C string handling bug enabled by the absence of length metadata in C strings. This is an instructive incident because sudo's privileged execution context means the vulnerability represented local privilege escalation to root on any affected system.

**Dirty COW (CVE-2016-5195) as a data race with security consequences.** The realist and detractor correctly identify this as a nine-year-old race condition in the Linux kernel's copy-on-write memory subsystem that enabled local privilege escalation [DIRTYCOW-WIKI]. It is discussed further under Section 4.

**Government guidance accurately summarized.** The detractor's enumeration of five government documents between 2022 and 2025 is accurate: the NSA's November 2022 guidance [NSA-MEMSAFE-2022], the White House National Cybersecurity Strategy (February 2023) [WHITE-HOUSE-2023], the CISA/NSA/FBI "Case for Memory Safe Roadmaps" (December 2023) [CISA-ROADMAPS-2023], the ONCD "Back to the Building Blocks" (February 2024) [ONCD-2024], and the NSA/CISA joint guidance (June 2025) [NSA-CISA-2025]. The realist is correct to treat this as a "meaningful signal" based on production incident data — these agencies have access to classified incident reporting that reinforces what the public CVE record shows.

**Annex K failure.** Multiple perspectives correctly cite N1967's finding that Annex K (bounds-checking interfaces from C11) had no viable conforming implementation after four years, with Microsoft non-conforming and glibc refusing [N1967]. This is important security evidence: the C ecosystem, when presented with an API that makes error-checking mandatory rather than optional, rejected it over a thirteen-year period. The lesson is operational, not merely historical.

#### Corrections Needed

**Citation precision: [GOOGLE-ANDROID-2024] conflates two separate datasets.** The detractor cites this key for both "70% of Chrome's high-severity security bugs are memory safety issues" and "76% of Android's security vulnerabilities in 2019 were memory safety issues." These are from different sources, different time periods, and different organizations. The Chrome figure comes from Google's Chrome Security team (a 2020 blog post by Adrian Taylor). The Android figure comes from a separate Google security blog post by Jeff Vander Stoep and Chong Zhang, also from 2020. The subsequent "24%" figure (memory safety CVEs after Rust adoption) comes from Google's 2024 Android security report. The citation key should be split into at minimum [CHROME-MEMSAFE-2020], [ANDROID-MEMSAFE-2020], and [ANDROID-RUST-2024] to distinguish these sources. As written, the key is not queryable and obscures which organization's data supports which claim.

**EternalBlue attribution is unconfirmed.** The detractor states EternalBlue was "developed by the NSA." This attribution derives from the Shadow Brokers disclosure (April 2017) and has been widely reported, but has never been officially confirmed by the United States government. The security profile claim should be stated as "attributed to the NSA by the Shadow Brokers group" rather than as established fact. The economic damage claim ("billions of dollars") is reasonable for WannaCry/NotPetya combined, with NotPetya alone estimated at $10B+ by various industry sources.

**Apologist's MISRA C "strong security track record" is unsubstantiated.** The apologist claims that C code written to MISRA C:2023 and validated with Polyspace or LDRA has a "strong security track record" in aircraft, medical devices, and automotive systems [MISRA-WIKI]. This claim is not supported by citation in the council documents, and the underlying evidence is ambiguous for several reasons. MISRA C is a functional safety standard (originating from the Motor Industry Software Reliability Association), not a security standard — it addresses defect prevention and portability for safety-critical functions, but does not systematically address all memory safety vulnerability classes. More importantly, MISRA-certified embedded systems have historically operated in isolated, non-networked environments; their security track record in adversarially networked contexts (connected vehicles, IoT medical devices) is not systematically documented and is the subject of ongoing concern. The claim should be scoped: MISRA C reduces specific dangerous constructs, but a "strong security track record in adversarial contexts" requires specific evidence that has not been provided.

**MSRC 2019 citation age.** Perspectives citing the 70% figure from [MSRC-2019] should note that the primary source is a 2019 blog post. The evidence file references a November 2025 MSRC report that presumably reconfirms the figure; where possible, the more recent citation should be the primary reference to avoid the objection that the data is stale.

#### Additional Context

**The Android/Rust migration data is the strongest counter-argument to the normalization objection.** The apologist's normalization argument — that C's high CVE count reflects its enormous deployed footprint rather than a per-unit higher vulnerability rate — is methodologically valid. However, the Android data directly refutes the strongest version of this argument. Google's Android team increased Rust's share of new code in Android starting around 2021. By their 2024 report, memory safety vulnerabilities had dropped from 76% to 24% of Android's total CVEs [GOOGLE-ANDROID-2024]. The codebase size and scrutiny level of Android did not change substantially; the language used for new components did. This is the closest thing available to a controlled experiment on memory-safe vs. memory-unsafe language choice at industrial scale. Every synthesis that engages with the normalization argument must reckon with this data.

**Memory safety CVEs are disproportionately exploitable, not uniformly distributed across severity.** No council perspective discusses the CVSS score distribution of C memory safety CVEs. This is a gap. Memory safety bugs — particularly heap use-after-free and buffer overflows — are disproportionately rated CVSS 7.0+ because their primary impact categories are remote code execution and privilege escalation. The CWE Top 25 danger score methodology weights by both prevalence and severity [CWE-TOP25-2024]. A normalization argument based on raw CVE counts understates the security impact if high-severity CVEs are overrepresented in C's portfolio, which the evidence suggests they are.

**CFI (Control Flow Integrity) is an important mitigation not discussed.** Clang's `-fsanitize=cfi` and Microsoft's Control Flow Guard (CFG) provide partial mitigation against control-flow hijacking attacks that exploit memory corruption. Hardware-enforced CFI (ARM MTE, Intel CET) is increasingly deployed. None of the perspectives discuss CFI's role in the defense-in-depth posture for C code, or the state of adoption in production. This is a genuine gap in the security profile analysis.

**Exploitation has shifted from stack to heap, with implications for the defense-in-depth assessment.** ASLR and stack canaries, now universal in production deployments, have substantially reduced the exploitability of classic stack buffer overflows. The vulnerability classes that dominate current exploitation are heap use-after-free (CWE-416) and heap buffer overflows (CWE-122) — the classes where stack-era mitigations provide less protection. The practitioner's defensive tooling discussion (clangd, clang-tidy, ASan, fuzzing) should be updated to reflect that the threat model has shifted from stack corruption to heap corruption, and that the tooling's effectiveness differs by class.

#### Missing Data

- **Severity-weighted CVE analysis.** The council documents treat CVEs as a count, not weighted by severity. A table of C memory safety CVEs by CVSS score range would sharpen the normalization discussion.
- **Temporal trend in C's per-KLOC vulnerability rate.** Is the rate improving as tooling adoption increases, or holding flat? The government guidance implies the latter, but no longitudinal analysis is present.
- **CFI adoption rates and bypass rates in practice.** How much does CFI deployment actually reduce attack surface for C codebases in production?
- **Formal verification (Compcert, seL4).** A brief discussion of proven-correct C subsets would contextualize the upper bound of what C security can achieve with maximum investment.
- **The Vafeiadis et al. POPL 2015 finding.** This belongs in Section 4 but has security implications that deserve mention in Section 7: the formal foundation of C's concurrency model has unresolved correctness issues, meaning concurrent C code that appears correctly synchronized may be operating on an under-specified base [VAFEIADIS-2015].

---

### Section 2: Type System (Security Implications)

#### Accurate Claims

**Signed/unsigned comparison and implicit conversion as integer overflow precursors.** The practitioner and detractor correctly identify that C's implicit integer conversion rules create a class of bugs that appears syntactically correct, compiles without error (and often without warning at default flags), and produces security-relevant wrong answers. The practitioner's example — a signed loop counter compared against an unsigned container size producing a loop that iterates 4 billion times — is accurate and documented in production CVE data [CVE-DOC-C]. The detractor's example — `if (len < 0)` failing silently when `len` is `unsigned` — is a canonical CWE-190 precursor pattern. Both are correct.

**Strict aliasing as a security concern.** The detractor's analysis is accurate: C's strict aliasing rules allow compilers to assume that pointers of different types do not alias the same memory. The Linux kernel builds with `-fno-strict-aliasing` because union-based network structure code violates strict aliasing rules pervasively, and the performance cost of disabling the optimization is accepted to avoid incorrect behavior [REGEHR-ALIASING-2016]. Firefox made the same choice. This is not a theoretical failure mode — it is a practical one that two of the most security-sensitive codebases in existence have addressed by disabling a language feature. The conclusion the detractor draws — "when major projects must disable a language rule to avoid incorrect behavior, that rule is evidence of a design failure" — is supported.

**Null pointer type safety gap.** The detractor's observation that C has no equivalent of Rust's `Option<T>`, Kotlin's nullable types, or Swift's optionals is accurate. Nullability is an informal contract communicated through naming conventions and documentation rather than enforced by the type system. The link to CWE-416 (use-after-free) that the detractor draws is reasonable: many use-after-free bugs begin with incorrect pointer lifetime assumptions that a non-nullable type would flag.

#### Corrections Needed

None at the factual level. The apologist's framing of C's type system as "permissive" rather than "unsafe" is a legitimate conceptual distinction, but it should not be used to minimize security implications — permissiveness that enables security vulnerabilities is, from a security engineering perspective, a safety concern regardless of what it is called.

#### Additional Context

**`char` signedness is implementation-defined and has security implications.** Whether `char` is signed or unsigned is implementation-defined in the C standard [C-STD-SPEC]. For security code that does character-by-character processing — parsers, protocol implementations, string classifiers — platform-dependent `char` signedness creates latent portability bugs. A comparison like `if (c == '\xff')` behaves differently on platforms with signed versus unsigned `char`. This is a minor but genuine type safety gap that no perspective mentions.

**Function pointer casting enables control-flow hijacking.** C permits casting between function pointer types with incompatible signatures; calling through a mistyped function pointer is undefined behavior, but commonly "works" in practice. Exploits targeting return-oriented programming (ROP) and JOP (jump-oriented programming) rely on the existence of usable gadgets reachable through function pointer corruption. While this is an exploitation technique rather than a vulnerability class per se, the permissiveness of C's function pointer type model is a relevant attack surface property.

**Integer promotion rules create non-obvious security behavior.** The C standard's usual arithmetic conversions and integer promotion rules are a documented source of security-relevant surprises. When a `char` or `short` participates in arithmetic, it is promoted to `int`; in expressions mixing signed and unsigned types, signed values are converted to unsigned. These rules are specified in the standard and correctly implemented by all compilers, but their security implications are not obvious from source code inspection and are not uniformly taught in C curricula.

---

### Section 3: Memory Model (Security Implications)

#### Accurate Claims

**No language-level safety guarantees.** All perspectives correctly state that C provides no compile-time or runtime protection against buffer overflow, use-after-free, double-free, null pointer dereference, or memory leak. This is accurate and is not contested by any perspective, including the apologist, which says "the apologist does not contest this." The mechanistic relationship between this design choice and the CVE profile is correctly drawn.

**AddressSanitizer and Valgrind overhead figures.** The practitioner's overhead figures — ASan at 2–3x runtime overhead, Valgrind at 3–13x — are cited from [ASAN-COMPARISON] and [VALGRIND-ORG] and are accurate for typical workloads. The security implication the practitioner draws — that these tools cannot be deployed in production, creating a gap between detectable-in-development and exploitable-in-production — is correct and important.

**The STACK study mechanism (security checks compiled away).** Addressed above under Section 7. The detractor's citation of the STACK study [WANG-STACK-2013] and the specific CVE-2009-1897 case (GCC removing a null pointer check in the Linux kernel TUN driver after the pointer was dereferenced) are accurate and verified. These represent a qualitatively distinct vulnerability type: the programmer wrote correct defensive code; the compiler deleted it; the shipped binary was vulnerable. No dynamic testing regime at `-O0` would have found this class of bug.

**Expert developers produce memory safety bugs at scale.** The detractor cites Jana et al. (USENIX Security 2016), who applied static analysis to 867,000 lines of C from four SSL/TLS libraries written by expert security-focused developers and found 102 error-handling bugs, 53 of which led to security flaws [JANA-EPEX-2016]. The detractor also cites Tian et al. (FSE 2017, ErrDoc) analyzing 13 million lines of C, confirming that error handling bugs are high-frequency in mature projects [TIAN-ERRDOC-2017]. These citations support the claim that the memory safety problem is structural, not a matter of developer skill — and they are more direct evidence for that claim than CVE counts alone.

**C23's `<stdckdint.h>` is opt-in, not structural.** All perspectives correctly note that C23's checked integer arithmetic functions (`ckd_add`, `ckd_sub`, `ckd_mul`) are a welcome improvement [C23-WIKI] but do not change the fundamental model: the programmer must opt in to checking at every arithmetic operation site, and the default remains unchecked. This is accurate.

#### Corrections Needed

None at the factual level.

#### Additional Context

**Hardened allocators shift but do not eliminate heap exploitation risk.** Modern systems increasingly deploy hardened memory allocators — OpenBSD's `malloc` uses randomized free-list layout; `hardened_malloc` (used in GrapheneOS) implements guard pages and randomized chunk placement; glibc's `MALLOC_CHECK_` and `malloc_perturb` provide development-time hardening. None of the perspectives mention these. Their security implication is significant: they raise the exploitation cost for heap use-after-free and heap buffer overflow substantially, but they do not prevent the memory errors from occurring — they make exploitation less reliable without eliminating the vulnerability class.

**The exploitation landscape has shifted toward heap-based attacks.** ASLR (Address Space Layout Randomization) and stack canaries, now universally deployed, have substantially reduced the exploitability of stack buffer overflows — the historically dominant exploitation class. Current exploitation, including Google Project Zero reports and pwn2own research, is dominated by heap use-after-free and type confusion. The council's security profile discussion does not distinguish between these classes in terms of current exploitability, which matters for assessing C's actual present-day risk profile.

---

### Section 4: Concurrency (Security Implications)

#### Accurate Claims

**Data races are undefined behavior with compiler optimization consequences.** All perspectives correctly identify that C11 specifies data-race-containing programs as having undefined behavior [C-STD-SPEC]. The detractor correctly notes this is strictly worse than Java's approach of defining race semantics for volatile variables. The practitioner correctly notes that ThreadSanitizer catches data races dynamically but cannot be deployed in production due to overhead [ASAN-COMPARISON].

**Dirty COW (CVE-2016-5195) as a canonical security data race.** The vulnerability — a race condition in the Linux kernel's `madvise` code path allowing unprivileged users to write to read-only memory — is correctly described as a nine-year-old bug enabled by C's data-race UB semantics and the absence of any compile-time race detection [DIRTYCOW-WIKI]. Its security impact (local privilege escalation to root) and duration (nine years undetected) are accurate.

**C11 threading standardized 39 years after the language; `<threads.h>` is optional.** The detractor's timeline is accurate: C was created circa 1972; C11 was ratified in 2011. The optional status of `<threads.h>` means portable C code cannot rely on it [C11-WIKI]. The practical consequence — that production C code uses pthreads (non-portable to Windows) or Win32 threads (non-portable to POSIX) rather than the C standard library — is correctly described by the practitioner.

#### Corrections Needed

**The Vafeiadis et al. POPL 2015 finding is underemphasized.** The detractor correctly cites Vafeiadis et al. (POPL 2015) as demonstrating that common compiler optimizations are not provably correct under the C11 memory model [VAFEIADIS-2015]. This is more serious than the other perspectives acknowledge. The finding is that the C11 memory model has the "out-of-thin-air" problem — values can appear in formally valid executions that no actual program could have produced — and that the formal model lacks monotonicity. This means C's concurrency semantics are not only unenforceable (no compile-time detection) and not only dangerous (data races are UB) but also formally underspecified at the model level. Concurrent C code written by expert programmers to specifications they believe correct may be relying on a model that is not formally consistent. No perspective fully integrates this finding into its security assessment.

#### Additional Context

**TOCTOU (Time-of-Check-to-Time-of-Use) is a security-specific concurrency vulnerability class absent from the council's analysis.** TOCTOU vulnerabilities exploit the window between a security check (is this file writable? does this user have permission?) and the use of the checked resource. In C, the idiom of checking then using is the natural programming pattern; C provides no atomic check-and-use primitives for most security operations. Filesystem TOCTOU attacks — checking file ownership with `stat()` before opening with `open()` — have been a documented attack class in Unix since at least 1995. They appear regularly in CVE databases affecting C system utilities and daemons. No council perspective mentions TOCTOU.

**Signal handler safety (async-signal-safety) is a security-relevant concurrency concern.** C's signal handling model requires that signal handlers call only functions specified as async-signal-safe (a restricted subset of standard library functions). Calling non-async-signal-safe functions from a signal handler is undefined behavior that can corrupt program state. This is a documented source of vulnerabilities in network daemons and privileged utilities where signal handlers interact with shared state. CERT C secure coding standard ERR32-C documents this vulnerability class. No council perspective discusses signal safety.

---

### Other Sections (Security-Relevant Issues)

#### Section 6: Ecosystem and Tooling — Supply Chain Security

**The Annex K failure is empirical evidence about ecosystem safety dynamics, not merely governance history.** The failure of Annex K (bounds-checking string functions, C11 Appendix K) to achieve any conforming implementation across thirteen years of standardization has security implications beyond the governance analysis. It is a natural experiment demonstrating that the C ecosystem will collectively reject a safety mechanism if it imposes higher ergonomic cost relative to the unsafe alternative. The safer string functions (`strcpy_s`, `strcat_s`, etc.) required the caller to pass buffer sizes and handle errors — more parameters, more branching. The ecosystem chose the unsafe path because it was easier. This is a finding about security ergonomics that should inform any language design discussion about mandatory safety APIs.

**The apologist's OS-package-manager counter-argument is partially valid but overstated.** The apologist argues that C's reliance on OS package managers for dependency security is preferable to centralized registries that enable npm-style typosquatting attacks. This is a legitimate point for software installed via well-curated distributions (Debian, Red Hat, Alpine). It fails for: (a) vendored source code (git submodules at specific commit hashes, copied source files), which has no package manager tracking at all; (b) the large ecosystem of C projects distributed only as tarballs or via project-specific registries; and (c) distributions with less rigorous security curation. The realist and detractor are correct that the absence of a `cargo audit` or `npm audit` equivalent is a genuine structural gap for C's supply chain security posture.

**No SBOM (Software Bill of Materials) toolchain exists natively for C.** The practitioner briefly mentions SBOM generation for supply chain security [practitioner.md §6], but none of the perspectives discuss the practical difficulty of generating accurate SBOMs for C projects with mixed dependency models (system packages + vendored source + submodules). This is increasingly a compliance requirement (US Executive Order 14028, 2021) and represents a genuine infrastructure gap.

---

## Implications for Language Design

**The secure default principle, demonstrated by failure.** C's design places the unsafe operation as the default: unchecked array access, unchecked integer arithmetic, unchecked string operations. The secure alternative — bounds checking, overflow checking, length-tracked strings — requires either additional code, a safer library, or compiler flags. Annex K's failure demonstrates that when safety is opt-in and adds ergonomic cost, it will be opted out of at scale, regardless of the security stakes. A language designed for security-sensitive deployment contexts should invert this: safe operations are the default; unsafe operations require explicit, visible opt-in. Rust's `unsafe {}` blocks are the reference implementation of this principle.

**Undefined behavior as a compiler optimization mechanism is structurally incompatible with security.** The optimization-by-UB mechanism that enables C's benchmark performance is the same mechanism that enables the STACK class of vulnerabilities (security checks compiled away) [WANG-STACK-2013]. These are not separate design decisions — they are the same decision. A language that grants compilers license to assume unreachable code is provably unreachable grants compilers license to delete code that the programmer intended as a safety check. Language designers should treat UB as a precision instrument to be used surgically, not as a general-purpose optimization handle. The cost of minimizing UB is bounded; the security cost of pervasive UB is unbounded.

**In-band error signaling fails at scale.** C's primary error mechanisms — return codes, `errno`, and NULL sentinels — are in-band: they use the same channel as successful return values. The consequence is that errors can be silently discarded without any syntactic visibility. The Jana et al. (2016) and Tian et al. (2017) studies confirm that even expert security-focused developers systematically miss error handling in C at scale [JANA-EPEX-2016, TIAN-ERRDOC-2017]. Languages that use out-of-band error mechanisms — exceptions, `Result<T, E>` types with syntactic propagation operators, panic-by-default — achieve higher error handling coverage in production codebases. The mechanism must be syntactically visible at the call site to be consistently used.

**Safety APIs will be rejected if they are ergonomically more expensive than unsafe alternatives.** Annex K is the canonical case study: safer string functions required more parameters and produced less convenient error handling than `strcpy`, and the ecosystem rejected them over thirteen years. Any language or library that introduces a safety mechanism must ensure the safety path is at minimum as ergonomically convenient as the unsafe path. Where this cannot be achieved, the unsafe path must be restricted (hidden behind a flag, not in the default namespace, or removed entirely).

**Memory ownership must be a compile-time property, not a documentation convention.** C's memory ownership model is expressed through comments, naming conventions, and institutional knowledge. There is no compiler-enforced ownership relationship between allocations and the code responsible for freeing them. The consequence is that ownership violations look identical to valid code until runtime. Making ownership a type-level concern — so that the compiler can verify ownership transfer, borrow duration, and deallocation responsibility — converts informal safety contracts into enforced invariants. The cost is a steeper type system; the benefit is that a class of vulnerabilities becomes a class of compile errors.

**Language design should treat supply chain security as a first-class concern.** C's distribution model predates the concept of a software supply chain and was never retrofitted to support systematic vulnerability tracking. The consequence is that a CVE in a C library may propagate invisibly through vendored copies and undocumented transitive dependencies. A language whose ecosystem includes a centralized registry with mandatory versioning and automated vulnerability disclosure (Cargo's `cargo audit`, npm's `npm audit`) provides security teams with an auditable dependency graph. This is a design-time choice with lifetime security consequences.

**The normalization argument does not exonerate, but it does calibrate.** C's enormous deployed footprint means that raw CVE counts are not a fair comparison to smaller-footprint languages. The council's realist and apologist perspectives are correct to raise this objection. However, the Android/Rust migration data [GOOGLE-ANDROID-2024] demonstrates that when the same engineering organization replaces C with a memory-safe language for new components in the same codebase, the memory safety CVE proportion drops by approximately two-thirds. The normalization objection is a methodological point about how to compare languages, not an exculpatory finding about C. Language designers should treat this data as confirmation that structural memory safety prevents a measurable fraction of security defects that tooling and developer discipline do not.

---

## References

[MSRC-2019] Miller, Matt. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center / BlueHat IL 2019. https://www.microsoft.com/en-us/msrc/blog/2019/07/a-proactive-approach-to-more-secure-code/

[CVE-DOC-C] "CVE Pattern Summary: C Programming Language." Evidence repository, February 2026. `evidence/cve-data/c.md`

[CWE-TOP25-2024] MITRE. "CWE Top 25 Most Dangerous Software Weaknesses — 2024." https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html

[HEARTBLEED-WIKI] Wikipedia. "Heartbleed." https://en.wikipedia.org/wiki/Heartbleed

[NSA-CISA-2025] NSA/CISA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://www.cisa.gov/news-events/alerts/2025/06/24/new-guidance-released-reducing-memory-related-vulnerabilities

[NSA-MEMSAFE-2022] NSA. "Software Memory Safety." November 2022. https://media.defense.gov/2022/Nov/10/2003112742/-1/-1/0/CSI_SOFTWARE_MEMORY_SAFETY.PDF

[WHITE-HOUSE-2023] The White House. "National Cybersecurity Strategy." February 2023. https://www.whitehouse.gov/wp-content/uploads/2023/03/National-Cybersecurity-Strategy-2023.pdf

[CISA-ROADMAPS-2023] CISA/NSA/FBI et al. "The Case for Memory Safe Roadmaps." December 2023. https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps

[ONCD-2024] White House ONCD. "Back to the Building Blocks: A Path Toward Secure and Measurable Software." February 2024. https://www.whitehouse.gov/wp-content/uploads/2024/02/Final-ONCD-Technical-Report.pdf

[ETERNALBLUE-WIKI] Wikipedia. "EternalBlue." https://en.wikipedia.org/wiki/EternalBlue

[DIRTYCOW-WIKI] Wikipedia. "Dirty COW." https://en.wikipedia.org/wiki/Dirty_COW

[CVE-2021-3156] NVD. "CVE-2021-3156: Sudo Heap Buffer Overflow." https://nvd.nist.gov/vuln/detail/CVE-2021-3156

[HEARTBLEED-CVE] NVD. "CVE-2014-0160: OpenSSL Heartbleed." https://nvd.nist.gov/vuln/detail/CVE-2014-0160

[GOOGLE-ANDROID-2024] Google Android Security Team / Google Chrome Security Team. Multiple blog posts: (a) Android memory safety CVEs 2019–2024 (Vander Stoep and Zhang); (b) Chrome memory safety bug proportion (Adrian Taylor, 2020). *Note: This key requires disaggregation — see corrections in the body of this review.*

[CHROME-MEMSAFE-2020] Taylor, Adrian. "Chromium: 70% of High Severity Security Bugs are Memory Safety Issues." Chrome Security Blog, 2020. https://security.googleblog.com/2021/09/an-update-on-memory-safety-in-chrome.html

[ANDROID-RUST-2024] Vander Stoep, Jeff. "Memory Safe Languages in Android 13." Android Security Blog, 2023/2024. https://security.googleblog.com/2022/12/memory-safe-languages-in-android-13.html

[WANG-STACK-2013] Wang, Xi, Haogang Chen, Alvin Cheung, Zhihao Jia, Nickolai Zeldovich, and M. Frans Kaashoek. "Undefined Behavior: What Happened to My Code?" SOSP 2013 (also: "Towards Optimization-Safe Systems: Analyzing the Impact of Undefined Behavior"). Best Paper Award. https://dl.acm.org/doi/10.1145/2517349.2522728

[VAFEIADIS-2015] Vafeiadis, Viktor, Thibaut Balabonski, Soham Chakraborty, Robin Morisset, and Francesco Zappa Nardelli. "Common Compiler Optimisations are Invalid in the C11 Memory Model and what we can do about it." POPL 2015. https://dl.acm.org/doi/10.1145/2676726.2676995

[JANA-EPEX-2016] Jana, Suman, Yuan Kang, Samuel Roth, and Baishakhi Ray. "Automatically Detecting Error Handling Bugs using Error Specifications." USENIX Security 2016. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/jana

[TIAN-ERRDOC-2017] Tian, Zifei, and Evan Chang. "ErrDoc: Detecting, Explaining, and Fixing Errors in C Programs." FSE 2017. https://dl.acm.org/doi/10.1145/3106237.3106290

[N1967] Seacord, Robert C. et al. "Field Experience With Annex K — Bounds Checking Interfaces." WG14 Document N1967, 2015. http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1967.htm

[CERT-VU162289-2008] CERT. "Vulnerability Note VU#162289: GCC silently discards some wraparound checks." 2008. https://www.kb.cert.org/vuls/id/162289/

[CVE-2009-1897] NVD. "CVE-2009-1897: Linux Kernel TUN driver null pointer dereference." https://nvd.nist.gov/vuln/detail/CVE-2009-1897

[REGEHR-ALIASING-2016] Regehr, John. "A Guide to Undefined Behavior in C and C++." https://blog.regehr.org/archives/1270 (and related posts on strict aliasing)

[C-STD-SPEC] ISO/IEC 9899:2024. International Standard for C (C23). Published October 31, 2024. https://www.iso.org/standard/82075.html

[C11-WIKI] Wikipedia. "C11 (C standard revision)." https://en.wikipedia.org/wiki/C11_(C_standard_revision)

[C23-WIKI] Wikipedia. "C23 (C standard revision)." https://en.wikipedia.org/wiki/C23_(C_standard_revision)

[MISRA-WIKI] Wikipedia. "MISRA C." https://en.wikipedia.org/wiki/MISRA_C

[ASAN-COMPARISON] Red Hat. "Memory Error Checking in C and C++: Comparing Sanitizers and Valgrind." https://developers.redhat.com/blog/2021/05/05/memory-error-checking-in-c-and-c-comparing-sanitizers-and-valgrind

[VALGRIND-ORG] Valgrind project. https://valgrind.org/

[WG14-N2611] Keaton, David. "C23 Charter." WG14 Document N2611, November 9, 2020. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n2611.htm

[LOG4SHELL-WIKI] Wikipedia. "Log4Shell." https://en.wikipedia.org/wiki/Log4Shell
