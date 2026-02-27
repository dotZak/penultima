# C++ — Security Advisor Review

```yaml
role: advisor-security
language: "C++"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
```

---

## Summary

C++'s security profile is among the most thoroughly documented failure cases in the history of programming language design — and simultaneously one of the strongest illustrations of why language-level safety properties matter more than equivalent effort spent on tooling mitigations. The empirical record is not ambiguous: 70% of Microsoft's annual CVEs and 70% of serious Chrome security bugs are attributable to memory safety failures in C/C++ codebases [MSRC-2019, GOOGLE-CHROME-SECURITY], figures that have remained stable for over a decade despite enormous investments in sanitizers, fuzzing, static analysis, and smart-pointer idioms. As of January 1, 2026 — the deadline set by NSA/CISA's June 2025 joint guidance — software manufacturers supplying critical infrastructure were expected to have published memory safety roadmaps. That deadline has now passed. The government's position is unambiguous [CISA-MEMORY-SAFE-2025].

The council members engage this record with varying degrees of candor. The apologist correctly describes the tooling investments (ASan, fuzzing, Core Guidelines) and makes a defensible "denominator matters" argument about the extraordinary scrutiny C++ code receives. The practitioner provides an accurate on-the-ground picture of what risk management actually looks like in production. The realist accurately notes that most of the CVE record reflects legacy code patterns, not contemporary idioms. But across all five perspectives, there is an underweighted point that a security reviewer must make explicit: **undefined behavior in C++ is not merely a correctness hazard — it is a security mechanism that compilers actively exploit to remove safety checks.** When a programmer writes a bounds check that is only reachable if pointer arithmetic produces UB, the compiler is legally entitled to assume the UB never occurs and delete the check. This is not a theoretical concern: it has been the root cause of concrete CVEs.

The honest security picture of C++ in 2026 is this: the language is structurally unsafe by design, the tooling ecosystem provides the best available compensating controls short of language-level enforcement, and the compensating controls are insufficient for the threat model faced by externally-exposed software. For high-assurance new development, the security calculus has shifted decisively toward memory-safe languages. For existing large C++ codebases, incremental hardening through smart pointers, sanitizer-in-CI mandates, compiler hardening flags, and eventual language-level profile enforcement represents the realistic path. The C++ community is correct that the situation is better than the raw 70% figure suggests; it is wrong to suggest that "better" means "acceptable."

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- The 70% figures for Microsoft CVEs and Chrome security bugs are correctly cited and traceable to primary sources [MSRC-2019, GOOGLE-CHROME-SECURITY]. The research brief correctly notes these reflect "serious security bugs" (Chrome's characterization) not all bugs.
- NSA/CISA June 2025 guidance is correctly characterized as identifying C/C++ as "not memory-safe by default" with a transition recommendation [CISA-MEMORY-SAFE-2025].
- C++ Core Guidelines Profiles are accurately described as "not yet available, except for experimental and partial versions" (Stroustrup's own characterization in CACM 2025 [STROUSTRUP-CACM-2025]).
- Smart pointers eliminating most single-ownership memory management errors (use-after-free, double-free) while not preventing buffer overflows: accurate.
- The practitioner's risk management posture — smart pointers, ASan in CI, static analysis as a gate, hardening compiler flags in production — correctly describes best-practice mitigation layers that mature teams use.
- The supply chain observation (no centralized security advisory database analogous to `cargo audit` or `npm audit`) is accurate.
- KEV (Known Exploited Vulnerability) data from VulnCheck: memory safety KEVs reached approximately 200 in 2024, the highest recorded value, with 18 buffer-overflow-related and 5 use-after-free entries in the actively exploited catalog [RUNSAFE-KEVS, CODE-INTELLIGENCE-2025]. This data validates that the 70% figure reflects actively exploited vulnerabilities, not just theoretical weaknesses.

**Corrections needed:**

- The apologist argues: "The question is not whether automatic memory management reduces bugs — it does. The question is what you pay for that reduction." While this is a legitimate design trade-off framing, it sidesteps an important normalization question. The "denominator matters" argument — that C++ is used for the most complex software and therefore produces more CVEs — is commonly invoked but should not be used to dismiss the vulnerability density question. Microsoft's MSRC has done internal normalization comparing their C/C++ and C# codebases and still finds memory safety issues dominate in their native-code components [MSRC-2019]. The "denominator" argument applies to raw counts, not to the fundamental insight that memory-unsafe languages structurally enable exploitation classes that memory-safe languages structurally prevent.

- The claim (apologist, realist) that "modern C++ written with modern idioms has lower vulnerability density than legacy code" is plausible and likely correct, but should be flagged as unverified at scale. There are no peer-reviewed, published studies measuring CVE density in modern-idiom C++ (C++17+ with exclusive smart pointer use, Core Guidelines compliance) versus legacy C++ at equivalent code complexity. This is an evidence gap the council should note explicitly rather than treating as established.

- The CISA deadline context is important and is not adequately flagged by any council member: as of February 2026, the NSA/CISA deadline of January 1, 2026 for critical infrastructure vendors to publish memory safety roadmaps has passed [CISA-MEMORY-SAFE-2025]. The framing in council documents as a future obligation is outdated.

- The council underweights **undefined behavior as a security hazard through optimizer interaction**. This is a C++ (and C) specific mechanism that is distinct from merely "writing buggy code." When UB occurs in a code path that a programmer intended as a safety check, the optimizer is permitted — and often does — delete the check. This has produced concrete CVEs, including cases where signed integer overflow in a bounds check (signed overflow being UB in C++) allowed the compiler to remove the entire check [WANG-UB-2012]. No council member explicitly discusses this mechanism.

- The research brief states `std::span` "provides bounds-checked view over contiguous data; does not enforce bounds by default in release builds." This is accurate but needs clarification. `std::span::operator[]` does not perform bounds checking in standard builds. Debug-mode or hardened-mode bounds checking is available via implementation-specific options (libc++ `_LIBCPP_HARDENING_MODE`, GCC libstdc++ `_GLIBCXX_ASSERTIONS`), but these are not the default, and no council member adequately distinguishes between what `std::span` guarantees versus what it can provide when explicitly configured.

**Additional context:**

- **Virtual dispatch hardening.** The research brief mentions "virtual dispatch abuse" and type confusion via unsafe downcasting as C++-specific vulnerability patterns beyond C. What is missing from all council documents is that Clang's `-fsanitize=cfi-vcall` (Control Flow Integrity for virtual calls) and `-fwhole-program-vtables` flags specifically mitigate vtable hijacking attacks. These are production-viable mitigations (lower overhead than sanitizers) that Google deploys in Chrome and that are absent from any council member's security hardening discussion. The practitioner's hardening recommendations should include `-fsanitize=cfi` as table stakes for security-sensitive C++ services.

- **MiraclePtr / MTE (Memory Tagging Extension).** Chrome's MiraclePtr project replaces raw pointers in the renderer process with a quarantine-based scheme that detects dangling pointer accesses with near-zero overhead. ARM's Memory Tagging Extension (available on ARMv8.5-A hardware) enables hardware-level use-after-free detection at ~1% runtime overhead. These represent state-of-the-art C++ memory safety mitigations that are not covered in any council document and represent the frontier of what is achievable without changing the language [CHROMIUM-MIRACLEPTR, GOOGLE-MTE-2022].

- **Hardened allocators.** PartitionAlloc (Chrome), jemalloc (Firefox/Meta), and tcmalloc (Google) are security-hardened memory allocators that provide exploit mitigation properties beyond the system allocator (heap layout randomization, guard pages, canaries). These are invisible to language-level analysis but materially affect the exploitability of C++ memory bugs in well-engineered systems. The council's discussion of security tooling is incomplete without this layer.

- **Integer overflow: signed versus unsigned asymmetry.** The C++ distinction between signed integer overflow (undefined behavior, enabling optimizer exploitation) and unsigned integer overflow (defined modular arithmetic) creates a subtle security trap. A programmer who writes a bounds check using signed arithmetic may produce UB when the check is reachable via large inputs, allowing the optimizer to eliminate it. This is documented as a recurring pattern in real CVEs [WANG-UB-2012].

**Missing data:**

- No C++-specific CVE frequency data exists disaggregated from the combined C/C++ figures. The C CVE data file (`evidence/cve-data/c.md`) applies to both languages with minor C++-specific additions. Creating a proper `cpp.md` evidence file would require querying NVD with C++-specific tags and would likely show similar distributions with the addition of vtable/type confusion and exception-safety categories.

- There is no rigorous measurement of how C++ vulnerability density has changed from pre-C++11 to post-C++17 idioms. This is the most important missing empirical question for assessing whether modern C++ represents a genuinely improved security profile or merely the same structural risks with better documentation.

- The OWASP Top 10 (primarily web-focused) does not address C++'s specific vulnerability classes. More relevant would be the embedded and systems security community's analogous guidance, which is fragmented across automotive (MISRA C++), avionics (DO-178C), and industrial (IEC 62443) standards.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- `reinterpret_cast` being "intentional, named, and auditable" is correct and has genuine security value over implicit C-style type punning. A code search for `reinterpret_cast` identifies all type-system bypasses in a C++ codebase, which is not possible in C where dangerous casts can be invisible.
- Concepts (C++20) improving error messages for template violations is accurate and not directly a security issue, though precise type constraints do catch a category of type mismatch bugs earlier in development.
- The council correctly identifies `void*` and C-style casts as legacy hazards.

**Corrections needed:**

- The apologist's characterization of escape hatches as "intentional, named, and auditable" is accurate for `reinterpret_cast` but misleading for **C-style casts** (`(int*)p`), which remain valid in C++ for backward compatibility and are not as visually distinct. C-style casts in C++ can silently perform `const_cast`, `static_cast`, or `reinterpret_cast` depending on context, with the actual operation determined by the compiler. This is a type-safety hazard that `grep reinterpret_cast` does not catch. All council members underweight this specific hazard.

- The implicit conversion between signed and unsigned integers deserves security-specific treatment. The C++ type system inherits C's implicit integer conversion rules. `size_t` (unsigned) and `int` (signed) comparisons involve implicit conversions where a negative `int` becomes a very large `size_t`, classically enabling `malloc(n * sizeof(struct))` where `n * sizeof(struct)` overflows to a small number, allocating an undersized buffer. This is CWE-190 and it is a type-system-level hazard, not purely a programmer discipline issue.

**Additional context:**

- C++17's `std::variant` is correctly described as a type-safe discriminated union, but an important security property is often missed: it prevents the type confusion attacks possible with C-style union access (where a union member of one type can be read as another type without checking a discriminant). The council mentions `std::variant` as a type system feature but does not make this security connection explicit.

- The `nullptr_t` type and `nullptr` literal (C++11) are security improvements over C's `NULL` macro (often defined as `0`, making it indistinguishable from integer zero in overload resolution). `nullptr` cannot be implicitly converted to an integer type, preventing a class of subtle null pointer check bypass.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- RAII provides deterministic resource management that is genuinely superior to GC for file handles, mutexes, and network connections — this is correct and relevant to security (unclosed file handles and unreleased locks create security hazards that GC does not address promptly).
- `unique_ptr` eliminates most single-ownership use-after-free and double-free patterns for application code: accurate.
- The C++11 formal memory model was a security improvement because it eliminated the legal-to-exploit undefined behavior of pre-C++11 multithreaded code: accurate.
- RAII alone is insufficient without enforcement — nothing prevents a programmer from using raw `new`/`delete`: correctly acknowledged by the apologist and practitioner.

**Corrections needed:**

- `shared_ptr` is sometimes presented as a comprehensive solution to use-after-free. It is not. Reference cycles produce memory retention that prevents deallocation, and `weak_ptr` misuse can create dangling weak pointers. More critically, `shared_ptr` cannot eliminate use-after-free in multi-threaded contexts where the shared object's state is mutated concurrently — the `shared_ptr` ensures the object is not destroyed, but does not prevent data races on its contents. The council's treatment of smart pointers as near-complete solutions to memory safety overstates their scope.

- The historian correctly notes the 13-year threading undefined behavior problem but does not fully articulate its security implications. Pre-C++11, a compiler was legally allowed to transform any threaded C++ program into one with arbitrary behavior. In practice, this enabled a class of time-of-check/time-of-use (TOCTOU) races that could be exploited through thread scheduling manipulation. C++11's formal memory model did not eliminate data races — it defined what they mean (UB) — but the clarity enabled ThreadSanitizer to detect them.

- The GC experiment abandonment (C++11 hooks, no implementations) has an underappreciated security consequence: C++ will never have automatic memory management as a first-class language feature. The community has permanently committed to RAII + smart pointers + sanitizers as the memory safety strategy, which means the security properties of C++ are bounded by what this combination can guarantee — which is "substantially better than raw C" but "categorically weaker than full memory safety."

**Additional context:**

- **`delete` vs `delete[]` mismatch.** This is a C++-specific memory safety hazard not present in C (which only has `free()`). Calling `delete` on memory allocated with `new[]`, or `delete[]` on memory allocated with `new`, is undefined behavior that can produce exploitable heap corruption. Modern compilers warn about obvious cases, but the pattern can be obscured through template code or inheritance. This is one of several ways that C++'s added abstraction mechanisms create vulnerability classes beyond what C itself has.

- **RAII and exception safety.** The historian touches on this but its security relevance deserves explicit treatment: if a destructor throws an exception during stack unwinding from another exception, `std::terminate()` is called — but more relevantly, if a destructor throws and the exception is swallowed, cleanup silently fails. RAII is only a reliable security mechanism if destructors are `noexcept` and reliably release resources. In legacy codebases, this is not always enforced.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- Lack of language-level data race prevention is a genuine gap; Rust's borrow checker prevents data races at compile time while C++ relies on runtime detection (TSan) or programmer discipline: correctly assessed by apologist and realist.
- TSan cannot run simultaneously with ASan, and TSan's 5–15x overhead makes it unsuitable for production: correctly noted by practitioner, with the correct implication that data races reaching tested codepaths but not TSan-monitored codepaths will reach production.
- The `memory_order_relaxed` footgun is real: incorrect use of non-sequentially-consistent atomics has historically produced security-relevant race conditions.

**Corrections needed:**

- The council largely treats data races as correctness issues. Their security implications need stronger emphasis. Data races in security-sensitive code paths — authentication checks, permission validation, bounds-checking logic — can produce exploitable race conditions (TOCTOU patterns). A classic example: checking `if (buffer.size() >= required_size)` while another thread modifies `buffer.size()` under a data race. The C++ memory model specifies that this is UB, meaning the optimizer may produce code that reads `buffer.size()` once and caches it, or reads it multiple times and sees different values. Either way, the safety check can be bypassed.

- The apologist describes the six-level memory ordering system as "correctly complex for what it models." This is defensible from a performance standpoint, but from a security standpoint, the complexity is a hazard: expert concurrency programmers have published incorrect lock-free data structures using C++11 atomics. A language feature that even experts misuse has amplified security risk in codebases written by less experienced developers.

**Additional context:**

- **Signal handlers and async-signal safety.** C++ signal handlers have strict constraints on what operations are async-signal-safe. Calling `malloc`, throwing exceptions, or accessing non-`volatile sig_atomic_t` variables from a signal handler is UB. In practice, signal handlers in C++ code frequently violate these constraints, and this is a source of exploitable races in security-sensitive code. No council member covers this.

- **Coroutine cancellation and resource safety.** C++20 coroutines suspended mid-execution hold resources (locked mutexes, open file handles, partially modified state). If a coroutine is destroyed while suspended, its destructors run, but the ordering and safety of this cleanup depends on the coroutine frame's structure in ways that are non-obvious and not always correct. This is a new category of resource safety hazard introduced in C++20 with limited coverage in security literature.

---

### Other Sections (security-relevant issues)

**Section 6: Ecosystem — Supply Chain**

The supply chain security situation for C++ is materially worse than the council documents convey, and warrants direct comparison with more secure package ecosystems:

- **No equivalent to `cargo audit`.** Rust's advisory database (RustSec) provides per-crate security advisories that `cargo audit` integrates directly into CI. Python's `pip-audit` and npm's `npm audit` provide similar functionality. C++ has no equivalent for vcpkg or Conan. When a C++ library dependency has a CVE, there is no automated mechanism to alert dependent projects [SUPPLY-CHAIN-CPP].

- **Bundled source and header-only libraries.** A significant portion of C++ dependencies are managed by copying source files into a project's repository. This pattern, inherited from before package managers existed, means security patches in upstream libraries do not automatically propagate to downstream users. The project must notice the CVE, find its bundled copy, and update it manually.

- **Build script trust.** CMake's `execute_process()` and `add_custom_command()` allow arbitrary code execution during configuration. vcpkg portfiles run during installation. Unlike Cargo's `build.rs` scrutiny or npm's attempts to limit install scripts, there is no sandboxing or privilege separation for C++ build scripts.

- **No SBOM tooling equivalent.** Software Bill of Materials generation for C++ projects is significantly more difficult than for languages with centralized package management, because C++ dependency graphs often include bundled code with no metadata. This matters for government contractors subject to executive order requirements on SBOM generation.

---

## Implications for Language Design

The security history of C++ generates the following high-priority lessons for language designers. These are structural observations, not implementation details.

**1. Unsafe-by-default is not neutral — it is a security decision that compounds over decades.**

C++'s choice to make memory-unsafe operations (raw pointer arithmetic, unchecked array access, `reinterpret_cast`) the default, with safe alternatives (smart pointers, `std::span`, named casts) as opt-in, means that every new developer, every tutorial, every piece of legacy code, and every API exposed from C leans toward the unsafe path. Rust's inversion — safe by default, unsafe operations requiring explicit `unsafe` blocks — is not a cosmetic difference. It changes the baseline distribution of code. The C++ experience over four decades demonstrates that "experts can write safe code if they know the rules" does not scale: the number of expert C++ developers has never been proportional to the volume of C++ code being written.

**2. Language-level undefined behavior, when used as an optimization mechanism, creates adversarially exploitable security properties.**

C++ compilers are permitted to delete branches of code that are only reachable through undefined behavior. Since many security checks involve conditions that would only be reached if a preceding computation produced UB (e.g., a signed integer overflow that a programmer expected to saturate), the compiler can and does eliminate these checks. This is not a compiler bug; it is correct behavior under the specification. The lesson: undefined behavior defined to enable compiler optimization is indistinguishable from undefined behavior that attackers exploit. A language serious about security should either eliminate the UB or, at minimum, provide a conformance mode that converts UB to defined (if slower) behavior without requiring sanitizer overhead in production [WANG-UB-2012].

**3. Post-hoc safety tooling (sanitizers, static analysis) cannot substitute for language-level enforcement, but it can substantially reduce vulnerability density when mandated.**

The 70% figure is stable over a decade despite enormous tooling investment. This is strong evidence that tooling alone cannot close the gap. However, the comparison should be: "C++ codebases with comprehensive sanitizer and fuzzing infrastructure versus C++ codebases without." Projects like Chrome and OpenSSL, with large bug bounties, continuous fuzzing, and sanitizer-in-CI mandates, have materially lower vulnerability densities than unmanaged C++ codebases. The lesson for language designers: do not wait for the community to organically adopt safety tooling — make the safest tooling the default, lowest-friction path. Languages that ship with `cargo audit`, `go vet`, or mandatory bounds-check modes as first-class default behaviors benefit from higher baseline safety without requiring every team to configure a security pipeline.

**4. The `unsafe` escape hatch model (explicit opt-out of safety) is measurably better than the C++ model (opt-in safety), but soundness of unsafe code remains a hard problem.**

Rust's `unsafe` block model creates an auditable boundary that allows code review and security auditing to focus effort. The Rust Foundation's 2024 survey finding that 34.35% of crates transitively depend on `unsafe` code [RUSTFOUNDATION-UNSAFE-WILD] shows that unsafe code remains pervasive even in a language designed to minimize it. This is not a failure of the model; it reflects the reality that interfacing with C code, hardware, and performance-sensitive operations requires unsafe operations. The lesson: explicit opt-out of safety properties is significantly better than implicit opt-out, even when a substantial fraction of code ends up behind the unsafe boundary.

**5. A language's exploit mitigation story must extend beyond the language itself to the toolchain, allocator, and OS integration.**

Chrome's most effective C++ memory safety improvements — MiraclePtr, PartitionAlloc, ARM MTE integration — are not language features. They are allocator and pointer-tagging engineering that happens below the language level. Windows' Control Flow Guard (CFG) and Intel's CET (Control-flow Enforcement Technology with shadow stack) require compiler cooperation but are fundamentally OS/hardware features. Language designers should treat this stack as part of the language's security story: the language should not impede the toolchain's ability to implement these mitigations, and ideally should expose first-class annotations or guarantees that enable them. C++'s explicit pointer semantics and ABI make it compatible with CFI and MTE in ways that garbage-collected runtimes are not. This is a genuine, underappreciated security asset of the language model.

**6. Security ergonomics determine security outcomes at scale more than security expressiveness.**

C++ can express memory-safe patterns — RAII, smart pointers, bounds-checked containers — with full coverage of the safety properties needed. What it cannot do is make these patterns the path of least resistance for an average developer. When the standard library exposes `std::vector::operator[]` (no bounds checking, UB on out-of-bounds access) alongside `std::vector::at()` (bounds-checked, throws on out-of-bounds), and the unchecked version is shorter, easier to type, and faster, most code will use the unchecked version. The lesson: security must be the default, not the opt-in. A language where safe and unsafe variants both exist but the safe variant requires extra characters or remembering a different API name will consistently produce unsafe code in practice.

---

## References

[MSRC-2019] Miller, M. "A Proactive Approach to More Secure Code." Microsoft Security Response Center, 2019. https://www.microsoft.com/en-us/msrc/blog/2019/07/a-proactive-approach-to-more-secure-code/

[GOOGLE-CHROME-SECURITY] Google Chrome Security Team. "Memory Safety." https://www.chromium.org/Home/chromium-security/memory-safety/

[CISA-MEMORY-SAFE-2025] CISA/NSA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://www.cisa.gov/news-events/alerts/2025/06/24/new-guidance-released-reducing-memory-related-vulnerabilities

[STROUSTRUP-CACM-2025] Stroustrup, B. "21st Century C++." *Communications of the ACM*, February 2025. https://cacm.acm.org/blogcacm/21st-century-c/

[STROUSTRUP-DNE-1994] Stroustrup, B. *The Design and Evolution of C++*. Addison-Wesley, 1994.

[MITRE-CWE-TOP25-2024] "CWE Top 25 Most Dangerous Software Weaknesses 2024." MITRE. https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html

[RUNSAFE-KEVS] VulnCheck / RunSafe Security. Memory safety KEV data, 2024. https://runsafesecurity.com/blog/memory-safety-vulnerabilities-rising/

[CODE-INTELLIGENCE-2025] "Top Six Most Dangerous Vulnerabilities in C and C++." Code Intelligence, 2025. https://www.code-intelligence.com/blog/most-dangerous-vulnerabilities-cwes-in-c-2025

[CVE-C-DATA] "CVE Pattern Summary: C Programming Language." evidence/cve-data/c.md, February 2026.

[RESEARCH-BRIEF] "C++ — Research Brief." research/tier1/cpp/research-brief.md, February 2026.

[WANG-UB-2012] Wang, X. et al. "Undefined Behavior: What Happened to My Code?" *APSYS 2012*. https://dl.acm.org/doi/10.1145/2349896.2349905 (Documented cases where C/C++ compiler optimizations removed security-relevant checks due to UB assumptions.)

[CHROMIUM-MIRACLEPTR] "MiraclePtr: Protecting against Use-After-Free bugs in Chrome." Chromium Blog. https://security.googleblog.com/2022/09/use-after-freedom-miracleptr.html

[GOOGLE-MTE-2022] Google Project Zero / Android. "ARM Memory Tagging Extension and How It Improves C/C++ Memory Safety." https://security.googleblog.com/2019/08/adopting-arm-memory-tagging-extension.html

[RUSTFOUNDATION-UNSAFE-WILD] "Unsafe Rust in the Wild: Notes on the Current State of Unsafe Rust." Rust Foundation, 2024. https://rustfoundation.org/media/unsafe-rust-in-the-wild-notes-on-the-current-state-of-unsafe-rust/

[SUPPLY-CHAIN-CPP] Lacking a canonical per-source publication; the absence of C++-specific supply-chain security tooling is documented by comparison with `cargo audit` (https://crates.io/crates/cargo-audit) and `pip-audit` (https://pypi.org/project/pip-audit/), neither of which has a vcpkg/Conan equivalent as of February 2026.

[HERBSUTTER-SAFETY-2024] Sutter, H. "C++ Safety, in Context." March 2024. https://herbsutter.com/2024/03/11/safety-in-context/

[OWASP-TOP10] OWASP Top Ten 2021. https://owasp.org/Top10/ (Reference for injection and other vulnerability classes not primarily attributed to C++ language design.)
