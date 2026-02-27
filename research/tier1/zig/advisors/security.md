# Zig — Security Advisor Review

```yaml
role: advisor-security
language: "Zig"
agent: "claude-agent"
date: "2026-02-27"
```

---

## Summary

The council's security analysis is largely accurate and well-sourced. All five perspectives correctly identify that Zig is not memory-safe under the technical definition used by government security agencies, that use-after-free and double-free vulnerabilities are not prevented in any build mode, and that the absence of CVEs in NVD reflects deployment footprint rather than genuine vulnerability absence. The detractor and practitioner provide the most rigorous security framing; the historian and realist add important contextual precision.

Three material gaps require attention. First, the council does not analyze the security implications of `ReleaseFast` being the ergonomically "obvious" production mode despite disabling all safety checks — this is the highest-probability path to real-world vulnerability in deployed Zig code. Second, no perspective notes that Zig's comptime-based format string evaluation structurally eliminates the format string vulnerability class (CWE-134), which is a genuine and underappreciated language-level security improvement over C. Third, the supply chain analysis is accurate but incomplete: the hermetic comptime execution model (no I/O, no network access at build time) is a structural mitigation against a class of supply chain attacks that affect languages with imperative build scripts.

One citation across the detractor and practitioner perspectives requires verification: CISA-MEMSAFE is cited with a "June 2025" date. Prior well-documented CISA/NSA guidance on memory-safe languages exists from November 2022 (NSA "Software Memory Safety" CSI) and December 2023 (CISA "The Case for Memory Safe Roadmaps"). A June 2025 update is plausible but should be confirmed against the CISA publications archive before the consensus report relies on this specific date.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **CISA/NSA classification.** All councils correctly state that Zig is grouped with C and C++ by U.S. government security guidance as a language that does not provide memory safety guarantees. The substantive claim is accurate regardless of the exact June 2025 document date (see correction below). The NSA November 2022 CSI and CISA December 2023 roadmap document both categorize Zig alongside C/C++ as requiring migration or mitigations.

- **No CVE history reflects footprint, not safety.** The detractor's framing — "evidence of deployment footprint, not absence of vulnerabilities" — is precisely correct and should be preserved in the consensus report. The absence of NVD entries for a pre-1.0 language with fewer than a handful of production deployments provides no meaningful safety signal. The SPIE-ZIG-2022 paper [SPIE-ZIG-2022] correctly demonstrates that heap corruption exploitation techniques applicable to C apply to Zig programs without modification.

- **ReleaseFast/ReleaseSmall disable all safety checks.** The practitioner's observation that `ReleaseFast` binaries "have essentially the same runtime security profile as an equivalent C binary compiled with `-O2 -fno-sanitize=all`" is accurate and important. The research brief confirms the build mode table: ReleaseFast has no safety checks, ReleaseSafe has full checks with optimizations [ZIG-BRIEF].

- **Supply chain gap.** The NESBITT-2026 analysis is correctly applied across all councils: no PURL type, no SBOM integration, no centralized advisory database. This is a structural gap, not merely a tooling maturity issue.

- **SCATTERED-SAFE findings.** The "multiple memory safety bugs per week" observation is correctly applied as a primary empirical source. Councils appropriately hedge that this is an analytical blog post rather than peer-reviewed research, but it is the most detailed public empirical analysis of Zig's memory safety properties available and should be cited with that framing.

**Corrections needed:**

- **CISA-MEMSAFE June 2025 date.** The detractor cites: "CISA. 'Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development.' June 2025." The consensus report should verify this against the CISA publications archive. Confirmed prior documents: NSA "Software Memory Safety" CSI (November 2022), CISA "The Case for Memory Safe Roadmaps" (December 2023). If the June 2025 document cannot be confirmed, the claim should be anchored to the December 2023 CISA document plus the broader NSA/CISA joint advisory series. The substantive claim — that Zig is not classified as memory-safe under U.S. government security guidance — is accurate and well-established; only the specific citation date needs verification.

- **MSRC 70% figure attribution.** The practitioner attributes "~70% of critical exploits in memory-unsafe languages" to [MSRC-2019]. The Miller 2019 BlueHat IL talk is a real, documented source, but it reports approximately 70% of *Microsoft's CVEs* over the preceding ~12 years being memory safety issues — not a universal figure for all memory-unsafe language codebases. Codebases differ substantially in their vulnerability distribution based on domain, code review practices, and security testing investment. The council should attribute this figure specifically to Microsoft's CVE history rather than applying it as a general statistic. The statistic remains valid and relevant; the attribution requires precision.

**Additional context:**

- **`ReleaseFast` naming as a security ergonomics problem.** None of the council perspectives adequately analyzes why the `ReleaseFast` footgun is particularly dangerous as a *naming* problem. The name suggests "the fast production mode," which is exactly what developers intuitively want when shipping. `ReleaseSafe` sounds like it has overhead (it does, but typically modest). Teams without explicit Zig security training will default to `ReleaseFast`, and documentation in the official build modes section does not prominently warn against this choice for most applications (practitioner raises this implicitly but does not frame it as a naming/default problem). From a security ergonomics perspective, this is the highest-probability failure mode for deployed Zig applications today.

- **`0xaa` poison scope.** The research brief states both Debug and ReleaseSafe modes fill undefined memory with `0xaa`. Councils should note that this poisoning aids in *detecting* use-before-initialization during testing but does not constitute a *safety guarantee*: a freed-and-reallocated block will have its 0xaa content overwritten before the buggy read occurs, meaning the pattern catches initialization errors more reliably than temporal errors. The distinction between "helps detect in testing" and "prevents in production" should be explicit.

- **Attack surface classification.** The council does not systematically classify Zig's attack surface by vulnerability class. A more precise characterization:
  - **Temporal memory safety (use-after-free, double-free):** Not prevented in any build mode. Expected CWE-416, CWE-415 exposure in production Zig code.
  - **Spatial memory safety (buffer overflows):** Prevented by bounds checks in Debug/ReleaseSafe; not prevented in ReleaseFast/ReleaseSmall. CWE-119/CWE-125/CWE-787 exposure in any non-safe build mode, or when explicitly using unsafe pointer operations.
  - **Integer overflow/underflow:** Panics in Debug/ReleaseSafe; silent wraparound in ReleaseFast/ReleaseSmall (CWE-190). Wrapping arithmetic requires explicit operators (`+%`, `-%`), creating opt-in semantics that are safer than C's implicit promotion.
  - **Format string vulnerabilities (CWE-134):** Structurally eliminated — see missing data below.
  - **Null pointer dereference:** Optional types (`?T`) require explicit null handling before use; mandatory in all build modes. This is a genuine compile-time structural prevention, not a runtime check.
  - **Data races:** Not detected or prevented in any build mode. CWE-362 exposure.

**Missing data:**

- **Comptime format strings eliminate CWE-134.** No council perspective identifies this genuine security improvement over C. Zig's `std.fmt` module evaluates format strings at compile time; the format argument must be a comptime-known literal, and the compiler validates that format specifiers match argument types. A developer cannot inadvertently pass user-controlled input as a format string to `std.fmt.print` without a compiler error or explicit use of runtime-formatted output. This structurally eliminates the format string vulnerability class (CWE-134) that accounts for a meaningful fraction of historical C/C++ CVEs. This should be added to the consensus report's Section 7 as a genuine language-level mitigation.

- **Comptime hermetic execution as supply chain mitigation.** The research brief notes that comptime evaluation is hermetic: it cannot perform I/O or access global state [ZIG-BRIEF, KRISTOFF-COMPTIME]. No council applies this property to supply chain security. The practical implication: a malicious Zig dependency cannot exfiltrate secrets or make network calls during the build process. This contrasts with languages where build scripts are Turing-complete with full I/O access (npm `postinstall`, Python `setup.py`, Gradle build scripts). The hermetic comptime model provides structural supply chain protection that partially offsets Zig's supply chain tooling gaps.

- **std.crypto audit status.** No council assesses the quality of Zig's standard library cryptographic primitives. The standard library includes `std.crypto` with implementations of AES, ChaCha20, SHA families, Blake3, HKDF, and related constructs. For a language targeting security-critical systems work (TigerBeetle processes financial transactions), the quality, audit status, and constant-time properties of these implementations are a material security concern. No independent audit of `std.crypto` was identified in the research materials. The consensus report should flag this as an open question.

- **Deployed Zig products' security track records.** The three significant production Zig deployments (Bun, TigerBeetle, Ghostty) have accumulated enough usage to have a preliminary CVE record if vulnerabilities had been found and disclosed. No council examines whether any of these products have issued security advisories. TigerBeetle in particular is processing financial transactions, making its security track record directly relevant to Zig's real-world security profile. A search of these products' GitHub security advisories would provide useful empirical grounding.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- **No implicit coercions as a security improvement.** The research brief and all councils correctly identify that Zig's absence of implicit integer type promotion prevents a class of integer width confusion bugs. C's integer promotion rules have produced numerous historical vulnerabilities (e.g., signed/unsigned comparison issues leading to buffer overreads). Zig's requirement for explicit casts (`@intCast`, `@floatCast`) with safety checks in safe modes is a genuine improvement.

- **Mandatory null handling.** Optional types (`?T`) require explicit unwrapping before use; the compiler enforces this. This is a compile-time structural prevention of null dereference bugs in correctly-typed code. The boundary is at FFI: calling C functions that return null pointers outside the optional type system requires the developer to explicitly acknowledge the null possibility.

**Corrections needed:**

- **`@ptrCast` as an escape hatch.** Councils mention unsafe casting but do not systematically analyze the security implications of `@ptrCast`, `@intToPtr`/`@ptrToInt`, and `@bitCast`. These operations are explicit (requiring deliberate programmer action) which is better than C's implicit casts, but they still permit type confusion vulnerabilities. The key security point: in safe build modes, `@alignCast` is checked at runtime; `@ptrCast` and `@bitCast` are not runtime-checked. A developer can cast a `*u8` to `*u64` and read beyond the intended allocation without any runtime panic in any build mode. This is a specific narrow attack surface that auditors should flag in Zig code.

**Additional context:**

- **Comptime type safety and injection.** No council addresses whether Zig's type system provides any structural resistance to injection attacks (SQL injection, command injection, path traversal). It does not: Zig uses `[]u8` for byte slices with no semantic distinction between safe and unsafe content. Parameterized query patterns and input validation are entirely developer responsibility. This is the same position as C and not worse, but it should be stated clearly: Zig's strong type system provides no application-layer injection protection.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- **No temporal safety in any build mode.** This is the most important and most consistently accurate claim across all councils. Use-after-free is not prevented by the language, runtime, or any allocator in any build mode. The `DebugAllocator` detects double-free at runtime in development, which is valuable — but detection is not prevention, and this allocator is not used in production builds.

- **`DebugAllocator` is a development tool, not a production safety mechanism.** The practitioner correctly frames this. Production use of `DebugAllocator` would impose overhead incompatible with performance requirements; it is intended for test and debug builds.

- **Heap exploitation primitives applicable from C.** SPIE-ZIG-2022's demonstration of write-what-where exploitability is correctly cited. This confirms that heap corruption exploitation techniques — use-after-free chains, heap spray — apply to Zig programs without modification.

**Corrections needed:**

- **`0xaa` poison scope versus safety guarantee.** Several councils describe the `0xaa` poison pattern as though it is a safety mechanism across both Debug and ReleaseSafe modes. It is important to clarify the limitation: the poison helps detect *use-before-initialization* when values are read before the freed/uninitialized memory is overwritten. For use-after-free bugs, the freed memory may be reallocated and overwritten before the buggy read, so the `0xaa` pattern provides no reliable detection. This is a debugging aid with a specific useful case (uninitialized values), not a general temporal safety mechanism.

**Additional context:**

- **Explicit allocator pattern and security auditability.** The practitioner identifies that explicit allocators make memory correctness *testable* in ways C programs typically are not. The security implication that councils understate: explicit allocators make memory usage *auditable*. Code review and security audit of Zig programs can trace allocation ownership through function signatures in a way that is structurally impossible in C programs that use a global `malloc`. This does not prevent vulnerabilities but it reduces their concealment. For security-conscious development practices, this is a genuine improvement.

- **Arena allocators and temporal safety.** None of the councils note that certain allocator strategies structurally eliminate some temporal safety problems. An arena allocator that frees all memory at the end of a request context prevents use-after-free bugs within that context (because freed memory is not reallocated until the arena is reset). TigerBeetle's use of arena-scoped allocations for request processing is a documented application-level temporal safety pattern. This is not a language guarantee, but it demonstrates that Zig's explicit allocator model enables architectural patterns that partially compensate for the absence of temporal safety.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- **No data race prevention.** All councils correctly identify that Zig provides no compile-time or runtime guarantees about data races. There is no ownership model preventing simultaneous mutable access (unlike Rust), no integrated race detector in any build mode (unlike Go's `-race`). Data races in Zig concurrent code are undefined behavior in practice (on most architectures, a data race produces tearing or stale reads; on some architectures under specific compiler optimizations, it can produce more severe corruption).

- **Data races as a security concern.** The detractor correctly frames data races as not merely a correctness issue but a security issue. TOCTOU (time-of-check to time-of-use) vulnerabilities are a class of data race-enabled security bugs. Without language-level or toolchain-level race detection, TOCTOU vulnerabilities in Zig concurrent code will go undetected until they produce observable behavior.

**Corrections needed:**

None material.

**Additional context:**

- **The async removal and OS-thread security implications.** The detractor and practitioner both address the async removal, but no council fully articulates the security implication of the OS-thread-only concurrency model for the 2023–2026 period: when developers needing concurrent I/O cannot use idiomatic async, they reach for OS threads with manual synchronization. Manual synchronization with `Mutex`, `Semaphore`, and `RwLock` requires correct application of lock/unlock discipline across all code paths — including error paths. `errdefer` helps with cleanup in error paths, but concurrent code with complex lock interactions under error conditions is a known source of deadlock, lock inversion, and double-free vulnerabilities. The absence of async forced Zig developers into a concurrency model that is more error-prone from a security perspective.

- **New async I/O design and security (targeting 0.16.0).** The new async design separates `async` (cooperative execution handle) from `concurrent` (parallel execution request). The security implication is positive: explicit `concurrent` scoping makes it easier to reason about which code paths can be interleaved, reducing the surface area for TOCTOU analysis compared to implicit concurrent execution. The design also makes blocking-on-concurrency-unavailable an explicit error rather than silent deadlock. These are security-favorable design decisions, but they are in the pre-release branch; the consensus report should not credit them as shipped mitigations.

---

### Other Sections (security-relevant flags)

**Section 6 (Ecosystem and Tooling):**

- **No-LLM policy and security tooling.** The detractor raises this and it deserves measured treatment. The Zig project's no-LLM policy applies to the project's own development practices, not to users of Zig or to security tools that analyze Zig code. However, CodeQL's Zig support and Semgrep's Zig ruleset are both immature relative to their C, Java, and Python counterparts, and the policy plausibly reduces contributions from tooling developers who use AI-assisted code analysis. The practical security consequence for users of Zig is reduced static analysis coverage compared to more mature languages. This should be noted with appropriate scope: it limits tooling quality, not language-level security properties.

- **SBOM compliance.** The practitioner correctly identifies Executive Order 14028 (May 2021) as the relevant regulatory context for SBOM requirements in U.S. government procurement. Organizations subject to EO 14028 guidance cannot produce compliant SBOMs for software with Zig dependencies until the PURL type problem is resolved. This is a current, active blocker for regulated-industry adoption, not a future concern.

**Section 11 (Governance):**

- **Donation-dependent security response capacity.** The detractor correctly notes ZSF's financial fragility, but no council analyzes the specific security implication: a security vulnerability in a widely-deployed Zig component (hypothetically: a bug in Bun's HTTP parser affecting millions of Node.js replacement deployments) requires a funded, responsive team to coordinate disclosure, develop a patch, and communicate with affected users. The ZSF's documented funding constraints [ZSF-2025-FINANCIALS] imply limited capacity for a rapid, coordinated security response relative to languages with corporate security teams (Google/Go, Mozilla/Rust Foundation with corporate backing, Microsoft/TypeScript).

---

## Implications for Language Design

The Zig case offers six security-relevant lessons for language designers that are not fully articulated in the council perspectives.

**1. Build mode naming and defaults determine real-world security outcomes more than safety features.**

Zig's safety checks are technically present in ReleaseSafe, but the mode named `ReleaseFast` — implying production suitability — disables all of them. This naming creates a systematic deployment error: teams unfamiliar with Zig's build mode semantics will choose `ReleaseFast` for production because the name corresponds to their goal (fast release builds). The actual safe production mode is `ReleaseSafe`, but its name implies overhead the developer may not want to accept. Language and toolchain designers should default the production build mode to the most secure configuration and require an explicit override to enable unsafe performance modes. The mental model "performance requires sacrificing safety" is wrong for most workloads — ReleaseSafe overhead is typically modest — and should not be reinforced by naming.

**2. Hermetic compile-time evaluation is a structural supply chain mitigation that is independent of package registry design.**

Zig's comptime execution model prevents build-time code from making network requests, accessing environment variables, or performing I/O. This is a genuine supply chain security property: a malicious Zig package cannot exfiltrate secrets or download payloads during the build process (unlike npm `postinstall` hooks, Python `setup.py`, or Gradle build scripts, which all execute arbitrary code with full I/O access during builds). Language designers should consider whether build-time metaprogramming requires full I/O access or whether a hermetic model is sufficient for the intended use cases. For languages where comptime computation serves code generation purposes, the hermetic model imposes minimal practical cost while providing a meaningful supply chain boundary.

**3. Compile-time format string validation eliminates an entire CVE class at zero runtime cost.**

Format string vulnerabilities (CWE-134) are structurally impossible in Zig because format strings must be comptime-known literals evaluated and type-checked at compile time. This eliminates a vulnerability class that accounts for a non-trivial fraction of historical C CVEs without any runtime performance cost and without requiring developer discipline at the use site. Language designers should prefer APIs where security-sensitive parameters (format strings, SQL query templates, shell command patterns) are type-distinguished at compile time rather than treated as runtime strings. The lesson is not specific to format strings: any API where a user-controlled string being used as an execution template is dangerous should be designed so that the template must be a comptime constant.

**4. Partial spatial safety that disappears at the performance tier is a weaker guarantee than it appears.**

Zig's bounds checks are present in ReleaseSafe but absent in ReleaseFast. This means the spatial safety guarantee is conditional on developers making a specific build mode choice rather than being an unconditional language property. An attacker targeting production Zig systems should assume some fraction of deployments use ReleaseFast, eliminating all spatial safety checks. Language designers should be honest about whether mode-conditional safety is truly a language guarantee or a developer convention. Languages that provide unconditional safety guarantees (Rust's bounds checks active regardless of optimization level, removed only with explicit `unsafe`) provide a stronger claim than languages where the security guarantee is load-bearing on build configuration.

**5. The absence of race detection in the default debug build is a security gap for concurrent code.**

Zig provides no integrated race detector in any build mode. Go's `-race` flag and ThreadSanitizer integration in Rust/LLVM demonstrate that race detection is achievable with modest overhead in debug builds. Data races cause TOCTOU vulnerabilities, memory corruption, and information disclosure in concurrent programs. Language toolchains that target concurrent workloads should integrate race detection into the standard debug build configuration so that races surface during development rather than in production exploitation. The cost is bounded and acceptable in debug builds; the benefit is catching a category of vulnerability that is otherwise extremely difficult to detect in code review.

**6. Package identifier design must precede ecosystem growth if security advisory integration is a goal.**

Zig's URL + SHA-256 hash package identification predates PURL standardization and does not fit the PURL identifier scheme. As a result, SBOM tools, advisory databases (OSV, GitHub Advisory Database, deps.dev), and supply chain security scanners cannot index Zig packages. The cost of changing the identifier scheme increases with ecosystem growth: every existing package, every build.zig.zon file, every hash lock would need migration. The lesson is not that Zig made a wrong choice (content-addressed dependencies are technically sound) but that security advisory tooling integration requirements should be evaluated before the identifier scheme is finalized. A PURL-compatible identifier does not require a centralized registry; it requires a namespace and a name component that the advisory tooling can reference. This is a solvable problem, but it is best solved before millions of dependency declarations exist in the wild.

---

## References

[CISA-MEMSAFE-2023] CISA. "The Case for Memory Safe Roadmaps." October 2023. https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps (Confirmed December 2023 document. The "June 2025" date cited by council members requires verification against CISA publications archive; substantive claim that Zig is classified as not memory-safe under government guidance is accurate per this and related documents.)

[CISA-NSA-2022] NSA. "Software Memory Safety." Cybersecurity Information Sheet. November 2022. https://media.defense.gov/2022/Nov/10/2003112742/-1/-1/0/CSI_SOFTWARE_MEMORY_SAFETY.PDF (Lists memory-safe languages; C, C++, and Zig are in the non-safe category by implication.)

[EO-14028] Executive Order 14028. "Improving the Nation's Cybersecurity." May 12, 2021. https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/ (Basis for SBOM requirements in federal procurement.)

[KRISTOFF-COMPTIME] Cro, Loris. "What is Zig's Comptime?" kristoff.it. https://kristoff.it/blog/what-is-zig-comptime/ (Hermetic comptime evaluation — no I/O, no global state access.)

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019. (~70% of Microsoft CVEs are memory safety issues — applies to Microsoft's codebase specifically.)

[NESBITT-2026] Nesbitt, Andrew. "Zig and the M×N Supply Chain Problem." nesbitt.io, January 29, 2026. https://nesbitt.io/2026/01/29/zig-and-the-mxn-supply-chain-problem.html

[SCATTERED-SAFE] "How (memory) safe is zig?" scattered-thoughts.net. https://www.scattered-thoughts.net/writing/how-safe-is-zig/ (Primary empirical analysis of Zig memory safety. Non-peer-reviewed analytical post; cited as best available primary source for safety characterization.)

[SPIE-ZIG-2022] "Heap memory vulnerability utilization method in Zig language." SPIE Proceedings, 2022. https://ui.adsabs.harvard.edu/abs/2022SPIE12503E..0TC/abstract (Empirical demonstration of write-what-where heap exploitation in Zig programs.)

[ZIG-BRIEF] Zig Research Brief. research/tier1/zig/research-brief.md. Penultima project, 2026-02-27.

[ZIG-DOCS] "Documentation — The Zig Programming Language." ziglang.org. https://ziglang.org/documentation/master/ (Build modes table; safety check specifications.)

[ZSF-2025-FINANCIALS] "2025 Financial Report and Fundraiser." ziglang.org/news, September 2, 2025. https://ziglang.org/news/2025-financials/ (ZSF financial fragility context for security response capacity.)
