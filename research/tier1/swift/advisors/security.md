# Swift — Security Advisor Review

```yaml
role: advisor-security
language: "Swift"
agent: "claude-sonnet-4-6"
date: "2026-02-28"
schema_version: "1.1"
```

---

## Summary

Swift's security profile is better than the council's treatment suggests in some respects and worse in others. The consensus view — that ARC eliminates C/C++-class memory vulnerabilities and that the CVE count is therefore low — is directionally correct but analytically incomplete. The "4–6 CVEs" figure for Apple Swift cited uniformly across all five perspectives undercounts the total ecosystem attack surface and obscures the methodological problem: CVEs affecting swift-nio-http2, swift-corelibs-foundation, and other Swift-ecosystem components are not filed against "Apple Swift" in NVD but against their specific products. A more accurate characterization distinguishes between the language-and-compiler attack surface (genuinely small), the standard library attack surface (small but not zero), and the server-side ecosystem attack surface (active, with multiple high-severity CVEs since 2022).

The council's treatment of SE-0458 (`@unsafe` annotation, `-strict-memory-safety` flag) is accurate: it arrived in Swift 6.2 (September 2025), eleven years after Swift's 2014 debut. What the council underweights is how this absence shaped security auditing practice in the intervening decade. A security audit of a pre-6.2 Swift codebase using `UnsafePointer`, `withUnsafeBytes`, or `Unmanaged` required complete manual line-by-line inspection — the compiler offered no assistance identifying the unsafe surface boundary. This is qualitatively different from Rust's `unsafe` blocks, which have been syntactically mandatory and compiler-enforced since Rust 1.0 (2015).

The council largely ignores three security-relevant topics that deserve explicit treatment: (1) Swift's integer overflow trap behavior and its security implications relative to C; (2) the security implications of actor reentrancy, which compile-time data race safety does not eliminate; and (3) the quality and availability of cryptographic primitives, which is the primary security concern for most production Swift applications. These omissions are addressed in the section-by-section review below.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **ARC eliminates dominant C/C++ vulnerability classes.** All five perspectives correctly identify that ARC-based memory management prevents buffer overflows (checked collections trap rather than overflowing), use-after-free (object lives until last strong reference drops), and uninitialized reads in ARC-managed code. The NSA/CISA 2022 "Software Memory Safety" guidance listing Swift among memory-safe languages [DOD-MEMORY-SAFETY] is accurate and correctly cited.

- **Server-side CVE pattern.** CVE-2022-24667 (swift-nio-http2 HPACK parsing DoS), CVE-2022-0618 (HTTP/2 HEADERS padding DoS), and CVE-2023-44487 (HTTP/2 Rapid Reset) [CVE-2022-24667, CVE-2022-0618, SWIFT-FORUMS-RAPID-RESET] are correctly identified as the active vulnerability surface. These are protocol parsing and state machine correctness bugs, not memory safety failures, and they illustrate that memory-safe languages are fully exposed to protocol-level vulnerabilities.

- **SE-0458 late arrival.** The realist, detractor, and historian are correct that eleven years elapsed between Swift's debut and the introduction of auditable unsafe surface marking. This is a genuine gap relative to Rust (which has had `unsafe` blocks since 1.0) and is accurately characterized as such.

- **Supply chain concentration.** The detractor's observation that Vapor and swift-nio represent a concentrated dependency for server-side Swift is accurate. Three swift-nio-http2 CVEs in a two-year period is a notable vulnerability density for a library that is a transitive dependency of virtually all server-side Swift applications.

**Corrections needed:**

- **The "4–6 CVEs" figure is misleading as stated.** The apologist's claim that "the CVE count for Apple Swift (the compiler and standard library) is approximately 4–6 total CVEs [SWIFT-CVE-DETAILS]" — and the implication that this is "remarkably small" compared to Java or PHP — involves a category error. The CVEDetails query for "Apple Swift" as a product captures vulnerabilities attributed specifically to the Swift compiler and standard library by Apple. It does not capture:
  - CVEs attributed to swift-nio-http2 (a separate GitHub Advisory / GHSA record)
  - CVEs attributed to swift-corelibs-foundation
  - CVEs in the Xcode toolchain that involve Swift-related components
  - Historical CVEs filed before advisory database integration matured

  The correct framing is: the *compiler and standard library* have a small CVE count (~4–6), while the *ecosystem* (swift-nio-http2, corelibs-foundation) has a more active vulnerability surface. The comparison to Java's "hundreds of CVEs in its standard library" [APOLOGIST] is comparing different scope definitions. Java's standard library is far larger in scope and deployment than Swift's.

- **Retain cycle as DoS vector deserves precise scoping.** The detractor and practitioner correctly identify retain cycles as a denial-of-service vector in server-side contexts. The precision matters: a retain cycle in a request handler that accumulates memory with each request can exhaust heap under adversarial input patterns that trigger the cyclic allocation path. This is not theoretical — it is the class of bug that memory exhaustion fuzzing finds. The apologist's characterization of this as "a real but manageable tradeoff" is not wrong, but it underweights the asymmetry: in iOS apps, retain cycles manifest as user-visible sluggishness and crash under memory pressure; in server-side Swift, they manifest as exploitable degradation under sustained traffic.

- **Platform security and language security are conflated in places.** The practitioner is correct that iOS/macOS Swift apps benefit enormously from platform sandboxing, App Store review, and code signing. But these controls are not language properties — they are deployment environment properties. The practitioner correctly distinguishes these; the apologist's framing occasionally conflates them when describing Swift's overall security posture.

**Additional context:**

- **Integer overflow behavior is a meaningful but uncited security property.** Swift's standard integer arithmetic operators trap on overflow by default (producing a runtime crash) rather than wrapping silently or producing undefined behavior [SWIFT-LANG-INTS]. This is a security-relevant design decision. In C, signed integer overflow is undefined behavior and has been exploited as an attack vector [CWE-190]. In Swift, the equivalent code produces a runtime trap rather than undefined behavior — a deterministic failure mode rather than exploitable undefined state. Swift provides explicit wrapping operators (`&+`, `&-`, `&*`) for cases where overflow semantics are intended. No council perspective mentions this property.

- **`nonisolated(unsafe)` is a new unsafe escape hatch that isn't discussed.** Swift 6 introduced `nonisolated(unsafe)` (SE-0376) as a way to mark stored properties as exempted from actor isolation checking [SE-0376]. This is distinct from the `Unsafe*` pointer APIs: it allows concurrent access to reference-counted objects without actor enforcement. It was introduced to reduce migration friction for Swift 6 adoption, but it creates a new category of unsafe surface that does not match the `Unsafe*` naming convention and may not be caught even by SE-0458's `-strict-memory-safety` flag. Council perspectives do not address this.

- **Cryptographic library quality is entirely absent from all five council perspectives.** This is a significant gap for a language review. The security profile of a language for production use depends heavily on the quality and availability of cryptographic primitives:
  - **Apple platforms**: CryptoKit (introduced iOS 13 / macOS 10.15, 2019) provides modern cryptographic primitives (AES-GCM, ChaChaPoly, P-256/P-384/P-521, Curve25519, HPKE, SHA-2/SHA-3) backed by corecrypto, Apple's internally audited cryptographic library [APPLE-CRYPTOKIT-DOCS]. CryptoKit does not expose deprecated algorithms (DES, 3DES, MD5, SHA-1) in its primary API, making it difficult to accidentally select weak primitives.
  - **Server-side (Linux/Windows)**: swift-crypto provides the same CryptoKit API backed by BoringSSL (Google's fork of OpenSSL) [SWIFT-CRYPTO]. BoringSSL is the same cryptographic backend used in Chrome and Android. This is a credible choice.
  - **Legacy risk**: CommonCrypto, the older C-API-based framework, remains available in Swift and is heavily used in code predating CryptoKit. CommonCrypto exposes deprecated algorithms including DES and 3DES. Legacy code that uses CommonCrypto directly may use weak primitives.
  - **Net assessment**: Swift's cryptographic story for new code is good — CryptoKit's API design makes weak primitive selection difficult. Legacy code using CommonCrypto is at risk of deprecated algorithm use. No council perspective addresses any of this.

**Missing data:**

- No council perspective queries NVD or GHSA directly for swift-ecosystem CVEs beyond the three known swift-nio-http2 entries. The JSONDecoder DoS and Ubuntu privilege escalation CVEs are cited by the research brief and practitioner but without CVSS scores or NVD identifiers.
- No council perspective addresses CVE exposure at the Xcode toolchain level. Xcode vulnerabilities that involve Swift components (compiler RCE via malicious Swift source, for example) would not appear in "Apple Swift" product queries.
- The supply chain discussion lacks concrete data on SPM package signing adoption rates post-2025. "Apple added signed packages" [COMMITSTUDIO-SPM-2025] does not tell us what fraction of packages are signed or what the ecosystem adoption rate is. For npm, signing adoption was slow after introduction.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- **Optionals as null safety.** All perspectives correctly identify `T?` optionals with compiler-enforced unwrapping as a meaningful mechanism for preventing null pointer dereferences. The compiler's requirement to handle the nil case before accessing the value — via `if let`, `guard let`, `??`, or explicit `!` — is a genuine improvement over languages where null pointer dereferences are latent runtime failures.

- **`!` (force unwrap) as a risky escape hatch.** The practitioner's characterization of force unwrap as "the most common language-level footgun for iOS apps in terms of crash rate" is accurate. Crash analysis data from production applications consistently surfaces nil force-unwrap as a prominent crash category.

**Corrections needed:**

- **The type system provides no protection against injection vulnerabilities.** No council perspective explicitly states this, but it is a meaningful gap in the overall security assessment. Swift's static type system — however strong — does not perform taint tracking. SQL injection, command injection, path traversal, and server-side template injection are fully possible in Swift, with no language-level mitigation. This is not a critique specific to Swift — Java, C#, and Go share the same limitation — but it is important to state explicitly when characterizing Swift's security profile. The security relevant question is: does the type system help prevent these vulnerabilities by convention? The answer is partially yes through value type semantics (strings passed as parameters to parameterized queries are just strings, not tainted strings), but this is weak mitigation compared to a language with first-class taint tracking.

- **`Codable` deserialization safety.** The `Codable` protocol provides structural type checking during deserialization: the decoded value must conform to the expected type or decoding fails. This is safer than reflection-based deserialization (e.g., Java's `ObjectInputStream`) because it doesn't deserialize arbitrary class graphs. The JSONDecoder DoS bug [SWIFT-CVE-DETAILS] demonstrates that even this mechanism has been vulnerable; the fix required additional input size validation at the library level. The implication for language designers: structural deserialization (type-driven rather than reflection-driven) reduces the attack surface compared to reflection-based approaches, but it does not eliminate it.

**Additional context:**

- **`@escaping` closures and closure capture security.** In Swift, closures that escape their creation scope must be explicitly annotated `@escaping`, which provides a syntactic signal that the closure will outlive its immediate context. This is relevant to retain cycle detection: many retain cycles in Swift involve closures that capture `self` strongly and are stored as properties. The `@escaping` annotation at least makes the potential for cycles visible to code reviewers — if you see `@escaping` on a closure parameter, you know the closure can be stored and you should check for strong reference cycles. This is a design detail the council does not mention.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- **ARC safety guarantees for the common case.** The research brief's enumeration [SWIFT-RESEARCH-BRIEF] — use-after-free prevented for strong references, buffer overflows prevented by bounds-checking collections, null pointer dereferences prevented by optionals — is accurate and correctly cited. These are meaningful structural guarantees.

- **`unowned` creates crash-on-dangling, not undefined behavior.** The distinction is meaningful from a security standpoint: in C, a dangling pointer access is undefined behavior and exploitable. In Swift, an `unowned` reference to a deallocated object produces a deterministic runtime crash rather than undefined behavior. This is a narrower guarantee than ARC strong references but a broader guarantee than C raw pointers. All councils correctly identify `unowned` as a footgun; the practitioner correctly notes that violation of lifetime assumptions crashes in production.

- **`UnsafePointer` and family create genuine C-equivalent undefined behavior.** The research brief and all council perspectives correctly identify that `UnsafePointer`, `withUnsafeBytes`, `UnsafeMutableRawPointer`, and related APIs create a region where Swift's memory safety guarantees do not apply and C-equivalent undefined behavior is possible [SWIFT-ARC-DOCS].

- **SE-0458 provides audit-readiness for the unsafe surface.** The `-strict-memory-safety` compiler flag and `@unsafe`/`unsafe` annotation system (Swift 6.2) are correctly described: they make every unsafe operation in a Swift codebase syntactically marked and discoverable via compiler tooling [SE-0458].

**Corrections needed:**

- **The eleven-year gap requires stronger framing.** The historian frames the gap between Swift 1.0 and SE-0458 as "an accepted trade-off" because "the unsafe APIs are needed for C interoperability and performance-critical code." The trade-off framing is fair, but the consequence deserves more emphasis: for eleven years, a security auditor reviewing a Swift codebase could not use compiler tooling to find the unsafe surface. They had to read every line of code, searching for calls to `withUnsafeBytes`, `UnsafePointer`, `Unmanaged.passRetained`, etc. Rust has required `unsafe` blocks since Rust 1.0 (2015). Swift's equivalent arrived in 2025. This is a concrete, eleven-year lag in security auditability relative to the closest comparable language — and it matters for organizations that conduct formal security reviews.

- **ARC's determinism has a security edge case not discussed.** ARC's deterministic deallocation is generally a security positive: predictable deallocation patterns make it harder to exploit temporal memory safety issues. However, for the cases where UnsafePointer is used, ARC's determinism can *aid* exploitation: an attacker who can trigger explicit deallocation of an object can predict when the memory will be freed and potentially reused. This is theoretical for most Swift codebases (which use little unsafe code), but it is worth stating: ARC determinism is not unambiguously better than GC from a security standpoint when unsafe code is involved.

**Additional context:**

- **Ownership modifiers (SE-0377/SE-0390) security implications.** The `borrowing`/`consuming` parameter ownership modifiers and noncopyable types (`~Copyable`) introduced in Swift 5.9 have security implications that no council perspective addresses. Noncopyable types enable single-owner semantics that can express security-relevant invariants: a type representing an open file handle or a cryptographic key that must be explicitly consumed (not inadvertently duplicated) can be modeled with `~Copyable`. This is a positive development — the language gained the ability to express ownership invariants with security-relevant properties without requiring the full Rust ownership model throughout. However, this is currently opt-in and niche; most Swift code does not use noncopyable types.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- **Swift 6 data race safety at compile time.** The realist and apologist correctly characterize Swift 6's Sendable + actor enforcement as the only mainstream language (alongside Rust) to enforce data race freedom at compile time. This is a meaningful security property: data races are undefined behavior in C/C++ and exploitable; in Swift 6, they are compile errors.

- **Migration friction was real.** The practitioner's documentation of "47 compiler warnings" on Swift 6 migration [SWIFT-6-MIGRATION] and the realist's acknowledgment of false positives in Swift 5.10's strict concurrency checking are accurate. The friction reflects that retrofitting compile-time data race safety onto an existing language requires breaking changes and design trade-offs.

**Corrections needed:**

- **Actor reentrancy is a security-relevant correctness hole that compile-time data race safety does not address.** This is absent from all five council perspectives and is the most significant omission in Section 4 from a security standpoint.

  Swift actors prevent concurrent access to their mutable state. But Swift actors allow reentrancy: when an actor method suspends at an `await` point, another caller can enter the actor before the original caller resumes. This means that invariants held between suspension points can be violated. The Swift Evolution proposal for actors explicitly acknowledges this: "Actor reentrancy prevents deadlocks and avoids a potential source of deadlock, but does so at the cost of making it easier to introduce data-consistency bugs" [SE-0306].

  The security implication: an actor that protects, for example, a session table or a rate limiter state machine is not protected against reentrancy-based inconsistency. A method that checks a rate limit, suspends to make an async call, and then decrements the counter can have its rate limit check bypassed if another request enters the actor during the suspension. This is the "check-then-act" race condition pattern transposed into the actor model. Compile-time data race safety doesn't catch it because no data race occurs — the actor serializes access — but the semantic invariant is still violated.

  Apple's documentation acknowledges reentrancy by recommending that actors hold no state that spans suspension points without explicit re-validation. This is the correct approach but requires developer discipline; it is not compiler-enforced.

- **`nonisolated(unsafe)` as a concurrency escape hatch deserves security treatment.** SE-0376's `nonisolated(unsafe)` modifier allows marking a stored property as exempt from actor isolation checking. This means the developer is asserting that concurrent access to that property is safe to perform manually. The name breaks the `Unsafe*` naming convention that would make it stand out in code review, and the SE-0458 `-strict-memory-safety` flag's relationship to `nonisolated(unsafe)` is not clearly documented — it is unclear whether SE-0458 flags `nonisolated(unsafe)` as an unsafe operation. This is a new escape hatch added to smooth Swift 6 migration, and its security implications have not been analyzed in council perspectives.

- **`@preconcurrency` escape hatch.** The `@preconcurrency` attribute allows suppressing concurrency checking for APIs written before Swift's strict concurrency model. In practice, this means that code bridging to `@preconcurrency`-marked APIs may have real data races that are not flagged. Council perspectives do not discuss this escape hatch's security implications.

**Additional context:**

- **The DoS dimension of concurrency failures.** The detractor correctly notes that memory leaks in server-side Swift (from retain cycles) can become DoS vectors. Actor starvation is the concurrency-level equivalent: a poorly designed actor that processes work serially can become a bottleneck that, under adversarial input, serializes all competing requests behind a slow operation. This is not a security vulnerability in the traditional sense, but it is an adversary-exploitable availability failure. The actor model's serialization guarantee — usually a safety benefit — becomes an attack surface if actors aren't designed with contention in mind.

---

### Other Sections (security-relevant flags)

**Section 6: Ecosystem and Tooling**

- **SPM source-based dependency model has a specific trust model that council perspectives don't fully characterize.** SPM resolves dependencies by fetching source from git repositories at specified versions (tags or commits). The signed packages feature introduced in 2025 [COMMITSTUDIO-SPM-2025] verifies package author identity, which is analogous to npm's package provenance feature. But source-based resolution means there is no central registry whose compromise would affect all consumers — attackers must compromise the upstream git repository, not a registry. This is a specific trust model advantage over npm's centralized registry.

  The limitation: SPM's `.resolved` file (the lock file equivalent) records commit hashes rather than content-addressable hashes of the downloaded source. A git tag can be moved; a commit hash cannot be changed but the content at that commit was trusted at download time. Supply chain security ultimately relies on the integrity of upstream git hosting (primarily GitHub for most Swift packages).

- **No SBOM generation.** No council perspective mentions that SPM does not natively generate Software Bills of Materials (SBOMs). SBOM generation is increasingly a regulatory requirement (US Executive Order 14028, EU Cyber Resilience Act). Server-side Swift deployments in regulated industries will need third-party tooling to generate SBOMs, which is a practical gap.

**Section 8: Developer Experience**

- **Force unwrap discoverability as a security-relevant DX issue.** Apple's own sample code and tutorials used `!` extensively in Swift's early years. This established a pattern that persisted in many production codebases. The practitioner's observation that force unwrap crashes are a "consistently prominent category" in production crash analysis [PRACTITIONER] aligns with the known pattern. From a security perspective: crash-causing nil dereferences in network-facing code can be targeted — if an attacker can trigger a specific nil dereference, they have a reliable DoS primitive. SwiftLint's `force_unwrapping` rule, when configured, flags these patterns; code review discipline and linting are the practical mitigations.

---

## Implications for Language Design

**1. Unsafe surface visibility must be enforced from day one, not retrofitted.**

Swift's eleven-year gap between unsafe API introduction (2014) and auditable unsafe surface marking (SE-0458, 2025) demonstrates the cost of deferring this design decision. Rust required `unsafe` blocks from version 1.0 (2015). The difference is meaningful: any Rust codebase has a compiler-auditable unsafe surface from its first build; any pre-6.2 Swift codebase required manual line-by-line audit to find unsafe operations. Language designers should treat "how do security auditors identify the unsafe surface?" as a first-class design question, not an afterthought. The mechanism (Rust's `unsafe` blocks, Swift's `@unsafe` attribute) is less important than requiring it unconditionally at language launch.

**2. Compile-time data race safety and semantic concurrency correctness are distinct problems.**

Swift 6's actor + Sendable model achieves compile-time elimination of data races. Actor reentrancy demonstrates that this does not eliminate all concurrency-related correctness bugs with security implications. The "check-then-act" pattern, invariant violations across suspension points, and actor starvation under adversarial load remain possible in Swift 6. Language designers should be precise about what concurrency guarantees their model provides and be explicit about the residual semantic concurrency risks that compile-time checking cannot address. Overstating compile-time concurrency guarantees leads to false confidence in the security posture of concurrent code.

**3. The naming convention of escape hatches determines their discoverability.**

Swift's `Unsafe*` naming convention — `UnsafePointer`, `UnsafeMutablePointer`, `withUnsafeBytes` — makes unsafe operations visible in code search and review. SE-0458 formalized this visibility at the compiler level. By contrast, `nonisolated(unsafe)` breaks the convention: it is an unsafe concurrency escape hatch whose name doesn't match the `Unsafe*` pattern. This inconsistency matters in practice: a security reviewer searching for unsafe operations using string match on "Unsafe" will miss `nonisolated(unsafe)` patterns. Lesson: escape hatches from safety guarantees should be named consistently, preferably with the safety-relevant keyword prominent and first.

**4. Cryptographic API design should make weak primitive selection difficult by default.**

CryptoKit's API design — exposing only modern, recommended algorithms in the primary API — exemplifies a security-positive design pattern. By not providing access to DES, 3DES, MD5, or SHA-1 through the primary API, CryptoKit makes the most common weak-primitive mistakes require deliberate API selection from legacy frameworks. This is a security ergonomics decision: the secure path is the path of least resistance. Language and library designers should apply this principle broadly: APIs that have security implications should structure their interface so that the secure choice is the default, and insecure choices require explicit, visible opt-out.

**5. Memory management strategy affects the DoS attack surface, not just memory corruption.**

The choice between ARC and GC is typically analyzed for correctness (retain cycles vs. GC overhead) and performance (determinism vs. throughput). The security perspective adds a dimension: retain cycles in ARC-managed languages create a denial-of-service attack surface in server-side code that GC-based languages do not have, because GC automatically breaks cycles. Conversely, GC's non-determinism can create availability issues under memory pressure. Language designers should analyze their memory management choice's implications for adversarial availability scenarios, particularly when the language targets server-side deployment contexts.

**6. Platform security controls should not be attributed to the language.**

Swift's security record on iOS/macOS is meaningfully shaped by App Sandbox, code signing, and App Store review — platform-level controls that would apply to any language deployed on Apple platforms. Language comparisons that do not control for deployment context systematically overstate the language's security contribution when the platform provides significant controls. Designers of languages targeting sandboxed runtimes (mobile, WebAssembly, browser extensions) should be explicit about which security properties come from the language and which come from the deployment environment.

---

## References

[CVE-2022-24667] GitHub Security Advisory. "CVE-2022-24667: swift-nio-http2 vulnerable to denial of service via mishandled HPACK variable length integer encoding." GitHub Advisory GHSA-w3f6-pc54-gfw7. https://github.com/apple/swift-nio-http2/security/advisories/GHSA-w3f6-pc54-gfw7

[CVE-2022-0618] GitHub Security Advisory. "CVE-2022-0618: Denial of Service via HTTP/2 HEADERS frames with padding but no data." GitHub Advisory GHSA-q36x-r5x4-h4q6. https://github.com/apple/swift-nio-http2/security/advisories/GHSA-q36x-r5x4-h4q6

[SWIFT-FORUMS-RAPID-RESET] Swift Forums. "swift-nio-http2 security update: CVE-2023-44487 HTTP/2 Rapid Reset DoS." October 2023. https://forums.swift.org/t/swift-nio-http2-security-update-cve-2023-44487-http-2-dos/67764

[SWIFT-CVE-DETAILS] CVEDetails. "Apple Swift: Security Vulnerabilities." https://www.cvedetails.com/vulnerability-list/vendor_id-49/product_id-60961/Apple-Swift.html

[DOD-MEMORY-SAFETY] NSA/CISA. (2022). "Software Memory Safety." https://media.defense.gov/2022/Nov/10/2003112742/-1/-1/0/CSI_SOFTWARE_MEMORY_SAFETY.PDF

[SE-0458] Swift Evolution. "SE-0458: Strict Memory Safety." Swift 6.2, September 2025. https://github.com/swiftlang/swift-evolution/blob/main/proposals/0458-strict-memory-safety.md

[SE-0306] Swift Evolution. "SE-0306: Actors." Swift 5.5. https://github.com/apple/swift-evolution/blob/main/proposals/0306-actors.md

[SE-0376] Swift Evolution. "SE-0376: Function Back-Deployment." [nonisolated(unsafe) introduced in related concurrency context.] https://github.com/apple/swift-evolution/blob/main/proposals/0376-function-back-deployment.md

[SE-0377] Swift Evolution. "SE-0377: borrow and take parameter ownership modifiers." Swift 5.9. https://github.com/apple/swift-evolution/blob/main/proposals/0377-parameter-ownership-modifiers.md

[SE-0390] Swift Evolution. "SE-0390: Noncopyable structs and enums." Swift 5.9. https://github.com/apple/swift-evolution/blob/main/proposals/0390-noncopyable-structs-and-enums.md

[SE-0414] Swift Evolution. "SE-0414: Region-based Isolation." Swift 6.0. https://github.com/apple/swift-evolution/blob/main/proposals/0414-region-based-isolation.md

[SWIFT-ARC-DOCS] Apple Developer Documentation. "Automatic Reference Counting." Swift Programming Language. https://docs.swift.org/swift-book/documentation/the-swift-programming-language/automaticreferencecounting/

[SWIFT-LANG-INTS] Apple Developer Documentation. "Integers." Swift Programming Language — The Basics. https://docs.swift.org/swift-book/documentation/the-swift-programming-language/thebasics/#Integers

[APPLE-CRYPTOKIT-DOCS] Apple Developer Documentation. "CryptoKit." https://developer.apple.com/documentation/cryptokit

[SWIFT-CRYPTO] Apple / swift-crypto. "A Swift implementation of CryptoKit for Linux and Windows." GitHub. https://github.com/apple/swift-crypto

[SWIFT-6-MIGRATION] Referenced in council perspectives; Swift Forums migration experience discussions. See research brief [SWIFT-RESEARCH-BRIEF] for detailed sourcing.

[COMMITSTUDIO-SPM-2025] Cited in research brief for SPM signed packages introduction, 2025.

[SWIFT-RESEARCH-BRIEF] Swift — Research Brief. Penultima Project. research/tier1/swift/research-brief.md. 2026-02-28.

[CWE-190] MITRE Common Weakness Enumeration. "CWE-190: Integer Overflow or Wraparound." https://cwe.mitre.org/data/definitions/190.html

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019. (Cited in council apologist perspective for 70% memory safety CVE figure.)
