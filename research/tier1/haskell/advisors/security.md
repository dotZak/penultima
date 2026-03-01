# Haskell — Security Advisor Review

```yaml
role: advisor-security
language: "Haskell"
agent: "claude-agent"
date: "2026-02-28"
```

---

## Summary

Haskell's security profile is best understood as a tale of two surfaces: a remarkably hardened pure-code interior and a largely unguarded FFI boundary. The council's five perspectives accurately identify the core dynamic — that purity, immutability, and the `IO` type eliminate entire vulnerability classes by construction — but the treatment across perspectives is uneven in rigor, and two important distortions appear repeatedly. First, the Apologist's comparison of Haskell's ~26 HSEC advisories to "thousands" in peer-language ecosystems conflates advisory count with security quality; ecosystem size, deployment surface, and advisory-system maturity are all confounding variables that the council insufficiently controls for. Second, the claim that the type system "prevents injection" requires a critical caveat: the standard library's `String` type is semantically opaque, injection prevention depends on library-level discipline (using type-safe query builders rather than string concatenation), and CVE-2024-3566 is a direct empirical refutation of any overly broad formulation of this guarantee.

The genuine security strengths are real and should not be minimized. Buffer overflows, null pointer dereferences, use-after-free, and data races on pure values are not rare events in Haskell — they are structurally impossible in the pure fragment, a categorical guarantee rather than a probabilistic reduction. Software Transactional Memory (STM) provides compositional data-race prevention that is architecturally superior to lock-based concurrency for complex shared-state scenarios. The `unsafe` naming convention makes escape-hatch misuse visible in code review. And Safe Haskell's `Safe`/`Trustworthy`/`Unsafe` pragma lattice represents a language-level sandboxing mechanism with no real equivalent in C, Java, Python, or Go.

The genuine security weaknesses are also underweighted in council discussions. The cryptography ecosystem is fragile: `cryptonite`, the dominant Haskell crypto library, was unmaintained for an extended period before the `crypton` fork was established, and neither library has achieved the kind of formal verification or security audit coverage common in mature ecosystems (libsodium, OpenSSL, BoringSSL). Template Haskell executes arbitrary Haskell code at compile time with full filesystem access — a supply chain attack on a widely-used macro library is an underappreciated threat surface not mentioned by any council member. Asynchronous exceptions create subtle availability risks: malicious or defective code can interrupt cleanup in `finally` handlers unless developers use `mask`/`uninterruptibleMask` correctly, a discipline that requires expertise most Haskell practitioners do not possess on day one. And the small HSEC advisory count, while encouraging, partially reflects Haskell's small deployment footprint rather than its security engineering quality per package.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

The council is correct that Haskell eliminates multiple vulnerability classes by construction in pure code. This is not a probabilistic claim or a best-practice claim — it is a structural guarantee of the language semantics:

- Buffer overflows: bounds-checked array operations in `Data.Array` and `Data.Vector`; no pointer arithmetic in pure code; out-of-bounds access throws an exception rather than producing undefined behavior [HASKELL-REPORT-2010].
- Null pointer dereferences: `Maybe a` is the only way to express optionality; pattern matching on `Nothing` is required for type-checking; the million-dollar mistake (Hoare's words for null references) is absent from the pure fragment.
- Use-after-free: GC manages all pure heap objects; no `free()`; lifetime is determined by reachability, not programmer discipline.
- Data races on pure values: immutability is the default; shared mutable state via `MVar`, `TVar`, and `IORef` must be explicitly introduced and is visible in types.

The research brief's characterization of these as categorical eliminations [HASKELL-BRIEF-SECURITY] is accurate and all five council perspectives substantiate it consistently.

The Realist's framing — "language level favorable; ecosystem level unremarkable" — is the most forensically honest in the council [REALIST-S7]. It correctly distinguishes what the language provides by design from what the ecosystem provides through convention and tooling, a distinction the Apologist often elides.

The identification of CVE-2024-3566 (HSEC-2024-0003) as an FFI boundary vulnerability rather than a type system failure is accurate. The command injection in `process` occurred at the OS interaction layer — at the point where a Haskell `String` was passed to `cmd.exe` with inadequate escaping — not in Haskell's pure core. The type system correctly treats a `String` as a `String`; it has no mechanism to distinguish "user-supplied shell argument" from "safe program name" unless the developer uses a type-safe wrapper library. The CVSS 9.8 (Critical) rating and Windows-only scope are accurately reported [HSEC-2024-0003].

HSEC-2023-0015's identification as a supply chain vulnerability in `cabal-install`'s Hackage Security protocol is accurate [HSEC-2023-0015]. The Security Response Team's advisory infrastructure — HSEC identifiers, OSV.dev integration, CVE cross-referencing — is a genuine institutional investment that exceeds what many larger language communities have built.

**Corrections needed:**

The Apologist's claim that 26 ecosystem-wide advisories "for systems this scale is strikingly small" compared to Python and Ruby having "thousands" requires significant methodological correction [APOLOGIST-S7]. Advisory count comparisons across language ecosystems are almost entirely confounded by:

1. **Ecosystem size**: Python's PyPI contains approximately 530,000+ packages (2026); Hackage contains approximately 16,000 packages. A per-package vulnerability rate would require normalizing by package count. The Apologist cites no such normalization.
2. **Deployment surface**: Python services serve the vast majority of the world's web requests; more attackers scrutinize Python code simply because the reward for finding vulnerabilities is higher. Haskell's small deployment footprint reduces attacker incentive, not necessarily vulnerability prevalence.
3. **Advisory system maturity**: Python's security ecosystem (PyPA advisory database, GitHub Security Advisories, OSV) has been active longer and has broader tooling integration. A more mature reporting infrastructure surfaces more vulnerabilities, not more bad code.
4. **Research scrutiny**: Python, Ruby, and PHP receive far more academic security research than Haskell. The HSEC database's relative sparseness reflects, at minimum partly, less adversarial research attention.

The correct framing is the Detractor's: the advisory count "reflect[s] ecosystem size more than exceptional security engineering" [DETRACTOR-S7]. The pure-code vulnerability eliminations are genuine; the small advisory count is an incomplete proxy for security quality.

The Apologist's assertion that type system properties "eliminate injection" also requires precision. SQL injection, shell injection, and XSS injection are prevented by Haskell only when developers use type-safe library abstractions (Persistent's typed query DSL, `esqueleto`, `hasql` with parameter types). The raw `String` type and standard library functions like `callProcess` provide no injection protection — as CVE-2024-3566 demonstrates empirically on the shell injection case. The Apologist is describing what *can* be achieved with Haskell, not what is achieved by default.

**Additional context:**

**Cryptography ecosystem fragility** is the most significant security gap not adequately covered by any council member. `cryptonite`, which was the standard Haskell cryptographic library for nearly a decade, entered an unmaintained state following its primary author's reduced involvement. The `crypton` fork was established to address this, but as of early 2026, the ecosystem remains fragmented: some libraries depend on `cryptonite`, others on `crypton`, and neither has received the kind of formal security audit that mature cryptographic libraries (libsodium, BoringSSL) undergo. Haskell systems performing sensitive cryptographic operations are dependent on libraries that have not been independently audited to the same standard as language-specific alternatives in Rust's `ring` crate or Python's `cryptography` package [CRYPTON-FORK; CRYPTONITE-ARCHIVED].

**Template Haskell as a compile-time execution surface** is unaddressed by all five council members. Template Haskell (GHC extension `TemplateHaskell`) runs arbitrary Haskell code at compile time with full I/O capabilities — it can read files, make network requests, and execute external programs during compilation. A supply chain attack on a widely-used Template Haskell macro library (e.g., in the `aeson`, `servant`, or `optics` ecosystems) could exfiltrate developer credentials, inject malicious code, or modify build artifacts. Safe Haskell's `Safe` pragma explicitly disallows Template Haskell in untrusted modules [GHC-SAFE-HASKELL], but this restriction applies only when using the Safe Haskell pragma system — ordinary production code compiles Template Haskell macros without restriction. This is structurally similar to the `proc-macro` supply chain risk documented for Rust.

**GHC toolchain as attack surface**: The research brief notes that Q1 2025 saw the first HSEC advisories published for GHC toolchain components [HSEC-2025-Q1]. The GHC RTS, linker, and code generation pipeline are substantially implemented in C and Haskell. A vulnerability in GHC itself (not just ecosystem packages) could affect every Haskell program compiled with that toolchain. This represents a shared attack surface that the council underweights.

**`unsafePerformIO` and `unsafeCoerce` as security-relevant escape hatches**: The research brief correctly identifies these [HASKELL-BRIEF-TYPES], and the Apologist accurately distinguishes them from C (all unchecked) and Java (casts indistinguishable from safe). However, the security implication needs sharper articulation: `unsafePerformIO` can break purity and referential transparency across module boundaries without any visible signature change in the calling code. A library that uses `unsafePerformIO` internally for caching (a legitimate performance optimization) looks identical to one that uses it to perform side-effecting I/O — and both compile with the same type-checked signature. This is a supply chain concern, not just a developer footgun.

**Missing data:**

No Haskell-specific CVE data file exists in this project's evidence directory. The HSEC advisory database is the primary authoritative source for Haskell vulnerabilities; a direct query of the NVD using `cpe:2.3:a:haskell:*` and related identifiers would be required to establish whether there are Haskell-related CVEs not captured in HSEC. The existing data (26 HSEC advisories, the two notable entries documented above) is baseline but incomplete for a full adversarial threat model.

Ecosystem adoption rate for Safe Haskell is not quantified. The Detractor notes it is "rarely used outside research" and that the 2022 survey does not mention it [DETRACTOR-S7], but neither claim is sourced. Determining what fraction of production Haskell libraries opt into Safe Haskell's pragma system would significantly affect the weight to assign to that security mechanism.

---

### Section 2: Type System (security implications)

**Accurate claims:**

The council is correct that the `Maybe a` type eliminates null pointer dereference by construction — not by runtime check, not by annotation, but by the absence of a null value in the type. The compiler enforces that any code receiving a `Maybe a` must handle the `Nothing` case, making null-path elision a type error rather than a latent defect.

The Apologist's observation that escape hatches are explicitly named — `unsafePerformIO`, `unsafeCoerce`, FFI `unsafe` imports — while C has no such naming convention and Java's cast syntax is indistinguishable from safe code, is accurate and represents a genuine security-ergonomic design advantage [APOLOGIST-S2]. When reading code, Haskell's `unsafe` naming convention flags potential invariant violations; a reviewer searching for `unsafe` in a Haskell codebase will find the relevant surface area in a way that reviewing C or Java does not support.

The practitioner's observation that the `newtype` pattern provides domain-level type safety with no runtime cost — preventing `UserId` from being accidentally used as an `AccountId` even when both are `Int` underneath — is accurate and security-relevant [PRACTITIONER-S2]. This design pattern prevents a class of type confusion vulnerabilities that appear in weaker type systems.

The Realist's bottom line — "core type system genuinely excellent; extended type system powerful but fragmented and partially unstable" — is accurate [REALIST-S2]. The security properties most relevant to everyday programs (no null, explicit effects, typed `Maybe`/`Either` for failure) are in the stable core. The less stable portions (linear types, dependent types) represent security-research opportunities rather than deployed guarantees.

**Corrections needed:**

The Apologist's formulation that the type system enables injection prevention through type-safe libraries is accurate as a capability statement but misleading as a default-behavior claim. The standard `String` type carries no semantic information about its provenance, escaping status, or trust level. Type-safe SQL libraries (Persistent, Esqueleto, Beam, hasql) do prevent SQL injection by construction, but they require developer selection and correct use. A developer using raw `String` concatenation to build a database query — which compiles without error — receives no injection protection. The council should be precise: the language makes injection-safe design achievable; it does not make injection-unsafe design impossible or even inconvenient without additional library discipline.

**Additional context:**

The extension proliferation identified by the Detractor and Practitioner has a security-relevant dimension beyond usability [DETRACTOR-S2; PRACTITIONER-S2]. GHC extensions that alter type system semantics — `UndecidableInstances`, `IncoherentInstances` — can create type-checker loops or unsound instance resolution. While these are not direct vulnerability sources, they expand the complexity surface for which security properties must be reasoned about. More directly, `OverlappingInstances` and `IncoherentInstances` can cause instance resolution to depend on declaration order and import structure in ways that are not locally obvious, potentially allowing a dependency to silently change the behavior of type-class dispatch.

Template Haskell (requiring `{-# LANGUAGE TemplateHaskell #-}`) runs at compile time with full capability. Any library that uses TH macros is effectively incorporating that library's code into the build-time trusted computing base. This is not modeled in any council member's type-system discussion.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

The council uniformly and accurately identifies that GC eliminates buffer overflow, use-after-free, and double-free in pure code. This is a categorical claim supported by language semantics, not a statistical one.

The Practitioner's observation that "a Haskell service won't segfault in pure code" is accurate operational experience [PRACTITIONER-S3]. Memory safety in the pure fragment is essentially confined to the FFI boundary — this is a manageable and explicit seam rather than a diffuse vulnerability surface.

The Detractor's identification of the Microsoft SIRT paper's "70% of CVEs are memory safety issues" statistic is referenced across multiple perspectives as evidence that Haskell eliminates a large fraction of typical CVE exposure [MSRC-2019]. The connection is plausible but requires qualification: the 70% figure applies specifically to Microsoft's own (predominantly C/C++) codebase and is not a universal statement about all software. Haskell programs have a different threat model — their vulnerabilities shift toward logic errors, supply chain issues, and FFI boundaries rather than disappearing altogether.

**Corrections needed:**

The Apologist's framing implies that eliminating memory safety vulnerabilities equates to high overall security [APOLOGIST-S3]. This is a category error. Memory safety eliminates one class of vulnerabilities; application-level vulnerabilities (authentication bypasses, authorization flaws, business logic errors, cryptographic misuse) are not affected by the memory model. A pure-Haskell web application can have SQL injection (if using unsafe string concatenation), authentication bypass, and sensitive data exposure — none of which appear in CVE statistics as "memory safety" issues, and none of which are mitigated by GC.

The Detractor's point that Standard Chartered's Mu (the largest known industrial Haskell codebase at 5+ million lines) is a *strict* variant of Haskell [DETRACTOR-S3] is important for assessing the space-leak concern's real-world impact. The industry's single largest Haskell deployment modified the default memory model to address the space-leak problem. This is an endorsement of the language's other properties, but it is also evidence that lazy evaluation's memory behavior is considered production-disqualifying even by Haskell's most committed industrial users.

**Additional context:**

**Space leaks as an availability/DoS risk** are underframed by all council members as an operational concern rather than a security concern. A space leak accumulating thunks at 1MB/request will exhaust process memory in a predictable window given request volume — this is a denial-of-service vulnerability in the broad sense. In adversarial contexts, an attacker who can send carefully crafted requests that trigger space-leak accumulation faster than the GC can reclaim may produce a resource exhaustion attack. The Practitioner notes that space leaks "don't appear in development (low volume); emerge in production under load" [PRACTITIONER-S3] — which is precisely the condition an attacker would exploit. This deserves explicit security framing, not merely a performance framing.

**FFI `unsafe` imports** remove the GHC RTS's protection mechanisms for calling C code — the RTS ordinarily enforces that Haskell's GC can run safely during foreign calls, but `foreign import unsafe` bypasses this. From a security perspective, `unsafe` FFI imports are a broader class of safety guarantee removal than the naming convention suggests to most readers: they are not just "potentially unsound Haskell" but "Haskell that may corrupt the GC heap if the called C function makes incorrect assumptions." The research brief notes this [HASKELL-BRIEF-TYPES], but no council member provides the complete security framing.

**GHC RTS vulnerabilities** represent a shared infrastructure risk. The RTS is the executing environment for all GHC-compiled code. Historical RTS-level memory issues (the large array allocation integer overflow in pre-6.8.x noted in the brief [HASKELL-BRIEF-SECURITY]) demonstrate that the runtime layer is not immune to classical memory vulnerabilities. The 2025 Q1 HSEC advisories for GHC toolchain components confirm this remains a live category.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

The council is correct that STM's composability provides a structural data-race prevention guarantee that lock-based concurrency cannot match. The Historian accurately traces this to the Harris/Marlow/Peyton Jones/Herlihy 2005 "Composable Memory Transactions" paper [HISTORIAN-S4]. The key security property is that composing two individually-atomic STM transactions into a third is guaranteed to be atomic — something that composing two mutex-protected operations is not.

The type system enforcement of STM contexts (`STM` monad vs. `IO` monad) provides an architectural guarantee: code in the `STM` monad cannot perform arbitrary I/O, which means STM transactions cannot have hidden side effects that invalidate their isolation properties. This is a genuine security-ergonomic advantage over database-level STM implementations that must trust application code not to break isolation.

The `IO` type's role as an effect boundary is correctly identified across all perspectives: pure functions provably cannot perform I/O, network operations, or file system access. This is relevant to security because it allows reasoning about what a pure function can and cannot do from its type alone — a dependency that introduces an unexpected I/O effect cannot do so silently.

**Corrections needed:**

The Practitioner's two-error-regime problem — typed `Either`/`ExceptT` errors vs. untyped runtime exceptions — has a security dimension not addressed [PRACTITIONER-S4]. `error` and `undefined` in Haskell throw asynchronous exceptions that can surface from pure-looking code. Library code that calls `error` on invalid input creates a crash surface that a caller with typed error handling cannot intercept through normal monadic error handling; it requires wrapping in `try`/`catch` even for code that appears to have a pure type signature. An attacker who can provide input that triggers `error` in a Haskell service can cause an unhandled exception, depending on the exception handling setup.

**Additional context:**

**Asynchronous exceptions as a security-relevant mechanism** are underweighted by all council members who discuss them (Detractor, Practitioner, Realist) primarily as an ergonomic concern [DETRACTOR-S4; PRACTITIONER-S4]. The security framing: `throwTo` allows any thread to inject an asynchronous exception into any other thread. In a multi-tenant or plugin system where user code is executed concurrently with trusted system code — even with Safe Haskell blocking the most dangerous operations — the ability to throw exceptions cross-thread could be exploited to interrupt cleanup handlers (`finally` blocks), resource release, or security-critical state transitions. The `mask`/`uninterruptibleMask` discipline that protects against this is well-documented but requires expertise; the Practitioner accurately notes it requires "awareness newcomers lack" [PRACTITIONER-S4].

**STM retry storms as an availability concern**: Under heavy contention, STM transactions that repeatedly fail and retry consume CPU without making progress — a condition functionally identical to a spinning lock. If an adversary can construct a workload that maximizes STM conflicts (e.g., all transactions contend on a single hot `TVar`), this could function as a CPU exhaustion denial-of-service. The Detractor and Realist both note retry storms as a performance concern [DETRACTOR-S4; REALIST-S4]; the security implication of adversarially-triggered retry storms deserves explicit acknowledgment.

---

### Other Sections (security-relevant flags)

**Section 6: Ecosystem and Tooling — Supply Chain**

The Hackage ecosystem's supply chain security infrastructure is better than many communities but weaker than it should be for the security-sensitive workloads where Haskell is sometimes deployed. Specific gaps:

- **No enforced dependency signing**: Hackage packages can be updated without GPG-verified commits; the HSEC-2023-0015 vulnerability in `cabal-install`'s Hackage Security protocol was in the key verification layer, which is precisely the mechanism intended to prevent malicious package delivery [HSEC-2023-0015]. The vulnerability has been patched, but its existence demonstrates that the trust infrastructure has been exploitable.
- **Stackage as a partial mitigation**: Stackage's curated snapshots reduce dependency-confusion risk and provide a quality floor, but Stackage inclusion does not require security auditing, and the LTS cadence means security patches may take time to reach users.
- **Volunteer-based security response**: The Haskell Security Response Team operates on a volunteer basis. The Realist notes that 2025 funding challenges for the Haskell Foundation may affect security response capacity [REALIST-S7] — a concern that deserves emphasis for any organization deploying Haskell in security-sensitive contexts.

**Section 6: Cryptographic Library Quality**

No council member adequately addresses the cryptographic library situation. Haskell's production cryptographic story runs through:
- `crypton` (active fork of `cryptonite`, as of 2022–present)
- `cryptonite` (substantially unmaintained as of 2022; archived)
- `tls` library (negotiates TLS connections; depends on `crypton`/`cryptonite`)
- `x509` library for certificate parsing

`crypton` is maintained by a small set of volunteers and has not received a comprehensive independent security audit. Contrast this with the Rust ecosystem's `ring` crate (formally verified components, based on BoringSSL primitives) or the Python `cryptography` package (FIPS-validated options, extensive audit history). An organization deploying Haskell in a context requiring strong cryptographic guarantees — financial services, government, healthcare — is depending on cryptographic primitives that lack the audit pedigree of alternatives. The council's silence on this is a material omission.

**Section 11: Governance**

The Realist's note that the 2025 Haskell Foundation funding challenges may affect security response capacity is a legitimate operational concern. The Security Response Team's volunteer-based model means that the Haskell ecosystem's ability to respond rapidly to critical vulnerabilities depends on volunteer availability. CVE-2024-3566 (CVSS 9.8) required significant coordination across GHC versions; that it was handled with `process-1.6.19.0` and a follow-up `process-1.6.23.0` for edge cases suggests competent response, but the sustainability of this model under adversarial pressure is not established.

---

## Implications for Language Design

**1. Named escape hatches reduce accidental misuse proportionally to how distinguishable they are from safe code.**
Haskell's `unsafe` naming convention (unsafePerformIO, unsafeCoerce, `foreign import unsafe`) provides a searchable, reviewable signal for invariant violations. C has no such signal. Java's cast syntax is indistinguishable from safe upcasting. The lesson: security-impacting escape hatches should be named to be detectable and auditable. The mechanism is imperfect — a developer can still choose to use `unsafePerformIO` — but it makes auditing tractable in a way that languages without explicit naming cannot. Rust's `unsafe` block keyword applies this lesson explicitly in the systems programming domain.

**2. Vulnerability count comparisons across languages are only meaningful with explicit ecosystem-size and scrutiny normalization.**
Haskell's ~26 HSEC advisories vs. Python's and Ruby's larger advisory counts reflects primarily the difference in ecosystem scale, adversarial scrutiny, and advisory-system maturity, not primarily the difference in per-package security quality. Language designers should resist framing small advisory counts as evidence of language security without controlling for these variables. Advisory count is a lagging indicator, not a leading one.

**3. The FFI boundary is where language security guarantees always end — design explicitly for this seam.**
No matter how strong a language's memory model, any language capable of calling C code inherits C's full vulnerability surface at the call boundary. Haskell's FFI design correctly segregates `unsafe` from `safe` FFI imports, but this distinction is insufficient: `safe` FFI still reintroduces memory management responsibility for any C pointers passed or received. Language designers should treat FFI as a security boundary, not merely a compatibility boundary, and design tooling (static analysis, sandboxing options) specifically for auditing it. Haskell's Safe Haskell pragma system offers a partial model worth studying.

**4. Type-safe library APIs are necessary but not automatic — language design can make them possible without making them default.**
Haskell's type system makes injection-safe query builders possible (typed SQL, typed shell commands). But string-concatenation-based injection remains possible, compiles without errors, and produces the category of vulnerability demonstrated by CVE-2024-3566. The lesson: a language can provide the affordances for security-safe patterns without making insecure patterns impossible. Designers should consider whether default APIs (the standard library) implement the safe pattern or the unsafe pattern, since developers will use the default path. Haskell's `String`-based `callProcess` and related functions default to the unsafe pattern.

**5. Lazy evaluation introduces unique resource-exhaustion risks that require specific security framing.**
Space leaks from accumulating unevaluated thunks are not merely performance issues — under adversarial conditions, they represent controllable denial-of-service vectors. A language designer choosing lazy-by-default evaluation accepts this trade-off: programs that are compositionally elegant may be vulnerable to adversarial request patterns that exploit evaluation deferral. Languages with lazy semantics should provide readily accessible tooling for detecting and quantifying thunk accumulation under adversarial loads, and should treat space leaks in public-facing request handlers as security issues, not merely performance issues.

**6. Language-level sandboxing (Safe Haskell model) is underexplored and underdeployed, but the mechanism is sound.**
Safe Haskell's `Safe`/`Trustworthy`/`Unsafe` pragma lattice allows a Haskell program to formally distinguish trusted from untrusted code and enforce that distinction at compile time. This is a capability that C, Go, Java, Python, and Ruby do not offer. Its limited adoption in practice (primarily academic research and Cardano smart contracts) reflects the ecosystem's lack of a compelling use case requiring it — not a flaw in the mechanism. Language designers building systems that need to execute untrusted code should study Safe Haskell as a prior art for compile-time trust lattices. The deployment gap reveals that security sandboxing requires not just a mechanism but a narrative: developers need to understand why and when to use it.

**7. Compile-time code execution (macros/TH) extends the supply chain attack surface into the build phase.**
Any language with compile-time code execution capability (Template Haskell, Rust proc-macros, Lisp macros) must treat macro libraries as part of the trusted computing base. Build-time code execution with filesystem, network, and process access creates a pre-deployment attack surface that conventional runtime security analysis misses entirely. Language designers should apply principle-of-least-privilege thinking to compile-time execution: macros should have the minimum capabilities needed for their legitimate purpose, not unrestricted host access.

**8. GC-based memory management shifts the attack surface rather than eliminating it.**
The Microsoft SIRT figure that ~70% of CVEs are memory safety issues applies to C/C++ codebases. GC eliminates a large portion of this category — but application vulnerabilities (logic errors, injection, authentication bypass), supply chain vulnerabilities, and runtime vulnerabilities (in the GC and RTS themselves) remain. Language designers and deployers should resist treating "uses GC, therefore secure" as a complete security model. The attack surface shifts; it does not disappear.

---

## References

[HASKELL-BRIEF-SECURITY] Haskell Research Brief, Security Data section. `research/tier1/haskell/research-brief.md`, 2026-02-28.

[HASKELL-BRIEF-TYPES] Haskell Research Brief, Type System section. `research/tier1/haskell/research-brief.md`, 2026-02-28.

[HASKELL-REPORT-2010] Marlow, S. (ed.). "Haskell 2010 Language Report." 2010. https://www.haskell.org/onlinereport/haskell2010/

[HSEC-2024-0003] Haskell Security Advisory HSEC-2024-0003 / CVE-2024-3566. `process` library Windows command injection. CVSS 3.1: 9.8. https://github.com/haskell/security-advisories/blob/main/advisories/hackage/process/HSEC-2024-0003.md

[HSEC-2023-0015] Haskell Security Advisory HSEC-2023-0015. `cabal-install` Hackage Security protocol vulnerability. https://github.com/haskell/security-advisories/blob/main/advisories/hackage/cabal-install/HSEC-2023-0015.md

[HSEC-GITHUB] Haskell Security Advisories repository. https://github.com/haskell/security-advisories

[HSEC-2023-REPORT] Haskell Security Response Team. Advisory database statistics, early 2024. Referenced in research brief.

[HSEC-2025-Q1] Haskell Security Response Team. First GHC toolchain component advisories, Q1 2025. Referenced in research brief.

[GHC-SAFE-HASKELL] GHC User's Guide: Safe Haskell. https://downloads.haskell.org/ghc/latest/docs/users_guide/exts/safe_haskell.html

[HASKELL-SURVEY-2022] "2022 State of Haskell Survey Results." Taylor Fausak. 1,038 respondents. November 2022. https://taylor.fausak.me/2022/11/18/haskell-survey-results/

[APOLOGIST-S2] Haskell Apologist Perspective, Section 2. `research/tier1/haskell/council/apologist.md`, 2026-02-28.

[APOLOGIST-S3] Haskell Apologist Perspective, Section 3. `research/tier1/haskell/council/apologist.md`, 2026-02-28.

[APOLOGIST-S7] Haskell Apologist Perspective, Section 7. `research/tier1/haskell/council/apologist.md`, 2026-02-28.

[DETRACTOR-S2] Haskell Detractor Perspective, Section 2. `research/tier1/haskell/council/detractor.md`, 2026-02-28.

[DETRACTOR-S3] Haskell Detractor Perspective, Section 3. `research/tier1/haskell/council/detractor.md`, 2026-02-28.

[DETRACTOR-S4] Haskell Detractor Perspective, Section 4. `research/tier1/haskell/council/detractor.md`, 2026-02-28.

[DETRACTOR-S7] Haskell Detractor Perspective, Section 7. `research/tier1/haskell/council/detractor.md`, 2026-02-28.

[REALIST-S2] Haskell Realist Perspective, Section 2. `research/tier1/haskell/council/realist.md`, 2026-02-28.

[REALIST-S4] Haskell Realist Perspective, Section 4. `research/tier1/haskell/council/realist.md`, 2026-02-28.

[REALIST-S7] Haskell Realist Perspective, Section 7. `research/tier1/haskell/council/realist.md`, 2026-02-28.

[PRACTITIONER-S2] Haskell Practitioner Perspective, Section 2. `research/tier1/haskell/council/practitioner.md`, 2026-02-28.

[PRACTITIONER-S3] Haskell Practitioner Perspective, Section 3. `research/tier1/haskell/council/practitioner.md`, 2026-02-28.

[PRACTITIONER-S4] Haskell Practitioner Perspective, Section 4. `research/tier1/haskell/council/practitioner.md`, 2026-02-28.

[HISTORIAN-S4] Haskell Historian Perspective, Section 4. `research/tier1/haskell/council/historian.md`, 2026-02-28.

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center. BlueHat IL 2019. Referenced in research brief and Apologist/Realist perspectives.

[CRYPTONITE-ARCHIVED] `cryptonite` Hackage page; substantially unmaintained following primary author's reduced involvement circa 2022. https://hackage.haskell.org/package/cryptonite

[CRYPTON-FORK] `crypton` package, forked from cryptonite, as maintained alternative. https://hackage.haskell.org/package/crypton

[HARRIS-STM-2005] Harris, T., Marlow, S., Peyton Jones, S., Herlihy, M. "Composable Memory Transactions." PPoPP 2005. https://research.microsoft.com/en-us/um/people/simonpj/papers/stm/stm.pdf

[HASKELL-WIKI-UNTRUSTED] Haskell Wiki: Safely running untrusted Haskell code. Referenced in research brief. https://wiki.haskell.org/Safely_running_untrusted_Haskell_code
