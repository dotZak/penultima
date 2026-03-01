# C# — Security Advisor Review

```yaml
role: advisor-security
language: "C#"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

The council's security analysis is broadly accurate in its core claims: managed code eliminates memory corruption CVE categories, the `unsafe` opt-in creates auditable code surface area, and Code Access Security's removal was the correct architectural decision. The research brief and five council perspectives together paint a mostly honest picture of C#'s security profile.

Two structural gaps undercut the analysis. First, no council member provides quantitative CVE data with stated methodology — the security narrative relies on individual named CVEs rather than density, severity distribution, or category breakdown compared against baseline expectations for a platform of .NET's scale and age. The two cited 2025 CVEs are real, but their selection was not systematic, and the detractor overstates what a single high-CVSS score implies about structural risk. Second, all five council members focus almost entirely on what C# does not prevent (memory corruption) without assessing what ASP.NET Core actively prevents at the framework layer — Razor's default HTML encoding (structural XSS prevention) and the built-in anti-CSRF token system are genuine security ergonomics advances with measurable real-world impact that the council completely omitted.

The most important correction to the council record concerns the scope of the NRT false-confidence risk. The detractor frames nullable reference type annotation errors as a potential security bypass vector, citing a PVS-Studio analysis that does not appear in the research brief's verified reference set. This risk is theoretically possible but overstated: the primary consequence of NRT false-negatives is NullReferenceException — a crash and potential DoS — not a security bypass, except in the specific scenario where null propagates silently past a security decision gate. The council should acknowledge this narrower scope before carrying the claim into the consensus report.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **Memory safety baseline.** All five council members correctly state that managed C# eliminates buffer overflows, use-after-free, heap corruption, and arbitrary memory read/write via pointer arithmetic in managed code. The CLR's type safety and array bounds checking enforce these properties unconditionally in managed code. The practitioner's observation — that these are "not theoretical guarantees" but "entire CVE categories absent from the .NET security advisory database because they are impossible in the managed execution model" — is accurate and precisely stated.

- **Vulnerability class shift, not elimination.** The historian and detractor make the accurate observation that managed memory safety shifts the vulnerability surface rather than eliminating it. CVE-2025-55315 (HTTP request smuggling, CVSS 9.9) and CVE-2025-24070 (authentication bypass via `RefreshSignInAsync`) are both logic errors, not memory corruption bugs [CSONLINE-SMUGGLING] [VERITAS-24070]. The practitioner's framing — "you trade memory corruption vulnerabilities for API misuse and logic vulnerabilities; the security model is different, not uniformly better" — is the most precise characterization across the council documents and should anchor the consensus report's Section 7 opening.

- **`unsafe` audibility.** The realist and practitioner accurately describe the `unsafe` opt-in mechanism: both the `unsafe` keyword at the code site and the `/unsafe` compiler flag at the project level are required, creating an auditable surface area. The "grep for unsafe blocks" audit approach is practical and correct for managed code reviewed at the source level [MS-UNSAFE].

- **CAS removal as the correct response to a failed security feature.** All council members correctly characterize Code Access Security's removal from .NET Core as the right decision. The historian's framing is particularly apt: "sometimes the right response to a failed security feature is removal, not repair." Microsoft's own documentation states CAS "is not supported as a security boundary" in .NET Core, confirming this assessment [MS-CAS-REMOVED]. CAS was both unconfigurable in practice and bypassable via full-trust code — a combination that produces the worst outcome: developer reliance on a guarantee that does not hold.

- **NuGet supply chain threat reality.** The documented attack campaigns are real and cited to identifiable sources: logic bombs (shanhai666, ~9,500 downloads by November 2025) [HACKERNEWS-LOGICBOMB]; credential theft via JIT hooking (4,500+ downloads) [OFFSEQ-NUGET]; crypto wallet theft (14 packages impersonating Nethereum, July 2025) [CYBERPRESS-WALLET]; 60-package sweep (July 2024) [HACKERNEWS-60PKG]. The practitioner's defense-in-depth recommendation — internal feed vetting, source mapping, SBOM generation, NuGet Audit for known CVEs, dependency review in PRs — is sound operational security guidance.

- **BinaryFormatter retirement.** The practitioner correctly identifies BinaryFormatter as a canonical example of deserialization-as-arbitrary-code-execution and notes it was permanently disabled in .NET 9 [MS-BINARYFORMATTER-NET9]. This is accurate — Microsoft's deprecation-then-removal sequence ran from .NET 5 (first obsoleted) through .NET 9 (execution throws NotSupportedException), specifically because the design had no safe usage pattern for untrusted data.

- **Dynamic and reflection injection risks.** The practitioner correctly identifies `dynamic`, `System.Reflection`, and `System.Reflection.Emit` as code injection vectors when applied to user-controlled data. "Applications that use these to execute user-controlled code paths introduce code injection vulnerabilities that the type system cannot protect against" is accurate.

**Corrections needed:**

- **NativeAOT's security benefit is overstated.** The apologist writes: "NativeAOT reduces the JIT attack surface: there is no JIT compiler at runtime that could be exploited to execute attacker-influenced code generation" [MS-NATIVEAOT]. The realist repeats the claim. This is technically true but significantly overstated as a security motivation. JIT compiler exploitation as an attack vector against the CLR's own JIT is essentially undocumented in the .NET CVE record — there is no known exploitation of CLR JIT compilation to execute attacker-influenced code generation in production systems. NativeAOT's real benefits are operational: startup time reduction (100–200ms versus 1–4 seconds for JIT-compiled services) and smaller binary footprint, not security surface reduction. Council members should not present a fringe theoretical security benefit as a significant motivation for NativeAOT adoption, or do so only with appropriate evidence that JIT exploitation is a real threat in the deployment model being discussed.

- **The detractor overstates what CVE-2025-55315 implies structurally.** The detractor frames the CVSS 9.9 HTTP request smuggling vulnerability as "a warning sign, not an isolated incident," and uses two 2025 CVEs (both in ASP.NET Core auth/request infrastructure) to imply structural security weakness. This inference requires comparative support that the detractor does not provide. A single high-CVSS vulnerability — even in a security-sensitive subsystem — is not evidence of structural weakness without a baseline: how does ASP.NET Core's rate of high-CVSS CVEs compare to Spring Security, Rails, Django, or Express per year and per deployed-instance? Without that comparison the structural claim is speculation. Both cited CVEs are real; the structural implication is not established by the evidence presented. The detractor should either supply the comparative CVE density data or moderate the claim to: "two high-severity CVEs in the same subsystem within seven months warrants monitoring."

- **NRT false-confidence as a security risk is scoped too broadly.** The detractor writes: "If the method dereferences url without a null check — reasoning that the type annotation guarantees it is non-null — the result is a NullReferenceException... If the null dereference is in a validation or authentication path, the consequence is a security bypass." The final conditional ("if... in a validation or authentication path") carries most of the security weight but is buried. The primary consequence of NRT false-negatives is NullReferenceException, which surfaces as an unhandled exception, a 500 response, or a process crash — a reliability and DoS concern, not a security bypass in the general case. The specific path to a security bypass requires null to propagate silently past a critical gate, which is a narrower failure mode than the general framing implies. Additionally, the PVS-Studio citation [PVS-STUDIO-NRT] referenced in the detractor document does not appear in the research brief's verified reference set. This source should be verified and a retrievable URL provided before the council relies on it in the consensus report.

- **The MSRC-2019 70% figure needs careful attribution.** Multiple council members cite the Microsoft research establishing that ~70% of Microsoft's CVEs are memory safety issues, with the implication that C# users avoid this category. This is accurate as context — the figure applies specifically to Microsoft's C/C++ codebases — and the implication that C# avoids memory corruption in managed code is correct [MSRC-2019]. However, the 30% of CVEs that are not memory safety issues (logic errors, auth bugs, input handling) are precisely what appear in C#'s own CVE record. The comparison should be explicit: C# eliminates the memory corruption category, not vulnerability exposure overall. The apologist's use of the figure edges toward implying C# has 30% of C/C++'s risk profile, which is not what the data establishes.

**Additional context:**

- **XSS prevention — a major security ergonomics win not covered by any council member.** ASP.NET Core's Razor view engine HTML-encodes all output by default. Developers must explicitly use `@Html.Raw()` to suppress encoding [MS-XSS-RAZOR]. This means Razor templates are structurally safe against reflected and stored XSS without developer vigilance — the equivalent of React JSX's `dangerouslySetInnerHTML` pattern. PHP's default output is not HTML-encoded (requiring `htmlspecialchars()`); old ASP.NET Web Forms similarly was not safe by default. ASP.NET Core made the correct change when redesigning the framework. This is a genuine security ergonomics achievement, and its complete omission from all five council perspectives is the largest gap in the Section 7 analysis.

- **CSRF protection — built-in but not universal.** ASP.NET Core's anti-forgery token system is automatically applied to Razor Pages POST/PUT/DELETE/PATCH endpoints [MS-ANTIFORGERY]. For Minimal APIs and `[ApiController]` REST endpoints, CSRF protection is not required by default (the framework assumes SameSite cookie policies or explicit token headers instead). This is a reasonable design choice for API endpoints but can expose endpoints when developers choose the API model without understanding the CSRF assumptions behind it. The council missed this differentiation entirely.

- **XML External Entity (XXE) attack surface.** Beyond BinaryFormatter (correctly retired), `XmlDocument` with an active `XmlResolver` can be vulnerable to XXE injection when processing untrusted XML. In older .NET Framework versions, `XmlDocument` resolved external entities by default. .NET Core changed the default to null (disabled), which is the secure default [MS-XXE]. Applications processing untrusted XML that explicitly set `XmlResolver` to enable resolution, or that use older XML processing APIs in .NET Framework compatibility mode, should be assessed for XXE exposure. The council's deserialization discussion stops at BinaryFormatter.

- **`Random` vs. cryptographic randomness.** `System.Random` is seeded from the current time and is not cryptographically secure. `System.Security.Cryptography.RandomNumberGenerator` (or its static convenience methods `RandomNumberGenerator.GetBytes()`, `RandomNumberGenerator.GetInt32()`) is the correct API for security-sensitive randomness. C# provides both but the easy-to-reach API is the insecure one. The distinction between security-safe and general-purpose random generation is not surfaced by naming convention or IDE guidance by default. Languages with a single well-designed secure-by-default random API (Python's `secrets` module as the security-recommended path) avoid this class of developer error.

- **SSRF via HttpClient.** The standard `HttpClient` does not restrict outgoing connections by default. In cloud-hosted multi-tenant environments, SSRF attacks where user-controlled input influences outgoing HTTP request targets can reach cloud metadata APIs (e.g., AWS IMDS at 169.254.169.254, Azure IMDS at 169.254.169.254) unless specific networking restrictions are applied externally. The framework provides no default protection against this class of attack. This is not a C# language deficiency but is a relevant gap in ASP.NET Core's security ergonomics surface.

- **Roslyn security analyzers.** The `Microsoft.CodeAnalysis.NetAnalyzers` package (included in .NET 5+ SDKs) contains security-specific analyzers: CA2100 (SQL injection review), CA3001 (XSS), CA3002 (XPath injection), CA3003 (file path injection), CA3075 (insecure XML), CA3077 (insecure XSLT), and others [MS-SEC-ANALYZERS]. These analyzers perform taint-like analysis over Razor and API call patterns. They are not enabled at the warning-level by default in most project templates; enabling them requires explicit `.editorconfig` or project property configuration. The council does not mention the security-specific analyzer set, which represents a meaningful language-ecosystem security control.

**Missing data:**

- **No CVE count with methodology.** No council member provides a systematic CVE count for .NET Core or ASP.NET Core with a stated query methodology, date range, and version scope. CVEDetails.com [CVEDETAILS-DOTNET] was cited in the research brief as a data source but no numbers appear in the council documents. For the consensus report, the gap should be addressed: how many CVEs does .NET Core have per year, how are they distributed by severity (CVSS), and what is the breakdown by vulnerability category (memory, logic, auth, input handling)? Without this data, the security profile section relies entirely on illustrative examples, which invites selection bias.

- **No comparison to peer frameworks.** Spring (Java), Rails (Ruby), Django (Python), and Express (Node.js) all have CVE records that could be normalized against ASP.NET Core's. The council makes no such comparison, leaving the reader unable to assess whether C#'s framework-level CVE profile is better, worse, or comparable to peer managed-language web frameworks operating at similar deployment scale.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- **NRT as compile-time annotation, not runtime enforcement.** All council members correctly state that NRT does not change runtime behavior — it is an annotation system verified at compile time. The apologist's framing of this as a deliberate trade-off (backward compatibility over runtime enforcement) is accurate: enforcing non-nullability at runtime would break reflection, serialization, COM interop, and any code passing null through unannotated API boundaries. This was the correct choice for ecosystem survival.

- **Reified generics as a type safety improvement over Java's erasure.** The apologist correctly identifies reified generics as a structural safety improvement — generic type arguments are preserved at runtime, enabling accurate `is`-type checks and eliminating the class of `ClassCastException` bugs that Java's type erasure can produce through unchecked cast combinations. For security-relevant code, this means generic-based APIs like `Dictionary<string, ClaimsPrincipal>` and `List<string>` are genuinely distinct at runtime, and type confusion between them produces a caught exception rather than silent data misinterpretation.

**Corrections needed:**

- **NRT false-confidence security framing needs tightening.** As noted under Section 7: the detractor's claim that NRT annotation errors can produce security bypasses is theoretically possible but overbroadly stated. The specific path for an NRT false-negative to enable a security bypass requires: (1) an NRT annotation asserts non-null, (2) null is passed from unannotated code, reflection, or dynamic dispatch, (3) null reaches a security decision without an intermediate null check, (4) the NullReferenceException occurs after the security gate rather than propagating as an exception before it. Code that performs security checks like `if (user.HasPermission("admin"))` is not vulnerable to null-based security bypass unless the NullReferenceException is somehow swallowed between the null value and the check. In most realistic authentication paths, null propagation produces an exception visible in logs before authorization is granted.

**Additional context:**

- **Covariant array soundness hole.** C# inherits the unsound covariant array rule: `string[] arr = new string[5]; object[] objs = arr;` is legal. Writing `objs[0] = 42` throws `ArrayTypeMismatchException` at runtime. This is a longstanding type soundness gap — C# arrays are not type-safe in the strong sense. Generic collections (`List<T>`, `IEnumerable<T>` with proper variance annotations) do not share this problem. In security terms, the consequence is a potential runtime crash in code that relies on array type guarantees — a DoS vector rather than a type confusion exploit in managed code, since the CLR enforces the check at the point of assignment.

- **Generic covariance is sound for the supported cases.** C# 4.0's covariant (`out`) and contravariant (`in`) type parameters for interfaces and delegates are sound: `IEnumerable<string>` is assignable to `IEnumerable<object>` because the interface is read-only covariant, and no unsound write can be performed through the upcast. The soundness gap is specifically in arrays, not in the variance system for generic interfaces.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- **GC prevents use-after-free in managed code.** Correct. The garbage collector's reachability-based reclamation ensures that no live reference can be dangled. This is an unconditional structural guarantee in managed code.

- **`unsafe` blocks as the raw pointer boundary.** The council correctly identifies that `unsafe` code is required for raw pointer access and is auditable through the `/unsafe` compiler flag requirement.

**Corrections needed:**

- **P/Invoke bypasses managed safety without requiring the `unsafe` keyword.** This is the most significant factual gap in Section 3 across all council documents. P/Invoke (calling native functions via `[DllImport]` or `[LibraryImport]`) does not require the `unsafe` keyword at the call site or the `/unsafe` compiler flag at the project level. You can declare and invoke a P/Invoke signature in fully managed code, and the interop layer crosses into native memory without any `unsafe` marking [MS-PINVOKE]. Native code called via P/Invoke can perform unchecked memory operations — it is outside the CLR's safety guarantees — but the call site bears no `unsafe` marker. This is a significant blind spot in the "grep for unsafe" audit strategy that multiple council members recommend. Security reviewers need a separate strategy for P/Invoke entry points: grep for `[DllImport]` and `[LibraryImport]` attributes, review the function signatures and marshaling attributes, and ensure argument validation occurs before native calls.

**Additional context:**

- **`Span<T>` as a safety improvement that eliminates some `unsafe` need.** `Span<T>` (C# 7.2+) and `ReadOnlySpan<T>` provide safe, bounds-checked access to contiguous memory regions — including stack-allocated buffers (`stackalloc`) — without requiring `unsafe` code [MS-SPAN]. The CLR validates span bounds at slice time and at element access time. Code that previously required `unsafe` pointer arithmetic to work with sub-arrays or stack-allocated buffers can now use `Span<T>` with full safety guarantees. For security purposes, span-based APIs are preferable to unsafe pointer APIs: they preserve memory safety while providing the zero-copy performance characteristics of raw pointer access.

- **`ref struct` and stack-only constraints.** `Span<T>` is a `ref struct`, which means it cannot escape the stack, cannot be boxed, and cannot be stored in heap-allocated fields. The compiler enforces these constraints statically. This is a type-system mechanism for preventing a class of use-after-stack bugs without requiring a borrow checker. It is a meaningful precedent: safety properties can sometimes be enforced through structural type constraints rather than linear type systems.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- **No structural data race prevention in managed C#.** Unlike Rust's ownership model, C# does not prevent data races at compile time. Multiple threads can concurrently read and write the same field without language-enforced synchronization. The council acknowledges this implicitly in discussions of `async/await` pitfalls and lock patterns.

- **`async/await` reduces shared state contention but does not eliminate it.** The practitioner correctly identifies that the async model eliminates thread-per-request shared state but does not address concurrent requests accessing the same mutable service state.

**Corrections needed:**

No significant factual corrections in this section; the council's coverage is thin but not wrong. The section is underweighted relative to its security relevance.

**Additional context:**

- **TOCTOU races as a web application security vector.** Time-of-check-to-time-of-use (TOCTOU) races are a real security concern in concurrent C# web code that the council did not address. If a security check is performed asynchronously and the checked state can be mutated by a concurrent request between check and use, the security check is unsound. C#'s `async`/`await` model can obscure this risk: code that looks sequential in an `await` chain may interleave with concurrent requests at every `await` boundary. ASP.NET Core's scoped DI lifetime mitigates some of this (each request gets its own scope), but developers who share mutable state across scopes or in singleton services bypass this protection. This is a C# concurrency security ergonomics problem — the language makes TOCTOU races easy to introduce by accident.

- **`Thread.Abort()` removal improves atomicity guarantees.** `Thread.Abort()` was removed in .NET Core because it could interrupt critical sections mid-execution, leaving invariants broken. Its removal means that `lock` blocks and `Monitor.Enter/Exit` pairs are no longer at risk from asynchronous thread termination violating atomicity contracts. This is a meaningful security improvement for code that uses locking for access control or state consistency.

---

### Other Sections (security-relevant flags)

**Section 6 (Ecosystem and Tooling) — Supply chain controls:**

The council's supply chain discussion is accurate. Two additions are warranted:

- **Package provenance is incomplete.** NuGet package signing (author signatures) provides integrity guarantees — the package has not been tampered with since signing — but not provenance guarantees. You cannot prove from a signed package alone that the binary was produced from the stated source repository. Sigstore-based attestation for NuGet packages (analogous to Python Trusted Publishing, which allows PyPI to cryptographically attest that a package was built from a specific GitHub Actions workflow on a specific commit) was under active discussion as of early 2026 but not yet universally available or required. This leaves a gap between package integrity (what signing provides) and package provenance (whether the binary matches the source).

- **Reproducible builds are not universal.** The NuGet ecosystem does not have universal reproducible build requirements. A package whose binary output differs between builds from the same source cannot be independently verified. Organizations with stringent supply chain requirements must independently verify or rebuild packages from source — a process that most C# shops do not perform. The Rust ecosystem's `cargo-vet` tool and the Go ecosystem's checksum database approach both provide stronger reproducibility guarantees than NuGet's current tooling.

**Section 8 (Developer Experience) — Security ergonomics:**

- **The "secure by default" trajectory.** ASP.NET Core's progressive hardening of defaults represents a genuine design direction: HTTPS redirection middleware added by default in project templates, HSTS headers configured for production environments, `SameSite=Lax` cookies as the default cookie policy, and Razor's HTML encoding on by default. The framework is moving toward "secure if you use defaults" more consistently than .NET Framework did. This trajectory is worth acknowledging in the security profile.

- **Roslyn security analyzers are a meaningful but underused control.** The `.NET security code quality rules` included in the .NET SDK's built-in analyzers (CA2100, CA3001–CA3147) cover SQL injection review, XSS, XPath injection, file path injection, insecure XML, and XSLT [MS-SEC-ANALYZERS]. These are not widely discussed as a security control, and they require explicit enablement. The council mentions Roslyn analyzers for code quality but not for the security-specific rule set, which is a meaningful omission.

---

## Implications for Language Design

**1. Memory safety shifts vulnerability classes — and the new classes require different mitigations.**

C#'s managed execution model definitively eliminates memory corruption CVE categories. This is a genuine structural achievement. But the vulnerability surface migrates to logic errors, authentication state bugs, and API misuse patterns that the type system cannot detect. CVE-2025-55315 and CVE-2025-24070 are the evidence. Language designers should not pitch memory safety as a security guarantee without immediately addressing the vulnerability classes that survive managed execution. "Memory safe" and "application secure" are separated by a large gap that the framework layer, not the language layer, must close.

**2. Framework-level security ergonomics have larger real-world impact than language-level guarantees.**

Razor's default HTML encoding, ASP.NET Core's built-in anti-CSRF tokens, Entity Framework Core's parameterized query generation, and HTTPS-by-default project templates have collectively prevented more vulnerabilities than any language type system feature. The practical security of a language ecosystem is determined more by whether the secure path is the easy path than by what the compiler enforces. Language and framework designers should evaluate security ergonomics — what is the default behavior when a developer takes the simplest approach? — at least as carefully as formal type system guarantees.

**3. Opt-in safety annotation creates a false-safety gradient during migration.**

NRT was introduced as opt-in to avoid breaking the existing ecosystem. The result is a language where annotated code makes safety claims that the runtime does not enforce, unannotated code makes no claims, and the boundary between them is invisible to consumers of a library. Developers working in annotated code can make incorrect safety assumptions when calling into unannotated APIs. Languages that add safety annotations to existing unsafe-by-default type systems must address the annotation boundary problem explicitly: the annotation/unannotated interface is where the safety guarantee degrades silently. The Java ecosystem faces the same problem with `@Nullable`/`@NonNull` annotations that are library-defined rather than language-defined.

**4. Auditable escape hatches are better than invisible ones — but the audit surface must be complete.**

C#'s `unsafe` keyword plus `/unsafe` compiler flag creates a mandatory disclosure mechanism for code that opts out of managed safety guarantees. The grep-for-unsafe audit is practical and effective for managed memory operations. However, P/Invoke does not require the `unsafe` keyword, which means the recommended audit strategy has a documented blind spot. Language designers who provide managed/unmanaged interop must decide whether interop call sites should require an explicit unsafe declaration at the call site (stronger, more auditable) or only at the function signature (current C# position, less auditable). For languages where security review is a requirement, requiring unsafe annotation at every call site that crosses into unmanaged memory is the more defensible design.

**5. Abandoned security features should be removed promptly and documented thoroughly.**

Code Access Security's removal from .NET Core is a case study in the correct handling of a failed security feature. CAS was too complex to configure correctly, too easy to bypass, and primarily generated false confidence. The decision to remove rather than repair was correct. The lesson: when a security mechanism consistently generates false assurance rather than genuine protection, it is actively harmful — developers relying on it are less secure than developers who know it does not exist. Removed security features need explicit migration documentation, not just removal notices, because the detection of their absence (developer guidance referencing them, books citing them, Stack Overflow answers recommending them) persists for years.

**6. Supply chain security is a language ecosystem property, not a developer discipline.**

The NuGet supply chain attacks document threat actors who invest in understanding the .NET runtime: JIT-hooking attacks specific to the CLR's execution model, time-delayed logic bombs embedded in extension methods. The defensive measures that work at scale — mandatory package signing, CI-integrated vulnerability scanning, SBOM generation, source-to-binary provenance attestation — are ecosystem infrastructure properties. Language ecosystem designers should build supply chain security into the toolchain as default-on capabilities. NuGet Audit's enablement by default in .NET 8 is the right direction; reproducible builds and Sigstore-based provenance attestation are the remaining gaps that warrant the same treatment.

**7. Insecure APIs should be removed, not deprecated alongside safe alternatives.**

BinaryFormatter's retirement trajectory — years of deprecation warnings, then disabled-by-default, then permanently disabled in .NET 9 — took over a decade from first security advisories to elimination. The safe alternative (System.Text.Json) coexisted with BinaryFormatter for years, and developers continued using the familiar API. The lesson: when an API has no safe usage pattern for untrusted data, removing it is more effective than providing a safer alternative alongside it. Secure alternatives should replace insecure defaults, not coexist with them. Every year of coexistence is a year of new production code taking the dangerous path.

---

## References

[CSONLINE-SMUGGLING] "Critical ASP.NET core vulnerability earns Microsoft's highest-ever severity score." CSO Online, October 2025. https://www.csoonline.com/article/4074590/critical-asp-net-core-vulnerability-earns-microsofts-highest-ever-severity-score.html

[CVEDETAILS-DOTNET] ".NET Core Security Vulnerabilities." CVEDetails.com. https://www.cvedetails.com/product/43007/Microsoft-.net-Core.html

[CYBERPRESS-WALLET] "Malicious NuGet Package Masquerades as .NET Library to Steal Crypto Wallets." CyberPress, July 2025. https://cyberpress.org/malicious-nuget-package/

[HACKERNEWS-60PKG] "60 New Malicious Packages Uncovered in NuGet Supply Chain Attack." The Hacker News, July 2024. https://thehackernews.com/2024/07/60-new-malicious-packages-uncovered-in.html

[HACKERNEWS-LOGICBOMB] "Hidden Logic Bombs in Malware-Laced NuGet Packages Set to Detonate Years After Installation." The Hacker News, November 2025. https://thehackernews.com/2025/11/hidden-logic-bombs-in-malware-laced.html

[MS-ANTIFORGERY] "Prevent Cross-Site Request Forgery (XSRF/CSRF) attacks in ASP.NET Core." Microsoft Learn. https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery

[MS-BINARYFORMATTER-NET9] "BinaryFormatter Obsoletion Strategy." dotnet/designs GitHub. https://github.com/dotnet/designs/blob/main/accepted/2020/better-obsoletion/binaryformatter-obsoletion.md

[MS-CAS-REMOVED] "Code Access Security is not supported or honored by the runtime." Microsoft documentation. https://learn.microsoft.com/en-us/dotnet/core/compatibility/core-libraries/2.0/code-access-security

[MS-NATIVEAOT] "Native AOT deployment overview." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/

[MS-NRT] "Nullable reference types — C#." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/nullable-references

[MS-PINVOKE] "Platform Invoke (P/Invoke) — .NET." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke

[MS-SEC-ANALYZERS] ".NET security code quality rules." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings

[MS-SPAN] "Memory and span-related types." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/standard/memory-and-spans/

[MS-UNSAFE] "Unsafe code, pointers to data, and function pointers — C# reference." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/unsafe-code

[MS-XXE] "CA3075: Insecure DTD processing in XML." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3075

[MS-XSS-RAZOR] "Prevent Cross-Site Scripting (XSS) in ASP.NET Core." Microsoft Learn. https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019.

[MSRC-55315] "CVE-2025-55315 — Microsoft Security Advisory." Microsoft Security Response Center. https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-55315

[NUGET-ENTERPRISE] "NuGet in the Enterprise, in 2025 and Beyond." Inedo Blog. https://blog.inedo.com/nuget/nuget-in-the-enterprise

[OFFSEQ-NUGET] "Four Malicious NuGet Packages Target ASP.NET Developers With JIT Hooking." OffSeq Threat Radar, August 2024. https://radar.offseq.com/threat/four-malicious-nuget-packages-target-aspnet-develo-3558d828

[VERITAS-24070] "Impact of CVE-2025-24070 affecting Microsoft .NET Core." Veritas Support. https://www.veritas.com/support/en_US/article.100074332
