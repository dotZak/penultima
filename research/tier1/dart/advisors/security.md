# Dart — Security Advisor Review

```yaml
role: advisor-security
language: "Dart"
agent: "claude-agent"
date: "2026-02-28"
```

---

## Summary

Dart's core security story is structurally accurate: managed memory eliminates the classes of vulnerabilities that dominate C and C++ CVE histories, sound typing prevents type confusion in pure Dart code, and sound null safety (mandatory since Dart 3.0) removes an additional class of runtime failure. These are genuine and significant properties. The council perspectives collectively get this right, and the evidence base in the research brief is correctly interpreted.

However, the council analysis contains several important distortions in scope and methodology that require correction. The most significant is the tendency to present "pure Dart code is memory-safe" as the primary security statement about Dart applications — without adequately accounting for the fact that most non-trivial Flutter apps include substantial native code via `dart:ffi`, and that the plugin model routes all platform API access through that boundary. The security guarantee that applies to Dart code does not apply to Flutter apps as deployed. This is a material distinction, not a footnote. Additionally, the council's CVE analysis lacks the methodological controls required to be meaningful: comparing raw CVE counts across languages without controlling for ecosystem age, deployment scale, and security research investment produces the appearance of a favorable record that may not reflect true vulnerability density.

The supply chain gap — pub.dev's lack of cryptographic package signing — is correctly identified by every perspective but systematically underweighted. Given the deployment context (Flutter apps in financial services, healthcare, and government), the absence of publish-time integrity verification is a significant institutional risk. The async error silencing design (unhandled Future errors dropped in some configurations) is primarily characterized by the council as a developer experience issue; from a security standpoint it is a correctness hazard in any code path where error propagation has security semantics (authentication, authorization, audit logging).

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **Memory safety by construction in pure Dart.** All five perspectives correctly identify that buffer overruns, use-after-free, and dangling pointer vulnerabilities are structurally impossible in pure Dart code. This is accurate: Dart's generational GC manages all pure-Dart allocation; the runtime performs bounds checking on array accesses; there are no pointer arithmetic operations available to pure-Dart code. The Flutter documentation's statement — "Pure Dart code provides much stronger isolation guarantees than any C++ mitigation can provide, simply because Dart is a managed language where things like buffer overruns don't exist" [FLUTTER-SECURITY-FALSE-POSITIVES] — is technically accurate for the constrained scope it describes.

- **Type soundness prevents type confusion.** Since Dart 2.0, the runtime enforces type soundness for pure Dart code. Type casting a value to an incompatible type produces a `TypeError` at runtime rather than reinterpreting memory. The Dart documentation's claim — "A sound type system means you can never get into a state where an expression evaluates to a value that doesn't match the expression's static type" [DART-TYPE-SYSTEM] — is accurate for pure Dart, subject to the covariant generics caveat discussed in the Section 2 review.

- **CVE profile is web-layer, not memory-corruption.** The documented CVEs are accurately characterized: URI backslash parsing inconsistency (authentication bypass vector), HTTP redirect Authorization header leakage (credential exposure to attacker-controlled hosts), and XSS via DOM clobbering in `dart:html` (≤ 2.7.1) [CVEDETAILS-DART]. None involve memory corruption. This profile is consistent with what managed language CVE profiles typically look like once memory management is abstracted away.

- **`dart:html` deprecated.** The apologist's claim that the `dart:html` XSS vulnerability was fixed and the library is now deprecated is accurate [DART33-RELEASE]. The deprecation was announced in Dart 3.3 (February 2024) and the library is scheduled for removal in late 2025 in favor of `package:web` and `dart:js_interop`.

- **pub.dev lacks cryptographic package signing.** All five perspectives correctly identify this gap [OSV-SCANNER-DART]. The OSV scanner integration provides reactive vulnerability advisory lookups; it does not provide proactive integrity verification at publish time.

**Corrections needed:**

- **"Low CVE count" requires methodological qualification.** The council presents Dart's limited CVE record as evidence of security quality without applying necessary controls. CVE counts across languages are not directly comparable without accounting for: (1) ecosystem age (Dart's modern managed-language era begins in 2018 with Dart 2.0; its production deployment scale grew substantially after 2021); (2) deployment surface area (Dart has a smaller server-side footprint than Java, PHP, or Python, reducing the attack surface that adversaries probe); (3) security research investment (languages with larger security research communities generate more CVEs through more active scrutiny, not because they are necessarily less secure). A language with three published CVEs and minimal server-side deployment is not straightforwardly more secure than a language with fifty CVEs and twenty years of scrutiny under internet-facing workloads. The council — particularly the apologist — should not present the raw count as conclusive evidence. Unverified: there is no Dart-specific CVE evidence file in this project, and the council's claims rest on a single undated CVE Details database query [CVEDETAILS-DART] without stated methodology.

- **The apologist's isolate isolation claim is partially incorrect in scope.** The apologist states: "In a Flutter application where third-party plugins run in separate isolates, this means that a vulnerable plugin cannot directly corrupt the main application heap." This is not accurate as stated. Flutter's plugin model routes platform API access through platform channels — the native code in a plugin runs in the host process (Android JVM or iOS/macOS process), not in a Dart isolate. The Dart isolate isolation property isolates *Dart code running in separate isolates*; it does not isolate *native code in the same process that was invoked via dart:ffi or platform channels*. A vulnerable native library loaded into the Flutter process via a plugin can still corrupt the Dart heap, because both share the same process address space. This is a security boundary claim that does not hold in the common plugin deployment model.

- **The Authorization header leakage CVE is more serious than the council represents.** The detractor flags this correctly: an HTTP client that forwards `Authorization` headers to cross-origin hosts on redirect is a fundamental credential theft vulnerability. Any application using `HttpClient` with bearer tokens to authenticate to one service, receiving a redirect to an attacker-controlled host, would have exposed its credentials. This is not a subtle implementation bug — it is a violation of a basic security invariant (credentials should not cross trust boundaries) that should have been caught in code review. The apologist's framing as "the kinds of vulnerabilities that occur in any active web-interacting runtime library" understates the severity. This is a patch-worthy credential leakage bug, not a routine library maintenance issue.

**Additional context:**

- **The MSRC 2019 "70%" figure requires citation discipline.** Multiple perspectives cite "memory safety issues account for approximately 70% of CVEs" [MSRC-2019]. This figure is from Matt Miller's 2019 BlueHat IL presentation analyzing Microsoft's *own CVEs in their own C/C++ codebase*. It is a specific claim about Microsoft's historical vulnerability profile, not a general claim about all software. Applying it as a universal statement — "this applies to why Dart's memory safety matters" — is legitimate as rhetorical context but should not be presented as a universally applicable statistic. When the detractor and practitioner use it, they are importing a claim about C/C++ systems software and applying it to justify managed language security properties for an application domain. The inference is reasonable but the citation's scope needs to be respected.

- **The `dart:mirrors` AOT ban is primarily a performance/tree-shaking feature.** Multiple perspectives frame the prohibition on `dart:mirrors` in AOT-compiled code as a security feature reducing reflection-based attack surface. This characterization is secondary, not primary. The actual motivation documented in the Dart SDK is that runtime reflection prevents the dead-code elimination that makes AOT compilation viable — the tree shaker cannot safely remove code that might be accessed dynamically. The security benefit of reduced reflection attack surface is a real but incidental byproduct. Presenting it as a deliberately security-motivated design decision overstates the security intent.

- **dart:js_interop and the Wasm path introduce new security boundaries.** The council's security analysis does not address the newer `dart:js_interop` interop model (Dart 3.3+) and the dart2wasm path. When Dart compiles to WebAssembly and calls into JavaScript APIs via `dart:js_interop`, the type safety at the boundary depends on the correctness of the interop declarations. Extension types used for JS interop are compile-time only — if the declared type does not match the actual JavaScript runtime object, type errors can occur that bypass Dart's type system guarantees. This is analogous to how Rust's `unsafe extern "C"` blocks transfer correctness responsibility to the developer. The security implications of incorrect `dart:js_interop` declarations warrant council acknowledgment.

**Missing data:**

- No analysis of the GitHub Advisory Database (GHSA) record for pub.dev packages — distinct from the Dart SDK CVE record, GHSA tracks vulnerabilities in third-party Dart and Flutter packages. For a production security assessment, the package vulnerability record is as important as the SDK record.
- No analysis of Dart's security advisory process response times or patch SLA adherence beyond the stated P0 priority policy [DART-SECURITY-POLICY].
- No assessment of cryptographic library quality in the Dart ecosystem. The `dart:math` `Random` class is not cryptographically secure [DART-CORE-LIBS]; applications requiring cryptographic randomness must use `dart:math`'s `Random.secure()` constructor. This is a documented footgun: developers accustomed to `Random()` for testing may use it in security contexts. The `pointycastle` package provides cryptographic primitives but has had its own vulnerabilities; the ecosystem lacks a single authoritative, audited cryptographic library.
- No analysis of Flutter's HTTPS certificate verification behavior and the degree to which applications can suppress certificate errors — a common mobile application vulnerability class (OWASP MASVS MSTG).

---

### Section 2: Type System (security implications)

**Accurate claims:**

- **Sound type system prevents runtime type confusion in pure Dart code.** Since Dart 2.0's mandatory sound mode, the type system is enforced at runtime. This is accurately presented by all five perspectives.

- **Null safety eliminates null dereferences for non-nullable types.** Mandatory since Dart 3.0, null safety is a genuine security-relevant correctness guarantee. Null pointer dereferences in critical code paths (authentication checks, permission gates) are structurally prevented for non-nullable types.

- **Covariant generics are deliberately unsound.** The detractor's analysis of covariant generics is accurate and important. Dart's `List<Cat>` being assignable where `List<Animal>` is expected is a "deliberate trade-off that sacrifices some type soundness for usability" [DART-TYPE-SYSTEM]. Runtime `TypeError` can result from write operations at covariant use sites. The dart-lang/language repository has an open issue (#753) for use-site variance [DART-VARIANCE-ISSUE-753] that has not shipped.

**Corrections needed:**

- **The security impact of covariant generics unsoundness needs scoping.** The detractor correctly identifies the unsoundness but does not distinguish when it matters for security. Runtime `TypeError` at a covariant write site causes an exception, not silent memory corruption (Dart's runtime type checks prevent heap corruption). The security concern is whether this exception could be caught by an overly broad `catch` block and silently suppressed — a realistic risk in code using bare `catch (e)` patterns. The failure mode is error suppression leading to inconsistent state, not type confusion leading to memory corruption. This distinction matters: the risk is a correctness hazard (like many type system gaps) rather than a direct memory safety violation.

- **`dynamic` as a security concern.** The detractor correctly flags `dynamic` as an inference fallback that creates "apparently typed but actually untyped" code. From a security perspective, this matters in contexts where the type system is being used as a substitute for input validation. If a value falls into `dynamic` due to inference failure, downstream operations on that value proceed without type checking, potentially allowing unexpected values to reach sensitive code paths. However, none of the council documents provide evidence of this failure mode producing actual security vulnerabilities — it remains a theoretical concern without concrete CVE evidence.

**Additional context:**

- **The `late` keyword is correctly identified as a null safety escape hatch.** Every `late` variable is a runtime-checked assertion replacing a compile-time guarantee. In security-sensitive code paths — initialization of cryptographic state, configuration loading before request handling — a `LateInitializationError` that crashes the application can itself be a denial-of-service vector or, if caught, can allow a code path to execute with uninitialized state. The council acknowledges this as an ergonomic concern; the security framing deserves equal attention.

- **No checked exceptions create API contract opacity.** The detractor's analysis is accurate: a function's type signature carries no information about what exceptions it throws. In security-critical code (permission checks, authentication handlers, cryptographic operations), callers cannot determine from the type system what failure modes they need to handle. This is not a memory safety issue, but it is a correctness concern that specifically affects the reliability of error handling in security-relevant code paths. Third-party `Result<T, E>` types from `fpdart` and `result_dart` address this, but they are not standard.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- **Managed memory eliminates memory safety CVE classes in pure Dart.** All perspectives accurately identify that buffer overruns, use-after-free, and dangling pointers cannot occur in pure Dart code. This is the primary security benefit of Dart's memory model.

- **Isolate heap isolation provides fault containment for Dart code.** A bug in one Dart isolate cannot corrupt another isolate's Dart heap. This is architecturally correct and a genuine security property for Dart-code-level fault isolation.

- **FFI boundary introduces unmanaged memory risk.** All perspectives correctly identify that `dart:ffi` native memory allocated via `malloc` is outside the GC's management, requires explicit `calloc.free()` calls, and can produce memory leaks and use-after-free vulnerabilities [DART-FFI-DOCS].

**Corrections needed:**

- **The scope of "memory-safe Dart" in production Flutter apps is systematically overrepresented.** The council consistently frames Dart's memory safety guarantee as applicable to Dart applications, with the FFI boundary noted as an exception. The more accurate framing for production Flutter apps is the reverse: Flutter's rendering engine itself is written in C++ [FLUTTER-ENGINE-GITHUB], all platform API access goes through platform channels backed by native code, and most non-trivial functionality (camera, sensors, maps, payments, biometrics, notifications) is accessed via plugins that contain substantial native code. The "pure Dart is memory-safe" guarantee covers the business logic layer; it does not cover the substantial C/C++ substrate that Flutter apps depend on. A production Flutter app is better understood as a C++ application with a Dart scripting layer than as a memory-safe Dart application with occasional native calls. This does not invalidate Dart's memory safety properties, but it requires more careful scoping.

- **Isolate isolation does not protect against native code in the same process.** As noted in the Section 7 review, isolate isolation applies to Dart heaps, not to native code sharing the same process. A memory corruption bug in a C library loaded via `dart:ffi` (common in plugins) can corrupt the Dart VM's own heap, because both share the process address space. The council's framing that isolates provide a security boundary against plugin bugs is only accurate for Dart-code plugins communicating via `SendPort`, not for native-code plugins operating via `dart:ffi`.

**Additional context:**

- **GC pause timing does not have direct security implications** beyond potential denial-of-service sensitivity in real-time applications. The council correctly identifies GC pauses as a performance concern for 60fps rendering; from a security standpoint, GC pauses can theoretically affect timing-sensitive cryptographic operations (GC-induced timing side channels), but this concern is theoretical for typical Flutter application code.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- **Isolate model structurally prevents data races in Dart code.** The apologist's claim that shared mutable state between concurrent workers is "structurally impossible" in pure Dart is accurate for the current model. Each isolate has a private heap; message passing semantics transfer or copy data [DART-CONCURRENCY-DOCS]. Race conditions on shared mutable state cannot occur in pure-Dart isolate code.

- **The in-development shared memory primitives introduce race conditions.** The detractor accurately notes that dart-lang/language issue #333 and the "shared variables" proposal (mid-2024) are working toward shared-memory multithreading [DART-SHARED-MEMORY-ISSUE-333]. If this ships, the race-condition-free property of the current isolate model will no longer apply to code using shared variables, requiring synchronization primitives. This is a security-relevant architectural transition.

**Corrections needed:**

- **The security benefit of data-race freedom needs scoping to Dart code.** The concurrency model prevents data races in *Dart code*. The Flutter engine's C++ rendering pipeline, platform channel handlers, and native plugin code operate under standard threading semantics and are subject to race conditions. The data race prevention property does not extend across the Dart/native boundary.

**Additional context:**

- **Async error silencing is the most security-relevant concurrency design issue.** No perspective fully characterizes the security implications of Future error silencing. The research brief documents: "Unhandled Future errors by default print to stderr (in debug mode) or are silently dropped (in some configurations)" [DART-FUTURES-ERRORS]. The security framing: in any asynchronous code path where the Future represents a security-sensitive operation — an authentication check, a permission verification, an audit log write, a rate limit enforcement check — a silently dropped Future error means the security control was applied, failed, and the failure was discarded. The code calling the future typically has no way to know the control failed; it may proceed as if the operation succeeded. This is a real security design hazard. It is not hypothetical: applications that swallow authentication errors can inadvertently grant access to failed requests.

  The mitigation is well-documented (install error handlers before Future completion; use `runZonedGuarded` for Zone-level error handling), but the burden is on the developer to apply these patterns everywhere. The "default behavior silently drops errors in some configurations" property is arguably the most dangerous security default in Dart's design.

---

### Other Sections (security-relevant)

**Section 5: Error Handling**

The `Exception` vs. `Error` distinction is convention, not enforcement. A `catch (e)` block catches both. Defensive catch-all patterns in application code can accidentally swallow `AssertionError` or `StateError` instances that indicate programming bugs — including bugs in security-critical code paths. The detractor correctly identifies this; the security implication is that debugging anomalous authorization behavior is harder when the error signals are indistinguishable from recoverable exceptions.

**Section 6: Ecosystem and Tooling (supply chain)**

The absence of cryptographic package signing on pub.dev is the most important supply chain security gap [OSV-SCANNER-DART]. The npm ecosystem has demonstrated that this attack surface is actively exploited: the `event-stream` incident (2018, 2M weekly downloads, malicious code targeting Bitcoin wallet credentials) and multiple `ua-parser-js` compromises demonstrate that signed artifact verification and account-compromise-resistant publishing pipelines are not theoretical concerns. Pub.dev's size (~55,000 packages) is smaller than npm's, but the ecosystem serves financial applications (GEICO), enterprise applications, and automotive infotainment systems (Toyota) — targets with sufficient value to attract supply chain attackers.

The pub.dev package scoring system provides quality signals (documentation, null safety, linting) but does not assess security properties. High pub-score packages can have poor security postures. The OSV integration [OSV-SCANNER-DART] provides advisory-based scanning; the gap between compromise and advisory publication can be days to weeks.

**Section 8: Developer Experience (security ergonomics)**

No perspective directly addresses the central question: Is the secure path the easy path in Dart? The analysis suggests a mixed picture:
- Memory safety: secure by default in pure Dart (secure path is the only path)
- Null safety: secure by default since Dart 3.0 (non-nullable is the default)
- `Random` vs. `Random.secure()`: insecure by default (the common constructor produces a non-CSPRNG)
- `dynamic` as inference fallback: insecure by default (type system protections silently drop)
- Future error handling: insecure by default (errors can be silently dropped without explicit Zone setup)
- Cryptographic APIs: no authoritative recommendation; ecosystem fragmentation leaves developers choosing among unaudited options

The pattern is that Dart's built-in language features tend toward secure defaults, while library and ecosystem choices require active security attention.

---

## Implications for Language Design

**1. "Memory safe" is a scoped claim that must travel with its scope boundaries.**

Dart's memory safety guarantee is genuine and structurally sound — for pure Dart code. The language design lesson is that any managed language that interfaces with native code via FFI faces the same scoping challenge. Languages that accurately communicate the scope of their safety guarantees ("pure language code is safe; FFI code is not") enable developers to reason correctly about their threat model. Languages that allow the guarantee to expand implicitly — through framing, through documentation, through community discourse — create a false sense of security for code that includes substantial native dependencies. The lesson: safety guarantees in language design documentation must be coupled with explicit scope boundaries, and those boundaries must be made structurally visible (separate `unsafe` annotations, FFI-specific linting, etc.) rather than documentarily visible only.

**2. Secure default behaviors matter more than secure capabilities.**

Dart demonstrates a tension between secure defaults and secure capabilities: the language *can* be used securely, but some defaults work against security. `Random()` is the obvious constructor; `Random.secure()` is the secure one. Errors can be silently dropped in async code without Zone error handlers. `dynamic` silently disables type checking on inference failure. The language design lesson is that secure APIs should be the default-reachable path. When a security-critical operation requires knowledge of a non-obvious alternative constructor, runtime configuration, or defensive pattern, security failures correlate with developer experience level, not developer intent.

**3. Error handling completeness and auditability are security properties.**

The Dart Future error silencing design reveals that error handling completeness is a security property, not just a correctness property. Any language where errors can be silently discarded creates code paths where security controls fail silently. The lesson: language-level error handling designs should preserve the ability to guarantee error observability. Rust's `Result<T, E>` with `#[must_use]` on `Result` is an example of a design that makes error discarding visible at compile time. Dart's async error model makes error discarding possible at runtime, with the discarding occurring in configurations that are not development-time observable. This is a language design tradeoff with security consequences.

**4. Supply chain security requires first-class language/toolchain support.**

Pub.dev's lack of cryptographic package signing is a design choice about where supply chain security responsibility resides: with the registry (infrastructure) vs. with the toolchain (language-level verification). The lesson is that as package ecosystems become central to language adoption and production use, supply chain security cannot be retrofitted from the infrastructure layer alone — it requires protocol-level signing (sigstore/Rekor-style transparency logs, or per-package signing keys) that the package manager enforces at install time. Languages whose package managers launched without signing capabilities are accumulating supply chain debt. New language designs should treat publish-time signing and install-time verification as mandatory, not optional.

**5. Concurrent error handling must be as reliable as synchronous error handling.**

Dart's async error model demonstrates that the introduction of `Future<T>` as a first-class return type creates new error observability gaps that do not exist in synchronous code. In synchronous code, an exception propagates up the call stack and reaches a handler or terminates the program. In async code, a Future error requires the developer to explicitly attach handlers; failure to do so can result in silent discard. The lesson: language designers who introduce promise/future types should design the error handling semantics with the same care as synchronous error handling — ensuring that unhandled errors are always observable (logged, re-raised to a supervising context, or caught by a runtime-level handler) and never silently discarded by default.

**6. Type system escape hatches erode the security value of type safety.**

Both `dynamic` (inference fallback) and `late` (null safety escape hatch) demonstrate that type system guarantees are only as strong as their most permissive escape hatch. When inference failure silently defaults to `dynamic`, the type system's security properties are conditionally absent. When `late` defers null checking to runtime, the null safety guarantee is conditionally replaced by a runtime crash. The lesson: type system safety guarantees should have predictable failure modes. Silent fallback to less-safe modes (inference → `dynamic`) is a worse design than explicit opt-in (`dynamic x = ...`). Languages designed with safety as a goal should require explicit, visible annotation for any relaxation of the type system's safety properties.

---

## References

[CVEDETAILS-DART] CVE Details database for Dart SDK. https://www.cvedetails.com/vendor/15543/Dart.html

[DART-TYPE-SYSTEM] "The Dart type system." dart.dev. https://dart.dev/language/type-system

[DART-FFI-DOCS] "C interop using dart:ffi." dart.dev. https://dart.dev/interop/c-interop

[DART-CONCURRENCY-DOCS] "Concurrency in Dart." dart.dev. https://dart.dev/language/concurrency

[DART-FUTURES-ERRORS] "Futures and error handling." dart.dev. https://dart.dev/guides/libraries/futures-error-handling

[DART-SECURITY-POLICY] Dart security policy. GitHub dart-lang/sdk. https://github.com/dart-lang/sdk/security/policy

[DART-CORE-LIBS] "dart:core library." api.dart.dev. https://api.dart.dev/dart-core/dart-core-library.html

[DART33-RELEASE] Moore, K. "New in Dart 3.3: Extension Types, JavaScript Interop, and More." Dart Blog, February 2024. https://medium.com/dartlang/dart-3-3-325bf2bf6c13

[DART-VARIANCE-ISSUE-753] "Support declaration-site variance." dart-lang/language issue #753. https://github.com/dart-lang/language/issues/753

[DART-SHARED-MEMORY-ISSUE-333] "Shared memory multithreading (isolate model relaxation)." dart-lang/language issue #333. https://github.com/dart-lang/language/issues/333

[FLUTTER-SECURITY-FALSE-POSITIVES] "Flutter — Security false positives." Flutter documentation. https://docs.flutter.dev/security/false-positives

[FLUTTER-ENGINE-GITHUB] Flutter Engine (C++ rendering pipeline). GitHub. https://github.com/flutter/engine

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019.

[OSV-SCANNER-DART] "OSV-Scanner: Dart and Flutter support." Google Open Source Security. https://google.github.io/osv-scanner/

[DART-MACROS-UPDATE-2025] Thomsen, M. "An update on Dart macros & next steps." Dart Blog, January 2025. https://medium.com/dartlang/an-update-on-dart-macros-417d1ceed29

[OWASP-MASVS] OWASP Mobile Application Security Verification Standard. https://mas.owasp.org/MASVS/

[GHSA-DART] GitHub Advisory Database — Dart/Flutter ecosystem advisories. https://github.com/advisories?query=ecosystem%3Apub

[NPM-EVENT-STREAM] "I don't know what to say." Dominic Tarr. November 2018. https://github.com/dominictarr/event-stream/issues/116

[DART-VARIANCE-STATIC-SAFETY] "Static safety and variance." dart-lang/language design documentation. https://github.com/dart-lang/language/blob/main/resources/variance-static-safety.md
