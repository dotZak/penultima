# Kotlin — Security Advisor Review

```yaml
role: advisor-security
language: "Kotlin"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
```

---

## Summary

Kotlin's security profile is structurally favorable but frequently overstated. The language eliminates an important class of vulnerabilities by inheriting JVM memory safety — no buffer overflows, no dangling pointers, no use-after-free in pure JVM/Android code — and adds compile-time null safety on top. The historical CVE record for the compiler and standard library is genuinely sparse: six documented vulnerabilities since 1.0, none of which are language-semantic. This is a real advantage. The council is broadly correct on these points, and the claims hold up against the evidence.

Where the council falls short is in adequately accounting for three structural security concerns that emerge from the language's design choices. First, platform types — Kotlin's mechanism for calling into unannotated Java code — create a systematic hole in null safety that is invisible at declaration sites and silent at runtime until a null arrives. Security-critical codepaths through Java interop carry real risk that is often underweighted in reviews. Second, the absence of checked exceptions combined with coroutine-specific exception swallowing patterns (particularly `runCatching` consuming `CancellationException`) creates conditions where security-relevant code can silently stop executing — an underappreciated correctness concern with exploitable consequences in authentication, rate-limiting, and access-control paths. Third, KMP's multi-ecosystem supply chain spans package registries with significantly different security models, and this is not yet adequately addressed by the council's supply chain section.

The council also misses a significant positive: Kotlin's `kotlinx.serialization` library avoids Java's ObjectInputStream/ObjectOutputStream deserialization mechanism, which is one of the most exploited vulnerability classes in the JVM ecosystem (OWASP A8). For teams that adopt it, this is a meaningful structural improvement that reduces the attack surface against insecure deserialization attacks. Overall, Kotlin's security ergonomics are better than Java's — the secure path tends to be the path of least resistance — but the escape hatches (`!!`, platform types, `runCatching`, `GlobalScope`) are all too easy to reach, and the tooling CVE history suggests that security engineering discipline should not be assumed.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **JVM memory safety eliminates an entire vulnerability class.** All five council members correctly identify that JVM-targeted Kotlin code has no buffer overflows, dangling pointers, or use-after-free vulnerabilities. This is accurate. The JVM's combination of bounds-checked array access, garbage collection, and type safety means that the approximately 70% of Microsoft CVEs attributable to memory corruption in C/C++ codebases [MILLER-2019] are simply not present in Kotlin/JVM's threat model. This claim is accurate and well-evidenced.

- **The six-CVE count is accurate but requires interpretation.** CVEdetails.com documents six CVEs for the Kotlin compiler and standard library [CVEDETAILS-KOTLIN]. The research brief correctly categorizes them:
  - CVE-2019-10101, CVE-2019-10102, CVE-2019-10103: MITM via HTTP artifact resolution; fixed in 1.3.30
  - CVE-2020-15824: Script cache in world-readable temp directory; fixed in 1.4.0
  - CVE-2020-29582: `createTempDir()`/`createTempFile()` world-readable; fixed in 1.4.21
  - CVE-2022-24329: Dependency locking gap in KMP Gradle; fixed in 1.6.0
  All are toolchain vulnerabilities, not language-semantic vulnerabilities. This is correctly stated across all council perspectives.

- **The ScienceDirect 2022 Android security study is correctly cited.** The finding that Kotlin null safety reduces null-dereference bugs but does not substantially alter dominant Android vulnerability categories (insecure data storage, improper authentication, insecure network communication) is accurate and appropriately attributed [SCIENCEDIRECT-ANDROID-2022]. The practitioner and realist handle this citation correctly.

- **PGP signing of releases on Maven Central is accurate.** The official Kotlin security documentation confirms this practice [KOTLIN-SECURITY-DOC].

**Corrections needed:**

- **The apologist overstates the comparison to C/C++.** The apologist writes: "Compare this to C or C++, where memory corruption vulnerabilities number in the thousands across the ecosystem." While technically accurate for C/C++, this is not the relevant comparison for Kotlin. Kotlin's primary comparison population is Java and other JVM languages, not C. The relevant comparison is Kotlin vs. Java, where neither language permits memory corruption. The meaningful Kotlin advantage over Java is null safety, not memory safety — Java is also memory-safe by design. Framing six CVEs against "thousands in C/C++" is technically defensible but rhetorically misleading: Java would look equally favorable by this metric.

- **The detractor's framing that the 2019 HTTP CVEs "reflect poorly on JetBrains' security engineering practices" is fair but incomplete.** Serving package manager artifacts over HTTP without verification was indeed a well-understood vulnerability class by 2019 — the Go modules team had addressed it with `GOPROXY` and `GONOSUMCHECK` in 2019 as well. However, context is warranted: Kotlin's build distribution was inheriting Gradle's artifact resolution mechanism, which also had incomplete HTTPS enforcement at that time. The responsibility is partially distributed. The detractor's conclusion (a "pattern of basic security hygiene failures") is accurate in direction; the framing that uniquely indicts JetBrains understates Gradle's co-responsibility.

- **No council member identifies the most significant missing security positive: deserialization safety.** Java's `ObjectInputStream`/`ObjectOutputStream` mechanism is one of the most heavily exploited vulnerability classes in JVM-ecosystem software — it accounts for critical RCE vulnerabilities across Apache Commons Collections, Spring, Struts, and many others. Kotlin's `kotlinx.serialization` library [KOTLINX-SERIALIZATION-GITHUB], the idiomatic serialization mechanism for Kotlin (particularly for KMP), does not use Java object deserialization. It operates on Kotlin-annotated data structures with compile-time code generation and does not invoke arbitrary object constructors. Teams that migrate from Java's `ObjectInputStream`-based serialization to `kotlinx.serialization` are structurally removing a major vulnerability class. This is a real security improvement that no council member identifies.

**Additional context:**

- **The CVE-2020-29582 (createTempFile) vulnerability is worth more attention.** The deprecated `kotlin.io.createTempFile()` and `createTempDir()` functions placed files in the system temp directory with world-readable permissions. Beyond information exposure, this class of vulnerability can be exploited for symlink attacks or race conditions in setuid environments. The fix (deprecating the functions and replacing them with `java.nio.file.Files.createTempFile()` with secure permissions) is correct. However, the deprecation does not automatically update existing code; teams with pre-1.4.21 practices embedded in their codebase should audit explicitly.

- **The dependency confusion attack surface from CVE-2022-24329 is underexamined.** The inability to lock KMP dependencies in Gradle (fixed in 1.6.0) exposed projects to dependency confusion: an attacker who publishes a malicious artifact with a higher version number in a public registry could have it resolved in place of a private artifact [DEPENDENCY-CONFUSION-2021]. Alex Birsan's February 2021 paper on dependency confusion attacks showed this affected multiple major companies. The 2022 fix is in place, but teams on Kotlin <1.6.0 or with KMP configurations that do not use Gradle's dependency locking should audit.

**Missing data:**

- No public audit of Kotlin's security posture from an independent security firm has been identified in available sources. JetBrains' security disclosure page is minimal [KOTLIN-SECURITY-DOC]. The absence of a published independent security audit is worth flagging — at Kotlin's adoption scale (dominant language for Android, primary language for hundreds of millions of devices), a formal security audit of the compiler and standard library would be appropriate.

- The research brief and council members cite CVEdetails.com but do not query NVD or GHSA directly for a complete picture. NVD and GHSA may include advisories not captured by CVEdetails.com's product-level categorization, particularly for `kotlinx` libraries (coroutines, serialization) which are separate artifacts. A complete NVD query for `org.jetbrains.kotlin` and `org.jetbrains.kotlinx` would be needed for a comprehensive picture. This review relies on the research brief's documented six CVEs as the available baseline.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- **Null safety genuinely reduces null-dereference as a security concern.** The compiler's enforcement that nullable types cannot be dereferenced without explicit handling removes an entire category of runtime-null security bugs — including null dereference in access control paths (e.g., `user.role.permissions` where `role` could be null) and null-caused silent failures in cryptographic code (e.g., `key.bytes` returning null treated as an empty array). The practical Android evidence supports this: Google's own retrospectives attribute lower crash rates in Kotlin vs. Java Android code partly to null safety [ANDROID-5YRS-2022].

- **Smart casts reduce defensive boilerplate that developers often skip.** After a `is` check or null check, the compiler narrows the type automatically. This is a security ergonomics win: when the safe path is the easy path, it gets taken. Smart casts reduce the temptation to use unsafe casts (`as`) with embedded null assumptions.

- **Sealed classes with exhaustive `when` prevent unhandled state.** In authentication flows, permission checks, or error dispatchers modeled as sealed hierarchies, compiler-enforced exhaustiveness means that adding a new authentication state or error type immediately fails all `when` expressions that haven't been updated. This is a security-positive property: incomplete handling of security states cannot accidentally slip into production.

**Corrections needed:**

- **Platform types are understated as a security risk by most council members.** The apologist frames platform types as an "honest cost" with "visible seams." The practitioner is more accurate: "In security-relevant code — authentication token extraction, permission checks, cryptographic key handling — a null return from a Java API treated as non-null by Kotlin can produce silent failures: an empty string where a token was expected, a zero where a key length was expected." This framing correctly identifies the security-specific risk.

  The structural problem: platform types are not annotated in source code. A developer reading `val token = javaLib.getToken()` cannot tell from context that `token` is a platform type — they must consult the Java source or know the library to understand that null safety is not guaranteed. The `T!` notation appears only in IDE tooltips, not in source. A developer who is not looking for this will write `token.trim()` without a null check and ship it. This is not a small gap in a security-critical codebase; it is a systematic hole at every Java interop boundary.

  For security reviews of Kotlin codebases, the recommended practice is to treat every Java-returning call site as potentially null and require explicit null assertions or null checks at all security-critical boundaries. This advice does not appear explicitly in any council section.

- **The `!!` operator's security implications are underexplored.** The detractor correctly identifies `!!` as problematic but frames it primarily as a code quality concern. The security framing is more precise: `!!` applied to a platform-type result in a security-critical path (token validation, permission checks, input parsing) converts a type-system guarantee into a runtime NPE. An NPE in a permission check may produce a denied result (safe) or an uncaught exception that propagates to an unhandled error handler (potentially unsafe, depending on fallback behavior). In Spring controllers, an unhandled NPE produces a 500 response — which could itself be a denial-of-service vector or leak information through error messages.

**Additional context:**

- **Type system as injection-prevention**: Kotlin's type system does not directly prevent SQL injection, SSRF, or command injection — these are API-level concerns. However, frameworks that build on Kotlin's type system (SQLDelight's type-safe SQL, Exposed's DSL) do prevent SQL injection by construction: queries are assembled from typed Kotlin expressions, not string concatenation. This is an ecosystem-level security advantage enabled by Kotlin's type system features (DSL builders, extension functions, sealed types) rather than language-level enforcement.

- **Generic type erasure has minimal direct security implications** in Kotlin compared to other type system properties. Runtime type erasure (JVM constraint) is more a correctness concern than a security concern in typical application code. No additional security context is warranted here.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- **JVM memory safety is correctly described.** No manual memory management means no buffer overflows, use-after-free, or dangling pointer vulnerabilities in pure Kotlin/JVM code. This is accurate and carries real security weight. The category of vulnerabilities that account for the majority of OS-level CVEs in C/C++ codebases is structurally absent.

- **Kotlin/Native's GC pause characteristics are correctly documented.** The stop-the-world GC without generational collection means Kotlin/Native is less suitable for latency-sensitive security-critical code (e.g., real-time intrusion detection, cryptographic timing-sensitive operations). The realist and practitioner correctly note this limitation.

**Corrections needed:**

- **The ARC interop claim "usually seamless" deserves harder scrutiny from a security perspective.** The Kotlin documentation's assertion that Swift/ObjC ARC integration "generally requires no additional work" is accurate for simple cases [KOTLIN-ARC-INTEROP]. The security concern is in the edge case: reference cycles crossing the Kotlin/Native–Swift boundary can produce memory leaks that are diagnosable only with specialized tooling (Instruments on iOS, Leak Sanitizer). Memory leaks in security-sensitive objects — cryptographic keys, session tokens, authentication credentials held in memory — increase the window during which those objects can be accessed by unauthorized code (e.g., in iOS apps via memory dump tools on jailbroken devices). The interaction between GC and ARC at the boundary should be explicitly tested for any security-sensitive object types in KMP iOS applications. No council member addresses this.

**Additional context:**

- **JVM heap dumps as a security concern**: Kotlin inherits Java's JVM heap dump exposure risk. Sensitive data held in memory (passwords, cryptographic keys, PII) is captured in JVM heap dumps. This is not Kotlin-specific, but teams using Kotlin in security-sensitive server-side contexts should apply the same mitigations as Java teams: minimize the lifetime of sensitive data in memory, use `char[]` (with explicit zeroing) rather than `String` for passwords (since `String` is immutable and cannot be zeroed), and avoid logging thread dumps that capture sensitive variables. These are operational security concerns, not language design flaws, but they are underaddressed in all council perspectives.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- **`GlobalScope.launch` deprecation is a security-positive ergonomic choice.** The detractor and practitioner both correctly identify that `GlobalScope` allows unstructured, lifecycle-independent coroutine launches. Deprecating it in favor of structured scope APIs (which enforce lifecycle boundaries) reduces the risk of operations continuing past their intended context — including security operations that should stop when a session ends or a user logs out.

- **The colored function (`suspend`) approach is correctly identified as a JVM interop constraint.** Elizarov's 2017 argument [ELIZAROV-COLOR-2017] is valid: the JVM ecosystem contains blocking code everywhere, and explicit `suspend` is more honest than pretending otherwise. From a security perspective, the explicit marking is beneficial — developers can see which functions may yield execution and reason about shared state during suspension.

**Corrections needed:**

- **The `runCatching` / `CancellationException` problem has underappreciated security implications.** The detractor correctly identifies this as a production correctness hazard: `runCatching` catches `Throwable`, including `CancellationException`, which is the mechanism by which coroutine cancellation propagates [NETGURU-EXCEPTIONS-2023]. When `CancellationException` is swallowed, a coroutine continues executing after its scope has been cancelled.

  The security framing, which no council member provides: in authentication, rate-limiting, or access-control paths implemented as coroutines, scope cancellation is often how the system enforces a security boundary. If a user session expires and the associated `CoroutineScope` is cancelled, any in-flight authentication check or permission validation in that scope should stop. If `runCatching` is used inside that check and silently swallows the `CancellationException`, the check continues executing in a context where it should have terminated. Depending on the outcome of that check, the result could be posted to a now-invalid UI state or return an incorrect authorization decision.

  This is not a theoretical concern — GitHub issue #1814, open since 2020, tracks the request for a coroutine-safe `runCatching` variant [GH-1814]. The standard library provides no safe alternative. Security-sensitive coroutine code should use a custom `runCatching` that re-throws `CancellationException` explicitly:
  ```kotlin
  inline fun <T> safeRunCatching(block: () -> T): Result<T> =
      try {
          Result.success(block())
      } catch (e: CancellationException) {
          throw e  // Do not swallow
      } catch (e: Throwable) {
          Result.failure(e)
      }
  ```
  No council member provides this guidance.

- **`CoroutineExceptionHandler` scoping is a security-relevant correctness concern.** The detractor notes that installing a `CoroutineExceptionHandler` on a child coroutine does nothing — it must be installed on the root scope. If a developer installing an error handler in an authentication flow places it incorrectly, exceptions from that flow will propagate upward unhandled, potentially triggering a catch-all error handler that does not enforce the right security posture. This is primarily a correctness concern, but in security-critical paths the consequence is material.

**Additional context:**

- **Concurrency and timing attacks**: Kotlin's coroutine model introduces suspension points that could, in theory, create timing side channels in cryptographic operations. If a `suspend` call suspends in the middle of a timing-sensitive comparison (e.g., constant-time HMAC verification), the actual execution time could be influenced by scheduler behavior. For cryptographic operations, teams should use dedicated constant-time comparison functions that do not involve coroutine suspension, and should benchmark timing behavior under concurrent load. This is a specialized concern but worth noting for security-sensitive applications.

- **Thread-safety of shared state**: Kotlin's coroutines do not prevent data races on mutable shared state in the JVM sense — they manage suspension but not exclusion. Code that shares mutable state across coroutines running on different dispatchers requires the same synchronization primitives as Java threads (locks, atomic references, thread-safe collections). The illusion that "coroutines handle concurrency" can lead developers to omit synchronization around shared mutable state that is accessed from coroutines on `Dispatchers.Default` or `Dispatchers.IO`. This is not a Kotlin-specific issue, but the coroutine abstraction can mask the underlying threading model.

---

### Other Sections (Security-Relevant Flags)

**Section 5: Error Handling — Security implications**

The absence of checked exceptions, combined with Kotlin's unchecked exception model, creates a condition where security-relevant exceptions can be silently swallowed. The specific risks:

1. **Empty `catch` blocks**: Without the compiler forcing acknowledgment of specific exception types, `catch (e: Exception) { /* TODO */ }` compiles without warning. In security-critical code paths (authentication, input validation, cryptographic operations), swallowed exceptions can produce silent authorization bypasses.

2. **No explicit propagation operator**: Unlike Rust's `?` operator for `Result`, Kotlin requires developers to explicitly propagate `Result` values through call stacks. The absence of propagation sugar creates pressure toward exceptions, which increases the risk of exception-swallowing in security-critical paths.

3. **`Result<T>` usability limitation**: The documented restriction that `Result<T>` cannot be used as a direct return type of non-inline functions in certain contexts [KOTLIN-EXCEPTIONS-DOC] reduces adoption of the functional error handling model in exactly the contexts — library boundaries, interface return types — where typed error contracts matter most for security auditing.

The practitioner's recommendation (establish explicit error handling conventions per layer, enforce via custom lint rules) is correct and should be adopted for security-sensitive codebases.

**Section 6: Ecosystem and Tooling — Supply chain**

The practitioner raises the most important supply chain concern and deserves amplification: KMP projects that target Android, iOS, and server span at least two package ecosystems (Maven Central, CocoaPods or Swift Package Manager). The security models of these ecosystems differ materially:

- **Maven Central**: PGP signature verification available; artifact checksums required; well-established supply chain security practices; dependency locking via Gradle lockfiles or Gradle Verification Metadata.
- **CocoaPods**: PGP signing not standard; artifact integrity relies on SHA hashes in Podfile.lock; historically weaker supply chain security than Maven Central.
- **Swift Package Manager**: Integrity via cryptographic commit hashes pinned in Package.resolved; no central vulnerability database comparable to NVD/GHSA coverage of Maven artifacts.

Teams deploying KMP to iOS production should apply different — and currently more manual — supply chain verification practices for the iOS dependency tree than for the JVM tree. The dependency confusion attack surface (CVE-2022-24329 pattern) applies differently across these registries, and there is no unified tooling to audit the full cross-platform dependency graph for known vulnerabilities.

Additionally, the Gradle Wrapper (`gradlew`) verification is a supply chain concern that applies to all Kotlin projects, not just KMP. The wrapper JAR (`gradle/wrapper/gradle-wrapper.jar`) is committed to the repository and run as part of every build. JetBrains' documentation does not prominently address verifying the wrapper JAR's integrity, although Gradle itself provides `gradle wrapper --verify` and checksum verification. Teams should verify the Gradle wrapper JAR against the expected SHA-256 hash on every update.

**Section 10: Interoperability — Security implications**

The practitioner correctly identifies KMP's multi-ecosystem supply chain as a concern. An additional interoperability concern not raised by any council member:

The Kotlin/Native-to-Swift interop, currently mediated via the Objective-C bridge, means that Kotlin objects crossing the boundary are handled by Objective-C's runtime, including its method dispatch and memory model. Objective-C's dynamic method dispatch (`objc_msgSend`) is different from Kotlin's static dispatch model. At the security level, this means that Kotlin objects exposed to Swift/ObjC via the bridge can potentially be subject to method swizzling by other Objective-C code in the process. This is a niche concern (relevant only on iOS, only when the app runs alongside third-party SDKs that use swizzling), but security-sensitive objects (authentication managers, cryptographic key stores) should not be exposed via the Objective-C bridge to more code than necessary.

---

## Implications for Language Design

**1. Platform type systems that interact with unsafe neighbors create structural false security signals.** Kotlin's null safety is genuinely valuable, but its interaction with Java's non-nullable-annotated APIs produces a category of invisible safety degradation that is harder to reason about than explicit unsafety. A language that claims null safety must either accept null safety boundaries that are explicit and prominently visible at call sites, or must require annotations on all imported types before they can be used. The platform type compromise — neither requiring annotations nor enforcing safety — is the pragmatic middle ground, but it creates code that reads as null-safe when it is not. Future languages that must interoperate with unsafe neighbors should make the boundary explicit in source syntax (not just IDE tooltips) and should fail loudly (at least via lint) when platform-typed values are used in safety-critical positions.

**2. Exception handling design has underappreciated security implications.** The decision to remove checked exceptions was correct — checked exceptions demonstrably failed to achieve their safety goals in Java — but the replacement mechanisms (sealed classes, `Result<T>`) require explicit adoption and impose cognitive overhead. In security-critical code paths, the path of least resistance (catch broadly, continue) can lead to silent authorization bypass. Language designers who want to eliminate checked exceptions should pair that decision with a first-class propagation operator (like Rust's `?`) that makes the correct pattern (explicit propagation of typed errors) as easy as the incorrect pattern (broad exception catching). Kotlin's `Result<T>` without a `?`-equivalent leaves a gap.

**3. The secure path must be easier than the escape hatch.** Kotlin's `!!` operator, `GlobalScope.launch`, and `runCatching` are all escape hatches that undermine safety properties the language provides. The pattern is consistent: the language provides a correct path (non-nullable types, structured scopes, explicit exception handling) and an easy bypass (`!!`, `GlobalScope`, catch-everything). When the bypass is reachable in one or two characters, production codebases will use it under deadline pressure. Language designers should consider making escape hatches syntactically costly enough to require deliberate choice: more verbose, requiring explicit suppression annotations, or triggering static analysis warnings that are not suppressible without justification. The principle is that safety properties are only as strong as the ergonomics of their escape hatches.

**4. Supply chain security for multi-target languages requires explicit design, not inheriting one ecosystem's practices.** Kotlin Multiplatform's decision to target JVM, native, and JavaScript ecosystems inherits three package registries with different security models. None of those models were designed for cross-registry supply chain verification. A language that targets multiple ecosystems from the start should either mandate a unified package registry with consistent security guarantees (as Rust does with crates.io for pure Rust dependencies) or provide tooling for cross-ecosystem supply chain verification. Leaving each target to use its native ecosystem's tools produces an aggregate security posture weaker than any individual ecosystem's.

**5. Security-aware serialization design eliminates an entire vulnerability class.** Kotlin's `kotlinx.serialization` — by operating on annotated Kotlin types with compile-time code generation rather than Java's ObjectInputStream mechanism — structurally prevents the class of deserialization vulnerabilities that have produced dozens of critical CVEs across the JVM ecosystem. This demonstrates that serialization mechanism choice is a security-critical language design decision. Languages that provide or endorse serialization mechanisms should prefer approaches that do not invoke arbitrary constructor code during deserialization. The lesson generalizes: any language feature that executes user-defined code as a side effect of a data-processing operation (deserialization, reflection, macro expansion) creates an attack surface that a more constrained design can avoid.

**6. Build tooling is part of the security surface of a language, not a separate concern.** Kotlin's CVE history is entirely toolchain CVEs. As languages mature and their core semantics are well-tested, the attack surface migrates to the build system, package registry, and distribution mechanism. Language designers and language maintainers should treat build toolchain security as a first-class responsibility: publishing artifacts over HTTPS, requiring artifact signing, providing dependency locking mechanisms, and auditing the build toolchain on the same schedule as the language runtime. The lesson from Kotlin's 2019 HTTP resolution CVEs is that supply chain security that was "not our code" was still "our vulnerability."

---

## References

[MILLER-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019.

[CVEDETAILS-KOTLIN] "Jetbrains Kotlin security vulnerabilities, CVEs, versions and CVE reports." CVEdetails.com. https://www.cvedetails.com/product/56854/Jetbrains-Kotlin.html?vendor_id=15146

[KOTLIN-SECURITY-DOC] "Security." Kotlin Documentation. https://kotlinlang.org/docs/security.html

[KOTLIN-NULL-SAFETY-DOC] "Null safety." Kotlin Documentation. https://kotlinlang.org/docs/null-safety.html

[KOTLIN-NULL-JAVA-INTEROP] "Calling Java from Kotlin: Null-safety and platform types." Kotlin Documentation. https://kotlinlang.org/docs/java-interop.html#null-safety-and-platform-types

[KOTLIN-ARC-INTEROP] "Integration with Swift/Objective-C ARC." Kotlin Documentation. https://kotlinlang.org/docs/native-arc-integration.html

[KOTLIN-NATIVE-MEMORY-DOC] "Kotlin/Native memory management." Kotlin Documentation. https://kotlinlang.org/docs/native-memory-manager.html

[KOTLIN-NATIVE-MEMORY-UPDATE-2021] "Kotlin/Native Memory Management Update." The Kotlin Blog, May 2021. https://blog.jetbrains.com/kotlin/2021/05/kotlin-native-memory-management-update/

[KOTLIN-EXCEPTIONS-DOC] "Exceptions." Kotlin Documentation. https://kotlinlang.org/docs/exceptions.html

[KOTLINX-SERIALIZATION-GITHUB] "Kotlin serialization." GitHub. https://github.com/Kotlin/kotlinx.serialization

[KOTLINX-COROUTINES-GITHUB] "Library support for Kotlin coroutines." GitHub. https://github.com/Kotlin/kotlinx.coroutines

[NVD-2020-15824] "NVD — CVE-2020-15824." National Vulnerability Database. https://nvd.nist.gov/vuln/detail/cve-2020-15824

[SNYK-CVE-2020-29582] "Information Exposure in org.jetbrains.kotlin:kotlin-stdlib — CVE-2020-29582." Snyk. https://security.snyk.io/vuln/SNYK-JAVA-ORGJETBRAINSKOTLIN-2393744

[GHSA-KOTLIN-2022] "Improper Locking in JetBrains Kotlin — CVE-2022-24329." GitHub Advisory Database. https://github.com/advisories/GHSA-2qp4-g3q3-f92w

[SCIENCEDIRECT-ANDROID-2022] "Taxonomy of security weaknesses in Java and Kotlin Android apps." ScienceDirect (Journal of Systems and Software), 2022. https://www.sciencedirect.com/science/article/pii/S0164121222000103

[ANDROID-5YRS-2022] "Celebrating 5 years of Kotlin on Android." Android Developers Blog, August 2022. https://android-developers.googleblog.com/2022/08/celebrating-5-years-of-kotlin-on-android.html

[ELIZAROV-COLOR-2017] Elizarov, R. "How do you color your functions?" Medium, 2017. https://elizarov.medium.com/how-do-you-color-your-functions-a6bb423d936d

[ELIZAROV-STRUCTURED] Elizarov, R. "Structured concurrency." Medium, 2018. https://elizarov.medium.com/structured-concurrency-722d765aa952

[DEPENDENCY-CONFUSION-2021] Birsan, A. "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." Medium, February 2021. https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

[NETGURU-EXCEPTIONS-2023] "Kotlin Coroutines: Exceptions and Cancellation." Netguru Engineering Blog, 2023. https://www.netguru.com/blog/kotlin-coroutines-exceptions

[GH-1814] "kotlinx.coroutines GitHub issue #1814: Consider adding runCatching that handles CancellationException." https://github.com/Kotlin/kotlinx.coroutines/issues/1814

[GH-1317] "kotlinx.coroutines GitHub issue #1317: SupervisorJob confusion." https://github.com/Kotlin/kotlinx.coroutines/issues/1317

[DEEPSOURCE-KT-W1066] "KT-W1066: runCatching with CancellationException." DeepSource Kotlin Analyzer documentation.

[PHAUER-SEALED-2019] Phauer, M. "Sealed Classes Instead of Exceptions in Kotlin." 2019. https://phauer.com/2019/sealed-classes-exceptions-kotlin/

[KOTLIN-SWIFT-EXPORT-DOC] "Swift export." Kotlin Documentation (Experimental). https://kotlinlang.org/docs/native-swift-export.html

[OWASP-A8-2017] OWASP. "A8:2017 – Insecure Deserialization." OWASP Top Ten 2017. https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization

[JAVACODEGEEKS-2026] "Kotlin Null Safety: Limitations With Java Interoperability." JavaCodeGeeks, 2026.

[EFFECTIVE-KOTLIN-MOSKALA] Moskała, M. *Effective Kotlin: Best Practices*. Kt. Academy, 2022.

[HOARE-2009] Hoare, T. "Null References: The Billion Dollar Mistake." QCon London, 2009.

[GRADLE-FOUNDATION] "Gradle Inc. Joins Kotlin Foundation as First New Member Since Founding by Google and JetBrains." Gradle / Develocity press release. https://gradle.com/press-media/gradle-inc-joins-kotlin-foundation-as-first-new-member-since-founding-by-google-and-jetbrains/
