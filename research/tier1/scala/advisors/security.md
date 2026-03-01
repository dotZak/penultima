# Scala — Security Advisor Review

```yaml
role: advisor-security
language: "Scala"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

Scala's security profile is substantially determined by its JVM platform rather than its own language design — which cuts both ways. The JVM eliminates an entire class of memory corruption vulnerabilities (buffer overflow, use-after-free, heap spray) that account for the majority of critical CVEs in C and C++ systems. That is a substantial structural win inherited at no additional cost. The cost of the same inheritance is Java's serialization mechanism, which has produced some of the JVM ecosystem's most severe historical CVEs, including CVE-2022-36944 — a deserialization gadget chain found not in a third-party dependency but in `scala-library.jar` itself. The council documents this CVE correctly but understates two critical dimensions: the three-year exposure window (Scala 2.13.0, 2019, through 2.13.9, 2022) during which the vulnerability was present in the standard library, and the compounding risk created by Akka Remote's historical default of using Java serialization for cluster communication.

Several council claims require correction or nuancing. The apologist's assertion that typed database interfaces "make parameterized queries the path of least resistance" is empirically backwards — string interpolation with `s"..."` is syntactically identical to safe query construction and is the lower-friction path. Doobie and Slick provide strong type-safe alternatives, but their adoption is not the default and cannot be inferred from the type system alone. The supply chain analysis conflates HTTPS transport integrity with artifact provenance: Coursier's SHA-256 checksum verification confirms that the downloaded artifact matches what Maven Central recorded, but does not verify that the upload to Maven Central came from a legitimate maintainer. This is a meaningful distinction. The security advisor also identifies an underexplored dimension absent from all five council perspectives: Scala 2's unrestricted implicit conversions constituted a covert value-transformation mechanism with direct security implications, and Scala 3's explicit `Conversion` type with required `import` is a genuine language-level security improvement that deserves explicit acknowledgment.

The most significant gap across the council is the absence of analysis around compile-time code execution. Scala macros run arbitrary code in the compiler process during the build. A malicious dependency containing macros can compromise the build environment, exfiltrate secrets from CI, or tamper with generated code — a supply chain attack vector orthogonal to runtime vulnerabilities. No council member addresses this. Additionally, effect system typing (Cats Effect's `IO`, ZIO's `ZIO[R, E, A]`) has underappreciated security auditing value: the explicitness of effects makes it structurally harder for malicious or buggy code to hide unauthorized I/O, and security reviewers can identify effect boundaries as trust boundaries. These are meaningful design dimensions that the council has left unaddressed.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **CVE-2022-36944 characterization**: All five council perspectives correctly identify this as a Java deserialization gadget chain in `scala-library.jar`, CVSS 8.1, patched in 2.13.9 (September 2022). The detractor and historian correctly note that the vulnerability resided in the standard library, not a third-party dependency — a more severe finding than typical transitive-dependency CVEs [CVEDETAILS-SCALA, RESEARCH-BRIEF].

- **JVM memory safety**: The claim that JVM Scala categorically prevents buffer overflow, use-after-free, dangling pointer, and heap spray vulnerabilities is accurate. These vulnerability classes require the ability to write to arbitrary memory addresses, which the JVM's verified bytecode execution model does not permit. The apologist's citation of the MSRC 2019 figure (approximately 70% of Microsoft's CVEs being memory safety issues) is appropriately attributed and contextualizes the scope of what Scala/JVM avoids [MSRC-2019].

- **SQL injection as common issue**: The identification of CWE-89 (SQL Injection) as a documented common vulnerability pattern in Scala codebases is accurate and well-sourced [KODEM-SECURITY]. The council is correct that string interpolation provides no safety over raw string concatenation — `s"SELECT * FROM users WHERE name = '$input'"` and `"SELECT * FROM users WHERE name = '" + input + "'"` have identical injection exposure.

- **Log4Shell cascade**: The description of CVE-2021-44228's impact on the Scala ecosystem is accurate. Log4j was a transitive dependency of many Scala projects; the Scala team published an ecosystem-wide status report [SCALA-LOG4J-2021]. The council is correct that this is JVM ecosystem exposure, not Scala-specific.

- **2025 CVE record**: No CVEs recorded against `scala-lang/scala` in 2025 is accurately sourced from Stack.watch [STACKWATCH-SCALA-2025].

- **Scala Native reintroduces memory safety risk**: The observation that `Ptr[T]` for C interop in Scala Native reintroduces memory corruption risk in a narrow context is accurate and appropriately scoped. Scala Native is not widely deployed in security-sensitive production systems.

**Corrections needed:**

1. **CVE-2020-26238 sourcing is inadequate.** The research brief lists "CVE-2020-26238 (High): Insecure reflection vulnerability in certain Scala versions, potentially enabling remote code execution" and attributes it to `[KODEM-SECURITY]`, a vendor security blog. The apologist reproduces this citation without verification. CVE-2020-26238 does not appear in the NVD database under that identifier as of the research date; it may be mis-attributed or the vendor's description may conflate multiple findings. The council should not have reproduced a CVE claim from a single vendor source without cross-referencing NVD or GHSA. This specific vulnerability claim should be treated as unverified until confirmed in the NVD or GitHub Security Advisory Database [NVD, GHSA].

2. **The exposure window of CVE-2022-36944 is understated.** The historian notes correctly that the vulnerability existed since Scala 2.13.0 (June 2019) and was patched in 2.13.9 (September 2022) — a three-year window during which any Scala application on 2.13.x was potentially vulnerable if receiving attacker-controlled serialized data. The other four council members do not mention this duration. A high-severity vulnerability in the standard library with a three-year exposure window represents a more significant security finding than a promptly-patched CVE, and the council's aggregate treatment of it is insufficiently weighted.

3. **Apologist's claim that typed SQL interfaces "make parameterized queries the path of least resistance" is factually inverted.** Doobie requires explicit adoption and learning of its `Fragment`/`Update`/`Query` API. Slick requires adoption and its own query DSL. Plain `s"SELECT ... $userInput"` requires nothing beyond basic Scala knowledge. In a codebase without explicit library policy, new code will default to string interpolation because it requires less setup. Typed query libraries make *type-safe queries possible*, not the path of least resistance. This is a meaningful distinction for teams assessing actual security posture.

4. **Supply chain analysis conflates transport integrity with provenance.** Multiple council members state that Coursier "fetches artifacts without signing verification" as the complete supply chain security critique. The more precise statement: Coursier verifies SHA-256 checksums from Maven Central, which provides transport integrity (the artifact you download is the artifact Maven Central recorded). What is absent is signing-based provenance verification: there is no cryptographic mechanism to confirm that the artifact uploaded to Maven Central was signed by the legitimate maintainer's key. Typosquatting (uploading a malicious artifact under a similar name), account compromise of a library maintainer, and CI/CD pipeline compromise during publication all remain viable attack vectors. This distinction matters for teams assessing supply chain risk [SONATYPE-SC-2025].

**Additional context:**

**Akka Remote and Java serialization — the highest-impact practical exposure.** This gap is present in all five council perspectives. Historically, Akka Remote (the clustering and distributed messaging layer) used Java serialization as its default wire protocol. This meant that any Scala application using Akka clustering for distributed services was, absent explicit configuration to disable it, potentially vulnerable to deserialization attacks over its cluster communication channel. The Akka documentation from 2015 onward warned that Java serialization was "not meant for production use" and should be replaced with Akka's Jackson or Protobuf serializers [AKKA-SERIALIZATION-DOCS]. Many organizations failed to make this configuration change. CVE-2022-36944 in `scala-library.jar` is therefore not merely an abstract code-execution risk — it was practically exploitable in any Akka cluster that had not opted out of Java serialization, which was a significant portion of real-world Scala deployments at the time. The council's aggregate treatment of deserialization as "an inherited JVM problem" understates the practical impact in the Scala ecosystem specifically.

**Compile-time code execution as a supply chain attack vector.** Scala macros execute arbitrary code in the compiler process during the build. This is not a theoretical concern: any library dependency that contains macros runs code in the developer's or CI system's environment at compile time, with access to the build environment's filesystem, network, and environment variables. This is functionally equivalent to the threat model of malicious build plugins. A compromised macro dependency could exfiltrate secrets from CI environment variables, tamper with generated bytecode, or establish persistence on the build host. Languages with compile-time metaprogramming must include this in their threat model. The Scala 3 macro system's "inline" mechanism (which is more principled and restricted than Scala 2's arbitrary reflective access) partially mitigates this, but inline macros still execute arbitrary code at compile time. The council does not address this dimension [SCALA-MACROS-SECURITY].

**Effect system typing as a security audit mechanism.** The apologist briefly notes that "Pure effect types (IO, ZIO) make side effects explicit and auditable," but this observation is not developed as a security property. In practice, a function signature of `def processPayment(order: Order): IO[PaymentResult]` makes the I/O boundary visible and auditable in a way that `def processPayment(order: Order): PaymentResult` does not. Security auditors reviewing codebase for unauthorized data exfiltration, unexpected network calls, or privilege escalation can use effect types as a guide: functions in the "pure" portion of the call graph (returning `A`, not `IO[A]`) are structurally prevented from performing I/O without the type signature changing. This represents a meaningful advantage over dynamically typed languages and over statically typed languages without effect tracking.

**Implicit conversions in Scala 2 as a covert value transformation risk.** In Scala 2, `implicit def convert(x: A): B = ...` allowed a value to silently change type at use sites without any indication at the call site. This created a class of security-adjacent bugs where security-sensitive type distinctions were silently erased. For example, a newtype `case class UserId(value: Int)` combined with an implicit `UserId => Int` conversion would allow `UserId` to appear in integer contexts — including string-interpolated SQL queries — without any compiler warning. Scala 3 requires explicit `import scala.language.implicitConversions` and wrapping in `Conversion[A, B]` with explicit import at use sites, effectively eliminating this covert conversion surface [SCALA3-GIVEN]. This is a genuine Scala 3 security improvement that the council does not explicitly identify.

**Missing data:**

- NVD query methodology for Scala CVEs is not stated in the research brief. The brief relies on CVEDetails and Stack.watch, which may not capture all relevant findings. A direct NVD query for `scala-lang` products would provide a more authoritative baseline.
- No analysis of the security posture of common Scala web frameworks (Play, http4s, Tapir). Play has CSRF protection built in; http4s's security model (functional middleware, explicit effect types) is meaningfully different from traditional servlet-based frameworks. This dimension is missing from all council perspectives.
- No analysis of cryptographic library patterns in Scala. The standard recommendation for JVM cryptography is to use `javax.crypto` (JDK built-in, reasonable for common operations) or Bouncy Castle (for advanced cryptographic protocols). Scala-specific cryptographic libraries are rare; teams use Java libraries. Whether this creates specific ergonomic risks in Scala code is not addressed.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- The type system does not prevent injection vulnerabilities because `String` does not distinguish safe values from user-controlled values. This is correctly identified by all council perspectives and is the fundamental limitation of Scala's security ergonomics.
- `asInstanceOf[T]` can cause `ClassCastException` at runtime and bypasses type safety guarantees. Correctly noted.
- `null` is legal in Scala (as a JVM necessity), and Java interop libraries return null, creating NPE risk in code that does not wrap Java return values in `Option`. Correctly noted.
- The `Any` universal supertype is an escape hatch that accepts any value, weakening type guarantees at boundaries where it is used.

**Corrections needed:**

The apologist's framing that Scala's type system "nudges developers toward safe patterns structurally" through typed query interfaces is overstated as discussed above. The type system creates *no structural nudge* toward Doobie or Slick; it merely fails to prevent the unsafe pattern. The nudge, if any, comes from code review policy and team convention, not from the compiler.

**Additional context:**

**Opaque types and the newtype pattern as security tools.** Scala 3's opaque type aliases (`opaque type Email = String`) provide zero-runtime-cost type distinctions with compile-time enforcement. This pattern is directly applicable to security-relevant distinctions: `opaque type SqlParam = String` can be used to distinguish parameterized SQL values from raw user input, with the constructor function performing sanitization or escaping. When combined with a library discipline that accepts only `SqlParam` in query-building positions, this provides a structural guarantee that user input has passed through the sanitization constructor. This is a meaningful security design pattern that Scala 3 enables more cleanly than most production languages. The council mentions opaque types in the type system context but not in the security context.

**Refined types via Iron library.** The apologist mentions Iron for compile-time constraint enforcement (`type Email = String Refined IsEmail`). This is an accurate description of a real library that provides compile-time validation at type level. For security-sensitive input processing (email validation, URL validation, integer range constraints), this eliminates entire classes of invalid-input bugs. The library deserves security context: it provides what Liquid Haskell provides in a more constrained form — types that carry proof of constraint satisfaction. The security value is that invalid inputs cannot be passed to functions expecting constrained types, making defensive-check omission a compile error rather than a runtime risk.

**JVM reflection as a type system bypass.** Standard JVM reflection (`Class.forName`, `Method.invoke`, `Field.set`) can bypass Scala's type system entirely. `Field.setAccessible(true)` followed by `field.set(obj, value)` can modify `val` fields and inject values that would be rejected at the Scala type level. This is the same exposure as Java — GraalVM Native Image's restriction on reflection (requiring explicit `reflect-config.json`) is in this sense a security improvement because it surfaces reflection dependencies explicitly. The council does not address this bypass mechanism.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- JVM garbage collection eliminates the memory corruption vulnerability classes (buffer overflow, UAF, double free, heap spray). This is an absolute property of the JVM bytecode verifier, not a probabilistic mitigation. Correct.
- Scala Native with `Ptr[T]` reintroduces manual memory management risk for C interop. Correctly scoped to a niche context.
- Immutable-first idioms reduce mutable shared state, which reduces the attack surface for race condition exploits in concurrent code. Correct.

**Corrections needed:**

None in this section — the council's coverage is accurate within its scope.

**Additional context:**

**Java deserialization bypasses type system guarantees at the memory level.** Java deserialization reconstructs object graphs from byte streams, bypassing constructor logic and Scala's type-level invariants. An object with an invariant enforced by its constructor (e.g., `require(value > 0, "must be positive")`) can have that invariant violated through deserialization of a crafted byte stream. This is not merely a code-execution risk (the gadget chain) — it is a correctness risk affecting any data that enters the system through deserialization, regardless of whether the deserialization chain is exploitable. Libraries like Circe (JSON), Protobuf, and Avro avoid this by constructing objects through validated paths. The council addresses gadget chain risk but not this more subtle invariant-violation risk.

**ThreadLocal misuse and request context leakage.** In Scala applications using thread-pooled HTTP servers (Play's Netty backend, servlet-based deployments), `ThreadLocal` values are sometimes used to propagate request-scoped context (authentication tokens, user identifiers, tracing context). Thread pool reuse can cause context from one request to leak into another if the ThreadLocal is not properly cleared at request boundaries. This is an authenticated-to-authenticated privilege escalation: user A's request executing on a thread that previously served user B may see user B's context if cleanup was not performed. This is a documented risk in Play and similar frameworks [PLAY-SECURITY-GUIDE]. Cats Effect's `IOLocal` and ZIO's `FiberRef` provide fiber-scoped alternatives that avoid thread pool reuse issues — a concrete security advantage of effect-based concurrency over traditional thread-pool models.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- Immutable-first data handling reduces the attack surface for concurrent state corruption. An immutable value cannot be maliciously or accidentally modified by a concurrent actor.
- Effect types (`IO`, `ZIO`) make side effects explicit in the type signature, providing auditability that is security-relevant.
- The Akka licensing episode is correctly documented. The practitioner correctly flags that the reliance on Akka Cluster for distributed Scala applications creates a supply chain dependency risk when controlled by a single commercial entity.

**Corrections needed:**

**Akka actor isolation claims should be more precise.** The council implies that Akka's actor model provides security isolation between actors. Actors in Akka are not isolated in the OS process sense — they share a JVM heap. A misbehaving actor can hold references to objects from other actors and access them directly. The "isolation" is a programming model discipline, not an enforced boundary. Untrusted actors (e.g., user-defined actors in a multi-tenant system) cannot be safely isolated from each other in a single Akka JVM process. This matters for multi-tenant Scala applications and should not be presented as a security guarantee.

**Additional context:**

**Race conditions in `Future`-based code as a security risk.** The realist correctly identifies that `scala.concurrent.Future` lacks structured cancellation and has untyped errors. From a security perspective, the more significant issue is that `Future`'s eager execution model can create time-of-check/time-of-use (TOCTOU) race conditions. A security check (authorization, rate limiting) may run on one `Future`, and the protected action may run on another `Future` with no enforcement that the check happened-before the action. This is not a hypothetical: authorization bypass via race condition in Future-based service code is a documented antipattern [OWASP-TOCTOU]. Cats Effect's `IO` (with its explicit sequencing and fiber-based structured concurrency) and ZIO (with `Ref` for atomic state) provide safer primitives for security-critical sequencing.

**FiberRef and IOLocal eliminate ThreadLocal leakage.** As noted in the memory model section, `FiberRef` (ZIO) and `IOLocal` (Cats Effect) scope state to the fiber rather than the OS thread. Since fibers don't share threads between requests in the same way thread pools do, context leakage between concurrent requests is structurally prevented. This is a concrete security advantage of effect-based concurrency that the council does not develop.

---

### Other Sections (security-relevant flags)

**Section 6: Ecosystem and Tooling — Supply chain precision**

All council perspectives correctly identify that Coursier fetches from Maven Central without mandatory signing. One correction applies throughout: the Kodem Security blog is used as a primary source for multiple security claims without any verification against primary databases (NVD, GHSA, CVEDetails). Vendor security blogs have an interest in finding and emphasizing vulnerabilities to sell scanning services. The CVE claims that originate solely from this source (including CVE-2020-26238) should be cross-referenced against authoritative databases before being treated as established findings. This does not mean the source is wrong; it means it requires corroboration.

**Section 6: Tooling — sbt plugins and build security**

The council does not address the security posture of the sbt plugin ecosystem. sbt plugins run in the build process with the same privileges as the build itself, analogous to npm postinstall scripts. A malicious sbt plugin can read CI environment variables, exfiltrate credentials, or modify compiled artifacts. The sbt plugin ecosystem is smaller than npm, which reduces the attack surface somewhat, but the risk model is identical. Teams with strict supply chain requirements should audit sbt plugins with the same rigor as runtime dependencies.

**Section 5: Error Handling — Silent exception swallowing and security**

The realist correctly identifies that `Future`'s exception handling can lead to unhandled errors. The security implication: silently swallowed exceptions in security-critical code paths (authorization checks, audit log writes) can create the appearance of successful security enforcement while the underlying operation failed. `Either`-based or effect-based error handling makes failure explicit in the type signature, preventing this class of silent security failure. This is a subtle but important security ergonomics point.

---

## Implications for Language Design

These observations from Scala's security trajectory yield the following generic design lessons for language designers.

**1. Inheriting a platform means inheriting its attack surface — audit explicitly, not implicitly.**
Scala inherited the JVM's memory safety (a benefit) and Java's serialization mechanism (a significant liability). The benefit was automatic; the liability was also automatic. Language designers targeting an existing runtime or VM should conduct an explicit security audit of what attack surfaces they are inheriting before committing to the platform, and should design opt-out mechanisms for dangerous inherited features (Java serialization, in Scala's case, was not properly restricted until a CVE forced the issue). Inheriting a platform's ecosystem value is not separable from inheriting its security debt.

**2. Type systems that do not model security domains provide false assurance unless the limitation is stated explicitly.**
Scala's powerful type system demonstrably does not prevent SQL injection, XSS, SSRF, or deserialization attacks. Developers who have internalized "Scala's type system is strong, therefore my code is safe" are more dangerous than developers with no type system assurances at all. Language documentation and community culture should be explicit: type safety and security are orthogonal properties. Strong types prevent type confusion bugs; they do not prevent injection unless the type system explicitly models untrusted input vs. trusted data. Languages that want their type system to contribute to security must design types for that purpose (opaque types for security-domain separation, taint tracking at the type level) and make those patterns ergonomic.

**3. Covert value transformation mechanisms (implicit conversions) create security-invisible code paths.**
Scala 2's `implicit def` for automatic type conversion allowed values to change type at use sites without any syntactic indication. In security-critical code, this can erase meaningful distinctions between user input and trusted data. Scala 3's requirement for explicit `Conversion[A, B]` with explicit import at use sites is a meaningful improvement. Language designers should treat any mechanism that can silently change a value's type or semantics (implicit conversions, automatic coercions, operator overloading on primitive types) as a potential security liability in contexts where value provenance matters.

**4. Compile-time code execution must be treated as a runtime code execution risk for the build environment.**
Macro systems, annotation processors, compiler plugins, and build tool plugins all execute developer-authored or dependency-authored code in the build environment. This execution has full access to the build environment's credentials, network, and filesystem. Language designers who add metaprogramming features must include explicit threat modeling for compile-time execution in their security model. Sandboxing compile-time code, restricting what it can access, and requiring explicit opt-in for expanded capabilities are appropriate mitigations. The Scala 3 macro system's "inline" model is more restricted than Scala 2's reflective macro model, but still requires attention in this threat model.

**5. Effect typing provides security auditing value that should be explicitly communicated as a security property.**
Effect systems that make I/O visible in the type signature allow security auditors to trace I/O boundaries statically. Functions that return `IO[A]` or `ZIO[R, E, A]` are immediately identified as performing potentially security-relevant operations; functions returning `A` are guaranteed pure (absent reflection bypasses). This is a meaningful security auditing tool. Language designers who add effect tracking should explicitly document this security property, and library designers working in effect-typed languages should understand that their `IO` boundary is also a trust boundary.

**6. Structured concurrency prevents authorization context leakage that thread-pool models enable.**
Thread-pooled concurrency (traditional JVM threading, unstructured `Future`) can leak request-scoped security context between concurrent requests when ThreadLocal state is improperly cleaned up. Fiber-based structured concurrency with fiber-local storage (Cats Effect's `IOLocal`, ZIO's `FiberRef`) eliminates this class of context leakage by scoping state to the logical computation unit rather than the physical thread. Language designers adding concurrency primitives should include analysis of request-context isolation as a security property of the concurrency model, not just as a correctness property.

---

## References

[AKKA-SERIALIZATION-DOCS] Akka Documentation. "Serialization." https://doc.akka.io/docs/akka/current/serialization.html. Warns that Java serialization is "not safe" for production use and should be replaced with Akka's serialization extensions.

[CVEDETAILS-SCALA] CVEDetails. "Scala-lang Scala: Security Vulnerabilities, CVEs." https://www.cvedetails.com/vulnerability-list/vendor_id-17258/product_id-41515/Scala-lang-Scala.html

[GHSA] GitHub Security Advisory Database. https://github.com/advisories

[KODEM-SECURITY] Kodem. "Addressing Scala Security Vulnerabilities: Best Practices for Fortifying your Code." https://www.kodemsecurity.com/resources/tips-to-reduce-scala-vulnerabilities — Note: vendor security blog; claims should be cross-referenced with NVD.

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center. BlueHat IL 2019. https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_BlueHatIL/2019_01%20-%20BlueHatIL%20-%20Trends%2C%20challenge%2C%20and%20shifts%20in%20software%20vulnerability%20mitigation.pdf

[NVD] National Vulnerability Database. https://nvd.nist.gov/

[OWASP-TOCTOU] OWASP. "Time Of Check Time Of Use." https://owasp.org/www-community/vulnerabilities/Time_of_check_time_of_use

[PLAY-SECURITY-GUIDE] Play Framework Documentation. "Security." https://www.playframework.com/documentation/latest/Security

[RESEARCH-BRIEF] Scala Research Brief. "Scala — Research Brief." Penultima Project, 2026-02-27.

[SCALA-LOG4J-2021] Scala-lang Blog. "The state of the log4j CVE in the Scala ecosystem." December 16, 2021. https://www.scala-lang.org/blog-detail/2021/12/16/state-of-log4j-in-scala-ecosystem.html

[SCALA-MACROS-SECURITY] Scala Documentation. "Macros." https://docs.scala-lang.org/scala3/guides/macros/. Note: the macro system documentation does not address compile-time security implications; this is a gap in official documentation.

[SCALA3-GIVEN] Scala 3 Documentation. "Contextual Abstractions — Given Instances." https://docs.scala-lang.org/scala3/book/ca-given-instances.html

[SONATYPE-SC-2025] Sonatype. "2025 State of the Software Supply Chain." https://www.sonatype.com/state-of-the-software-supply-chain

[STACK-WATCH] Stack.watch. "Scala Lang Security Vulnerabilities in 2025." https://stack.watch/product/scala-lang/

[STACKWATCH-SCALA-2025] Stack.watch. "Scala Lang Security Vulnerabilities in 2025." https://stack.watch/product/scala-lang/
