# Java — Detractor Perspective

```yaml
role: detractor
language: "Java"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## 1. Identity and Intent

Java's origin story is instructive and somewhat damning. The language was designed for embedded consumer electronics — set-top boxes and handheld devices — then hastily repurposed for the World Wide Web when the commercial internet arrived. That pivot was not a clean redesign. It was a marketing rebranding, and Java has spent thirty years inheriting constraints from a problem domain it abandoned before it shipped [JAVA-WIKIPEDIA].

The stated design goals from the 1996 white paper — simple, robust, portable, high-performance, multithreaded — were aspirational. Some were delivered. Others were contradicted by the implementation. "Simple" was achieved relative to C++, but that is a low bar. Java is not simple in any absolute sense: the language today has checked and unchecked exceptions, two categories of types (primitives and references), a generics system with type erasure, sealed classes, records, pattern matching in switch, virtual threads, module system (JPMS), annotation processing, and a standard library spanning hundreds of packages. Beginners encounter this complexity immediately in enterprise contexts, where even a "Hello World" web service requires understanding Spring Boot, dependency injection, Maven, and the JVM lifecycle before making a single HTTP request.

"Write Once, Run Anywhere" — the slogan that sold Java to an entire generation — was a sophisticated technical achievement in 1996 and a marketing myth by 2005. JVM implementations diverged; browser applets were a security nightmare [PSYCHIC-SIGS]; server-side Java always assumed specific target environments anyway. The WORA promise also created a design constraint that haunts Java to this day: backward compatibility. The commitment to run Java 8 bytecode on Java 25 JVMs — a compatibility window of approximately eleven years [JAVA-VERSION-HISTORY] — means broken early decisions cannot be corrected. Every design error from 1996 onward is permanent, or nearly so.

The most consequential single mistake in Java's design intent was this: the language was engineered for safety relative to C++, but its safety guarantees were weaker than they appeared. `null` was retained. Checked exceptions were added as a supposed improvement but became an industry-wide anti-pattern. The Security Manager was architecturally unsound from conception and finally removed in 2024 after decades of false confidence. Java's robustness claims were real but overstated, and the gap between the promise and the reality has shaped the language's reputation ever since.

---

## 2. Type System

Java's type system contains one structural flaw so severe that it has shaped eleven years of remediation work and still is not resolved: the **primitive/reference type duality**.

Java has two entirely separate categories of values. Primitive types — `boolean`, `byte`, `char`, `short`, `int`, `long`, `float`, `double` — are value types with no identity, efficient in memory and computation. Reference types — every class, interface, array — are heap-allocated objects with identity, headers, and pointer indirection. These two categories are not unified. A `List<int>` cannot exist; you must use `List<Integer>`, where `Integer` is a heap-allocated object wrapping an `int`. This mandatory boxing incurs memory overhead (every `Integer` carries an object header of 12–16 bytes plus its value), GC pressure (boxed numbers are heap objects, therefore garbage), and indirection costs [OPENJDK-VALHALLA]. For performance-sensitive code — financial calculations, numerical processing, data structures — this duality is not aesthetic; it is a material performance tax.

Project Valhalla has been working to address this since approximately 2014 [OPENJDK-VALHALLA] [INSIDE-JAVA-VALHALLA]. As of early 2026, value types reached early-access builds for JDK 26 — twelve years after the project began. No committed delivery date for general availability exists. The community has been promised a fix to a foundational design error for over a decade, and the fix is still not in a production release. Other languages — C# with value types, Rust with stack allocation by default, Go with value semantics for structs — did not make this mistake in the first place or corrected it earlier.

**Generics with type erasure** is Java's second major type-system failure. When generics arrived in Java 5 (2004), backward compatibility with pre-5 JVMs mandated that generic type parameters be erased at compile time [OPENJDK-ERASURE-DEFENSE]. At runtime, a `List<String>` and a `List<Integer>` are both just `List`. The consequences cascade:

- No `instanceof` check on parameterized types at runtime. `x instanceof List<String>` is a compile error.
- No generic array creation. `new T[]` is impossible.
- No primitive type parameters. `List<int>` does not compile; use `List<Integer>` with all its boxing costs.
- Heap pollution: raw types (backward-compatibility escape hatches) can silently corrupt parameterized containers at runtime, producing `ClassCastException` far from the actual defect.

Type erasure was a pragmatic compatibility choice. But "pragmatic in 2004" has compounded into a permanent liability. Every Java programmer eventually encounters the limits of erased generics. Framework authors write elaborate workarounds — `TypeToken`, `Class<T>` parameters, reflection hacks — to recover type information that should never have been discarded. Project Valhalla, in addition to value types, promises reified generics. That fix is also still pending after twelve years.

**Nullability** is a separate but related dysfunction. Java retained `null` from C as a value for all reference types. The consequence — `NullPointerException` as the most common runtime error in Java codebases — was acknowledged by Tony Hoare (who introduced null references in ALGOL W in 1965) as his "billion-dollar mistake" [JAVA-VERSION-HISTORY]. Java 8 introduced `Optional<T>` in 2014, but `Optional` is a library type, not a language-enforced contract. Existing APIs — and there are hundreds of thousands of legacy APIs in Maven Central — still return `null`. The JDK's own standard library returns `null` in countless places. Adding `Optional` to new code without fixing the ecosystem means developers must learn two systems for absence: the explicit `Optional` path and the implicit `null` path through all pre-2014 APIs. Java 25 still does not have nullable/non-nullable type annotations enforced by the compiler.

**Unsigned integers** are absent. Java's integer primitives are all signed. `byte` in Java is -128 to 127, not 0 to 255. Systems programming, network protocols, and cryptographic code that works with unsigned byte values must use bitwise masking, casts to larger types, or `Byte.toUnsignedInt()` helper methods. This is pure friction with no design benefit. Every other systems-adjacent language — C, C++, Rust, Go — supports unsigned integer types.

The type system has improved substantially with records (Java 16), sealed classes (Java 17), and exhaustive pattern matching for switch (Java 21). These additions partially approximate algebraic data types that ML, Haskell, Rust, and Kotlin have offered for years. The belated arrival is credited; the belatedness is not. Java 25 developers have ADT-adjacent tools that were available in competing languages 10–15 years earlier.

---

## 3. Memory Model

Java's memory model story has two periods: the pre-ZGC/Shenandoah era of real pain, and the post-ZGC era of mostly-solved-but-still-costly management. The honest assessment requires acknowledging that the JVM's memory model is now genuinely good for many workloads, but this obscures how badly the original design failed and how many structural costs remain embedded.

**GC pause history**: Until ZGC became production-ready (JDK 15, 2020) and its generational mode became the default (JDK 23, 2024), Java applications running on large heaps suffered stop-the-world GC pauses of hundreds of milliseconds to multiple seconds [FOOJAY-GC-GUIDE]. Financial services firms running Java for trading systems — a core Java use case — spent enormous engineering resources tuning G1 GC parameters to minimize pause times. This was not a theoretical concern. It was a real operational cost paid by real teams for real years. The problem was structural: the G1 GC's "best effort" 200ms pause target was not a guarantee, and the engineering required to approach that target was significant.

The fix exists now. ZGC achieves sub-millisecond pauses on terabyte heaps [LOGICBRACE-GC]. But "fixed in 2024, after 28 years" is not a defense of the design — it is an indictment of the original choice and the slow pace of remediation.

**Memory overhead from object model**: Every Java object carries a header (12–16 bytes on 64-bit JVMs with compressed OOPs). For small objects — boxed integers, boxed booleans, small POJOs — the header dominates. A `List<Integer>` of one million integers requires one million `Integer` objects plus one million references plus the list's internal array plus the list object itself. In native code, the same data is a contiguous array of four-byte values. The overhead is not theoretical; it drives memory requirements for data-intensive Java applications to levels that would be impossible in a language with value semantics.

**JVM startup cost**: Spring Boot on the JVM starts in 3–4 seconds and consumes 300–500MB of heap [GRAALVM-ADVANTAGES]. Go, Rust, and compiled C programs start in milliseconds and run in megabytes. For long-running server processes, this is inconsequential at steady state. For serverless functions (AWS Lambda, GCP Cloud Functions), Kubernetes deployments with fast scaling requirements, and CLI tools, it is a decisive disadvantage. GraalVM Native Image addresses this — <100ms startup, ~50-150MB total — but at the cost of giving up dynamic class loading, weakening reflection support, and requiring compile-time configuration of reflection and proxies.

The Native Image workaround is real and increasingly practical, but observe the pattern: Java's memory model required a new compilation technology (AOT via GraalVM), a new runtime model (Substrate VM), new configuration formats (reflection configs), and new frameworks that AOT-optimize their code (Quarkus, Micronaut) to mitigate a weakness that was baked into the original JVM design. That is a significant ecosystem investment to compensate for a design limitation.

**JNI (Java Native Interface)**: For 25+ years, calling native code from Java required JNI — a C-language binding API that is verbose, error-prone, type-unsafe at the boundary, and requires writing C boilerplate to expose Java objects to native code. The research brief accurately characterizes it as "verbose and error-prone" [OPENJDK-JEP454]. Memory safety guarantees evaporate at JNI boundaries; JNI bugs have historically crashed JVMs. The Foreign Function & Memory API (stable Java 22, 2024) is the official replacement — clean, safe, pure-Java. But "replaced in 2024, after 28 years of JNI" is the same pattern. A problem that should have been designed correctly initially required decades to fix.

---

## 4. Concurrency and Parallelism

Java's concurrency story falls into the same pattern as its type system and memory model: original design inadequate, partial fixes added over decades, finally approximately right after twenty-plus years.

**Platform threads**: From Java 1.0 to Java 20, every Java thread was a 1:1 wrapper over an OS thread. OS threads are expensive — approximately 1MB stack by default, kernel scheduling overhead, context switching cost. Applications needing high concurrency under the platform-thread model required thread pools (a significant complexity layer), careful pool sizing (always heuristic, never optimal), and eventually either callback hell (`CompletableFuture` chains) or reactive programming frameworks (Reactor, RxJava). Go shipped goroutines — lightweight, JVM-managed threads equivalent to Java's virtual threads — in 2009. Java shipped virtual threads in 2021 as a preview, final in 2023 as Java 21. The twelve-year lag is not a measurement of feature difficulty; Go is a smaller team with fewer constraints. It is a measurement of governance velocity and backward-compatibility caution.

**CompletableFuture**: Java 8 (2014) introduced `CompletableFuture` as the mechanism for asynchronous computation composition. The API is notoriously complex. Consider a simple operation: make two HTTP calls concurrently, combine their results, handle errors from either, and cancel both if the caller cancels. In Go, this is straightforward with goroutines and channels. In Java before virtual threads, the idiomatic approach involved `CompletableFuture.allOf()`, multiple `.exceptionally()` or `.handle()` chains, and careful attention to thread pool assignment for each stage. The research brief notes this: "`CompletableFuture` composability is less ergonomic than async/await in other languages" [JAVA-VERSION-HISTORY]. This is diplomatic. `CompletableFuture` is the Java equivalent of callback hell, renamed.

**Structured Concurrency** (final Java 24) and **Scoped Values** (final Java 24) are genuine improvements. `StructuredTaskScope` makes the parent-child relationship between tasks explicit and enforces cancellation semantics. But these arrived in 2025. The structured concurrency concept — "task lifetime is scoped to a lexical scope" — has been available in languages like Go (via context cancellation) and Kotlin (via coroutines with structured concurrency semantics) since 2017–2018.

**Data race prevention**: Java has none, by design. The JMM specifies what happens when data races occur (sequential consistency only for data-race-free programs; defined but weak behavior for racy programs) rather than preventing them. The `synchronized` keyword, `volatile`, and `java.util.concurrent.locks` interfaces are the tools developers have. There is no borrow checker, no ownership system, no static race detection built into the language. Runtime race detection tools (Java Race Detector, Chord) exist as external research tools but are not part of the standard development workflow. A Java developer who writes a data race may not discover it until load testing or production incident. Rust prevents data races at compile time. Go's race detector is built into the toolchain and runs with `go test -race`.

**The "colored function" problem**: Virtual threads eliminate the sync/async coloring for I/O-bound code — blocking code on virtual threads simply suspends rather than blocking an OS thread. This is the correct solution. But for CPU-bound parallelism, Java still uses platform threads and `ForkJoinPool`. The parallel streams API from Java 8 uses the common `ForkJoinPool` by default, leading to a well-documented failure mode: one slow parallel stream in one part of an application can saturate the shared pool and starve all other parallel operations. The fix — configure a custom ForkJoinPool — is non-obvious and underdocumented.

---

## 5. Error Handling

Checked exceptions are the most thoroughly discredited feature in Java's design. The case against them is not controversial; it is settled. Every major JVM language adopted after Java — Kotlin, Scala, Groovy, Clojure — dropped checked exceptions. Spring, the dominant Java enterprise framework, wraps all checked exceptions in `DataAccessException` (unchecked). Hibernate does the same. Java 8's Stream API cannot propagate checked exceptions from lambda expressions without unchecked wrapper code — a tension so severe that it appears in the official documentation as a known limitation [LITERATE-JAVA-CHECKED].

The design intent was clear: make failure modes visible at API boundaries. If a method can throw `IOException`, callers must acknowledge this. This is not a foolish idea in the abstract. The execution failed because it underestimated how developers would respond to mandatory exception handling. The actual response was:

```java
try {
    riskyOperation();
} catch (CheckedException e) {
    // ignored
}
```

Or:

```java
try {
    riskyOperation();
} catch (CheckedException e) {
    throw new RuntimeException(e);
}
```

The first pattern silently swallows failures. The second wraps and rethrows, losing the original context. Both are the mechanical responses of developers who were told "you must handle this" but not given ergonomic tools to handle it in lambda expressions, functional interfaces, or stream pipelines. Research on production Java codebases consistently documents exception swallowing and inappropriate catch-all handlers. A 2016 PLDI paper analyzing 94 Java open-source projects found exception handling code accounting for a disproportionate share of bug-inducing changes — the complexity of Java's exception model contributed directly to defects [NAKSHATRI-2016].

**No standard Result type**: Modern languages with good error handling — Rust, Swift, Kotlin (with `Result<T, E>`), Haskell — make error paths visible in the type signature without requiring callers to catch exceptions. A function returning `Result<User, DatabaseError>` documents its failure modes and forces callers to handle both paths. Java's `Optional<T>` handles the present/absent case, not the success/failure case. There is no standard `Result<T, E>` in the Java stdlib. Third-party libraries (Vavr's `Either`, Resilience4j's `Result`) exist, but without standard library integration, they cannot be used across API boundaries without mandating a dependency.

The absence of a standard Result type is not an oversight — it would have required acknowledging that checked exceptions had failed. The preference for maintaining the fiction that checked exceptions work has cost Java developers decades of boilerplate.

**Helpful NPE messages**: Java 14 added improved NullPointerException messages that describe which reference was null. This is good. It was added in 2020, twenty-four years after Java 1.0 shipped. The fact that NullPointerExceptions have been the single most common runtime error in Java for twenty-four years, and that improved diagnostics for them took twenty-four years to arrive, is an indictment of the governance prioritization process.

---

## 6. Ecosystem and Tooling

Java's ecosystem is enormous — 600,000+ artifacts on Maven Central, an extensive framework landscape, world-class IDEs — and this scale is genuinely useful. But enormous ecosystems create problems that small ecosystems avoid, and Java's problems here are acute.

**Supply chain risk**: Log4Shell (CVE-2021-44228, CVSS 10.0) is the canonical case. Apache Log4j 2 was a transitive dependency in millions of Java applications [CISA-LOG4J]. When the vulnerability was disclosed in December 2021, organizations worldwide faced a multi-week emergency response. Many did not know they ran Log4j; it was four or five levels deep in their dependency trees. The vulnerability was exploitable with a single crafted log string, required no authentication, and gave remote code execution. CISA characterized it as one of the most serious vulnerabilities ever discovered [CISA-LOG4J].

The structural cause was Java's dependency model: Maven pom.xml files declare dependencies which declare their own dependencies, and so on recursively. A typical Spring Boot application has 100–300 transitive dependencies. No developer reads all of them; no developer audits all of them. The Java ecosystem's size is its strength and its attack surface. The supply chain tooling — OWASP Dependency-Check, Snyk, GitHub Dependabot — is valuable remediation but does not eliminate the risk. It cannot, because the risk is structural.

**Maven's XML verbosity**: Apache Maven uses XML `pom.xml` files for build configuration. This was reasonable in 2002 when XML was the universal configuration format. In 2026, writing a `<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>` block for every library — with closing tags for every element — is an ergonomic tax with no benefit. Gradle (Kotlin or Groovy DSL) is more ergonomic, but the Java ecosystem bifurcated: approximately 75% Maven, 40-50% Gradle (significant overlap) [MEDIUM-MAVEN-GRADLE]. This means developers moving between projects must know both systems. The fragmented build tooling is a productivity cost that newer language ecosystems avoided by choosing one build system and not splitting.

**Spring complexity**: Spring Boot is used by 60–70%+ of Java enterprise projects [INFOQ-JAVA-TRENDS-2025]. Spring Boot is also famously complex. A "simple" Spring Boot application involves understanding: application context, dependency injection, auto-configuration, bean lifecycle, `@Component`/`@Service`/`@Repository` semantics, `@Autowired` vs. constructor injection, Spring MVC request mapping, Jackson serialization, Spring Data repositories, Spring Security filter chains, and actuator endpoints. Each layer has its own documentation, its own gotchas, and its own debugging surface. Spring's magic — convention over configuration, auto-configuration — means failures are non-obvious. When Spring auto-configures a DataSource you did not request, the resulting error message points to Spring internals, not your code.

The Spring ecosystem is also the cause of meaningful Java security problems. Spring's reflection-heavy dependency injection model motivated Oracle's `--add-opens` workarounds when JPMS strong encapsulation arrived in Java 17; it motivated Spring AOT for GraalVM compatibility; it has historically been a vector for prototype pollution and object injection attacks in frameworks that deserialize user-controlled data into Spring-managed beans.

**Logging fragmentation**: The Java logging ecosystem is one of the most embarrassing examples of ecosystem dysfunction in any language. The options — `java.util.logging` (built-in, rarely used), Log4j 1 (deprecated, security issues), Log4j 2 (CVE-2021-44228 incident), SLF4J (facade over implementations), Logback (SLF4J implementation), Tinylog, Java Flight Recorder — require developers to understand a facade API, an implementation API, binding JARs, configuration file formats, and classpath ordering rules. The SLF4J model — a logging facade that binds to an implementation at runtime via classpath — is an architectural workaround for the absence of a standard logging API, which caused competing logging frameworks, which caused the facade. Log4Shell happened because Log4j 2 was the de facto standard for years despite this fragmentation.

**IDE dependency**: IntelliJ IDEA is the overwhelmingly dominant Java IDE [JetBrains Developer Survey]. Java development without IntelliJ — with Eclipse or VS Code — is noticeably less productive. This is not unique to Java, but the gap between IntelliJ and alternatives is particularly sharp because Java's ergonomics lean heavily on IDE support: code generation for getters/setters, `equals`/`hashCode`, constructor boilerplate; Spring-specific auto-completion; complex refactoring. The language's verbose nature becomes tolerable in IntelliJ because IntelliJ generates the boilerplate. Without it, the verbosity is fully exposed.

---

## 7. Security Profile

Java's security track record is mixed. Memory safety eliminates the most common C/C++ vulnerability classes — buffer overflows, use-after-free, integer overflow leading to memory corruption — and this is a genuine, important property. But Java's design introduced its own characteristic vulnerability classes, and several of them are severe.

**Deserialization vulnerabilities** are Java's original sin in security. `java.io.ObjectInputStream` was designed to deserialize Java objects from byte streams. When Frohoff and Lawrence demonstrated in 2015 that Apache Commons Collections — a transitive dependency in millions of applications — contained "gadget chains" allowing arbitrary code execution through Java's native serialization, the impact was enormous. The root cause is architectural: deserialization of untrusted data in Java's object serialization format allows an attacker to instantiate arbitrary classes and invoke methods during deserialization, before any application-level validation occurs. The CWE-502 pattern (Deserialization of Untrusted Data) has generated hundreds of CVEs in Java applications and frameworks [CVEDETAILS-ORACLE-JRE].

The mitigations — serialization filters (JEP 290, Java 9; JEP 415, Java 17) — help but require explicit configuration. The default is still unsafe for untrusted input. The better fix — not using Java native serialization — is the approach all modern Java applications should take, but it requires migrating existing systems. Java's backward compatibility commitment means `ObjectInputStream` will never be removed, so the vulnerable API surface remains perpetually available.

**CVE-2022-21449 ("Psychic Signatures")**: This vulnerability is instructive because it was not an implementation bug in the classical sense — it was a complete failure of cryptographic validation in the JDK's ECDSA implementation. In JDK 15 through 18, the JDK's ECDSA signature verification would accept an all-zeros signature as valid for any message and any public key [PSYCHIC-SIGS]. An attacker who knew the target application used ECDSA for authentication could forge any signed message with an all-zeros byte sequence. JWT tokens, signed JARs, TLS handshakes using ECDSA certificates — all potentially affected. The vulnerability was in production releases for years before discovery.

The deeper problem is that Java ships security-critical cryptographic code that developers trust implicitly because "the JDK has it." That trust was violated. Java's security promise — that memory safety and type safety provide meaningful security guarantees — is true but incomplete. The language's safety properties do not prevent implementation errors in cryptographic code, and Java developers typically have no choice but to trust the JDK's cryptographic implementations.

**Security Manager removal**: The Java Security Manager was intended to sandbox untrusted code — applets, downloaded code — by restricting operations based on permissions. It was deprecated in Java 17 (2021) and removed in Java 24 (2025) [JAVA-VERSION-HISTORY]. Its removal was justified by the Security Manager's history of inadequacy: bypasses were routinely found, and the complexity of maintaining the permission model was not matched by actual security value. But the removal also acknowledges that Java's original security architecture for untrusted code execution never worked reliably. The applet security model was unsound; the Security Manager was its infrastructure; both are gone.

**Oracle CPU cadence and patch lag**: Oracle issues quarterly Critical Patch Updates. Users on unsupported JDK versions — any non-LTS release after the next release ships, and any LTS release without a commercial support contract — receive no security patches. The April 2025 CPU patched 6 Java SE vulnerabilities, 5 of which were remotely exploitable without authentication [ORACLE-CPU-APR2025]. Organizations running JDK 8 without an Oracle support contract (many do) receive no patches for these vulnerabilities.

**XML External Entity (XXE) injection**: Java's XML parsing APIs — `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory` — historically enabled external entity processing by default. XXE allows attackers to read arbitrary files from the server filesystem or initiate server-side request forgery. Disabling external entity processing required setting `FEATURE_SECURE_PROCESSING` flags or explicit parser configuration — a non-obvious step that developers frequently omitted. XXE vulnerabilities have been in the OWASP Top 10 for years specifically because of Java's XML API defaults [CVEDETAILS-ORACLE-JRE].

---

## 8. Developer Experience

Java occupies a paradoxical position: it is the language most developers have used (7th by Stack Overflow 2025 survey [SO-2025-TECH]; 30% of all developers by 2024 survey [SO-2024-TECH]) but rarely tops "most loved" rankings. Stack Overflow's 2024 "admired" rankings have Java in the middle tiers, behind Rust, Go, Python, Kotlin, TypeScript — languages that Java developers often choose when given a choice. The gap between Java's obligatory usage and developer preference is real and meaningful.

**Verbosity and ceremony**: Java's verbosity has improved since Java 8 — lambdas, method references, streams, records, `var`, text blocks have all reduced boilerplate. But the baseline remains high. Consider a simple data class in Java 25 versus Kotlin or Go:

Java (with `record`):
```java
public record Person(String name, int age) {}
```

This is now comparable to Kotlin's `data class Person(val name: String, val age: Int)`. But this is the best-case scenario — a simple immutable value type. For mutable objects, for entities with business logic, for JPA entities that require a no-arg constructor (incompatible with `record`), for Spring components — the boilerplate returns. JPA entities in Hibernate require: no-arg constructor, getter/setter pairs for every field, `@Entity`, `@Table`, `@Id`, `@Column`, `@GeneratedValue` annotations. The annotation-driven programming model that makes Spring and Hibernate work trades explicit code for configuration-by-annotation, but when something breaks, the developer must understand both the Java code and the annotation semantics and the framework behavior triggered by those annotations.

**Generics syntax complexity**: Advanced Java generics involve wildcard types (`<? extends T>`, `<? super T>`), bounded wildcards, type parameters on methods, and the PECS principle (Producer Extends, Consumer Super). These are correct solutions to real type system problems, but they are not learnable by reading an error message. A developer who writes `void addAll(List<T> list)` and is told they should have written `void addAll(List<? extends T> list)` — with no explanation from the compiler about why — is in a poor DX situation. Kotlin's declaration-site variance (`out T`, `in T`) is significantly more learnable than Java's use-site wildcards.

**The learning curve's real cost**: Enterprise Java development requires knowledge of: the Java language itself, the JVM's behavior (GC, JIT, class loading), Maven or Gradle, Spring Boot (which encapsulates Spring Framework, Spring Data, Spring Security, Spring Cloud), JPA/Hibernate (a separate abstraction over JDBC), SLF4J and a logging implementation, Docker for deployment, and organizational frameworks on top of all of this. A junior developer hired to work on a Java microservice needs 6–12 months before they are independently productive — not because Java is hard to learn, but because the ecosystem surrounding Java enterprise development has accumulated thirty years of layers.

**The null problem's DX cost**: Every Java developer learns, within their first months, to defensively sprinkle null checks throughout code. `Optional<T>` improved this for new APIs, but the old APIs — `Map.get()` returns null for missing keys; `Class.getField()` returns null for absent fields; essentially any Java 1 through Java 7 API can return null — remain pervasive. The DX cost is not just learning to check for null; it is the cognitive overhead of always wondering whether any given reference might be null, and the debugging cost when a NPE appears six stack frames from where the null was introduced.

**Android displacement**: Java was the original Android language. Kotlin was declared the preferred language for Android development by Google in 2019. By 2025, Kotlin is primary in 87% of professional Android apps [ANDROID-METRO]; 70%+ of Android job postings require Kotlin [ANDROID-METRO]. Java's most significant mobile ecosystem has migrated away. The platform still supports Java, but new Android development is Kotlin-first. This is the market's verdict: given a choice, Android developers prefer Kotlin over Java. Kotlin runs on the JVM, preserving ecosystem access, while eliminating Java's friction points — nullable safety by default, concise data classes, coroutines for async, extension functions, no checked exceptions.

---

## 9. Performance Characteristics

Java's raw throughput performance is competitive in steady-state server workloads. The JIT compiler is genuinely sophisticated — decades of HotSpot optimization work produce code that approaches native performance for computation-heavy hot paths. The benchmarks support this: Java (HotSpot JVM) performs comparably to Go and C# in Computer Language Benchmarks Game algorithmic tests, significantly faster than Python and PHP [BENCHMARKSGAME].

But "competitive at steady state" conceals the costs.

**TechEmpower comparison**: TechEmpower Round 23 (2025) shows Spring Boot at approximately 14.5x baseline throughput, versus Go Fiber at 20.1x and C# ASP.NET Core at 36.3x [TECHEMPOWER-R23]. Spring Boot's throughput is meaningfully lower than the most competitive alternatives. The gap is not catastrophic — these are web framework benchmarks measuring specific workloads — but Spring Boot's framework overhead is measurable in production, and for teams optimizing infrastructure cost, it translates to more servers per request rate.

**Startup overhead**: 3–4 seconds for a Spring Boot application [GRAALVM-ADVANTAGES] is not relevant for long-running services, but it is disqualifying for serverless functions. AWS Lambda imposes time limits; a 3-second cold start is often half the total budget for a Lambda invocation. The Java community's answer — GraalVM Native Image — works, but comes with constraints: no dynamic class loading, reflection requires compile-time configuration, and build times extend to minutes. A workaround that requires a different compilation model and limits language features is not a satisfying performance solution.

**Boxing performance costs**: As discussed in the type system section, `List<Integer>` incurs boxing costs that `list<int>` in a language with value semantics does not. For numerical-heavy code — scientific computing, financial calculations, data processing — the boxing overhead is significant. Java's reputation for being "slow for numerical computing" relative to C++ and Fortran is partially explained by GC overhead and partially by boxing. Python with NumPy outperforms naive Java numerical code for the same reason: NumPy arrays are contiguous unboxed values; Java arrays of `Integer[]` are arrays of pointers to boxed heap objects.

**GC tuning as operational complexity**: Even with modern GCs, Java applications require GC tuning for production. G1 GC accepts dozens of configuration flags; ZGC has its own tuning parameters; choosing between G1, ZGC, and Shenandoah requires understanding GC internals. Many Java operations teams run with default GC settings and discover GC-related performance issues only under production load. The fact that modern Java GCs are excellent does not eliminate the complexity of understanding them — it just means the consequences of misconfiguration are less severe than they once were.

**Warmup period**: JIT compilation is triggered by invocation counts. A freshly started JVM runs interpreted code until the JIT kicks in. For applications that process bursts of traffic — rolling deployments, canary instances, seasonal workloads — the warmup period means the first minutes of operation are slower than steady-state performance. Profile-Guided Optimization with GraalVM Enterprise Edition can mitigate this for AOT-compiled code, but that requires a commercial product and additional build complexity.

---

## 10. Interoperability

**JNI as 25-year technical debt**: Java's primary native interoperability mechanism from 1996 to 2024 was JNI. The research brief calls it "verbose, error-prone" [OPENJDK-JEP454]. This is accurate but understated. JNI requires:
- Writing C code to define native methods
- Handling JNIEnv pointers in every call
- Manual management of local and global references to Java objects (get this wrong, and you leak or corrupt memory)
- Explicit type conversion between Java types and C types
- Exception handling that crosses the Java/native boundary

Every JNI bug can crash the JVM, not just the current thread. JVM crashes from JNI bugs have caused production incidents across thirty years of Java deployment. The Foreign Function & Memory API (final Java 22, 2024) is the correct solution — clean, safe, pure-Java. But it arrived twenty-eight years after JNI did. The timeline matters: C# had P/Invoke (1.0, 2002) as a comparably ergonomic native interop from its initial release. Java required twenty-eight years to reach equivalent ergonomics.

**Module system adoption struggles**: The Java Platform Module System (JPMS), introduced in Java 9 (2017), was intended to modularize the JDK and provide a mechanism for application modularization. Nine years later, JPMS adoption outside the JDK itself is limited. The Spring Boot team documented extensive struggles making Spring Boot fully compatible with JPMS modules [JAVA-VERSION-HISTORY]. The result: JPMS's `--add-opens` flags became a standard workaround, widely visible in application startup scripts and build configurations. JPMS's promise — that the JDK's internal APIs would be inaccessible by default, improving security and maintainability — was partially achieved by brute-forcing access via `--add-opens` in the applications that needed it most.

**The Oracle v. Google lawsuit**: Oracle acquired Sun in 2010 and immediately sued Google over Android's use of Java APIs. The case ran for eleven years, through multiple trial courts and two trips to the US Supreme Court, ultimately resolved in Google's favor in 2021 on fair use grounds [GOOGLE-ORACLE-SCOTUS]. The lawsuit's duration and uncertainty created a chilling effect on Java adoption in new platforms. Companies considering Java for new projects had to assess Oracle's willingness to sue over API compatibility. The resolution is favorable, but the eleven-year uncertainty is a governance failure: Oracle used intellectual property law as a business weapon against the Java ecosystem's most prominent adopter.

**The Android fork**: Android's ART runtime (Android Runtime) is not the JVM. Android supports a subset of Java APIs — historically Java 6-7 level, now with backported Java 8 features — and has diverged from standard Java in toolchain, API availability, and runtime behavior. This means Java code written for the JVM does not necessarily run on Android, and vice versa. The "Write Once, Run Anywhere" promise failed for Java's most important mobile platform. Kotlin solved this by targeting both JVM and Android ART transparently.

---

## 11. Governance and Evolution

Oracle's stewardship of Java is the most legitimately concerning aspect of the language's future. The criticisms here are structural, not personal.

**Oracle's monopolistic control**: Oracle controls the Java Language Specification, the Java Virtual Machine Specification, the JCP, and the TCK. No external body can standardize Java. Sun submitted Java to ISO/IEC in 1997 and to ECMA in 1998; both efforts failed because Sun refused to cede control [JAVA-WIKIPEDIA]. Oracle inherited this control and has not changed the posture. Every other major language has either external standardization (C/C++/COBOL via ISO, ECMAScript via ECMA) or a fully independent governance structure (Python Software Foundation, Rust Foundation, Go via Google but with external community governance). Java's specification is controlled by a commercial entity that has demonstrated willingness to use Java as a litigation weapon.

**JCP effectiveness**: The Java Community Process theoretically allows the broader community to participate in Java's evolution. In practice, Oracle controls the JCP's Executive Committee and has final say over all JSRs. The JCP has been criticized for being a rubber-stamp process for Oracle's predetermined decisions. The OpenJDK community is more genuinely collaborative — significant GC work (Shenandoah by Red Hat, ZGC by Oracle, contributions from Amazon, Azul, Microsoft) reflects real multi-vendor cooperation — but language evolution remains Oracle-controlled.

**Licensing uncertainty**: Oracle changed its licensing model for Oracle JDK in 2019, requiring paid subscriptions for commercial use of Oracle JDK 8 and later in production environments. This drove the adoption of OpenJDK distributions (Eclipse Temurin, Amazon Corretto, Microsoft OpenJDK, Azul Zulu) — Oracle JDK market share fell from ~75% in 2020 to ~21% in 2024 [TMS-JAVA-STATS]. The licensing change itself may have been legitimate business strategy, but the manner of its introduction — mid-cycle, without extended notice, affecting existing production deployments — created real operational disruption. Organizations had to audit their Java usage, switch distributions, and in some cases negotiate Oracle support contracts. The uncertainty about Oracle's future licensing decisions is a real factor in enterprise Java adoption planning.

**Feature delivery velocity**: The case of Project Valhalla is the clearest evidence of governance dysfunction. Value types — the fix for Java's primitive/reference duality — have been in active development since approximately 2014. As of February 2026, JEP 401 (Value Classes and Objects) is in early-access JDK 26 builds, not in a production release. Twelve years for a feature that is conceptually straightforward (Rust has had value semantics since its first release; C# had value types from .NET 1.0 in 2002) is not explained by technical difficulty alone. It reflects the extreme caution required when every design decision must preserve backward compatibility with thirty years of JVM bytecode and library code.

**String templates withdrawal**: Java 21 (2023) introduced string templates as a preview feature (JEP 430). Java 22 (2024) continued them as a second preview. Java 23 (2024) **withdrew** string templates entirely, citing insufficient design refinement [JAVA-VERSION-HISTORY]. This is the correct governance behavior — the preview mechanism is intended to allow iteration and retraction — but it demonstrates that Java's feature pipeline is not free of dead ends. Developers who adopted string templates in previews were left with code that no longer compiled on the latest JDK. The incident reveals that even Java's careful preview process does not guarantee forward progress.

**Vector API as chronic incubation**: The Vector API (SIMD operations via JVM) has been in incubation since Java 16 (2021). As of JDK 26 early-access builds (2025), it is in its eleventh incubation — four years in incubator status. This is not a preview (which can be graduated or retracted); it is incubation, meaning the API is not yet stable enough for preview. For developers who need SIMD performance, the API has been technically available but unstable for four years.

---

## 12. Synthesis and Assessment

### Greatest Strengths

Java's strengths are real and deserve acknowledgment:

**Ecosystem maturity**: The Maven Central repository with 600,000+ artifacts, the depth of Spring/Hibernate/Kafka tooling, and the quality of IntelliJ IDEA's Java support are genuine competitive advantages that take decades to build. No new language — not Go, not Rust, not Kotlin — has matched Java's ecosystem breadth in the enterprise domain.

**JVM engineering**: ZGC's sub-millisecond pauses on terabyte heaps, HotSpot's JIT optimizations, and virtual threads are world-class engineering achievements. The JVM is one of the most sophisticated runtime environments ever built.

**Backward compatibility**: While the costs of Java's compatibility commitment are high, the benefits are real. A Java 8 application written in 2014 runs on Java 25 in 2026 without modification. This stability has enabled long-lived enterprise systems that other ecosystems cannot match.

**Institutional presence**: 90% of Fortune 500 companies rely on Java for core systems [SECONDTALENT-JAVA]; Apache Hadoop, Kafka, and Spark — foundational big data infrastructure — are Java/JVM-based. Java's institutional embeddedness is not going away.

### Greatest Weaknesses

**The primitive/reference duality is a foundational design error.** Requiring boxing for generic collections — a mandatory indirection that imposes memory and performance costs — was not inevitable. C# had value types from .NET 1.0. The fix has been in progress for twelve years and is not yet in a production release. Until Project Valhalla ships, Java collections cannot be specialized for primitive types without third-party libraries (Eclipse Collections, Trove), and every `List<Integer>` pays the boxing tax.

**Checked exceptions failed, and Java will not remove them.** The industry verdict is unanimous: Kotlin, Scala, Groovy, and all post-Java JVM languages dropped checked exceptions. Spring, Hibernate, and Java's own Stream API route around them. The feature adds ceremony, encourages exception swallowing, and is incompatible with functional programming patterns. Yet checked exceptions will never be removed from Java because removal would break existing code. Language designers who add mandatory exception handling to APIs should study Java's trajectory: if ergonomics are poor, developers will find the worst possible workarounds.

**Backward compatibility as a religion has compounding costs.** Java's commitment to run Java 8 bytecode on Java 25 JVMs is extraordinary. It is also why type erasure cannot be fixed without a new compilation model, why `ObjectInputStream` remains in the standard library despite being a systemic security risk, why `java.util.Date` and `java.util.Calendar` remain after `java.time` replaced them in 2014, and why generics cannot be reified. Every bad early decision is permanent. The language designer's lesson: define the scope and limits of backward compatibility before shipping, because "everything forever" is not a sustainable policy.

**Oracle's governance model is a single point of failure and a litigation risk.** Java has no external standardization, no governance structure that survives Oracle's strategic priorities, and a history of using Java as a legal weapon (the Android lawsuit). The ecosystem's dependence on Oracle's continued benevolence is uncomfortable. The OpenJDK multi-vendor collaboration mitigates this somewhat, but Oracle retains ultimate control over the specification.

### Lessons for Language Design

**1. Unify your type system or pay indefinitely.** A type system with two fundamentally different categories of values (primitives and references) forces designers to choose one for every generic abstraction and forces users to pay boxing costs when the wrong one is chosen. Java chose references as the universal generic container and paid the boxing tax for thirty years. The fix — value types and specialized generics — required twelve years of active remediation work and has not shipped. If your type system has primitives and objects, make generics work over both from day one. C# did this with `struct` and value types in generics. Java did not.

**2. Mandatory exception handling must have ergonomic support or it will be circumvented.** Checked exceptions were a well-intentioned attempt to make failure modes explicit. They failed because Java provided no ergonomic way to handle checked exceptions in lambda expressions, functional pipelines, or higher-order functions. The result was exception swallowing (the worst outcome), unchecked wrapping (losing type information), and ecosystem-wide abandonment (Spring, Kotlin). If you require exception handling, ensure your language's functional abstractions can propagate exceptions naturally. If you cannot guarantee that, do not require exception handling.

**3. Null should not be a value for reference types without compiler enforcement.** Retaining null as a universal sentinel value for all reference types guaranteed that NullPointerException would be the most common runtime error. Optional<T> as a library type does not fix this — it creates two parallel null-handling systems. The lesson: nullable and non-nullable types must be first-class language concepts with compiler enforcement (Kotlin's `String?` vs. `String`, Rust's `Option<T>`), not library conventions. Every year of delay in adding nullable types is another year of NPEs in production.

**4. API defaults must be secure.** Java's XML parsers enabled XXE by default; Java's object deserialization enables arbitrary class instantiation by default; Java's JNDI integration enabled remote code execution through Log4j. The pattern is consistent: Java's libraries were designed for functionality without considering what the default security posture should be. Language designers should assume their APIs will be used under adversarial conditions and design defaults accordingly. Insecure functionality should require explicit opt-in, not opt-out.

**5. Interoperability cannot be an afterthought.** JNI was the only native interop mechanism for twenty-eight years and was notoriously difficult to use correctly. Designing clean native interop is not easy, but it should be designed at the language's inception for any language that will interact with native code. The Foreign Function & Memory API is excellent — it arrived twenty-eight years too late. C# had P/Invoke as part of .NET 1.0. Rust has FFI built into its design model.

**6. Backward compatibility scope must be defined explicitly.** Java's "everything forever" compatibility commitment has compounding costs that grow with the language's age. The language designer's choice is not binary (break everything vs. break nothing) — it is dimensional: which compatibility guarantees are load-bearing, and which can be relaxed to enable progress? Python 3 broke backward compatibility and survived (at cost). Java has been unable to fix type erasure, checked exceptions, the serialization API, or null because of compatibility. Designers should identify the highest-risk early decisions and build in migration paths before shipping rather than discovering them after the ecosystem has locked in.

**7. Governance structure must be independent of commercial stewardship.** A programming language with no external standardization and no governance structure that survives its commercial owner's strategic interests is fragile. Java's eleven-year litigation against Android's use of Java APIs created uncertainty across the entire ecosystem. Language designers building infrastructure that others will depend on for decades should establish independent governance early, before commercial interests diverge from ecosystem interests.

**8. Supply chain risk scales with ecosystem size.** Java's 600,000+ Maven Central artifacts create an attack surface that individual developers and organizations cannot audit. Log4Shell demonstrated that a vulnerability in a transitive dependency can affect virtually every Java application simultaneously. Ecosystem builders should invest in supply chain tooling, SBOM support, and minimal-dependency defaults. The Go standard library's breadth reduces third-party dependency exposure by design.

**9. Preview features should be graduated, not retracted, when possible.** Java's withdrawal of string templates after two preview cycles demonstrates that even careful preview processes can produce dead ends. Developers who invested in previewed features lost that work. Where possible, design preview features conservatively — prefer underspecified but stable over ambitious but retractable.

**10. Performance regression paths must be addressed before they calcify.** Java's startup overhead, boxing costs, and GC pause history were all addressable at different points in the language's evolution. They were not addressed until market pressure (serverless, cloud costs, latency requirements) became acute. By then, fixing each problem required either a new compilation model (GraalVM Native Image), new language features (Project Valhalla), or a new GC algorithm (ZGC). Each fix took years. Performance problems that are structural should be fixed before they create path dependencies that make remediation expensive.

### Dissenting Views

*The following views are held by some council members and are preserved here for completeness.*

**On backward compatibility**: Some argue that Java's backward compatibility is its greatest strength, not a weakness, and that the compounding cost argument underestimates how much value existing Java codebases represent. The ability to upgrade JDKs without recompiling application code is genuinely extraordinary and has saved enormous migration costs across the enterprise Java ecosystem.

**On Oracle governance**: Some argue that Oracle's stewardship, while imperfect, has funded the JVM engineering work (ZGC, Virtual Threads, Panama, Valhalla) that no community organization would have funded at this scale. The OpenJDK multi-vendor collaboration works precisely because Oracle sets the technical direction rather than fragmenting it across competing visions.

**On Java's decline**: Java's usage (30% of all developers in 2024 [SO-2024-TECH]) and market position (90% of Fortune 500 [SECONDTALENT-JAVA]) make "decline" a strong claim. Java is not declining — it is maturing. The migration of new use cases to Go, Rust, and Kotlin does not affect Java's dominant position in existing enterprise infrastructure, which will be Java for the foreseeable future.

---

## References

[JAVA-WIKIPEDIA] "Java (programming language)." Wikipedia. https://en.wikipedia.org/wiki/Java_(programming_language)

[JAVA-VERSION-HISTORY] "Java version history." Wikipedia. https://en.wikipedia.org/wiki/Java_version_history

[OPENJDK-VALHALLA] "Project Valhalla." OpenJDK. https://openjdk.org/projects/valhalla/

[INSIDE-JAVA-VALHALLA] "Try Out JEP 401 Value Classes and Objects." Inside.java, October 2025. https://inside.java/2025/10/27/try-jep-401-value-classes/

[OPENJDK-ERASURE-DEFENSE] "In Defense of Erasure." OpenJDK Project Valhalla design notes. https://openjdk.org/projects/valhalla/design-notes/in-defense-of-erasure

[LITERATE-JAVA-CHECKED] "Checked Exceptions and Functional Interfaces." Literate Java. https://literatejava.com/exceptions/checked-exceptions-and-functional-interfaces/

[CISA-LOG4J] "Apache Log4j Vulnerability Guidance." CISA, December 2021. https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance

[PSYCHIC-SIGS] Forshaw, J. "You're Probably Not Using ECDSA Correctly." Project Zero Blog, April 2022. https://bugs.chromium.org/p/project-zero/issues/detail?id=2233

[ORACLE-CPU-APR2025] "Oracle Critical Patch Update Advisory — April 2025." Oracle. https://www.oracle.com/security-alerts/cpuapr2025.html

[ORACLE-CPU-JAN2025] "Oracle Critical Patch Update Advisory — January 2025." Oracle. https://www.oracle.com/security-alerts/cpujan2025.html

[CVEDETAILS-ORACLE-JRE] "Oracle JRE / JDK Vulnerabilities." CVEDetails.com. https://www.cvedetails.com/vendor/93/Oracle.html

[BROADCOM-JAVA-CVE-2025] "Oracle Java SE April 2025 Critical Patch Update." Broadcom Security Advisory.

[NAKSHATRI-2016] Nakshatri, S. et al. "Analysis of Exception Handling Patterns in Java Projects: An Empirical Study." ICSE 2016 Workshop, 2016. (Analyzes exception handling in 94 Java open-source projects.)

[SO-2024-TECH] Stack Overflow Developer Survey 2024 — Technology. https://survey.stackoverflow.co/2024/technology

[SO-2025-TECH] Stack Overflow Developer Survey 2025 — Technology. https://survey.stackoverflow.co/2025/technology

[SECONDTALENT-JAVA] "Java Statistics: Adoption, Usage, and Future Trends." Second Talent. https://www.secondtalent.com/resources/domain-java-statistics/

[TMS-JAVA-STATS] "Java statistics that highlight its dominance." TMS Outsource. https://tms-outsource.com/blog/posts/java-statistics/

[ANDROID-METRO] "Android Kotlin Vs Java Market Share." Android Metro. https://www.androidmetro.com/2024/01/android-kotlin-vs-java-market-share.html

[INFOQ-JAVA-TRENDS-2025] "InfoQ Java Trends Report 2025." InfoQ. https://www.infoq.com/articles/java-trends-report-2025/

[INFOQ-JAVA25] "Java 25, the Next LTS Release." InfoQ, September 2025. https://www.infoq.com/news/2025/09/java25-released/

[TECHEMPOWER-R23] TechEmpower Web Framework Benchmarks Round 23. https://www.techempower.com/benchmarks/

[GRAALVM-ADVANTAGES] "GraalVM Native Image Advantages." GraalVM Documentation. https://www.graalvm.org/latest/reference-manual/native-image/

[FOOJAY-GC-GUIDE] "The Ultimate 10 Years Java Garbage Collection Guide 2016–2026." Foojay.io. https://foojay.io/today/the-ultimate-10-years-java-garbage-collection-guide-2016-2026-choosing-the-right-gc-for-every-workload/

[LOGICBRACE-GC] "Generational ZGC in JDK 23." LogicBrace. https://logicbrace.com/posts/generational-zgc-in-jdk-23/

[DATADOGHQ-GC] "A deep dive into Java garbage collectors." Datadog Blog. https://www.datadoghq.com/blog/understanding-java-gc/

[OPENJDK-JEP454] "JEP 454: Foreign Function & Memory API." OpenJDK. https://openjdk.org/jeps/454

[BENCHMARKSGAME] "Computer Language Benchmarks Game." https://benchmarksgame-team.pages.debian.net/benchmarksgame/

[GOOGLE-ORACLE-SCOTUS] "Google LLC v. Oracle America, Inc." U.S. Supreme Court, April 5, 2021. 593 U.S. 1 (2021).

[MEDIUM-MAVEN-GRADLE] "Maven vs. Gradle in 2025." Medium. https://medium.com/@ntiinsd/maven-vs-gradle-in-2025-the-ultimate-deep-dive-to-choose-your-build-tool-wisely-b67cb6f9b58f

[JETBRAINS-2025-ECOSYSTEM] "State of Developer Ecosystem 2025." JetBrains. https://devecosystem-2025.jetbrains.com/

[JAVACHALLENGERS-JCP] "Java Community Process (JCP) Explained." Java Challengers. https://javachallengers.com/java-community-process/

[ORACLE-EXCEPTIONS-TUTORIAL] "Lesson: Exceptions." Oracle Java Tutorials. https://docs.oracle.com/javase/tutorial/essential/exceptions/index.html

[ROCKTHEJVM-LOOM] "Java Virtual Threads." Rock the JVM Blog. https://blog.rockthejvm.com/ultimate-guide-to-java-virtual-threads/

[ROCKTHEJVM-STRUCTURED] "Structured Concurrency in Java." Rock the JVM Blog. https://blog.rockthejvm.com/structured-concurrency-in-java/

[JLS-MEMORY-MODEL] "Chapter 17. Threads and Locks." Java Language Specification. https://docs.oracle.com/javase/specs/

[GILLIUS-STARTUP-2025] "Spring Boot GraalVM Native Image Startup." Gillius Blog, 2025. https://gillius.org/blog/2023/09/graalvm-native-image-spring-boot.html

[ANDREW-BAKER-PAUSELESS] Baker, A. "Pauseless GC Improvements in Java 25." Deep-dive analysis, 2025.
