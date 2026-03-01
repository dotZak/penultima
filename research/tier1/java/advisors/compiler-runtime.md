# Java — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Java"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

Java's compiler and runtime story is, at its core, one of the most sophisticated managed-runtime engineering programs in computing history — and one of the most instructive for understanding the tradeoffs inherent in managed execution. The five council members have collectively produced a technically accurate picture of this story. The factual claims about GC algorithms, JIT compilation, virtual threads, and GraalVM are substantially correct and well-evidenced. The analysis is sophisticated enough that the advisor's primary job is not to correct errors but to sharpen precision, flag technical nuances that affect design lessons, and draw out implications the council has identified but not fully developed.

Three areas require the most attention. First, the sub-millisecond ZGC claim is correct but underspecified: the council says "sub-millisecond pauses regardless of heap size" without distinguishing stop-the-world pauses from concurrent GC phases, and without noting ZGC's throughput overhead relative to throughput-optimized collectors. Second, the GraalVM Native Image treatment is technically sound but underemphasizes a critical detail: Native Image runs on Substrate VM with a different GC subsystem, not HotSpot, which has throughput implications the council does not make explicit. Third, virtual thread pinning in `synchronized` blocks — a real and documented operational hazard addressed by JEP 491 in JDK 24 — deserves more precise treatment than it receives.

The council's handling of the Java Memory Model (JMM) is one of its strongest technical contributions. The JMM's choice to specify defined (if weak) behavior for data races — rather than the undefined behavior model of C/C++ — is correctly identified as a significant design decision, one with concrete implications for language safety that the broader field has not always recognized.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

The council's consensus on GC safety is technically correct. Java's GC-based memory model does eliminate dangling pointers, use-after-free, double-frees, and buffer overflow from manual allocations — the vulnerability classes documented in [MSRC-2019] as approximately 70% of Microsoft's C/C++ CVEs. This is a structural elimination, not a mitigation. All five council members correctly identify this.

The GC algorithm timeline is accurate. The historian correctly states that G1 GC was introduced experimentally in Java 6 and became the default in Java 9. ZGC's progression — experimental in Java 11, production-ready in Java 15, Generational mode as default in Java 23 — is correctly documented across multiple council members with appropriate citations [LOGICBRACE-GC] [FOOJAY-GC-GUIDE].

The historian's treatment of JSR-133 is technically sound: the original Java 1.0–1.4 memory model underspecified concurrent semantics, and JSR-133 (Java 5, 2004) established formal happens-before semantics for `synchronized`, `volatile`, and `final` fields [JLS-MEMORY-MODEL]. The characterization of JSR-133 as "one of the most rigorous memory models in mainstream language design at the time" is defensible. The implication — that Java shipped a language with inadequate concurrency semantics and required nine years to formalize them — is historically accurate.

The realist correctly distinguishes Shenandoah's availability: it is included in OpenJDK builds (Eclipse Adoptium Temurin, Amazon Corretto) but not in Oracle's official JDK builds. This is an important practical detail. Oracle JDK users who want Shenandoah must switch distributions.

The object header size claim — "12–16 bytes on 64-bit JVMs with compressed OOPs" — is accurate. With compressed OOPs enabled (required for heaps < ~32GB): 8-byte mark word + 4-byte compressed class pointer = 12 bytes per object. Without compressed OOPs: 8 + 8 = 16 bytes. The boxing overhead calculation is correct: a `List<Integer>` of one million elements requires approximately 16–20 bytes per Integer object (header + 4-byte value, rounded to 8-byte alignment) plus 4–8 bytes per reference in the backing array, versus 4 bytes per element in a contiguous `int[]` array. The overhead is real and meaningful for memory-intensive applications.

The JMM's treatment of data races is accurately characterized by the realist: the JMM specifies defined (if weak) behavior for programs containing data races, unlike C/C++ which treats races as undefined behavior. This is an important design distinction with security implications: undefined behavior in C/C++ can be exploited by compilers to produce arbitrary code in the presence of races; Java's defined semantics prevent this class of optimization-enabled security vulnerability.

The Foreign Function & Memory API (FFM, final Java 22, JEP 454) descriptions are accurate [OPENJDK-JEP454]. The historical comparison to JNI's 25-year dominance is correct.

**Corrections needed:**

*ZGC pause claims need precision.* The apologist's claim that "ZGC achieves sub-millisecond garbage collection pauses regardless of heap size, including on terabyte heaps" is directionally correct but requires clarification: the sub-millisecond claim refers specifically to stop-the-world (STW) pause phases. ZGC's concurrent marking and compaction phases run alongside application threads (as concurrent work) and do not pause execution, but they consume CPU resources and add GC barrier overhead in mutator threads. The realist correctly notes "ZGC's concurrent collection requires CPU overhead, typically 10–15% compared to Parallel GC in throughput-maximizing scenarios" — but the apologist's framing omits this cost entirely, giving an incomplete picture. Language designers reading this as a cost-free solution will be misled.

Additionally, "sub-millisecond" is the design target for STW pauses, not an absolute guarantee under all conditions. Under extreme allocation rates or initialization/finalization phases, brief STW pauses can exceed this target. The claim is broadly accurate but should be stated with appropriate hedging.

*Platform thread default stack size.* The detractor states "approximately 1MB stack by default." On most Linux x86-64 OpenJDK deployments, the default JVM thread stack size (`-Xss`) is 512KB, not 1MB. The figure is configurable at both the OS level and JVM level, and some platforms and configurations do use 1MB, but "approximately 1MB" overstates the common case by roughly 2x. The correct characterization is "hundreds of kilobytes to ~1MB, depending on platform and configuration." For the architectural point being made — that platform threads are expensive relative to virtual threads — the qualitative claim holds, but the specific figure should be corrected.

**Additional context:**

The JMM's formally specified behavior for racy programs is worth developing further in the consensus report. The JMM's choice to avoid undefined behavior is not simply a correctness decision — it is a security decision. C/C++ compilers can eliminate security-critical checks that appear unreachable after undefined behavior, leading to vulnerability exploitation. Java's defined race semantics prevent this class of compiler-assisted security failure. This is an underappreciated design lesson.

The historian correctly notes that the original JMM allowed "subtly broken concurrent Java programs" in the Java 1.0–1.4 era. The nine-year gap between Java 1.0 and JSR-133 represents a period during which production Java systems built concurrent code on assumptions that the specification did not guarantee. Some JVM implementations happened to be conservative enough that the code worked anyway; this masked the specification problem for years.

C2's escape analysis optimization is relevant to the object header overhead discussion. Escape analysis allows the JVM to allocate objects on the stack rather than the heap when the JIT can prove they do not escape the current method scope. This reduces GC pressure for short-lived objects in hot paths. The practitioner and apologist discuss GC but do not mention escape analysis, which is a meaningful optimization that narrows the boxing overhead impact in JIT-warmed code.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

The core facts about virtual threads are correct across all council members. Virtual threads (JEP 444, final Java 21) are JVM-managed fibers that unmount from carrier OS threads when blocking on I/O, enabling millions of concurrent operations without the stack-per-thread overhead of platform threads. The carrier thread pool defaults to one thread per CPU core. The claim that "millions of virtual threads can run concurrently" is verifiable.

The historian's account of green thread removal in Java 1.3 (2000) is correct. Early Java on Linux did support green threads (userspace scheduling), which were removed in favor of 1:1 OS thread mapping because the platform assumed symmetric multiprocessing (SMP) support and because OS threading was expected to improve. The subsequent twenty-year absence of lightweight threading, followed by virtual threads' introduction, is historically accurate.

The description of the `synchronized` block pinning problem is accurate and technically precise. The practitioner correctly states that "a virtual thread blocked in `synchronized` holds the carrier thread the way a platform thread would" and that "Java 24's synchronized block optimization partially addresses this." JEP 491 (Synchronize Virtual Threads without Pinning), targeted for JDK 24, does allow virtual threads to unmount from their carrier threads even while holding monitors — eliminating the primary pinning concern in most application code. This is a correct and important technical detail that the practitioner handles better than other council members.

The characterization of the `CompletableFuture` API as less ergonomic than async/await is correct. The realist says "`CompletableFuture` composability is less ergonomic than async/await in other languages" — this is an accurate and widely-acknowledged assessment of the API.

The description of Structured Concurrency (JEP 505, final Java 24) is accurate. `StructuredTaskScope` provides hierarchical task scoping where subtasks are bounded to a parent's lifetime. The `ShutdownOnFailure` and `ShutdownOnSuccess` shutdown policies the practitioner describes match the actual API.

The claim that "virtual threads do not help CPU-bound parallelism" (realist) is correct and important. A virtual thread blocked on CPU computation does not release its carrier thread. This is not a deficiency but a scope boundary: virtual threads address I/O-bound concurrency scaling; CPU-bound parallelism still requires explicit thread management via `ForkJoinPool`.

The detractor's description of the shared `ForkJoinPool` starvation problem is technically accurate. The parallel streams API uses `ForkJoinPool.commonPool()` by default. A computationally expensive parallel stream operation in one component of an application can saturate the common pool, starving parallel operations in other components. The workaround (submitting a `Callable` that executes the stream to a custom `ForkJoinPool`) is non-obvious and underdocumented.

**Corrections needed:**

*Platform thread stack size (same as Section 3).* The detractor states "approximately 1MB stack by default." In most OpenJDK configurations, the actual default is 512KB. As noted above, this is a minor but verifiable inaccuracy.

*The JMM's race semantics.* The detractor says "The JMM specifies what happens when data races occur (sequential consistency only for data-race-free programs; defined but weak behavior for racy programs) rather than preventing them." The first part is accurate (DRF programs have SC semantics). The second part — "defined but weak behavior for racy programs" — is broadly correct but slightly imprecise: the JMM for racy programs allows behaviors consistent with Java's hardware memory model, which means that specific operations may appear out of order as observed by other threads, but it does not allow the arbitrary behavior (including security-critical violations like eliminating bounds checks) that C/C++ undefined behavior permits. The distinction matters for security analysis.

**Additional context:**

The council correctly identifies that Java has no built-in data race detector, contrasting with Go's `go test -race`. What the council does not mention is that ThreadSanitizer (TSan) can be applied to JVM-hosted code via instrumentation agents, and there are JVM-level race detection research projects (e.g., RoadRunner, Chord). These are not part of the standard development workflow, but they exist. The more significant point is that Go's race detector is first-class (zero configuration, ships with the toolchain, runs in CI by default in many organizations), while Java's race detection requires third-party tools and deliberate setup. The qualitative claim — "meaningful gap" — is correct.

The carrier thread pool configuration for virtual threads is an operational detail worth noting for the consensus report: the JVM creates a `ForkJoinPool` of carrier threads equal to `Runtime.getRuntime().availableProcessors()`. This means that I/O operations on virtual threads scale to millions of concurrent tasks, but CPU-bound virtual thread work still saturates at the carrier thread count. The abstraction can mislead developers who create millions of virtual threads for CPU-bound work expecting actual parallelism.

The JEP 491 virtual thread pinning improvement (JDK 24) is an important correction to pre-JDK-24 documentation. Prior to JDK 24, any `synchronized` block would pin the virtual thread. This was a documented known limitation that caused performance problems when legacy code (including JDK internal classes using `synchronized`) appeared in virtual thread call stacks. Post-JDK-24, most synchronization no longer causes pinning, with a few remaining exceptions (JNI calls, native methods). This transition should be noted in the consensus report because it affects the validity of pre-JDK-24 performance guidance about virtual threads.

---

### Section 9: Performance Characteristics

**Accurate claims:**

The TechEmpower Round 23 benchmark citations are directionally accurate. Spring Boot occupies a lower throughput tier than C# ASP.NET Core and Rust Actix, while performing comparably with many Go frameworks in absolute terms. The Computer Language Benchmarks Game comparison (Java competitive with Go and C#, significantly faster than Python/PHP/Ruby) is consistent with published data [BENCHMARKSGAME]. The directional claims are correct.

The description of HotSpot's tiered compilation (C1 for initial invocations, C2 for hot paths) is accurate. C2's optimization portfolio — inlining, loop unrolling, escape analysis, lock elision, devirtualization — represents state-of-the-art JIT optimization. The apologist's comparison to profile-guided optimization (PGO) in C/C++ is apt: JIT compilation has access to actual runtime profile data, which can make it more effective than static PGO for adaptive optimization under changing workloads.

Spring Boot startup time (3–4 seconds JVM mode) and GraalVM Native Image startup time (<100ms) are accurately and consistently reported across all five council members with appropriate citations [GILLIUS-STARTUP-2025] [GRAALVM-ADVANTAGES].

The native image build time figure (5–15 minutes for a Spring Boot application, per the practitioner) is accurate for typical hardware configurations and typical project sizes.

The practitioner's description of Class Data Sharing (CDS) as reducing warmup time is accurate: CDS precomputes class layout metadata and can substantially reduce JVM startup and initial JIT warmup time for long-running server processes, without the full constraints of Native Image.

The realist's note that ZGC's throughput overhead is "typically 10–15% compared to Parallel GC" is accurate and important. ZGC achieves low pause times through concurrent work and GC barriers in mutator threads. These barriers — write barriers for object reference updates — add overhead to every pointer store operation. Parallel GC, which stops the world for collection, has no such runtime overhead in application threads, making it superior for maximum throughput in batch scenarios where pause times are irrelevant.

**Corrections needed:**

*TechEmpower category specificity.* Multiple council members cite specific multipliers from TechEmpower Round 23: "Spring Boot at approximately 14.5x baseline throughput, versus Go Fiber at 20.1x and C# ASP.NET Core at 36.3x" (detractor). TechEmpower measures five test types: JSON serialization, single database query, multiple database queries, Fortunes (template rendering), data updates, and plaintext response. These multipliers vary significantly by test category. The cited numbers appear to reference a specific category (likely the JSON or plaintext test) but the council documents do not specify which. This omission means readers may incorrectly generalize the exact multipliers to all test types. The directional claim (Spring Boot significantly lower than ASP.NET Core) is correct across most categories, but the specific multipliers should reference a specific test category or be presented as approximate ranges. The consensus report should clarify this.

*GraalVM Native Image — Substrate VM vs. HotSpot.* This is the most technically significant clarification the council requires. Multiple council members describe GraalVM Native Image as a performance optimization for startup time and memory, which is accurate. What is not clearly stated anywhere in the council output is that Native Image does not run on HotSpot at all. GraalVM Native Image produces a standalone executable that runs on Substrate VM — a different VM implementation with a different GC subsystem (Serial GC or G1, but without HotSpot's JIT-adaptive tuning and profiling). This has two practical consequences:

1. **Native Image trades JIT throughput for AOT startup.** A JIT-warmed HotSpot application typically outperforms the equivalent Native Image application in sustained throughput for compute-intensive workloads, because HotSpot can observe actual runtime profiles and recompile hot paths with increasingly aggressive optimization. Native Image is compiled once at build time and cannot adapt to runtime behavior. The tradeoff is intentional and appropriate for the target use cases (serverless, CLI, startup-sensitive containers), but the apologist's framing — that Native Image "fundamentally changes the deployment calculus" without noting the throughput tradeoff — gives an incomplete picture.

2. **Native Image GC is separate from HotSpot's GC portfolio.** ZGC (Generational) is not available in Native Image; Native Image uses either Serial GC (default for small images) or G1 (explicitly requested). The sub-millisecond GC pause claims that the council makes for JVM-based Java do not apply to Native Image deployments.

The consensus report must distinguish HotSpot and Substrate VM clearly, as conflating them produces incorrect inferences about where each technology's performance claims apply.

*Boxing vs. NumPy comparison precision.* The detractor states: "Python with NumPy outperforms naive Java numerical code for the same reason: NumPy arrays are contiguous unboxed values; Java arrays of `Integer[]` are arrays of pointers to boxed heap objects." This is accurate when comparing `List<Integer>` or `Integer[]` to NumPy arrays. However, Java's primitive `int[]` arrays *are* contiguous unboxed values — identical in memory layout to NumPy's `int32` arrays. The performance difference for numerical computing is correctly explained by the generic collections boxing problem, but the comparison should clarify that Java's primitive arrays and NumPy arrays have equivalent memory layout; the overhead arises specifically from generic collections requiring reference types.

**Additional context:**

The council does not mention the Vector API (SIMD operations), which has been in incubator status since Java 16 (2021). As of JDK 26 early-access builds (2025), the Vector API is in its eleventh incubation — four years without graduating to preview status. For performance-sensitive numerical computing, the absence of a stable SIMD API means Java cannot access vectorized hardware instructions through an official language-level mechanism. This represents a significant gap in Java's performance story for numerical workloads. The detractor mentions it in Section 11 (Governance) as evidence of chronic incubation dysfunction, but it belongs in Section 9 as a performance limitation.

The JIT deoptimization and recompilation capability is a performance characteristic that differentiates JIT from AOT and deserves mention. HotSpot's JIT can deoptimize previously compiled code when runtime assumptions are violated (e.g., a class that was assumed to have a single implementation gets a second implementation, invalidating devirtualization). This adaptive deoptimization/recompilation loop is more powerful than static PGO in workloads with changing profiles. It also means that long-running JVM applications can improve performance over time as the JIT accumulates better profile data — a characteristic not present in AOT-compiled systems.

Application Class Data Sharing (AppCDS), Class Data Sharing (CDS), and Spring AOT (Spring Boot 3+) all reduce warmup time by precomputing work that would otherwise occur at JVM startup. The council references Spring AOT in the context of Native Image compatibility but does not consistently connect it to warmup reduction on the JVM. For deployments that cannot use Native Image (due to reflection complexity or dynamic class loading requirements), CDS + AppCDS + Spring AOT can reduce JVM startup time from 3–4 seconds to under 1 second for Spring Boot applications — a middle path the council under-discusses.

---

### Other Sections (Compiler/Runtime Relevant)

**Section 2: Type System — Type Erasure**

The council's treatment of type erasure is accurate: Java generics are compiled with type erasure, meaning `List<String>` and `List<Integer>` have the same JVM type at runtime. The council correctly identifies that this prevents generic code from distinguishing type parameters at runtime (no `T instanceof SomeType`) and requires boxing for primitive type parameters. What the council adds only in passing is the reason this decision was made: type erasure was chosen specifically to maintain backward binary compatibility with pre-Java-5 bytecode. Non-erased generics (reified generics) would require a new bytecode format incompatible with Java 1.4 class files. This was a deliberate compiler-level design tradeoff — compatibility over expressiveness — and it is the kind of decision that language designers must make consciously.

Project Valhalla (value types, JEP 401 in early-access JDK 26 builds) is the designed fix for the primitive-in-generics problem. The council correctly notes it has been in development since approximately 2014. The technical complexity is substantial: retrofitting value types onto a bytecode format and class system designed around reference semantics requires changes to the JVM specification, bytecode verification, and the reflection API. This is genuine compiler engineering difficulty, not just governance slowness.

**Section 6: Ecosystem — Spring's Reflection Dependency**

The detractor and practitioner both correctly note that Spring's dependency injection model relies heavily on reflection, which interacts adversely with both the JPMS module system and GraalVM Native Image. This is a compiler/runtime issue. Spring's use of `@Autowired`, `@Component`, `@Configuration`, and similar annotations relies on runtime reflection to discover and wire beans. The JVM's reflection API allows accessing private fields and methods, bypassing normal access control — which is precisely what JPMS's strong encapsulation intended to restrict. Spring Boot's use of `--add-opens` flags as a workaround is evidence that the framework's runtime model predates and conflicts with the module system.

For Native Image, this means that Spring's reflection usage must be described at build time via JSON configuration files (or Spring AOT's automated equivalent). Spring AOT (Spring Boot 3+) automates much of this, but it adds a build-time analysis step with its own failure modes. The practitioner describes this accurately; it should be prominent in the consensus report's synthesis of GraalVM trade-offs.

**Section 11: Governance — String Templates Withdrawal**

The withdrawal of string templates from JDK 23 (previewed in Java 21 and 22, withdrawn in Java 23) has compiler implementation implications worth noting. String templates were designed to support safe interpolation of strings with arbitrary processors (not just string concatenation). The design was withdrawn because the proposal's interaction with existing string constants (compile-time string constants in the constant pool) and with frameworks expecting literal string templates proved insufficiently refined. This is an example of a feature that appeared sound at the language level but had underspecified compiler semantics at the bytecode level. The consensus report's treatment of this as a governance success (retraction over premature finalization) is correct, but the compiler implementation complexity deserves acknowledgment.

---

## Implications for Language Design

**1. Specifying concurrent semantics before shipping is not optional.**
Java's nine-year gap between Java 1.0's informal threading model and JSR-133's JMM formalization demonstrates the cost of underspecifying concurrency. Programs written against informal assumptions "worked" on specific JVM implementations but had no guaranteed behavior. Language designers must formalize their memory model — happens-before relationships, volatile-equivalent semantics, final field guarantees — before the language is in production. Retrofitting a formal model onto an existing language and codebase is substantially harder than designing it in from the start, because real-world programs will have developed dependencies on implementation-specific behaviors. Java's JSR-133 was a success precisely because it was specification-conservative: it specified at least as much as existing implementations already provided.

**2. Undefined behavior in concurrent programs is a security property, not just a correctness one.**
The JMM's choice to specify defined (if weak) behavior for data races — rather than the undefined behavior model of C/C++ — has security significance beyond correctness. C/C++ compilers can eliminate security-critical bounds checks or null-pointer guards through undefined behavior optimization. Java's defined race semantics prevent compilers from exploiting races to produce arbitrary security violations. Language designers choosing a memory model should understand that "undefined behavior for races" is not merely a performance optimization license — it is a class of security vulnerability.

**3. JIT and AOT compilation serve different use cases and should not be conflated.**
Java's experience with HotSpot (JIT) and GraalVM Native Image (AOT) demonstrates that these are not interchangeable compilation strategies. JIT provides adaptive optimization at the cost of warmup time and persistent memory footprint. AOT provides fast startup and predictable memory at the cost of the JIT's adaptive recompilation capability. Languages that need to serve both long-running services (where JIT's adaptive optimization is valuable) and short-lived workloads (where AOT's startup advantage dominates) need either two distinct compilation strategies or a design that bridges them. The JVM's design proved sufficiently general to support both through GraalVM, but at the cost of a Substrate VM that is architecturally distinct from HotSpot. Language designers should not assume their JIT design will naturally extend to AOT.

**4. GC algorithm selection as a runtime parameter is a strong design pattern.**
Java's practice of shipping multiple production-quality GC implementations behind a single command-line switch — Parallel GC for throughput, G1 for general-purpose, ZGC for latency, Shenandoah for consistent low-latency — is an underappreciated design success. It allows the same language and bytecode to serve radically different workload requirements without code changes. The cost is GC implementation maintenance complexity at the JVM level, but the benefit is that operators can tune the execution model to the problem domain without changing the program. Language designers building managed runtimes should consider whether a single GC algorithm is sufficient for the language's intended workload range, or whether a pluggable GC strategy is warranted from the start.

**5. Primitives-in-generics must be designed correctly before the type system ships.**
Java's thirty-year effort to add value types (Project Valhalla) to address the boxing overhead problem is the canonical case study in the cost of primitive/reference duality in generic type systems. The original decision to implement generics via type erasure — motivated by backward compatibility — baked in boxing overhead for all generic collections. C# and .NET, designing generics after observing Java's approach, implemented reified generics with value type specialization from the start. The lesson is sharp: if a language has primitive types and reference types, and if it will have generic types, the question of whether generics can specialize over primitives must be answered before generics ship — not twelve years later via a multi-year JVM specification project.

**6. Concurrent GC barriers impose real throughput costs that must be quantified.**
ZGC's sub-millisecond pause times are achieved partly by inserting read/write barriers in mutator threads — small overhead operations on every pointer load or store. These barriers allow the GC to do concurrent work without stopping the application, but they impose a throughput tax (typically 10–15% versus stop-the-world Parallel GC for throughput-oriented workloads). Language designers choosing concurrent GC must present this tradeoff clearly: concurrent GC is better for latency-sensitive applications; stop-the-world GC is better for throughput-maximizing applications; no GC is optimal for all workloads. The JVM's GC portfolio expresses this tradeoff honestly. A language that claims concurrent GC is "strictly better" than stop-the-world GC is misleading users about throughput costs.

---

## References

[LOGICBRACE-GC] "ZGC — Sub-Millisecond GC Pauses." LogicBrace Technical Documentation. Referenced across council documents.

[DATADOGHQ-GC] "Java Garbage Collection Tuning with Generational ZGC." Datadog Engineering. Referenced in practitioner document.

[FOOJAY-GC-GUIDE] "JVM Garbage Collectors Guide." Foojay.io. Referenced in realist document.

[IBM-COMMUNITY-GC] "Shenandoah GC Performance." IBM Developer Community. Referenced in realist document.

[JLS-MEMORY-MODEL] "The Java Language Specification, Chapter 17: Threads and Locks." Oracle. Defines happens-before semantics and the formal Java Memory Model.

[OPENJDK-JEP454] JEP 454: Foreign Function & Memory API (Final). OpenJDK. https://openjdk.org/jeps/454

[GRAALVM-ADVANTAGES] GraalVM Native Image Performance Overview. GraalVM Documentation.

[GILLIUS-STARTUP-2025] Gillius. "Spring Boot Native Image vs. JVM Startup Comparison." 2025.

[BENCHMARKSGAME] The Computer Language Benchmarks Game. https://benchmarksgame-team.pages.debian.net/benchmarksgame/

[TECHEMPOWER-R23] TechEmpower Web Framework Benchmarks, Round 23. https://www.techempower.com/benchmarks/

[ROCKTHEJVM-LOOM] "Project Loom: Virtual Threads in Java." Rock the JVM. Referenced in council documents for JEP 444.

[ROCKTHEJVM-STRUCTURED] "Structured Concurrency in Java." Rock the JVM. Referenced for JEP 505.

[INFOQ-JAVA-TRENDS-2025] "Java Ecosystem and Trends 2025." InfoQ.

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019.

[JAVA-VERSION-HISTORY] Oracle / OpenJDK. "Java Version History." Covers JDK release notes from 1.0 through JDK 25.

[OPENJDK-VALHALLA] Project Valhalla. "Value Objects and Primitive Classes (JEP 401)." OpenJDK Early Access Builds.
