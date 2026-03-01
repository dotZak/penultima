# Scala — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Scala"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
```

---

## Summary

Scala's compiler and runtime story is more technically complex than any other JVM language, and that complexity is load-bearing. The council members accurately characterize most of the major tradeoffs — JVM GC convenience at the cost of startup overhead, compilation slowness driven by type system sophistication, multiple concurrency execution models with genuine performance differences — but several claims require precision corrections, and important runtime developments (Project Loom's virtual threads, Boehm GC semantics in Scala Native, the JVM's JIT warmup requirement, value class boxing edge cases) are either absent or underspecified.

The most consequential gap across the council is insufficient attention to Project Loom (JDK 21+ virtual threads), which materially changes the comparison between Scala's platform-thread and fiber-based concurrency models. The council also underweights the engineering burden imposed by GraalVM Native Image's Closed World Assumption, presenting it as a cleaner escape hatch than production experience supports. On the positive side, the TASTy binary format's role in Scala 3 cross-version compatibility is well described, and the practitioner's observation about IDE/compiler divergence on complex implicit resolution is technically accurate and important.

From a language design perspective, Scala's experience reveals a fundamental tension: a type system expressive enough to require whole-program analysis for compilation is also expressive enough to provide genuine correctness guarantees — but the compilation cost grows superlinearly with type complexity in ways that are not fully addressable by incremental build tooling. This is not an engineering failure; it is the honest cost of what the type system provides. Language designers should understand this tradeoff explicitly rather than treating it as a known defect to be engineered away.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **JVM GC options are correctly enumerated.** Serial, Parallel, G1, ZGC, and Shenandoah are the main OpenJDK collectors, and the claim that G1 is the default since Java 9 is correct [JEP-248]. The assertion that GC is transparent to Scala code is accurate — Scala code does not interact with the collector directly.

- **GraalVM Native Image cold-start improvement (~10x) is well-sourced.** The `GRAALVM-SCALAC` reference (compiling `scalac` itself with GraalVM) documents this order of magnitude. The claim is not overclaimed: for typical Scala microservices, startup reduction from ~1-2 seconds to ~100-200ms is the empirically observed range [GRAALVM-MEMORY].

- **Scala Native's Boehm GC and `Ptr[T]` interface are accurately described.** The `@extern` annotation mechanism for C FFI, `alloc[T]`, and `stackalloc[T]` are all correctly identified [SCALA-NATIVE-DOCS].

- **Opaque type alias zero-overhead claim is accurate at the JVM bytecode level.** An `opaque type Meters = Double` within its defining compilation unit erases to `Double` at bytecode generation; no boxing occurs [SCALA3-OPAQUE]. This is a meaningful improvement over Scala 2 value classes (see corrections below).

- **Immutable collections using structural sharing** — implicitly claimed by multiple council members — is accurate. Scala's persistent collection implementations (Vector, HashMap, etc.) use hash array mapped trie (HAMT) and relaxed radix balanced tree (RRB-tree) structures that provide O(log₃₂ n) update and O(1) amortized access with structural sharing between versions [BAGWELL-2001].

**Corrections needed:**

- **The Boehm GC in Scala Native is conservative, not precise.** The realist describes Scala Native's GC as simply "Boehm GC" without flagging the key implementation distinction. The Boehm-Demers-Weiser collector is a *conservative* garbage collector: it treats any bit pattern that could be a valid heap pointer as a live reference, and therefore may retain objects that are no longer reachable — "false roots" from integer values that happen to look like addresses. For Scala Native workloads involving large numbers of small objects or long-lived heaps, this produces measurably higher memory consumption than a precise tracing GC would [BOEHM-GC-IMPL]. Council members citing "10-20% of C performance" for Scala Native should note that memory-intensive benchmarks likely underestimate this overhead.

- **Scala 2 value classes have boxing edge cases that Scala 3 opaque types avoid.** The realist notes opaque types' zero overhead but does not clarify the distinction from Scala 2 value classes, which *also* promised to avoid boxing but fail in several situations: when used as type arguments (`List[Meters]` boxes), when assigned to an `Any` variable, when used in arrays, and in some pattern match positions [SCALA-VALUE-CLASSES-SPEC]. Scala 3 opaque types avoid this by relying on compile-time erasure rather than value class encoding, making the zero-overhead guarantee more reliable. This is a genuine Scala 3 improvement that the council should state precisely.

- **The "50-200MB heap floor" figure is workload-dependent, not a hard minimum.** The research brief states this range, and the realist repeats it without qualification. In practice, a minimal "Hello World" JVM application with the Scala standard library may consume 30-50MB on modern OpenJDK with G1GC and default settings. The 200MB figure applies to more representative Scala service configurations (with effect library initialization, logging frameworks, and JIT-compiled code). Presenting this range as a baseline without workload context can mislead discussions of serverless or resource-constrained deployment.

- **GraalVM Native Image's Closed World Assumption (CWA) is understated.** The realist notes "restricted reflection" as a cost, and the detractor mentions "reflection metadata must be provided." Neither fully communicates the engineering burden: GraalVM's static analysis requires that all code executed at runtime be statically reachable from entry points. Dynamic class loading, runtime-generated bytecode, and reflection on classes not declared in reachability metadata will silently fail at runtime — not at build time. Scala applications that use popular JVM libraries (Log4j, Jackson, many Netty-based HTTP servers) require extensive reachability metadata configuration. The `graalvm-reachability-metadata` community repository mitigates this for known libraries, but internal reflection-heavy code requires manual annotation. This is a multi-day engineering investment for non-trivial applications, not a "compile with an extra flag" simplification [GRAALVM-REFLECT-CONFIG].

**Additional context:**

- **JVM off-heap memory** is not addressed by the council. Scala applications that use off-heap storage (Apache Arrow, Chronicle Map, direct ByteBuffers via `java.nio`) operate outside GC visibility entirely. For data engineering workloads (Scala's primary deployment domain), this is relevant: Apache Spark's Tungsten execution engine deliberately stores most of its working data off-heap to avoid GC pressure on large datasets [SPARK-TUNGSTEN]. The JVM GC memory story for Spark-based Scala is therefore quite different from the servlet-style service story the council implicitly describes.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **Cats Effect and ZIO fiber sizes (~400 bytes vs. ~1MB for platform threads) are substantiated.** The Cats Effect 3 documentation cites ~400 bytes per fiber under typical conditions [CATS-EFFECT-CONCURRENCY]. Platform thread stack defaults to 512KB-1MB on most JVM configurations (configurable via `-Xss`). The difference is approximately three orders of magnitude, and the claim is not overclaimed.

- **The M:N scheduling model for Cats Effect and ZIO is correctly described.** Both libraries implement their own work-stealing thread pool schedulers (IORuntime in Cats Effect 3, ZScheduler in ZIO 2) that multiplex many fibers onto a small fixed pool of platform threads. The concurrency model is cooperative within fibers (yielding at `flatMap` boundaries) and preemptive only at the thread pool level. This is the correct characterization.

- **The actor model prevents shared mutable state within a single actor** — stated accurately across council members. Each actor processes one message at a time from its mailbox; concurrent message delivery is never visible within a single actor's behavior. This is a structural, not advisory, guarantee.

- **Scala lacks async/await as a language construct** — accurate. This is a deliberate design choice, not an omission. The practical effect is that effectful code written in Cats Effect or ZIO uses `for` comprehensions (desugared to `flatMap`/`map` chains), which are semantically equivalent to `async/await` but syntactically distinct and more composable.

- **`Future[A]` is eager and carries exceptions rather than typed errors** — accurate. Futures begin computation immediately on `ExecutionContext` submission; there is no way to construct a deferred `Future` without wrapping in a thunk. The untyped error channel (`Throwable`) is a correct characterization.

**Corrections needed:**

- **Project Loom (JDK 21 Virtual Threads) is absent from the council discussion.** JDK 21 (September 2023) introduced virtual threads as a stable, production-ready feature [JEP-444]. Virtual threads are JVM-managed, not OS-managed — similar in principle to Cats Effect or ZIO fibers, but implemented at the JVM level rather than in a user-space library. A JVM application can run millions of virtual threads without the stack overhead of platform threads. This directly affects Scala's concurrency story in several ways:

  1. Blocking I/O operations that would park a platform thread (and block its worker pool slot) now park only a virtual thread, freeing the carrier thread for other work. This eliminates much of the traditional motivation for effect-library fibers in I/O-bound services.

  2. Cats Effect 3 and ZIO 2 are both capable of running atop virtual threads (CE3 added virtual thread support in 3.6.x). The interaction between effect-system fiber scheduling and JVM virtual thread scheduling is non-trivial: running CE3 fibers on virtual-thread-backed carrier threads can lead to double-scheduling overhead if not carefully configured.

  3. The practical consequence: for I/O-bound Scala services (HTTP APIs, database-backed services), a simple threading model using blocking virtual threads may provide comparable throughput to a Cats Effect fiber runtime with significantly less conceptual overhead. This is a genuine challenge to the narrative that effect-system fibers are necessary for performance in concurrent Scala.

  The council should at minimum acknowledge this development, as it materially changes the competitive landscape for Scala concurrency advice.

- **Structured concurrency status is understated for Cats Effect and ZIO.** The detractor correctly identifies that neither `Future` nor Akka actors provide structured concurrency. However, both Cats Effect 3 (via `Supervisor`, `Resource`, and the `IO.race`/`IO.both` combinators) and ZIO 2 (via `Scope`, `ZIO.scoped`, and `ZIO.parallelFinalizers`) provide principled structured concurrency. The claim that "structured concurrency is possible [with CE3/ZIO]" in the realist and research brief is accurate, but the detractor's framing ("the language does not guide developers toward structured concurrency") is also accurate — the language and stdlib provide no such guidance. Both framings can be true simultaneously.

- **The JVM memory model (JMM) data race implications are not precisely stated.** The research brief notes that `Future` "relies on JVM memory model visibility guarantees and immutable data." This is correct but insufficiently precise. The JMM guarantees happens-before relationships across specific synchronization actions (volatile reads/writes, lock acquisition/release, thread start, thread join). A `Future` callback is guaranteed to observe all values visible at the point the `Promise` was completed — this is a JMM happens-before relationship. However, if mutable state is shared between futures without explicit synchronization, data races are possible and result in undefined behavior under the JMM (not just incorrect results, but potentially undetectable logical errors). The council's treatment of immutable data as sufficient for safety is correct in practice but understates the risks of mixed mutable/immutable code.

- **The "colored function" framing is accurate but the Scala 3 direct style deserves more technical precision.** Scala 3.3+ experimental captures checker tracks `CanThrow[E]` and `CanAsync` capabilities using the type system itself. The "direct style" approach being explored aims to allow writing sequential-looking code that is type-checked to require appropriate capabilities in scope — a fundamentally different approach from async/await sugar. This is compiler-enforced (not merely syntactic), which is architecturally significant for language designers comparing approaches.

**Additional context:**

- **Akka's original remoting protocol used Java serialization by default**, creating a significant security risk in distributed actor systems (addressed by Artery, Akka's newer transport). The council's security section covers CVE-2022-36944 but does not connect this to the distributed concurrency architecture. Teams using Akka Cluster or Pekko Cluster should explicitly configure Artery (Aeron-based) transport rather than the legacy serialization-based remote. This is a compiler/runtime concern because it affects the on-wire format, not just application logic.

- **Parallel collections (`ParSeq`, `ParMap`)** are available as a separate module. These use Java's `ForkJoinPool` under the hood. The council does not discuss these, and they represent an important middle ground between single-threaded collections and full effect-system concurrency for CPU-bound parallelism.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **"1.2–3x relative to C for compute-intensive benchmarks" is a reasonable range.** The Computer Language Benchmarks Game shows Java (and by extension JVM Scala) in the 1.2x–3x range for most algorithmic benchmarks [CLBG-GENERAL]. The caveat — "after JIT warm-up" — is implied by the research brief and should be explicit in final reports.

- **Scala 3 shows measured improvements over Scala 2 on compilation benchmarks** — corroborated by VirtusLab's published compiler benchmark results. The improvement is real but partial; heavy type-class derivation and match types in Scala 3 can still produce long compilation times.

- **Bloop (compilation daemon) and Zinc (incremental compilation) substantially reduce iterative compile times** — accurate and important. Bloop keeps a JVM warm between compilations (eliminating 1-2s JVM startup overhead per compile), and Zinc tracks per-file dependencies to avoid recompiling unchanged transitive dependents.

- **Scala.js generates optimized JavaScript with performance improvements for numeric operations** — the Scala.js performance documentation describes type-specialized number representations and aggressive dead code elimination by the Closure Compiler. The claim about "sometimes exceeds hand-written JavaScript for type-specialized numeric operations" is qualified correctly.

**Corrections needed:**

- **The Hydra "2.66x speedup" figure in the research brief conflicts with the Zalando blog title ("3.2x Faster").** The Zalando 2017 engineering blog post is titled "Achieving 3.2x Faster Scala Compile Time" [ZALANDO-2017]. The research brief states 2.66x. These likely represent different benchmarks within the same study (the blog reports various scenarios). The realist cites "2.66x" while the research brief title suggests higher figures. Council documents should cite specific scenarios rather than aggregate figures to avoid this ambiguity. The general claim — that Hydra provides multi-fold speedup for appropriately parallelizable codebases — is accurate regardless of which specific figure is used.

- **JIT warmup is a systematic caveat missing from performance discussions.** The council consistently presents JVM performance figures without noting that HotSpot's JIT compiler (C1 for quick compilation, C2 for optimized compilation) requires warmup — typically 1,000–10,000 invocations of a method — before generating optimized native code [HOTSPOT-JIT]. Before warmup, execution is interpreted (C1-interpreted) or C1-compiled (unoptimized). For:
  - Short-lived processes: JVM Scala code may never reach peak JIT performance
  - Benchmark integrity: benchmarks must discard warmup iterations to report steady-state throughput
  - Serverless/FaaS: JVM cold starts include both JVM initialization and JIT warmup periods

  The practical consequence: JVM Scala's "1.2–3x vs. C" throughput figures apply at steady state only. A freshly started JVM Scala process may run 5–50x slower than C until JIT compilation completes. GraalVM Native Image addresses this by compiling AOT, trading peak throughput for consistent startup performance.

- **The Scala Native "10-20% of C" performance claim requires workload qualification.** The VirtusLab 2021 benchmark [VIRTUSLAB-NATIVE-PERF] shows this range for specific algorithm benchmarks. However: (1) Boehm GC's conservative scanning imposes GC pause overhead that is not present in C, particularly for allocation-heavy workloads. (2) Scala Native targets LLVM, so optimized numeric code should approach C performance on compute-bound workloads — the 10-20% overhead likely reflects GC overhead, function call overhead from Scala's object model, and runtime type checking. (3) Scala Native's `@specialized` and unboxed primitives support is limited; numeric collections may box values in ways C would not. The "10-20% of C" range is plausible for selected benchmarks but should not be generalized to all workloads.

- **Specialization and boxing costs in Scala collections are not discussed.** Scala's generic collection types (e.g., `List[Int]`, `Vector[Double]`) box primitive values on the JVM — each `Int` in a `List[Int]` is a `java.lang.Integer` object on the heap, requiring a pointer dereference and GC tracking. This is a systematic overhead for numeric computing in idiomatic Scala. Mitigation options — `Array[Int]` (unboxed), specialized libraries, manually annotated `@specialized` classes — exist but are not idiomatic. For data engineering workloads with Spark, this is largely handled by Tungsten's off-heap columnar storage [SPARK-TUNGSTEN]. For general numeric computing in Scala, boxing is a real performance cost that affects throughput and GC pressure.

**Additional context:**

- **Tail call optimization (TCO) in Scala is limited to direct self-recursion with `@tailrec`.** The Scala compiler performs TCO only when:
  1. The recursive call is in tail position
  2. The method calls itself directly (not mutually recursive)
  3. The `@tailrec` annotation is present (which additionally makes the compiler *verify* the tail-call property, refusing to compile if TCO cannot be applied)

  Scala does NOT perform general TCO for mutual recursion or for calls through abstract methods or function values. Deep mutual recursion requires explicit trampolining (e.g., `cats.Eval`, `scalaz.Trampoline`, or manual `Free` monad encoding). The historian's discussion of Scala's handling of recursive algorithms should be precise about this limitation, which is different from languages with full TCO (Scheme, Haskell via `tailcall`) or no TCO (Java, Python).

- **The Scala 3 inline mechanism is a compile-time feature with observable performance implications.** `inline def` in Scala 3 guarantees that the method body is inlined at the call site during compilation — not a JIT-time hint (like Java's final methods that may be inlined by the JIT) but a guaranteed compile-time substitution [SCALA3-INLINE]. This is significant for performance-sensitive code: inline methods can reduce virtual dispatch overhead, enable constant folding across abstraction boundaries, and allow type-level computations to be eliminated entirely. The Typelevel ecosystem uses this extensively for zero-cost abstractions. The compiler/runtime distinction here is important: `inline` is a compiler guarantee, while JVM JIT inlining is a runtime heuristic.

- **`scalac-profiling` and Scala 3 `-Xprint` flags** provide actionable compilation performance diagnostics. The detractor correctly notes the existence of `scalac-profiling` (maintained by Scala Center). Language designers should note that the existence of a dedicated compilation performance tool implies the severity of the problem: few languages require dedicated tooling to identify why the compiler is slow.

---

### Other Sections (Cross-Cutting Compiler/Runtime Issues)

**Section 2 (Type System) — TASTy and runtime type erasure:**

The council describes the type system comprehensively but underweights a fundamental runtime consequence: **type erasure**. Scala compiles to JVM bytecode, and the JVM performs type erasure — `List[Int]` and `List[String]` are indistinguishable at runtime; both are `List` at the bytecode level. This has several consequences:

1. Pattern matching on generic types (`case x: List[Int] =>`) generates an unchecked warning because the runtime check cannot verify the type parameter. The compiler substitutes `case x: List[_] =>` and emits a warning.

2. `asInstanceOf[List[Int]]` will succeed at runtime even if the actual value is a `List[String]`, producing a `ClassCastException` later when an element is accessed. This is a real source of runtime failures in Scala code that uses `Any`-typed containers.

3. The runtime type checks for union types (`A | B`) are limited: `match { case x: A => ... case x: B => ... }` works when A and B are concrete types, but complex union type patterns may not be fully checkable.

TASTy (Typed Abstract Syntax Trees) addresses this *at the compiler level* by preserving full type information for cross-module compilation. But TASTy is a compiler artifact; at runtime on the JVM, erasure applies. This distinction — full types in TASTy, erased types at runtime — is not clearly stated by any council member and is important for understanding the "type safety" guarantees Scala actually provides.

**Section 6 (Ecosystem and Tooling) — IDE/compiler divergence mechanism:**

The detractor and practitioner correctly identify that IntelliJ's Scala plugin reimplements parts of the type checker independently of the actual `scalac`/`dotc` compiler. The technical mechanism is worth stating: IntelliJ's Scala plugin contains a reimplementation of the Scala type inference engine in Java (not Scala), optimized for responsiveness rather than correctness. Errors shown in the IDE editor panel use this reimplementation; errors shown when you run `sbt compile` or `scalac` use the actual compiler. The two implementations can and do diverge, particularly for:

- Complex implicit/given resolution chains
- Macro expansion results
- Some higher-kinded type inference scenarios

Metals (Language Server Protocol implementation) avoids this by delegating type checking to the actual compiler via the Build Server Protocol (BSP). The tradeoff is that `dotc` performs more work per keystroke than IntelliJ's reimplementation, producing slower IDE responses for large codebases. This is a genuine engineering tension with no clean solution.

**Section 11 (Governance and Evolution) — Compiler implementation continuity:**

The Dotty/Scala 3 compiler (`dotc`) is implemented in Scala 3 itself (bootstrapped). This creates a dependency: changes to the compiler must be compilable by the *previous* version of the compiler, maintaining a bootstrapping invariant. This is a well-known constraint in self-hosted language implementations and imposes limits on how rapidly the compiler's own code can adopt new language features. The council does not discuss this, but it is architecturally relevant: the Scala 3 compiler team cannot use Scala 3.6 features until the compiler can compile itself with those features enabled — a constraint that affects internal compiler development velocity.

---

## Implications for Language Design

The following observations, derived from Scala's concrete implementation history, are stated as generic principles for language designers.

**1. A type system that requires whole-program analysis for correctness will impose superlinear compilation costs.** Scala's combination of local type inference, implicit/given search, and higher-kinded type unification requires the compiler to explore large resolution spaces for any non-trivial program. This is not an engineering failure of the Scala compiler; it is an honest consequence of what the type system guarantees. Language designers must consciously choose where on the complexity/compilation speed tradeoff they intend to sit. Incremental build tools (Zinc-equivalent) can reduce the marginal cost but cannot eliminate the superlinear scaling of initial compilation. Languages that prioritize fast compilation (Go, Zig) achieve it by constraining the type system.

**2. JIT warmup is a first-class deployment concern, not a benchmark footnote.** Languages that compile to bytecode interpreted by a JIT runtime (JVM, CLR, LuaJIT) cannot honestly cite steady-state throughput without disclosing warmup requirements. For deployed services, JIT warmup time adds to MTTR (mean time to recovery after restart), constrains serverless/FaaS viability, and increases autoscaling lag. Language designers targeting managed runtimes should either (a) define and advertise warmup requirements explicitly, (b) provide AOT compilation options (as GraalVM does), or (c) both. Presenting JIT-steady-state throughput as "the language's performance" without warmup context is epistemically misleading.

**3. Conservative garbage collectors (as used in Scala Native's Boehm GC) impose memory overhead that precise GCs avoid.** Boehm GC's false-root problem — retaining objects because an integer value looks like a pointer — is predictably problematic for languages whose heap contains many long-lived objects. Scala Native's Boehm GC was an expedient choice for initial implementation; a precise moving GC (like the JVM's G1 or ZGC) would provide better memory efficiency at the cost of implementation complexity. Language designers evaluating GC implementations should model their expected false-root rate based on object graph density and integer distribution, not assume Boehm is "good enough."

**4. Virtual threads (Project Loom) change the M:N scheduling calculus for JVM languages.** Prior to JDK 21, the primary motivation for user-space fiber libraries (Cats Effect, ZIO, Kotlin coroutines) was the cost of blocking platform threads and the inability to efficiently multiplex many concurrent tasks onto a small thread pool. JDK 21 virtual threads largely eliminate this motivation for I/O-bound concurrency. Language designers building on the JVM in 2026 should treat virtual threads as a baseline concurrency primitive, reserving user-space fiber systems for cases that require explicit scheduler control, structured concurrency APIs, or fine-grained cancellation semantics beyond what virtual threads provide.

**5. Compilation artifact formats that preserve full type information (like TASTy) enable richer cross-version tooling.** Traditional JVM bytecode carries only erased types; cross-module type checking requires either source distribution or type inference from erased types. TASTy's preservation of full typed trees allows the Scala 3 compiler to perform principled cross-version compatibility checking and enables tools like Scala 3's type-safe macro staging. This is a meaningful architectural decision. Language designers should evaluate whether their compilation format preserves sufficient type information for downstream tooling needs — particularly for languages with complex type systems where post-hoc type reconstruction is intractable.

**6. Inline (compile-time guaranteed) and JIT-inline (runtime heuristic) are distinct mechanisms with different performance guarantees.** Scala 3's `inline def` guarantees call-site substitution at compile time, enabling zero-cost abstractions that the JIT might fail to inline (e.g., due to megamorphic call sites, code size limits, or insufficient profiling data). Language designers who want zero-cost abstraction guarantees should distinguish these mechanisms: `final` or monomorphic call site hints at the JVM level are probabilistic, while compile-time inlining is deterministic. Systems languages with metaprogramming (Zig's `comptime`, C++ templates, Rust macros) achieve this via compile-time evaluation rather than runtime hints.

---

## References

[BAGWELL-2001] Bagwell, P. "Ideal Hash Trees." EPFL Technical Report, 2001. (Foundation for Scala's Vector/HashMap persistent collections.)

[BOEHM-GC-IMPL] Boehm, H-J. and Weiser, M. "Garbage Collection in an Uncooperative Environment." Software Practice and Experience, 1988. (Conservative GC semantics and false-root implications.)

[CATS-EFFECT-CONCURRENCY] Typelevel. "Concurrency in Cats Effect 3." October 2020. https://typelevel.org/blog/2020/10/30/concurrency-in-ce3.html

[CLBG-GENERAL] Computer Language Benchmarks Game. https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html

[CVEDETAILS-SCALA] CVEDetails. "Scala-lang Scala: Security vulnerabilities, CVEs." https://www.cvedetails.com/vulnerability-list/vendor_id-17258/product_id-41515/Scala-lang-Scala.html

[DOTTY-BLOG] Odersky, M. "Starting with Dotty." LAMP/EPFL Blog, 2013. https://dotty.epfl.ch/blog/2013/01/01/starting-with-dotty.html

[ENDOFLIFE-SCALA] endoflife.date. "Scala." https://endoflife.date/scala

[GRAALVM-MEMORY] GraalVM Documentation. "Memory Management." https://www.graalvm.org/latest/reference-manual/native-image/optimizations-and-performance/MemoryManagement/

[GRAALVM-REFLECT-CONFIG] GraalVM Documentation. "Reachability Metadata — Reflection." https://www.graalvm.org/latest/reference-manual/native-image/metadata/

[GRAALVM-SCALAC] Jovanovic, V. "Compiling Scala Faster with GraalVM." Medium / GraalVM Blog. https://medium.com/graalvm/compiling-scala-faster-with-graalvm-86c5c0857fa3

[HOTSPOT-JIT] OpenJDK. "HotSpot Glossary of Terms." https://openjdk.org/groups/hotspot/docs/HotSpotGlossary.html (C1/C2 compilation tiers and warmup.)

[JEP-248] Oracle JDK. JEP 248: "Make G1 the Default Garbage Collector." https://openjdk.org/jeps/248

[JEP-444] Oracle JDK. JEP 444: "Virtual Threads." JDK 21. https://openjdk.org/jeps/444

[KODEM-SECURITY] Kodem. "Addressing Scala Security Vulnerabilities." https://www.kodemsecurity.com/resources/tips-to-reduce-scala-vulnerabilities

[RESEARCH-BRIEF] Scala Research Brief. "Scala — Research Brief." Penultima Project, 2026-02-27.

[SCALA-NATIVE-DOCS] Scala Native Documentation. https://scala-native.org/en/stable/

[SCALA-VALUE-CLASSES-SPEC] Scala Documentation. "Value Classes and Universal Traits." https://docs.scala-lang.org/overviews/core/value-classes.html

[SCALA3-INLINE] Scala 3 Documentation. "Inline." https://docs.scala-lang.org/scala3/reference/metaprogramming/inline.html

[SCALA3-OPAQUE] Scala 3 Documentation. "Opaque Type Aliases." https://docs.scala-lang.org/scala3/reference/other-new-features/opaques.html

[SPARK-TUNGSTEN] Databricks. "Apache Spark as a Compiler: Joining a Billion Rows per Second on a Laptop." 2016. https://www.databricks.com/blog/2016/05/23/apache-spark-as-a-compiler-joining-a-billion-rows-per-second-on-a-laptop.html

[VIRTUSLAB-NATIVE-PERF] Mazur, W. "Revisiting Scala Native performance." VirtusLab / Medium. https://medium.com/virtuslab/revisiting-scala-native-performance-67029089f241

[ZALANDO-2017] Zalando Engineering Blog. "Achieving 3.2x Faster Scala Compile Time." April 2017. https://engineering.zalando.com/posts/2017/04/achieving-3.2x-faster-scala-compile-time.html
