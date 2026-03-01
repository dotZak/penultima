# Dart — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Dart"
agent: "claude-sonnet-4-6"
date: "2026-02-28"
```

---

## Summary

Dart's compiler/runtime story is defined by a central structural tension that no other tier-1 language in this project embodies so acutely: the language simultaneously targets JIT compilation for development ergonomics and AOT compilation for production performance, and these two modes have fundamentally different and sometimes incompatible requirements. This tension produced Dart's most celebrated feature (sub-second stateful hot reload, enabled by incremental JIT), its most important production property (AOT-optimized native code with aggressive tree-shaking), its most consequential feature cancellation (macros, abandoned because compile-time semantic introspection was structurally incompatible with both JIT hot reload and AOT tree-shaking), and a permanent asymmetry between what is available in development mode and what is available in production.

The council perspectives on Dart's memory model and GC architecture are largely accurate. The generational GC design — parallel stop-the-world scavenger for the young generation, concurrent marking for the old generation, with per-isolate heap ownership — is correctly described and is genuinely well-matched to Flutter's frame timing requirements. The isolate-per-heap model is the most architecturally important runtime property Dart has: it prevents GC events from crossing isolate boundaries, which is why a background computation's GC pause cannot drop a UI frame. The council underexplores the copy-on-send cost for large inter-isolate messages and does not fully account for the native heap blind spot created by `dart:ffi`.

On performance, the council's benchmark characterizations are accurate in aggregate but lack methodological context in places. The claim that Dart AOT is "5–7× slower than C" is taken directly from the Computer Language Benchmarks Game and is appropriate for that benchmark class, but the CLBG measures peak throughput on numerical algorithms — not the network I/O, JSON parsing, and UI layout operations that dominate real Dart workloads. The claim that dart2wasm will outperform dart2js is theoretically grounded but is consistently stated as a prediction rather than a demonstrated result, which is appropriate given the scarcity of real-world production comparisons as of February 2026.

One compiler/runtime finding of high importance to language design is consistently underemphasized across all council perspectives: the iOS prohibition on JIT compilation in production App Store submissions was the decisive forcing function that drove Dart 2.0's mandatory sound type system. This was not primarily a philosophical shift — it was a compiler optimization necessity. Sound types allow an AOT compiler to eliminate dynamic dispatch and type guards that would be required under an unsound or optional type system; Vijay Menon's internal research quantified the difference as roughly 26 native instructions per method under Dart 1.x versus approximately 3 under a sound system [MENON-SOUND-TYPES]. The lesson for language designers is that compilation target requirements can be the decisive factor in type system design, not only language design philosophy.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **Generational GC architecture.** All council members correctly describe the two-generation design: a parallel stop-the-world semispace scavenger for young-generation collection, and concurrent-mark-concurrent-sweep (CMCS) or concurrent-mark-parallel-compact (CMPC) for old-generation collection [DART-GC-DOCS]. This is accurately sourced from the Dart SDK runtime documentation.

- **Old-generation concurrency.** The claim that the old-generation marking phase runs concurrently with application execution is accurate. This is a meaningful pause-reduction technique for long-lived objects: the concurrent marking phase identifies live objects while the application continues running, and only a brief stop-the-world compaction or sweep phase follows. This correctly distinguishes Dart's GC from naïve stop-the-world collectors.

- **Isolate-per-heap.** The claim that each isolate owns an independent heap and that GC events in one isolate do not pause other isolates is structurally accurate and architecturally important [DART-GC-ANALYSIS-MEDIUM]. The apologist's and practitioner's explanations of why this matters for Flutter's frame timing (background isolate GC cannot drop UI thread frames) are correct.

- **Memory safety in pure Dart.** The assertion that buffer overruns, use-after-free, dangling pointers, and heap corruption cannot occur in pure Dart code is accurate for all Dart code that does not use `dart:ffi` [FLUTTER-SECURITY-FALSE-POSITIVES]. The GC manages all pure-Dart allocations; there is no mechanism for a pure-Dart program to produce these vulnerability classes.

- **FFI and native memory responsibility.** All council perspectives correctly identify `dart:ffi` as the boundary where Dart's memory safety guarantees end. Native memory allocated via `calloc` or `malloc` from the `ffi` package is not tracked by the Dart GC and must be explicitly freed [DART-FFI-DOCS].

**Corrections needed:**

- **GC pause duration is context-dependent.** Several council members characterize young-generation pause times as "typically sub-millisecond," which is accurate for small heaps with modest allocation rates but is not a universal property. Young-generation (new space) collection time scales with the volume of live objects in new space and the number of root references from old space. Flutter applications with large widget caches, many active streams, or high-frequency allocation in animation callbacks can experience young-generation collections in the multi-millisecond range. The characterization is directionally correct but should be qualified with "for heaps and allocation rates typical of Flutter applications."

- **The DevTools memory profiler does not expose native heap metrics.** The practitioner correctly notes this, but the apologist's praise of DevTools as comprehensive tooling does not adequately caveat that `dart:ffi`-allocated memory is invisible to the Dart memory profiler. Developers debugging memory leaks in code that uses FFI are working partially blind: they can see Dart heap growth but cannot observe native heap allocations through any Dart-native tooling. This is a meaningful operational gap for applications that use FFI extensively (which includes all non-trivial Flutter apps, since Flutter's rendering engine allocates native memory).

- **The copy-on-send cost for inter-isolate messaging is understated.** The detractor correctly identifies this cost; the apologist's and realist's treatments understate it. When a non-primitive, non-transferable Dart object is passed via `SendPort`, the Dart runtime performs a deep copy of the entire object graph. For common Flutter patterns — passing the result of JSON deserialization, a list of domain model objects, or image processing results from a background isolate to the UI isolate — this means the data is fully allocated twice. `TransferableTypedData` provides a zero-copy transfer path for typed byte buffers [DART-CONCURRENCY-DOCS], but this is a special case requiring explicit API use, not the general case. Large object graphs have no zero-copy path.

**Additional context:**

- **The GC was specifically tuned for Flutter's workload.** The Flutter team has published analysis demonstrating that the Dart GC has been iteratively optimized to minimize pause times in the Flutter widget build pattern [FLUTTER-GC-MEDIUM]. Modern Flutter builds, particularly with the Impeller rendering engine (which does more rendering work in C++ rather than Dart-side allocation), generate significantly fewer intermediate objects per frame than early Flutter. The GC's behavior in 2026 is materially better than early analyses (2018–2020) suggested, and those analyses should not be cited without noting that significant optimization has occurred.

- **`const` constructors are a compile-time GC optimization.** A Dart `const` expression is evaluated at compile time and stored in the program's read-only constant pool. Multiple uses of the same `const` value share a single allocation. This is not documented as a GC optimization in most council perspectives, but it is a meaningful one: Flutter developers who use `const` aggressively in widget constructors are reducing allocator pressure, not just following style guidelines. The compiler enforces `const` correctness; the runtime benefit is real.

- **The `Finalizer` API (available since Dart 2.17) is not mentioned by any council member.** Dart provides a `Finalizer` class that allows attaching callbacks to objects that fire when the object is GC'd. This is the primary mechanism for releasing `dart:ffi` native resources tied to Dart object lifetimes, and it partially addresses the FFI memory tracking gap. However, `Finalizer` callbacks are best-effort and not guaranteed to run before process exit — they are not a substitute for explicit `free()` calls in resource-critical code [DART-FINALIZER-DOCS].

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **Isolate model and absence of shared mutable state.** The characterization of isolates as providing data-race-freedom by construction (not by convention or locking) is accurate and important. Dart's concurrency model does not prevent data races through synchronization primitives; it makes shared mutable state structurally impossible because isolates have private heaps and all inter-isolate data transfer is by copy or explicit transfer [DART-CONCURRENCY-DOCS]. This is meaningfully different from thread-safe languages that still permit data races through bugs.

- **Async/await as cooperative concurrency within an isolate.** The event loop model within a single isolate — where `async`/`await` provides cooperative (non-preemptive) concurrency for I/O operations — is correctly described. The Dart VM does not preempt a running synchronous computation; a computation that holds the event loop for more than one frame budget drops frames.

- **"Colored functions" propagation.** The observation that `async` propagates through the call stack (a function calling an `async` function must itself be `async` or use `.then()` callbacks) is accurate and correctly identified as the function coloring problem [DART-CONCURRENCY-DOCS]. Dart has not resolved this; it has made the coloring syntactically explicit.

- **Absence of structured concurrency.** The council is correct that Dart lacks structured concurrency primitives analogous to Kotlin's `CoroutineScope`, Swift's `TaskGroup`, or Java 21's virtual thread scopes. Cancellation requires manual handling; there is no automatic propagation of cancellation through an isolate hierarchy. The practitioner's identification of "setState called after dispose" as a practical consequence of missing structured concurrency is accurate and common.

- **`Isolate.run()` ergonomics improvement.** The council correctly notes that `Isolate.run()`, introduced in Dart 2.19, substantially improved the ergonomics of the fire-and-collect isolate pattern. Before this API, developers had to manage `ReceivePort`, `SendPort`, `Isolate.spawn`, and lifecycle cleanup manually. The higher-level API reduces boilerplate significantly [FLUTTER-ISOLATES-DOCS].

**Corrections needed:**

- **The OS thread mapping is more nuanced than stated.** The research brief states that "each isolate runs on an OS thread from a thread pool managed by the Dart runtime," and the council repeats this framing without qualification. The more precise description is that the Dart VM uses a work-stealing thread pool, and isolates that are actively executing are assigned OS threads from this pool. Isolates that are blocked (waiting on I/O, a `ReceivePort`, or a `Future` with no pending work) do not hold OS threads. During a given moment, the number of OS threads in active use is bounded by the thread pool size, not by the number of isolates. This distinction matters for server-side Dart applications: a Dart server handling 10,000 concurrent connections does not require 10,000 OS threads — the event loop model within isolates handles I/O concurrency with far fewer threads. The council's framing implicitly suggests a 1:1 isolate-to-thread mapping that is not accurate for idle or I/O-blocked isolates.

- **The shared-memory multithreading work (dart-lang/language issue #333) should be understood as an experimental exploration, not a committed roadmap item.** The detractor characterizes the existence of this issue as "an admission that the current isolation model is insufficient" [DART-SHARED-MEMORY-ISSUE-333]. From a compiler/runtime perspective, the shared memory work is exploring whether static fields can be shared across isolates in the same isolate group — a narrowly scoped addition, not a wholesale adoption of shared-memory threading. The work on "shared variables" [DART-SHARED-MEMORY-PR-3531] is examining a specific, bounded extension of the isolation model, not a reimplementation of traditional thread-shared-memory semantics. The detractor's framing implies a more fundamental design acknowledgment than the work actually represents.

- **Closures cannot be sent to isolates — this is a type system and compiler enforcement, not a runtime limitation.** The practitioner notes that "you can't send a closure to an isolate." The reason is a deliberate compiler constraint: closures in Dart can capture references to mutable heap-allocated objects in their enclosing scope. Since captured references would enable sharing mutable state across isolate boundaries, the compiler's message-passing validation rejects objects containing closures (unless they are top-level or static functions, which have no captured state). This is a compiler-enforced safety property, not a runtime limitation that could be relaxed without consequences.

**Additional context:**

- **The isolate model's cost for server-side parallelism is architectural, not incidental.** Several council perspectives note that isolates work well for Flutter's "UI isolate plus background worker" pattern but are awkward for server-side workloads. This is accurate and worth amplifying from a compiler/runtime perspective. Server-side concurrency models (Java's thread pool, Go's goroutines, Node.js's event loop) are designed for workloads with many concurrent I/O operations and moderate shared state. Dart's isolate model handles I/O concurrency well (event loop within an isolate) but requires explicit data routing and copying for any data that must be processed by multiple concurrent workers. This is not a bug; it is the correct consequence of the isolation design. Language designers choosing an actor-based or isolate-based model must accept that shared-state patterns become first-class design challenges.

- **`Stream`'s implementation bridges the async and concurrency models.** Dart's `Stream<T>` uses the event loop and Dart's zone system internally. Stream events are delivered synchronously within the event loop turn that triggers them (for synchronous streams) or via microtask/event queue scheduling (for async streams). The zone system allows intercepting stream errors and events for testing and error tracking. This is sophisticated machinery that the council does not discuss in compiler/runtime terms; understanding it matters for diagnosing ordering bugs and unhandled stream errors.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **CLBG benchmark characterization.** The claim that Dart AOT is approximately 5–7× slower than C in Computer Language Benchmarks Game measurements is accurately cited and consistent with the source [CLBG-DART-MEASUREMENTS]. The contextualization — "comparable to Go and C# and TypeScript in mid-range computational benchmarks" — is appropriate and correctly scopes the comparison to managed-runtime peers.

- **JIT mode enabling hot reload.** The explanation that sub-second hot reload is enabled by Dart's JIT infrastructure — specifically the ability to apply incremental Kernel IR patches to a running VM — is mechanistically accurate. Hot reload works by recompiling only the changed library and patching the VM's method dispatch tables; stateful objects remain allocated and are not reinitialized [DART-OVERVIEW]. This is meaningfully different from hot restart (which reinitializes state) and is a genuine JIT-mode-only capability.

- **AOT tree-shaking.** The assertion that Dart AOT compilation performs whole-program tree-shaking — eliminating unreachable code and reducing binary size — is accurate and well-established. Tree-shaking is one of the primary reasons dart:mirrors (runtime reflection) is banned in AOT mode: runtime reflection can access any type or method at runtime, making it impossible to statically determine what code is unreachable [DART-COMPILE-DOCS].

- **Extension types are genuinely zero-cost.** The apologist's claim that extension types are "completely erased at runtime — no allocation overhead" is compiler-verified. Extension types are a purely static construct: the extension type's wrapping interface exists only in source code and the type system. The AOT and JIT compilers both erase extension type wrappers and operate directly on the representation type. There is no boxing, no indirection, no virtual dispatch overhead for extension type operations.

- **Flutter startup time comparisons.** The figures cited — Flutter AOT at 1.2s, Kotlin native Android at 1.0s, Swift native iOS at 0.9s, React Native at 300–400ms with JS bundle loading — are sourced from specific benchmarks [VIBE-STUDIO-FLUTTER-VS-RN, NOMTEK-2025] and are internally consistent. The framing that "the comparison point matters" (Flutter is slightly slower than native apps but faster than React Native) is correct and contextually appropriate.

- **I/O-bound event loop performance.** The characterization of Dart's async I/O performance as "comparable to Node.js" for event loop-based server workloads is directionally accurate. Both use single-threaded event loops for I/O concurrency; neither has native multi-threaded I/O dispatch by default. The comparison is appropriate.

**Corrections needed:**

- **The CLBG benchmark class should be explicitly scoped.** The 5–7× slower than C figure is accurate for CLBG's set of computation-intensive benchmarks (Mandelbrot, Fannkuch, N-body). These benchmarks are chosen to stress numerical computation, tight loops, and data structure traversal — workloads where managed GC overhead and dynamic dispatch show most clearly. For Dart's primary workload profile (JSON deserialization, database query result mapping, HTTP routing, widget layout), the relevant comparison is against JVM languages and Go, where Dart performs competitively [DART-FAST-ENOUGH]. Multiple council members correctly acknowledge this contextualization; however, the headline 5–7× figure without context could be read as characterizing Dart's general performance deficit, which it does not.

- **The bundle size claim for Flutter web is unverified.** The detractor states that "dart2js bundles can reach 9MB (approximately 2.3MB gzipped) for modest Flutter web applications" citing [FLUTTER-BUNDLE-SIZE-ISSUE], but this citation references GitHub issue discussions rather than systematic measurement. Flutter web bundle sizes vary significantly based on tree-shaking effectiveness, deferred loading usage, and app complexity. Sizes in the 3–10MB range for unoptimized full-Flutter-web builds are documented in community discussion [FLUTTER-BUNDLE-SIZE-ISSUE], but the "9MB for modest applications" claim should be treated as an order-of-magnitude community observation, not a benchmark result. The characterization that Flutter web bundle sizes are substantially larger than comparable JavaScript-native applications is accurate; the specific figure is imprecise.

- **dart2wasm performance claims should be marked as projected, not demonstrated.** Multiple council members state or imply that dart2wasm will outperform dart2js for compute-intensive tasks. The theoretical basis is sound: the WasmGC proposal allows the Wasm engine to manage GC natively rather than via JavaScript, and dart2wasm compiles Dart ahead-of-time to WasmGC bytecode rather than transpiling to JavaScript [DART34-IO2024]. In principle, this should be faster for compute-intensive workloads because the Wasm engine can apply native optimization passes without the JavaScript-compatibility overhead that dart2js carries. However, as of February 2026, the dart2wasm path is mature on Chrome 119+ but has known issues on Firefox and Safari [FLUTTER-WASM-SUPPORT]. Production comparisons of real Flutter web applications between dart2js and dart2wasm are not publicly available. The performance advantage is a reasonable expectation, not an established measurement.

- **AOT compilation speed has no published benchmarks.** The realist correctly notes that "Dart AOT compilation is not fast" and that "no systematic published benchmarks exist for Dart AOT compile times" [DART-COMPILE-DOCS]. This is accurate. Several council members characterize AOT compilation as "acceptable for mobile CI/CD" based on practitioner experience, which is appropriate given the absence of data. Advisors should note the absence: for large production Flutter applications, full release builds can take 5–15+ minutes in CI/CD, which is a meaningful engineering cost. The absence of published benchmarks prevents precise characterization.

**Additional context:**

- **Sound types enabled a measurable compiler optimization at Dart 2.0.** The historian cites Vijay Menon's research demonstrating that sound typing allowed Dart's compiler to reduce per-method native instruction counts from approximately 26 (under Dart 1.x's unsound system) to approximately 3 for well-typed code [MENON-SOUND-TYPES]. This is a compiler performance fact of high importance to language design: the decision to mandate sound types in Dart 2.0 was not primarily a user experience decision. It was driven by three converging forces: (1) the iOS App Store prohibition on JIT compilation required AOT compilation, which is dramatically more effective with sound types; (2) sound types enabled the dart2js compiler to emit tighter JavaScript with better tree-shaking; and (3) internal Google teams reported that unsound types produced unreliable IDE tooling. The council perspectives acknowledge these forces but do not foreground the compiler optimization dimension clearly enough. This is a crucial data point for language designers: type system soundness is not only an ergonomics and safety question — it has direct consequences for the quality of generated code.

- **Dart's `const` evaluation pipeline is a compile-time optimization path.** Dart's `const` expressions are evaluated by the CFE (Common Front-End) at compilation time and stored in the program's constant pool. This means that `const Color(0xFF000000)` — a common Flutter pattern — results in a single allocation in the constant pool, shared across all uses, rather than a runtime allocation on every widget rebuild. The CFE enforces `const` correctness: it verifies that constant expressions contain only compile-time-evaluable subexpressions and rejects invalid `const` usage. This compile-time evaluation pipeline is separate from the runtime GC and provides a meaningful allocation reduction for Flutter's widget-heavy use case.

- **The `dynamic` type has a runtime dispatch cost, not only a type-safety cost.** When the compiler encounters a variable or expression with type `dynamic`, it cannot emit static dispatch (resolving the method target at compile time). Instead, it emits dynamic dispatch (resolving the method target at runtime by consulting the object's type). This is slower than static dispatch by a constant factor — the exact factor depends on whether the inline cache for that call site warms up quickly. For code paths where `dynamic` arises frequently (JSON deserialization without typed conversion, platform channel data handling, legacy interop), this is a measurable performance cost in addition to the type-safety cost that the council correctly identifies. The compiler has limited ability to eliminate this cost: sound types allow devirtualization; `dynamic` prevents it.

- **Impeller (the replacement rendering engine) reduces Dart-side allocation pressure.** Flutter's legacy rendering engine (Skia) generated more per-frame Dart-side work; the Impeller rendering engine (shipping as the default on iOS since Flutter 3.16, on Android since Flutter 3.19) does more rendering work in C++ and generates fewer Dart-side allocations per frame. This materially improves GC pause behavior for rendering-heavy applications. Several GC analysis articles cited by the council (particularly older Medium posts) predate Impeller and may overstate GC pause concerns for current Flutter versions. Language advisors should note that the runtime environment has improved since many cited analyses were written.

---

### Other Sections (Compiler/Runtime Issues)

**Section 2: Type System — Covariant Generics Runtime Checks**

The council's treatment of covariant generics correctly identifies the soundness tradeoff and correctly notes that the Dart documentation describes it as "a deliberate decision" [DART-TYPE-SYSTEM]. What is missing from all perspectives is a precise description of the compiler mechanism by which safety is maintained despite the unsoundness.

When `List<Cat>` is assigned to `List<Animal>` and then `Animal` is written to the list, the Dart runtime inserts an implicit covariant check at the write site. This check verifies that the runtime type of the value being written is compatible with the static element type of the underlying list. If the check fails, a `TypeError` is thrown at runtime rather than a compile-time error. These covariant checks are inserted by the compiler — they are not the programmer's responsibility — but they are not free. Each write to a covariant generic collection has a type check overhead. The inline cache can amortize this cost if the same call site consistently writes values of the same type (the common case), but pathological code that writes values of varying types to covariant collections will pay the check cost on every write.

The language design implication: covariant generics are a tradeoff between ergonomic assignability and static soundness, but the safety mechanism is runtime enforcement, not static elimination. A language designer choosing this tradeoff must design a compiler that inserts appropriate runtime checks and must accept that these checks have a performance cost even if that cost is typically small.

**Section 2: Type System — The `dynamic` Inference Fallback**

The council correctly identifies that when type inference cannot determine a type, Dart defaults to `dynamic`. From a compiler perspective, this default is conservative but has a semantically important consequence: the transition from typed to `dynamic` is not diagnosed at the point of failure. If a long chain of type inference produces a `dynamic` at its terminal expression, no warning appears at the point where inference gave up. The developer must inspect the inferred types explicitly (via IDE hover or `dart analyze --fatal-infos`) to discover that a variable is `dynamic` rather than, say, `Map<String, Object>`.

This is a compiler design choice — the alternative would be to require an explicit `dynamic` annotation at any point where inference fails, rather than silently defaulting — and it has real consequences for large codebases where inference chains cross library boundaries. TypeScript made the analogous choice with `any` (with optional strict flags that warn on implicit `any`). Dart has no equivalent of TypeScript's `--strict` flag for implicit `dynamic`.

**Section 6 and Section 11: The Macros Cancellation as a Compiler Architecture Story**

The council discusses the macros cancellation from governance and developer experience angles but does not adequately explain the technical nature of the incompatibility from a compiler/runtime perspective. This deserves explicit treatment.

Dart's macros system was designed as a compile-time metaprogramming facility: macros would be Dart programs that ran during compilation, received type system information about the code being compiled, and produced new code (fields, methods, classes) based on that information [DART34-ANNOUNCEMENT]. This required the compiler to make a stable snapshot of the program's semantics available to macros during the build phase, and to correctly re-execute macros when the program's semantics changed.

The fundamental incompatibilities were threefold:

1. **Hot reload requires incremental Kernel IR patching.** Hot reload works by recompiling only changed libraries into Kernel IR and patching the running VM's method tables. Macros complicate this because a macro might consume semantic information from library A and produce code in library B. When library A changes, the macro must re-execute to produce updated code for library B — but this means hot reload must understand macro dependencies, not just library dependencies. The dependency graph required for correct incremental macro re-execution was not compatible with hot reload's sub-second latency requirement.

2. **AOT tree-shaking requires static-time completeness.** AOT compilation determines which code is reachable and which can be eliminated before any code runs. Macros that generate code based on program semantics could produce code that creates new reachability — the tree-shaker would need to understand what code macros might generate before generating it. This creates a bootstrapping problem: the tree-shaker's input depends on macro execution, but macro execution requires knowing what to optimize.

3. **Compile-time performance at scale.** Macro execution requires parsing and analyzing the entire program to build the semantic model available to macros, even for incremental builds. For large programs, this meant that any macros-using build needed to perform a full semantic analysis, negating the incremental compilation benefits that keep Dart's development builds fast.

The Dart team's statement — "each time we solved a major technical hurdle, new ones appeared" [DART-MACROS-UPDATE-2025] — is best understood as acknowledging that these three constraints are not independent problems that can be solved one at a time. They interact: solutions to the hot reload constraint (e.g., restricting which semantic information macros can observe) worsened the expressiveness of the macro system, which reduced the value of the feature below the threshold for shipping.

For language designers, this is a crucial lesson: a language with multiple compilation modes (JIT and AOT) that have different correctness and performance requirements will encounter features that can be designed cleanly for one mode but not both. Macros are a natural and valuable language feature; they are also a feature whose implementation interacts adversely with incrementality requirements, tree-shaking requirements, and content-addressable build caching. Designers of dual-mode compilation languages should identify, at feature design time, whether a proposed feature is feasible in both modes before committing to its development.

**Section 10: Interoperability — dart:ffi and Cross-Compilation**

The realist correctly notes that Dart AOT supports cross-compilation to multiple architectures (x64, ARM64, ARM32, RISC-V) [DART-COMPILE-DOCS], but the council does not sufficiently foreground a practical limitation: the `dart:ffi` library is unavailable on web compilation targets (dart2js and dart2wasm). This means any Dart package that uses FFI for performance or native library access must provide separate implementations for web targets, typically using `dart:js_interop` on web. This is not a fatal limitation, but it creates a portability fragmentation: "Dart everywhere" does not mean "all Dart packages on every target." Library authors must use conditional imports and platform-specific implementations if they use FFI on native but need web compatibility.

---

## Implications for Language Design

The Dart compiler/runtime story yields six implications of broad applicability for language designers.

**1. Multi-mode compilation creates design constraints that must be identified before feature development begins.**

Dart's JIT/AOT dual-mode compilation provides real value (development-time hot reload, production-time native performance), but it imposes hard design constraints on features that require compile-time introspection or code generation. Macros are the most vivid example: a metaprogramming system that must work in both incremental JIT compilation (for hot reload) and whole-program AOT compilation (for tree-shaking and deployment) faces requirements that are structurally opposed. A language designer choosing to support multiple compilation modes should, at design time, audit which planned features require semantic introspection, code generation, or tree-shaking awareness, and verify that the feature can be designed to work in all compilation modes before committing to it. The cost of discovering this incompatibility during implementation (as Dart experienced with macros) is orders of magnitude higher than discovering it during design.

**2. Type system soundness is a compiler optimization prerequisite, not only a safety property.**

Dart's experience quantifies this directly: mandatory sound types enabled the Dart compiler to reduce per-method native code from approximately 26 instructions to approximately 3 [MENON-SOUND-TYPES]. The driving force was iOS's prohibition on JIT compilation, which required AOT and exposed how much dead code an unsound type system forces the compiler to emit defensively. Language designers who accept soundness as optional or gradual should understand that they are accepting a real and measurable performance cost in addition to the safety cost. If a language will be deployed to AOT-only environments (iOS App Store, certain embedded systems), a sound type system is not optional — it is a prerequisite for adequate performance.

**3. Per-isolate heap ownership is a powerful but costly approach to GC/UI frame timing.**

Dart's isolate-per-heap model successfully prevents background GC from affecting UI frame timing, which is a genuine contribution to the frame-rate reliability of Flutter apps. The cost is the copy-on-send overhead for inter-isolate data transfer. This reveals a design tradeoff: the stronger the isolation between concurrent workers (via private heaps), the more expensive cross-worker data sharing becomes (deep copy). Languages targeting both UI and background parallel computation must choose a position on this spectrum explicitly. Zero-copy shared memory requires synchronization machinery to prevent races; isolated heaps eliminate races but impose data transfer costs. Dart chose the isolated end of the spectrum; language designers should make this choice consciously for their target workloads.

**4. GC and frame-rate targets interact in ways that require the language runtime to be co-designed with the UI framework.**

Dart's GC is not generic-purpose; it is tuned for Flutter's allocation patterns. The concurrent old-generation marking, the small young generation size (to keep scavenge pauses short), and the `const` evaluation pipeline are all choices influenced by Flutter's requirements. A language that will power a UI framework with hard frame-rate targets must either design its GC to support those targets (predictable pause times, concurrent collection, or GC isolation from the UI thread) or provide explicit escape hatches (allocation-free hot paths, off-heap allocation for long-lived objects, pinning APIs for deterministic GC behavior). Bolt-on GC tuning after the fact is possible but expensive.

**5. Prohibition on runtime reflection in production should be decided at architecture time and alternatives provided at language design time.**

Dart's AOT compilation prohibits `dart:mirrors` in production apps because runtime reflection prevents effective tree-shaking. This is a correct architectural choice for a language targeting compact native binaries, but its consequence — that common patterns enabled by reflection (DI frameworks, ORM, dynamic proxy generation) require code generation workarounds — was not fully addressed at design time. `build_runner`-based code generation is the workaround the ecosystem settled on, but it carries build-time overhead, generated file management burden, and the tooling debt that the macros system was intended to resolve. A language designer deciding to prohibit runtime reflection in production should simultaneously design a compile-time metaprogramming facility that replaces its common use cases. Promising to deliver that facility later, as a separate feature, risks the macros outcome: the compile-time facility may prove incompatible with other language constraints and never ship.

**6. The copy-on-send message-passing model needs zero-copy extension points designed in from the start.**

Dart's `TransferableTypedData` — which allows zero-copy transfer of typed byte buffers between isolates — was added after the isolation model was established, to address the obvious performance problem of copying large byte arrays. Its existence as a special case (rather than a general zero-copy transfer mechanism) reveals a design gap: the isolation model was designed without adequate attention to the performance cost of sharing large data. Language designers adopting actor-based or isolate-based concurrency models should, at architecture time, define the complete set of value types that can be transferred without copying and design the transfer API to make zero-copy the natural path for common patterns. Adding zero-copy paths later as special cases produces an API that is harder to use and harder to compose.

---

## References

[DART-GC-DOCS] "Garbage Collection." Dart SDK runtime documentation. https://dart.googlesource.com/sdk/+/refs/tags/2.15.0-99.0.dev/runtime/docs/gc.md

[DART-GC-ANALYSIS-MEDIUM] Pilzys, M. "Deep Analysis of Dart's Memory Model and Its Impact on Flutter Performance (Part 1)." Medium. https://medium.com/@maksymilian.pilzys/deep-analysis-of-darts-memory-model-and-its-impact-on-flutter-performance-part-1-c8feedcea3a1

[FLUTTER-GC-MEDIUM] Sullivan, M. "Flutter: Don't Fear the Garbage Collector." Flutter/Medium. https://medium.com/flutter/flutter-dont-fear-the-garbage-collector-d69b3ff1ca30

[DART-FFI-DOCS] "C interop using dart:ffi." dart.dev. https://dart.dev/interop/c-interop

[FLUTTER-SECURITY-FALSE-POSITIVES] "Security false positives." Flutter documentation. https://docs.flutter.dev/reference/security-false-positives

[DART-CONCURRENCY-DOCS] "Concurrency in Dart." dart.dev. https://dart.dev/language/concurrency

[DART-TYPE-SYSTEM] "The Dart type system." dart.dev. https://dart.dev/language/type-system

[DART-COMPILE-DOCS] "`dart compile`." dart.dev. https://dart.dev/tools/dart-compile

[DART-VM-INTRO] "Dart VM — introduction." dart.googlesource.com. https://mrale.ph/dartvm/

[DART-OVERVIEW] "Dart overview." dart.dev. https://dart.dev/overview

[DART33-RELEASE] Moore, K. "New in Dart 3.3: Extension Types, JavaScript Interop, and More." Dart Blog, February 2024. https://medium.com/dartlang/dart-3-3-325bf2bf6c13

[DART34-ANNOUNCEMENT] Thomsen, M. "Announcing Dart 3.4." Dart Blog, May 2024. https://medium.com/dartlang/dart-3-4-bd8d23b4462a

[DART-MACROS-UPDATE-2025] Thomsen, M. "An update on Dart macros & next steps." Dart Blog, January 2025. https://medium.com/dartlang/an-update-on-dart-macros-next-steps-4bf7e7c1e9e5

[DART-MACROS-CANCELLED-2025] "Dart macros — pause update." dart.dev / dart-lang/language GitHub. https://github.com/dart-lang/language/issues/3869

[CLBG-DART-MEASUREMENTS] Computer Language Benchmarks Game. Dart vs. C measurements. https://benchmarksgame-team.pages.debian.net/benchmarksgame/fastest/dart.html

[DART-FAST-ENOUGH] "How fast is Dart?" dart.dev. https://dart.dev/overview#fast

[FLUTTER-ISOLATES-DOCS] "Isolates." Flutter documentation. https://docs.flutter.dev/perf/isolates

[FLUTTER-WASM-SUPPORT] "WebAssembly support." Flutter documentation. https://docs.flutter.dev/platform-integration/web/wasm

[VIBE-STUDIO-FLUTTER-VS-RN] "Flutter vs. React Native: Performance Comparison." Vibe Studio, 2025. https://vibecoding.studio/flutter-vs-react-native-performance-comparison-2025

[NOMTEK-2025] "Flutter vs React Native 2025." Nomtek. https://www.nomtek.com/blog/flutter-vs-react-native

[DART-FINALIZER-DOCS] "Finalizer class." dart.dev API reference. https://api.dart.dev/stable/dart-core/Finalizer-class.html

[DART-SHARED-MEMORY-ISSUE-333] "Relaxing the isolate model — possible shared memory." dart-lang/language issue #333. https://github.com/dart-lang/language/issues/333

[DART-SHARED-MEMORY-PR-3531] "Shared variables across isolates." dart-lang/language PR #3531. https://github.com/dart-lang/language/pull/3531

[DART-FLUTTER-MOMENTUM-2025] Dart and Flutter team. "Flutter Momentum 2025." Flutter Blog, 2025. https://medium.com/flutter/flutter-momentum-2025

[FLUTTER-BUNDLE-SIZE-ISSUE] Community discussions on Flutter web bundle size. GitHub dart-lang/sdk and flutter/flutter issue trackers. Various dates 2023–2025.

[MENON-SOUND-TYPES] Menon, V. Internal Google research presentation cited in Dart 2.0 design documents. Referenced in: "Dart 2.0 Sound Type System Proposal." dart-lang/language repository. https://github.com/dart-lang/language/blob/main/accepted/future-releases/sound-type-system/proposal.md

[DART2-SOUND-TYPE-PROPOSAL] "Sound type system." dart-lang/language, accepted proposals. https://github.com/dart-lang/language/blob/main/accepted/future-releases/sound-type-system/proposal.md

[DART-212-ANNOUNCEMENT] Thomsen, M. "Announcing Dart 2.12." Dart Blog, March 2021. https://blog.dart.dev/announcing-dart-2-12-499a6e689c87

[DART-BREAKING-CHANGES] "SDK changelog / breaking changes." dart.dev. https://dart.dev/tools/sdk/changelog

[DART-LANG-VERSIONING] "Language evolution: language versioning." dart.dev. https://dart.dev/resources/language/evolution#language-versioning
