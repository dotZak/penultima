# C# — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "C#"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

The C# council has produced five perspectives of high technical quality. Claims about the CLR's generational garbage collector, reified generics, async/await state machine compilation, and TechEmpower benchmark performance are consistently accurate and well-sourced across the council. The areas requiring correction or additional context cluster around three patterns: (1) median-case GC pause statistics being presented without P999 context, obscuring the latency unpredictability that production documentation reveals; (2) the Nullable Reference Type system being framed as a safety mechanism when it is strictly a compile-time annotation layer with zero runtime enforcement; and (3) NativeAOT compatibility constraints being understated, particularly by the apologist.

The council's treatment of async/await is broadly accurate on the design achievement but inconsistent on the operational footguns. The SynchronizationContext deadlock and `async void` exception-swallowing behaviors are correctly characterized by the practitioner and detractor, but the apologist and historian treat these as edge cases rather than the pervasive production hazards that incident reports indicate. The detractor's documented issue references (dotnet/runtime #65850, #88426, #101746) provide the most granular evidence in the report and should be incorporated into the consensus synthesis rather than treated as adversarial corner-cases.

The performance section benefits from consistent citations of TechEmpower Round 23 data and appropriately contextualized NativeAOT cold-start numbers. The primary gap is the absence of Profile-Guided Optimization (PGO) discussion — a significant RyuJIT capability introduced in .NET 7 and central to .NET 8's performance story — and the omission of ReadyToRun as a distinct middle-ground between full JIT and NativeAOT.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **Generational GC structure.** All five perspectives accurately describe three generations (Gen 0, Gen 1, Gen 2) plus the Large Object Heap (LOH, threshold ≥85 KB). The research brief correctly sources this to [CLR-GC].

- **Gen 0/Gen 1 sub-millisecond pause claim.** The claim that Gen 0/1 collection pauses are "typically under 1 ms" is accurate as a median-case statement for workloads that don't promote objects to Gen 1 in large volumes. The apologist, realist, and practitioner all state this correctly.

- **`Span<T>` and ref struct semantics.** Claims that `Span<T>` is a ref struct that cannot escape to the heap, that `stackalloc` produces a `Span<T>` in modern C#, and that Span-based APIs eliminate GC pressure in hot paths are technically accurate and consistent across the council. The practitioner's "40–60% reduction in allocation rates" for Span-migrated hot paths is consistent with BenchmarkDotNet production case studies.

- **LOH non-compaction default.** The practitioner's note that the LOH is not compacted by default and fragments under large-buffer workloads is accurate. LOH compaction is available via `GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce` but incurs a full GC pause.

- **`IDisposable` / `using` determinism.** The characterization of `IDisposable`/`using` as providing RAII-equivalent deterministic cleanup is accurate with one qualifier: the timing is deterministic only when `Dispose()` is explicitly called or triggered by a `using` statement. Objects not explicitly disposed are finalized non-deterministically by the GC finalizer thread, which is a weaker guarantee than RAII. The apologist's comparison to RAII is accurate if limited to the `using`-statement path.

- **NativeAOT eliminates JIT warmup.** Accurate across all perspectives. NativeAOT has been production-ready since .NET 8 [MS-NATIVEAOT].

- **`ValueTask<T>` single-await constraint.** The practitioner correctly identifies that `ValueTask<T>` can only be awaited once and that double-await compiles without error but produces undefined behavior at runtime. This is accurate and important.

**Corrections needed:**

- **GC pause statistics require P999 framing.** The apologist states Gen 0/1 pauses are "typically under 1 ms" without qualification, implying this is representative of tail latency. The detractor's cited production evidence complicates this: dotnet/runtime issue #65850 documents Gen 2 pauses of 55 ms on ARM64 hardware (a 3.4× overrun of 16 ms frame budget); issue #101746 documents Roblox's .NET 6→.NET 8 migration producing an 8× GC pause regression (24 ms to ~200 ms average) caused by a Gen 0 minimum budget change; issue #88426 documents production .NET 7 pauses reaching ~1 second with 98.98% heap fragmentation [DOTNET-65850, DOTNET-101746, DOTNET-88426]. The sub-millisecond claim is accurate for Gen 0/1 median behavior in well-tuned applications with small, short-lived heaps. It is not representative of P999 behavior, Gen 2 pause times, or large-heap server workloads. The consensus should frame this accurately: median Gen 0/1 pauses are sub-millisecond; maximum Gen 2 pauses scale with live heap size and can reach hundreds of milliseconds; GC version changes can introduce latency regressions without breaking changes in application code.

- **`async void` exception handling is not an edge case.** The apologist and historian both treat `async void` as a known antipattern without characterizing the severity. In production codebases, `async void` methods silently swallow exceptions — the exception goes to the `SynchronizationContext.UnhandledException` handler, not to the calling try/catch. The detractor correctly cites Cleary's documentation of this [CLEARY-MSDN-2013] and documented production failures in Puppeteer-Sharp and WPF applications [STRAHL-ASYNCVOID, DEV-PUPPETEER]. The distinction matters for the consensus: `async void` is not merely discouraged — it is a category of silent exception loss with documented production consequences.

- **Pinned Object Heap (POH) omission.** .NET 5 introduced the Pinned Object Heap, a separate heap region for pinned objects that eliminates the fragmentation penalty previously associated with `fixed`-pinned objects in the regular heap. The research brief does not mention this, and neither does any council member. This is relevant to unsafe code and interop discussions in Section 10.

**Additional context:**

- **GC modes matter for production.** The CLR offers workstation GC (low-latency, concurrent, single-heap) and server GC (high-throughput, per-core heaps, background collection). The practitioner alludes to this when mentioning "monitoring dashboards for well-written ASP.NET Core services," but the consensus should note that ASP.NET Core defaults to server GC in production and workstation GC in development, making local testing a poor predictor of production pause behavior.

- **LOH compaction option.** The `GCSettings.LargeObjectHeapCompactionMode` API (introduced .NET 4.5.1) allows one-time LOH compaction, trading a pause for fragmentation relief. High-throughput services that process large buffers should use `ArrayPool<byte>` rather than relying on LOH compaction.

- **Finalization is a GC-pressure multiplier.** Objects with finalizers require two GC passes to collect (one to queue for finalization, one to reclaim after the finalizer runs). The council does not mention this. In library code that wraps unmanaged resources, incorrect finalizer implementation is a GC performance hazard distinct from, and in addition to, the IDisposable pattern.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **Async/await compiler transformation.** The characterization of async/await as a compiler-generated state machine that transforms sequential-looking code into non-blocking continuations is technically accurate across all perspectives. The historian correctly identifies C# 5 (2012) as the origin point and notes the subsequent adoption pattern across JavaScript, Python, Rust, Swift, and Kotlin.

- **Colored function problem.** The realist and detractor accurately characterize the colored function problem. Bob Nystrom's 2015 analysis explicitly names C# [NYSTROM-COLOR], and Cleary's "zombie virus" metaphor for async propagation is correctly attributed [CLEARY-MSDN-2013]. This is a real and accurately described design constraint.

- **SynchronizationContext deadlock.** The practitioner's description of the `.Result`/`.Wait()` deadlock pattern is technically precise and consistent with Cleary's documentation. Microsoft's CA2007 rule for `ConfigureAwait(false)` detection confirms this is a recognized systemic issue, not an edge case.

- **No compile-time race detection.** The apologist's acknowledgment that C# has no compile-time data race detection (unlike Rust's borrow checker) is accurate. The CLR provides `volatile`, `Interlocked`, and monitor-based primitives as programmer-managed synchronization, with no language-level enforcement.

- **`System.Threading.Lock` (C# 13).** The apologist and research brief correctly describe the new `Lock` type in C# 13/.NET 9, which provides more efficient exclusive locking than `Monitor.Enter/Exit`.

- **Async state machine heap promotion.** The research brief correctly notes that local variables in async methods are lifted into heap-allocated state machine objects [DOTNET-ASYNC-GC]. This has GC pressure implications that are accurately acknowledged in the practitioner's discussion of ValueTask.

**Corrections needed:**

- **`async void` characterization needs escalation.** The apologist treats `async void` as a known antipattern that developers should avoid. The operational reality is stronger: `async void` exception loss is not merely a style concern but a production reliability risk. Microsoft's own CA1031/VSTHRD100 Roslyn analyzer rules exist specifically because this pattern is common enough to warrant automated detection. The practitioner correctly identifies `ConfigureAwait(false)` as a necessary discipline in library code; the same level of specificity should be applied to `async void`.

- **`ValueTask<T>` double-await is an unsafe specification gap.** The practitioner correctly identifies that double-awaiting a `ValueTask<T>` compiles without error and produces undefined behavior. This is worth reinforcing in the consensus: it is a case where the type system provides no protection against a correctness bug. The `IValueTaskSource<T>` interface allows implementations to reuse storage after the first await completes, meaning a second await on the same instance reads a different or recycled result. This is an ABI-level hazard that no Roslyn analyzer currently catches in general.

**Additional context:**

- **`ConfigureAwait(false)` propagation is architectural.** The SynchronizationContext deadlock is not merely a "pitfall" — it imposes an architectural constraint on library authors: all library-level async code should use `ConfigureAwait(false)` to avoid capturing the caller's context. The burden is asymmetric: application code controls the context, but library code must defend against it without knowing the application context. This is a genuine language design tradeoff — the alternative (no SynchronizationContext by default) would break WPF and WinForms UI-thread async patterns.

- **Async state machine allocation.** In high-throughput I/O scenarios, async state machines become a source of GC pressure because each invocation of an async method allocates a state machine object on the heap. `ValueTask<T>` with `IValueTaskSource<T>` was designed to mitigate this via pooled state machine objects, but the correct use of this pattern requires manual implementation of `IValueTaskSource<T>`, which is significantly more complex than using `Task<T>`.

- **Channel<T> and structured concurrency.** The council's coverage of `System.Threading.Channels` and `IAsyncEnumerable<T>` is accurate but does not address the absence of structured concurrency primitives (as found in Kotlin's coroutines or Swift's task groups). C# async/await allows "fire and forget" patterns that lose exception tracking. The upcoming `TaskCompletionSource` and existing `CancellationToken` patterns provide partial mitigation but not the hard guarantees structured concurrency offers.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **TechEmpower Round 23 figures.** The claim that ASP.NET Core with .NET 9 achieves approximately 27.5 million requests/second in plaintext tests, with approximately 3× advantage over Node.js in JSON serialization and 1.9× in database-bound scenarios, is consistently accurate across all perspectives and sourced correctly to [TECHEMPOWER-R23].

- **JIT warmup latency.** The practitioner's description of JIT-compiled services experiencing elevated latency for the first 10–30 seconds (especially in serverless/Lambda deployments) is accurate and reflects documented production behavior.

- **NativeAOT cold-start numbers.** The claim of ~100–200 ms cold-start for NativeAOT-compiled Lambda functions versus 1–2 seconds for JIT-compiled equivalents is consistent with production case studies from AWS Lambda deployments.

- **Tiered compilation mechanics.** The apologist's description of Tier 0 (fast initial compilation) and Tier 1 (profile-informed recompilation) JIT tiers is accurate as a description of RyuJIT's tiered compilation behavior.

- **Rust-based frameworks occupy the top tier.** The research brief's note that Rust-based frameworks occupy the highest TechEmpower positions is accurate; .NET is correctly characterized as upper-middle tier among managed/GC'd runtimes.

**Corrections needed:**

- **Profile-Guided Optimization (PGO) is absent from the council's performance discussion.** .NET 7 introduced Dynamic PGO (DPGO), where the JIT uses profile data collected at Tier 0 to generate better-optimized Tier 1 code. .NET 8 enabled DPGO by default and extended it to cover more hot paths, with documented performance improvements of 15–30% in throughput-sensitive scenarios. This is a significant advancement in the JIT's optimization story that no council member mentions. The consensus should note PGO explicitly, as it changes the character of the JIT from "profile-blind" to "profile-driven" — a meaningful distinction for comparing against ahead-of-time compilers.

- **ReadyToRun (R2R) is not distinguished from NativeAOT.** The council treats the compilation model as a binary (JIT vs. NativeAOT), but ReadyToRun is a third option: the assembly is pre-compiled to native code at publish time and embedded alongside IL, providing faster startup than cold JIT while preserving the ability to re-JIT hot methods for better optimization. The practitioner mentions R2R parenthetically, but neither it nor any other perspective characterizes it as a distinct deployment option. For language designers, R2R's "pre-warmed JIT" model is architecturally interesting as a middle ground between full JIT and fully static AOT.

- **NativeAOT build-time cost understated.** All perspectives that discuss NativeAOT's advantages mention restricted reflection and dynamic loading as tradeoffs, but none quantifies the build-time cost. NativeAOT compilation is substantially slower than standard `dotnet build` — for non-trivial solutions, full NativeAOT publish can take 2–5× longer than JIT-enabled publish. For CI/CD-sensitive workflows, this is a material tradeoff. The consensus should acknowledge this.

- **GC pause non-determinism across .NET versions is a deployment risk.** The detractor's Roblox regression case (dotnet/runtime #101746 — a Gen 0 minimum budget change in .NET 8 caused 8× pause regression) reveals a specific compiler/runtime risk: CLR internal GC tuning changes between minor versions can silently alter latency characteristics without API-level breaking changes. Application code that meets latency SLOs on .NET 6 may fail them on .NET 8 with no code changes. This is not a flaw unique to C# among GC'd languages, but it is underemphasized in the council's performance section.

**Additional context:**

- **LINQ expression tree compilation.** The council notes LINQ's `IEnumerable<T>` vs `IQueryable<T>` distinction but does not address expression tree compilation as a performance characteristic. LINQ expression trees (used by Entity Framework Core to translate queries to SQL) are compiled at runtime via `Expression.Compile()`, which invokes the Roslyn compiler infrastructure at runtime. This is a startup-time cost for first-query scenarios. EF Core 7+ introduced compiled queries (`EF.CompileAsyncQuery()`) to amortize this cost, and NativeAOT-compatible EF Core 9+ avoids expression tree compilation entirely in favor of source-generated interceptors.

- **Boxing remains a performance hazard.** Despite reified generics eliminating boxing for generic value types, boxing still occurs in non-generic paths: casting a `struct` to `object` or an interface, storing value types in non-generic collections, and certain reflection operations. The council mentions boxing in the context of reified generics correctly, but the consensus should note that boxing is still a GC pressure source in large codebases using older API patterns (pre-generic BCL code, object-typed dictionaries, etc.).

---

### Other Sections (Compiler/Runtime-Relevant Flags)

**Section 2: Type System — Nullable Reference Types**

All five perspectives acknowledge that Nullable Reference Types (NRT, C# 8+) are compile-time-only annotations with no runtime enforcement. However, the severity of this limitation is not consistently framed. The apologist calls NRT "the most significant attempt since Kotlin to retrofit null-safety into a reference type system" while admitting the compile-time-only nature is "real and should be acknowledged." The detractor frames this more precisely: NRT creates a false sense of safety, because a method annotated as returning `string` (non-nullable) that returns `null` at runtime does not throw; the consumer may receive null and dereference it, producing a `NullReferenceException` that the annotation system was supposed to prevent [PVS-STUDIO-NRT].

The compiler/runtime implication is structural: NRT warnings are suppressible (via the `!` null-forgiving operator), are disabled by default in existing projects, and have an opt-in migration path that often takes months or years in large codebases. The annotation system is only as strong as the least-annotated dependency in the call chain. A correctly annotated method calling an unannotated third-party library receives no null-safety guarantee from NRT whatsoever.

Additionally, the Entity Framework Core team documented a production-risk interaction: enabling NRT on an existing EF Core project alters column nullability inference, potentially generating schema migrations that change production database column constraints [EFCORE-NRT]. This is a case where a compile-time annotation feature has unintended runtime (and persistence layer) consequences.

**Section 2: Type System — Pattern Matching Exhaustiveness**

The council accurately describes switch expression exhaustiveness warnings over sealed hierarchies. One precision is needed: exhaustiveness checking is a *warning*, not an error, unless the switch expression has no default arm and the pattern coverage is provably incomplete — in that case, the compiler emits CS8509 (non-exhaustive switch expression). But for open hierarchies (non-sealed types), no exhaustiveness checking is performed, and adding a new subtype of an unsealed class or interface silently breaks existing switch expressions at runtime. The council does not distinguish between sealed and unsealed coverage semantics; the consensus should.

**Section 5: Error Handling — Exception Performance**

None of the council perspectives address the performance cost of exception-as-control-flow patterns. Throwing and catching .NET exceptions is substantially more expensive than returning a result value: exception throw/catch involves stack walking, stack trace capture, and GC allocation for the Exception object. In hot paths where errors are frequent (e.g., parsing, validation), using exceptions for expected failure cases is a known performance antipattern. The Result<T, E> pattern (via OneOf, ErrorOr, or similar NuGet packages) or the newer C# union type proposals address this, but no language-native solution exists in C# 13. The compiler does not warn about exception-as-control-flow, and the runtime provides no zero-cost path equivalent to Rust's `?` operator.

**Section 6: Ecosystem — Source Generators and Reflection**

The council correctly identifies Roslyn Source Generators (C# 9+) as a compile-time code generation mechanism that reduces runtime reflection overhead. The compiler/runtime implication worth foregrounding: source generators run during compilation, not at application startup, and their output is ordinary C# that the compiler compiles normally. This makes source-generated code NativeAOT-compatible, which is why .NET's move toward source generators (System.Text.Json, EF Core interceptors, Regex source generation) is architecturally aligned with the NativeAOT story. Libraries that have not migrated to source generators and still rely on `Type.GetMethod()`, `Activator.CreateInstance()`, or dynamic proxy generation are incompatible with NativeAOT. The consensus should note this alignment explicitly: source generators are not merely a developer experience feature but a migration path toward static compilation.

**Section 10: Interoperability — P/Invoke and Unsafe FFI**

The council's interoperability section describes P/Invoke for native code invocation but does not address the marshaling cost. P/Invoke marshaling — type conversion between managed CLR types and native C types — is performed by the CLR's interop layer and can be a significant overhead on hot paths (e.g., tight loops calling native APIs thousands of times per second). The .NET 7 `LibraryImportAttribute` with source-generated marshalers addresses this by generating static marshaling code at compile time rather than using runtime reflection-based marshaling. This is another instance of the compile-time-vs-runtime tradeoff that runs throughout .NET 8+'s performance story.

---

## Implications for Language Design

The C# council record yields several compiler/runtime lessons of broad applicability:

**1. Median statistics obscure tail latency risk in GC systems.**
Claiming "sub-millisecond GC pauses" without a percentile qualifier misleads language adopters about production operational characteristics. GC pause distributions are heavy-tailed: median behavior in synthetic workloads is a poor predictor of P999 behavior under production heap sizes. Language designers specifying GC behavior should mandate SLA-style latency bounds (P50/P95/P99/P999) rather than "typical" statements, and runtime implementations should expose programmatic pause telemetry. The Roblox 8× regression (a runtime internals change producing a latency regression with no API-level breakage) demonstrates that GC tuning policy should be part of the public contract, not an implementation detail.

**2. Compile-time annotation systems are not safety systems.**
C#'s NRT demonstrates the risks of conflating "the compiler warns about X" with "the runtime prevents X." An annotation system that produces warnings rather than errors, is opt-in, is suppressible via escape hatches, and has no runtime enforcement provides ergonomic benefits but creates an illusion of safety. For language designers: if null safety is a stated design goal, it must be enforced at the type system level with runtime checks or a non-nullable type that the runtime treats as distinct (not merely annotated). NRT's value is real but should be scoped to "improved documentation and tooling feedback," not "null safety."

**3. Async/await's colored function cost is permanent; design it with eyes open.**
C#'s async/await is a genuine engineering achievement, but it commits adopters to the colored function model for the language's lifetime. Languages that have since added async/await (Python, JavaScript, Kotlin) have confirmed that the ergonomics are worth the cost — but the cost (viral propagation, SynchronizationContext hazards, `async void` footguns) is also real. Language designers adopting async/await should simultaneously adopt: (a) no synchronization context by default (ASP.NET Core's lesson), (b) `async void` either prohibited or isolated from the exception propagation system, and (c) an analyzer rule for `ConfigureAwait` discipline enforced at the project level.

**4. AOT compilation is a design constraint, not a deployment option.**
NativeAOT's incompatibility with reflection-based runtime code generation (DI containers, serialization, ORM mapping, dynamic proxy frameworks) reveals that AOT compilation is not a deployment option that can be added to an existing language ecosystem. It is a design constraint that reshapes the entire ecosystem. Libraries built on the assumption of runtime reflection cannot be made AOT-compatible with source generators without rewriting their core abstractions. For new language designers: if AOT compilation is a goal, the standard library and idioms should avoid runtime reflection from the start, not retrofit source generators after the ecosystem has been built around reflection.

**5. Reified generics eliminate an entire class of performance bugs at non-trivial implementation cost.**
C#'s choice to implement generics via CLR reification (versus Java's type erasure) was the right call for performance — `List<int>` carries no boxing overhead, while Java's `ArrayList<Integer>` boxes every element — but it required modifications to the runtime itself. The lesson is that generic specialization is not a "compiler trick"; it requires runtime support (distinct native code per value-type instantiation, distinct vtable layouts). Language designers choosing generics should make this implementation decision consciously: erasure is cheaper to implement; reification produces better performance for value-type-heavy workloads.

**6. State machine compilation of coroutines imposes hidden allocation costs.**
C#'s async state machines are heap-allocated objects, meaning every `async` method invocation that actually suspends creates a GC-managed object. This is invisible in the source code, making `async` methods appear "free" when they are not. High-throughput scenarios require `ValueTask<T>` with `IValueTaskSource<T>` pooling to amortize this cost, adding implementation complexity that defeats the simplicity that async/await promised. Language designers implementing coroutines via state machine compilation should consider: (a) stack-allocated state machines where feasible, (b) pooled state machine allocators at the runtime level, or (c) accepting the allocation cost but being explicit about it in documentation.

---

## References

[CLR-GC] "Garbage Collection — .NET." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/

[MS-NATIVEAOT] "Native AOT deployment overview — .NET." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/

[MS-SPAN] "Span<T> — .NET API." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/api/system.span-1

[MS-UNSAFE] "Unsafe code, pointers to data, and function pointers — C# reference." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/unsafe-code

[MS-VALUETASK] "ValueTask<TResult> — .NET API." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.valuetask-1

[MS-ASYNC-TAP] "The Task Asynchronous Programming (TAP) model with async and await — C#." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/asynchronous-programming/task-asynchronous-programming-model

[ECMA-334] Standard ECMA-334: C# Language Specification, 6th Edition. Ecma International, 2022.

[ECMA-335] Standard ECMA-335: Common Language Infrastructure (CLI). Ecma International.

[MS-MANAGED-EXEC] "Managed execution process — .NET." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/standard/managed-execution-process

[MS-NRT] "Nullable reference types — C#." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/nullable-references

[MS-DISPOSE] "Implementing a Dispose method — .NET." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/standard/garbage-collection/implementing-dispose

[MS-ASYNCSTREAMS] "Asynchronous streams — C#." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/asynchronous-programming/generate-consume-asynchronous-stream

[MS-CHANNELS] "System.Threading.Channels — .NET API." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/api/system.threading.channels

[MS-CS13] "What's new in C# 13." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/whats-new/csharp-13

[TECHEMPOWER-R23] "TechEmpower Framework Benchmarks — Round 23." February 24, 2025. https://www.techempower.com/benchmarks/#section=data-r23

[CLEARY-MSDN-2013] Cleary, S. "Async/Await — Best Practices in Asynchronous Programming." MSDN Magazine, March 2013.

[NYSTROM-COLOR] Nystrom, B. "What color is your function?" nystrom.craftinginterpreters.com, 2015.

[DOTNET-65850] dotnet/runtime Issue #65850. "GC pauses reaching 55 ms on ARM64 hardware." GitHub. https://github.com/dotnet/runtime/issues/65850

[DOTNET-88426] dotnet/runtime Issue #88426. "Production .NET 7 server experiencing periodic long pauses of approximately 1 second." GitHub. https://github.com/dotnet/runtime/issues/88426

[DOTNET-101746] dotnet/runtime Issue #101746. "Roblox .NET 6 to .NET 8 migration: GC pause regression from 24 ms to ~200 ms." GitHub. https://github.com/dotnet/runtime/issues/101746

[WARREN-GC] Warren, M. "Analysing .NET GC Pause times." mattwarren.org. https://mattwarren.org/2017/01/13/Analysing-.NET-GC-Pause-times/

[PVS-STUDIO-NRT] PVS-Studio. "Nullable Reference Types and Null-Forgiving Operator in C#." 2024. https://pvs-studio.com/en/blog/posts/csharp/1088/

[EFCORE-NRT] Entity Framework Core documentation. "Nullable reference types." Microsoft Learn. https://learn.microsoft.com/en-us/ef/core/miscellaneous/nullable-reference-types

[STRAHL-ASYNCVOID] Strahl, R. "Surprised by async void." weblog.west-wind.com. https://weblog.west-wind.com/posts/2021/oct/22/surprised-by-async-void

[DEV-PUPPETEER] "async void and event handling in Puppeteer-Sharp." GitHub/dev.to — documented production issues in PuppeteerSharp repository.

[DOTNET-ASYNC-GC] ".NET Async State Machine and GC Pressure." dotnet/runtime — internal implementation documentation. https://github.com/dotnet/runtime

[MS-TYPES] "Types — C# language reference." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/built-in-types

[MS-RECORDS] "Records — C# reference." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/record

[ENDJIN-NRT] "C# Nullable Reference Type interactions with generics." endjin.com. https://endjin.com/blog/2020/12/nullable-reference-types-in-generic-interfaces

[BLOG-COLORED] Nystrom, B. "What color is your function?" 2015. (See [NYSTROM-COLOR].)

[BLOG-ASYNC-MISTAKE] "Don't Block on Async Code." Stephen Cleary's blog. https://blog.stephencleary.com/2012/07/dont-block-on-async-code.html

[MS-TAP] "Task-based Asynchronous Pattern (TAP) in .NET." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/standard/asynchronous-programming-patterns/task-based-asynchronous-pattern-tap

[MS-TPL] "Task Parallel Library (TPL)." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/standard/parallel-programming/task-parallel-library-tpl

[ADAMSITNIK-ARRAYPOOL] Sitnik, A. "Pooling large arrays with ArrayPool." adamsitnik.com. https://adamsitnik.com/Array-Pool/
