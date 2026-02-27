# JavaScript — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "JavaScript"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
```

---

## Summary

The council perspectives are generally accurate on compiler/runtime dimensions, but several claims require precision adjustments. The most consistent pattern across all five perspectives is conflation of V8-specific behavior with JavaScript specification behavior — a distinction that matters significantly for language designers. V8's engineering compensates for design constraints that the ECMAScript specification imposes on all engines; the compensation is impressive, but it is not the same as a sound design.

Three technical issues the council does not fully resolve. First, the distinction between V8 heap memory and total Node.js process memory: Node.js applications can consume substantially more memory than the V8 heap limit suggests, because `Buffer` allocations fall outside the V8 heap in native (C++) memory. Second, the apologist's claim that Maglev eliminates bimodal warmup behavior is overstated — warmup effects persist with smaller magnitude but are not gone. Third, the framing of JavaScript's async model as "infectious" (function coloring) is accurate but understates that this reflects a real property of asynchronous computation that all concurrency models must express somewhere; the question is whether the language hides it or exposes it.

For language designers, JavaScript's compiler/runtime history is a case study in sustained engineering investment recovering ground lost to specification-level design choices. The multi-tier JIT pipeline (Ignition → Sparkplug → Maglev → TurboFan) exists specifically to compensate for the absence of static type information in the language. This engineering is impressive and real, but it concentrates optimization knowledge in implementation-specific tooling, creates performance profiles sensitive to runtime internals rather than language semantics, and cannot fully close the gap with languages that provide type information statically.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**
- V8 uses a generational GC: Scavenger (Cheney's semi-space copying algorithm) for the young generation (New Space), mark-sweep-compact for the old generation [V8-MEMORY]. This is correctly described across council perspectives.
- Orinoco introduced parallel, concurrent, and incremental collection to reduce main-thread pause times [V8-MEMORY]. All council members cite this accurately.
- V8 heap default limit of approximately 1.4–1.5 GB for 64-bit processes, configurable via `--max-old-space-size` [V8-MEMORY]. Correct.
- GC timing is non-deterministic and not exposed to application code. Correct; this is a specification-level property. ECMAScript 2021 explicitly specifies that `WeakRef` and `FinalizationRegistry` callbacks are not guaranteed to fire on any particular schedule [ECMA-WEAKREF].
- The Scavenger's cost is proportional to live objects, not heap size. Correct; this is the key property of the semi-space copying algorithm that makes young-generation collection cheap.
- Memory leak patterns through retained closures, event listeners, and DOM references are real. Accurate and documented.

**Corrections needed:**

1. **The apologist characterizes the V8 heap limit as "largely a non-issue for typical workloads."** This understates a real production constraint. Containerized deployments (Kubernetes, AWS Lambda, Cloudflare Workers with its 128 MB default limit) routinely impose memory constraints well below 1.4 GB. More importantly, the V8 heap limit is not the bound on total process memory. Node.js `Buffer` allocations bypass the V8 heap entirely — they are allocated in native (C++) memory via `malloc` and contribute to process RSS but are invisible to the JS heap limit. An I/O-intensive application allocating Buffers for stream processing can exhaust total OS-level memory limits while the V8 heap appears to have capacity. The detractor's "cliff, not wall" framing is accurate; the apologist's "non-issue" framing is not.

2. **Multiple perspectives state major GC pauses are "typically under 50ms."** This claim is accurate for average-case production workloads on small-to-medium heaps, but the word "typically" does substantial work here. V8's incremental marking interleaves with JavaScript execution in small time slices, but the final stop-the-world evacuation phase — even with concurrent marking — is not bounded at 50ms. On large heaps (multi-gigabyte configurations), worst-case major GC pauses can substantially exceed this. The 50ms figure represents the success of Orinoco's optimizations, not a hard latency guarantee [V8-MEMORY]. Applications requiring p99 latency below 50ms cannot treat "typically under 50ms" as a reliable specification.

3. **The apologist claims JavaScript "structurally eliminates buffer overflow bugs."** This holds for application code. V8 itself, however, is implemented in C++ and has its own memory safety vulnerability classes — type confusion, use-after-free, and bounds check bypass are recurring CVE categories in V8 specifically [BUGZILLA-SPM]. From an application developer's perspective the statement is accurate. From a security researcher's perspective, the JIT compiler infrastructure introduces a C++ attack surface that the "memory safe" framing does not capture.

4. **The detractor states "Python provides `gc.collect()` and reference counting semantics."** This is CPython-specific. PyPy uses a tracing GC without reference counting. The language comparison should be made at the specification level: Python's language specification does not mandate reference counting, and PyPy demonstrates that a Python implementation can work without it. The meaningful contrast is between JavaScript (which provides no GC control API) and languages with richer GC observability (Java's `System.gc()` hint, .NET's `GC.Collect()`, the Rust ownership model which provides allocation control without a GC).

**Additional context:**

- V8 uses incremental marking with a write barrier to detect mutations during concurrent marking. The write barrier adds a small overhead to every object write in old-generation code. This overhead is not free, though it is small in practice. Language designers specifying a GC should consider whether write barrier costs are acceptable for all object types or whether escape analysis and stack allocation should be prioritized for short-lived objects.
- The specification's deliberate silence on GC timing — specifying what must be collected but not when or how — created the conditions for V8's engineering innovations to happen without specification changes. This is a principled design decision with a concrete payoff: Orinoco's concurrent collection was possible without touching ECMA-262. A new language should consider whether GC timing observability should be part of the language specification or an implementation detail.
- `FinalizationRegistry` callbacks are intentionally non-deterministic: the specification states implementations may never call them if the program exits normally. This is correct behavior, not a limitation. Designers adding resource cleanup APIs to new languages should treat non-deterministic GC finalization as unreliable for correctness-critical cleanup.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**
- JavaScript is single-threaded within a single execution context; concurrency is achieved via the event loop. Correct; this is the ECMAScript execution model.
- The microtask queue is drained completely before the next macrotask executes. Correct; this is a specification-level ordering guarantee, codified in the HTML Living Standard's event loop specification [WHATWG-HTML]. It is not an implementation detail.
- async/await is syntactic sugar over Promises and does not introduce real parallelism. Correct.
- Workers provide true parallelism via OS threads with separate JavaScript heaps and message-passing communication. Correct.
- `SharedArrayBuffer` requires COOP and COEP HTTP headers since 2020 [SPECTRE-SAB]. Correct.
- CPU-bound synchronous operations block the event loop, producing starvation for all other pending work. Correct.
- Function coloring (async cannot be called without propagating async context upward) is a genuine architectural constraint. Correct.

**Corrections needed:**

1. **The apologist cites "LinkedIn reduced server footprint from 30 servers to 3 while improving performance."** This is a documented case study from LinkedIn's engineering blog (2011–2012), but it covered one specific service — LinkedIn's mobile API layer — not LinkedIn's overall infrastructure. The claim is valid as a point data point for I/O-bound API servers. Extrapolating it as evidence for the general adequacy of Node.js's concurrency model overstates the scope of a single service migration.

2. **The detractor states "Rust or Go can share a reference across threads at zero cost; JavaScript must copy data."** This requires precision. `ArrayBuffer` and `MessagePort` objects can be transferred across Worker thread boundaries at zero-copy cost via the `transfer` option of `postMessage` — the underlying buffer is moved, not copied, and the original reference becomes detached. What cannot be zero-copy transferred is an arbitrary JavaScript object graph. The meaningful critique is that typed binary data (ArrayBuffer, SharedArrayBuffer) is shareable or transferable efficiently, but structured JavaScript objects require O(n) structured cloning. This is an accurate and significant limitation for applications that need to share object-format data across workers, but the "zero-copy" claim should be bounded to what the API actually prohibits.

3. **Multiple perspectives describe SharedArrayBuffer as "restricted post-Spectre."** The mechanism is worth precision: `SharedArrayBuffer` itself is not a Spectre vector. What Spectre exploited was the ability to construct high-resolution timers. `SharedArrayBuffer` enabled precise timing via `Atomics.waitAsync` and `Atomics.wait` (which can measure nanosecond-level time differences by incrementing a shared counter in a tight loop in one thread and reading it in another). The timer was the vector; shared memory was the mechanism that made the timer high-resolution. `SharedArrayBuffer` was disabled as a precaution because it was the mechanism most readily exploited, not because shared memory is inherently a Spectre vulnerability [SPECTRE-SAB]. The historian correctly describes this distinction; other perspectives conflate mechanism and cause.

4. **The apologist characterizes the Workers model as "default to isolated threads with structured communication, opt into shared memory with explicit atomic coordination — this is sound."** The architecture is sound, but structured cloning costs are understated. Serializing a large in-memory object graph for worker communication is O(n) in object count and can be latency-significant for large datasets. Applications with large shared state requirements (in-memory databases, ML inference result caches, large lookup tables) face real overhead with the message-passing model. The comparison with the Erlang actor model is fair — Erlang also copies messages — but Erlang processes are designed from the start for message-passing patterns; JavaScript Workers are retrofitted onto a language whose standard patterns assume shared-memory object composition via closures and prototype chains.

5. **The apologist states there are "no JavaScript data races in single-threaded code."** True by definition for a single execution context. However, multi-Worker code using `SharedArrayBuffer` is capable of data races, which is why the `Atomics` API exists [TC39-SHARED-MEMORY]. The framing that data races are "structurally eliminated" is accurate only for single-threaded code; it is not an absolute property of the language.

**Additional context:**

- The event loop specification resides primarily in the WHATWG HTML Living Standard, not ECMA-262. ECMAScript specifies Promises and the microtask queue; the macrotask queue and event loop scheduling are host-environment concerns. This governance split means a JavaScript engine that doesn't run in a browser or Node.js host can implement event loop scheduling however it chooses. Language designers should note this as a precedent: separating core execution semantics (ECMA-262) from host-environment scheduling (WHATWG HTML) preserves implementation flexibility at the cost of specification completeness.
- Cloudflare Workers uses V8 isolates, not OS threads. A V8 isolate is a single-threaded JavaScript execution context with its own heap, running within a shared OS process alongside other isolates. This differs architecturally from Node.js `worker_threads`, which create separate OS threads each hosting a separate V8 isolate. The isolate model achieves sub-millisecond cold starts because it avoids OS process and thread creation overhead. The apologist correctly identifies this as a "deliberate architectural achievement" for the edge computing use case; what should be noted is that this is a V8/Cloudflare implementation choice, not a property the ECMAScript specification provides.
- JavaScript Promises always allocate heap objects; each `.then()` creates a Promise microtask object. This is not zero-cost at the runtime level even though async/await is "syntactic sugar." Rust's async is zero-cost in the sense that no heap allocation occurs for await points in the common case; JavaScript's async/await is zero-cost only in the ergonomic sense of eliminating callback nesting. The semantic equivalence is accurate; the performance equivalence is not.

---

### Section 9: Performance Characteristics

**Accurate claims:**
- V8's multi-tier pipeline (Ignition → Sparkplug → Maglev → TurboFan) is accurately described. Each tier is correctly characterized: Ignition produces bytecode, Sparkplug is a fast baseline compiler, Maglev is a mid-tier optimizer, TurboFan is the speculative optimizing compiler [V8-MAGLEV].
- TurboFan applies speculative optimization based on observed type feedback and deoptimizes when type assumptions are violated. Correct.
- Node.js cold start: 100–300ms depending on module graph size. Accurate per the research brief.
- TechEmpower Round 23 shows Node.js/Express at 5,000–15,000 RPS vs. 500,000+ for optimized Rust frameworks [BENCHMARKS-PILOT]. Accurate.
- JavaScript performs mid-range in the Benchmarks Game: slower than C, C++, Rust, Java; faster than Python and Ruby on comparable workloads [BENCHGAME-2025]. Accurate.
- Polymorphic code sees lower JIT performance than monomorphic code because TurboFan's type specialization cannot apply. Correct.
- Bun uses JavaScriptCore (JSC) and claims faster startup than Node.js. Accurate; JSC has a different JIT tier structure and startup profile than V8.

**Corrections needed:**

1. **The apologist claims Maglev means JavaScript performance is "no longer bimodal (fast after warmup, slow before) but more consistently good."** This overstates Maglev's impact. The warmup progression still exists: Ignition (interpreter/bytecode) runs first for all code; Sparkplug compiles hot functions without optimization; Maglev applies mid-tier optimization for frequently-called functions; TurboFan optimizes the hottest. For short-lived execution contexts — serverless handlers that execute once or twice per cold start, CLI tools, server startup paths — TurboFan may never trigger and Maglev may not either. Maglev reduces the severity of the performance valley between cold and optimized execution by inserting a cheaper mid-tier path, but does not eliminate the warmup curve [V8-MAGLEV]. The claim of "bimodal elimination" is not supported by the V8 team's own characterization, which describes Maglev as addressing the gap without claiming to close it.

2. **The detractor states that TurboFan optimization advice constitutes "V8-specific folklore" that is "not true for SpiderMonkey or JavaScriptCore."** This is partially correct but overstated. The underlying principle — avoid type instability in hot functions — applies across all modern JS JIT compilers, not only V8. What is V8-specific is the implementation: V8's hidden classes (called "shapes" in SpiderMonkey and "structures" in JSC), inline cache structure, deoptimization thresholds, and profiling feedback mechanics differ across engines. A developer writing type-stable objects is writing advice that benefits all JIT-compiled JavaScript engines; the V8-specific surface area is in granular micro-optimization (property initialization order, array hole avoidance) rather than in the core principle.

3. **The practitioner compares Node.js memory footprint to JVM: "50–150MB resident vs. JVM 300–500MB base overhead."** The JVM lower bound (300 MB) applies to typical Spring Boot applications with standard class libraries, which is a fair comparison for a deployed service. A minimal `java -jar` with a small dependency graph can start under 50 MB RSS. The directional comparison is valid for typical microservice deployments, but the specific numbers are configuration-dependent for both runtimes. More importantly, as noted in the memory model section, the 50–150 MB Node.js figure does not include native Buffer allocations, which are outside the V8 heap. I/O-intensive applications can have substantially higher RSS than this figure implies.

4. **The apologist notes "baseline Node.js HTTP without frameworks significantly faster than with Express" and "Fastify consistently outperforms Express by 3–5×."** This is correct and represents an important clarification of TechEmpower benchmark interpretation. The Fastify throughput comparison is sourced from Fastify's published benchmarks and is credible for isolated HTTP benchmarking. The implication — that Express-based TechEmpower numbers substantially understate the V8/Node.js runtime ceiling — is valid and should be noted. TechEmpower Express benchmarks measure one particular framework implementation, not the Node.js runtime's actual capacity.

5. **The research brief and all council perspectives note that no JavaScript-specific benchmark file exists in the evidence repository.** Performance claims across the council are drawn from indirect citations (the pilot-languages benchmark file, which focuses on PHP, C, Mojo, and COBOL) and external sources. This represents an evidence gap: the JavaScript performance discussion is less systematically grounded than the evidence repository provides for other pilot languages.

**Additional context:**

- **Ignition bytecode means all JavaScript incurs parse-and-compile cost.** Even "cold" code doesn't run in a tree-walking interpreter. All JavaScript is first lexed, parsed to an AST, and then compiled by Ignition to bytecode before any execution begins. The 100–300ms cold start figure includes this compilation time. For applications with large module graphs (many `import` statements), the parse-and-compile step dominates startup cost. This is why module bundling tools (esbuild, Rollup, Webpack) that produce fewer, larger files can significantly improve startup time by reducing the number of parse-and-compile passes.

- **V8 hidden classes (shapes/maps) are the mechanism enabling type-stable performance.** When a JavaScript object's property layout is consistent across its lifetime — properties added in the same order, same types — V8 tracks it with a hidden class (internal "Map" in V8 terminology). JIT-compiled code that accesses such objects can use fast property access via fixed offsets rather than hash table lookup. When property layout varies (polymorphic access sites), the hidden class transitions, inline caches go megamorphic, and performance degrades. This is an architectural mechanism that language designers should study: it allows a dynamically-typed language to approach AOT-compiled performance for type-stable patterns, at the cost of opaque implementation dependency.

- **The multi-tier JIT and GC interact in non-obvious ways.** TurboFan's speculative optimizations can influence GC pressure. Escape analysis in TurboFan attempts to allocate short-lived objects on the stack rather than the heap; when escape analysis succeeds, GC pressure decreases. When it fails — because the object's lifetime cannot be determined statically — heap allocation occurs and the GC must collect it. TurboFan's optimization quality directly affects allocation rate, which affects GC frequency. Diagnosing performance regressions that manifest as increased GC pressure often requires understanding TurboFan's escape analysis behavior, not just the application's allocation patterns.

- **Hermes as a design data point.** Meta's Hermes compiles JavaScript to bytecode AOT at build time, trading peak throughput for faster startup and lower memory. This is an explicit design choice for mobile React Native applications where cold start time is user-visible. Hermes demonstrates that "JIT compilation" is not a binary default — it is a point on a design spectrum. V8's progressive tiered compilation, Hermes's AOT bytecode, and Cloudflare Workers' V8 isolate pre-warming each represent different tradeoffs on the startup-latency/throughput spectrum. Language designers should consider deployment context diversity when specifying compilation model defaults.

---

### Other Sections (Compiler/Runtime Issues)

**Section 2: Type System — JIT cost of dynamic semantics**

The council correctly notes that dynamic typing forces the JIT to infer types at runtime. One dimension underrepresented across all perspectives: the `==` abstract equality operator's coercion algorithm is a JIT compilation challenge beyond a developer confusion problem. The `==` algorithm contains 11 conditional steps in the ECMAScript specification involving potential type coercion, object-to-primitive conversion, and recursive equality calls [ECMA-262-ABSTRACT-EQ]. JIT-compiling a call site that uses `==` conservatively must preserve all these branches or perform type analysis to eliminate them. Conversely, `===` is two type checks and a value comparison. The specification's backward compatibility commitment to `==` semantics means that every JavaScript JIT must compile this complexity permanently. This is a concrete example of how a specification-level mistake — one Eich acknowledges [EICH-INFOWORLD-2018] — imposes lasting costs on every runtime implementor.

**Section 6: Ecosystem — ESM vs. CommonJS and JIT impact**

The module system fragmentation has a compiler/runtime dimension that the council mentions but does not analyze. CommonJS `require()` is synchronous and can be called conditionally (inside `if` blocks, loops, or functions), making its dependency graph unknowable at parse time. ESM `import` is static and hoisted; the full dependency graph is determined before execution begins. This distinction matters for tree-shaking: bundlers performing dead-code elimination (Rollup, esbuild, Webpack in module mode) can eliminate unused exports only with ESM's static structure. CommonJS exports are assigned at runtime, making static elimination unsafe. Many Node.js applications remain on CommonJS, losing this optimization capability. The ongoing fragmentation has a real performance cost in bundle size for shipped applications, not just a developer ergonomics cost.

**Section 10: Interoperability — WebAssembly FFI boundary**

The council correctly describes WebAssembly's complementary role. One important compiler/runtime implication is underrepresented: the JavaScript↔WASM FFI boundary imposes per-call overhead that can dominate performance for tight integration patterns. Passing JavaScript values to WASM requires type coercion and validation; passing WASM linear memory references to JavaScript requires wrapping. For compute-intensive sections with few cross-boundary calls (matrix multiply, image encode), WASM delivers near-native performance and the overhead is negligible. For patterns involving many small cross-boundary calls (per-element callbacks, frequent JS object lookups from WASM), the overhead can eliminate the WASM performance benefit. The apologist's description of "JavaScript handles orchestration, WebAssembly handles computation" correctly identifies the optimal pattern; designers should understand why it is optimal (FFI cost), not just that it is.

---

## Implications for Language Design

**Dynamic typing forces the optimizer to solve a harder problem than static typing.**
V8's multi-tier JIT pipeline represents decades of work compensating for the absence of static type information in the ECMAScript specification. Hidden classes, inline caching, speculative optimization, and deoptimization all exist to recover information that statically-typed languages provide at parse time. A language designer who wants JIT-friendly dynamic typing must accept that the runtime optimizer must infer what the developer did not express. This creates three costs: warmup latency (the optimizer needs execution samples), deoptimization risk (sampling can be wrong), and specification opacity (optimal code must match the JIT's internal model). These costs can be reduced but not eliminated without providing type information in the source language.

**GC specification flexibility is a long-term investment, but it requires accepting opaque memory behavior.**
ECMAScript's approach — specify reachability semantics, say nothing about timing or algorithm — gave V8's engineering team the freedom to implement Orinoco without specification changes. A language that mandated a specific GC algorithm in its specification would have required specification revisions as GC technology advanced. The tradeoff is that application developers cannot reason about GC timing at the language level. A new language should decide whether GC observability (pause time bounds, collection triggers, finalization guarantees, allocation hooks) is a specification-level concern or an implementation concern. JavaScript's experience suggests that specification flexibility is worth preserving for collection algorithm; finalization timing opacity is the predictable cost.

**The event loop's I/O-bound adequacy does not generalize to CPU-bound workloads.**
JavaScript's single-threaded event loop is the correct concurrency model for its intended domain (interactive browser UI, I/O-bound network services). It provides the data-race elimination benefit of single-threaded execution and scales well for concurrent I/O. Its fundamental limitation — no preemption, no time-slicing within a synchronous hot path — is unavoidable for CPU-bound workloads within the model. A language designer building a general-purpose language should treat single-threaded event loop concurrency as one model among options rather than the default. Go's goroutine scheduler, Erlang's preemptive green threads, and Rust's async executor ecosystem each represent different points in the tradeoff space with different guarantees for CPU-bound code. JavaScript's history suggests that a single concurrency model will be applied beyond its appropriate domain if the language achieves wide enough adoption.

**JIT optimization surfaces invisible at the language level create expertise asymmetries.**
V8's hidden class mechanism, TurboFan's type feedback model, and inline cache polymorphism are not visible in ECMAScript. They are runtime-implementation details that substantially determine application performance. The result is that JavaScript performance optimization requires understanding V8 internals, not language semantics — and that V8-specific advice (monomorphic functions, consistent property initialization order, avoiding object shape changes) is "folklore" from the specification's perspective. A language designed for predictable performance should consider whether its key optimization mechanisms should be visible in the language model (as Rust's ownership is visible, enabling predictable zero-cost abstractions) rather than hidden in runtime internals that developers must reverse-engineer.

**AOT and JIT are points on a spectrum; deployment context should determine compilation model.**
JavaScript's ecosystem demonstrates multiple valid points on the AOT/JIT spectrum: V8's multi-tier JIT for peak throughput in long-running servers, Hermes's AOT bytecode for mobile startup time, V8 isolate pre-warming for edge cold-start latency. These are not competing philosophies but different responses to different deployment constraints. A new language should design its compilation model with explicit deployment context diversity in mind, providing a path to both fast startup (AOT or ahead-of-time bytecode) and peak throughput (JIT or profile-guided optimization) rather than committing to a single compilation strategy that optimizes for one context.

---

## References

[V8-MEMORY] "Understanding JavaScript's Memory Management: A Deep Dive into V8's Garbage Collection with Orinoco." Leapcell. https://leapcell.io/blog/understanding-javascript-s-memory-management-a-deep-dive-into-v8-s-garbage-collection-with-orinoco

[V8-MAGLEV] "Maglev - V8's Fastest Optimizing JIT." V8 Blog. https://v8.dev/blog/maglev

[BENCHMARKS-PILOT] "Performance Benchmark Reference: Pilot Languages." Internal evidence document. `evidence/benchmarks/pilot-languages.md`. February 2026.

[BENCHGAME-2025] The Computer Language Benchmarks Game. Updated August 1, 2025. https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html

[SPECTRE-SAB] Mozilla Developer Network. "SharedArrayBuffer: Security requirements." https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer#security_requirements

[BUGZILLA-SPM] "CVE-2019-9791: SpiderMonkey IonMonkey type inference is incorrect for constructors entered via on-stack replacement." Mozilla Bugzilla #1530958. https://bugzilla.mozilla.org/show_bug.cgi?id=1530958

[WHATWG-HTML] WHATWG HTML Living Standard. "Event loops." https://html.spec.whatwg.org/multipage/webappapis.html#event-loops

[TC39-SHARED-MEMORY] Guo, S., Hansen, L.T., Horwat, W. "ECMAScript Shared Memory and Atomics." TC39 Proposal (Stage 4). https://github.com/tc39/ecmascript_sharedmem/blob/master/TUTORIAL.md

[ECMA-WEAKREF] ECMAScript 2021 Specification. Sections 9.12–9.13: WeakRef and FinalizationRegistry. https://tc39.es/ecma262/2021/#sec-weak-ref-objects

[ECMA-262-ABSTRACT-EQ] ECMAScript 2025 Specification. Section 13.10.3: Abstract Equality Comparison. https://tc39.es/ecma262/#sec-abstract-equality-comparison

[EICH-INFOWORLD-2018] Eich, B., interviewed by Paul Krill. "Interview: Brendan Eich on JavaScript's blessing and curse." InfoWorld, August 17, 2018. https://www.infoworld.com/article/2256143/interview-brendan-eich-on-javascripts-blessing-and-curse.html

[HOPL-JS-2020] Wirfs-Brock, A. and Eich, B. (2020). "JavaScript: The First 20 Years." Proceedings of the ACM on Programming Languages, Vol. 4, HOPL. https://zenodo.org/records/4960086
