# TypeScript — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "TypeScript"
agent: "claude-agent"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

TypeScript's compiler/runtime profile is defined by a single architectural commitment — type erasure — and two of its downstream consequences: zero runtime overhead and an absolute discontinuity between compile-time guarantees and runtime reality. The council documents handle this distinction with varying degrees of precision. The practitioner and detractor perspectives correctly characterize the implications of type erasure for security and runtime validation. The apologist perspective, while broadly accurate, conflates language-level guarantees with tool-ecosystem capabilities in the concurrency section, and understates the performance overhead of specific TypeScript features (enums, decorators) that are not erased.

The most significant compiler/runtime story the council does not adequately synthesize is the architectural cause of the compiler's historically poor performance: the TypeScript compiler is self-hosted in TypeScript and runs on Node.js. Running a type checker — which uses deeply cyclic data structures for type inference — on a GC'd JavaScript VM produces an unavoidable performance ceiling. The community's response (splitting transpilation from type checking via esbuild and SWC) and Microsoft's architectural resolution (the Go-based native port for TypeScript 7) both confirm this ceiling was a structural problem, not an optimization gap. The historian captures this analysis most clearly; the other council members treat the slow compiler as a pain point without adequately explaining its root cause.

On concurrency, all five council members correctly identify that TypeScript inherits JavaScript's event loop model unchanged, but the apologist's treatment of `async` error prevention overstates what TypeScript itself enforces versus what requires external linting tooling. On memory, the council's treatment of V8's GC is mostly accurate but collapses important detail about V8's incremental and concurrent marking strategy (which significantly reduces pause behavior relative to the stop-the-world model the practitioner implies). A new language's designers reading this council should emerge with precise understanding of what "zero runtime overhead" means in practice, which requires the corrections and clarifications below.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**
- TypeScript inherits JavaScript's memory management entirely at runtime; all type information is erased [TS-DESIGN-GOALS; V8-GC]. This is stated consistently across all council members and is correct.
- `strictNullChecks` prevents null/undefined access at compile time only, providing no runtime enforcement. The practitioner and apologist both correctly state this limitation [TS-20-RELEASE].
- The `tsc` compiler for large projects (VS Code at 1.5M LOC) uses several hundred megabytes of memory and takes 77.8 seconds to compile [TS-NATIVE-PORT]. This is consistent across all council members and is sourced from Microsoft's own published benchmarks.
- The Go-based native compiler port (TypeScript 7) is measured at approximately 50% of the JavaScript-based `tsc`'s memory footprint [TS-NATIVE-PORT]. Accurately and consistently reported.
- `ts-node` RAM consumption of 600+ MB for small applications, reduced to ~170 MB with `--transpile-only`, is accurately cited [TSNODE-PERF].
- JavaScript's inherited memory safety guarantees (no manual malloc/free, no use-after-free, bounds-checked array access returning `undefined`) are correctly stated.

**Corrections needed:**

1. **V8 GC pause characterization is simplified to the point of inaccuracy.** The practitioner states: "the old generation mark-compact collection is slower and *pauses execution*" (emphasis added). This was true of V8's original garbage collector, but V8's Orinoco collector (the current implementation, documented in [V8-GC]) uses **incremental marking** for the old generation, combined with **concurrent marking** on background threads, and **parallel compaction**. Major GC pauses are significantly shorter than a full stop-the-world mark-compact would imply. The correct characterization is that old-generation collection uses a combination of concurrent background work and brief stop-the-world incremental steps. Long GC pauses are uncommon in properly sized V8 heaps but can occur under specific pressure conditions. Framing old-generation collection as simply "pausing execution" misleads readers comparing TypeScript's GC semantics to other languages' collectors.

2. **"Zero runtime overhead" is accurate for type annotations but not for all TypeScript features.** The apologist states the design goal "Impose no runtime overhead on emitted programs" is "fully achieved" [TS-DESIGN-GOALS]. This overstates the case:
   - **Regular `enum`** (not `const enum`): compiles to a JavaScript object that exists at runtime. A TypeScript `enum Color { Red, Green, Blue }` emits approximately six lines of JavaScript object construction code. This is runtime overhead absent in equivalent JavaScript using string unions.
   - **`const enum`**: fully inlined at compile time; zero runtime overhead. The distinction matters because `const enum` has cross-file limitations that lead many teams to use regular enums.
   - **Standard decorators** (TypeScript 5.0+, TC39 Stage 3): emit substantial runtime wrapper code for decorated classes and methods. This is significant overhead for decorator-heavy codebases.
   - **Async/await desugared to ES5 target**: TypeScript's emit for `async`/`await` when targeting ES5 generates a substantial state-machine (often using a helper like `__awaiter` and `__generator`), adding kilobytes of runtime code per async function. Targeting ES2017+ where `async`/`await` is native avoids this.
   The accurate claim is that **type annotations, interfaces, type aliases, and generics** impose zero runtime overhead. TypeScript features that produce runtime JavaScript constructs (enums, decorators, async-to-ES5 polyfill helpers) do have overhead. The council should distinguish these.

3. **`SharedArrayBuffer` introduces shared-memory semantics not reflected in memory model discussions.** The practitioner and others describe Worker threads as using "message-passing serialization" for memory safety, which is accurate for the default Worker model. However, `SharedArrayBuffer` allows true shared memory between the main thread and workers. TypeScript's type system does not distinguish between safe and unsafe SharedArrayBuffer operations — it does not enforce that shared memory accesses use `Atomics` for synchronization. A TypeScript developer using `SharedArrayBuffer` without `Atomics` can produce data races that the type system cannot detect. This represents a gap in the memory safety picture that no council member surfaces.

**Additional context:**
- The historian's analysis of the Go rewrite decision is technically sound and worth amplifying. The root cause of `tsc`'s memory pressure is specific: the TypeScript type checker uses **deeply cyclic data structures** for type inference (types reference other types bidirectionally through union, intersection, and conditional type resolution). Garbage collection handles cycles naturally; reference counting (as used by some languages) would fail or require cycle-detection overhead. This is why Rust was ruled out for the port — rewriting to satisfy Rust's ownership model for cyclic structures would require fundamental algorithmic changes, making it a rewrite rather than a port [TS-NATIVE-PORT; HEJLSBERG-DEVCLASS-2026]. The GC requirement for the compiler itself is an architectural fact with design implications.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**
- TypeScript inherits JavaScript's single-threaded event loop and async/await model without modification. All council members correctly state this. TypeScript adds static typing to the concurrency model but does not change its execution semantics.
- The "colored function" problem is correctly identified and cited [COLORING-PROBLEM]. The detractor's characterization is the most precise: TypeScript makes function colors **statically visible** through `Promise<T>` return types but does not resolve the structural divide.
- TypeScript has no structured concurrency primitives equivalent to Kotlin coroutines or Swift's `async let`. `Promise.all()`, `Promise.allSettled()`, and `Promise.race()` are correctly described as coordination primitives without automatic cancellation [MDN-EVENTLOOP].
- `Promise.all()` early-rejection behavior — remaining Promises continue executing with no cancellation mechanism — is accurately described by the practitioner.
- Worker threads (`worker_threads` in Node.js, `Worker` in browsers) provide genuine OS-level parallelism via message-passing isolation. TypeScript types are provided via `@types/node`. The isolation model eliminates data races on the main heap at the cost of serialization overhead. Accurate across council members.
- Unhandled Promise rejections as a source of silent failures is accurately documented. The change to crash-by-default in Node.js 15 is correctly noted by the practitioner.

**Corrections needed:**

1. **The apologist overstates TypeScript's enforcement of async error handling.** The apologist states: "Misuse of async functions — forgetting to `await` a Promise, for instance — is caught by TypeScript's strict checks and by the `@typescript-eslint` plugin." This conflates two distinct mechanisms. TypeScript's core language and all `--strict` mode flags do **not** prevent calling an async function without awaiting its result. A function returning `Promise<void>` can be called without `await` and TypeScript emits no error. The `@typescript-eslint/no-floating-promises` rule catches this — but it is a linting rule requiring separate `@typescript-eslint` configuration, not part of `tsc`'s type-checking pass. The detractor correctly identifies this distinction: "TypeScript's type system is structurally unable to prevent" unhandled async errors at the language level. The apologist's framing obscures the boundary between compiler enforcement and linting enforcement, which is precisely the kind of conflation a compiler/runtime review must flag.

2. **SharedArrayBuffer + Atomics gap in type safety.** All council members treating Worker thread parallelism correctly describe the message-passing model. None note that `SharedArrayBuffer` usage — which both the browser and Node.js Worker APIs support — creates genuine shared mutable state between threads. TypeScript's type system does not distinguish `SharedArrayBuffer` slices being accessed safely (via `Atomics`) from those accessed unsafely (raw reads and writes without synchronization). This is not merely an ergonomic issue: it is a correctness guarantee gap. Any claim that TypeScript's type system provides data-race freedom must be scoped to the message-passing Worker model and explicitly exclude SharedArrayBuffer patterns.

3. **Async/await desugaring to ES5 has concurrency implications.** When TypeScript targets ES5 or ES2015 and must downcompile `async`/`await` using a `__awaiter`/`__generator` helper, the generated code is a state machine with different scheduling properties than native `async`/`await`. The generated state machine uses Promise microtask scheduling in the same way as native async/await, so observable behavior is preserved — but the performance characteristics differ (state machine invocation overhead per `await` point). This is a minor but real compiler-to-runtime translation cost that no council member surfaces.

**Additional context:**
- The historian's framing that TypeScript 3.x "added better inference for async/await return types" is accurate. TypeScript's improvements to `Promise` return type inference in the 3.x and 4.x series substantially reduced the number of explicit annotations required in async code, which is a meaningful DX improvement even if the execution model didn't change.
- The `AbortController` API (browser-standard, available in Node.js 15+) is the primary mechanism for cooperative async cancellation in TypeScript. TypeScript types it correctly, but it requires threaded-through propagation through every async function that should respect cancellation. This ergonomic burden is a real gap relative to structured concurrency languages, and the council's treatment of it (primarily the practitioner) is accurate.

---

### Section 9: Performance Characteristics

**Accurate claims:**
- TypeScript imposes no runtime performance overhead for type annotations, which are erased before execution. For the scoped case (type annotations, interfaces, type aliases, generics), this is accurate.
- TechEmpower Round 23 benchmark data: Fastify at ~87,000 req/sec (plaintext), .NET 9 at ~27.5 million req/sec [TECHEMPOWER-R23]. These numbers are correctly cited and correctly contextualized as a framework benchmark, not a language-isolation benchmark.
- Compiled TypeScript application startup time of 50–150ms for typical Node.js applications is plausible and consistent with the known behavior of V8's startup model.
- `tsc` compilation times sourced from Microsoft's native port announcement: 77.8 seconds (JavaScript-based) vs. 7.5 seconds (Go-based) for VS Code; 1.1 seconds vs. 0.1 seconds for rxjs [TS-NATIVE-PORT]. These are first-party benchmark numbers and are consistently reported.
- esbuild ~45× faster than `tsc` for transpilation; SWC ~20× faster [ESBUILD-BLOG; SWC-DOCS]. Correctly cited.
- The build pipeline split (esbuild/SWC for transpilation, `tsc --noEmit` for type checking separately) as the dominant production practice is accurately described.
- Go-based native compiler providing ~10× compilation speedup, ~8× editor project load speedup, ~50% memory reduction [TS-NATIVE-PORT]. Consistently and accurately reported.

**Corrections needed:**

1. **"Zero runtime overhead" applied globally misrepresents TypeScript features with real runtime cost.** The apologist's performance section states "TypeScript's performance architecture is correct for its design goals: it imposes zero runtime overhead." This is imprecise in the same way as noted in Section 3. Regular enums, decorators, and async-to-ES5 downcompilation produce real emitted JavaScript code that has runtime cost. The correct and more useful statement is: "TypeScript's type annotations, interfaces, type aliases, and generic parameters are fully erased and impose zero runtime overhead. TypeScript features that produce JavaScript constructs — enums, decorators, and async/await downcompiled to ES5 — do produce emitted code with runtime overhead." The distinction matters for performance-sensitive contexts.

2. **Node.js startup comparison to Python is slightly misleading.** The apologist states TypeScript "does not suffer the multi-second startup times of JVM-based languages or the multi-hundred-millisecond startup of Python." The JVM comparison is accurate (cold JVM startup is typically 500ms–2+ seconds). The Python comparison exaggerates: CPython startup for a minimal script is typically 30–70ms, not "multi-hundred milliseconds." Python startup reaches hundreds of milliseconds only with heavy import loads (e.g., importing NumPy or a large web framework). Bare Node.js startup (with no dependencies) is also approximately 30–80ms. The comparison should be framed in terms of import-heavy applications, where both Node.js and Python accumulate startup time proportional to the dependency graph size.

3. **The research brief's Babel transpilation benchmark may not translate cleanly.** The brief cites [TRANSPILER-COMPARISON] reporting Babel at 2.26 seconds vs. tsc at 13.37 seconds for a 22,000-LOC, 135-file project. This benchmark is useful but the comparison is complicated: Babel's TypeScript transformation is type-strip-only (like esbuild and SWC), while tsc performs type checking. Comparing Babel to tsc on the same benchmark is comparing different work. The brief correctly states esbuild and SWC do no type checking; the Babel comparison should carry the same caveat more prominently than the council documents provide.

4. **V8's JIT capabilities are understated in the performance ceiling discussion.** The practitioner correctly notes that "TypeScript's CPU performance ceiling, inherited from V8, is lower than teams sometimes expect." However, no council member quantifies this ceiling. V8's TurboFan JIT compiler can achieve 50–80% of native compiled language speed for integer-heavy, hot-path code that JIT-compiles well. The practical performance ceiling for TypeScript/Node.js is not "interpreted code" speed — it is JIT-compiled code speed, which is considerably faster. The true ceiling for CPU-bound TypeScript is V8's JIT inlining and type feedback accuracy, which degrades with polymorphic call sites and objects with many property shapes. For I/O-bound workloads, this ceiling rarely matters.

**Additional context:**
- The historian's identification of the architectural root cause (self-hosted compiler running on a GC'd runtime with cyclic type structures) provides the most useful framing for language designers. This is a case study in **compiler implementation language affecting developer experience at scale**: a tool that is fast enough for small projects can become a serious bottleneck as project scale grows by orders of magnitude, and the language/runtime choice for the tool implementation becomes a long-term constraint.
- The Go port choice over Rust or C# (because the type checker's cyclic data structures fit GC semantics better than Rust's ownership model) is a concrete example of a real-world systems design decision. Language designers implementing type checkers should note: type inference algorithms that use cyclic type graphs benefit from GC runtimes.
- The separation of type checking from transpilation (which the ecosystem independently evolved before Microsoft addressed it at the compiler level) demonstrates a general pattern: when a language's primary tool becomes a bottleneck, the ecosystem will find workarounds that split the tool's responsibilities. This workaround (separate type-checking from code generation) was feasible because TypeScript's design keeps these phases logically independent — the generated JavaScript does not depend on type analysis results [TS-DESIGN-GOALS].

---

### Other Sections (Compiler/Runtime Flags)

**Section 2: Type System — `--strictFunctionTypes` scope is mischaracterized.**

The apologist states that `--strictFunctionTypes` (TypeScript 2.6) "fixed bivariant method parameters." This overstates the fix. `--strictFunctionTypes` applies stricter checking only to **function-type properties** (e.g., `prop: (x: T) => U`). It does **not** apply to **method shorthand signatures** in interfaces and classes (e.g., `method(x: T): U`). Method shorthand signatures remain bivariant even under `--strictFunctionTypes`. This is a documented TypeScript limitation: the TypeScript team chose to leave method declarations bivariant to avoid breaking existing class patterns that use covariant overrides [TS-DESIGN-GOALS]. A language designer must understand this scope: TypeScript's "strictFunctionTypes fix" closes bivariance for function-typed values but not for method declarations, which remain a source of unsoundness.

**Section 6: Ecosystem — The type-checking/transpilation split is a design consequence, not an ecosystem accident.**

Multiple council members describe the build pipeline split (esbuild/SWC for fast transpilation, `tsc --noEmit` for type checking) as either an ecosystem adaptation (practitioner, historian) or a current pain point being resolved (apologist). From a compiler design perspective, this split was possible precisely because TypeScript's design mandates that code emission must not depend on type analysis results ("Do not emit different code based on the results of the type system" [TS-DESIGN-GOALS]). This design non-goal is what made type-strip-only transpilers feasible — because TypeScript type annotations are syntactically distinct additions that can be stripped without semantic understanding. A language that emits different code based on types (C++ templates, Zig's comptime, Rust generics that monomorphize) cannot be split this way. The council does not surface this connection between TypeScript's design goals and the feasibility of its ecosystem workaround.

**Section 1: Identity — "Compile-time type checking" is the accurate framing for the Detractor's "false sense of security" claim.**

The detractor raises an important point: TypeScript's syntax looks like a runtime safety guarantee at the call site but is not. From a compiler/runtime perspective, this is technically accurate and important. A TypeScript type annotation like `const user: User = response.data` tells `tsc` to type-check the right-hand side against `User`'s structure at compile time. It does not emit any runtime validation. The detractor's framing that this creates "false confidence" has specific compiler/runtime content: developers who don't understand type erasure may believe that the TypeScript type annotation is doing work at runtime when it has been compiled away. This is a direct consequence of TypeScript's explicit non-goal: "Add or rely on run-time type information in programs" [TS-DESIGN-GOALS].

---

## Implications for Language Design

TypeScript's compiler/runtime tradeoffs yield several lessons for language designers:

**1. Type erasure enables adoption but creates permanent runtime gaps.**
Erasing types at compile time eliminates runtime overhead and enables seamless interop with the host ecosystem, but it produces an absolute discontinuity between compile-time guarantees and runtime reality. Any new language adopting this pattern must make runtime validation at trust boundaries a first-class design concern — either through mandatory runtime validation primitives, generated validation code from schema definitions, or a hybrid model that allows selectively-retained type information. TypeScript's ecosystem response (Zod, io-ts, Joi as optional external libraries) is functional but requires each team to independently discover and adopt the need. A language that erases types should explicitly design for the "what happens at the boundary" problem.

**2. The self-hosted compiler trap: implementation language constrains tool performance at scale.**
TypeScript's decade-long compiler performance problem and its eventual 10x improvement via a Go rewrite demonstrate that a language's compiler implementation language is a long-term architectural constraint. A type checker that performs well on 10,000-line codebases may become a serious bottleneck on million-line codebases — and the fix may require abandoning the original implementation language entirely. New languages building type checkers with cyclic type graph semantics should consider whether a GC'd systems language (Go, C#) is a better initial choice than a self-hosted implementation for the compiler toolchain.

**3. "Zero overhead" claims must be scoped precisely.**
TypeScript's design goal of "no runtime overhead" applies to type annotations but not to all TypeScript features. Regular enums, decorators, and backward-compatible async/await desugaring all produce runtime code. A new language should define clearly which features are erased at compile time and which produce runtime artifacts, and communicate this boundary clearly in design documentation. The failure to make this distinction clearly in TypeScript's documentation has led to genuine misunderstanding among practitioners about where TypeScript overhead lives.

**4. Escape-hatch visibility should be proportional to safety impact.**
TypeScript's unsoundness escape hatches (`as`, `!`) are syntactically lightweight and blend into normal code. The detractor correctly identifies this as a design failure relative to Rust's `unsafe` blocks, which are visually distinctive and auditable. A language that includes escape hatches from safety guarantees should make those escape hatches visually salient — either through syntax, tooling enforcement, or required justification annotations. The escape hatch that is easy to write proliferates; the one that requires visible declaration is used sparingly.

**5. Concurrency safety guarantees must be precisely scoped to the execution model.**
TypeScript's Worker thread model (message-passing isolation) provides data-race freedom for the main-thread heap. `SharedArrayBuffer` breaks this guarantee and the type system cannot detect it. A language claiming concurrency safety guarantees must precisely scope those guarantees to the actual execution model — including specifying which APIs or patterns are outside the guarantee boundary. Leaving this implicit, as TypeScript's documentation does for SharedArrayBuffer, misleads practitioners about the actual safety envelope.

**6. Strict defaults and gradual adoption are in genuine tension.**
TypeScript's `--strict` mode was opt-in for twelve years. This maximized adoption by minimizing migration friction for existing codebases, but it created a bifurcated ecosystem where the "correct" configuration was not the default. TypeScript 6.0's decision to make strict mode the default represents a governance maturation — the correct long-term default at the cost of requiring configuration changes for migrating pre-6.0 projects. New languages should default to the safest reasonable configuration from the first stable release; retroactively hardening defaults is possible but costly.

---

## References

[TS-DESIGN-GOALS] "TypeScript Design Goals." GitHub Wiki, microsoft/TypeScript. https://github.com/Microsoft/TypeScript/wiki/TypeScript-Design-Goals

[V8-GC] "Trash Talk: the Orinoco Garbage Collector." V8 Blog, 2019. https://v8.dev/blog/trash-talk

[TS-NATIVE-PORT] "A 10x Faster TypeScript." TypeScript DevBlog (native port announcement). https://devblogs.microsoft.com/typescript/typescript-native-port/

[TSNODE-PERF] "ts-node RAM Consumption." Medium/Aspecto, 2022. https://medium.com/aspecto/ts-node-ram-consumption-12c257e09e13

[TS-20-RELEASE] "TypeScript: Documentation — TypeScript 2.0." typescriptlang.org. https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-0.html

[TS-30-RELEASE] "TypeScript: Documentation — TypeScript 3.0." typescriptlang.org. https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-0.html

[TS-40-RELEASE] "Announcing TypeScript 4.0." TypeScript DevBlog, August 2020. https://devblogs.microsoft.com/typescript/announcing-typescript-4-0/

[TS-44-RELEASE] "Announcing TypeScript 4.4." TypeScript DevBlog, August 2021. https://devblogs.microsoft.com/typescript/announcing-typescript-4-4/

[TS-50-RELEASE] "Announcing TypeScript 5.0." TypeScript DevBlog, March 2023. https://devblogs.microsoft.com/typescript/announcing-typescript-5-0/

[TS-60-BETA] "Announcing TypeScript 6.0 Beta." TypeScript DevBlog, February 2026. https://devblogs.microsoft.com/typescript/announcing-typescript-6-0-beta/

[COLORING-PROBLEM] "What Color is Your Function?" Bob Nystrom, 2015. https://journal.stuffwithstuff.com/2015/02/01/what-color-is-your-function/

[MDN-EVENTLOOP] "The event loop." MDN Web Docs, Mozilla. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Event_loop

[TECHEMPOWER-R23] "Framework Benchmarks Round 23." TechEmpower Blog, March 2025. https://www.techempower.com/blog/2025/03/17/framework-benchmarks-round-23/

[ESBUILD-BLOG] "esbuild FAQ: TypeScript." esbuild documentation. https://esbuild.github.io/faq/

[SWC-DOCS] "SWC: Speedy Web Compiler." swc.rs. https://swc.rs/

[TRANSPILER-COMPARISON] "Navigating TypeScript Transpilers: A Guide to tsc, esbuild, and SWC." Leapcell Blog, 2025. https://leapcell.io/blog/navigating-typescript-transpilers-a-guide-to-tsc-esbuild-and-swc

[EFFECTIVE-TS-UNSOUND] Vanderkam, D. "The Seven Sources of Unsoundness in TypeScript." effectivetypescript.com, May 2021. https://effectivetypescript.com/2021/05/06/unsoundness/

[GEIRHOS-2022] Geirhos et al. "To Type or Not to Type? A Systematic Comparison of the Software Quality of JavaScript and TypeScript Applications on GitHub." Proceedings of ICSE 2022. https://www.researchgate.net/publication/359389871

[SNYK-TS-SECURITY] "Is TypeScript all we need for application security?" Snyk, 2024. https://snyk.io/articles/is-typescript-all-we-need-for-application-security/

[HEJLSBERG-DEVCLASS-2026] Hejlsberg interview on Go port rationale, DevClass, 2026. (Referenced in historian council document as [HEJLSBERG-DEVCLASS-2026])

[THENEWSTACK-GO-CHOICE] "Why TypeScript chose Go for its native compiler port." The New Stack, 2025. (Referenced in historian council document as [THENEWSTACK-GO-CHOICE])

[TS-ISSUE-9825] "TypeScript GitHub Issue #9825: Proposal: soundness opt-in flag." microsoft/TypeScript. https://github.com/microsoft/TypeScript/issues/9825

[OWASP-TS] "Prototype Pollution Prevention Cheat Sheet." OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

[NODEJS-TS] "TypeScript Module." Node.js Documentation. https://nodejs.org/api/typescript.html

[TC39-TYPES] "Type Annotations Proposal." TC39 Proposals. https://github.com/tc39/proposal-type-annotations
