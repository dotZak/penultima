# Ruby — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "Ruby"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

The Ruby council perspectives are generally technically accurate on compiler and runtime mechanics, but several claims require precision or calibration. The most consequential issue is how YJIT's "92% faster than interpreter" benchmark is handled: the apologist deploys this as a standalone argument, which obscures the actual baseline. The detractor's correction — that a 2× speedup over the interpreter leaves a substantial gap to compiled languages — is the more technically complete framing. The realist and practitioner contextualize the figure appropriately by citing real-world production improvement rates (15–25% for typical Rails applications) as the more operationally meaningful metric.

On concurrency and the GVL, all five council members describe the mechanism accurately: one thread executes Ruby bytecode at a time; the GVL is released during blocking I/O and certain C extension calls; Ractors provide per-domain GVL isolation but remain production-immature due to C extension compatibility; the M:N thread scheduler (Ruby 3.3) is disabled on the main Ractor by default, again due to C extension compatibility. The council correctly identifies this as a self-reinforcing constraint, though the underlying technical reason — that C extensions receive direct RVALUE pointers without synchronization guarantees — deserves sharper articulation.

On memory, the council's treatment of the RVALUE 40-byte overhead is accurate, and the GC evolution timeline is correctly described. However, the distinction between Ruby's incremental GC and a fully concurrent GC is underspecified across all perspectives; this matters for production reasoning about pause behavior under load. The YJIT memory overhead story also deserves clarification: YJIT 3.4 is more memory-efficient than YJIT 3.3, but it still requires more memory than the unaugmented interpreter; "memory-efficient" in the Shopify engineering post is a relative claim, not an absolute one.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **40-byte RVALUE per object** is correctly cited across all perspectives (historian, realist, practitioner, detractor, apologist). This is a structural consequence of the uniform object model: CRuby represents every value in a single `RVALUE` union type, whose size is determined by the largest member. The overhead is unavoidable without changing the fundamental object representation [RUBY-GC; historian §3].

- **GC evolution timeline** — mark-and-sweep → generational (2.1) → incremental (2.2) → modular (3.4) — is correctly stated by the apologist and historian. The generational collector introduced the write barrier machinery necessary for later improvements.

- **Symbol GC** introduced in Ruby 2.2 is correctly identified by the historian as closing a 19-year-old memory leak vector where dynamically-created symbols could never be collected. This is also a security-relevant fix: before 2.2, an attacker who could cause arbitrary symbol creation could drive unbounded memory growth.

- **Modular GC framework (Ruby 3.4)** is correctly described as enabling pluggable GC implementations via the `RUBY_GC_LIBRARY` environment variable. This is a meaningful architectural investment, though the historian's observation that "the modular GC introduced in Ruby 3.4 is the most honest recent acknowledgment of these problems" [detractor §3] accurately captures that production Ruby GC behavior is workload-dependent enough to require external configurability.

- **C extension memory opacity** — that C extensions can allocate memory outside the Ruby heap that the GC does not track — is flagged in the research brief and touched on by the practitioner and detractor. This is accurate and important: native extensions are responsible for registering external allocations with `rb_gc_adjust_memory_usage()` or equivalent, and failure to do so causes CRuby's GC heuristics to underestimate live memory, leading to under-collection. This is a real source of memory bloat in production Rails applications using C-extension gems.

**Corrections needed:**

- **"Incremental GC reduces maximum pause time"** — Multiple council members use "incremental" in ways that could be confused with "concurrent." Ruby's incremental GC (2.2) does *not* run GC work concurrently with application threads. Instead, it breaks the mark phase into smaller incremental steps, interleaved with program execution across multiple GC entry points. The result is reduced *maximum* pause time (large pauses become multiple small pauses) but not elimination of all pauses. This is categorically different from Go's concurrent GC, which runs the mark phase concurrently with application goroutines on separate OS threads. The distinction matters for production reasoning: under sufficient allocation pressure, Ruby's incremental GC will still produce pauses proportional to heap size; it just distributes them. The apologist's framing of "reducing maximum pause time" is technically correct but could leave the reader thinking Ruby's GC is fully concurrent when it is not.

- **GC.compact** is absent from all council perspectives. Ruby 3.0 added heap compaction via `GC.compact` (and subsequently `GC::Profiler`, automatic compaction options). Compaction is relevant because CRuby's GC is traditionally non-moving — objects stay at their allocated addresses for their lifetimes, which means that as objects are freed, the heap fragments, increasing memory overhead relative to live object count. `GC.compact` moves live objects together and updates references, reducing RSS. For memory-sensitive deployments (containerized environments with memory limits), compaction can reduce baseline memory usage by 20–40% in practice. This is a significant operational tool that the council omits entirely.

- **YJIT memory overhead** — The apologist notes that "Memory usage actually *lower* than YJIT 3.3 despite compiling more code" [apologist §9], which is accurate as a comparison between YJIT 3.3 and YJIT 3.4. However, the research brief notes that Ruby 3.3 YJIT adds ~21% memory overhead relative to the interpreter [RAILSATSCALE-YJIT-3-4]. YJIT stores compiled native code, metadata about compiled YARV blocks, and invalidation information; this overhead is real and should be factored into memory budget planning for YJIT-enabled deployments. Claiming YJIT is "memory-efficient" requires the baseline to be specified.

**Additional context:**

- **Write barriers and the generational GC**: The generational GC (2.1) required introducing write barriers throughout CRuby's C implementation to track object graph mutations (old-generation objects referencing new-generation objects). This is relevant to C extension authors: C extensions that manipulate Ruby objects must use write barrier APIs (`RB_OBJ_WRITE`, `RB_OBJ_WRITTEN`) or they will create invisible cross-generation references that defeat generational collection assumptions, potentially causing objects to be incorrectly freed. This is a source of subtle memory-safety bugs in C extensions and illustrates how GC evolution imposes correctness obligations on extension code.

- **Frozen string literal pragma**: The `# frozen_string_literal: true` file pragma instructs the interpreter to intern all string literals in a file as frozen, immutable objects. This reduces object allocation for frequently-used string literals and reduces GC pressure. It is a compile-time optimization available since Ruby 2.3. All council members omit it, though it is a meaningful tool for production Ruby performance tuning.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **GVL behavioral description** is correct across all five council perspectives: only one Ruby thread executes bytecode at a time; the GVL is released during blocking I/O operations, sleep, and certain C extension calls [GVL-SPEEDSHOP]. This is the foundational fact from which all downstream conclusions follow.

- **Green threads (1.8) → POSIX threads with GVL (1.9 YARV)** is correctly described by the historian. The historian's articulation of the GVL's origin — modeled on CPython's GIL, designed by Koichi Sasada as part of YARV — is accurate and important historical context. The GVL was a deliberate simplification, not an accident.

- **Ractor isolation model** is correctly described: each Ractor runs in its own GVL domain, enabling true CPU parallelism; communication is restricted to message-passing of frozen or transferred objects; mutable shared state is prohibited. All council members correctly state that Ractors are not production-ready as of 2026 [DEVCLASS-RUBY-4].

- **Ractor API instability** — The detractor's observation that `Ractor.yield`/`Ractor#take` were removed in Ruby 4.0 in favor of `Ractor::Port` [RUBY-4-0-RELEASE] is accurate and is a concrete signal of design immaturity. An API breaking change to a feature that has been available for five years is a reliable indicator that the feature has not stabilized. The practitioner and realist mention this; the apologist frames it as "design-in-progress" which is technically not wrong but underweights the stabilization failure.

- **M:N thread scheduler (Ruby 3.3)** is correctly described by the detractor: it maps M Ruby threads to N native OS threads, reducing OS thread creation overhead. The detractor's observation that it is disabled on the main Ractor by default due to C extension compatibility concerns is accurate [RUBY-3-3-RELEASE]. The M:N scheduler reduces context switching overhead and allows higher thread counts without exhausting OS thread descriptors, but it does not change the GVL's fundamental constraint on CPU-bound Ruby code.

- **Fiber Scheduler (Ruby 3.0)** as a non-parallel concurrency mechanism is correctly described. The practitioner's observation that the `async` gem can make I/O-bound fiber switching transparent is accurate, and the caveat that every library in the call stack must be fiber-aware for the scheduler to function is also correct. Fiber scheduling is cooperative and does not preempt blocking calls in libraries that are not fiber-compatible.

- **Jean Boussier's GVL analysis** is cited accurately by multiple council members: per-object locking or atomic reference counting would be required throughout the C runtime; C extensions would require pervasive refactoring; the ecosystem cost is prohibitive in the near term [BYROOT-GVL-2025].

**Corrections needed:**

- **GVL release scope** is slightly underspecified. The GVL is released not only during POSIX blocking I/O but also during any C extension operation that explicitly calls `rb_thread_call_without_gvl()` or equivalent. This matters in practice: the OpenSSL extension releases the GVL during cryptographic operations; many database adapter gems release it during query execution. Real-world Ruby applications thus achieve more parallelism than naive analysis suggests, because the expensive C operations release the GVL while running. Council members imply "blocking I/O" but the actual mechanism is broader.

- **C extension coupling as root cause** — The detractor frames C extension compatibility as "a constraint" but the connection is worth making more explicit: the *reason* every concurrency improvement (M:N scheduler, Ractors, and hypothetical GVL removal) is blocked by C extension compatibility is structural. CRuby's C extension API gives extensions direct access to `RVALUE` pointers into the Ruby object heap. This means:
  1. Extensions assume the GVL protects their heap access — they can walk the heap without locks.
  2. Extensions that store `VALUE` (pointer-sized Ruby object references) in C structs are invalidated by heap compaction.
  3. Extensions that create Ruby objects in background threads without the GVL corrupt the heap.

  Any runtime change that alters these assumptions requires auditing and updating every C extension. The ecosystem scale — hundreds of gems with millions of downloads — makes this a de facto veto on radical runtime evolution. This is correctly intuited by the detractor but not stated as precisely as the mechanism deserves.

- **Ractors and the actor model** — The historian identifies that Ractors implement the actor model (Hewitt 1973, Erlang 1986, Elixir 2011). This is accurate and worth the emphasis. The historian's observation that "Ruby arrived at actors forty-seven years after Hewitt described them" is pointed but not unfair. What the historian underweights is that the challenge is not recognizing the model but implementing it on top of a runtime that was never designed for it. Erlang was designed as an actor system from the ground up; Elixir runs on the BEAM, an actor-native VM. CRuby must retrofit actor isolation onto a heap model that assumes shared mutability. This is a substantially harder engineering problem, which explains the five-year stabilization delay.

**Additional context:**

- **Fiber vs. Thread memory overhead** — Fibers in Ruby use significantly less memory than threads: a Ruby Thread allocates a 1MB default stack (configurable) while a Fiber defaults to 4KB (expandable). For I/O-bound concurrency where thousands of concurrent operations are needed, Fiber-based concurrency is substantially more memory-efficient than Thread-based concurrency. The `async` gem leverages this for high-concurrency I/O workloads. This is the core argument for the Fiber scheduler as a pragmatic solution for the I/O-bound use case that comprises Ruby's primary deployment domain.

- **JRuby's parallelism model** — JRuby achieves true thread parallelism by relying on the JVM's thread scheduling and the JVM's own GC, which is designed for concurrent multi-threaded access. JRuby maps Ruby threads to JVM threads; there is no GVL. The trade-off is JVM startup overhead (~1–3 seconds for JVM initialization before Rails even loads), JVM memory overhead (JVM itself requires ~50–200MB base), and compatibility gaps with C extension gems (JRuby re-implements the CRuby C API on the JVM, which works for many but not all gems). The realist correctly notes JRuby and TruffleRuby as "not drop-in replacements for all workloads." [realist §4]

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **YJIT production validation** — The Shopify Black Friday 2024 metrics (80 million requests per minute, $11.5 billion in BFCM sales, prerelease YJIT 3.4) are accurate and cited from a primary source [RAILSATSCALE-YJIT-3-4]. This is the strongest evidence available for YJIT's production impact and all council members handle it appropriately.

- **Real-world improvement rates** — The practitioner and realist correctly cite 15–25% real-world improvement for typical Rails applications and higher for CPU-intensive workloads [UPDOWN-RUBY-3-3; RAILSATSCALE-YJIT-3-4]. This is the operationally meaningful number, not the 92% headline.

- **ZJIT is not production-ready** — All council members accurately characterize ZJIT as experimental in Ruby 4.0 [DEVCLASS-RUBY-4]. The practitioner's observation that the "experimental label, years to stabilization" pattern has repeated with YJIT and now ZJIT is fair and accurate.

- **Startup time** — The cited figures (50–150ms without Rails; 1–10 seconds for Rails) are accurate and match the research brief [RUBY-RESEARCH-BRIEF]. The detractor's observation that these figures make Rails "largely absent from the serverless ecosystem" is correct: AWS Lambda and similar platforms impose cold-start constraints that Rails cannot meet without pre-warming strategies.

- **TruffleRuby performance** — The realist's claim that "TruffleRuby on GraalVM achieves peak performance that often exceeds CRuby with YJIT" is accurate for steady-state throughput after warmup [TRUFFLERUBY-CEXT]. The practitioner correctly notes the warmup caveat.

- **YJIT architecture**: Block-based JIT that compiles hot YARV bytecode sequences to native machine code. The C method inlining rates cited for YJIT 3.4 (56.3% on lobsters, 82.5% on liquid-render) [RAILSATSCALE-YJIT-3-4] are accurate and explain a significant part of YJIT's performance gains: inlining C method calls eliminates the overhead of the C call convention and enables further optimization across the inlined code.

**Corrections needed:**

- **YJIT "92% faster" framing** — The apologist states: "92% faster than the interpreter on x86-64 headline benchmarks" without qualification. The detractor correctly identifies the misleading nature of this: a 92% improvement over baseline means YJIT runs at approximately 1.92× the interpreter's speed. If the interpreter baseline is already 20–40× slower than C for a given benchmark, YJIT reaches approximately 10–20× slower than C. The gap has narrowed; it has not closed. Language designers comparing Ruby's performance trajectory to compiled languages should use the real-world production figures (15–25% improvement for typical workloads) as the primary data point, not the synthetic headline number. The research brief correctly presents all figures; the apologist selectively emphasizes the most favorable presentation.

  Additionally, "92% faster than the interpreter" requires specifying which interpreter configuration. YJIT 3.4's benchmarks are run against CRuby 3.4 without YJIT. The comparison baseline matters because interpreter performance has also improved across the 3.x series; a 92% improvement on 3.4's interpreter represents different absolute performance than a 92% improvement on 3.1's interpreter would.

- **YJIT warmup behavior and startup time** — Multiple council members correctly note that YJIT does not improve startup time, and the practitioner correctly states "YJIT warmup begins after startup." However, the technical mechanism is worth making explicit: YJIT operates by compiling YARV bytecode blocks that have been observed executing (profiling-guided JIT). During the first several requests after startup, YJIT is observing and compiling; peak performance is only achieved after sufficient warmup. For short-lived processes, YJIT may provide no benefit at all. For long-lived server processes, YJIT benefits are substantial. This warmup characteristic is an important constraint for CLI tools and ephemeral scripts, and explains why YJIT's measured production improvement (15–25%) is lower than its benchmark headline (92%): production workloads include warmup time and varied code paths that may not achieve full JIT coverage.

- **ZJIT design architecture** — The council members correctly identify ZJIT as "method-based" vs. YJIT's "block-based" approach, with ZJIT using an SSA (Static Single Assignment) intermediate representation [DEVCLASS-RUBY-4]. The significance of this distinction is underexplained. SSA form enables classical compiler optimizations (constant propagation, dead code elimination, common subexpression elimination) that are difficult or impossible to apply to basic block sequences. YJIT's block-based approach allows fast partial compilation but has limited optimization scope per compilation unit. ZJIT's method-level compilation with SSA should enable more aggressive optimization of hot method bodies, at the cost of longer warmup (methods must be fully analyzed before any part can be compiled) and higher JIT compilation overhead. This is a meaningful architectural difference that explains why ZJIT is expected to eventually outperform YJIT but requires more development to achieve production stability.

- **TruffleRuby warmup penalty** — The realist correctly notes that TruffleRuby "peak performance often exceeds CRuby with YJIT, at the cost of longer JIT warmup" [realist §9], but the magnitude deserves clarification. TruffleRuby warmup is measured in minutes of execution for some workloads, because GraalVM's partial evaluation and speculative optimization pipeline is more aggressive than YJIT's block compilation. For short-lived processes or latency-sensitive request handlers, TruffleRuby can be *slower* than CRuby with YJIT until full warmup is reached. The production deployments where TruffleRuby shines are long-lived, throughput-sensitive services — exactly the opposite profile from the serverless or batch-processing scenarios where startup time is paramount.

**Additional context:**

- **Compilation pipeline summary** — For language design reference, Ruby's current pipeline is:
  1. Source code parsed by Prism (portable, error-tolerant recursive descent parser, default since Ruby 3.4, shared with JRuby, TruffleRuby, RuboCop)
  2. Prism AST compiled to YARV bytecode
  3. YARV interprets bytecode (baseline execution path)
  4. YJIT observes hot basic blocks and compiles to native x86-64/ARM64 (production-ready since Ruby 3.2, enabled by default since 3.2)
  5. ZJIT (Ruby 4.0 experimental): compiles hot methods to SSA IR then to native code, enabling more aggressive optimization

  This pipeline is well-engineered for incremental JIT compilation. The Prism parser's cross-implementation sharing is an underappreciated quality improvement: it reduces parsing divergences between CRuby, JRuby, and TruffleRuby, which historically produced subtle incompatibilities in parsing of edge-case syntax.

- **Inline caching** — YJIT's most impactful optimization is not simply compiling bytecode to native instructions but eliminating the overhead of Ruby's dynamic dispatch. Ruby method calls require a method lookup at runtime (checking the receiver's class, walking the method resolution order, possibly invoking method_missing). YJIT installs inline caches for method dispatch: after the first call observes the receiver's class, YJIT compiles a guard check (is the receiver's class still X?) followed by a direct call to X's implementation of the method. This turns O(n) method lookups into O(1) guarded direct calls for the common case. The C method inlining rates cited in YJIT 3.4 benchmarks reflect this mechanism working at its best.

- **Memory model for concurrent GC** — Ruby does not have a concurrent GC. The comparison to languages that do (Go's tri-color concurrent mark-and-sweep, Java's G1/ZGC) is relevant for language designers: Ruby's incremental GC reduces maximum pause duration by breaking GC work into smaller increments, but it does not eliminate pauses or run concurrently with application code. The modular GC framework in Ruby 3.4 opens the door to plugging in a concurrent GC implementation, but no production concurrent GC is available for Ruby as of early 2026. This is a genuine gap compared to Go and Java for latency-sensitive server workloads.

---

### Other Sections (Compiler/Runtime-Relevant Issues)

**Section 2: Type System — Impact on JIT Optimization**

All council members discuss the type system purely from a correctness and developer experience perspective. From a JIT optimization perspective, dynamic typing is the principal challenge YJIT must overcome. Ruby method dispatch is polymorphic by default: a method call `obj.foo` might dispatch to any class that implements `foo`. YJIT addresses this with type specialization: it observes the actual class of `obj` at runtime and compiles a class guard plus a specialized direct call. This works well when callsites are monomorphic (one receiver class) or polymorphic with a small number of classes, but degrades for megamorphic callsites (many receiver classes), which cannot be effectively specialized. The council's discussion of RBS and static typing does not address this optimization angle, but language designers should note that static type information at compile time would enable direct call resolution without runtime guards, which is a significant potential optimization opportunity.

**Section 10: Interoperability — C Extension API as Runtime Constraint**

The detractor's Section 10 is the most technically precise of the council perspectives on this topic: "C extension compatibility as a perpetual constraint" [detractor §10]. The specific mechanism deserves amplification. The CRuby C extension API (defined in `ruby.h`) exposes:
- Direct `VALUE` (a C `unsigned long`) holding either an immediate value (small integer, symbol, true, false, nil) or a pointer to an RVALUE on the Ruby heap
- Macros and functions for accessing RVALUE fields directly (`RSTRING_PTR`, `RARRAY_PTR`, etc.)
- Lock acquisition/release via `rb_thread_call_without_gvl()`

Extensions compiled against this API are tightly coupled to CRuby's object representation. Any change to how objects are laid out in memory, how the GVL works, or how the heap is structured will break such extensions. JRuby and TruffleRuby have partially addressed this by implementing the C API as a compatibility layer, but this adds indirection and is not complete for all extensions. The C extension API is CRuby's most significant backward compatibility constraint and the primary reason the runtime cannot evolve aggressively.

**Section 6: Ecosystem — Prism Parser as Compiler Infrastructure Success**

The realist's mention of Prism parser adoption is worth amplifying from a compiler infrastructure perspective. Prism is an error-tolerant recursive descent parser designed for portability — it is a pure C library with no Ruby runtime dependency, usable by CRuby, JRuby, TruffleRuby, and tooling without modification. Its error recovery capabilities mean IDEs can parse syntactically incomplete Ruby code (during editing) and still produce a useful AST. The decision to make Prism the shared cross-implementation parser reduces parsing divergences that had historically caused subtle compatibility bugs. This is a high-leverage compiler infrastructure investment that benefits the entire ecosystem simultaneously — language designers maintaining multiple implementations should note the payoff from shared parser infrastructure.

---

## Implications for Language Design

**1. Legacy C extension APIs are the most durable constraint on runtime evolution.** CRuby's C extension API exposes internal object representation and heap management conventions as a stable ABI surface. Once this API is in wide use, every subsequent runtime innovation — new GC algorithms, new concurrency models, new object layouts — must either maintain backward compatibility with the API or require ecosystem-wide updates. The cost of the latter is prohibitive when hundreds of gems are involved. Language designers creating extension APIs should treat those APIs as durable contracts and design them to minimize exposure of internal representation details. Abstract APIs that hide implementation details (like Python's stable ABI, or JNI's object handle model) preserve more runtime evolution freedom than APIs that expose raw memory pointers.

**2. Incremental GC and concurrent GC solve different problems; conflating them misleads.** Incremental GC distributes pause time across many small increments, reducing maximum pause but not eliminating pauses. Concurrent GC runs mark phases alongside application code, approaching zero-pause at throughput cost. Ruby has incremental; Go and Java have concurrent. For language designers targeting latency-sensitive server workloads, the design question is whether to target incremental (simpler implementation, pause distribution) or concurrent (higher engineering cost, lower latency ceiling). Ruby's modular GC framework is an acknowledgment that the right answer is workload-dependent, and pluggability is the appropriate design response.

**3. JIT compilation design choices (block-based vs. method-based) expose a warmup/optimization tradeoff.** YJIT (block-based) can begin optimizing and generating native code quickly, with lower warmup latency and lower compilation overhead. ZJIT (method-based, SSA) enables broader optimizations within compilation units but requires more warmup and more compilation work. For language designers considering JIT strategies: block-based compilation is appropriate when warmup latency matters and workloads are diverse; method-based compilation with SSA is appropriate for long-running workloads with stable hot methods. Neither is universally superior; the tradeoff should be explicit in the JIT design.

**4. Uniform object representation (everything is an object) carries a fixed per-object memory tax.** Ruby's 40-byte RVALUE per object is the implementation cost of "everything, including integers and booleans, is a first-class object with identity." Languages that provide a uniform object model must either accept this overhead or invest significantly in optimization techniques (pointer tagging for small values, value types for unboxed primitives). Ruby uses pointer tagging for small integers and symbols (immediate values encoded in the `VALUE` itself, not pointing to an RVALUE), reducing the overhead for the most common values. But other objects — strings, arrays, hashes, user-defined instances — all require full RVALUE allocation. Language designers should explicitly budget for this overhead when designing uniform object models.

**5. Heap compaction requires GC cooperation with the entire C layer.** `GC.compact` in Ruby required significant engineering to make safe: every code path that holds a raw C pointer to a Ruby object must be updated to use stabilized references (or the compactor must pin those objects in place). The difficulty of adding compaction to an existing GC is proportional to how much raw pointer use exists throughout the runtime and C extension ecosystem. Language designers adding compaction to an existing GC should plan for an extended period of pinning (where some objects cannot be moved) before full compaction is achievable. Languages designed with compaction in mind from the start (as the JVM was) have significantly less friction adding it.

**6. JIT performance claims require explicit baselines to be meaningful.** The lesson from Ruby's "92% faster than interpreter" headline is not that the number is wrong but that it is relative. A claim of "N% faster" is only useful when the comparison class (interpreter, unoptimized, previous version, competing language, specific hardware configuration) is stated. Language designers evaluating JIT strategies for new languages should insist on benchmark methodology transparency: what is the baseline, what hardware, what warmup period, what code characteristics? Production throughput improvement figures from representative workloads are generally more meaningful than synthetic micro-benchmarks.

**7. Shared parser infrastructure is high-leverage compiler investment.** Prism's adoption across CRuby, JRuby, TruffleRuby, and major tooling provides parsing consistency that benefits every downstream user simultaneously. For language ecosystems with multiple implementations, investment in a portable, shared parser — rather than each implementation maintaining its own — reduces compatibility bugs, enables better error recovery in tooling, and lowers the cost of adding new implementations. The cost is upfront design work to make the parser embeddable and portable; the return is compounding across the entire ecosystem lifetime.

---

## References

[BYROOT-GVL-2025] Boussier, J. "So You Want To Remove The GVL?" byroot.github.io, January 29, 2025. https://byroot.github.io/ruby/performance/2025/01/29/so-you-want-to-remove-the-gvl.html

[DEVCLASS-RUBY-4] DevClass. "Ruby 4.0 released – but its best new features are not production ready." January 6, 2026. https://devclass.com/2026/01/06/ruby-4-0-released-but-its-best-new-features-are-not-production-ready/

[GVL-SPEEDSHOP] Hoffman, N. "The Practical Effects of the GVL on Scaling in Ruby." speedshop.co, May 11, 2020. https://www.speedshop.co/2020/05/11/the-ruby-gvl-and-scaling.html

[RAILSATSCALE-YJIT-3-3] Shopify Engineering. "Ruby 3.3's YJIT: Faster While Using Less Memory." railsatscale.com, December 4, 2023. https://railsatscale.com/2023-12-04-ruby-3-3-s-yjit-faster-while-using-less-memory/

[RAILSATSCALE-YJIT-3-4] Shopify Engineering. "YJIT 3.4: Even Faster and More Memory-Efficient." railsatscale.com, January 10, 2025. https://railsatscale.com/2025-01-10-yjit-3-4-even-faster-and-more-memory-efficient/

[RACTORS-BYROOT-2025] Boussier, J. "What's The Deal With Ractors?" byroot.github.io, February 27, 2025. https://byroot.github.io/ruby/performance/2025/02/27/whats-the-deal-with-ractors.html

[RUBY-3-0-RELEASE] ruby-lang.org. "Ruby 3.0.0 Released." December 25, 2020. https://www.ruby-lang.org/en/news/2020/12/25/ruby-3-0-0-released/

[RUBY-3-2-RELEASE] ruby-lang.org. "Ruby 3.2.0 Released." December 25, 2022. https://www.ruby-lang.org/en/news/2022/12/25/ruby-3-2-0-released/

[RUBY-3-3-RELEASE] ruby-lang.org. "Ruby 3.3.0 Released." December 25, 2023. https://www.ruby-lang.org/en/news/2023/12/25/ruby-3-3-0-released/

[RUBY-3-4-RELEASE] ruby-lang.org. "Ruby 3.4.0 Released." December 25, 2024. https://www.ruby-lang.org/en/news/2024/12/25/ruby-3-4-0-released/

[RUBY-4-0-RELEASE] ruby-lang.org. "Ruby 4.0.0 Released." December 25, 2025. https://www.ruby-lang.org/en/news/2025/12/25/ruby-4-0-0-released/

[RUBY-GC] Ruby Documentation. "ObjectSpace and GC." https://ruby-doc.org/core/GC.html

[RUBY-RESEARCH-BRIEF] Ruby Research Brief. research/tier1/ruby/research-brief.md (this project)

[TECHEMPOWER-ROUND-23] TechEmpower Framework Benchmarks. Round 23, March 2025. https://www.techempower.com/benchmarks/

[TRUFFLERUBY-CEXT] TruffleRuby documentation and performance benchmarks. https://github.com/oracle/truffleruby

[UPDOWN-RUBY-3-3] Updown.io. "Upgrading a Rails app from Ruby 3.2 to 3.3, observations about YJIT." https://blog.updown.io/2024/01/02/upgrading-ruby-3-3-and-yjit.html
