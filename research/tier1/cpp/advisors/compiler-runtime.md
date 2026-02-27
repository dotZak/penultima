# C++ — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "C++"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
```

---

## Summary

The C++ council has produced technically solid perspectives across its five documents. The core claims — zero-overhead abstraction, RAII determinism, the significance of the C++11 memory model, and the genuine pain of compilation speed — are accurate and grounded in implementation reality. However, several important compiler and runtime nuances are either understated, overstated, or missing entirely, and these gaps matter for the lessons the council draws.

The most consequential technical gap is the treatment of the zero-overhead principle as a binary property rather than a context-dependent one. The council correctly states that `std::unique_ptr` has zero overhead over a raw pointer, and that exception tables impose no execution cost when no exception is thrown. But these claims require qualification: `unique_ptr` is zero-overhead in release builds only; exception tables do impose binary-size and cold-code overhead even when no exception propagates; and template monomorphization, while essential for the zero-overhead property of generics, produces code-size growth that the council underweights. The council also underrepresents Link-Time Optimization (LTO) and Profile-Guided Optimization (PGO) as meaningful parts of C++'s performance story.

The most consequential factual issue is the claim about C++17 parallel algorithms. The apologist and others present these as a real, available feature for parallelizing work across hardware threads. In practice, the implementation status is severely uneven across standard libraries: Clang's libc++ had no parallel algorithm implementation as of 2024; GCC's libstdc++ requires Intel TBB as a separately installed backend; only MSVC has a self-contained implementation. The council's framing implies available capability that does not exist portably. For a language that positions portability as a strength, this gap in the parallel algorithms story is significant and should be corrected in the consensus report.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **RAII is genuinely deterministic.** All five council members accurately describe RAII: resource release is tied to scope exit via stack unwinding, which is invoked on both normal and exception paths. This is not a convention or a soft guarantee — it is a compiler-enforced invariant. When a scope exits, the compiler generates destructor calls in reverse construction order. This is correct and important.

- **`std::unique_ptr` zero overhead in optimized builds.** The apologist and realist both state that `unique_ptr` has zero overhead over a raw pointer. This is true in release builds (`-O1` or above): the compiler sees through the template wrapper and generates identical machine code to a raw pointer with manual delete. The claim is well-supported by assembly inspection.

- **C++11 formal memory model as a significant achievement.** All council members correctly identify the C++11 memory model as resolving a decades-long gap. Before C++11, multithreaded C++ was formally undefined behavior; the standard specified no ordering constraints between threads. The C++11 model, incorporating Hans Boehm's work on the "happens-before" relation and the six memory-ordering levels, provides a formal foundation that allowed compilers to both optimize and preserve correctness guarantees. That this model was subsequently adopted by Java, Go, and Rust validates its design quality.

- **Smart pointer taxonomy.** The council correctly distinguishes `unique_ptr` (single-owner, zero overhead), `shared_ptr` (reference-counted, shared ownership), and `weak_ptr` (non-owning, breaks cycles). This taxonomy is accurate.

**Corrections needed:**

- **`shared_ptr` overhead is significantly understated.** The council describes `shared_ptr` overhead as "reference-counted" and notes it is "measurably slower than `unique_ptr` or raw pointers in multithreaded code," but this understates the implementation cost. A `shared_ptr` has three distinct overhead sources that the council conflates:
  1. **Control block allocation.** By default, `std::make_shared` allocates the object and control block in a single allocation (efficient); but `shared_ptr<T>(new T(...))` requires two separate allocations — one for the object, one for the control block. This is a common mistake that creates double allocation overhead.
  2. **Atomic reference count operations.** The reference count is maintained via `std::atomic<long>`, which on x86-64 uses `lock xadd` or similar instructions. These instructions force a cache-line ownership transfer, which in multicore scenarios causes cache-coherency traffic. A high-frequency `shared_ptr` copy/destroy in a multi-threaded hot path can degrade throughput by 10-50× compared to `unique_ptr` — not the 1.5-2× implied by the "a few nanoseconds" framing.
  3. **Double indirection.** Accessing the managed object through a `shared_ptr` requires dereferencing two pointers (the `shared_ptr` itself points to a control block or uses an internal pointer to the object). This extra indirection is typically irrelevant for application code but matters in tight loops.

  The consensus report should be explicit that `shared_ptr` is emphatically *not* a zero-overhead alternative to `unique_ptr` and should not be used as a "safe default" in performance-sensitive code.

- **Exception "zero-cost" claim requires binary-size qualification.** The apologist states: "the overhead when *no exception is thrown* is essentially zero." This is true for *execution overhead* — no runtime check per function call, no branch taken on the success path. However, the claim is misleading for two other cost dimensions that the council ignores:
  1. **Binary size.** Table-based exception handling (the Itanium/DWARF model used by GCC and Clang on all non-Windows platforms) embeds LSDA (Language Specific Data Area) tables in the binary for every function that contains objects with non-trivial destructors or contains try blocks. These tables must be loaded from disk and potentially paged in. For a large binary with extensive RAII use, this table data can represent 10-30% of the binary size. Compiling with `-fno-exceptions` removes these tables and produces measurably smaller binaries.
  2. **Cold-path code generation.** The exception landing pads and cleanup code are emitted as machine code, even if the exception path is never executed. This affects I-cache footprint and binary size. The instruction cache "sees" this code whether or not it runs.

  The council's framing that exceptions are "zero cost" should be qualified: they are zero cost for *runtime performance on the happy path* but not zero cost for binary size or cold code footprint. This distinction matters significantly in embedded targets with flash size constraints.

**Additional context:**

- **ABI stability as a constraint on memory model evolution.** The Itanium C++ ABI, effectively frozen on Linux/macOS for binary compatibility, has constrained improvements to both object layout and exception handling. The `std::string` small-string optimization (SSO) changed object size across standards in some implementations; this caused ABI breaks in Linux distributions that had to be managed carefully. The ABI freezing is a production reality that limits the committee's ability to improve memory-related features even when better designs exist. This tension (ABI stability vs. language improvement) deserves mention in the consensus report.

- **Static Initialization Order Fiasco (SIOF).** The practitioner mentions this briefly; it warrants compiler-advisor emphasis. SIOF is a genuine runtime issue: the initialization order of objects with static storage duration in different translation units is unspecified by the standard. This means that a static object in TU A that depends on a static object in TU B may run its constructor before TU B's static is initialized. The result is a subtly initialized or zero-initialized "pointer" that produces undefined behavior on first use. The workarounds (function-static / Meyer's singleton pattern; `constinit` in C++20 for constant initialization; `constexpr` for compile-time initialization) are effective but require awareness. Compilers offer no diagnostic for SIOF in the general case.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **`memory_order_consume` is unimplemented in practice.** The apologist correctly flags that `memory_order_consume` "remains unimplemented in practice by most compilers." This is accurate and important: GCC, Clang, and MSVC all promote `memory_order_consume` to `memory_order_acquire`. The specification intends `consume` to provide dependency ordering — on weakly ordered architectures (POWER, ARM), a load operation carries ordering to subsequent loads that are *computationally dependent* on its result, without requiring a full acquire barrier. This would enable lock-free pointer-following code to run faster on POWER. In practice, the analysis required to verify dependency ordering is too complex for compilers to implement correctly, so they upgrade to acquire, which is always correct but heavier than necessary. The council should note that this means dependency ordering — a potentially significant performance feature for lock-free programming on non-x86 hardware — is unavailable in standard C++.

- **C++20 coroutines are stackless.** The apologist and historian correctly identify C++20 coroutines as stackless (no separate stack allocated per coroutine). This is accurate: a suspended C++20 coroutine stores only its live state in a heap-allocated coroutine frame. The frame size is generally O(number of live variables at suspension point). This is more efficient per-coroutine than stackful coroutines for scenarios with many simultaneous suspended coroutines (millions of connections in an async server). The tradeoff — that stack-based recursive patterns are harder to express — is also correctly noted.

- **ThreadSanitizer is a testing tool, not a production mitigation.** All council members who address TSan correctly note it catches data races dynamically, in testing, not in production. This is the right framing: TSan imposes 5-15× runtime slowdown and 5-10× memory overhead, making it entirely unsuitable for production deployment.

- **C++ provides no compile-time data race prevention.** The council uniformly acknowledges this gap and correctly contrasts it with Rust's borrow checker. This is accurate and appropriately presented as a genuine weakness.

**Corrections needed:**

- **C++17 parallel algorithms implementation status is misrepresented.** The apologist states: "`std::sort(std::execution::par, begin, end)` parallelizes a sort across available hardware threads without requiring the programmer to manage threads manually." This is the specification. The implementation reality is substantially different and the council does not adequately communicate it:
  - **Clang/libc++:** As of Clang 18 (2024), libc++ does not implement parallel algorithms. The `execution::par` overloads exist in the header for compilation, but fall back to serial execution or are simply not provided [LIBCXX-PAR-STATUS].
  - **GCC/libstdc++:** Implements parallel algorithms using Intel TBB (Threading Building Blocks) as a backend. If TBB is not installed and linked, parallel algorithms are not available. TBB is a separately installed library, not bundled with GCC. On many Linux distributions, libtbb-dev must be explicitly installed.
  - **MSVC:** Has a self-contained parallel algorithms implementation using the Visual C++ runtime. This is the most complete implementation.

  For a feature presented as enabling "parallelization without manual thread management," the actual portability story is: only on MSVC without additional setup, and on GCC only if TBB is installed. This is a significant gap between specification and implementation that the council should correct.

- **The memory ordering complexity of `memory_order_consume` deserves full explanation.** The apologist notes it is "unimplemented" and calls this "correctly complex" but doesn't explain why this matters. As noted above, the inability to express dependency ordering in standard C++ means that some lock-free algorithms that would be provably correct with lighter barriers on POWER/ARM must use heavier acquire barriers instead, potentially reducing the performance advantage over lock-based code. For the performance-focused language C++ is, this gap deserves explicit treatment.

**Additional context:**

- **`std::atomic<T>` for non-trivially-sized types.** The council's discussion of atomics focuses on `memory_order`. An additional implementation reality: `std::atomic<T>` for types larger than the hardware's native atomic width (typically 8 bytes on 64-bit) may be implemented via a mutex or via `LOCK CMPXCHG16B` (double-width compare-and-swap). This is implementation-defined. Code using `std::atomic<std::pair<int64_t, int64_t>>` may silently acquire a lock, defeating the "lock-free" assumption. `std::atomic<T>::is_lock_free()` can be queried at runtime; `std::atomic<T>::is_always_lock_free` can be checked at compile time. Practitioners who don't check this may believe they have lock-free code when they have lock-based code with worse ergonomics than a mutex.

- **C++26 `std::execution` (senders/receivers) is promising but unproven at scale.** The council mentions this feature positively. The caution: the design, while theoretically sound, is complex enough that its ergonomics at scale remain to be demonstrated. The networking library based on Asio was similarly promising and has not yet reached standardization despite years of proposal work. Language designers should note that concurrency abstractions are particularly prone to the gap between specification and production usability.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **CLBG data: C++ in the top tier alongside C.** The council correctly cites Computer Language Benchmarks Game data showing C++ performing at parity with C on algorithmic benchmarks [BENCHMARKS-PILOT]. This is accurate and well-supported. The key enabling factor is that the C++ compiler sees through RAII and template wrappers in optimized builds, producing machine code equivalent to hand-written C.

- **Virtual dispatch overhead of 1-5 ns (best case).** The 1-5 ns figure for vtable dispatch is cited in multiple council documents and is approximately correct for a cache-warm vtable access. However, see the additional context section below.

- **Template monomorphization enables zero-overhead generics.** The apologist and realist correctly explain that C++ templates generate specialized code per type, eliminating runtime dispatch. This is the mechanism behind `std::vector<int>` being as fast as a hand-written int array: the compiler has generated integer-specific code.

- **Compilation time is a genuine weakness.** All council members correctly identify compilation time — especially for template-heavy code — as a practical productivity cost. The Chrome 15-30 minute build figure is accurate and representative of large-scale C++ projects.

- **C++20 modules as a structural fix for compilation time.** The practitioner's honest assessment of modules adoption — that the feature exists but the brownfield adoption path is difficult — is accurate and appropriately cautious.

**Corrections needed:**

- **Virtual dispatch overhead: 1-5 ns is the best case, not the typical case.** The council consistently cites 1-5 ns for virtual function dispatch. This is the hardware latency for an indirect call when the vtable pointer is in L1 cache. Two additional effects are not accounted for:
  1. **I-cache pressure and missed inlining.** The compiler cannot inline a virtual function call because the target is not known at compile time. Inlining is often the most valuable optimization the compiler applies to hot paths — it enables constant propagation, dead code elimination, and further loop optimizations across the call boundary. A virtual call forecloses these. The cost of *not inlining* often exceeds the 1-5 ns dispatch latency by an order of magnitude in compute-intensive code.
  2. **Branch predictor and cache miss scenarios.** Virtual dispatch in polymorphic containers (e.g., a vector of base class pointers to different derived types) produces branch mispredictions and vtable cache misses. On realistic object-oriented code patterns, virtual dispatch in a tight loop with varied derived types can cost 50-300 ns per call from cache misses alone. The council's 1-5 ns figure applies only to monomorphic call sites (same derived type every time) or cache-warm vtable scenarios. Heterogeneous dispatch is substantially more expensive.

  The consensus report should present virtual dispatch overhead as: "1-5 ns for monomorphic, cache-warm dispatch; potentially 50-300 ns when the vtable or target code is cache-cold, or when the call site is highly polymorphic."

- **Template code bloat is underweighted.** The council correctly identifies that monomorphization enables zero-overhead generics. It does not adequately address the code-size consequence. Each `std::vector<T>` instantiation for a distinct `T` generates its own machine code: `push_back`, `resize`, `erase`, etc. A large codebase using `std::vector` with dozens of distinct types will have dozens of copies of these functions in the binary. Effects:
  1. **Binary size growth.** Binaries with heavy template use are substantially larger than type-erased equivalents. For embedded systems with flash constraints, this can be prohibitive — which is why embedded C++ practitioners often avoid STL containers entirely.
  2. **I-cache pressure at scale.** A very large binary with many template instantiations can exceed the working set of the instruction cache, causing cache thrashing in applications that touch many distinct instantiations. This is rare but real for large libraries.
  3. **Link time.** The linker must deduplicate template instantiations across translation units (via COMDAT folding). This deduplication itself adds to link time.

  Language designers weighing monomorphization vs. type erasure for generics should understand that the binary-size tradeoff is real and significant for resource-constrained deployment targets.

- **LTO and PGO are absent from the performance story.** The council does not mention Link-Time Optimization (LTO) or Profile-Guided Optimization (PGO), which are significant and commonly used parts of C++'s production performance story:
  1. **LTO** (via `-flto` in GCC/Clang, `/GL` in MSVC) allows the optimizer to perform inlining, constant propagation, and dead code elimination *across translation unit boundaries* at link time. C++'s compilation model (separate translation units linked together) can limit inter-module optimization without LTO. With LTO, the performance gap between C++ and C narrows further, and template-heavy code that is instantiated in one TU and called from another becomes fully optimizable. Thin LTO (supported by Clang) reduces LTO build time overhead significantly.
  2. **PGO** (Profile-Guided Optimization) uses runtime execution profiles to guide compiler decisions — which branches to predict, which functions to inline, which code to move to cold sections. Google reports 10-15% performance improvements from PGO on large production binaries. Chrome, Firefox, and LLVM itself are built with PGO in release configurations.

  The consensus report's performance section should include LTO and PGO as tools that practitioners use to extract additional performance beyond what debug/release compilation provides. Their existence also has a language design implication: a language that separates compilation from linking (as C++ does) makes LTO technically necessary to recover the optimization opportunities that a whole-program compilation model provides for free.

**Additional context:**

- **Undefined behavior as a performance mechanism.** The practitioner correctly identifies "UB as a performance vector." This deserves fuller treatment from the compiler perspective. UB in C++ is not merely a safety failure — it is an intentional mechanism by which the language delegates optimization authority to the compiler. Specific examples:
  1. **Signed integer overflow is UB** → the compiler can assume it never occurs → loop variables that would overflow wrap around in undefined ways, allowing the compiler to infer loop bounds and apply vectorization or strength reduction. If overflow were defined (as two's complement), the compiler would have to respect it and emit conservative code.
  2. **Strict aliasing rule** (pointer to type A does not alias pointer to type B, unless one is `char*`) → the compiler can cache values in registers across pointer stores to other types → more aggressive register allocation, fewer memory loads. Violating this rule (type-punning through incompatible pointers) is UB and produces optimization-induced correctness bugs.
  3. **Null pointer dereference is UB** → the compiler can eliminate null checks on the assumption that if a pointer is dereferenced, it must be non-null → shorter generated code for common patterns.

  This mechanism — using UB to transfer optimization authority from programmer to compiler — is a deliberate design choice with real performance benefits and real safety costs. Language designers must explicitly decide whether to take this tradeoff. Rust's approach (defined behavior for safe code, explicit `unsafe` for UB-enabling optimization) is an alternative design point.

- **`__attribute__((optimize))`, PRAGMAs, and function-level optimization control.** GCC and Clang allow per-function optimization levels (`__attribute__((optimize("O0")))` for debug, `__attribute__((hot))` for aggressive inlining, `[[likely]]/[[unlikely]]` for branch hints). These are not standard C++ but are widely used in performance-critical code. The council doesn't mention them, but they are part of how practitioners actually tune C++ performance beyond the language specification.

---

### Other Sections: Compiler/Runtime Observations

**Section 2 (Type System) — `constexpr` compile time cost:**

The council correctly identifies `constexpr` as enabling valuable compile-time computation. The missing observation: heavy `constexpr` and `consteval` computation shifts work from runtime to compile time, which is beneficial for runtime performance but can dramatically increase compilation time. A `constexpr` function computing a large lookup table at compile time may take seconds of compiler CPU time. The tradeoff — faster runtime, slower compilation — is the correct one in most scenarios, but it compounds the existing compilation-time problem the council identifies in Section 9. For language designers, the lesson is that compile-time computation is not "free" from the developer's perspective; it trades runtime latency for build latency.

**Section 5 (Error Handling) — Zero-cost exception mechanism:**

The realist correctly notes that exceptions were "zero-cost in the narrow sense: when no exception is thrown, the cost is essentially zero." The additional compiler detail: this zero-cost property is not universal across platforms. On Windows with MSVC, the exception handling model (SEH-based) differs from the Itanium DWARF model and has different performance characteristics. Moreover, on some embedded targets, the setjmp/longjmp exception model (used when DWARF unwinding is unavailable) does impose a constant per-function overhead — a small setup and teardown cost — even when no exception is thrown. The council presents zero-cost exceptions as universal; they are universal only on platforms that support table-based DWARF unwinding (Linux, macOS, most POSIX platforms). This distinction matters for practitioners targeting embedded systems, which is one of C++'s identified major domains.

**Section 6 (Ecosystem) — Sanitizer interaction constraints:**

The practitioner correctly notes that ASan and TSan cannot be combined simultaneously. The underlying reason: both use compiler instrumentation that modifies how memory accesses are tracked, and the two tracking mechanisms conflict. This means a team cannot run a "combined sanitizer build" that catches both memory safety errors and race conditions simultaneously. Multiple CI configurations (one ASan build, one TSan build) are required — not just for process reasons but as a fundamental implementation constraint. UBSan can generally be combined with ASan but not with TSan. This is worth stating explicitly for any language design that considers sanitizers as a mitigation strategy.

**Section 7 (Security) — Hardware mitigations:**

The practitioner mentions `-fstack-protector-strong, ASLR, CFI` as "essentially free in terms of performance cost." This is approximately true for ASLR (pure OS-level) and stack canaries (1-2% overhead on function calls). Control Flow Integrity (CFI) has a more variable cost: basic CFI (forward-edge CFI via `clang -fsanitize=cfi`) can add 1-5% overhead; fine-grained CFI can be higher. Intel's CET (Control-flow Enforcement Technology) shadow stack, available on Ice Lake and newer CPUs, adds minimal overhead (Intel reports <1% for most workloads). These are real mitigations that language designers should understand as OS/hardware complements to language-level safety — they reduce exploitation difficulty without reducing bug occurrence.

---

## Implications for Language Design

The C++ experience at the compiler and runtime level yields five precise implications for language designers:

**1. The specification-implementation gap is widest for concurrency and parallel features.** C++17 parallel algorithms, `memory_order_consume`, and early module support all demonstrate that a feature can be standardized before its implementation is viable. For language designers, the lesson is that concurrency and parallel abstractions require tight coordination between the language specification team and compiler implementers — and should ideally have at least one complete reference implementation before standardization. A standardized-but-unimplemented feature creates false confidence and may be dead-on-arrival if the implementation burden deters compiler vendors.

**2. Binary-size costs from monomorphization must be budgeted.** C++'s template monomorphization produces zero-overhead runtime performance at the cost of binary-size growth. For general-purpose computing (megabyte binaries on gigabyte systems) this tradeoff is almost always correct. For resource-constrained targets (embedded firmware in 256KB flash) it can be a showstopper. Language designers choosing between monomorphization and type erasure for generics should provide both mechanisms and let the programmer choose. A single unified approach optimized for one deployment context will fail in the other.

**3. Undefined behavior as an optimization contract has diminishing returns and growing liabilities.** C++ used UB as the contract under which the compiler may optimize aggressively. This produced real performance benefits and is demonstrably a significant source of security vulnerabilities. Rust demonstrates that a language can achieve comparable performance without UB in safe code by using a type system that makes UB structurally impossible in safe contexts and confines UB-enabling operations to `unsafe` blocks. For new language designers, C++'s experience should be read as: if you want UB-based optimizations, the safety cost is real and must be managed with explicit syntactic containment (`unsafe`), not convention.

**4. Sanitizers are a development-cycle mitigation, not a production one.** The 2-15× overhead of production-relevant sanitizers (ASan, TSan, UBSan) makes them unsuitable for always-on production deployment. This means that bugs caught by sanitizers represent bugs that escaped to production and were caught only when sanitizer builds were triggered by test coverage. A class of bugs that can only be caught by test coverage is fundamentally more dangerous than a class prevented by the type system. Language designers should treat "detectable at test time by instrumented build" as significantly weaker than "prevented at compile time by the type system," even when the detection rate is high.

**5. ABI stability imposes compounding constraints on runtime improvements.** C++'s effectively frozen ABI on Linux/macOS has prevented improvements to `std::string` layout, exception handling internals, and standard library data structure sizes that would break binary compatibility. Language designers should plan ABI stability policy from the beginning: stable ABI is a strong user benefit but a strong constraint on optimization. Explicit versioned ABI epochs (similar to how some Linux kernel subsystems handle this) provide a middle path — users opt into new ABI with explicit recompilation, but the language retains the ability to improve.

---

## References

[BENCHMARKS-PILOT] "Performance Benchmark Reference: Pilot Languages." evidence/benchmarks/pilot-languages.md, February 2026.

[CPPREFERENCE-ATOMIC] "std::memory_order — cppreference.com." https://en.cppreference.com/w/cpp/atomic/memory_order.html

[CPPREFERENCE-NOEXCEPT] "noexcept specifier — cppreference.com." https://en.cppreference.com/w/cpp/language/noexcept_spec

[LIBCXX-PAR-STATUS] LLVM Project. "libc++ C++17 Status — Parallel Algorithms." https://libcxx.llvm.org/Status/Cxx17.html (Parallel algorithms listed as not implemented as of Clang 18, 2024.)

[MSRC-2019] Miller, M. "A Proactive Approach to More Secure Code." Microsoft Security Response Center, 2019. https://www.microsoft.com/en-us/msrc/blog/2019/07/a-proactive-approach-to-more-secure-code/

[MOMTCHEV-EXCEPTIONS] Momtchev, M. "The true cost of C++ exceptions." Medium. https://mmomtchev.medium.com/the-true-cost-of-c-exceptions-7be7614b5d84

[RESEARCH-BRIEF] "C++ — Research Brief." research/tier1/cpp/research-brief.md, February 2026.

[STROUSTRUP-DNE-1994] Stroustrup, B. *The Design and Evolution of C++*. Addison-Wesley, 1994. https://www.stroustrup.com/dne.html

[STROUSTRUP-CACM-2025] Stroustrup, B. "21st Century C++." *Communications of the ACM*, February 2025. https://cacm.acm.org/blogcacm/21st-century-c/

[VELDHUIZEN-1995] Veldhuizen, T. "Using C++ Template Metaprograms." *C++ Report*, 1995.

[WG21-SITE] "ISO/IEC JTC1/SC22/WG21 — The C++ Standards Committee." https://www.open-std.org/jtc1/sc22/wg21/
