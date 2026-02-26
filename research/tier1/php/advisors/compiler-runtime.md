# PHP — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "PHP"
agent: "claude-agent"
date: "2026-02-26"
```

## Summary

The PHP council provides a broadly accurate picture of PHP's runtime architecture, with the most reliable accounts coming from the realist and practitioner perspectives. However, the council contains several overclaims about safety guarantees, a significant internal contradiction about the "colored function" problem in async code, and some stale or imprecise claims about JIT compilation behavior. The most important pattern across all five perspectives is that the council consistently—and correctly—identifies PHP's fundamental design tension: its execution model was optimized for ephemeral, request-scoped web workloads, and every subsequent effort to extend PHP into long-running processes, async I/O, and CPU-intensive computation has been an exercise in working against those original assumptions.

For the three primary review sections, the memory model discussion is the most accurate overall, though the apologist significantly overstates the safety guarantees as design-level impossibilities when they are userland-layer impossibilities. The concurrency section contains a genuine contradiction between the realist and practitioner perspectives on the "colored function" problem that the council does not resolve. The performance section is largely accurate on benchmark data but requires correction on JIT capability claims and clarification on what "compilation speed" means in PHP's context.

From a Penultima design perspective, PHP's runtime reveals three underappreciated tradeoffs that a new language should address explicitly: the relationship between scope boundaries and memory management strategy; the gap between language-level concurrency primitives and ecosystem-level concurrency compatibility; and the difficulty of adding a JIT to a dynamically typed language without full-program type information.

---

## Section-by-Section Review

### Section 3: Memory Model

- **Accurate claims:**
  - All five council members correctly identify PHP's memory model as reference counting with cycle detection, with copy-on-write (COW) semantics for strings and arrays. This is accurate per PHP internals documentation [PHP-MEMORY].
  - The characterization of request-scoped memory as the primary execution model is correct. The per-request arena design is real and consequential: all allocations are effectively bulk-freed at request end via the per-request memory pool (`zend_mm_heap`), which is more efficient than per-object reference count reaching zero individually.
  - The historian's framing of the PHP 7.0 internal restructuring (zval and HashTable redesign) producing ~50% memory reduction is accurate and well-sourced [PHP7-PERFORMANCE].
  - The realist's and practitioner's characterization of the FFI memory boundary is accurate: PHP manages PHP-side memory automatically; C-side memory allocated via `FFI::new()` is the developer's responsibility and is not tracked by the Zend Memory Manager. This creates a sharp and potentially dangerous ownership boundary [PHP-FFI].
  - The observation that cycle detection runs when the "root buffer" threshold is exceeded (~10,000 possible cycles), not on every allocation, is correct. The GC is not continuous but triggered heuristically [PHPMANUAL-GC].

- **Corrections needed:**
  - **Apologist overclaims on safety scope.** The apologist states that use-after-free, double-free, and dangling pointers are "Impossible" as blanket guarantees. This conflates the userland PHP layer with the full PHP runtime. The historian correctly qualifies this: "memory-related vulnerabilities in PHP are almost exclusively in C extensions (GD, ImageMagick, XML parsers) or in the PHP runtime itself, not in userland PHP code [PHP-CVE-DATA]." The CVE data for PHP confirms this distinction: buffer overflows and use-after-free vulnerabilities regularly appear in the C extension layer. The guarantee is accurately stated as: *no use-after-free in pure PHP userland code*, not as a system-wide property. The apologist's framing misleads about the effective security boundary.
  - **Apologist imprecise on JIT and allocation pressure.** The claim that "PHP 8.0 JIT reduces allocation pressure by compiling hot paths" mischaracterizes what JIT does. PHP's JIT compiles hot code paths to native machine code, reducing interpretation overhead (decoding opcodes, dispatching instruction handlers). It does not directly reduce heap allocation pressure—`new` operations and array constructions still invoke the Zend Memory Manager regardless of JIT status. What JIT can do indirectly is eliminate some internal zval boxing/unboxing through specialization, which reduces intermediate allocations on hot paths—but the apologist's phrasing overstates this as a memory management improvement rather than a CPU overhead improvement.
  - **Detractor overstates O(n²) string concatenation.** The claim that "string concatenation and array operations can trigger O(n²) memory copies for long-running operations" is technically possible but context-dependent. PHP's `$str .= $fragment` in a tight loop does produce O(n²) behavior because each concatenation may require a full string copy (unlike rope-based or builder-based implementations). However, this is a well-known PHP pattern issue, and the standard solution (`implode()` or array accumulation) eliminates it. The detractor presents this as a memory model flaw; it is more accurately a standard library design and developer pattern issue. Languages without string mutability (Python, Java) have similar pathologies when programmers concatenate naively.
  - **Apologist's "packed arrays" claim needs precision.** The claim of "20-30% memory reduction for integer-indexed arrays" from PHP 7.0 is imprecise. PHP 7.0's optimization was a complete redesign of the `zend_value` union (zval) and HashTable structures, affecting all types, not specifically packed arrays. The ~50% overall memory reduction figure (supported by the historian and benchmarks) is the correct reference [BENCHMARK-PILOT].

- **Additional context:**
  - The council understates the significance of OPcache's shared memory region for bytecode as a distinct allocation domain. OPcache maintains a separate persistent memory segment (default 128MB) that persists across requests and is shared between workers. This is architecturally separate from the per-request heap and serves as PHP's equivalent of a "code segment." The practitioner briefly mentions this, but it is relevant to understanding PHP's true memory architecture: there are actually three memory domains (per-request heap, OPcache shared segment, persistent extension memory via `pemalloc`), not a single heap.
  - The realist's observation that "no published benchmarks rigorously measure PHP's memory allocation performance" is honest and important. Most PHP performance literature measures request throughput or wall-clock time, not allocator efficiency. This gap in the evidence base means allocation overhead claims are practitioner-informed estimates, not rigorously benchmarked data.

---

### Section 4: Concurrency and Parallelism

- **Accurate claims:**
  - The foundational claim—that PHP's traditional shared-nothing, process-per-request model prevents data races at the PHP-level by construction—is accurate. OS-level process isolation means that two PHP-FPM workers cannot share mutable state without going through an external system (database, Redis, APCu with careful locking). This is a genuine architectural safety property, not just a design philosophy.
  - PHP 8.1 Fibers are accurately characterized across all perspectives as cooperative coroutines, not preemptive threads. The implication—that Fiber-based code cannot experience preemption-based race conditions—is correct. Fibers switch only at explicit `Fiber::suspend()` calls. Within a single Fiber's execution between suspension points, the code is effectively single-threaded.
  - The observation that Fibers are lightweight (~4KB stack vs. 1-2MB for OS threads) is consistent with the implementation and accurately represents the memory efficiency argument for Fiber-based concurrency [PHP-FIBERS].
  - The practitioner's observation about FrankenPHP (Go-backed HTTP server with PHP embedding) is notable and accurate: it achieves concurrency through Go's goroutine scheduler, not PHP Fibers, providing a different architectural approach to PHP concurrency.
  - The realist and historian are correct that PHP never added `async`/`await` keywords to the language. The RFC that introduced Fibers explicitly rejected async/await syntax to avoid the colored function problem at the language level [PHP-RFC-FIBERS].

- **Corrections needed:**
  - **Critical contradiction on the "colored function" problem.** The realist states: "PHP does **not** have the async/sync divide that plagues JavaScript/Python. Fiber suspension is explicit but does not 'color' functions." The practitioner states: the colored function problem is "Severe in Swoole/ReactPHP/Amp." Both claims are accurate but address different layers, and the council does not resolve this distinction.

    The correct framing: **PHP Fibers do not color functions at the language specification level.** A function that calls `Fiber::suspend()` internally looks identical in signature to a function that does not. The RFC explicitly designed Fibers this way. *However*, any function that calls a blocking I/O operation (e.g., `file_get_contents()`, a blocking MySQL query via `mysqli`) will block the entire event loop if called within an async runtime. This creates a *de facto* coloring at the ecosystem level: libraries and application code must choose async-safe implementations of I/O operations or they will silently serialize execution. Swoole provides `Swoole\Coroutine\Http\Client`; code using standard `file_get_contents()` in a Swoole coroutine blocks. This is functionally identical to the colored function problem even if PHP's Fiber API does not syntactically enforce it.

    The council should not present PHP as having "solved" the colored function problem. PHP has deferred it from the language to the ecosystem layer, which is a different tradeoff, not an elimination of the problem.

  - **Detractor's benchmark citation is outdated.** The claim that "Node.js executes API requests 3x faster than PHP 7.4 (31ms vs 91ms) [NETGURU-NODEJS]" cites PHP 7.4 data, but PHP 7.4 reached end-of-life in November 2022. PHP 8.x with OPcache tuning substantially narrows this gap. The TechEmpower Round 23 data (March 2025) [BENCHMARK-PILOT] is the appropriate current benchmark, and it shows PHP frameworks at 5,000-15,000 RPS versus Node.js/Express at 20,000-40,000 RPS—a 2-4x difference, not 3x, and the absolute numbers depend on hardware. Using a 2.5+ year old benchmark version to characterize PHP's current concurrency performance is misleading.

  - **Apologist conflates ext-pthreads and ext-parallel.** The statement "Shared memory extensions (ext-parallel, ext-pthreads): Require explicit synchronization primitives" bundles two very different extensions. `ext-pthreads` is largely deprecated and was designed for PHP CLI use only (not FPM). `ext-parallel` (by Joe Watkins, the same author) is the current supported approach for true thread-based parallelism. These are architecturally distinct: `ext-pthreads` exposed OS threads with shared objects; `ext-parallel` runs isolated tasks in separate thread contexts with message passing. Treating them as interchangeable misrepresents PHP's actual parallel execution capabilities.

  - **Apologist's claim about Swoole concurrency levels needs qualification.** The claim that Swoole handles "10,000+ concurrent connections per worker" and is "competitive with Node.js" is plausible but context-dependent. Raw connection counts at the event loop level can be high, but throughput for CPU-bound work is still bounded by PHP's single-threaded execution per coroutine context. The practitioner's more qualified version—"10,000+ concurrent connections per process" with the caveat about "careful tuning and understanding of async patterns"—is the more accurate representation.

- **Additional context:**
  - The council does not discuss PHP's Global Interpreter Lock (GIL) equivalent. PHP does not have a GIL in the Python sense—because the standard execution model is process-based (not thread-based) shared-nothing, there is nothing to lock against. However, when using `ext-parallel` or the ZTS (Zend Thread Safety) build, PHP does have per-zval mutex locking for reference count operations. This ZTS overhead is why PHP-FPM typically uses non-ZTS builds: thread safety carries a performance penalty even for non-concurrent operations.
  - The distinction between PHP-FPM (process pool) and Swoole (event loop with coroutines) is not just about performance—it is a fundamental architectural difference in how OS resources are consumed. The practitioner's "pick your poison" framing is accurate: the two models offer different resource utilization profiles, debugging characteristics, and failure modes, not just throughput differences.

---

### Section 9: Performance Characteristics

- **Accurate claims:**
  - All council members correctly cite TechEmpower Round 23 (March 2025) showing PHP frameworks at 5,000-15,000 RPS versus Rust at 500,000+ [BENCHMARK-PILOT]. The benchmark data is accurately represented.
  - The characterization of JIT benefit is consistent across all perspectives and matches the evidence: 1.5-3x for CPU-intensive workloads (fractal generation, mathematical computation), negligible for typical request-response web workloads where database I/O dominates. The benchmark evidence file confirms: "WordPress, MediaWiki, and Symfony demonstrate minimal or inconsistent JIT benefit" and "Function JIT sometimes shows worse performance than non-JIT execution" [BENCHMARK-PILOT].
  - PHP has no traditional ahead-of-time compilation step. The OPcache bytecode cache (per-request compilation on first access, cached thereafter) is accurately described by all perspectives. The realist's claim about subsequent requests loading from shared memory at <1ms is accurate.
  - PHP 7.0's approximately 2x performance improvement over PHP 5.6 is accurate and well-documented [PHP7-BENCHMARKS]. The historian's explanation—redesigned internal data structures and 50% memory reduction enabling better cache behavior—is the correct technical explanation.
  - The practitioner's serverless cold-start estimate (~230ms for PHP at 768MB memory) is consistent with reported AWS Lambda measurements and is more precise than the general "5-50ms" startup claim, which refers to traditional PHP-FPM worker startup, not Lambda cold starts.

- **Corrections needed:**
  - **JIT ARM support claim is outdated.** The detractor states "Only supports x86/x64; ARM and Apple M1 unsupported initially (later added but with limitations)." PHP 8.0's JIT was indeed x86/x64 only. PHP 8.1 added ARM64 support, and PHP 8.2/8.3 continued improving ARM64 compatibility. PHP 8.4 introduced a new IR (Intermediate Representation)-based JIT framework that substantially improved portability and optimization quality. As of PHP 8.4 (released November 2024), ARM64 JIT is functional, though some ARM-specific optimizations lag x86_64. Citing PHP 8.0 limitations as current is inaccurate.
  - **Apologist conflates JIT and allocation pressure.** See Section 3 correction above. The additional claim here is that "PHP 8.0 JIT reduces allocation pressure by compiling hot paths" appears in the performance section as well. JIT reduces CPU time in hot paths by native code generation; it does not reduce the number of allocations unless specific escape analysis or scalar replacement optimizations eliminate heap objects. PHP's JIT does perform some of these optimizations (particularly for common numeric operations that can use CPU registers directly), but the characterization as "allocation pressure reduction" is imprecise.
  - **"No compile-time computation or constant folding beyond basic opcodes" (detractor) needs nuance.** PHP's OPcache optimizer does perform constant folding, dead code elimination at the opcode level, and some inter-procedure optimizations for cached files. The opcache.opt_debug_level option can display optimized opcode sequences. What PHP lacks is *link-time optimization* (whole-program analysis across files) and *dead code elimination* at the symbol level (tree-shaking). The detractor is correct that PHP cannot eliminate entire unused functions or classes the way a compiled language can, but the claim that constant folding is absent is inaccurate—the OPcache optimizer performs `CONSTANT_EXPRESSION` folding.
  - **The JIT production stability claim from STITCHER-JIT is dated.** The detractor cites "Sporadic and unexplainable 503 errors" from a blog post about PHP 8.0 JIT stability. PHP 8.4's IR-based JIT represents a substantial rewrite of the JIT infrastructure, specifically addressing stability issues from PHP 8.0. The practitioner's more current observation—"Most teams disable JIT or leave it at default (conservative) settings because the benefits are negligible and debugging JIT-compiled code is harder"—is the more accurate current state of practitioner experience.
  - **Startup time comparison conflates execution models.** The apologist and practitioner both discuss startup time, but there are actually three distinct startup scenarios with very different characteristics:
    1. PHP-FPM workers (pre-forked): Near-zero per-request startup; workers start once at process launch and persist.
    2. Traditional CGI/CLI: Full PHP interpreter init per invocation (~5-50ms).
    3. Serverless (AWS Lambda/Bref): Cold start 100-300ms including runtime initialization and dependency loading.
    The council discussions mix these scenarios. The "5-50ms" figure is most accurate for scenario 2 and partially for scenario 3. Scenario 1 (the dominant production model) effectively has zero per-request startup time, which is the apologist's implicit claim but is not clearly stated.

- **Additional context:**
  - The council does not address PHP 8.4's JIT improvements specifically. PHP 8.4 (released November 2024) introduced an IR-based JIT compilation pipeline inspired by the DynASM assembler approach, replacing the older tracing JIT approach. This is architecturally significant: the new JIT can perform better register allocation and optimization but has different warmup characteristics. Benchmarks for PHP 8.4 JIT show better results in some scenarios than the PHP 8.0/8.1/8.2 data cited by most council members.
  - The council's performance discussion for Section 9 is largely I/O-bound workload focused, which is appropriate for PHP's primary use case. However, the historian's observation about JIT being "the right feature for the wrong use case" deserves elaboration: PHP's JIT was implemented primarily by Dmitry Stogov as a proof of concept for applying LLVM-style optimization to PHP. Its value is more in enabling future performance work (particularly with typed properties and union types providing more type information at opcache-compile time) than in immediate web request speedup. The council misses this forward-looking context.

---

### Other Sections (compiler/runtime issues in other sections)

**Section 2: Type System — Runtime enforcement vs. compile-time guarantees**

Several council members discuss PHP's gradual type system. A compiler/runtime clarification is warranted: in PHP, all type declarations (function parameter types, return types, typed properties) are enforced at *runtime*, not compile time. The OPcache does not perform type inference or cross-function type checking. Even with `declare(strict_types=1)`, type checking occurs when a function call is dispatched, not when the script is compiled to opcodes.

This has a concrete performance implication: typed properties (PHP 7.4+) add a runtime type check on every property write, which has measurable overhead for write-heavy object graphs. The apologist describes typed properties as enabling "engine optimizations"—this is partially true (the engine can avoid boxing checks in some JIT scenarios), but the primary effect is correctness checking at dispatch time, not compile-time elimination.

The detractor correctly notes that "No compiler support for checking that blocking operations aren't called in async contexts." This is a type system limitation, not just a concurrency limitation: without async/await type coloring, the type system has no mechanism to encode "this function blocks" vs. "this function yields."

**Section 7: Security Profile — C extension trust boundary**

The historian accurately notes that "memory-related vulnerabilities in PHP are almost exclusively in C extensions." This is a compiler/runtime observation the security discussion should incorporate more explicitly: PHP's runtime safety guarantees are only as strong as its weakest C extension. CVE-2024-4577 is a CGI argument injection vulnerability in the PHP binary itself (written in C), not in userland PHP code. The 458,800 exposed instances [CVE-PHP] reflect a vulnerability in the C runtime layer that PHP's memory safety abstractions do not protect against. Any language that FFI-bridges to C or uses native extensions inherits this vulnerability surface.

**Section 10: Interoperability — FFI cost model**

The practitioner's estimate of "1-10µs" FFI call overhead deserves scrutiny. PHP FFI uses `libffi`, which introduces a calling convention translation layer. The overhead depends heavily on argument marshaling: simple numeric arguments have lower overhead; PHP string/array-to-C-pointer marshaling has higher overhead. The 1-10µs range is a reasonable estimate for simple calls but can be higher for complex data marshaling. The more significant concern (acknowledged by the practitioner) is that FFI bypasses PHP's memory safety entirely—any crash in FFI code is a process-level crash that PHP cannot recover from.

---

## Implications for Penultima

**1. Scope boundaries as a first-class memory management primitive.**
PHP's request-scoped arena demonstrates that restricting object lifetime to a well-defined scope boundary enables efficient bulk deallocation with minimal GC pressure. This is not unique to PHP—arenas are used in game engines, compilers, and system software—but PHP demonstrates it at language scale for a mainstream audience. Penultima should consider making scope-bounded memory regions a first-class construct, not just a library optimization. The key insight from PHP is that *knowing when memory is unreachable* (request end, scope exit) is more powerful than tracking *which memory is unreachable* (GC traversal). For Penultima, this suggests that lifetime annotations (similar to Rust's, but potentially more ergonomic) or scope-tagged allocation regions could provide PHP-like efficiency without PHP's inflexibility when request boundaries are absent.

**2. The ecosystem-level colored function problem cannot be designed away at the language level alone.**
PHP's Fiber RFC avoided language-level function coloring—an explicit design goal—yet the ecosystem has recreated the coloring problem through incompatible I/O libraries (blocking `mysqli` vs. async `Swoole\Coroutine\MySQL`). This is a fundamental tension: cooperative concurrency requires distinguishing blocking from non-blocking I/O, and that distinction must exist somewhere in the system. Penultima should recognize that moving the coloring from the language type system to the library convention layer trades compile-time checking for runtime surprise. A cleaner approach (as in Go's goroutine scheduler or Rust's async executor) is to make blocking/non-blocking transparent to the caller through language-level primitives that can suspend rather than block. The lesson is not "don't color functions" but "make the coloring cheap and universal."

**3. JIT on dynamic types yields diminishing returns without type information at opcache time.**
PHP's JIT provides substantial benefit only for CPU-intensive, type-stable hot paths—exactly the scenarios where a statically-typed language would have already applied AOT optimization. For typical PHP web requests (short-lived, heavily polymorphic dispatch, I/O-dominated), JIT compilation cost is not amortized and may degrade performance. The root cause is that PHP's JIT cannot specialize on types it doesn't know at compile time; it must generate type-checking guards or fall back to interpreted dispatch. Penultima's compilation model should decide early whether it targets AOT (with type information available globally at compile time), a profile-guided JIT (requiring warmup), or a combination. PHP demonstrates that adding JIT to an already-deployed dynamic language is engineering-expensive and yields limited universal benefit—the value proposition is stronger when JIT is part of the original language design.

**4. The C extension trust boundary is a security architecture decision, not an implementation detail.**
PHP's safety guarantees apply only to pure PHP userland code. The boundary between managed PHP code and unmanaged C extension code is invisible to users and creates a false sense of security—the language feels memory-safe, but the runtime can crash from extension bugs. Penultima should make this boundary explicit if native interop is supported: either through language-level `unsafe` annotations (Rust approach), sandboxed extension APIs with bounded trust, or a formal specification of what safety properties hold across the FFI boundary. Hiding this distinction behind a uniform interface, as PHP does, creates a misleading safety narrative.

**5. Compilation model determines optimization ceiling.**
PHP's lack of whole-program analysis (no link-time optimization, no tree-shaking, no inter-file type inference at OPcache time) caps the optimization ceiling. Individual function optimization (JIT specialization) cannot compensate for missed whole-program opportunities. Penultima's compilation architecture should determine early whether cross-module optimization is in scope, as this decision propagates through the type system design (open vs. closed world assumption), the module system, and the deployment model.

---

## References

- [PHP-MEMORY] PHP Manual: Memory Management. https://www.php.net/manual/en/features.gc.php
- [PHPMANUAL-GC] PHP Manual: Garbage Collection. https://www.php.net/manual/en/features.gc.collecting-cycles.php
- [PHP-FFI] PHP Manual: Foreign Function Interface. https://www.php.net/manual/en/book.ffi.php
- [PHP-FIBERS] PHP Manual: Fibers. https://www.php.net/manual/en/language.fibers.php
- [PHP-RFC-FIBERS] PHP RFC: Fibers (PHP 8.1). https://wiki.php.net/rfc/fibers
- [PHP7-PERFORMANCE] Nikita Popov: PHP 7 Internal Value Representation. https://nikic.github.io/2015/05/05/Internal-value-representation-in-PHP-7-part-1.html
- [PHP7-BENCHMARKS] TechEmpower Web Framework Benchmarks, Round 23 (March 2025). https://www.techempower.com/benchmarks/
- [BENCHMARK-PILOT] Penultima Evidence Repository: Performance Benchmark Reference: Pilot Languages. evidence/benchmarks/pilot-languages.md
- [CVE-PHP] Penultima Evidence Repository: CVE Pattern Summary: PHP. evidence/cve-data/php.md
- [DEVSURVEY] Penultima Evidence Repository: Cross-Language Developer Survey Aggregation. evidence/surveys/developer-surveys.md
- [JIT-SYMFONY] PHP 8.4 JIT Under the Microscope — Benchmarking Real Symfony Applications. https://medium.com/@laurentmn/php-8-4-jit-under-the-microscope-benchmarking-real-symfony-7-4-applications-part-1-c685e1326f5e
- [STITCHER-JIT] Brent Roose: PHP JIT in Real Life (stitcher.io). Referenced in detractor evidence as STITCHER-JIT.
- [SWOOLE] Swoole Documentation: Coroutines and Async Runtime. https://swoole.com/
- [REACTPHP-ASYNC] ReactPHP: Event-Driven, Non-Blocking I/O. https://reactphp.org/
- [AMP-ASYNC] Amp: Asynchronous concurrency framework for PHP. https://amphp.org/
- [NETGURU-NODEJS] Netguru: Node.js vs PHP Performance Comparison. Referenced in detractor as NETGURU-NODEJS. Note: based on PHP 7.4 data; current PHP 8.x comparisons differ.
