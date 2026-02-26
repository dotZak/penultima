# Internal Council Report: PHP

```yaml
language: "PHP"
version_assessed: "PHP 8.3"
council_members:
  apologist: "claude-agent"
  realist: "claude-agent"
  detractor: "claude-agent"
  historian: "claude-agent"
  practitioner: "claude-agent"
schema_version: "1.0"
date: "2026-02-26"
```

---

## 1. Identity and Intent

### Origin and Context

PHP began in 1994 when Rasmus Lerdorf created a set of C-based CGI binaries to track visits to his online resume. He called these tools "Personal Home Page Tools" [LERDORF-HISTORY]. By 1995, he had rewritten them to include form-handling and database access, calling the result "Personal Home Page / Forms Interpreter" (PHP/FI) [PHP-MANUAL-HISTORY]. The language expanded through community contribution when Zeev Suraski and Andi Gutmans rewrote the core parser for PHP 3 in 1997, transforming a personal tool into a community project [PHP-HISTORY].

Lerdorf's own words from a 2003 interview define the terms of all subsequent PHP analysis: "I really don't like programming. I built this tool to program less so that I could just reuse code [...] There was never any intent to write a programming language [...] I just kept adding the next logical step on the way" [CODEMOTION-25YEARS]. This is not false modesty. The evidence is in the design itself: PHP's function names are case-insensitive because HTML is case-insensitive, and Lerdorf designed it "for being case insensitive in function names" since PHP was meant to be embedded in HTML templates [CODEMOTION-25YEARS].

Understanding the 1994-1995 web development context is essential to fair evaluation. Developers then faced a stark choice: static HTML, or Perl CGI scripts with explicit HTTP header management, process-per-request overhead, and steep syntax demands. PHP offered a third path—embed small snippets directly in HTML, get results immediately. The alternative was not a better-designed dynamic language; the alternative was substantially more friction. PHP's rapid adoption reflects a genuine gap it filled, not merely marketing [HISTORIAN].

### Stated Design Philosophy

PHP's design philosophy, as it emerged and was later articulated, prioritized:
- Immediate problem-solving over theoretical elegance
- Direct web integration (HTTP, HTML, databases) over general-purpose abstraction
- Low barrier to entry over type safety or formal correctness
- Backward compatibility over breaking changes

As Lerdorf stated: "In the end, what I think set PHP apart in the early days, and still does today, is that it always tries to find the shortest path to solving the Web problem. It does not try to be a general-purpose scripting language" [LERDORF-SITEPOINT]. This is the correct frame for evaluating most PHP design decisions: they make sense for a templating system that grew into a web language, and many look inexplicable only when evaluated against the standards of a general-purpose programming language designed from scratch.

### Intended Use Cases

PHP was designed for server-side web development, specifically dynamic HTML generation tied to form processing and database access. By 2026, PHP powers 74.5-77.5% of all websites with a known server-side programming language, representing over 33 million live websites [DEVSURVEY]. WordPress alone, written in PHP, powers approximately 43% of all websites globally. This is dominance achieved by solving its stated problem better than 1990s alternatives, not by corporate backing or marketing.

Modern PHP has drifted substantially from its origin. With PHP 8.x and frameworks like Laravel and Symfony, developers build REST APIs, GraphQL services, CLI tools, worker queues, and long-running async services—use cases never envisioned in 1994. The addition of Fibers (PHP 8.1) for cooperative concurrency, JIT compilation (PHP 8.0), and property hooks (PHP 8.4) represents genuine evolution toward a more general-purpose platform. This drift has been partially successful, though the web remains PHP's primary domain and most of its design decisions remain web-optimized.

### Key Design Decisions

**1. Request-scoped, shared-nothing execution model.** Every request starts with a fresh process; state does not persist between requests by default. This decision eliminates entire classes of bugs—memory leaks, state corruption, inter-request race conditions—and provides automatic resource cleanup. The cost is per-request initialization overhead, partially mitigated by OPcache and PHP-FPM worker pooling.

**2. Dynamic typing with gradual strictness.** Defaults to type coercion; allows opt-in strict typing per file via `declare(strict_types=1)`. This design allowed PHP to begin as a quick templating tool and gradually acquire type discipline as its use cases matured. The cost is a bifurcated ecosystem and type juggling vulnerabilities in code not using strict mode.

**3. Case-insensitive function names and HTML integration.** Explicit decision to coexist within HTML templates; HTML is case-insensitive, and PHP was embedded within it. Creates chaos in a general-purpose language but was correct for the original templating use case [CODEMOTION-25YEARS].

**4. Associative arrays as the universal data structure.** A single structure serves as indexed array, dictionary, set, and ordered map. Simplicity and JSON compatibility are real advantages; the cost is no distinction between empty array and empty dict, and hash-table semantics where contiguous-memory semantics would serve better.

**5. Permissive defaults for maximum accessibility.** No automatic output escaping, loose type comparisons by default, `register_globals` and `magic_quotes` in early versions. These choices lowered the barrier to entry spectacularly while creating security vulnerabilities at enormous scale. The full cost of these defaults is documented in Section 7.

**6. Backward compatibility as a near-absolute constraint.** PHP has removed bad features—`register_globals` (PHP 5.4), `mysql_*` functions (PHP 7.0), `magic_quotes` (PHP 5.4)—but only after years of deprecation warnings. Known mistakes like type juggling in the `==` operator and inconsistent stdlib naming are now effectively permanent, as fixing them would break too much existing code. This produces a language that accumulates technical debt at the margins while modernizing at the center.

---

## 2. Type System

### Classification

PHP's type system is dynamic with gradual static typing capabilities, weak by default with strong enforcement available, and primarily structural for primitive types with nominal class hierarchies. The correct modern characterization is: dynamic language with an opt-in, gradually expanding strict type layer [REALIST].

PHP 8.x (as of 8.3) provides:
- Union types: `int|string|null` (PHP 8.0)
- Intersection types: `Countable&Traversable` (PHP 8.1)
- DNF types combining unions and intersections (PHP 8.2)
- Enumerations with optional backing type (PHP 8.1)
- `never`, `mixed`, `void`, `null` as first-class types
- Readonly properties and readonly classes (PHP 8.1-8.2)
- Named arguments (PHP 8.0)

### Expressiveness

The type system ceiling is low compared to languages like TypeScript, Rust, or Haskell. PHP has no generics, no template types, no parameterized classes, no higher-kinded types, and no pattern matching with exhaustiveness checking. There is no way to express "an array of T" generically without resorting to docblock annotations (`@param array<int, User>`), which are community conventions recognized by static analyzers but not enforced by the language itself [REALIST].

Enums (PHP 8.1) are a genuine improvement—they eliminate magic constants and make intent explicit. The `match` expression (PHP 8.0) improves on `switch` by throwing `UnhandledMatchError` on non-matching values rather than falling through silently. These are real quality-of-life improvements with pedagogical significance: they model correct practice rather than permissive behavior [PEDAGOGY-ADVISOR].

### Type Inference

PHP's type inference is minimal. The runtime tracks types dynamically, but the language provides no compile-time inference. Static analyzers PHPStan and Psalm perform global inference using docblock annotations, but these are community conventions, not part of the language specification. PHPStan adoption jumped to 36% in 2025, up 9 percentage points from 2024 [DEVSURVEY], indicating increasing developer desire for stronger type guarantees than the language itself provides.

The lack of inference means PHP developers must explicitly annotate more than in languages like TypeScript or Kotlin, which is partly a design choice (explicit signatures improve readability) and partly a limitation (no annotation still works, it just means less checking).

### Safety Guarantees

**What the type system prevents:**
- At runtime with strict mode: type mismatches in function arguments when `strict_types=1` is enabled at the call site
- With static analysis: null pointer errors, type confusion, undefined method calls—but only if using PHPStan/Psalm

**What the type system does not prevent:**
- Type juggling bugs when using `==` instead of `===` (partially addressed in PHP 8.0—see advisor correction below)
- Passing wrong types in non-strict mode
- Array key errors (associative arrays are untyped by key)
- Standard library argument order errors (both `strpos` and `array_search` accept strings; swapping them passes the type checker but produces wrong results)

**Advisor correction on PHP 8.0 type comparison fix [SECURITY-ADVISOR]:** PHP 8.0 changed `0 == "non-numeric-string"` to return `false` (previously `true`), closing a significant authentication bypass vector. The "Saner String to Number Comparisons" RFC (passed 44-1) directly addressed the "magic hash" family of vulnerabilities. Council members who characterize type juggling as entirely unfixed in PHP 8 are incorrect about this specific case. However, loose comparison in PHP 8 still produces: `"1" == true`, `"" == false`, `"0" == false`, `null == false`, `null == ""`, `0 == null`—all true. The non-transitivity property (A == B and B == C does not imply A == C) remains [EEVEE-2012]. Type juggling is partially addressed, not resolved.

**Advisor correction on `declare(strict_types=1)` scoping [PEDAGOGY-ADVISOR]:** The apologist's claim that PHP "implements true gradual typing correctly" overstates the implementation. `declare(strict_types=1)` applies to calls *made from the declaring file*, not to the function definitions within that file. Whether a function call is type-checked depends on where the call site is, not where the function is defined. A developer reading a function signature cannot determine whether type enforcement is active without also checking the calling file. A correctly designed gradual type system would scope strictness to function definitions.

### Escape Hatches

- `mixed` type explicitly accepts any value
- Absence of `declare(strict_types=1)` allows implicit coercion
- `@phpstan-ignore-next-line` and `@psalm-suppress` annotations bypass static analysis
- Dynamic property access via `$$variable` syntax
- `call_user_func()` and `call_user_func_array()` with string function names

The realist's evidence that approximately 42% of developers do not use strict mode indicates type juggling is active in a large fraction of PHP code in the wild [REALIST]. (Note: the realist's citation requires verification; the pedagogy advisor flags this statistic as needing a source [PEDAGOGY-ADVISOR].)

### Impact on Developer Experience

The gradual type system is simultaneously PHP's greatest pragmatic strength and its most significant source of bugs. Modern frameworks (Laravel, Symfony) embrace types heavily and the IDE experience with typed PHP code is excellent—PHPStorm and VS Code with Intelephense provide world-class autocomplete, inline errors, and refactoring. The problem is the default path: without `declare(strict_types=1)`, PHPStan, and a quality IDE, PHP code is written and read in a mode where the type system provides minimal guarantees. Two different PHP codebases—one fully typed with maximum static analysis, one untyped legacy—are barely the same language in practice.

---

## 3. Memory Model

### Management Strategy

PHP uses automatic reference-counted garbage collection with cycle detection added in PHP 5.3 [PHP-MEMORY]. Every value in PHP has a reference count (`refcount`) tracking how many variables point to it. When `refcount` reaches zero, memory is immediately freed [PHPMANUAL-GC]. For circular references, a mark-and-sweep garbage collector activates when a threshold of "possible cycles" is reached—approximately 10,000 possible cycles—not on every allocation [PHPMANUAL-GC].

Copy-on-write (COW) semantics apply to strings and arrays: sharing a value without modifying it does not trigger a copy. This design provides both memory efficiency and developer simplicity.

The PHP 7.0 redesign of internal data structures (the `zend_value` union and HashTable structures) produced approximately 50% memory reduction across the board and roughly 2x throughput improvement [PHP7-PERFORMANCE]. The historian and realist correctly attribute this improvement to better cache behavior and more compact internal representations.

**Advisor note on OPcache memory [COMPILER-RUNTIME-ADVISOR]:** The council underweights a significant architectural detail: PHP's memory model actually comprises three distinct domains, not one heap. (1) The per-request heap, bulk-freed at request end via `zend_mm_heap`. (2) The OPcache shared memory segment (default 128MB), which persists across requests and stores bytecode. (3) Persistent extension memory allocated via `pemalloc`. Understanding this tripartite structure is important for accurate reasoning about PHP's memory behavior, particularly in server contexts where OPcache is the dominant memory consumer between requests.

### Safety Guarantees

PHP provides strong memory safety guarantees within userland PHP code:
- No use-after-free: impossible in userland; reference counting ensures memory remains valid while referenced
- No double-free: impossible; memory management is automatic
- No dangling pointers: impossible; no pointers exist in userland PHP
- No buffer overflows in PHP arrays: PHP arrays are bounds-checked; accessing a non-existent key creates the key (or returns null/warning) rather than overwriting memory

**Advisor correction on safety scope [COMPILER-RUNTIME-ADVISOR]:** The apologist's claim that use-after-free, double-free, and dangling pointers are "Impossible" as blanket guarantees conflates the userland PHP layer with the full PHP runtime. The correct claim is: no use-after-free in *pure PHP userland code*. CVE data for PHP confirms that buffer overflows and use-after-free vulnerabilities regularly appear in the C extension layer (GD, ImageMagick, XML parsers, the PHP runtime itself) [CVE-PHP]. CVE-2024-4577 (CVSS 9.8) is a vulnerability in the PHP binary's CGI-mode argument parsing—C code—not userland PHP [SECURITY-ADVISOR]. The safety guarantee applies only to the PHP-managed execution layer.

PHP does not prevent:
- Memory exhaustion: a script can allocate until `memory_limit` is hit
- Cyclic memory leaks if GC is disabled (`gc_disable()`)
- Data races via shared memory extensions (`shmop`, APCu) or external shared resources (databases, files, Redis)

### Performance Characteristics

Allocation overhead is low for small objects; PHP uses slab allocation for common sizes. The cycle collector causes brief pauses when triggered (milliseconds for large object graphs), not continuous stop-the-world pauses.

**Advisor correction on JIT and allocation pressure [COMPILER-RUNTIME-ADVISOR]:** The apologist claims "PHP 8.0 JIT reduces allocation pressure by compiling hot paths." This characterizes JIT inaccurately. PHP's JIT compiles hot code paths to native machine code, reducing CPU overhead from opcode interpretation. It does not directly reduce heap allocation pressure—`new` operations and array constructions still invoke the Zend Memory Manager regardless of JIT status. What JIT can do indirectly is eliminate some intermediate zval boxing through specialization, which reduces some intermediate allocations on hot paths—but the apologist's phrasing overstates this as a memory management improvement.

For long-running CLI processes and worker queues, PHP can accumulate memory from uncollected cycles. The standard mitigations are explicit `gc_collect_cycles()` calls and periodic worker restarts. This is an "escape from automatic memory management" pattern—unusual but necessary for non-request-scoped PHP.

**Advisor correction on O(n²) string concatenation [COMPILER-RUNTIME-ADVISOR]:** The detractor claims that "string concatenation and array operations can trigger O(n²) memory copies for long-running operations." This is technically possible: PHP's `$str .= $fragment` in a tight loop can produce O(n²) behavior because each concatenation may require a full string copy. However, the standard solution—`implode()` or array accumulation—eliminates it. This is a developer pattern issue, not a fundamental memory model flaw. Python and Java have similar pathologies with naive string concatenation.

### Developer Burden

PHP developers almost never think about memory in request-scoped applications. No malloc/free, no ownership types, no arena lifetimes. The cognitive load is near zero for typical web development. The burden increases for long-running processes and when working with FFI (see below).

### FFI Implications

PHP FFI (PHP 7.4+) creates a sharp ownership boundary: PHP manages PHP-side memory automatically via reference counting; C-side memory allocated via `FFI::new()` is the developer's responsibility and is not tracked by the Zend Memory Manager [PHP-FFI]. Any crash in FFI code is a process-level crash that PHP cannot recover from. FFI bypasses PHP's memory safety entirely. This is not a niche concern—the FFI boundary is where PHP's safety guarantees end, and the C extension trust boundary is a security architecture decision, not an implementation detail [COMPILER-RUNTIME-ADVISOR].

---

## 4. Concurrency and Parallelism

### Primitive Model

PHP offers multiple concurrency models as of 2026, none of which has become a universal standard:

**1. Shared-nothing process model (PHP-FPM).** The traditional and dominant model. Each HTTP request gets a fresh PHP-FPM worker process with isolated memory. Concurrency is achieved by running multiple workers. No shared state between workers at the PHP level. This is the model that powers the vast majority of production PHP deployments.

**2. Fibers (PHP 8.1).** Lightweight, cooperative coroutines within a single process. A Fiber maintains its own stack (~4KB, versus 1-2MB for OS threads) and can be suspended via `Fiber::suspend()` and resumed. Switching between Fibers requires changing approximately 20 pointers—substantially cheaper than process or thread context switches. The PHP RFC explicitly designed Fibers to avoid async/await syntax and avoid "coloring" functions at the language specification level [PHP-RFC-FIBERS].

**3. Swoole.** A C extension providing an async HTTP server with coroutines, connection pooling, and non-blocking I/O. Handles 10,000+ concurrent connections per process when properly configured [SWOOLE]. Requires compilation and framework lock-in; not purely PHP.

**4. ReactPHP and Amp.** Pure-PHP event loop and async concurrency frameworks. ReactPHP (2012) is battle-tested; Amp v3 is designed around PHP 8.1+ Fibers.

**5. FrankenPHP.** A newer approach combining Go's `net/http` server with PHP embedding, achieving concurrency through Go's goroutine scheduler rather than PHP Fibers. A qualitatively different architectural model.

### Data Race Prevention

The shared-nothing model prevents data races by design in traditional PHP-FPM deployment. OS-level process isolation means PHP-FPM workers cannot share mutable state without going through an external system (database, Redis, APCu with careful locking). This is a genuine architectural safety property [SECURITY-ADVISOR].

Fibers introduce intra-process shared state with race risks. Fibers share process memory; cooperative scheduling limits (but does not eliminate) race windows. PHP provides no native concurrency primitives—no mutexes, no channels, no STM—to manage shared Fiber state.

**Advisor correction on shared-nothing safety scope [SECURITY-ADVISOR]:** All council members who praise shared-nothing isolation should note that shared state commonly exists via: databases, Redis/Memcached, PHP's `shmop`/`shmem` extensions, APCu shared memory cache, and files. Race conditions on these external shared resources are common in PHP applications and are not addressed by the shared-nothing process model. The model prevents *in-process* races; it does not prevent races on external shared resources, where most application-level concurrency bugs actually occur.

### Ergonomics

Traditional PHP concurrency is trivial: write synchronous code; the web server handles parallelism. No callbacks, no promises, no event loop management. For web applications, this is ideal.

Fiber-based concurrency is substantially more complex. Developers must identify suspension points, ensure all I/O calls use async-safe implementations, and manage Fiber lifecycle. Common pitfalls include accidentally calling blocking functions (e.g., `file_get_contents()`) within an async context, which blocks the entire event loop.

### Colored Function Problem

**Advisor correction on the colored function contradiction [COMPILER-RUNTIME-ADVISOR]:** The realist states "PHP does not have the async/sync divide that plagues JavaScript/Python. Fiber suspension is explicit but does not 'color' functions." The practitioner states the colored function problem is "Severe in Swoole/ReactPHP/Amp." Both statements are accurate but address different layers, and the council does not resolve this distinction.

The correct framing: PHP Fibers do not color functions at the *language specification level*. A function that calls `Fiber::suspend()` internally looks identical in signature to a function that does not—this was an explicit design goal of the Fiber RFC. However, any function that calls a blocking I/O operation (e.g., `file_get_contents()`, a blocking MySQL query via `mysqli`) will block the entire event loop if called within an async runtime. This creates a *de facto* coloring at the ecosystem level: libraries must choose async-safe implementations of I/O or they will silently serialize execution. Swoole provides `Swoole\Coroutine\Http\Client`; code using standard `file_get_contents()` in a Swoole coroutine blocks. This is functionally identical to the colored function problem even if PHP's Fiber API does not syntactically enforce it.

PHP has deferred the coloring from the language type system to the library convention layer. This is a different tradeoff, not an elimination of the problem. Penultima should recognize this distinction.

### Structured Concurrency

Not built into the PHP language. Async libraries implement structured concurrency patterns (Amp's task groups, ReactPHP's combinators), but the language provides no native enforcement. Leaked Fibers and unhandled exceptions in async contexts are common in production async PHP code.

### Scalability

The shared-nothing architecture scales horizontally by adding more workers, limited by external resources (database connections, memory per worker). PHP-FPM with OPcache handles approximately 1,000 requests/second/core for typical web applications; the bottleneck is almost always the database, not PHP execution [PRACTITIONER].

Fiber-based systems (Swoole, Amp) show substantial gains for I/O-bound workloads. A documented real-world example reduced an RSS aggregator from 10+ seconds to under 3 seconds [REALIST]. These improvements are genuine, but they require framework lock-in and significantly increase complexity.

**Advisor correction on benchmark currency [COMPILER-RUNTIME-ADVISOR]:** The detractor's claim that "Node.js executes API requests 3x faster than PHP 7.4 (31ms vs 91ms)" cites end-of-life PHP 7.4 data. TechEmpower Round 23 (March 2025) shows PHP frameworks at 5,000-15,000 RPS versus Node.js/Express at 20,000-40,000 RPS—a 2-4x difference for current PHP 8.x, not 3x for PHP 7.4 [BENCHMARK-PILOT].

---

## 5. Error Handling

### Primary Mechanism

PHP employs a layered hybrid model that evolved over four distinct eras, creating the inconsistency practitioners experience today.

**Historical evolution [HISTORIAN]:**
- Era 1 (1995-2004): C-style `E_NOTICE`, `E_WARNING`, `E_ERROR`. Fatal errors terminated; no structured recovery.
- Era 2 (2004-2014): PHP 5 introduced exceptions and `try`/`catch`, but core functions still returned `false` on failure, not exceptions. The split between exception-throwing new code and warning-returning built-in functions begins here.
- Era 3 (2015-2020): PHP 7.0 introduced the `Throwable` interface with `Exception` (recoverable) and `Error` (programming mistakes, formerly fatal). Type errors, division by zero, and other previously fatal errors became catchable.
- Era 4 (2021-present): PHP 8.0 and 8.1 upgraded many warnings to `TypeError` or `ValueError`, improving fail-fast behavior. `null` operations that previously issued warnings now throw exceptions.

**Current state:** Exceptions are the preferred mechanism for modern PHP code. Frameworks (Laravel, Symfony) use exceptions throughout. Legacy code and many built-in functions use the warning/return-false pattern. A single codebase can use all three paradigms simultaneously.

### Composability

Exception propagation works well. The `throw` statement unwinds the stack until a matching `catch` block, `finally` ensures cleanup. PHP lacks Rust's `?` operator, requiring explicit `try`/`catch` or `throw` at every error boundary.

Warnings and notices do not compose. They emit to output or logs but do not propagate through the call stack. This creates a disjoint model: some errors are exceptions, some are warnings, and correct handling requires knowing which category any given function uses.

### Information Preservation

Exceptions preserve full stack traces, exception chaining (via `getPrevious()`), and custom contextual data. Tools like Sentry and Bugsnag extract full causal chains automatically.

Warnings and notices log messages without structured stack context unless error handlers are configured via `set_error_handler()` to convert them to exceptions (a workaround for the inconsistency, not an intended API). PHP 8.0 improved argument naming in error messages: `substr(): Argument #2 ($start) must be of type int, array given` versus the old terse format [PEDAGOGY-ADVISOR].

### Recoverable vs. Unrecoverable

PHP distinguishes `Exception` (recoverable errors) from `Error` (programming mistakes), but both implement `Throwable` and both can be caught. There is no language-enforced distinction preventing `catch (Throwable $t)` from swallowing fatal errors. The distinction is semantic, not enforced.

### Impact on API Design

The standard library's inconsistency in error handling is a genuine structural problem: `file_get_contents()` returns `false` on error; `json_decode()` returns `null` and requires `json_last_error()` for diagnosis; PDO can be configured to throw or return `false`. Every function requires documentation consultation for error behavior. Frameworks mitigate this by providing consistent exception-throwing wrappers.

### Common Mistakes

- **Empty catch blocks:** Swallowing exceptions silently. Static analyzers flag these, but legacy code is full of them.
- **Overly broad catches:** `catch (Throwable $t)` hides logic errors alongside expected failures.
- **Ignored return values:** Functions returning `false` on error are frequently called without checking. The CVE evidence documents injection vulnerabilities enabled by ignored error returns [CVE-PHP].
- **Missing `finally` cleanup:** Resources leaked when exceptions occur on exception paths not covered by catch blocks.
- **Mixed error modes:** Single codebases using exceptions, return values, and warnings inconsistently because different eras of code coexist.

**Advisor note [PEDAGOGY-ADVISOR]:** The dual error-handling model creates genuine teachability friction that the council underweights. A learner who understands exception handling will write `try`/`catch` and miss file operation errors that emit warnings rather than throwing. The `set_error_handler()` and `ErrorException` conversion pattern bridge the gap but are incidental complexity—a workaround for a design inconsistency. The lesson from PHP's error handling history is not just "choose one mechanism" but "choose it before you accumulate a decade of code using the other mechanism, because you cannot change it afterward without breaking everything."

---

## 6. Ecosystem and Tooling

### Package Management

Composer (launched 2011) is PHP's dependency manager and among its genuine success stories. Packagist.org hosts over 500,000 packages (the "400,000+" figure cited by the apologist and realist is now an undercount as of 2026 [SYSTEMS-ARCHITECTURE-ADVISOR]). The lock file model prevents version drift; PSR-4 autoloading eliminated manual `require` statements; semantic versioning with flexible constraints provides precise dependency specification.

**Advisor correction on `composer audit` [SYSTEMS-ARCHITECTURE-ADVISOR]:** Both the detractor and realist state that Composer has no built-in security auditing command. This was accurate until Composer 2.4 (released September 2022), which added a native `composer audit` command querying the GitHub Advisory Database. The specific factual claim is now outdated. The real gaps—package signing, automated malware detection at ingestion time, monorepo support—remain real but differ from what the council describes.

**Advisor correction on npm security comparison [SECURITY-ADVISOR]:** The detractor's claim that "Packagist has no malware scanning comparable to npm's" overstates npm's security posture. npm has been a vector for high-profile supply chain attacks (event-stream, ua-parser-js, colors.js/faker.js). Neither Composer nor npm provides reliable automated malware detection at package ingestion time. Both ecosystems have structural supply chain weaknesses.

Composer limitations that remain accurate: dependency resolution is slow for large projects (5+ minutes for enterprise codebases); monorepo support is poor compared to Cargo workspaces or Nx; platform requirement mismatches create "works on my machine" issues.

### Build System

PHP has no standard build system for pure PHP code. "Building" PHP typically means running `composer install`, compiling assets via Node.js tools (Vite, Webpack), and generating framework configuration caches. Every project invents its own build process, creating per-project bespoke tooling that fragments team knowledge and increases onboarding cost [SYSTEMS-ARCHITECTURE-ADVISOR].

### IDE and Editor Support

PhpStorm (JetBrains) is widely regarded as best-in-class for PHP: deep PHP integration, Laravel/Symfony plugins, refactoring tools, database GUI. VS Code with Intelephense (paid for premium features) is the most popular free alternative. LSP implementations (Intelephense, Psalm Language Server, PHPActor) enable consistent editor support across Vim, Emacs, and Sublime Text.

Autocomplete and navigation are excellent when types are present, mediocre otherwise. Dynamic PHP features (`$$variable`, `call_user_func`) break static analysis and degrade IDE quality.

**Advisor note [DETRACTOR]:** Note what PhpStorm compensates for: type inference to recover generics; error detection for standard library functions because PHP's weak mode allows type errors at runtime; more conservative rename refactoring than statically typed languages because `$$foo` syntax means static analysis cannot guarantee correctness. The IDE compensates for language-level gaps at substantial tooling cost.

### Testing Ecosystem

PHPUnit is the standard testing framework since 2004. Pest (2017) is gaining rapid adoption, particularly in the Laravel ecosystem, with a more concise functional syntax. Coverage tools include Xdebug (richer data, significantly slows execution) and PCOV (faster, development-only). Property-based testing exists (Eris) but sees minimal adoption. Mutation testing (Infection PHP) is gaining traction among quality-focused teams.

Testing culture is bimodal: Laravel and Symfony projects tend toward 60-80% test coverage; WordPress plugins often have 0% coverage. Survey data shows 32% of PHP developers do not write tests at all [DEVSURVEY].

### Debugging and Profiling

Xdebug is the primary step debugger. Xdebug 3 (2020) improved performance and configuration, but it still slows execution 3-10x, making it unsuitable for production use. Developers frequently debug via `var_dump()` and logging because Xdebug's overhead makes interactive debugging inconvenient.

Profiling tools: Blackfire.io and Tideways (commercial, excellent for production), XHProf (open-source, unmaintained). No native language-level tracing or metrics primitives exist [SYSTEMS-ARCHITECTURE-ADVISOR]. All observability requires external APM tooling (New Relic, Datadog, Sentry). OpenTelemetry PHP's tracing reached stability and PHP 8+ added `zend_observer` hooks enabling automatic instrumentation, but the absence of built-in observability primitives is a real operational cost.

### Documentation Culture

php.net is comprehensive as a function reference but weaker for concepts. User-contributed notes are prominent and often invaluable but can contain outdated practices. A Quarkslab security review found that php.net user-contributed notes do not consistently enforce error handling and input validation best practices [PEDAGOGY-ADVISOR]. The existence of "PHP: The Right Way" as a community corrective resource is direct evidence that the official onboarding path produces enough bad habits to warrant an explicit corrective guide [PHP-THE-RIGHT-WAY].

Framework documentation for Laravel is industry-leading: comprehensive, versioned, searchable, with practical examples. Symfony's documentation is thorough but dense. WordPress documentation is scattered and inconsistent.

### AI Tooling Integration

95% of PHP developers have tried at least one AI tool; 80% regularly use AI assistants [DEVSURVEY]. ChatGPT leads (49% daily use), followed by GitHub Copilot (29%) and JetBrains AI Assistant (20%). PHP's large corpus of training data produces high-quality code generation for common patterns (CRUD operations, form validation). AI tools struggle with legacy PHP and framework-specific magic (Laravel facades, Symfony dependency injection). The pedagogy advisor notes that PHP's inconsistent naming patterns create a specific challenge for AI assistants: even well-trained models produce argument-order errors in PHP at higher rates than in languages with consistent conventions, because the patterns do not generalize [PEDAGOGY-ADVISOR].

---

## 7. Security Profile

### CVE Class Exposure

PHP's vulnerability profile is dominated by injection-class vulnerabilities. The most common CWE categories affecting PHP applications (2020-2025) [CVE-PHP]:

1. **CWE-79 (XSS):** ~30,000 CVEs. PHP does not auto-escape output; XSS requires explicit `htmlspecialchars()` or framework escaping. The single largest class of PHP CVEs.
2. **CWE-89 (SQL Injection):** ~14,000 CVEs. Deprecated `mysql_*` functions (removed PHP 7.0) lacked prepared statement support; legacy code using string concatenation for queries remains widespread.
3. **CWE-78 (OS Command Injection):** ~1,000+ CVEs. Recent critical example: CVE-2024-4577 (PHP-CGI argument injection, CVSS 9.8) exposed ~458,800 instances as of June 2024 [CVE-PHP, CENSYS-2024].
4. **CWE-98 (RFI/LFI):** Hundreds of active CVEs. `include()` and `require()` with user input remain common. Historical spike in 2006 (~1000% increase). Stream wrappers (`data://`, `php://input`) expand attack surface.
5. **CWE-434 (Unrestricted File Upload):** Thousands of CVEs. PHP's ability to execute uploaded `.php` files directly amplifies risk of insufficient upload validation.
6. **CWE-287/284 (Auth/Access Control):** Tens of thousands across all languages. PHP-specific: historical `register_globals` feature enabled variable overwrite attacks.
7. **CWE-611 (XXE):** Hundreds to low thousands. SimpleXML and DOM libraries enabled external entity processing by default (fixed in later versions).

### Language-Level Mitigations and Their Limits

**Structural security properties PHP provides:**
- Memory safety in userland (no buffer overflows, use-after-free, dangling pointers in PHP code)
- Request-scoped isolation preventing cross-request memory leakage
- Prepared statements via PDO/MySQLi (if used correctly)
- `password_hash()` with bcrypt/Argon2 for passwords (PHP 7.x+)
- libsodium for modern cryptography (PHP 7.2+)
- `random_bytes()` for cryptographically secure randomness

**Structural security gaps PHP does not address:**
- No automatic output escaping: the most consequential default, directly enabling 30,000+ XSS CVEs
- No taint tracking: the type system cannot distinguish a string from `$_GET` from a trusted internal string [SECURITY-ADVISOR]
- No language-level primitive for restricting filesystem or network access
- No memory safety guarantees beyond the PHP/C extension boundary

**Advisor correction on CVE-2024-4577 attribution [SECURITY-ADVISOR]:** The detractor frames CVE-2024-4577 in a list of language-design-enabled vulnerabilities. This conflates layers. CVE-2024-4577 is a CGI argument injection vulnerability on Windows servers rooted in PHP's CGI-mode argument parsing—a runtime implementation bug in a specific deployment mode, not a consequence of PHP's type system or API defaults. This does not diminish its severity, but the causal attribution matters for designing mitigations.

### Common Vulnerability Patterns

**Structurally enabled by language design choices:**
- **XSS via no default output escaping:** `echo $_GET['name']` is immediately exploitable; `echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8')` is safe. The language places the burden on the developer. The ergonomic gradient points toward insecurity [SECURITY-ADVISOR].
- **Type juggling authentication bypasses:** Before PHP 8.0, `0 == "any-string"` returned true, enabling authentication bypass where any non-numeric input passed a zero-comparison check. Partially addressed (see Section 2 advisor correction).
- **Deserialization exploits:** `unserialize()` of user input instantiates arbitrary registered classes, enabling POP (Property-Oriented Programming) chains leading to code execution [OWASP-PHP-INJECTION]. PHP 7.0 added `allowed_classes` option as partial mitigation.
- **File inclusion with user input:** `include($_GET['page'])` with stream wrapper support creates remote code execution vectors.

**Legacy API surface:**
- `register_globals` (removed PHP 5.4): automatically populated global scope with GET/POST/COOKIE values. Enabled variable overwrite attacks for over a decade.
- `magic_quotes` (removed PHP 5.4): provided false security with incorrect auto-escaping.
- `mysql_*` functions (removed PHP 7.0): no prepared statement support, required manual string escaping.

### Supply Chain Security

Composer `audit` command (Composer 2.4+) queries the GitHub Advisory Database for packages with known CVEs. The GitHub Advisory Database covers PHP packages. `composer audit` integration into CI provides meaningful automated checking [SECURITY-ADVISOR]. Packagist does not perform automated malware scanning on package content; neither does npm reliably. Both ecosystems have structural supply chain weaknesses.

PHP Security Team handles core vulnerabilities; response times are generally fast for critical CVEs. ~100-200 CVEs/year in PHP core [CVE-PHP]. The security picture for PHP as *actually deployed* is worse than for current PHP 8.x, because 38% of teams deploy EOL PHP versions (7.4 or earlier) [DEVSURVEY], which are unpatched against vulnerabilities discovered since those versions reached end-of-life.

### Cryptography Story

Modern PHP (7.2+) includes libsodium for ChaCha20-Poly1305, Ed25519, X25519, and other modern primitives. `password_hash()` with bcrypt or Argon2 is the correct pattern for password storage. `random_bytes()` provides cryptographically secure randomness.

Historical footguns: `md5()` and `sha1()` for password hashing (trivially crackable); `mcrypt` extension (removed PHP 7.2) with insecure defaults; `crypt()` with weak DES algorithm. Audited third-party libraries (`paragonie/halite`, `defuse/php-encryption`) provide safer high-level abstractions. Crypto-related CVEs are rare in modern PHP codebases following framework guidelines.

---

## 8. Developer Experience

### Learnability

PHP's low initial barrier to entry is real: write `<?php echo "Hello, $name"; ?>`, save as a `.php` file, and it runs with zero build infrastructure. This accessibility specifically minimizes time-to-first-working-result for developers who already understand HTML and HTTP. For this target profile, no other language circa 1994-2005 matched PHP's immediacy.

**Advisor correction on accessibility claims [PEDAGOGY-ADVISOR]:** PHP's low barrier applies to developers who (a) already understand HTML and HTTP, (b) are working on web projects, and (c) are in environments where silent type coercions are not immediately catastrophic. For first-time programmers without web context, or developers from strongly-typed backgrounds, PHP's semantic permissiveness creates confusion rather than accessibility. The accessibility claim is context-dependent, not universal.

Furthermore, the code that is *easiest to write* in PHP is not the code that teaches correct practice. The natural beginner path produces `echo $_GET['name']` (XSS), `== false` comparisons (type juggling), procedural scripts with globals (no encapsulation), and copy-pasted snippets from php.net user notes that may be a decade out of date. This "false floor" problem is absent from the apologist's account [PEDAGOGY-ADVISOR].

Current practitioner consensus (2023-2025) explicitly recommends against PHP as a first programming language, citing "syntax and general design inconsistencies" and "bad habits" formed by PHP's permissive defaults [LEARNPYTHON]. The demographic data supports this: 88% of PHP developers have more than three years of experience; the largest cohort is in the 6-10 year range [DEVSURVEY]. If PHP were genuinely used as a first-language entry point at scale, a higher proportion of developers with one to three years of experience would be expected.

Time to productivity in modern frameworks: days to weeks for basic CRUD applications; months to master framework internals (Laravel Eloquent, Symfony dependency injection); years to internalize security best practices.

### Cognitive Load

**Low for traditional request-response code.** PHP-FPM's shared-nothing model means developers reason about one request at a time. No race conditions, no manual memory management, minimal ceremony for web patterns.

**Higher for typed, statically analyzed code.** In codebases enforcing PHPStan level 8, developers spend significant time annotating generic types in docblocks (`@var array<string, User>`) because the language has no generics. This is incidental complexity—types the runtime ignores but analyzers require.

**Significantly higher for async contexts.** Fiber-based concurrency requires understanding event loops, blocking vs. non-blocking I/O, and which PHP standard library functions block the event loop.

**Persistent high cognitive load from standard library inconsistency:** `strpos($haystack, $needle)` versus `array_search($needle, $haystack)`; `array_map($callback, $array)` versus `array_filter($array, $callback)`; `str_replace()` versus `strpos()` versus `substr()` naming conventions [PEDAGOGY-ADVISOR]. The PHP RFC for consistent function names (filed 2015, still unresolved) formally acknowledges these inconsistencies cannot be fixed due to backward compatibility [RFC-CONSISTENT-NAMES]. Every function must be individually memorized; learning one part of the standard library does not help predict another part. This is a structural learnability defect, not merely an aesthetic complaint.

### Error Messages

PHP 8.x error messages are substantially better than PHP 5/7 behavior. PHP 8.0 changed internal functions to throw `TypeError` or `ValueError` instead of issuing `E_WARNING` [PHP-WATCH-80], making errors fail-fast with named argument information:

```
TypeError: array_keys(): Argument #1 ($array) must be of type array, string given
```

versus the old:

```
Warning: array_keys() expects parameter 1 to be array, string given
```

This is a concrete pedagogical improvement: errors halt at the source of the problem rather than propagating as false-ish return values. The `match` expression throwing `UnhandledMatchError` versus `switch` falling through silently is another improvement in the same direction [PEDAGOGY-ADVISOR].

Still problematic: "Class 'Foo' not found" when you meant `\Namespace\Foo`; template engine errors showing compiled template file locations rather than source locations; warnings that depend on `php.ini` configuration and may be silently suppressed in some environments while appearing as output in others.

Historical comparison: PHP 5 era produced `Parse error: syntax error, unexpected T_PAAMAYIM_NEKUDOTAYIM` ("Paamayim Nekudotayim" is Hebrew for `::`). Modern PHP 8 messages are substantially more actionable but still lag behind Rust's compiler messages in explanatory quality.

### Expressiveness vs. Ceremony

PHP is concise for web-specific patterns. Laravel code demonstrates the framework's expressive ceiling:

```php
Route::get('/users', fn() => User::all());
```

This defines a route, queries the database, and returns JSON in one line. Modern PHP features (named arguments, match expressions, constructor property promotion, readonly properties, enums) reduce boilerplate substantially compared to PHP 7.x.

Ceremony remains in strict-mode PHP: every file needs `declare(strict_types=1);` separately (not a project-wide setting), and the lack of generics forces docblock annotations for typed arrays.

### Community and Culture

PHP's community spans from hobbyist WordPress plugin developers to enterprise Symfony teams. Laravel (61% developer usage [DEVSURVEY]) has a notably welcoming community; Symfony is smaller but professional. WordPress represents a parallel ecosystem with different patterns, quality standards, and security norms.

PHP-FIG (PHP Framework Interop Group) PSR standards (PSR-1/12 for coding style, PSR-4 for autoloading, PSR-7 for HTTP messages) provide interoperability; they are widely adopted in modern projects but remain recommendations, not requirements.

Conferences (PHP[tek], SymfonyCon, Laracon) are well-attended with practical content orientation. No major community controversies in recent years.

### Job Market and Career Impact

- Web infrastructure dominance (~77% of sites) ensures high job availability; the installed base is not disappearing
- Average U.S. salary: $102,144/year [DEVSURVEY], below Python ($112,504) and typically below Go, Rust
- 58% of PHP developers do not plan to migrate to other languages in the next year [DEVSURVEY], indicating stable satisfaction
- Hiring for junior developers is easy; hiring senior developers with modern PHP expertise (Laravel, static analysis, async) is harder
- JetBrains classifies PHP as "stable but in long-term decline" in developer mindshare [DEVSURVEY], declining in surveys even as production dominance holds. Teams hiring PHP engineers in 2030 may face increasing competition for diminishing new-entrant talent—a genuine long-term risk [SYSTEMS-ARCHITECTURE-ADVISOR]

---

## 9. Performance Characteristics

### Runtime Performance

TechEmpower Framework Benchmarks (Round 23, March 2025) provide the current authoritative data. PHP frameworks (Laravel, Symfony) occupy lower-mid tiers: 5,000-15,000 RPS for typical web workloads. Comparison points: Rust-based frameworks at 500,000+; Go at 100,000+; Node.js/Express at 20,000-40,000 [BENCHMARK-PILOT].

This is 30-100x slower than highly-optimized compiled alternatives for throughput. The practitioner framing is correct: most web applications are I/O-bound. A typical PHP web request spends 100-500ms waiting for database queries and 5-50ms in PHP execution [PRACTITIONER]. Improving PHP execution speed by 2x reduces total request time from 150ms to 145ms—imperceptible to users. PHP performance is "adequate" for most web workloads; it is not competitive for CPU-bound work.

PHP 7.0's approximately 2x throughput improvement over PHP 5.6 is the most significant performance inflection in PHP's history, achieved through the redesigned internal data structures and approximately 50% memory reduction enabling better cache behavior [PHP7-BENCHMARKS].

### JIT Compilation

PHP 8.0 introduced JIT; PHP 8.4 introduced an IR (Intermediate Representation)-based JIT framework that substantially improved portability and optimization quality [COMPILER-RUNTIME-ADVISOR].

JIT benefit is well-characterized across all council perspectives and confirmed by benchmark data:
- CPU-intensive workloads (fractal generation, mathematical computation): 1.5-3x improvement
- Real-world web applications: minimal to inconsistent. WordPress, MediaWiki, and Symfony show 0-7% improvement; some workloads regress slightly [BENCHMARK-PILOT]
- CLI scripts and long-running batch workers: 1.5-2x improvement

The reason JIT fails to help web applications is architectural: PHP web requests are too short to amortize JIT compilation cost, and the execution time is dominated by I/O rather than computation. The realist's characterization—"the right feature for the wrong use case"—is accurate for typical web PHP.

**Advisor correction on JIT architecture [COMPILER-RUNTIME-ADVISOR]:** The detractor claims "Only supports x86/x64; ARM and Apple M1 unsupported initially." PHP 8.0's JIT was indeed x86/x64 only. PHP 8.1 added ARM64 support; PHP 8.4's IR-based JIT substantially improved ARM64 compatibility and optimization quality. Citing PHP 8.0 ARM limitations as current is inaccurate. The practitioner's observation—"Most teams disable JIT or leave it at default (conservative) settings because the benefits are negligible and debugging JIT-compiled code is harder"—more accurately represents 2026 practitioner experience.

**Advisor correction on constant folding [COMPILER-RUNTIME-ADVISOR]:** The detractor claims PHP has "No compile-time computation or constant folding beyond basic opcodes." PHP's OPcache optimizer performs constant folding, dead code elimination at the opcode level, and some inter-procedure optimizations. What PHP lacks is link-time optimization (whole-program analysis across files), dead code elimination at the symbol level, and tree-shaking. The detractor's claim is partially inaccurate.

### Compilation Speed

PHP has no traditional compilation step. Code is parsed and compiled to opcodes on first execution, then cached by OPcache in shared memory. Subsequent requests load bytecode at <1ms from the shared memory segment [REALIST]. Deployment impact: the first request after deployment (cold OPcache) is slower; preloading (PHP 7.4+) mitigates this by loading files into shared memory at server startup.

The absence of a compilation step is PHP's killer feature for iteration speed: save a file, refresh the browser, see changes. CI/CD build times are dominated by `composer install` (2-10 minutes) and test suites (5-30 minutes), not compilation.

### Startup Time

**Advisor correction on startup time comparison [COMPILER-RUNTIME-ADVISOR]:** The council discussions conflate three distinct startup scenarios:
1. PHP-FPM workers (pre-forked): effectively zero per-request startup; workers start once at process launch
2. Traditional CGI/CLI: full PHP interpreter initialization per invocation (~5-50ms)
3. Serverless (AWS Lambda/Bref): cold start 100-300ms including runtime initialization and dependency loading

The practitioner's reported cold start of ~230ms for PHP at 768MB AWS Lambda memory is consistent with scenario 3 [PRACTITIONER]. The "5-50ms" figure most accurately describes scenario 2. Scenario 1—the dominant production model—has zero per-request startup time, which is the correct characterization for typical PHP-FPM deployments.

### Resource Consumption

- Typical web request: 2-10MB peak heap usage
- Laravel request: 30-50MB; WordPress request: 50-100MB (framework overhead, plugins)
- Per-worker memory overhead is the main constraint on PHP-FPM concurrency
- CPU is single-threaded per request; multi-core scaling via multiple worker processes

Under resource constraints, PHP's shared-nothing model isolates failures—one request exhausting memory does not affect other workers.

### Optimization Story

Idiomatic PHP is reasonably performant for its execution model. Performance-critical differentiation involves using OPcache and preloading, avoiding dynamic features (`$$variable`, `call_user_func()`), enabling JIT for CPU-bound tasks, and using async I/O for high-concurrency scenarios. The practitioner's strategy—profile first (Xdebug, Blackfire), optimize database queries (N+1 queries are the most common bottleneck), add caching (Redis, Memcached), then optimize PHP code—reflects correct prioritization.

---

## 10. Interoperability

### Foreign Function Interface

PHP FFI (PHP 7.4+) allows calling C libraries without writing PHP extensions [PHP-FFI]. PHP-side memory is automatic; C-side memory allocated via `FFI::new()` must be manually freed. FFI bypasses PHP's memory safety entirely; crashes in FFI code produce process-level crashes that PHP cannot recover from.

**Advisor note [COMPILER-RUNTIME-ADVISOR]:** The practitioner's estimate of "1-10µs" FFI call overhead is a reasonable estimate for simple calls but can be higher for complex data marshaling. PHP FFI uses `libffi`, which introduces a calling convention translation layer; the overhead depends heavily on argument marshaling.

**Advisor correction on PHP's primary interoperability story [SYSTEMS-ARCHITECTURE-ADVISOR]:** The historian briefly identifies this correctly, but no council member adequately explains that PHP's production-scale C library integration has always been via compiled C extensions, not FFI. The extension ecosystem is PHP's actual primary interoperability mechanism: `ext-pdo`, `ext-redis`, `ext-amqp`, `ext-gd`, `ext-imagick`, `ext-swoole`. FFI is an escape hatch for edge cases, not the primary integration story. This distinction matters for architects evaluating PHP's integration surface.

In practice, most teams never write extensions. When native performance is needed, they deploy microservices in Go/Rust and call them via HTTP/gRPC from PHP [PRACTITIONER].

### Embedding and Extension

PHP can be embedded via `libphp`, but documentation and tooling are minimal and embedding is rare. PHP's design as a top-level server process creates architectural mismatch with embedding use cases. Unlike Lua (designed for embedding) or JavaScript (widely embedded via V8/JavaScriptCore), PHP is not a natural choice for embedded scripting.

Writing native extensions requires C knowledge, understanding of Zend Engine APIs, and compilation for each PHP version and platform. The barrier is high but the extension ecosystem is mature: core extensions (mysqli, pdo, gd, curl) are written in C; popular third-party extensions (imagick, redis, xdebug, swoole) extend PHP with native performance.

**Advisor correction [SYSTEMS-ARCHITECTURE-ADVISOR]:** The apologist conflates `ext-pthreads` and `ext-parallel`. `ext-pthreads` is largely deprecated and was designed for PHP CLI use only. `ext-parallel` (by the same author) is the current supported approach for true thread-based parallelism, using isolated task contexts with message passing rather than shared objects. These are architecturally distinct and should not be treated as interchangeable.

### Data Interchange

JSON interoperability is excellent: `json_encode()`/`json_decode()` are fast, handle UTF-8 correctly, and PHP arrays map naturally to JSON structures. The realist's characterization of PHP's JSON performance as "relatively slow compared to dedicated parsers" is overstated—for typical web payloads (sub-100KB JSON), PHP's JSON performance is competitive [SYSTEMS-ARCHITECTURE-ADVISOR].

Protobuf: available via `google/protobuf` extension or library; performance is adequate but not as optimized as Go or C++. gRPC: supported via `grpc` extension; moderate adoption in PHP microservice architectures. GraphQL: userland libraries (webonyx/graphql-php, Lighthouse) are mature and widely used.

PHP's native `serialize()`/`unserialize()` format is PHP-specific and insecure: `unserialize()` of user input can instantiate arbitrary registered classes [OWASP-PHP-INJECTION]. JSON or explicit type whitelisting should be used for any externally-sourced data.

### Cross-Compilation

PHP does not cross-compile. PHP scripts are interpreted; deployment means ensuring the target platform has a compatible PHP interpreter with required extensions. Platform-specific concerns (path separators, filesystem APIs) are the main cross-platform considerations.

WebAssembly: experimental. The php-wasm project compiles the entire PHP interpreter to WASM—a ~20MB+ payload—which is architecturally unsuitable for most WASM use cases (edge runtimes, browser embedding). PHP's design as a server-side, process-per-request language is fundamentally misaligned with WASM's deployment model. The systems architecture advisor confirms: this is likely a permanent limitation, not a temporary gap [SYSTEMS-ARCHITECTURE-ADVISOR].

### Polyglot Deployment

PHP naturally occupies the web tier in polyglot architectures: serving APIs and rendering HTML while delegating computation to Go/Rust/Python microservices via HTTP, message queues (RabbitMQ, Redis), or gRPC. Lightweight PHP-FPM containers (100-200MB) are HTTP-native and fit naturally into Docker/Kubernetes architectures [PRACTITIONER].

**Advisor note [SYSTEMS-ARCHITECTURE-ADVISOR]:** The Facebook/Meta case study is the canonical evidence for PHP interoperability at scale. Facebook ran PHP alongside C++ and other languages for years, scaled their PHP monolith rather than breaking into microservices to maintain development velocity. When the performance ceiling became architecturally blocking, they built HHVM rather than rewrite in another language. When HHVM's divergence became maintenance overhead, they created Hack—a PHP-derived language with a static type system. This trajectory is the definitive case study: PHP can coexist in polyglot systems at massive scale, but crossing the performance ceiling requires either custom runtime infrastructure or language migration, not PHP tuning.

---

## 11. Governance and Evolution

### Decision-Making Process

PHP uses a public RFC (Request for Comments) process. Anyone can propose an RFC; only voting members (contributors with commit access) can vote. Language changes require a 2/3 supermajority; other changes require 50%+1. The process is transparent: RFCs are public, voting is public, mailing list discussions are archived [PHP-RFC-WIKI].

The PHP Foundation, formed in 2021 following Nikita Popov's reduced involvement, funds ten core developers at $627,000 annually (2024) and received Sovereign Tech Agency project funding from the German government [PHP-FOUNDATION-2024]. This institutional structure materially reduced PHP's bus factor from "handful of volunteers" to "funded institution with corporate backing."

**Advisor note [SYSTEMS-ARCHITECTURE-ADVISOR]:** The PHP Foundation's Sovereign Tech Agency engagement is a qualitatively different sustainability model than pure corporate sponsorship—it acknowledges PHP as critical public infrastructure and creates funding independence from commercial PHP ecosystem players.

### Rate of Change

Annual release cadence: PHP 8.0 (November 2020), 8.1 (November 2021), 8.2 (December 2022), 8.3 (November 2023), 8.4 (November 2024). Each release includes new features and deprecations; the deprecation window is typically 2-3 years before removal.

PHP 8.0 was the most significant recent release: JIT compilation, named arguments, attributes, union types, constructor property promotion, match expressions, nullsafe operator, and breaking changes to type comparison behavior. Subsequent 8.x releases have been gentler.

Backward compatibility is effectively absolute for stable features. This is both PHP's greatest governance strength (makes large-scale adoption possible) and its greatest governance limitation (makes known mistakes permanent).

### Feature Accretion

**Advisor correction [SYSTEMS-ARCHITECTURE-ADVISOR]:** The apologist understates the governance asymmetry: adding features requires 2/3 majority; keeping existing features requires no vote at all. This systematically biases toward accumulation. PHP has ~1,300 functions in 8.0 versus ~1,000 in 5.0. Removals have occurred (register_globals, mysql_*, magic_quotes, ereg functions), but net function count grew.

Known mistakes that cannot be fixed: type juggling in the `==` operator; inconsistent standard library naming (the "Consistent Function Names" RFC, filed 2015, remains unresolved because backward compatibility makes the fix impossible [RFC-CONSISTENT-NAMES]); no default output escaping. The governance model has produced a language that can remove the most egregious historical mistakes given a decade of deprecation warnings, but cannot make the systematic improvements that would require coordinated breaking changes.

**Advisor note on Rector [SYSTEMS-ARCHITECTURE-ADVISOR]:** The automated code transformation tool Rector changes the calculus on upgrade costs. Rector automates version migrations, compressing 6-month manual migrations to days. MyHeritage's PHP 7.2→8.4 migration (1,300+ files, spanning 2018-2025) was managed incrementally partly via automated tooling. For architects evaluating PHP upgrade costs, Rector is a significant mitigating factor the council largely misses.

### Bus Factor

The PHP Foundation provides genuine improvement: 10+ funded core developers, corporate sponsorship from JetBrains, Automattic (WordPress), Zend, and others, plus government-funded project work. Bus factor has improved from "handful of individuals" to "funded institution." PHP has one canonical implementation (Zend Engine), which simplifies ecosystem compatibility but increases risk if core development stalls—there is no alternative implementation to carry the language forward.

### Standardization

PHP has no formal ISO, ECMA, or ANSI specification. The canonical implementation is the specification. HHVM (Facebook's HipHop Virtual Machine) was an alternative implementation that diverged to become Hack; as of 2020, HHVM no longer supports PHP. A formal language specification was started but never completed. In practice, single implementation means no compatibility issues across vendors; testing on the target PHP version is sufficient.

### Version Adoption Lag

**Advisor note [SYSTEMS-ARCHITECTURE-ADVISOR]:** Version adoption lag is a real operational risk that the council underweights. PHP 7.4 (end-of-life November 2022) still accounts for 38.68% of production deployments as of January 2025 [PHP-VERSION-STATS]. CVE-2024-4577 (CVSS 9.8) affected PHP versions below 8.1.29/8.2.20/8.3.8 and exposed approximately 458,800 instances. The combination of slow adoption and PHP's 77% market share means critical vulnerabilities have outsized blast radius. This is not a language design failure but an upgrade incentive structure failure with serious security consequences.

---

## 12. Synthesis and Assessment

### Greatest Strengths

**1. Unmatched deployment simplicity and iteration speed for web development.**

PHP's shared-nothing, request-scoped model combined with no compilation step makes it the most immediately productive web development environment that has ever existed at scale. Save a file, refresh the browser, see changes. No build pipeline. No container rebuild during development. Automatic resource cleanup at request boundaries eliminates a class of bugs that afflicts event-loop and thread-based systems. For MVPs, agency work, and rapid prototyping, this advantage is decisive. Modern PHP-FPM containers (100-200MB) deploy more simply than JVM-based alternatives while providing comparable throughput for I/O-bound workloads [PRACTITIONER].

**2. A mature, cohesive framework ecosystem with massive production validation.**

Laravel and Symfony provide batteries-included web development that handles authentication, ORM, routing, validation, queues, caching, and testing out of the box. The ecosystem is *deep*: payments (Cashier/Stripe), admin panels (Nova/Filament), WebSockets (Echo/Reverb), real-time dashboards. 74.5-77.5% of all websites with a known server-side language run on PHP [DEVSURVEY]—the largest production validation any web technology has ever had. The practical consequence: PHP patterns for common web problems are known, documented, and battle-tested at a scale no other server-side language can match.

**3. The shared-nothing concurrency model as an underappreciated security and reliability asset.**

PHP's request isolation provides automatic fault isolation, no inter-request race conditions at the PHP level, and no cross-request memory leakage—properties that thread-based systems must explicitly design and verify. This is a genuine architectural safety property that Go's goroutines, Node.js's event loop, and Python's asyncio do not provide by default [SECURITY-ADVISOR]. For teams that want reliability without concurrency expertise, PHP-FPM's simplicity is a structural advantage.

**4. A realistic incremental modernization path.**

PHP allows gradual improvement: add types to one function, introduce static analysis with a baseline ignoring existing issues, adopt Rector for automated refactoring. Teams can ship value while improving quality, rather than freezing features for a "big rewrite." Facebook migrated from PHP to Hack incrementally; WordPress still runs on PHP despite being 20+ years old. This evolutionary capacity is PHP's most underappreciated engineering property [PRACTITIONER].

**5. PHP 8.x as a legitimately modern language (when used in full).**

PHP 8.0-8.4 added JIT compilation, Fibers, named arguments, attributes, union types, intersection types, enums, readonly properties, match expressions, nullsafe operator, constructor property promotion, and first-class callable syntax. With `declare(strict_types=1)` and PHPStan at maximum strictness, PHP 8.x is a capable, modern language. The gap between PHP's reputation (based on 2005-2010 experience) and PHP 8.x's actual capabilities is substantial and consequential for fair evaluation.

### Greatest Weaknesses

**1. Security ergonomics that systematically favor insecurity as the path of least resistance.**

PHP's XSS problem—the single largest class of CVEs—is a direct consequence of the language treating raw output as the easy path [SECURITY-ADVISOR]. `echo $_GET['name']` is immediately exploitable; the safe equivalent requires explicit `htmlspecialchars()`. This ergonomic gradient, multiplied by 30 years and 33 million websites, explains the CVE record better than any characterization of PHP developers as careless. The language's type juggling in comparisons, permissive file inclusion semantics, and `unserialize()` instantiating arbitrary classes all follow the same pattern: the insecure behavior was the easy behavior. Modern frameworks have compensated for this at the framework layer, but the language defaults remain unchanged.

**2. Permanent technical debt from backward compatibility absolutism.**

Type juggling in `==`, inconsistent standard library naming, no default output escaping—these are known design mistakes that cannot be fixed because fixing them would break enormous codebases. The "Consistent Function Names" RFC is the canonical example: community consensus that the problem is real, no viable path to resolution [RFC-CONSISTENT-NAMES]. PHP's governance can remove the most egregious historical mistakes given a decade of deprecation warnings, but it cannot make systematic improvements. The result is a language that is simultaneously much better than its reputation and permanently encumbered by design decisions made before security, consistency, and type safety were design priorities.

**3. A fragmented concurrency story with no clear production winner.**

PHP offers five production-capable concurrency approaches in 2026: PHP-FPM, Swoole, ReactPHP, Amp v3, and FrankenPHP. These models are architecturally incompatible—libraries designed for one model may not work with another, and switching concurrency model mid-project can require significant refactoring. The colored function problem, while nominally avoided at the language level by Fiber design, is recreated at the ecosystem level: code using standard blocking `mysqli` silently serializes execution in an async Swoole context [COMPILER-RUNTIME-ADVISOR]. No single async model has emerged as the clear winner, creating ecosystem fragmentation and hiring challenges.

**4. A type system that requires extensive compensatory infrastructure to be professionally usable at scale.**

PHP requires PHPStan, Psalm, quality IDE configuration, and `declare(strict_types=1)` in every file to achieve what TypeScript, Rust, or Go provide by default. The 64% of PHP projects not running PHPStan [DEVSURVEY] are accepting meaningful type-safety debt. The absence of generics forces docblock annotations for typed arrays—types the runtime ignores but static analyzers require. This is four layers of process to achieve what statically typed languages provide as a baseline [SYSTEMS-ARCHITECTURE-ADVISOR].

**5. A performance ceiling incompatible with CPU-bound, high-concurrency, or latency-sensitive workloads.**

PHP frameworks at 5,000-15,000 RPS versus Rust at 500,000+ and Go at 100,000+ represents a real architectural constraint for high-throughput systems [BENCHMARK-PILOT]. JIT helps 1.5-3x for CPU-intensive work but provides negligible benefit for typical web workloads. Teams building real-time systems, high-frequency event processing, or ML inference workloads must delegate those workloads to other languages. This is not merely a matter of optimization—it is an architectural ceiling inherent to PHP's interpretation model and dynamic dispatch.

### Dissenting Views

**On the nature of PHP's security problems:**

The detractor argues that PHP's security failures are primarily language design failures—permissive defaults, type juggling, dangerous inclusion semantics—and that these represent structural choices that Penultima must reject. The apologist and security advisor offer a more nuanced position: PHP's injection vulnerability record reflects design choices made in 1994-2000 when web security was not a design priority, and modern PHP with frameworks compensates substantially for those defaults. The realist's framing is closest to defensible: the language design choices were *structurally enabling*—they made insecure code easy to write—but the CVE record also reflects 30 years of legacy code and PHP's 77% market share, which inflates absolute CVE counts without necessarily reflecting higher per-site vulnerability rates. This distinction matters for Penultima: the lesson is "secure defaults from the start" more than "PHP developers were careless."

**On PHP's type system progress:**

The apologist argues that PHP's gradual typing is a correctly-implemented modern type system enabling progressive adoption without big-bang migrations. The detractor argues that the type system is fundamentally weak and that compensatory toolchain (PHPStan, Psalm) merely patches a language-level deficiency. Both are partially correct. PHP's gradual typing enables practical migration strategies that full breakage would preclude. But the implementation—call-site scoping for `strict_types`, no generics, no soundness guarantees—means PHPStan and Psalm are indeed compensating for language-level gaps rather than adding value above a sound baseline. The pedagogy advisor's framing is the most precise: PHP's gradual typing is backwards for learning purposes—it requires opting into correct behavior rather than starting from a correct default.

**On whether PHP's concurrency story represents failure or adequate pragmatism:**

The historian argues that PHP's concurrency model is a failure to adapt to changing deployment models—the shared-nothing model was correct for 2000-2010 but insufficient for long-running services that became standard by 2015. The apologist argues that process-based concurrency is an underappreciated architectural strength providing safety properties that thread-based and event-loop-based systems lack. The practitioner's "pick your poison" framing is most accurate: PHP-FPM and Fiber-based async offer different resource utilization profiles, debugging characteristics, and failure modes, not just throughput differences. For I/O-bound web request-response workloads, PHP-FPM remains competitive. For high-concurrency long-running services, Fiber-based options exist but impose framework lock-in and ecosystem fragmentation costs.

### Lessons for Penultima

**Adopt: Scope-bounded memory management as a first-class construct.**

PHP's request-scoped arena demonstrates that restricting object lifetime to a well-defined scope boundary enables efficient bulk deallocation with minimal GC pressure. The key insight is that *knowing when memory is unreachable* (request end, scope exit) is more powerful than tracking *which memory is unreachable* (GC traversal). For Penultima, scope-tagged allocation regions or lifetime annotations could provide PHP-like efficiency for request-scoped workloads without PHP's inflexibility when request boundaries are absent [COMPILER-RUNTIME-ADVISOR]. This is a structurally sounder approach than either full GC or manual memory management for many web-oriented workloads.

**Adopt: Concrete standards for named-argument calling conventions and standard library consistency.**

PHP's standard library inconsistency—`strpos($haystack, $needle)` versus `array_search($needle, $haystack)`; `array_map($callback, $array)` versus `array_filter($array, $callback)`—is among the best-documented sources of incidental cognitive load in any mainstream language. The pedagogical consequence is that learning one part of the library does not help predict another part; every function must be individually memorized. Penultima should treat naming convention consistency as a first-class design constraint with enforced mechanical verification, not an aesthetic preference. The specific anti-patterns to avoid: inconsistent argument ordering for semantically related operations, inconsistent naming schemes across functional areas, and inconsistent verb/noun conventions [PEDAGOGY-ADVISOR].

**Adopt: Default-safe output in all string interpolation and templating contexts.**

PHP's XSS problem—30,000+ CVEs—is the direct cost of treating raw output as the default path. Penultima's string interpolation semantics should treat context-escaped output as the default, requiring explicit opt-out for raw interpolation. This is a solved problem in modern template engines (Twig, Blade); the lesson for Penultima is to make it a *language default*, not a library feature [SECURITY-ADVISOR]. Secure defaults that persist at scale for decades are more valuable than insecure defaults with documented mitigation advice.

**Adopt: Strict equality semantics by default with explicit, named coercions.**

PHP's loose equality operator `==` created a decade of authentication bypass vulnerabilities before PHP 8.0 partially addressed it. Penultima should use strict equality semantics by default. If type coercion is supported, it should be explicit (a cast, not an implicit comparison behavior), and the language specification should enumerate the security implications of any implicit coercion rules [SECURITY-ADVISOR].

**Adopt: Serialization that requires explicit type declarations.**

PHP's `unserialize()` is a textbook example of a dangerous default—a general-purpose deserialization function that can instantiate any registered class from an attacker-supplied byte stream. Penultima's serialization primitives should require explicit type whitelisting or only deserialize into declared value types, not arbitrary object graphs [SECURITY-ADVISOR].

**Adopt: A unified concurrency model committed to at language level.**

PHP's fragmented concurrency story (five production-capable models, none universally adopted) demonstrates the cost of leaving concurrency to the ecosystem. Penultima should choose one concurrency primitive—structured concurrency with async/await, goroutines with channels, or Erlang-style actors—and build it into the language design from the beginning. The lesson from PHP's Fiber RFC is instructive: avoiding language-level function coloring is a reasonable design goal, but the ecosystem will recreate the coloring problem at the library layer if the language does not provide transparent blocking/non-blocking primitives [COMPILER-RUNTIME-ADVISOR]. The goal should not be "don't color functions" but "make the coloring cheap and universal."

**Adopt: Built-in observability primitives.**

PHP has no native tracing or metrics primitives; all observability requires external APM tooling. Modern production systems require distributed tracing, structured logging, and metrics collection. Penultima should define standard interfaces for these in the standard library, with optional pluggable implementations, rather than leaving each project to negotiate APM vendor lock-in independently [SYSTEMS-ARCHITECTURE-ADVISOR].

**Adopt: A principled backward-compatibility break mechanism.**

PHP's governance cannot fix type juggling, inconsistent stdlib naming, or insecure output defaults because backward compatibility is effectively absolute. Penultima needs a designed answer to "how do we break things that need breaking?"—whether via edition-based evolution (Rust's approach), explicit deprecation windows with compiler-enforced migration, or formal breakage budgets. Without this mechanism, the cost of early design mistakes becomes permanent. The cost of designing this mechanism correctly once is paid by language designers; without it, every project pays it independently through accumulated technical debt [SYSTEMS-ARCHITECTURE-ADVISOR].

**Avoid: Gradual typing scoped to call sites rather than function definitions.**

`declare(strict_types=1)` applies to calls *made from the declaring file*, not to function definitions. This means whether a function call is type-checked depends on the caller, not the function. A developer reading a function signature cannot determine whether type enforcement is active. Penultima's gradual typing, if implemented, should scope strictness to function *definitions*, making the strictness of a function visible at its declaration point rather than dependent on caller configuration [PEDAGOGY-ADVISOR].

**Avoid: Compensatory toolchain as a substitute for language-level guarantees.**

PHP requires PHPStan, Psalm, Rector, and a quality IDE to be professionally productive at scale. Each represents a gap in the language's own guarantees. Penultima should provide static type safety, automated upgrade paths, and high-quality error messages as language-level features. The cost is paid once by language designers; without it, every project and every team pays it independently [SYSTEMS-ARCHITECTURE-ADVISOR].

**Avoid: Extension/FFI boundaries that are invisible to the language's safety model.**

PHP's userland memory safety is undermined by C extensions with poor memory safety. The boundary between managed PHP code and unmanaged C extension code is invisible to users, creating a misleading safety narrative. If Penultima has a native extension or FFI mechanism, the safety boundary should be explicit—through language-level `unsafe` annotations (Rust's approach), sandboxed extension APIs, or formal specification of what safety properties hold across the FFI boundary [COMPILER-RUNTIME-ADVISOR, SECURITY-ADVISOR].

**Avoid: Permissive defaults with the expectation that documentation will compensate.**

PHP's history demonstrates that defaults, once adopted at scale, take 10-15 years to fully remove. `register_globals` (introduced ~1997, deprecated 2009, removed 2012) is the canonical case study in why initial default security choices have multi-decade consequences. Penultima should design its defaults with the expectation that they will persist at scale for decades. The correct standard: safe patterns should be the path of least resistance; unsafe or unsound operations should require explicit opt-in [SECURITY-ADVISOR].

**Open architectural question: How to balance initial accessibility with long-term learnability.**

PHP optimized aggressively for initial accessibility (time from "I have an idea" to "working webpage") and paid a price in long-term learnability (the mental models formed in the first days are incorrect and must be unlearned). Rust optimizes for long-term correctness and pays a price in initial accessibility. Go finds a middle point but sacrifices type expressiveness. The ideal is a language that scores well on both: how long does it take a new developer to produce correct output, and how long for their mental model to become accurate and generalizable? PHP demonstrates that these are separate design targets requiring separate design choices. Penultima should measure both explicitly [PEDAGOGY-ADVISOR].

---

## References

- **[LERDORF-HISTORY]** Lerdorf, Rasmus. "History of PHP." PHP Manual. https://www.php.net/manual/en/history.php.php
- **[PHP-MANUAL-HISTORY]** PHP Documentation. "History of PHP and Related Projects." https://www.php.net/manual/en/history.php
- **[PHP-HISTORY]** PHP Manual. "History of PHP." https://www.php.net/manual/en/history.php.php
- **[CODEMOTION-25YEARS]** Lerdorf, Rasmus. "25 Years of PHP." Codemotion conference talk. Referenced in council documents as CODEMOTION-PHP and LERDORF-CODEMOTION.
- **[LERDORF-SITEPOINT]** Lerdorf, Rasmus. Interview. SitePoint. Referenced in council documents.
- **[DEVSURVEY]** Penultima Evidence Repository: Cross-Language Developer Survey Aggregation. `evidence/surveys/developer-surveys.md`. Sources: Stack Overflow Annual Developer Survey 2024-2025; JetBrains State of Developer Ecosystem 2024-2025; JetBrains State of PHP 2025; Zend PHP Landscape Report 2025.
- **[CVE-PHP]** Penultima Evidence Repository: CVE Pattern Summary: PHP. `evidence/cve-data/php.md`. Sources: NVD CVE Database; OWASP Top 10; CWE/MITRE; CVEdetails.
- **[BENCHMARK-PILOT]** Penultima Evidence Repository: Performance Benchmark Reference: Pilot Languages. `evidence/benchmarks/pilot-languages.md`. Sources: TechEmpower Web Framework Benchmarks Round 23 (March 2025).
- **[COMPILER-RUNTIME-ADVISOR]** PHP Council — Compiler/Runtime Advisor Review. `research/tier1/php/advisors/compiler-runtime.md`. 2026-02-26.
- **[SECURITY-ADVISOR]** PHP Council — Security Advisor Review. `research/tier1/php/advisors/security.md`. 2026-02-26.
- **[PEDAGOGY-ADVISOR]** PHP Council — Pedagogy Advisor Review. `research/tier1/php/advisors/pedagogy.md`. 2026-02-26.
- **[SYSTEMS-ARCHITECTURE-ADVISOR]** PHP Council — Systems Architecture Advisor Review. `research/tier1/php/advisors/systems-architecture.md`. 2026-02-26.
- **[PHP-MEMORY]** PHP Manual: Memory Management. https://www.php.net/manual/en/features.gc.php
- **[PHPMANUAL-GC]** PHP Manual: Garbage Collection. https://www.php.net/manual/en/features.gc.collecting-cycles.php
- **[PHP-FFI]** PHP Manual: Foreign Function Interface. https://www.php.net/manual/en/book.ffi.php
- **[PHP-FIBERS]** PHP Manual: Fibers. https://www.php.net/manual/en/language.fibers.php
- **[PHP-RFC-FIBERS]** PHP RFC: Fibers (PHP 8.1). https://wiki.php.net/rfc/fibers
- **[PHP7-PERFORMANCE]** Nikita Popov. "PHP 7 Internal Value Representation." https://nikic.github.io/2015/05/05/Internal-value-representation-in-PHP-7-part-1.html
- **[PHP7-BENCHMARKS]** TechEmpower Web Framework Benchmarks, Round 23 (March 2025). https://www.techempower.com/benchmarks/
- **[CENSYS-2024]** Censys. "June 10, 2024: PHP-CGI Argument Injection Vulnerability (CVE-2024-4577)." https://censys.com/cve-2024-4577/
- **[OWASP-PHP-INJECTION]** OWASP Foundation. "PHP Object Injection." https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection
- **[FOXGLOVE-2017]** Foxglove Security. "Type Juggling and PHP Object Injection, and SQLi, Oh My!" (2017). https://foxglovesecurity.com/2017/02/07/type-juggling-and-php-object-injection-and-sqli-oh-my/
- **[PHP-MIGRATION-80]** PHP Documentation. "Migrating from PHP 7.4.x to PHP 8.0.x — Backward Incompatible Changes." https://www.php.net/manual/en/migration80.incompatible.php
- **[EEVEE-2012]** Eevee. "PHP: A Fractal of Bad Design." April 2012. https://eev.ee/blog/2012/04/09/php-a-fractal-of-bad-design/
- **[PHP-THE-RIGHT-WAY]** PHP: The Right Way. Community resource. https://phptherightway.com/
- **[PHP-RFC-FUNCNAMES]** PHP RFC: Consistent Function Names (2015, status: stalled). https://wiki.php.net/rfc/consistent_function_names
- **[RFC-CONSISTENT-NAMES]** PHP Wiki. "Consistent Function Names RFC." https://wiki.php.net/rfc/consistent_function_names
- **[PHP-WATCH-80]** PHP.Watch: Internal Function Warnings Now Throw TypeError and ValueError (PHP 8.0). https://php.watch/versions/8.0/internal-function-exceptions
- **[PHP-RFC-WIKI]** PHP Wiki. "Requests for Comments." https://wiki.php.net/rfc
- **[PHP-FOUNDATION-2024]** PHP Foundation. "The PHP Foundation: Impact and Transparency Report 2024." https://thephp.foundation/blog/2025/03/31/transparency-and-impact-report-2024/
- **[JETBRAINS-PHP-2025]** JetBrains. "The State of PHP 2025." https://blog.jetbrains.com/phpstorm/2025/10/state-of-php-2025/
- **[PHP-VERSION-STATS]** Stitcher.io. "PHP Version Stats." https://stitcher.io/blog/php-version-stats-june-2025; Zend. "PHP Version Stats January 2025."
- **[RECTOR]** Rector Project. "Fast PHP Code Upgrades." https://getrector.com/
- **[LEARNPYTHON]** LearnPython.com. "Python vs PHP." 2023-2025. https://learnpython.com/blog/python-vs-php/
- **[COMPOSER-AUDIT]** Composer documentation. "composer audit" command (Composer 2.4+). https://getcomposer.org/doc/03-cli.md#audit
- **[SWOOLE]** Swoole Documentation. https://swoole.com/
- **[REACTPHP]** ReactPHP. https://reactphp.org/
- **[PRACTITIONER]** PHP Council — Practitioner Perspective. `research/tier1/php/council/practitioner.md`. 2026-02-26.
- **[REALIST]** PHP Council — Realist Perspective. `research/tier1/php/council/realist.md`. 2026-02-26.
- **[HISTORIAN]** PHP Council — Historian Perspective. `research/tier1/php/council/historian.md`. 2026-02-26.
- **[APOLOGIST]** PHP Council — Apologist Perspective. `research/tier1/php/council/apologist.md`. 2026-02-26.
- **[DETRACTOR]** PHP Council — Detractor Perspective. `research/tier1/php/council/detractor.md`. 2026-02-26.
- **[FACEBOOK-PHP-KEITH]** Software Engineering Daily. "Facebook PHP with Keith Adams." https://softwareengineeringdaily.com/2019/07/15/facebook-php-with-keith-adams/
- **[SLACK-HACKLANG]** Slack Engineering. "Hacklang at Slack: A Better PHP." https://slack.engineering/hacklang-at-slack-a-better-php/
- **[RFC-SCALAR-TYPES]** PHP Wiki. "Scalar Type Hints RFC." https://wiki.php.net/rfc/scalar_type_hints
- **[FRANKENPHP-BENCH]** Dev.to. "Performance benchmark of PHP runtimes." https://dev.to/dimdev/performance-benchmark-of-php-runtimes-2lmc
- **[PHP-SURVEYS]** Zend/Perforce PHP Landscape Report 2025. https://www.zend.com/resources/php-landscape-report
- **[OTEL-PHP-AUTO]** OpenTelemetry. "PHP Auto-Instrumentation." https://opentelemetry.io/blog/2023/php-auto-instrumentation/
- **[COMPOSER-V2]** Composer. "Composer 2.0 Release Notes." https://blog.packagist.com/composer-2-0-is-now-available/
- **[MONOREPO-PHP]** LogRocket. "Hosting all your PHP packages together in a monorepo." https://blog.logrocket.com/hosting-all-your-php-packages-together-in-a-monorepo/
- **[PHP-RFC-SANER]** PHP RFC: Saner String to Number Comparisons. https://wiki.php.net/rfc/string_to_number_comparison
- **[INVICTI-TYPEJUGGLING]** Invicti. "PHP Type Juggling Vulnerabilities & How to Fix Them." https://www.invicti.com/blog/web-security/php-type-juggling-vulnerabilities
- **[GHSA]** GitHub Advisory Database — PHP ecosystem advisories. https://github.com/advisories?query=ecosystem%3Acomposer
- **[NVD]** NIST National Vulnerability Database. https://nvd.nist.gov/vuln/search
- **[CWE-79]** MITRE CWE. "CWE-79: Cross-site Scripting." https://cwe.mitre.org/data/definitions/79.html
- **[CWE-89]** MITRE CWE. "CWE-89: SQL Injection." https://cwe.mitre.org/data/definitions/89.html
- **[MYHERITAGE-MIGRATION]** MyHeritage Engineering. "How AI Transformed Our PHP Upgrade Journey." https://medium.com/myheritage-engineering/how-ai-transformed-our-php-upgrade-journey-c4f96a09c840
- **[QUARKSLAB-DOCS]** Quarkslab. "Security Review of PHP Documentation." https://blog.quarkslab.com/security-review-of-php-documentation.html
- **[BACKENDTEA-STRICT]** BackEndTea. "PHP declare(strict_types=1)." https://backendtea.com/post/php-declare-strict-types/
- **[PHP-MANUAL-TYPEJUGGLING]** PHP Manual: Type Juggling. https://www.php.net/manual/en/language.types.type-juggling.php
