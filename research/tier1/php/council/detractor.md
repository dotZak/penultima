# PHP — Detractor Perspective

```yaml
role: detractor
language: "PHP"
agent: "claude-agent"
date: "2026-02-26"
```

## 1. Identity and Intent

PHP's original design philosophy reveals the root of many of its problems: it was never intended to be a programming language at all.

Created in 1994 by Rasmus Lerdorf as "Personal Home Page Tools," PHP began as a simple set of CGI binaries for tracking visits to his online resume [PHP-HISTORY]. Lerdorf designed it as a templating language to embed small snippets in HTML while keeping business logic in separate CGI programs [CODEMOTION-PHP]. As Lerdorf himself stated: "I don't know how to stop it, there was never any intent to write a programming language [...] The world ignored the original vision and started forcing business logic into the templating system" [CODEMOTION-PHP].

This accidental evolution explains PHP's fundamental problem: **it is a collection of pragmatic patches that accumulated features without coherent design principles**. Design decisions like case-insensitive function names were made because "they needed to be included in a templating language like HTML, which is case-insensitive" [CODEMOTION-PHP]. What made sense for a template system creates chaos in a general-purpose language.

The consequences are visible everywhere:
- Function naming follows no consistent convention because different parts were added by different people at different times with different conventions
- The standard library is largely thin wrappers around C APIs, exposing C's interface inconsistencies directly to PHP programmers
- Type coercion rules were designed for convenient HTML form processing, not for building reliable software systems
- Security features were bolted on after deployment at massive scale, rather than designed in from the start

PHP's stated design philosophy, insofar as one exists, prioritizes "solve practical web problems efficiently" and "simplicity over comprehensive programming features" [CODEMOTION-PHP]. This sounds reasonable until you realize it translates to: ship features fast, fix problems later, and never break backward compatibility even when features are fundamentally broken. The result is a language that solves 1995's web problems while creating 2025's security and maintenance nightmares.

## 2. Type System

PHP's type system is a case study in how not to design types. It combines the worst aspects of dynamic and static typing while delivering the benefits of neither.

### The Type Juggling Disaster

PHP's "type juggling" — automatic type coercion during comparisons and operations — creates non-transitive equality relations that violate basic mathematical properties programmers rely on [INVICTI-TYPE-JUGGLING]:

```php
"foo" == 0        // true (string converts to 0)
"foo" == true     // true (non-empty string is truthy)
0 == false        // true
// Therefore: "foo" == true AND "foo" == 0 AND 0 == false
// But: true != false
```

This isn't a corner case — it's a fundamental property of the `==` operator. The recommended solution is "always use `===` instead of `==`" [COFFEE-CODER-TYPE], which raises an obvious question: **why does the dangerous operator get the shorter syntax?**

Type juggling in comparisons enables authentication bypasses. The Foxglove Security research documented a real-world ExpressionEngine vulnerability where type juggling in password comparison allowed attackers to bypass authentication via deserialization and SQL injection chains [FOXGLOVE-TYPE-JUGGLING]. This isn't theoretical — type juggling vulnerabilities appear regularly in CVE databases [PHP-CVE].

### The Gradual Typing Half-Measure

PHP 7.0 introduced type declarations, and PHP 7.4 added typed properties. This sounds like progress until you examine the limitations:

- **Nullable types require explicit `?` annotation**: In PHP, types are nullable by default in function parameters (for backward compatibility), but typed properties are non-nullable by default. This inconsistency means developers must remember different rules for different contexts.

- **No generics**: As of PHP 8.3, there are no generics. Collections must be typed as `array`, losing all type information about elements. Static analysis tools like PHPStan and Psalm add generic support through docblock annotations, which means **type safety depends on comments**.

- **Weak mode by default**: PHP's type system operates in "weak mode" by default, performing type coercion even with type declarations. Declaring `function foo(int $x)` will happily accept `"42"` and coerce it to `42`. Strict mode must be enabled per-file with `declare(strict_types=1)`, and it doesn't affect return type checking for calls into non-strict files.

- **Internal function inconsistency**: PHP's internal functions largely don't use type declarations, returning `false` on errors rather than throwing exceptions, meaning the type system can't help you handle errors safely.

The type system's weakness shows in the tooling ecosystem: PHPStan, Psalm, and Phan exist specifically to add the static analysis that the language fails to provide [JETBRAINS-PHP-2025]. 36% of developers use PHPStan as of 2025 [JETBRAINS-PHP-2025], representing a massive investment in compensating for language-level deficiencies.

### What This Means for Penultima

A type system should either commit to dynamic typing (like Python or Ruby) and provide excellent runtime introspection, or commit to static typing (like TypeScript or Rust) and provide compile-time guarantees. PHP's gradual typing sits in the uncanny valley: too weak to catch bugs at compile time, too restrictive to enable the metaprogramming that makes dynamic languages productive.

Penultima must avoid:
- Non-transitive equality operators
- Type coercion rules that enable security vulnerabilities
- Type systems that require third-party tools to be usable
- Different nullability rules in different contexts
- Weak mode as the default

## 3. Memory Model

PHP uses reference counting with cycle detection for garbage collection. This approach has known limitations but isn't PHP's main problem — the real issue is that PHP's memory model was designed for short-lived request/response cycles and performs poorly in any other context.

### The Request/Response Assumption

PHP's memory model assumes every request starts with a clean slate and ends by releasing all memory. This works for traditional page-based web applications but creates problems for:

- **Long-running processes**: The garbage collector only triggers when 10,000 possible cyclic objects accumulate [PHP-GC]. For daemons and workers, this means memory can grow unbounded until the threshold triggers. Manual `gc_collect_cycles()` calls are necessary, but determining when to call them is application-specific guesswork [TIDEWAYS-GC].

- **Circular references**: If objects have cyclic references (A references B, B references A), the reference counter never reaches zero. The garbage collector detects and cleans these, but only when triggered. The overhead "can impact global performance significantly and ultimately increase execution time" [PHP-GC-MEDIUM].

- **No control over allocation**: PHP provides no mechanisms for arena allocation, memory pools, or custom allocators. Every allocation goes through the same system, regardless of whether you're building a high-performance parser or rendering a simple template.

### No Memory Safety Guarantees

PHP is implemented in C, and PHP extensions often expose C-level memory operations. This creates vulnerabilities:

- Buffer overflows in PHP extensions appear regularly in CVE databases [PHP-CVE]
- The `php://memory` and `php://temp` stream wrappers have different behavior, and choosing wrong can cause memory exhaustion [PHP-STREAMS]
- String concatenation and array operations can trigger O(n²) memory copies for long-running operations

PHP provides no language-level protection against these issues. Memory safety depends entirely on the quality of C code in the runtime and extensions.

### Performance Characteristics

The reference counting approach imposes overhead:
- Every assignment requires incrementing and decrementing reference counts
- Circular reference detection requires periodic graph traversal
- Copy-on-write semantics for arrays mean that seemingly simple operations can trigger full array copies

The PHP 7.3 garbage collector improvements were necessary because "the performance of PHP's garbage collector" was a significant bottleneck for "applications with a large number of objects" [PHP-GC-GUIDE]. The fact that GC performance was a known issue until 2018 — 23 years after PHP's creation — demonstrates how the memory model wasn't designed for modern workloads.

### What This Means for Penultima

PHP's memory model isn't disastrous, but it's limiting. The bigger lesson is: **don't design a language's memory model around a single deployment pattern**. PHP optimized for request/response and paid the price when developers wanted to use it for workers, daemons, async processing, and other long-running workloads.

## 4. Concurrency and Parallelism

PHP has no built-in concurrency model. The language was designed for single-threaded request/response cycles, and concurrency was added as an afterthought through extensions.

### The Absent Primitive Model

Standard PHP has no threads, no goroutines, no async/await, no actors, no channels. Concurrency requires one of:

1. **Process forking with `pcntl`**: Heavyweight, difficult to coordinate, and not available on Windows
2. **Swoole/OpenSwoole**: C extension providing coroutines and async I/O [SWOOLE-MEDIUM]
3. **ReactPHP**: Pure PHP event loop library [REACTPHP-ASYNC]
4. **Amp**: Fiber-based async using PHP 8.1 Fibers [AMP-ASYNC]

The problem: these are mutually incompatible. Code written for Swoole doesn't work with ReactPHP. Fibers are a primitive that libraries can build on, but as of 2025, the ecosystem remains fragmented [ASYNC-PHP-2025].

### No Data Race Prevention

PHP provides no language-level protection against data races. When using Swoole or pthreads, shared memory corruption is entirely the programmer's responsibility. There's no ownership system like Rust, no goroutine scheduler like Go, no actor isolation like Erlang.

### The Async/Await Problem

PHP doesn't have `async`/`await` keywords. Amp provides async/await-like syntax through Fibers, but it's library-level, not language-level [AMP-ASYNC]. This means:

- No compiler support for checking that blocking operations aren't called in async contexts
- No colored function problem because there are no colored functions — but also no language support for making the distinction clear
- Error messages don't help you understand why your async code is blocking

As one 2025 analysis notes: "In 2025, async PHP is no longer the exception... but PHP lacks mechanisms such as SQL preprocessing, connection pooling, long connection keep-alive, and reconnection on disconnection, leading to poor performance in high-concurrency scenarios" [ASYNC-PHP-2025].

### Performance Reality

Benchmarks show Node.js executing API requests 3x faster than PHP 7.4 (31ms vs 91ms) [NETGURU-NODEJS]. "Node.js operates asynchronously, allowing it to efficiently process multiple requests simultaneously. PHP operates synchronously, which means it must wait for each process to complete before moving on to the next, limiting its ability to handle large numbers of concurrent connections" [NETGURU-NODEJS].

The PHP 8.x JIT compiler doesn't help with concurrency — it optimizes computational code, not I/O [PHP-JIT].

### What This Means for Penultima

PHP demonstrates what happens when you design a language without concurrency and then try to add it later: fragmented ecosystem, incompatible libraries, no language-level safety, and performance that lags behind languages designed with concurrency from the start.

Penultima should:
- Design concurrency primitives into the language from day one
- Provide language-level protection against data races
- Make async/sync distinction explicit and compiler-checked
- Avoid the "add concurrency via extension" trap

## 5. Error Handling

PHP's error handling is a lesson in how accumulated backward compatibility constraints can make a system fundamentally incoherent.

### Three Incompatible Systems

PHP has three error handling mechanisms that don't interoperate:

1. **Traditional PHP errors** (E_ERROR, E_WARNING, E_NOTICE, etc.): Handled by `set_error_handler()`, cannot be caught with try/catch, and fatal errors cannot be handled at all [EEVEE-PHP]

2. **Exceptions**: Introduced in PHP 5, caught with try/catch, don't trigger error handlers set by `set_error_handler()` [EEVEE-PHP]

3. **Errors (the class)**: Introduced in PHP 7 to make fatal errors catchable, creating a separate `Error` hierarchy parallel to `Exception` [SITEPOINT-ERRORS]

The interaction between these systems is byzantine:
- PHP errors cannot be caught with try/catch
- Exceptions don't trigger error handlers
- There's a separate `set_exception_handler()` for uncaught exceptions
- Error (the class) can be caught with try/catch, but it's not an Exception
- Some fatal errors throw Error instances; others still can't be caught [SITEPOINT-ERRORS]

### Information Loss

Error handlers "can't handle errors that may arise within your handler itself, and is not able to catch certain internal errors, like E_CORE_ERROR and E_COMPILE_ERROR" [SITEPOINT-ERRORS]. When an error occurs during error handling, you get silence.

Custom error handlers bypass PHP's standard error handling, meaning error_log() and display_errors settings may not work as expected. Logging becomes a per-application concern with "loggers injected in classes all over the place logging problems independently with inconsistent behaviour" [NETGEN-ERROR].

### The False Return Value Anti-Pattern

PHP's internal functions return `false` on error rather than throwing exceptions:

```php
$data = file_get_contents('config.json');
// $data is now false if the file doesn't exist,
// but false is a valid string value in loose comparisons
if ($data) {  // Bug: empty file contents also fail this check
    // ...
}
```

This pattern encourages developers to either:
1. Check every return value explicitly (verbose, often skipped)
2. Use `@` error suppression operator (hides legitimate errors)
3. Convert errors to exceptions with custom error handlers (more boilerplate)

### Inconsistent Exception Usage

Even in modern PHP, exception usage is inconsistent:
- `mysqli` throws exceptions in PHP 8.1+ by default
- `PDO` throws exceptions if you set `PDO::ATTR_ERRMODE`
- Many internal functions still return `false`
- Some functions throw `ValueError`, others throw `TypeError`, others throw generic `Exception`

The JetBrains 2025 survey found that 32% of developers still don't write tests at all [JETBRAINS-PHP-2025]. While this reflects developer culture, the language's error handling complexity contributes: when error handling is this difficult to get right, testing becomes even more important — and more difficult.

### What This Means for Penultima

PHP demonstrates that error handling compatibility can't be fixed incrementally. Once you have three incompatible systems, you can't unify them without breaking enormous codebases.

Penultima must:
- Choose one error handling mechanism and commit to it completely
- Make errors visible and difficult to ignore by default
- Preserve error context through all propagation paths
- Avoid sentinel values (like returning false) for error signaling
- Never use error suppression operators

## 6. Ecosystem and Tooling

PHP's ecosystem is vast but uneven. The sheer scale of deployment (77% of websites with identifiable server-side languages [PHP-CVE]) ensures comprehensive tooling, but quality varies dramatically.

### Package Management: Composer

Composer is mature and functional, solving dependency resolution correctly. However:

- **No built-in security auditing**: Unlike npm or cargo, Composer has no native `composer audit` command. Third-party tools like Roave Security Advisories exist but aren't standard.

- **Version resolution complexity**: Composer's constraint solver is powerful but slow for large dependency trees. The `platform` config and extension requirements create resolution failures that are difficult to debug.

- **Autoloading performance**: PSR-4 autoloading requires filesystem stats on every class load. Composer's optimized classmap helps, but production deployments still pay an I/O cost that compiled languages avoid entirely.

### Build System: None

PHP has no standard build system. For pure PHP projects, Composer suffices. But for projects mixing PHP with frontend assets, database migrations, Docker containers, and deployment automation:

- Common choices: Make, custom shell scripts, or framework-specific commands (Laravel Mix, Symfony Encore)
- No standardization means every project invents its own build process
- No caching or incremental build support (because there's nothing to build — PHP is interpreted)

### IDE Support: Excellent But Compensatory

PhpStorm is industry-leading, but note what it compensates for:

- **Type inference to recover generics**: PhpStorm infers array element types from docblock `@param` annotations because PHP has no generics
- **Error detection for standard library**: PhpStorm flags incorrect parameter counts and types for internal functions because PHP's weak mode allows these at runtime
- **Refactoring support**: PhpStorm's rename refactoring must be more conservative than in statically-typed languages because PHP's dynamic features (variable variables, `$$foo`) mean static analysis can't guarantee correctness

PHPStan (36% usage) and Psalm are essential precisely because the language doesn't provide static analysis [JETBRAINS-PHP-2025]. This is a tax on every PHP developer — a tool that TypeScript, Rust, or Go developers simply don't need.

### Testing Ecosystem: Fragmented

PHPUnit dominates unit testing, but:
- 32% of developers still don't write tests [JETBRAINS-PHP-2025]
- Property-based testing (PHPQuickCheck) exists but is marginal
- Mutation testing (Infection) exists but requires careful configuration
- Integration testing approaches vary wildly (Behat, Codeception, Dusk)

The testing gap isn't entirely PHP's fault, but the language doesn't help. Lack of generics makes test doubles more difficult. Weak type checking means tests catch issues that compilers should catch.

### Debugging and Profiling: Adequate

Xdebug is functional but slow (not suitable for production). For production:
- Tideways, Blackfire, or New Relic (commercial)
- Built-in profiling (`register_tick_function`) with high overhead
- No built-in tracing or metrics primitives

### What This Means for Penultima

PHP's ecosystem demonstrates that third-party tools can compensate for language weaknesses — but at a cost. Every PHP developer needs PhpStorm or equivalent, needs PHPStan, needs Composer, needs Xdebug, needs a testing framework. That's significant cognitive load and tooling expense.

Penultima should provide:
- Built-in security auditing for dependencies
- First-class IDE protocol support in the language specification
- Static analysis that doesn't require external tools
- Testing primitives in the standard library

## 7. Security Profile

PHP's security profile is dominated by injection vulnerabilities, type juggling bypasses, and insecure defaults. The CVE data is stark.

### Injection Dominance

From the CVE baseline [PHP-CVE]:

- **SQL Injection (CWE-89)**: ~14,000 CVEs across all languages, with PHP applications consistently represented
- **XSS (CWE-79)**: ~30,000 CVEs; ranks #2 in CWE Top 25
- **OS Command Injection (CWE-78)**: Thousands of CVEs; recent PHP-CGI argument injection (CVE-2024-4577) affected ~458,800 instances [PHP-CVE]
- **Remote/Local File Inclusion (CWE-98)**: Persistent in legacy codebases; historical spike in 2006 with ~1000% increase [PHP-CVE]

### Language-Level Enablers

These vulnerabilities aren't just implementation mistakes — they're enabled by language design:

**1. No Output Escaping by Default**

PHP doesn't auto-escape output. Developers must explicitly call `htmlspecialchars()` or use frameworks that do it. This is backwards: unsafe should be explicit, safe should be default [PHP-CVE].

Modern frameworks (Laravel Blade, Symfony Twig) auto-escape, but plain PHP templates (still widespread) don't. This split means "output security" depends on framework choice.

**2. Type Juggling Authentication Bypasses**

Type juggling enables authentication bypasses documented in real CVEs [FOXGLOVE-TYPE-JUGGLING]. When user input is compared with `==` instead of `===`, attackers can exploit type coercion to bypass checks.

**3. Dangerous Inclusion Semantics**

`include()`, `require()`, and their `_once` variants accept user input and support stream wrappers:
- `data://` wrapper allows inline code execution
- `php://input` allows POST body execution
- `allow_url_include` (a php.ini directive) enables remote code execution via HTTP URLs [PHP-CVE]

The secure default would be: includes are static paths only. Runtime includes should require explicit opt-in with different syntax. PHP did the opposite.

**4. Legacy API Vulnerabilities**

Deprecated APIs remain in widespread use:
- `mysql_*` functions (removed PHP 7.0) lacked prepared statements, enabling SQL injection [PHP-CVE]
- `register_globals` (removed PHP 5.4) enabled variable overwrite attacks [PHP-CVE]
- `eval()` and `assert()` with user input are still code injection vectors

### Deployment Scale Amplification

PHP's 77% market share means a single PHP vulnerability affects hundreds of thousands of sites [PHP-CVE]. CVE-2024-4577 (PHP-CGI argument injection, CVSS 9.8) exposed ~458,800 instances within months [PHP-CVE].

This isn't PHP's fault per se, but it means PHP vulnerabilities have outsized impact. A language designed to replace PHP must be more secure, not equally secure.

### Supply Chain Gaps

Composer has no built-in security auditing. Packagist (the package repository) has no malware scanning comparable to npm's. The PHP Foundation formed in 2021, but supply chain security remains underdeveloped compared to npm, cargo, or pip.

### What This Means for Penultima

PHP's security problems aren't unsolvable — modern PHP frameworks demonstrate that secure-by-default APIs work. But the language itself enables vulnerabilities through:
- Insecure defaults (no auto-escaping, permissive includes)
- Type system weaknesses (juggling bypasses)
- Legacy API surface that can't be removed due to backward compatibility

Penultima must:
- Make security the default: output escaping, parameterized queries, sandboxed includes
- Eliminate type coercion in comparisons
- Design APIs that make insecure patterns difficult to write
- Provide built-in supply chain security tooling

## 8. Developer Experience

PHP's developer experience is characterized by high initial accessibility followed by mounting frustration as projects scale.

### Learnability: Deceptively Easy

PHP is easy to start with: write `<?php echo "Hello"; ?>`, save as `.php`, and it works. This accessibility is real and valuable.

The problem is what comes next. Developers learn PHP's loose comparison, then discover `===` is required for correctness. They learn `mysql_*` functions, then discover they're deprecated and insecure. They learn `include($_GET['page'])`, then discover it's a security vulnerability. **PHP teaches bad habits by making them the path of least resistance.**

The JetBrains 2025 survey shows 88% of PHP developers have more than 3 years of experience [JETBRAINS-PHP-2025]. This isn't because PHP is hard to learn — it's because PHP experience is largely learning what not to do.

### Cognitive Load: Death by Inconsistency

PHP's standard library naming is legendarily inconsistent [RFC-CONSISTENT-NAMES]:
- `strpos` vs `str_split` vs `substr`
- `htmlspecialchars` vs `html_entity_decode`
- `array_map($fn, $arr)` vs `array_filter($arr, $fn)` — parameter order differs

This isn't pedantic — it's cognitive load. Developers can't rely on naming patterns to predict API shape. They must memorize each function individually or constantly refer to documentation.

The PHP RFC for consistent function names documents the problem but couldn't fix it due to backward compatibility constraints [RFC-CONSISTENT-NAMES]. Community libraries like `brick/std` and `azjezz/psl` exist specifically to provide consistent APIs wrapping PHP's inconsistent ones [GITHUB-PSL].

### Error Messages: Improving But Still Weak

PHP 8 improved error messages significantly, but fundamental issues remain:

- Fatal errors still don't show stack traces in many contexts
- Namespace resolution errors are cryptic ("Class 'Foo' not found" when you meant `\Namespace\Foo`)
- Type errors in weak mode are suppressed entirely until runtime, then report at the call site rather than the declaration site

Compare to Rust's errors (which tell you how to fix the problem) or TypeScript's errors (which show type mismatch details). PHP's errors tell you what broke, rarely why.

### Expressiveness vs. Ceremony

Modern PHP (8.3) has improved dramatically:
- Constructor property promotion reduces boilerplate
- Named arguments improve clarity
- Match expressions are cleaner than switch
- Enums eliminate magic constants

But PHP still requires more ceremony than necessary:
- No pipeline operator (though RFC exists)
- Array operations require explicit loops or `array_*` functions rather than chainable methods
- No pattern matching beyond basic `match`
- String interpolation requires specific quote types and syntax

### Community and Culture

PHP's community is vast but fragmented. Laravel dominates (64% usage [JETBRAINS-PHP-2025]) but isn't universal. WordPress (25% usage) has a different culture, different patterns, different standards.

The PHP-FIG (PHP Framework Interop Group) created PSR standards to unify conventions, but they're recommendations, not requirements. Code style wars continue (PSR-2 vs PSR-12, tabs vs spaces).

The 32% of developers who don't write tests [JETBRAINS-PHP-2025] reflect a culture where testing isn't universal practice. This is changing — Laravel and Symfony emphasize testing — but the legacy of "PHP as quick scripting glue" persists.

### Job Market Reality

PHP jobs exist in abundance due to the massive installed base, but:
- Stack Overflow 2025 salary data (if available) would likely show PHP salaries below Go, Rust, or TypeScript
- Modern startups default to Node.js, Python, or Go for new projects
- PHP's reputation problem means "PHP developer" carries stigma that "TypeScript developer" doesn't

This is partly unfair — modern PHP is far better than its reputation — but perception matters for hiring and career growth.

### What This Means for Penultima

PHP's developer experience problems are fixable (as modern frameworks prove), but the language itself actively works against developers:
- Inconsistent naming creates unnecessary memorization burden
- Weak defaults require constant vigilance
- Backward compatibility prevents fixing known issues

Penultima should:
- Design naming conventions before writing standard library
- Make safe patterns the path of least resistance
- Prioritize error message quality from day one
- Foster testing culture through built-in testing primitives

## 9. Performance Characteristics

PHP's performance has improved dramatically with PHP 7 and 8, but fundamental limitations remain due to its interpreted, dynamically-typed nature.

### Runtime Performance: Better, But Still Behind

The Computer Language Benchmarks Game and TechEmpower benchmarks consistently show PHP trailing compiled languages and even other interpreted languages in compute-intensive tasks.

Real-world 2025 benchmarks show Node.js executing API requests 3x faster than PHP 7.4 (31ms vs 91ms) [NETGURU-NODEJS]. "Node.js operates asynchronously, allowing it to efficiently process multiple requests simultaneously. PHP operates synchronously, which means it must wait for each process to complete before moving on to the next" [NETGURU-NODEJS].

PHP 8's JIT compiler improves computational performance but has minimal impact on typical web applications. As one analysis notes: "JIT is unable to significantly improve the performance of web applications, and in some specific scenarios, it might even result in worse performance than before" [STITCHER-JIT]. The reason: web applications spend time in I/O, database queries, and framework overhead, not tight CPU loops where JIT helps.

### JIT Limitations

PHP 8.0's JIT has structural limitations [PHP-JIT-WATCH]:

- **Architectural constraints**: Only supports x86/x64; ARM and Apple M1 unsupported initially (later added but with limitations)
- **Debugging barriers**: JIT-compiled code is opaque to standard debuggers [ZEND-JIT]
- **Bug risk**: "JIT increases risk of bugs in JIT itself... Fixing these new kind of bugs is going to be more difficult" [PHP-JIT-RFC]
- **Real-world impact**: "Sporadic and unexplainable 503 errors and weak performance gain in general" reported in production [STITCHER-JIT]

The JIT is a performance improvement, but it's a band-aid on fundamental issues: PHP's dynamic dispatch, type checking overhead, and lack of zero-cost abstractions.

### Compilation Speed: N/A

PHP is interpreted (or JIT-compiled at runtime), so there's no ahead-of-time compilation step. This is an advantage for rapid iteration — edit PHP, refresh browser — but eliminates opportunities for ahead-of-time optimization.

OpCache caches parsed bytecode, which helps, but the lack of static compilation means:
- No tree-shaking or dead code elimination
- No link-time optimization
- No compile-time computation or constant folding beyond basic opcodes

### Startup Time: Fast for Scripts, Irrelevant for Web

PHP scripts start instantly because there's no compilation step and minimal runtime initialization. This makes PHP excellent for CLI tools and traditional page-based web apps.

However:
- For serverless/FaaS, PHP's lack of native async means it's not competitive with Node.js or Go
- For long-running workers, startup time is irrelevant, and PHP's lack of concurrency primitives is the limiting factor

### Resource Consumption: Memory Hungry

PHP's memory footprint is large compared to compiled languages:
- Each Apache mod_php process replicates the entire PHP interpreter and loaded code
- PHP-FPM improves this but still requires separate processes for parallelism
- No shared memory between requests unless using extensions like APCu

For high-traffic sites, this means high memory costs. Benchmarks show PHP consuming 2-5x the memory of equivalent Go or Rust services.

### Optimization Story: Fight the Language

Performance-critical PHP requires fighting the language:
- Avoid array operations (copy overhead); use explicit loops
- Avoid magic methods (`__get`, `__call`); use explicit methods
- Avoid abstractions (overhead); inline hot paths
- Avoid dynamic features; use static analysis to eliminate them

This is backwards. Languages like Rust and C++ let you write idiomatic code with zero-cost abstractions. PHP's abstractions have costs that show up in profilers, forcing developers to choose between readability and performance.

### What This Means for Penultima

PHP's performance is "good enough" for many web applications, but that's not the standard for a new language in 2025. Languages like Go and Rust provide orders-of-magnitude better performance while being safer and more maintainable.

Penultima should:
- Provide ahead-of-time compilation for optimizability
- Design zero-cost abstractions into the language
- Support both async I/O and compute parallelism
- Compete with compiled languages, not just interpreted ones

## 10. Interoperability

PHP's interoperability is constrained by its design as a shared-nothing, request-oriented language.

### Foreign Function Interface: Belated and Limited

PHP 7.4 introduced FFI (Foreign Function Interface) for calling C libraries without writing extensions [PHP-FFI]. This is progress, but:

- **Performance overhead**: FFI calls are significantly slower than native extension calls
- **Safety**: No memory safety guarantees; segfaults are possible and unrecoverable
- **Platform limitations**: FFI requires `libffi` and isn't available in all environments
- **Debugging**: Crashes in FFI code produce C-level stack traces that PHP developers can't easily interpret

Before FFI, interop required writing C extensions, which meant compiling against PHP's internal API — an API that changes between major versions and is poorly documented.

### Embedding: Possible But Uncommon

PHP can be embedded (e.g., in nginx with php-fpm, or in custom applications), but:
- The embedding API is C-only and poorly documented
- The thread-safety story is complex (ZTS vs non-ZTS builds)
- Embedded PHP still assumes request/response lifecycle

Unlike Lua (designed for embedding) or JavaScript (widely embedded via V8/JavaScriptCore), PHP isn't a natural choice for embedded scripting.

### Data Interchange: Standard but Inefficient

PHP supports JSON, XML, and other formats, but:

- **JSON performance**: PHP's json_encode/decode are relatively slow compared to dedicated parsers
- **Protobuf**: Requires third-party extensions (Google's protobuf-php or Protobuf-PHP)
- **MessagePack**: Available via extension but not standard library
- **Serialization format**: PHP's native `serialize()` format is PHP-specific and insecure (object injection vulnerabilities [OWASP-PHP-INJECTION])

### Cross-Compilation: None

PHP doesn't cross-compile. You can deploy PHP code to any platform that has a PHP interpreter, but you can't compile PHP to native binaries for distribution.

This contrasts with Go (trivial cross-compilation), Rust (excellent cross-compilation), and even Python (PyInstaller, though imperfect).

### WebAssembly: Experimental

PHP to WebAssembly compilation exists experimentally (php-wasm), but it's not production-ready and involves compiling the entire PHP interpreter to WASM — a heavy payload.

### Polyglot Deployment: Common But Awkward

PHP commonly coexists with other languages (Python for ML, Go for services, Rust for performance), but integration is awkward:
- Communication via HTTP, message queues, or databases
- No shared memory or efficient IPC
- Different deployment models (PHP-FPM vs standalone binaries)

This is solvable at the architecture level, but PHP's design doesn't facilitate it.

### What This Means for Penultima

PHP's interoperability is adequate for traditional web hosting but weak for modern polyglot systems. A language designed in 2025 should:
- Provide safe, fast FFI from day one
- Support WebAssembly compilation as a first-class target
- Offer embedding APIs for multiple host languages
- Standardize efficient serialization formats (protobuf, msgpack)

## 11. Governance and Evolution

PHP's governance demonstrates how corporate-sponsored open source can improve technical outcomes while creating sustainability questions.

### The PHP Foundation Era

Historically, PHP development was informal and personality-driven. Rasmus Lerdorf created it, Andi Gutmans and Zeev Suraski rewrote it (PHP 3-7), and Nikita Popov drove many modern improvements (PHP 7 AST, JIT architecture).

In 2021, after Nikita Popov reduced his involvement, the PHP Foundation formed with backing from Automattic, Laravel, Acquia, Zend, Private Packagist, Symfony, and others [PHP-FOUNDATION]. The Foundation now funds core developers.

This is positive — it ensures bus factor isn't one person — but creates dependency on corporate sponsors. If sponsors withdraw, development could slow dramatically.

### RFC Process: Democratic But Slow

PHP uses an RFC (Request for Comments) process where proposals require 2/3 supermajority vote from core developers [PHP-RFC-PROCESS]. This is democratic but creates high barriers:

- Good ideas can fail due to implementation concerns
- Controversial features require extensive discussion
- Backward compatibility concerns block necessary breaking changes

The "Consistent Function Names" RFC documents the problem: everyone agrees PHP's function names are inconsistent, but fixing them would break millions of lines of code, so the RFC was essentially abandoned [RFC-CONSISTENT-NAMES].

### Rate of Change: Fast Feature Addition, No Breaking Changes

PHP releases annually (8.0 in 2020, 8.1 in 2021, 8.2 in 2022, 8.3 in 2023) with new features. But backward compatibility is sacrosanct:

- `mysql_*` functions were deprecated for years before removal
- `register_globals` was deprecated in 2002, removed in 2012
- Type juggling can't be fixed because it would break existing code
- Inconsistent function names will likely never be fixed

This creates a language that accumulates features but can't remove mistakes. PHP 8.3 carries the design decisions of PHP 3 from 1998.

### Feature Accretion: Visible

PHP has accumulated features that now seem redundant or questionable:
- Multiple string quote types with different interpolation rules
- Magic quotes (removed), register_globals (removed), safe_mode (removed) — all added, then removed after causing security issues for years
- Multiple extension mechanisms (extensions, Zend extensions, FFI)
- Multiple array iteration syntaxes (foreach, each/list, array_walk, iterators)

Some of this is natural for a 30-year-old language, but it reflects a governance culture that's more willing to add than to remove.

### Bus Factor: Improved But Uncertain

The PHP Foundation reduces bus factor from "handful of individuals" to "funded organization," which is progress. But:

- Core developers are still relatively few
- RFC voting is restricted to core developers
- If major sponsors withdraw, sustainability is unclear

### Standardization: None

PHP has no ISO or ECMA standard. The php.net documentation is de facto specification, and the Zend Engine implementation is the reference. Alternative implementations exist (HHVM was PHP-compatible but diverged) but aren't maintained for compatibility.

This means "PHP" is defined by what Zend Engine does, not by a specification. Behavior can change between versions without violating a standard because there is no standard.

### What This Means for Penultima

PHP's governance shows that:
- Democratic RFC processes can preserve backward compatibility at the cost of fixing mistakes
- Corporate sponsorship improves sustainability but creates dependencies
- Lack of formal specification makes the implementation the specification

Penultima should:
- Define a specification before creating an implementation
- Establish governance that can make breaking changes when necessary
- Ensure bus factor is high through institutional support, not individual contributors
- Balance stability with evolution — backward compatibility is valuable, but not sacred

## 12. Synthesis and Assessment

### Greatest Weaknesses

**1. Type System Incoherence**

PHP's type juggling creates non-transitive equality, enabling security vulnerabilities and logic errors. The gradual typing system is too weak to provide static guarantees but restrictive enough to require workarounds. Lack of generics means type safety is comment-based.

**Impact**: Developers require third-party tools (PHPStan, Psalm) to achieve basic type safety. 36% adoption of static analyzers [JETBRAINS-PHP-2025] represents massive ecosystem investment compensating for language failure.

**2. Security-Hostile Defaults**

No output escaping by default, permissive file inclusion with stream wrappers, weak type comparisons in authentication contexts, and legacy APIs designed before security was a priority. The CVE data is overwhelming: XSS, SQL injection, RFI/LFI, and command injection dominate PHP's vulnerability profile [PHP-CVE].

**Impact**: PHP applications require constant vigilance and framework-level compensations to be secure. The language makes insecure code easier to write than secure code.

**3. Standard Library Inconsistency**

Function naming, parameter ordering, and error handling are inconsistent across the standard library. This isn't cosmetic — it's cognitive load that makes PHP harder to learn and use correctly. The RFC to fix this was abandoned due to backward compatibility [RFC-CONSISTENT-NAMES].

**Impact**: Developers must memorize irregularities or constantly check documentation. Community creates wrapper libraries (brick/std, azjezz/psl) to provide consistency the language doesn't [GITHUB-PSL].

**4. No Coherent Concurrency Model**

PHP was designed for single-threaded request/response and has no built-in concurrency. Extensions (Swoole, pthreads) and libraries (ReactPHP, Amp) provide incompatible solutions. Performance lags behind languages designed with concurrency primitives [NETGURU-NODEJS].

**Impact**: PHP is unsuitable for high-concurrency workloads without significant extension-based workarounds. The ecosystem remains fragmented with no path to unified async/await.

**5. Accumulated Technical Debt**

30 years of backward compatibility means PHP carries design mistakes that can't be fixed. Type juggling, inconsistent APIs, and insecure defaults persist because breaking changes affect 77% of websites [PHP-CVE].

**Impact**: The language is harder to learn and use than it should be. Modern PHP (8.3) is significantly better than PHP 5, but fundamental issues remain unfixable.

### Greatest Strengths

**1. Deployment Accessibility**

PHP's shared-nothing architecture and ubiquitous hosting support mean deploying PHP is trivial. No compilation, no container orchestration required — upload files, and it works. This accessibility is real and valuable.

**2. Mature Ecosystem**

Laravel and Symfony are excellent frameworks that compensate for many language weaknesses. Composer is reliable. PHPStorm is industry-leading. The ecosystem has solutions for most problems.

**3. Continuous Improvement**

PHP 7 and 8 represent dramatic improvements in performance, type system, and language features. The PHP Foundation and RFC process ensure ongoing development. Modern PHP is far better than its reputation.

### Lessons for Penultima

**What to Avoid:**

1. **Don't design for a single use case**: PHP optimized for request/response; everything else is awkward
2. **Don't allow unfixable mistakes**: Backward compatibility is valuable, but not if it prevents fixing security issues
3. **Don't have permissive security defaults**: Make safe behavior the default, require opt-in for unsafe
4. **Don't add concurrency as an afterthought**: Design it into the language from day one
5. **Don't skip type system discipline**: Either commit to dynamic typing or provide real static guarantees
6. **Don't let standard library grow organically**: Design naming conventions first, enforce them
7. **Don't use comments for type safety**: If the type system needs docblocks to be useful, it's not useful

**What to Adopt:**

1. **Deployment simplicity matters**: PHP's ease of deployment is a genuine advantage
2. **Iterative improvement works**: Annual releases with new features keep the language relevant
3. **Framework ecosystem is critical**: Language features should enable great frameworks
4. **Community governance can work**: RFC process with corporate backing provides stability

**Open Questions:**

1. Can a language balance "easy to start" with "hard to misuse"? PHP is easy to start but easy to misuse.
2. How much backward compatibility is too much? PHP can't fix type juggling; is that acceptable?
3. What's the right relationship between language and framework? PHP depends heavily on frameworks to be usable.

### Conclusion

PHP is a language that succeeded despite its design, not because of it. Its dominance reflects the historical accident of being "good enough" when the web exploded, combined with hosting ubiquity and ecosystem investment.

Modern PHP (8.3) is dramatically better than PHP 5, but fundamental problems remain: type juggling, insecure defaults, standard library inconsistency, and lack of concurrency. These can't be fixed without breaking the massive installed base.

For Penultima, PHP is a cautionary tale: **languages that prioritize backward compatibility over correctness accumulate unfixable problems**. A new language has the luxury of learning from PHP's mistakes without inheriting its constraints.

The goal shouldn't be to build "PHP but better" — it should be to provide what PHP developers *wish* they had: type safety without ceremony, security by default, coherent concurrency, and a standard library designed as a whole rather than grown organically.

PHP proves that you can build a successful language with serious flaws. Penultima should prove that you can build a successful language without them.

## References

[PHP-HISTORY] PHP Foundation. "PHP: History of PHP - Manual". https://www.php.net/manual/en/history.php.php

[CODEMOTION-PHP] Codemotion Magazine. "25 years of PHP: history and curiosities by Rasmus Lerdorf". https://www.codemotion.com/magazine/languages/25-years-of-php-history-and-curiosities-by-rasmus-lerdorf/

[PHP-CVE] Evidence file: `evidence/cve-data/php.md`. CVE Pattern Summary: PHP. Document Date: February 2026.

[INVICTI-TYPE-JUGGLING] Invicti. "PHP Type Juggling Vulnerabilities & How to Fix Them". https://www.invicti.com/blog/web-security/php-type-juggling-vulnerabilities

[COFFEE-CODER-TYPE] Coffee Coder. "My Perfect Reason to Avoid PHP: Type Juggling". https://coffeecoder.net/blog/my-perfect-reason-avoid-php-type-juggling/

[FOXGLOVE-TYPE-JUGGLING] Foxglove Security. "Type Juggling and PHP Object Injection, and SQLi, Oh My!". https://foxglovesecurity.com/2017/02/07/type-juggling-and-php-object-injection-and-sqli-oh-my/

[EEVEE-PHP] fuzzy notepad (Eevee). "PHP: a fractal of bad design". https://eev.ee/blog/2012/04/09/php-a-fractal-of-bad-design/

[JETBRAINS-PHP-2025] JetBrains. "The State of PHP 2025 – Expert review". https://blog.jetbrains.com/phpstorm/2025/10/state-of-php-2025/

[PHP-GC] PHP Foundation. "PHP: Performance Considerations - Manual". https://www.php.net/manual/en/features.gc.performance-considerations.php

[TIDEWAYS-GC] Tideways. "How to optimize the PHP garbage collector usage to improve memory and performance?". https://tideways.com/profiler/blog/how-to-optimize-the-php-garbage-collector-usage-to-improve-memory-and-performance

[PHP-GC-MEDIUM] Aamou, Khouloud Haddad. "PHP Memory Optimization Tips". Medium. https://medium.com/@khouloud.haddad/php-memory-optimization-tips-f362144b9ce4

[PHP-GC-GUIDE] DEV Community. "How PHP Handles Memory Management and Garbage Collection: A Comprehensive Guide". https://dev.to/abhay_yt_52a8e72b213be229/how-php-handles-memory-management-and-garbage-collection-a-comprehensive-guide-436o

[SWOOLE-MEDIUM] Chimin. "Why Swoole 6.2 maybe the Best Technical Choice for Building PHP Asynchronous Concurrent Programming Capabilities". Medium. https://medium.com/php-developer/why-swoole-6-2-360c3c05a1c5

[REACTPHP-ASYNC] fsck.sh. "Async PHP in Production: Fibers, ReactPHP, and Swoole Demystified". https://fsck.sh/en/blog/async-php-fibers-reactphp-swoole/

[AMP-ASYNC] AMPHP. "Asynchronous Multitasking PHP". https://amphp.org/

[ASYNC-PHP-2025] Shahkhajeh, Mohamad. "Async PHP in 2025: Beyond Workers with Fibers, ReactPHP, and Amp". Medium. https://medium.com/@mohamadshahkhajeh/async-php-in-2025-beyond-workers-with-fibers-reactphp-and-amp-e7de384c3ea6

[NETGURU-NODEJS] Netguru. "An In-Depth Comparison of Node.js vs. PHP in 2025". https://www.netguru.com/blog/node-js-vs-php

[SITEPOINT-ERRORS] SitePoint. "Error Handling in PHP". https://www.sitepoint.com/error-handling-in-php/

[NETGEN-ERROR] Netgen. "Modern Error handling in PHP". https://netgen.io/blog/modern-error-handling-in-php

[RFC-CONSISTENT-NAMES] PHP Foundation. "PHP: rfc:consistent_function_names". https://wiki.php.net/rfc/consistent_function_names

[GITHUB-PSL] GitHub. "azjezz/psl: 📚 PHP Standard Library - a modern, consistent, centralized, well-typed, non-blocking set of APIs for PHP programmers". https://github.com/azjezz/psl

[PHP-JIT-WATCH] PHP.Watch. "PHP JIT in Depth". https://php.watch/articles/jit-in-depth

[ZEND-JIT] Zend. "PHP JIT Compiler | New PHP 8.0 JIT | PHP 8 Features". https://www.zend.com/blog/exploring-new-php-jit-compiler

[PHP-JIT-RFC] PHP Foundation. "PHP: rfc:jit". https://wiki.php.net/rfc/jit

[STITCHER-JIT] Stitcher.io. "PHP 8: JIT performance in real-life web applications". https://stitcher.io/blog/jit-in-real-life-web-applications

[PHP-STREAMS] PHP Foundation. "PHP: Stream Wrappers - Manual". https://www.php.net/manual/en/wrappers.php

[PHP-FFI] PHP Foundation. "PHP: FFI - Manual". https://www.php.net/manual/en/book.ffi.php

[OWASP-PHP-INJECTION] OWASP. "PHP Object Injection". https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection

[PHP-FOUNDATION] PHP Foundation. "The PHP Foundation". https://thephp.foundation/

[PHP-RFC-PROCESS] PHP Foundation. "PHP: RFC Process - Wiki". https://wiki.php.net/rfc/howto
