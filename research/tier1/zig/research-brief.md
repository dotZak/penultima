# Zig — Research Brief

```yaml
role: researcher
language: "Zig"
agent: "claude-agent"
date: "2026-02-27"
```

---

## Language Fundamentals

### Creator and Institutional Context

Zig was created by Andrew Kelley. Kelley began work on the language in 2015 and published the first public announcement, "Introduction to the Zig Programming Language," on February 8, 2016 [KELLEY-2016]. The language was developed independently; there is no corporate creator. In July 2020, Kelley incorporated the **Zig Software Foundation (ZSF)**, a 501(c)(3) non-profit corporation, to provide legal and financial infrastructure for the project [ZSF-ABOUT].

Andrew Kelley serves as President of the ZSF and is designated as the language's BDFL (Benevolent Dictator for Life) [LWN-2024]. Loris Cro (VP of Community) and Jacob Young (core team, backend specialist) are among the other prominent contributors as of 2025. The core team is paid through ZSF contractor agreements.

### Stated Design Goals

From the official Zig documentation and Kelley's public statements:

> "Zig is a general-purpose programming language and toolchain for maintaining **robust**, **optimal**, and **reusable** software." [ZIGLANG-HOME]

The language homepage explicitly contrasts Zig with alternatives by listing what it lacks: no hidden control flow, no hidden memory allocations, no preprocessor or macros, no undefined behavior (in safe modes). From the language overview:

> "Zig competes with C as a language whose job is to be the baseline for other languages to call into." [ZIGLANG-OVERVIEW]

On simplicity of the specification, Kelley has stated:

> "The primary goal of Zig is to be a better solution to the sorts of tasks that are currently solved with C, with a primary concern in that respect being readability; Zig attempts to use existing concepts and syntax wherever possible, avoiding the addition of different syntax for similar concepts." [INFOWORLD-2024]

On the 2024 roadmap, Kelley identified four prerequisites to 1.0: compiler performance, language improvements, standard library quality, and writing a formal language specification, with the specification being described as "a stability turning point" [LWN-2024].

### Classification

- **Paradigm:** Imperative, structured; comptime enables metaprogramming without a separate macro language
- **Typing discipline:** Static, nominative, strongly typed; no implicit coercions between types
- **Memory management:** Manual; allocators are explicit parameters — the language has no global allocator
- **Compilation model:** Ahead-of-time compiled; LLVM backend (primary for release builds); self-hosted x86_64 backend (default for Debug builds as of 0.15.x)
- **Runtime:** No garbage collector; minimal runtime (Zig programs can be free-standing)
- **Standard:** No ISO/ECMA standard; no formal backward-compatibility policy pre-1.0

### Current Stable Version

As of February 2026, the current stable release is **0.15.2**, released October 12, 2025 [ZIGGIT-0152]. Version 0.16.0 is in active development on Codeberg (canonical origin since November 26, 2025) [ZIG-CODEBERG].

---

## Historical Timeline

### Founding and Early Development (2015–2019)

- **2015:** Andrew Kelley begins work on Zig as a personal project, motivated by a need for better low-level control in a music studio project [CORECURSIVE-067].
- **February 8, 2016:** First public blog post: "Introduction to the Zig Programming Language" [KELLEY-2016].
- **October 17, 2017:** Version 0.1.0 — initial public release [RELEASES].
- **November 1, 2017:** Version 0.1.1 — minor patch [RELEASES].
- **March 15, 2018:** Version 0.2.0 [RELEASES].
- **September 28, 2018:** Version 0.3.0 [RELEASES].
- **April 9, 2019:** Version 0.4.0 [RELEASES].

### Infrastructure and Growth (2020–2022)

- **July 2020:** Zig Software Foundation incorporated as a 501(c)(3) non-profit by Andrew Kelley [ZSF-ABOUT].
- **2020–2022:** Bootstrap compiler (written in C++) progressively replaced by a self-hosted compiler written in Zig itself.
- **December 2022:** C++ bootstrap compiler officially discontinued; self-hosted compiler capable of building itself [ZIG-SELF-HOSTED]. This milestone represented a significant maturation of the compiler.

### Language Stabilization Phase (2023–2025)

- **2023 (July 19):** 0.11.0 release postponed; async/await removed from the language pending a complete redesign [ZIG-NEWS-2023]. Async functions had been present since 0.6.0 but were removed because the self-hosted compiler could not yet implement them, and the design was being reconsidered.
- **2023 (~August):** Version 0.11.0 released without async/await.
- **2024 (~April):** Version 0.12.0 released; introduced the built-in package manager (build.zig.zon dependency format) as a first-class feature [ZIG-PKG-HN].
- **2024 (~June):** Version 0.13.0 released; compilation speed improvements as the release theme [ZIG-013-NOTES].
- **October 2024:** Mitchell Hashimoto pledges $300,000 to ZSF (paid in two annual $150,000 installments) [MITCHELLH-DONATION]. TigerBeetle and Synadia together pledge $512,000 to ZSF [TIGERBEETLE-DONATION].
- **March 5, 2025:** Version 0.14.0 released (delayed from February 17, 2025 target) [ZIG-014-DAILY]. 9 months of work; 251 contributors; 3,467 commits. Key features: incremental compilation (500K-line project: 14s → 63ms reanalysis), filesystem watching for auto-rebuild, DebugAllocator and SmpAllocator additions, labeled switch statements [ZIG-014-NOTES].
- **August 20, 2025:** Version 0.15.1 released (0.15.0 was released then retracted) [ZIGGIT-0151]. 5 months of work; 162 contributors; 647 commits. Key feature: x86_64 self-hosted backend now default for Debug mode on Linux and macOS (5× faster debug builds). aarch64 backend work begins.
- **October 12, 2025:** Version 0.15.2 released (patch) [ZIGGIT-0152].
- **November 26, 2025:** Canonical Zig repository migrated from GitHub to Codeberg (codeberg.org/ziglang/zig). Reasons stated: GitHub Actions reliability issues, Microsoft's AI-integration direction, Zig project's strict no-LLM policy, and general decline of engineering quality on the platform [ZIG-CODEBERG-ANN].

### Features Proposed and Rejected or Deferred

- **Async/await (first design):** Present in 0.6.0–0.10.x; removed in 0.11.0 pending redesign. New async I/O design targets 0.16.0 [ZIG-ASYNC-BACK].
- **Green threads:** Never adopted; Zig uses OS threads (std.Thread).
- **Garbage collector:** Explicitly excluded by design philosophy; allocator-explicit approach is intentional.
- **Macros/preprocessor:** Excluded; comptime serves all use cases addressed by macros in C.

### Key Inflection Points

1. **December 2022:** Self-hosting achievement. The compiler can compile itself, marking Zig's transition from "interesting experiment" to "serious language infrastructure."
2. **2023:** Async removal. Kelley's willingness to remove a shipped feature signals the project's pre-1.0 philosophy: correctness and design quality over backward compatibility.
3. **March 2025:** Incremental compilation. Reanalysis time drops from 14 seconds to 63 ms on a 500K-line codebase, addressing a major developer experience complaint.
4. **November 2025:** GitHub migration. The decision to leave GitHub—despite losing access to GitHub Sponsors revenue—demonstrates the project's independence and values.

---

## Adoption and Usage

### Production Users

Pre-1.0 status means Zig carries no formal stability guarantee. Nevertheless, several organizations ship production Zig:

- **Bun** — JavaScript runtime, bundler, test runner, and package manager. Written in Zig with JavaScriptCore as the JS engine. As of December 2025, Bun was acquired by Anthropic [BUN-ANTHROPIC]. Bun's creator (Jarred Sumner) chose Zig for performance and explicit memory control [BUN-WHY-ZIG].
- **TigerBeetle** — financial accounting database written in Zig. Shipped production in 2024 after 3.5 years of development. Raised a $24 million Series A in July 2024 (Spark Capital lead). TigerBeetle has made major financial contributions to ZSF [TB-SERIES-A].
- **Ghostty** — terminal emulator by Mitchell Hashimoto (HashiCorp co-founder). Written in Zig.
- **Mach engine** — experimental game engine and graphics toolkit, written in Zig.

### Market Share and Survey Presence

- Zig is absent from most web-infrastructure deployment statistics (no server-side web framework adoption comparable to Rails or Laravel).
- **Stack Overflow Developer Survey 2023:** First year Zig appeared in survey results. Ranked #1 highest-paid technology globally, with a median salary of $103,000 USD among 259 respondents [SO-2023-SALARY].
- **Stack Overflow Developer Survey 2024:** Zig retained highest-paid status. In the UK subset, 95% of developers expressed desire to work with Zig in the next year, despite only 18% having used it in the past year [SO-2024-UK].
- **Stack Overflow Developer Survey 2025:** Zig ranked 4th most admired programming language (64% admiration rate), after Rust (72%), Gleam (70%), and Elixir (66%). Usage remains approximately 1% of survey respondents. Average reported salary: $75,332 USD [SO-2025].
- **TIOBE Index:** Not consistently ranked as of early 2026; insufficient deployed-codebase presence for TIOBE's web-search methodology.
- **IEEE Spectrum:** Not in top rankings due to limited production deployment.

### Community Indicators

- **Codeberg repository (post-migration):** Primary canonical location as of November 2025.
- **GitHub repository (pre-migration):** 42,600 stars; 3,100 forks at time of migration [REGISTER-GITHUB].
- **Ziggit forum:** Primary community discussion platform.
- **Zigistry:** Unofficial package registry at zigistry.dev.

### Primary Domains

Zig is primarily used in:
1. Systems programming (OS components, drivers, embedded systems)
2. High-performance infrastructure (databases, runtimes, servers)
3. C interoperability projects (using Zig as a better C compiler/toolchain)
4. Bootstrapping other language runtimes (Bun uses Zig for the JS runtime shell)

---

## Technical Characteristics

### Type System

Zig's type system is static and nominative. Key properties:

**Primitive types:** Fixed-width integers (i8 through i128, u8 through u128), arbitrary-width integers (iN/uN for any N), floats (f16, f32, f64, f80, f128), bool, void, noreturn, anyopaque (equivalent of C's void*), type (the type of types, used at comptime).

**Composite types:** Structs, enums, unions, packed structs (exact bit layout), extern structs (C ABI compatible), tuples.

**Sum types:** Tagged unions. Error unions (`!T` or `ErrorSet!T`). Optional types (`?T`).

**Generics:** Implemented via comptime parameters. Functions that take a `type` parameter as a `comptime` argument produce generic behavior. No separate template system.

> "Types are first-class data types… operating on them is surprisingly ergonomic." [ZIG-OVERVIEW]

**Type inference:** Variables use `const x = value` or `var x: T = value`. The `_` discard syntax prevents "unused variable" errors.

**No implicit coercions:** Integer types do not implicitly promote. Explicit casts are required (`@intCast`, `@floatCast`, etc.), and these are safety-checked in safe build modes.

**Reflection:** `@typeInfo(T)` returns a tagged union describing the type. `@Type(info)` creates a type from a typeinfo structure. Both are comptime-only operations [ZIG-DOCS].

### Comptime System

Comptime is Zig's primary metaprogramming mechanism. The `comptime` keyword marks values or blocks that must be evaluated at compile time. Properties of comptime evaluation [KRISTOFF-COMPTIME]:

- Comptime evaluation is **hermetic**: it cannot perform I/O or access global state (excluding comptime-known constants).
- Comptime evaluation is **reproducible**: same inputs yield same outputs, enabling caching.
- Comptime values can be types; this enables compile-time duck typing.
- Comptime can call any Zig function that does not require runtime I/O.
- Comptime does NOT support: closures that capture runtime state, returning runtime values, or spawning threads.

A post analyzing comptime limitations notes: "Comptime will not do: closures, lazy evaluation, const generics (where bounds are verified per-instantiation rather than per-type), or true reflection of runtime values." [MATKLAD-COMPTIME-2025]

### Memory Model

Zig's memory model is explicitly manual. The language enforces this through its allocator design:

**No global allocator:** No equivalent of C's `malloc`. Functions that allocate memory take an `allocator: std.mem.Allocator` parameter explicitly. This makes allocations visible at call sites and enables testing with custom allocators (e.g., arena allocators, leak-detecting allocators) [ZIG-OVERVIEW].

**No hidden allocations:** The language specification guarantees that standard library functions that allocate will accept an explicit allocator. String concatenation, array growth, and similar operations are not implicit.

**Build mode safety:**

| Mode | Optimizations | Safety Checks |
|------|--------------|---------------|
| Debug | None | Full (bounds checks, overflow, null dereference, unreachable) |
| ReleaseSafe | Yes | Full |
| ReleaseFast | Aggressive | None |
| ReleaseSmall | Size-optimized | None |

In Debug and ReleaseSafe modes, Zig fills undefined memory with `0xaa` bytes to help detect use of uninitialized memory [ZIG-DOCS]. Integer overflow in safe modes causes a panic rather than undefined behavior.

**Safety classification:** Zig is **not memory-safe** in the sense used by the memory-safety community (i.e., it does not prevent temporal safety violations such as use-after-free). It provides **spatial safety** (bounds checks on slice accesses) in safe build modes but not **temporal safety** [SCATTERED-SAFE]. An independent analysis concluded: "In several zig codebases, multiple memory safety bugs occur per week, making it difficult to ship secure zig programs without substantial additional mitigations." [SCATTERED-SAFE]

**Sentinel-terminated slices:** Zig supports slice types with a compile-time-known sentinel value (e.g., `[:0]u8` for null-terminated strings), enabling safe C interop without losing bounds information.

### Concurrency Model

**Current state (0.15.x):** Concurrency is via OS threads (`std.Thread`). No green threads, no event loop, no async/await in the released language. Thread primitives include `Mutex`, `Semaphore`, `ResetEvent`, and `WaitGroup` from the standard library.

**Async/await history:** Async functions were introduced in early versions of Zig and were stackless coroutines with an explicit execution model. They were **removed in 0.11.0** (2023) when the self-hosted compiler could not yet support them and the design was determined to require rethinking [ZIG-NEWS-2023].

**New async I/O design (targeting 0.16.0):** Announced in mid-2025. Key design decisions [ZIG-NEW-ASYNC]:

1. **`async` separated from `concurrent`:** `async` means "call a function and get back a handle to resume it later" — it does not imply true parallel execution. `concurrent` explicitly requests that multiple operations run concurrently.
2. **Not colored functions:** The new design does not require marking all calling code as async. This addresses the "function coloring" problem described in Bob Nystrom's analysis that affects Rust, JavaScript, and Python.
3. **Error on single-threaded systems:** If `concurrent` is called on a system without concurrency, the error `error.ConcurrencyUnavailable` is returned rather than deadlocking.
4. **Implementation status:** Available on the master branch as of late 2025; not in a stable release.

### Error Handling

Zig replaces exceptions with **error unions** [ZIG-DOCS]:

**Error sets:** A compile-time enumeration of possible error values. Defined with `const MyError = error { Foo, Bar };`. Error values form a global namespace; the compiler ensures no two distinct error values share the same integer.

**Error unions:** A value of type `ErrorSet!T` is either a value of type `T` or an error from `ErrorSet`. The shorthand `!T` uses an inferred error set.

**Propagation:** The `try` keyword is syntactic sugar for `return catch |err| return err`. It propagates the error to the caller.

**Local handling:** The `catch` keyword handles an error locally: `result = foo() catch |err| handleErr(err)`.

**Deferred error actions:** `errdefer` executes a block when the enclosing function returns with an error.

**Inferred error sets:** A function declared as `fn foo() !T` has its error set inferred by the compiler from all code paths.

Key properties: no stack unwinding (C++ exception overhead absent); all errors must be explicitly handled or discarded (using `_ = try foo()` to discard); error values are part of the function's type signature; no checked/unchecked exception split.

### Compilation and Build Pipeline

**Backends:**
- **LLVM backend:** Used for release builds (ReleaseSafe, ReleaseFast, ReleaseSmall). Produces highly optimized code. Cross-compilation supported for ~40 targets.
- **Self-hosted x86_64 backend:** As of 0.15.x, the default for Debug builds on Linux and macOS. Bypasses LLVM entirely for faster compilation. As of 0.14.0, passes more behavior tests than the LLVM backend (1987 vs. 1980) [ZIG-DEV-2025].
- **Self-hosted aarch64 backend:** In development as the next priority after x86_64.

**Incremental compilation:** Introduced in 0.14.0. On a 500K-line project, reanalysis time improved from 14 seconds to 63 milliseconds [ZIG-014-NOTES].

**Cross-compilation:** Zig bundles libc implementations (musl, glibc stubs) for major targets. Cross-compilation from any host to any supported target requires only the Zig toolchain — no separate sysroot or toolchain installation. `zig build-exe -target aarch64-linux` works out of the box [ZIG-CC-DEV].

**Zig as C compiler:** `zig cc` and `zig c++` are drop-in replacements for `clang`/`g++` with cross-compilation support. This enables projects to adopt Zig tooling without changing their source language.

**Standard library scope:** The standard library includes data structures (ArrayList, HashMap, BoundedArray), I/O abstractions, networking (std.net), HTTP client and server, JSON parsing, cryptography primitives, testing framework, and thread pool. Notable omissions: no official GUI framework; no official web framework.

---

## Ecosystem Snapshot

### Package Manager

Zig's package manager is built into the compiler (introduced as a first-class feature in 0.12.0). Configuration is in `build.zig.zon` (Zig Object Notation). Packages are identified by URL and SHA-256 hash; the compiler fetches and caches them. There is no central package registry [ZIG-PKG-WTF].

This approach has a supply-chain implication: packages cannot yet be referenced in SBOMs or advisory databases because Zig lacks a PURL type [NESBITT-2026]. A peer-to-peer torrenting mechanism for dependency trees is planned for future releases [ZIG-PKG-HN].

**Unofficial registries:** Zigistry (zigistry.dev) provides a browsable index of community packages. No official statistics on total package count were available as of early 2026.

### Build System

`build.zig` is a Zig source file that drives the build process. The build system API is Zig code; there is no separate DSL. Features as of 0.14.0: file system watching for automatic rebuilds, artifact caching, cross-compilation targets, custom build steps.

### IDE and Editor Support

- **ZLS (Zig Language Server):** Primary editor integration tool. Provides semantic completion, go-to-definition, rename, diagnostics. Available for VSCode, Neovim, Emacs, and other editors supporting LSP.
- **Official VSCode extension:** ziglang.vscode-zig.
- **IntelliJ/CLion:** Third-party Zig plugin available.
- AI code assistant training data coverage is limited due to Zig's relative novelty.

### Testing Framework

Built into the compiler. Test blocks are defined with `test "name" { ... }` syntax. `zig test` runs all test blocks. Tests can be comptime or runtime. The standard library provides `std.testing` with assertion helpers. No third-party testing framework is in wide use; the built-in framework is the convention.

### Notable Frameworks and Projects

- **Mach:** Game engine and graphics toolkit.
- **Capy:** Cross-platform GUI library.
- **Zap:** HTTP server library.
- **Zig HTTP client/server:** In standard library.
- **ziglings:** Tutorial exercises for learning Zig (hosted on Codeberg).

### CI/CD

Zig's migration away from GitHub Actions (November 2025) is notable. The project now uses self-hosted CI. Most Zig projects in the community continue to use GitHub Actions or similar CI systems.

---

## Security Data

### Memory Safety Classification

Zig is classified as **not memory-safe** by the Cybersecurity and Infrastructure Security Agency (CISA) definition, which groups it with C and C++ as languages that do not guarantee memory safety by default [SCATTERED-SAFE].

Specific properties:
- **Spatial safety (in safe modes):** Bounds checks on array/slice access; null dereference checked for optionals; integer overflow panics in Debug/ReleaseSafe.
- **No temporal safety:** Use-after-free bugs are not prevented by the language in any build mode. A freed pointer remains accessible until overwritten.
- **No guaranteed initialization:** Memory is not zero-initialized by default (it is poisoned with `0xaa` in Debug for detection purposes, but this is not a safety guarantee).

An independent safety analysis concluded: "Zig is not a memory-safe language, because it does not guarantee memory safety even in its most conservative configuration." [SCATTERED-SAFE]

### CVE Data

No CVE entries specific to the Zig language runtime or compiler appear in the NVD as of early 2026, reflecting Zig's very limited production deployment footprint rather than absence of vulnerability classes.

Academic research (2022, SPIE proceedings) demonstrated exploitation of heap memory vulnerabilities in Zig programs, achieving "writing eight-byte data at any writable address" — a standard write-what-where primitive [SPIE-ZIG-2022]. This research confirms that heap corruption techniques applicable to C programs apply to Zig programs as well.

### Language-Level Mitigations

The following are language-level mitigations present in Zig (effective in Debug and ReleaseSafe):

- **Bounds checking:** Slice and array access is bounds-checked; out-of-bounds panics.
- **Mandatory null handling:** Optional types (`?T`) require explicit null handling before use.
- **No undefined integer overflow:** Integer overflow panics in safe modes; wrapping arithmetic requires explicit operators (`+%`, `-%`, `*%`).
- **No implicit type punning:** `@bitCast` enforces type size compatibility at compile time.
- **`0xaa` poison:** Undefined memory bytes in Debug builds help detect use-before-initialization in debuggers.
- **`DebugAllocator` (0.14.0):** Leak detection allocator for use in testing and debug builds.

### Common Vulnerability Patterns

By analogy with C/C++ (the languages Zig most closely resembles in memory model), the expected vulnerability patterns in Zig programs are:
- Use-after-free (not prevented by language)
- Double-free (not prevented)
- Out-of-bounds write (prevented in safe modes, possible in ReleaseFast/ReleaseSmall)
- Integer overflow logic errors (prevented in safe modes)
- Type confusion via unsafe casting

### Supply Chain

Zig's URL + hash package model provides content-addressed dependencies (similar to Go modules). The absence of a PURL type and SBOM tooling support is a current ecosystem gap [NESBITT-2026]. No centralized registry means no centralized security advisory database for Zig packages.

Zig's own strict no-LLM/no-AI policy is a governance choice that affects tooling decisions but not language-level security.

---

## Developer Experience Data

### Survey Data

**Stack Overflow Developer Survey 2023** [SO-2023-SALARY]:
- First year Zig appeared in the survey.
- Ranked #1 highest-paid technology globally.
- Median salary among Zig respondents: $103,000 USD.
- Notable context: 259 respondents total; Andrew Kelley himself noted he earns $108,000/year (above the median).
- Small sample size limits statistical significance.

**Stack Overflow Developer Survey 2024** [SO-2024-UK]:
- Zig retained highest-paid status.
- UK developer subset: 95% expressed desire to use Zig next year; only 18% had used it in the past year.
- This discrepancy (interest >> usage) is characteristic of pre-mainstream languages.

**Stack Overflow Developer Survey 2025** [SO-2025]:
- Zig ranked **4th most admired language** (64% of developers who used it would use it again).
  - #1 Rust: 72%; #2 Gleam: 70%; #3 Elixir: 66%; #4 Zig: 64%.
- Usage rate: ~1% of all respondents.
- Average reported salary for Zig developers: $75,332 USD.
- Survey base: 49,000+ respondents across 177 countries.

**Note on salary interpretation:** The SO survey salary data for Zig is based on a very small sample of self-selected respondents, likely skewed toward senior engineers at companies (like TigerBeetle and Bun) where Zig use correlates with high-paying positions. It does not reflect a general labor market.

### Learning Curve Characteristics

Zig is documented as having a steep initial learning curve for developers without C background, and a moderate curve for experienced C/C++ developers. Challenges identified by practitioners:
- Comptime semantics are unfamiliar to developers from languages with generics or macros.
- The allocator-per-function pattern requires new design thinking.
- Build system API (build.zig) is unusual; no CMake/Makefile analog.
- No 1.0 stability means APIs change between releases; upgrading is a recurring cost.
- Error messages from the compiler are generally considered good; the comptime error model can produce long traces.

### Job Market

Zig job listings are rare in mainstream job markets as of early 2026. The language remains primarily a niche skill at specialized companies (systems software, high-performance infrastructure). No systematic job posting count data was found.

---

## Performance Data

### General Profile

Zig compiles to native machine code via LLVM (for release builds) or its self-hosted backends (for debug builds). Its performance profile is comparable to C and Rust: no garbage collection pauses, no runtime overhead beyond what the programmer explicitly invokes.

**Key performance claims from the Zig team:**
- Debug builds: 5× faster compilation compared to LLVM backend, due to the self-hosted x86_64 backend (as of 0.15.x) [ZIG-DEV-2025].
- Incremental recompilation: 500K-line project from 14 seconds to 63 milliseconds reanalysis time (0.14.0) [ZIG-014-NOTES].

### Computer Language Benchmarks Game

The Computer Language Benchmarks Game (benchmarksgame-team.pages.debian.net) includes Zig. Results as of available 2024-2025 data:
- Zig implementations are competitive with C and Rust in compute-bound benchmarks.
- Performance is architecture-dependent; Zig's LLVM backend enables the same LLVM optimization passes used by Clang and Rust's rustc.
- No systematic head-to-head comparison of all benchmarks with dates was available in this research; the benchmarks game website contains current figures.

### Runtime Performance Comparison

From independent benchmark comparisons (programming-language-benchmarks.vercel.app, data generated August 1, 2025):
- Zig and Rust are broadly comparable in runtime performance across typical benchmark tasks (binarytrees, fannkuch-redux, fasta, mandelbrot, json-serde).
- Performance differences are task-dependent and often within 10–20% of each other.
- Neither language shows consistent dominance over the other.

### HTTP Client Benchmarks

An independent benchmark (orhun/zig-http-benchmarks) compared Zig's HTTP client against Rust, Go, Python, C++, and curl. Zig performed competitively with Rust and C++ for HTTP client throughput.

### Compilation Speed

- **LLVM-backed Release builds:** Zig compilation is comparable to Clang (Zig uses Clang's LLVM libraries).
- **Self-hosted Debug builds (0.15.x):** Approximately 5× faster than LLVM backend for the same source. Parallelism in the self-hosted backend allows machine code generation to run concurrently with semantic analysis [ZIG-DEV-2025].
- **Pre-incremental-compilation (pre-0.14.0):** Full rebuilds were cited as a pain point by practitioners on large projects.

### Startup Time and Resource Consumption

Zig programs have minimal startup overhead (no runtime to initialize, no GC). Static linking is supported; programs can be produced without any libc dependency. This makes Zig suitable for embedded systems and environments where binary size and startup latency are constrained.

---

## Governance

### Decision-Making Structure

Zig operates as a **BDFL project**: Andrew Kelley is the lead developer with final authority on language design and project direction. The term "benevolent dictator for life" is used explicitly in coverage of the project [LWN-2024].

No formal RFC process exists comparable to Rust's or Python's. Design decisions are made through GitHub/Codeberg issues, discussion, and Kelley's judgment. Loris Cro manages community communication.

### Organizational Backing

The **Zig Software Foundation** is the legal entity:
- Type: 501(c)(3) non-profit corporation (EIN 84-5105214)
- Incorporated: July 2020
- Board of Directors: Andrew Kelley (President), Josh Wolfe (Secretary), Mason Remaley (Treasurer) [ZSF-ABOUT]
- No corporate ownership; no single corporate backer

### Funding Model

ZSF is funded entirely by donations. From the 2024 financial report [ZSF-2024-FINANCIALS]:
- Total income (2024): **$670,672.59**
- Expenditure: 92% on direct contributor payments
- ZSF does not borrow or invest; donations convert directly to development time
- Recurring corporate donors providing $1,000+/month: TigerBeetle, Blacksmith, ZML, Silares
- Individual large donors: Mitchell Hashimoto ($300,000 pledge, October 2024); TigerBeetle + Synadia ($512,000 pledge, October 2024)
- Donation channels: Every.org, Benevity (employer matching), bank transfer, physical check, Wise

**Funding challenge (2025):** The 2025 financial report noted that with current recurring income, ZSF cannot renew all contributor contracts or offer new contracts. The foundation is actively fundraising [ZSF-2025-FINANCIALS].

**GitHub Sponsors concern:** When migrating from GitHub to Codeberg (November 2025), ZSF noted that GitHub Sponsors represents a substantial portion of recurring revenue, and the migration could disrupt this funding stream [DEVCLASS-CODEBERG].

### Backward Compatibility Policy

**Pre-1.0, no backward compatibility guarantee.** Each minor version (0.N.0) routinely introduces breaking changes to the language, standard library, and build system. Upgrading a Zig project between minor versions typically requires code changes. This is acknowledged as a cost of pre-1.0 development.

The 2024 roadmap explicitly lists reaching a specification as a prerequisite to the "stability turning point" [LWN-2024]. No 1.0 release date has been announced.

### Repository and Infrastructure

- **Primary repository (post-November 2025):** codeberg.org/ziglang/zig
- **GitHub mirror (read-only):** github.com/ziglang/zig (42,600 stars at time of migration)
- **Migration rationale:** GitHub Actions reliability, Microsoft AI focus, CLOUD Act jurisdiction concerns, Zig project's no-LLM policy [ZIG-CODEBERG-ANN]
- **Self-hosted CI:** Zig project moved to self-hosted CI post-migration
- **Self-hosted website:** In September 2024, ziglang.org was migrated from AWS to self-hosted infrastructure [ZIG-NEWS]

### Standardization Status

No ISO, ECMA, or other formal standard exists. An unofficial language specification document exists (maintained on a best-effort basis; not normative) [ZIG-SPEC-UNOFFICIAL]. The formal specification is one of Kelley's four stated 1.0 prerequisites.

---

## References

[BUN-ANTHROPIC] "Bun acquired by Anthropic." December 2025. (Via multiple news reports, December 2025.)

[BUN-WHY-ZIG] "Why zig." Bun GitHub Discussions #994. oven-sh/bun. https://github.com/oven-sh/bun/discussions/994

[CORECURSIVE-067] "Full-Time Open Source With Andrew Kelley." CoRecursive Podcast, Episode 67. https://corecursive.com/067-zig-with-andrew-kelley/

[DEVCLASS-CODEBERG] "Zig project ditches GitHub for Codeberg but move could be costly." DevClass, November 27, 2025. https://devclass.com/2025/11/27/zig-project-ditches-github-for-codeberg-but-move-could-be-costly/

[INFOWORLD-2024] "Meet Zig: The modern alternative to C." InfoWorld. https://www.infoworld.com/article/2338081/meet-the-zig-programming-language.html

[KELLEY-2016] Kelley, Andrew. "Introduction to the Zig Programming Language." andrewkelley.me, February 8, 2016. https://andrewkelley.me/post/intro-to-zig.html

[KRISTOFF-COMPTIME] Cro, Loris. "What is Zig's Comptime?" kristoff.it. https://kristoff.it/blog/what-is-zig-comptime/

[LWN-2024] "Zig 2024 roadmap." LWN.net. https://lwn.net/Articles/959915/ (summary of Kelley's Zig Roadmap 2024 presentation.)

[MATKLAD-COMPTIME-2025] "Things Zig comptime Won't Do." matklad.github.io, April 19, 2025. https://matklad.github.io/2025/04/19/things-zig-comptime-wont-do.html

[MITCHELLH-DONATION] Hashimoto, Mitchell. "Pledging $300,000 to the Zig Software Foundation." mitchellh.com, October 2024. https://mitchellh.com/writing/zig-donation

[NESBITT-2026] Nesbitt, Andrew. "Zig and the M×N Supply Chain Problem." nesbitt.io, January 29, 2026. https://nesbitt.io/2026/01/29/zig-and-the-mxn-supply-chain-problem.html

[REGISTER-GITHUB] "Zig quits GitHub, gripes about Microsoft's AI obsession." The Register, December 2, 2025. https://www.theregister.com/2025/12/02/zig_quits_github_microsoft_ai_obsession/

[RELEASES] "Releases · ziglang/zig." GitHub (archived). https://github.com/ziglang/zig/releases

[SCATTERED-SAFE] "How (memory) safe is zig?" scattered-thoughts.net. https://www.scattered-thoughts.net/writing/how-safe-is-zig/ (Updated version: https://lobste.rs/s/nw7hsd/how_memory_safe_is_zig_updated)

[SO-2023-SALARY] Stack Overflow Annual Developer Survey 2023. https://survey.stackoverflow.co/2023/ (Zig as #1 highest-paid technology.)

[SO-2024-UK] "UK developers favour Zig & Rust for 2024, survey reveals." Channel Life, citing Stack Overflow 2024 data. https://channellife.co.uk/story/uk-developers-favour-zig-rust-for-2024-survey-reveals

[SO-2025] Stack Overflow Annual Developer Survey 2025. Technology section. https://survey.stackoverflow.co/2025/technology (Zig: 4th most admired, 64% admiration rate.)

[SPIE-ZIG-2022] "Heap memory vulnerability utilization method in Zig language." SPIE Proceedings, 2022. https://ui.adsabs.harvard.edu/abs/2022SPIE12503E..0TC/abstract

[TB-SERIES-A] "Why TigerBeetle is the most interesting database in the world." Amplify Partners blog. https://www.amplifypartners.com/blog-posts/why-tigerbeetle-is-the-most-interesting-database-in-the-world (Series A: July 2024.)

[TIGERBEETLE-DONATION] "Synadia and TigerBeetle Pledge $512,000 to the Zig Software Foundation." TigerBeetle Blog, October 25, 2024 (approx.). https://tigerbeetle.com/blog/2025-10-25-synadia-and-tigerbeetle-pledge-512k-to-the-zig-software-foundation/

[ZIG-013-NOTES] "0.13.0 Release Notes." ziglang.org. https://ziglang.org/download/0.13.0/release-notes.html

[ZIG-014-DAILY] "Zig announces version 0.14.0." daily.dev, March 2025. https://daily.dev/blog/zig-announces-version-0140

[ZIG-014-NOTES] "0.14.0 Release Notes." ziglang.org. https://ziglang.org/download/0.14.0/release-notes.html

[ZIG-ASYNC-BACK] "Async/Await is finally back in Zig." DEV Community / Substack, late 2025. https://dev.to/barddoo/asyncawait-is-finally-back-in-zig-23hi

[ZIG-CC-DEV] Cro, Loris. "Zig Makes Go Cross Compilation Just Work." DEV Community. https://dev.to/kristoff/zig-makes-go-cross-compilation-just-work-29ho

[ZIG-CODEBERG] "ziglang/zig." Codeberg. https://codeberg.org/ziglang/zig

[ZIG-CODEBERG-ANN] "Migrating from GitHub to Codeberg." ziglang.org/news, November 26, 2025. https://ziglang.org/news/migrating-from-github-to-codeberg/

[ZIG-DEV-2025] "Devlog 2025." ziglang.org. https://ziglang.org/devlog/2025/ (Various entries on x86 backend, aarch64 backend, incremental compilation.)

[ZIG-DOCS] "Documentation — The Zig Programming Language." ziglang.org. https://ziglang.org/documentation/master/

[ZIG-NEW-ASYNC] "Zig's New Async I/O." Loris Cro's Blog, 2025. https://kristoff.it/blog/zig-new-async-io/ Also: Kelley, Andrew. "Zig's New Async I/O (Text Version)." andrewkelley.me. https://andrewkelley.me/post/zig-new-async-io-text-version.html

[ZIG-NEWS] "News." ziglang.org. https://ziglang.org/news/

[ZIG-NEWS-2023] "The Upcoming Release Postponed Two More Weeks and Lacks Async Functions." ziglang.org/news, July 2023. https://ziglang.org/news/0.11.0-postponed-again/

[ZIG-OVERVIEW] "Overview." ziglang.org/learn. https://ziglang.org/learn/overview/

[ZIG-PKG-HN] "Zig Package Manager MVP." Hacker News discussion. https://news.ycombinator.com/item?id=34337079

[ZIG-PKG-WTF] "Zig Package Manager — WTF is Zon." zig.news. https://zig.news/edyu/zig-package-manager-wtf-is-zon-558e

[ZIG-SELF-HOSTED] Cro, Loris. "Zig Is Self-Hosted Now, What's Next?" kristoff.it, December 2022. https://kristoff.it/blog/zig-self-hosted-now-what/

[ZIG-SPEC-UNOFFICIAL] "Zig Language Specification (unofficial)." https://nektro.github.io/zigspec/

[ZIGGIT-0151] "Zig 0.15.1 Released." Ziggit community forum. https://ziggit.dev/t/zig-0-15-1-released/11583

[ZIGGIT-0152] "Zig 0.15.2 Released." Ziggit community forum. https://ziggit.dev/t/zig-0-15-2-released/12466

[ZIGLANG-HOME] ziglang.org homepage. https://ziglang.org/

[ZSF-2024-FINANCIALS] "2024 Financial Report and Fundraiser." ziglang.org/news, January 2024. https://ziglang.org/news/2024-financials/

[ZSF-2025-FINANCIALS] "2025 Financial Report and Fundraiser." ziglang.org/news, September 2, 2025. https://ziglang.org/news/2025-financials/

[ZSF-ABOUT] "Zig Software Foundation." ziglang.org/zsf. https://ziglang.org/zsf/
