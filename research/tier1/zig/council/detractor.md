# Zig — Detractor Perspective

```yaml
role: detractor
language: "Zig"
agent: "claude-agent"
date: "2026-02-27"
```

---

## 1. Identity and Intent

Zig positions itself as a "better C" — a general-purpose systems language without hidden control flow, hidden allocations, or a preprocessor. The pitch is elegant and the frustrations with C it addresses are real. The problem is the gap between this stated identity and what Zig currently delivers to someone who actually needs a stable, deployable, C-level systems language in production.

Zig's stated design goals — robust, optimal, reusable — are the correct aspirations. The difficulty is that all three remain conditional on a pre-1.0 language where any of these properties can be broken by the next minor version. "Robust" is harder to achieve in a language that does not prevent temporal memory safety violations in any build mode and whose concurrency story was deleted wholesale in 2023 [ZIG-NEWS-2023]. "Optimal" is easier to believe given LLVM-backed codegen, but "reusable" is undermined by a package ecosystem with no central registry, no PURL type, and no SBOM tooling [NESBITT-2026].

The deeper tension is between two incompatible identities that Zig is trying to hold simultaneously: (a) a language in active, breaking design exploration that can remove features and rethink core abstractions, and (b) a language stable enough to trust with production financial infrastructure. TigerBeetle and Bun have made their bets; the language's own foundation acknowledges that this is "pre-release software" with no backward-compatibility guarantee [ZSF-ABOUT]. Both things cannot be simultaneously true in a useful sense.

Andrew Kelley's motivating insight — that systems programmers need better tools than C without the complexity tax of C++ — is sound. But the execution has repeatedly demonstrated that insight and execution are different skills. A language's identity is ultimately what it does to its users over time, not what it promises in its overview page.

---

## 2. Type System

Zig's type system is static, nominative, and correctly avoids implicit coercions — these are genuine strengths. The problem lies at the edges: where the type system needs to do more, it either cannot, or makes you pay an ergonomic price that C developers would not have paid.

**The comptime type system cannot check declarations, only instantiations.** In Rust's generics, you can express a bound at the declaration site (`fn foo<T: Clone>(x: T)`) and get an error when the bound is violated before you even call the function. Zig's comptime duck typing means errors are only discovered at call time, and only when that specific call path is actually compiled [MATKLAD-COMPTIME-2025]. For library authors, this means: your "generic" code compiles fine in your own tests but fails with inscrutable errors in your user's code. This is not a minor ergonomic issue — it is the difference between a type system that provides guarantees and one that provides suggestions.

The verbosity of comptime reflection is another real cost. `@typeInfo(T)` returns a tagged union, and navigating it for anything non-trivial produces code that developers avoid in favor of duck typing [EDAYERS-ZIG]. Duck typing at comptime is convenient until it isn't: the absence of bounds means the compiler cannot tell you what interface a type was supposed to satisfy, only that it failed to at some specific point. Error messages from generic instantiation failures can be long and difficult to trace.

**Error unions cannot carry payload data.** This is a deliberate design choice — Zig avoids implicit allocations, and allowing error values to carry heap-allocated data would violate this — but it has real consequences. When a function fails, the caller gets an error enum value and nothing else. The standard library's own JSON parser has been criticized for emitting "bad character" errors with no location information [EATONPHIL-ERRORS]. The community's workarounds — out parameters for diagnostic data, the "sneaky error payloads" pattern using separate diagnostic structs — are functional but unidiomatic; they scatter error-handling logic and increase function signature complexity [ZIG-NEWS-ERROR]. GitHub issue #2647 ("Allow returning a value with an error") has been open since the early days and remains unresolved as of 2026 [ZIG-ISSUE-2647].

This is a structural design constraint, not a bug waiting for a fix. A language designer choosing to replicate this constraint should do so consciously, aware that the "no allocations on the error path" principle costs you the ability to give users useful error context.

**No access control beyond module-level `pub`.** There is no `protected`, no `friend`, no fine-grained visibility. Whether this is minimalism or incompleteness depends on the use case; for large codebase organization, the absence of field-level access control within a package is felt [EDAYERS-ZIG].

---

## 3. Memory Model

Zig's explicit-allocator design is its most genuinely novel contribution to systems programming. The principle — make every allocation visible at the call site — is correct, and it meaningfully improves testability and auditability compared to C's global `malloc`. This is credit genuinely given. The criticism is that explicit allocators do not make Zig memory-safe, and the gap between what Zig claims about safety and what it delivers is obscured by imprecise marketing.

**Zig provides no temporal memory safety in any build mode.** Use-after-free and double-free bugs are not prevented by the language, compiler, or runtime in Debug mode, ReleaseSafe mode, ReleaseFast mode, or ReleaseSmall mode [SCATTERED-SAFE]. The `0xaa` poison pattern helps a developer using a debugger catch these bugs during testing, but it is not a safety guarantee — it is a debugging aid. In ReleaseFast and ReleaseSmall modes, even bounds checks are disabled, leaving spatial safety as well.

This matters because Zig explicitly positions itself as a replacement for C in security-critical contexts. An independent analysis of Zig codebases found "multiple memory safety bugs per week" in production Zig projects, leading the author to conclude that shipping secure Zig programs requires "substantial additional mitigations" [SCATTERED-SAFE]. Academic research from 2022 demonstrated that heap corruption techniques applicable to C programs — specifically, writing eight-byte data to arbitrary writable addresses — apply directly to Zig programs [SPIE-ZIG-2022]. The expected vulnerability classes in Zig production code are the same as C: use-after-free (CWE-416), double-free (CWE-415), out-of-bounds writes in unsafe modes (CWE-119).

The NSA/CISA June 2025 guidance on memory-safe languages does not list Zig as a recommended safe language; it groups Zig with C and C++ in the category of languages that do not provide memory safety guarantees [CISA-MEMSAFE]. For any organization subject to this guidance — or to regulatory pressure around software security — Zig currently provides no path to compliance.

**The explicit allocator pattern has ergonomic costs at scale.** Passing allocators through every function that might allocate is correct in principle, but it creates function signatures that are heavier than C equivalents. For functions that need multiple different allocators for different allocations (arena for short-lived, persistent heap for retained data), this burden compounds [EDAYERS-ZIG]. The community's response is to accept the pattern as idiomatic; the detractor's response is that an ergonomic cost that is accepted rather than solved is still a cost.

The `DebugAllocator` (introduced in 0.14.0) is a welcome addition for leak detection. But detection is not prevention, and testing infrastructure that catches bugs is not equivalent to language features that prevent them.

---

## 4. Concurrency and Parallelism

This is Zig's most consequential design failure to date, and the most important section for any language designer to study carefully.

**Zig shipped async/await, relied on it for production use cases, then removed it.** Async functions were present from version 0.6.0 through 0.10.x. Projects built on async. Documentation was written for it. Then, in July 2023, Zig announced that the 0.11.0 release would ship without async/await because the self-hosted compiler could not yet implement the existing design, and the design itself was being reconsidered [ZIG-NEWS-2023]. The decision is defensible from a long-term design perspective — the existing async design had problems and the team had a better vision. But the cost fell entirely on developers who had built on async. This is not a hypothetical scenario about unstable software; it is a documented, executed removal of a shipped feature.

As of 0.15.x (October 2025), async/await is still absent from the released language. The new design is targeting 0.16.0 [ZIG-ASYNC-BACK]. That means Zig will have shipped a production-targeted systems language without a first-class concurrency story from mid-2023 through at least 2026 — a gap of three or more years. During that time, the only concurrency mechanism available was OS threads with manual synchronization primitives [RESEARCH-BRIEF].

**OS-threads-only is a real limitation for I/O-bound workloads.** Zig's target domains include high-performance servers (Bun, Zap HTTP library) and asynchronous I/O-heavy systems. Without async, developers building these systems must either: use blocking I/O with a thread-per-connection model (not competitive with async runtimes at scale), write their own event loop (duplicated effort, error-prone), or wait for 0.16.0 (not an option for production systems that needed this today). TigerBeetle, one of Zig's flagship users, is a database — it can get away with an IO_uring-based approach using OS threads; Bun, a JavaScript runtime where event-loop performance is critical, built its own abstractions. These workarounds work but represent exactly the kind of ecosystem fragmentation that happens when a language lacks a standard concurrency story.

**The new async design, while promising, introduces its own complexity.** The separation of `async` (call a function and get a handle) from `concurrent` (request parallel execution) is conceptually cleaner than the colored-functions pattern used by Rust and JavaScript. But the devil is in the implementation details, and the implementation will not exist in a stable release until 0.16.0 at the earliest. The Devclass report on "Writergate" — Kelley's "extremely breaking" changes to `std.io.Reader` and `std.io.Writer` in preparation for async's return — illustrates that even a feature redesign in progress requires sweeping changes to the standard library that break user code [DEVCLASS-BREAKING].

**No data race prevention.** Zig provides no compile-time or runtime guarantees about data races between OS threads. There is no ownership model (unlike Rust), no race detector integrated into the default build modes (unlike Go's `-race`). Data races in Zig code are silent undefined behavior. This is consistent with Zig's "trust the programmer" philosophy, but it means that concurrent Zig code is as unsafe as concurrent C code.

---

## 5. Error Handling

Zig's error union system is its best-received design decision, and for good reason: it makes errors explicit in the type system, forces callers to handle them, and the `try`/`catch`/`errdefer` syntax is readable. The criticism is not that the design is wrong, but that it is incomplete in ways that matter.

**Errors cannot carry data.** As discussed in Section 2, error values in Zig are enum variants with no payload. This is a fundamental limitation, not an implementation detail. The practical consequence is that when a function fails, it cannot return context about why. The JSON parser example — returning "bad character" with no line or column number — is not a standard library quality problem; it reflects the language's inability to cheaply attach this information to an error return [EATONPHIL-ERRORS]. In C, you might return an error code and set a thread-local error message. In Rust, you return `Result<T, E>` where `E` can be any type carrying any information. In Zig, you get an enum value.

The workarounds — out parameters for diagnostics, wrapper structs, separate diagnostic output arguments — add boilerplate and impose an API design burden. These patterns work, but they mean every library author who needs to provide error context must invent their own convention. There is no standard. This is visible in the standard library itself, where error reporting quality is inconsistent.

**Inferred error sets are a double-edged sword.** The ability to write `fn foo() !T` and have the compiler infer the complete error set from all code paths is convenient during development but creates unstable API surfaces. If an internal function call adds a new error variant, the inferred error set of the public function changes — which is a breaking change for callers who exhaustively switch on error values. Library authors who care about API stability must use explicit error sets, at the cost of more verbose declarations and the need to manually keep them synchronized with the implementation.

**`errdefer` adds power but also cognitive load.** `errdefer` is genuinely useful for ensuring cleanup only happens on the error path. But it creates a temporal ordering concern: `errdefer` must appear after the allocation it is guarding, meaning initialization order affects correctness. For complex initialization sequences with multiple resources, the interleaving of `defer` and `errdefer` blocks can be difficult to read and verify.

**There is no equivalent of panics with context.** In Rust, a panic can carry a message. In Zig, `@panic` takes a string, but this is in a different category from error handling entirely. The boundary between recoverable errors (handled through error unions) and unrecoverable errors (panics) is philosophically clean but practically awkward when a condition is error-like in some callers and panic-worthy in others.

---

## 6. Ecosystem and Tooling

Zig's ecosystem is in the state expected of a pre-1.0 language with a small team and donation-only funding. This is not surprising. But the gap between Zig's ambitions and its ecosystem depth is wider than its age alone explains, and several structural choices will make closing that gap harder.

**The package manager has no central registry.** Packages are identified by URL and SHA-256 hash; the compiler fetches them directly. This is content-addressed and supply-chain sound in one sense — you know exactly what you're getting — but it creates cascading problems [NESBITT-2026]:

1. No PURL type means Zig packages cannot appear in SBOMs or advisory databases. Organizations required to produce SBOMs for their software (a growing regulatory requirement) cannot include Zig dependencies.
2. Metadata platforms (deps.dev, Libraries.io, ecosyste.ms) cannot index or analyze Zig's dependency graph.
3. GitHub's dependency graph, GitLab's dependency scanning, and similar tools cannot parse Zig manifests.
4. There is no centralized security advisory database for Zig packages. A vulnerability in a popular Zig library has no standard disclosure path.

The Nesbitt analysis estimates that it took Go modules, shipping in 2018, a decade to achieve full tooling integration parity [NESBITT-2026]. Zig's package manager shipped as a first-class feature in 0.12.0 (2024). The integration debt accumulates while the ecosystem grows.

**ZLS cannot perform semantic analysis.** Zig's language server (ZLS) is a community project that provides parser-level diagnostics — syntax errors, unused variables — but cannot resolve complex comptime expressions. It cannot perform type checking [ZLS-GITHUB]. The practical consequence: developers cannot see type errors in their editor as they type; they must run the compiler to discover them. This is a significant step backward from the experience of mature ecosystems where the editor provides real-time type feedback. The reason is architectural: semantic analysis in Zig requires the compiler's comptime evaluator, and ZLS does not embed the compiler. The Zig team's long-term plan is to expose compiler internals to ZLS, but this is not yet implemented.

**AI code assistance is degraded.** Zig is too new and too niche to have substantial representation in AI coding assistant training data [RESEARCH-BRIEF]. Tools like GitHub Copilot, Cursor, and Claude struggle with non-trivial Zig code. For a language competing for developers' time, the absence of AI code assistance is a compounding disadvantage: developers choosing between Zig and Rust will find significantly better AI support for the latter.

**No web framework, no GUI framework.** These are acknowledged gaps. For a language targeting general-purpose systems work, the absence of a web framework with serious production use limits its applicability to a narrow set of use cases. The HTTP client/server in the standard library is functional but not a production web framework.

**The build.zig API is breaking across versions.** The build system is Zig code, which means it is subject to the same pre-1.0 breaking changes as the language. Upgrading a Zig project between minor versions typically requires updating both source code and build.zig. This is an ongoing maintenance cost that has no equivalent in a language with a stable build system like Go's.

---

## 7. Security Profile

Zig's security posture is the consequence of three design choices working against each other: manual memory management, an absence of memory-safety guarantees, and production deployment in security-sensitive contexts.

**Zig is not a memory-safe language by any formal definition.** CISA classifies it alongside C and C++ in the category of languages that do not prevent memory safety violations [CISA-MEMSAFE]. The SCATTERED-SAFE analysis, the most careful independent assessment available, concludes that Zig does not guarantee memory safety even in its most conservative configuration and that production Zig codebases encounter multiple memory safety bugs per week [SCATTERED-SAFE]. Academic research demonstrated heap corruption exploitation in Zig programs using standard write-what-where primitives — the same exploitation techniques that apply to C [SPIE-ZIG-2022].

The safety properties Zig does provide — bounds checks, integer overflow panics, mandatory null handling — are meaningfully better than raw C, but they are partial mitigations, not solutions. They are absent entirely in ReleaseFast and ReleaseSmall modes. The decision to ship safe-mode binaries in production is a developer choice, not a language guarantee, and the performance cost of ReleaseSafe vs. ReleaseFast creates pressure to disable safety checks.

**No CVE history reflects deployment footprint, not absence of vulnerabilities.** The research brief notes that no CVEs specific to the Zig runtime appear in NVD as of early 2026 [RESEARCH-BRIEF]. This is not evidence of security; it is evidence that Zig has not yet accumulated enough production deployment for vulnerabilities to be found, reported, and catalogued. Bun, TigerBeetle, and Ghostty are notable — but they represent a tiny fraction of the deployed systems written in C. As Zig use grows, so will its vulnerability surface.

**Supply chain tooling is absent.** The consequences of having no PURL type and no central registry for security extend beyond convenience: there is no mechanism for a Zig library author to publish a security advisory in a way that consumers will receive automatically. There is no equivalent of RubyGems advisories, npm advisories, or Go vulnerability scanning. An organization depending on Zig libraries for security-critical code is operating without the tooling infrastructure that modern security practice requires [NESBITT-2026].

**The no-LLM policy complicates security tooling.** Zig's project-wide prohibition on AI/LLM assistance is a values decision that has real consequences for security tooling development. Modern static analysis tools and security scanners increasingly incorporate AI-based analysis. The policy limits contributions from tooling developers who work with AI-assisted code analysis, and it creates friction for integration with AI-powered security tooling platforms.

---

## 8. Developer Experience

Zig's developer experience scores high on admiration and low on adoption — a pattern characteristic of a language that is better to think about than to use daily at scale. The 64% admiration rate in the 2025 Stack Overflow survey [SO-2025] comes from approximately 1% of respondents. The gap between enthusiasm and adoption is not trivial to explain away.

**Breaking changes are a constant tax.** Every Zig minor version (0.N.0) introduces breaking changes to the language, standard library, and build system. Upgrading from 0.13.0 to 0.14.0 required code changes in nearly every production project. Upgrading to support async in 0.16.0 will require more. The "Writergate" std.io changes are described as "extremely breaking" by Kelley himself [DEVCLASS-BREAKING]. For a language promising to replace C in long-lived infrastructure code, the expectation that you will rewrite portions of your project every nine months to twelve months is a serious burden. C code written in 1990 often compiles today without modification. Zig code written in 2022 frequently does not compile in 2025.

**No 1.0 means no stability guarantee, indefinitely.** Kelley has stated that the path to 1.0 includes: compiler performance, language improvements, standard library quality, and a formal specification [LWN-2024]. None of these has a completion date. The formal spec is described as "a stability turning point" — implying that even after 1.0, the stability story may take time to deliver. For a developer evaluating Zig as the foundation for a multi-year infrastructure project, "indefinitely pre-1.0" is a real answer to a real concern.

**Comptime errors are hard to read.** While the basic comptime system is learnable, errors from complex comptime code — particularly when generics fail at instantiation — produce traces that are notoriously verbose. Because type errors manifest at call sites rather than declaration sites [MATKLAD-COMPTIME-2025], the user who calls a generic function must understand the generic function's internal type requirements, not just the interface they expected to satisfy. This inverts the expected direction of error communication.

**The allocator pattern has a constant cognitive cost.** Passing `allocator: std.mem.Allocator` to every function that might allocate is correct architecture, but it is a pattern that developers from garbage-collected languages must internalize, and a pattern that creates decision fatigue at every function boundary: which allocator? Arena for this scope? Which scope? A general-purpose heap? The language provides no guidance, and the convention is not immediately obvious [EDAYERS-ZIG].

**Job market is nearly nonexistent.** As of early 2026, Zig job listings are rare in mainstream markets [RESEARCH-BRIEF]. The salary data from Stack Overflow (median $103,000 in 2023, from 259 respondents) reflects a tiny, self-selected sample of senior engineers at a handful of companies, not a labor market [RESEARCH-BRIEF]. Developers choosing Zig for career reasons are making a speculative bet on adoption growth; developers choosing it for employer reasons are joining a small club of companies with specific use cases.

**The GitHub migration had real costs.** Migrating from GitHub to Codeberg (November 2025) was driven by principled disagreements with Microsoft's direction [ZIG-CODEBERG-ANN]. The Register noted the potential disruption to GitHub Sponsors revenue [DEVCLASS-CODEBERG]. GitHub Sponsors is described as "a substantial portion of recurring revenue." The migration was a values-driven decision that imposed a funding risk on the project and reduced visibility for new contributors who expect projects to live on GitHub.

---

## 9. Performance Characteristics

Zig's runtime performance is genuinely competitive. LLVM-backed release builds perform comparably to Clang-compiled C and Rust; benchmark comparisons show Zig and Rust within 10–20% of each other across typical compute-bound tasks [RESEARCH-BRIEF]. This is the section where the detractor has least to say.

The criticisms are real but second-order:

**Release build performance versus debug experience is a wide gap.** Zig's self-hosted x86_64 backend (default for Debug builds in 0.15.x) produces fast compilation but generates code that is significantly less optimized than LLVM release builds. This is expected and by design. But it means that performance-sensitive bugs that only manifest in release code — particularly those related to integer overflow behavior, which changes between safe and unsafe modes — are difficult to reproduce in the development cycle.

**Pre-incremental-compilation builds were painful.** Before 0.14.0 introduced incremental compilation (500K-line project: 14s → 63ms reanalysis [ZIG-014-NOTES]), full rebuilds on large Zig projects were cited as a serious pain point. One developer documented spending 181 minutes waiting for the Zig compiler in a single week [ZACKOVERFLOW]. This was a real productivity cost that affected developers for years before being addressed.

**No mature profiling or optimization toolchain.** Zig relies on external tools (perf, Valgrind, or LLVM-based profilers) for performance analysis. There is no Zig-native profiler, no integrated flame graph tooling, and no memory profiler analogous to Valgrind's massif with Zig-specific integration. Optimizing Zig programs at the performance ceiling requires the same mix of external tooling required for C, with none of the ecosystem maturity around those tools that C has accumulated.

**Startup and binary size are genuine strengths.** No GC, minimal runtime, static linking, free-standing support — these are legitimately good properties for the embedded and CLI use cases Zig targets. The detractor acknowledges these cleanly.

---

## 10. Interoperability

Zig's C interoperability story (`@cImport`, `zig cc`, cross-compilation) is one of its strongest selling points and one of the best-executed features in the language. Reading a C header and using its functions with full type information is genuinely easier in Zig than in most alternatives. Cross-compilation with bundled musl and glibc stubs removes an entire class of toolchain headaches.

The criticisms are narrow but real:

**`@cImport` is not without failure modes.** Complex C headers with macros, conditional compilation, and non-standard extensions can fail to import correctly. The `translate-c` translation layer that powers `@cImport` is effective on well-behaved C headers but requires workarounds for the subset of C idioms it cannot handle. For heavily macro-laden C codebases — common in embedded systems and platform SDKs — this requires manual bridging code.

**No Rust FFI story.** Zig can talk to C. It can talk to C++ through `extern "C"` linkage. There is no first-class interoperability with Rust, which is increasingly the language Zig competes with for the same developer audience and use cases. Projects that want to incrementally adopt Rust into a Zig codebase, or vice versa, must go through C ABI as an intermediary.

**No stable ABI for Zig-to-Zig interoperability.** Zig has no stable ABI in any released version. Two Zig libraries compiled with different compiler versions cannot reliably link. This makes binary distribution of Zig libraries impractical; everything must be compiled from source [RESEARCH-BRIEF]. While this is consistent with the pre-1.0 status, it means that the package ecosystem must be source-only, which limits deployment options and increases build time for projects with many dependencies.

---

## 11. Governance and Evolution

Zig's governance structure is its most underexamined risk. The project is a BDFL-model organization led by Andrew Kelley, funded by donations, without an RFC process, without a formal specification, and without a 1.0 commitment. Each of these individually is manageable; the combination creates a fragility that users of infrastructure-level languages should take seriously.

**The BDFL model is a single point of failure.** Kelley is the lead developer, the Foundation president, the primary decision-maker, and the author of the most critical design decisions [LWN-2024]. The async removal, the Codeberg migration, and the "Writergate" std.io redesign were all unilateral decisions made by one person. Loris Cro's blog post "Interfacing with Zig, a BDFL-run Project" acknowledges this explicitly: the project's conceptual integrity is maintained by a single individual [KRISTOFF-BDFL]. The bus factor for Zig's design direction is one.

This is a different risk from most BDFL projects because Zig does not have the institutional depth to absorb a leadership disruption. Python's BDFL abdication in 2018 resulted in a Steering Council because Python had decades of institutional contributors and a large community with governance experience. Zig is still a project where the core team is small, paid through ZSF contracts, and dependent on Kelley's judgment for architectural decisions.

**The funding situation is precarious.** The 2025 financial report states explicitly: "with the current level of recurring income, the ZSF will not be able to renew everyone's contracts, nor offer new contracts to Zig core team members" [ZSF-2025-FINANCIALS]. The foundation spent 92% of its income on contributor payments and noted a "widening gap between total issues opened and closed" — more users than the team can serve [ZSF-2025-FINANCIALS]. The largest single donors are Mitchell Hashimoto (a pledge, not a committed recurring revenue stream) and TigerBeetle/Synadia. Any of these relationships could change.

The Codeberg migration compounded the funding risk. GitHub Sponsors "represents a substantial portion of recurring revenue" for ZSF; migrating away from GitHub threatens this income stream [DEVCLASS-CODEBERG]. The migration was made for principled reasons — objection to Microsoft's AI policies, GitHub Actions reliability, CLOUD Act concerns — but the financial consequence is real and was acknowledged.

**No RFC process means no community input into major decisions.** When Kelley decided to remove async in 0.11.0, there was no formal RFC process where community members could propose alternatives, discuss impact, or vote. When the std.io redesign was declared "extremely breaking," the community was informed, not consulted. For a language inviting production adoption, the absence of structured governance around breaking changes is a meaningful risk.

**No formal specification and no timeline to 1.0.** The language has no normative specification. The unofficial specification at nektro.github.io/zigspec is not maintained by the core team and is not authoritative [ZIG-SPEC-UNOFFICIAL]. Kelley has identified the formal spec as a 1.0 prerequisite, but there is no timeline. For organizations whose procurement processes, compliance frameworks, or legal teams require stable, specified languages, Zig is currently disqualified.

**The no-LLM policy is a governance choice with ecosystem consequences.** Zig's strict prohibition on AI/LLM tooling in the project is a values decision, but it limits the range of contributors who can participate, slows tooling development, and creates friction with the direction most developer tooling ecosystems are moving. The policy is consistently applied — but its costs compound as AI-assisted development becomes the norm.

---

## 12. Synthesis and Assessment

### Greatest Strengths

Zig has three things genuinely right that any language designer should study:

1. **Explicit allocators.** Making every heap allocation visible at the call site is a better design than C's global `malloc` and it is not in conflict with performance. This should be the default for systems languages.

2. **Error unions as first-class types.** The `try`/`catch`/`errdefer` system eliminates exception-as-control-flow bugs, makes error paths visible in function signatures, and avoids the checked/unchecked exception split that plagued Java. The design is incomplete (no payload), but the fundamental approach is correct.

3. **Comptime as the single metaprogramming system.** Using one evaluable language for both runtime and compile-time computation, without a separate macro language, is architecturally cleaner than C's preprocessor or C++'s template language. The hermetic execution model (no I/O at comptime) is correct.

### Greatest Weaknesses

**1. Not memory-safe, claimed as safe.** Zig is grouped with C and C++ by CISA, not with Rust and Swift [CISA-MEMSAFE]. It occupies an uncomfortable middle ground: better than C for safety-conscious developers who use safe modes consistently, but not memory-safe in any guarantee sense. The language's marketing does not always make this clear. A language designer building for security-critical contexts should note: partial safety guarantees that disappear in performance-optimized builds are not safety guarantees; they are debugging aids.

**2. Breaking changes as the default.** Every minor version breaks code. Async was shipped, then removed. The std.io layer was "extremely broken" in preparation for a feature still not in a stable release [DEVCLASS-BREAKING]. A language's evolution policy is part of its design; a pre-1.0 "everything may change" policy is incompatible with the "production infrastructure replacement for C" positioning.

**3. No concurrency story for years.** Removing async from 0.11.0 and not replacing it through 0.15.x means Zig had no first-class concurrency story for the entire 2023–2026 period. For a language targeting high-performance servers and databases, this is not a feature gap — it is a foundational gap that pushed flagship users to build their own concurrency abstractions.

**4. Errors cannot carry context.** The decision to prohibit payload data on error returns — made for allocation-avoidance reasons — systematically degrades the quality of error messages and forces ad hoc workarounds onto every library author who needs to provide diagnostic information.

**5. Governance fragility.** A BDFL model with a donation-funded foundation, no RFC process, no formal spec, and no 1.0 timeline, with a core team that cannot be fully funded on current recurring income, is an organizational risk that is independent of the language's technical quality.

### Lessons for Language Design

These lessons are stated generically. They trace to specific Zig findings but apply to any language in this design space.

**L1: Partial memory safety is not a safety guarantee; do not market it as one.** If a language prevents spatial violations but not temporal violations, say that precisely. A developer relying on "safe modes" to prevent all memory corruption will encounter use-after-free bugs. The gap between "safer than C" and "memory-safe" must be stated explicitly. Removing safety checks in performance builds compounds the problem. If safety guarantees are build-mode-dependent, they are developer conventions, not language features.

**L2: Error values should carry structured data.** The ability to propagate errors up the call stack is necessary but not sufficient; callers need context to act on errors. Prohibiting error payloads to avoid allocation forces every library to invent its own out-parameter convention for diagnostics. A language that prevents implicit allocations can still allow error types to carry data — the solution is to require callers to provide allocators for error paths that need them, or to support stack-allocated error context. The "no allocations on the error path" principle, applied absolutely, trades allocation predictability for diagnostic quality.

**L3: Never ship a concurrency model you cannot maintain.** If the compiler cannot implement the concurrency design, the concurrency design was not ready to ship. Shipping it and later removing it is worse than not shipping it: it creates a false sense of capability, produces dependent code, and requires a breaking removal that destroys user trust. The correct sequence is: design, implement fully, stabilize, ship.

**L4: Breaking changes must have a stability horizon.** A language in active development will change. The question is whether changes are predictable and bounded. Languages that commit to stability windows (e.g., "no breaking changes between minor versions within the same major version," or "breaking changes announced N releases in advance with a migration path") impose a constraint on developers that builds rather than erodes trust. Zig's current model — every minor version may break anything — is the worst possible for production adoption.

**L5: Comptime without declaration-site type checking shifts error discovery to users.** Library authors cannot tell comptime-generic interfaces from runtime-generic interfaces when type errors only manifest at call sites. The practical consequence is that generic library code either cannot be fully tested (because the error only appears in user code) or must be tested with exhaustive instantiation. A language can achieve comptime duck typing for flexibility while still providing opt-in declaration-site bounds for correctness guarantees. Doing neither forces library authors to document intended interfaces in comments rather than types.

**L6: Package manager design decisions create integration debt that accumulates for years.** The decision to use URL + hash as a package identifier rather than a registry-based identifier means that the entire surrounding infrastructure (SBOM tooling, vulnerability advisory databases, dependency graph scanning) cannot be integrated without first resolving the identifier scheme. This is a recoverable mistake — Zig could add a registry — but Nesbitt's analysis suggests the integration work takes years even after the technical decision is made [NESBITT-2026]. Package manager designers should resolve the identifier scheme before the ecosystem grows past the point where changing it requires breaking all existing packages.

**L7: BDFL governance requires institutional depth proportional to scope.** A single individual making all architectural decisions is coherent for a small project. As the scope grows — production databases, JavaScript runtimes, terminal emulators, embedded systems — the decision surface grows with it. Without RFC processes, structured community input, or co-leadership, the BDFL becomes a bottleneck and a single point of failure. The correct time to invest in governance structure is before the project outgrows it, not after.

**L8: Language server quality is a first-class feature, not an afterthought.** ZLS cannot perform type checking because it does not embed the Zig compiler's semantic analysis [ZLS-GITHUB]. The gap between what developers see in their editor and what the compiler reports is a daily productivity tax. A language whose type system requires a full semantic analysis pass to produce type errors should build the language server on top of the compiler's analysis infrastructure from the beginning, not as a separate community project that can only access the parser.

### Dissenting Views

**On memory safety:** Some argue that Zig's "safe by default with opt-out for performance" is a reasonable pragmatic position and that demanding Rust-style ownership for a C replacement is an unrealistic standard. This is a legitimate position for embedded systems where explicit memory management is required and Rust's borrow checker is impractical. The detractor's response: position the language accurately. "Safer than C, not memory-safe" is a correct claim. "Robust" as a top-level design goal, without that qualification, is not.

**On pre-1.0 breaking changes:** Some argue that breaking changes now prevent worse breakage later, and that a language that locked in async's first design would be worse off than one that removed and redesigned it. This is true. The lesson is not "never break things" but "publish a stability policy so users can make informed decisions." TigerBeetle adopted Zig knowing it was pre-1.0; many would-be users have not adopted Zig for the same reason. Transparency about instability enables informed consent; omitting that framing from the marketing does not.

**On BDFL:** Loris Cro argues that conceptual integrity — having one person with a coherent vision — is more valuable than committee-designed consistency [KRISTOFF-BDFL]. This is plausible for a language still discovering its identity. The detractor's response is that it becomes a risk profile issue, not a design philosophy issue, as organizational maturity demands more than one person's availability and judgment.

---

## References

[CISA-MEMSAFE] CISA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://www.cisa.gov/resources-tools/resources/memory-safe-languages-reducing-vulnerabilities-modern-software-development

[DEVCLASS-BREAKING] "Zig lead makes 'extremely breaking' change to std.io ahead of Async and Await's return." DevClass, July 7, 2025. https://devclass.com/2025/07/07/zig-lead-makes-extremely-breaking-change-to-std-io-ahead-of-async-and-awaits-return/

[DEVCLASS-CODEBERG] "Zig project ditches GitHub for Codeberg but move could be costly." DevClass, November 27, 2025. https://devclass.com/2025/11/27/zig-project-ditches-github-for-codeberg-but-move-could-be-costly/

[EATONPHIL-ERRORS] Phil Eaton. "Errors and Zig." notes.eatonphil.com. https://notes.eatonphil.com/errors-and-zig.html

[EDAYERS-ZIG] Ed Ayers. "Notes on the Zig programming language." edayers.com. https://www.edayers.com/blog/review-zig

[KRISTOFF-BDFL] Loris Cro. "Interfacing with Zig, a BDFL-run Project." kristoff.it. https://kristoff.it/blog/interfacing-with-zig/

[LWN-2024] "Zig 2024 roadmap." LWN.net. https://lwn.net/Articles/959915/

[MATKLAD-COMPTIME-2025] "Things Zig comptime Won't Do." matklad.github.io, April 19, 2025. https://matklad.github.io/2025/04/19/things-zig-comptime-wont-do.html

[NESBITT-2026] Nesbitt, Andrew. "Zig and the M×N Supply Chain Problem." nesbitt.io, January 29, 2026. https://nesbitt.io/2026/01/29/zig-and-the-mxn-supply-chain-problem.html

[RESEARCH-BRIEF] Zig Research Brief. research/tier1/zig/research-brief.md. Penultima project, February 2026.

[SCATTERED-SAFE] "How (memory) safe is zig?" scattered-thoughts.net. https://www.scattered-thoughts.net/writing/how-safe-is-zig/ (Updated version: https://lobste.rs/s/nw7hsd/how_memory_safe_is_zig_updated)

[SO-2025] Stack Overflow Annual Developer Survey 2025. Technology section. https://survey.stackoverflow.co/2025/technology

[SPIE-ZIG-2022] "Heap memory vulnerability utilization method in Zig language." SPIE Proceedings, 2022. https://ui.adsabs.harvard.edu/abs/2022SPIE12503E..0TC/abstract

[STRONGLY-TYPED-2025] "Zig; what I think after months of using it." strongly-typed-thoughts.net, 2025. https://strongly-typed-thoughts.net/blog/zig-2025

[ZIG-ASYNC-BACK] "Async/Await is finally back in Zig." DEV Community / Substack, late 2025. https://dev.to/barddoo/asyncawait-is-finally-back-in-zig-23hi

[ZIG-CODEBERG-ANN] "Migrating from GitHub to Codeberg." ziglang.org/news, November 26, 2025. https://ziglang.org/news/migrating-from-github-to-codeberg/

[ZIG-ISSUE-2647] "Allow returning a value with an error." GitHub issue #2647. https://github.com/ziglang/zig/issues/2647

[ZIG-NEWS-2023] "The Upcoming Release Postponed Two More Weeks and Lacks Async Functions." ziglang.org/news, July 2023. https://ziglang.org/news/0.11.0-postponed-again/

[ZIG-NEWS-ERROR] Ityonemo. "Sneaky Error Payloads." zig.news. https://zig.news/ityonemo/sneaky-error-payloads-1aka

[ZIG-SPEC-UNOFFICIAL] "Zig Language Specification (unofficial)." https://nektro.github.io/zigspec/

[ZIG-014-NOTES] "0.14.0 Release Notes." ziglang.org. https://ziglang.org/download/0.14.0/release-notes.html

[ZLS-GITHUB] "Improving Your Zig Language Server Experience." kristoff.it. https://kristoff.it/blog/improving-your-zls-experience/ (Acknowledges ZLS cannot resolve complex comptime expressions or perform type checking.)

[ZACKOVERFLOW] "I spent 181 minutes waiting for the Zig compiler this week." zackoverflow.dev. https://zackoverflow.dev/writing/i-spent-181-minutes-waiting-for-the-zig-compiler-this-week/

[ZSF-2025-FINANCIALS] "2025 Financial Report and Fundraiser." ziglang.org/news, September 2, 2025. https://ziglang.org/news/2025-financials/

[ZSF-ABOUT] "Zig Software Foundation." ziglang.org/zsf. https://ziglang.org/zsf/
