# C++ — Detractor Perspective

```yaml
role: detractor
language: "C++"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
```

---

## 1. Identity and Intent

C++ was born from a compromise that has never stopped haunting it. Stroustrup wanted Simula's expressiveness and C's performance; he got both by layering abstraction on top of C rather than designing a new language from scratch. That decision — to be "C with Classes" rather than a clean replacement — locked in a compatibility burden that has constrained every subsequent design choice for four decades.

The zero-overhead principle sounds like a guarantee but functions more like an ideology. In practice, "you don't pay for what you don't use" has been used to justify keeping dangerous patterns in the language indefinitely. Yes, you can avoid virtual dispatch if you don't use polymorphism. Yes, you can avoid exception tables if you compile with `-fno-exceptions`. Yes, you can avoid undefined behavior if you know all 200+ instances and never trigger any of them. The problem is that the language makes it trivially easy to accidentally opt into all of these costs and dangers, and the "you chose to use it" defense dissolves when the feature is inherited from C, implicit, or not widely understood.

Stroustrup himself acknowledged the underlying problem in *The Design and Evolution of C++*: "Within C++, there is a much smaller and cleaner language struggling to get out" [STROUSTRUP-DNE-1994]. He also conceded: "I could have built a better language instead of a better C by assigning less importance to compatibility with C. [But it] would have been an unimportant cult language." [STROUSTRUP-DNE-1994] This is an honest statement of the trade-off — and a clear-eyed admission that compatibility was chosen over correctness. The detractor position is not that this was an obviously wrong choice in 1979. It is that 47 years of accumulated consequence should have accumulated proportionate urgency to correct it, and it has not.

The goal of C++ has also shifted without anyone declaring the shift. Originally a systems language for writing efficient programs, C++ became the dominant language for game engines, browsers, databases, ML infrastructure, and financial systems — domains with wildly different safety, correctness, and development-speed priorities. The language was never redesigned for these different contexts; new features were added to address each domain's needs, producing a language that is simultaneously too dangerous for security-critical code and too cumbersome for high-productivity application development. The sprawl is not a sign of success; it is a sign of a language that never said no.

---

## 2. Type System

C++'s type system is large, and large type systems should be judged by whether their size buys safety and expressiveness. C++'s does not do this efficiently.

The system maintains multiple overlapping mechanism layers: raw C types (with their platform-dependent sizes and implicit conversion rules), template-based generic programming, and the relatively recent ADT additions (`std::variant`, `std::optional`, `std::expected`). That these layers coexist rather than supersede each other creates a maintenance and comprehension burden that grows with each standard.

The escape hatches are the most damning part. C-style casts (`(int)x`) bypass most of the type system silently. `reinterpret_cast` allows arbitrary type punning. `const_cast` removes const qualifiers. Unions allow type-unsafe memory aliasing. None of these need to invoke a runtime, throw an exception, or even trigger a compiler warning in most configurations. The language's strong-typing claims are conditional on the programmer's decision not to use a substantial portion of the language.

Undefined behavior further subverts the type system. A signed integer overflow is undefined behavior; the compiler is entitled to assume it does not occur, meaning it can legally optimize away branches that check for it. A 2013 study by Wang et al. found that the STACK checker — a tool for finding UB-caused optimization instabilities — discovered 161 new bugs in widely deployed systems including the Linux kernel and PostgreSQL, confirmed and fixed by the projects' own developers [WANG-STACK-2013]. These were not exotic edge cases; they were the result of normal C++ being compiled with normal optimizations, producing code that violated programmer intent.

The template system is genuinely powerful but occupies an awkward position. Templates are Turing-complete [VELDHUIZEN-1995] — a fact established by demonstration rather than design — which means the language's compile-time computation subsystem has capabilities far exceeding what was planned or documented. Template error messages remained notoriously incomprehensible until Concepts (C++20) imposed semantic constraints; even with Concepts, failures in multiply-nested template instantiations produce diagnostic dumps that require expert interpretation. The mechanism works but cannot be called ergonomic.

The ADT story is a timeline indictment. `std::variant` (C++17) and `std::optional` (C++17) arrived 19 years after the first ISO standard. `std::expected<T,E>` (C++23) — the explicit error-as-value type analogous to Rust's `Result` — arrived 25 years after C++98. Pattern matching on these types is slated for C++26, nearly three decades after languages like Haskell demonstrated the design. During those decades, C++ developers had to either manage error states through exception handling (with all its costs and complications), error codes (which composition requires manual discipline), or `std::pair` / output parameter hacks. The type system had the pieces to do better; the committee was not organized to prioritize delivering them.

---

## 3. Memory Model

C++'s memory model is where the language's structural weaknesses become unavoidable and quantified.

The data is not disputed. Microsoft reports approximately 70% of its annually assigned CVEs are memory safety issues, predominantly in C/C++ codebases [MSRC-2019]. Google reports approximately 70% of serious security bugs in Chrome — written substantially in C++ — are memory safety problems [GOOGLE-CHROME-SECURITY]. Google's MiraclePtr mechanism alone has cut Chrome use-after-free bugs by 57% [GOOGLE-MIRACLEPTR-2024]. The NSA and CISA, in joint guidance published June 2025, explicitly identify C and C++ as "not memory-safe by default" and recommend moving new development to memory-safe languages [CISA-MEMORY-SAFE-2025].

RAII is a genuine improvement over raw C-style manual management, and smart pointers are a further improvement over raw `new`/`delete`. The detractor position is not that these patterns are useless — they are valuable and real. The position is that "use smart pointers correctly, apply RAII everywhere, and hope your dependencies do the same" is not a safety model. It is a best-practices regimen, and best practices are not enforced by the language.

The crucial distinction is structural vs. incidental. In Rust, the borrow checker enforces temporal and ownership safety at compile time; a violation is a compile error. In C++, a use-after-free is a logical error that the compiler is not required to detect, the runtime is not required to catch, and the language is not required to define any behavior for — yet it happens in shipping software at enterprises running the most sophisticated static analysis and review processes in the industry. Microsoft and Google are not making avoidable amateur mistakes. They are experiencing the predictable output of a language design that places memory safety responsibility entirely on the programmer.

Smart pointers do not prevent buffer overflows. `std::unique_ptr<int[]>` manages the lifetime of a heap array, but accessing it out of bounds in release builds is undefined behavior with no diagnostic. `std::span` (C++20) provides bounds-checked views but only enforces bounds in debug builds or when the implementation chooses to. The language provides no mechanism for the programmer to statically guarantee that an array access is in bounds.

The ABI stability policy compounds the structural problem. Because the C++ community has committed to not breaking binary compatibility, the standard library's memory model cannot be radically improved. Containers use `std::allocator` by default; the allocator interface is frozen. Reference counting in `std::shared_ptr` uses atomic operations, which carry measurable overhead in multithreaded code — the design choice is embedded in the ABI and cannot be changed. A language that could fix its memory model but chooses not to, for backward compatibility reasons, is a language that has decided legacy interoperability is more important than the safety of new code.

---

## 4. Concurrency and Parallelism

C++'s concurrency story has the same structural shape as its memory model: the primitives are there, the safety guarantees are not.

The C++11 memory model was a genuine achievement — defining for the first time a formal happens-before model for multi-threaded programs. Before C++11, "threading" in C++ was implementation-defined behavior, and the committee's formalization enabled both compiler optimizations and formal reasoning about correct programs [CPPREFERENCE-ATOMIC]. Credit where due.

But "formal model" and "safe" are different things. The language provides no static guarantee against data races. If two threads write to the same non-atomic variable, the behavior is undefined — but the compiler is not required to detect this, and the program will compile and sometimes appear to work. ThreadSanitizer detects data races dynamically, which means it can only find races in code paths that execute during testing. Rust's ownership model detects data races at compile time, across all possible executions. The gap between these two approaches is not a gap in tooling; it is a gap in language design.

The `memory_order_consume` ordering is an instructive case study. Introduced in C++11, it was designed to be more efficient than `memory_order_acquire` on weakly-ordered architectures, with optimized semantics for pointer-carrying loads. It has never been correctly implemented by any compiler — GCC, Clang, and MSVC all silently promote `consume` to `acquire`, negating the intended performance benefit [CPPREFERENCE-ATOMIC]. The feature exists in the standard, appears in the documentation, and is a trap for developers who attempt to use it as designed. A language standard that specifies a feature that no implementation has ever correctly implemented is not providing a feature; it is providing a landmine.

The coroutine design (C++20) exemplifies the zero-overhead philosophy taken past the point of usefulness. C++20 coroutines are stackless, have no scheduler, and require the programmer to build or adopt a runtime framework to do anything practical. The language specification defines the coroutine machinery (`co_await`, `co_yield`, `co_return`) but deliberately omits anything resembling an async executor, leaving each library or application framework to reinvent this wheel [INFOWORLD-CPP20]. The result is a fragmented ecosystem of incompatible coroutine frameworks (cppcoro, ASIO's coroutine integration, Qt's coroutine support, various game engine async systems) rather than a coherent concurrency model. Compare this to Go's goroutines (scheduled automatically, with a standard runtime) or Rust's async ecosystem (multiple runtimes, but a single standard async trait machinery). Programmers can use C++ coroutines in production, but they cannot point to "the C++ concurrency model" — there is no unified model, only components.

The parallel algorithms in C++17 (execution policies on `std::for_each`, etc.) represent a narrower version of the same problem: useful for data-parallel workloads over standard containers, but requiring that the implementation actually parallelize them, which is not guaranteed and varies by platform.

---

## 5. Error Handling

C++ error handling is not bad by accident. It is bad by accretion — three incompatible philosophies deposited in layers over 40 years, with none fully superseding the others.

Layer one is C's error model: return codes, `errno`, and the discipline-based convention that error checks happen manually. Layer two is C++'s exception model: `throw`/`try`/`catch`, introduced as the "correct" C++ way to handle recoverable errors. Layer three is the value-based error model now represented by `std::expected<T,E>` (C++23) — arriving 25 years after C++98, inspired by Rust and Haskell, and still lacking the propagation sugar (a `?`-equivalent operator) that makes it ergonomic in those languages.

A real C++ codebase typically contains all three layers: C libraries using errno and error codes, C++ standard library APIs that throw, and modern C++23 code using `std::expected`. There is no standard way to bridge these; developers write wrapper functions or adopt conventions that are project-local. The result is that error handling discipline requires more boilerplate than any single coherent design would demand, and errors are dropped at the seams between paradigms.

The exception model's specific costs are domain-defining. Binary size: enabling exceptions adds +15% to +52% overhead even when no exception is ever thrown or caught, because stack-unwinding tables must be generated for all functions in the call stack [EXCEPTION-BLOAT]. This cost is why virtually every game engine — Unreal Engine, Unity, Frostbite — disables exceptions with `-fno-exceptions` and prohibits their use in production code. It is why the Linux kernel never adopted C++ exception handling. It is why embedded and real-time system developers standardly reject exceptions. Linus Torvalds described exception handling as "fundamentally broken" for kernel code, specifically because of the non-determinism it introduces [TORVALDS-CPP]. When a language feature is so costly that major professional domains specifically prohibit it, that feature is not a general solution.

The "zero-cost exception" framing is partially misleading. Zero cost applies to the happy path — when no exception is thrown. When an exception is thrown, the cost is orders of magnitude higher than an equivalent return-value error path [MOMTCHEV-EXCEPTIONS]. For code that must handle errors as a normal case (file parsing, network I/O, user-facing operations), exceptions impose a severe performance cliff. The appropriate response to this cliff is to use something other than exceptions — which brings the developer back to manual error code handling, where they started.

`std::expected` is a real improvement and arrived better late than never. But without a propagation operator analogous to Rust's `?` or Haskell's `do`-notation, `.and_then()` chains quickly become syntactically heavier than the errors they replace. Until C++ adds a first-class error propagation mechanism, `std::expected` will remain more ergonomic than exceptions for some workloads but less ergonomic than the equivalent in Rust or Swift.

---

## 6. Ecosystem and Tooling

The C++ ecosystem's fragmentation is not merely an inconvenience — it imposes real, measurable productivity costs and introduces supply chain risks that other major languages have addressed.

**Package management** is the clearest failure. After 40+ years and billions of deployed C++ programs, the language has no official package manager. Developers choose between vcpkg (~2,000 packages), Conan (~1,500 packages), or manual source download and integration [TWDEV-PKGMGMT]. A 2024 Modern C++ DevOps survey found that a significant fraction of C++ developers still copy-paste source code or download prebuilt binaries rather than using any package manager [MODERNCPP-DEVOPS-2024]. npm has over 2 million packages; PyPI has over 500,000; Rust's crates.io has over 170,000. The C++ ecosystem's package catalogues, even combined, are an order of magnitude smaller than these, reflecting the friction of publishing and consuming C++ libraries through any standardized mechanism.

This fragmentation has security consequences. Neither vcpkg nor Conan provides centralized security advisory infrastructure analogous to PyPI's security advisories or npm's audit functionality. There is no `cpp audit` command a developer can run to check whether their dependency tree contains known-vulnerable packages. Supply chain attacks in C++ are most likely to occur through build scripts or bundled source dependencies that developers incorporated manually — exactly the mode of adoption that remains common [RESEARCH-BRIEF-SECURITY].

**Build systems** compound the fragmentation. CMake is de facto standard but widely criticized as arcane; Bazel is powerful but imposes steep setup costs; Meson is faster but less ubiquitous; legacy Make persists in large codebases. Library maintainers who want broad adoption must typically support multiple build systems simultaneously — a maintenance burden that discourages library publication [INCREDIBUILD-BUILD]. The ISO C++ Foundation's position that "CMake is fine" does not match developer experience at scale: Chrome uses Bazel; LLVM uses CMake but has considered migrating; TensorFlow uses Bazel.

**Module adoption** is the most instructive recent failure. C++20 modules were the headline feature promised to finally fix C++'s compilation speed and header inclusion mess — a problem visible since the 1990s. The standard was published in 2020. As of early 2026, over four years later: GCC's module support is still experimental and progress "has pretty much stalled until very recently" according to compiler developers; Clang's module support requires version-specific flags and incomplete interoperability with major build systems; MSVC is the only compiler with mature module support [MODULES-SKEPTICAL-2025]. The feature is in the standard, but most C++ developers cannot safely use it in production because the toolchain support is incomplete.

Contrast this with Rust's module system, which was stable at 1.0 and immediately usable, or Go's package system, which required no migration period. C++'s governance and standardization model is capable of standardizing features that take a decade to become practically available — which means the standards serve as aspirational documents rather than deployment targets for years at a time.

**AI tooling** presents an underappreciated risk. C++ is well-represented in training data for GitHub Copilot and similar tools. However, because the language has changed substantially across 8 major standards (C++98 through C++23), AI tools frequently generate syntactically valid but semantically outdated or subtly incorrect modern C++ — pre-C++11 patterns with raw pointers, or modern patterns containing undefined behavior that compiles without warning [RESEARCH-BRIEF-DX]. Unlike Python or TypeScript, where "modern Python" and "old Python" are largely compatible, "modern C++23" and "C++98" have radically different idioms that the generated code may conflate without triggering any diagnostic.

---

## 7. Security Profile

C++'s security profile is well-documented, extensively studied, and consistently damning. The problem is not marginal or improving at a satisfactory rate.

The headline statistics bear repeating precisely because their consistency across independent sources eliminates the possibility of measurement bias: Microsoft reports ~70% of its CVEs are memory safety issues in C/C++ [MSRC-2019]; Google reports ~70% of serious Chrome security bugs are memory safety problems [GOOGLE-CHROME-SECURITY]; the NSA/CISA joint guidance published June 2025 identifies C/C++ as the primary source of memory safety vulnerabilities in critical infrastructure and recommends migrating to memory-safe languages [CISA-MEMORY-SAFE-2025]. VulnCheck data shows memory safety Known Exploited Vulnerabilities reached approximately 200 in 2024, the highest recorded value [RUNSAFE-KEVS].

The clearest demonstration of the structural nature of this problem is Google's Rust migration in Android. After systematically introducing Rust for new code, memory safety vulnerabilities in Android declined from 223 in 2019 to fewer than 50 in 2024. Memory safety issues now represent less than 20% of Android's vulnerability total, down from over 75% four years prior [ANDROID-MEMSAFETY-2025]. The Google Security team estimates a 1,000x reduction in memory safety vulnerability density compared to equivalent C/C++ code [GOOGLE-ANDROID-RUST-2025]. These are not theoretical projections; they are observed outcomes in a production system at scale.

Beyond the shared C/C++ patterns, C++ introduces vulnerability classes specific to its object model:

**Vtable corruption and type confusion.** C++ virtual dispatch relies on vtable pointers embedded in object headers. Memory corruption — from any buffer overflow — can overwrite a vtable pointer, redirecting all subsequent virtual function calls through an attacker-controlled table. A 2017 NDSS study identified vtable escape bugs as a distinct vulnerability class in deployed software including Adobe Reader, Microsoft Office, and Windows subsystem DLLs [NDSS-VTABLE-2017]. Chromium's V8 JavaScript engine has experienced multiple type confusion CVEs exploiting virtual dispatch (CVE-2024-0517, CVE-2024-7971) [CVE-CHROME-2024]. This vulnerability class does not exist in C (no vtables), Java (no raw memory access), or Rust (no unsafe virtual dispatch by default).

**Exception handling edge cases.** Stack unwinding during exception propagation can leave resources in inconsistent state if destructors throw — a condition explicitly undefined in the standard. The interaction between RAII cleanup and exception propagation creates a mode of correctness failure that is difficult to test because it requires precisely the error conditions that normally disrupt testing.

**Compiler exploitation of undefined behavior.** A study by Wang et al. using the STACK checker found 161 confirmed UB-caused bugs in the Linux kernel and PostgreSQL — bugs where compiler optimizations, legally applied, produced code that contradicted programmer intent [WANG-STACK-2013]. The Check Point OptOut research (2020) documented specific instances where NULL dereference checks were optimized away because an earlier dereference implied the pointer was valid — effectively removing security checks added by defensive programmers [CHECKPOINT-OPTOUT-2020]. The language's UB rules do not merely tolerate misoptimization; they enable it.

The language-level mitigations available in C++ are all compensatory: smart pointers prevent some use-after-free but not buffer overflows; `std::span` provides bounds views but does not enforce them in release builds; C++ Core Guidelines Safety Profiles are "not yet available, except for experimental and partial versions" as of Stroustrup's own 2025 CACM assessment [STROUSTRUP-CACM-2025]. The gap between "we know what we should do" and "the language enforces it" has not closed in 47 years.

---

## 8. Developer Experience

The developer experience of C++ is one of the most empirically studied aspects of the language, and the data is consistent: C++ is professionally necessary for a significant fraction of developers and preferred by a small fraction.

Stack Overflow's 2023 survey placed C++ in the "most dreaded" language category [SO-SURVEY-2024] — meaning more of those using it would prefer not to be than for any similarly used language. The 2024 survey replaced this framing, but C++ maintained its reputation for complexity among developers who do not use it daily. Among those who do use it professionally, satisfaction is higher — but this conflates expertise with preference.

The learning curve problem is structural, not pedagogical. C++ has several independent complexity layers that must all be understood for safe usage:

**Undefined behavior.** The ISO C++ standard contains approximately 200+ instances of undefined behavior — cases where program behavior is not specified, allowing compilers to assume the situation never occurs and optimize accordingly. Unlike C11, which provides an explicit list (Annex J), C++ scatters its undefined behavior through the standard without a comprehensive enumeration. A developer who does not know that shifting an integer by more than its width is undefined behavior will write code that works in debug builds and fails silently in release builds. This is not a failure of the compiler; it is the language working as designed.

**Initialization.** C++ has at least six forms of initialization — default, value, direct, copy, list (brace), and aggregate — with subtly different semantics in edge cases. "Uniform initialization" in C++11 was meant to unify these, but list initialization introduced its own ambiguities (the "most vexing parse" was joined by "auto with braces deduces initializer_list"). A developer cannot understand C++ initialization without understanding all of these forms and their interactions.

**The Rule of Zero/Three/Five.** Any class that manages a resource must correctly implement the destructor, copy constructor, copy assignment operator, and (post-C++11) move constructor and move assignment operator — or explicitly delete them. Omitting any of them in a class that manages ownership produces subtle bugs. The Rule of Zero (don't write any of them; use smart pointers to manage resources) is the current recommended practice — which is a workaround for an asymmetry in the language's defaults, not a solution to it.

**Template complexity.** Template error messages are famously difficult even after Concepts. A mistaken type in a deeply nested template instantiation can produce multiple screenfuls of error output tracing through intermediate instantiations before reaching the actual constraint violation. Concepts improve the top level but do not eliminate the intermediate noise.

Compile times impose a direct productivity tax. Chrome takes 15–30 minutes for a full build on a developer workstation [RESEARCH-BRIEF-DX]. Large projects use distributed compilation systems (Bazel remote cache, Incredibuild) as a mitigation, adding infrastructure complexity. The module system was promised to address this, but its adoption is still incomplete in 2026 — four years after standardization.

The toolchain complexity is also real: a developer joining a C++ project must potentially learn CMake or Bazel or Meson, choose between GCC and Clang, configure a sanitizer-enabled test build, set up a package manager, and configure clang-tidy. No other major compiled language imposes this configuration matrix. Rust ships with `cargo`; Go ships with `go`; Python ships with `pip`. C++ ships with the expectation that someone else has already figured all of this out.

---

## 9. Performance Characteristics

C++ is undeniably fast, and this section should acknowledge it honestly before noting where the performance narrative is distorted.

C++ and C rank in the top tier across Computer Language Benchmarks Game categories; at equivalent optimization levels on equivalent hardware, C++ often matches or marginally exceeds C [BENCHMARKS-PILOT]. This reflects the zero-overhead principle operating as intended for programmer-optimized hot paths. The compilers — GCC and Clang — have 40+ years of optimization investment, producing some of the most sophisticated code generation in existence.

But the performance argument is more complicated than "C++ is fast."

**Virtual dispatch has real cost.** Virtual function calls add approximately 1–5 ns per call on modern hardware and inhibit inlining — the single most important optimization a compiler can perform on hot paths. In tight loops on performance-critical code, avoiding virtual dispatch is a standard optimization technique, requiring architectural changes (policy-based design, CRTP) that increase code complexity. A language that achieves peak performance only when avoiding one of its core OOP mechanisms has performance characteristics tied to OOP usage patterns in a way that requires expert awareness.

**`std::shared_ptr` overhead is real in concurrent code.** The atomic reference count increment and decrement in `shared_ptr` are measurably slower than `unique_ptr` operations in multithreaded workloads, because atomic operations serialize execution [BENCHMARKS-PILOT]. The correct C++ answer is "use `unique_ptr` when possible" — but code that passes ownership between components frequently cannot avoid shared ownership, and `weak_ptr` cycles add further complexity.

**Exception handling has non-zero cost.** The "zero-cost exception" claim applies only to the non-throwing path. On the throwing path, exception cost is orders of magnitude higher than a comparable return-value path [MOMTCHEV-EXCEPTIONS]. For latency-sensitive code in financial systems or games — exactly the domains C++ is used for — this cliff matters. The standard answer is "don't use exceptions for expected failure"; the practical answer is that "expected failure" is poorly defined in many real systems.

**Template bloat.** Heavy template instantiation significantly increases binary size. An application using the full STL with multiple container types and algorithm specializations will have a meaningfully larger binary than equivalent C code. Link-time optimization and dead code elimination mitigate this, but require careful configuration. In binary-size-constrained environments (embedded systems, firmware), template bloat has forced developers to write custom non-template versions of standard data structures.

**Compilation speed** is not a performance characteristic of the compiled program, but it is a developer-visible performance characteristic of the language system. C++ is among the slowest languages to compile at scale. This imposes feedback-cycle costs: a developer who must wait 20 minutes for a full build performs fewer experimental iterations per hour than one using a language with second-scale compile times.

The underlying truth is that C++ can be made extremely fast by skilled practitioners who understand its cost model. The question for language design is not "can experts make it fast?" but "does the language make fast code the default, with inefficiency requiring effort?" In C++, the answer is partially yes — but the performance defaults include `shared_ptr` overhead, vtable overhead in polymorphic hierarchies, and exception table overhead, which require deliberate opt-out.

---

## 10. Interoperability

C++'s interoperability story has a single strong point and several structural weaknesses.

The strong point: C ABI compatibility via `extern "C"` is genuine and valuable. C++ code can export C-compatible interfaces that any language capable of C FFI can call. This has made C++ a natural choice for high-performance library implementations with thin C-API wrappers (OpenSSL, SQLite integration layers, GPU computing libraries). This compatibility is real.

The structural weaknesses:

**The C++ ABI is not stable.** C++ has no standard ABI across compilers or platforms. Name mangling (encoding function signatures into linker symbols) differs between GCC and MSVC. Virtual table layout differs between compilers. Exception handling metadata format differs. The practical consequence: C++ shared libraries must either expose C APIs or be linked against by code compiled with the same compiler, same version, and same flags [GCC-ABI-POLICY]. Binary distribution of C++ libraries is a persistent infrastructure problem. In practice, distributing a C++ library in binary form means either limiting to a single compiler ecosystem (Visual Studio), distributing as source (the entire Linux/CMake ecosystem), or maintaining compiler-specific binary packages — adding O(n×m) maintenance burden where n is platforms and m is compilers.

**The consequence of ABI fragility on library design.** Because changing the internal layout of a C++ standard library type breaks binary compatibility with all existing callers, the standard library is effectively frozen at the design decisions made when each type was first standardized. `std::string`'s small-buffer-optimization implementation, `std::unordered_map`'s chained-bucket design, `std::shared_ptr`'s control-block layout — all are frozen. Known improvements (Facebook's `folly::F14Map` is substantially faster than `std::unordered_map`; virtually every major C++ project replaces standard string with a custom implementation) cannot be incorporated into the standard library without an ABI break. The ABI stability commitment that was meant to enable interoperability has calcified performance-critical infrastructure.

**FFI complexity from other languages.** Calling C++ from Python, Rust, or Go typically requires writing C wrapper functions for the C++ API, binding generators (pybind11, cxx-rs, SWIG), or project-specific bridge layers. This is substantially more complex than calling C from those languages, which requires only a simple FFI header. Projects like TensorFlow and PyTorch expose Python APIs through pybind11 wrappers over C++ backends — a pattern that works but requires expertise and maintenance that would not be necessary if the library were written in a language with a stable, standard ABI.

**Cross-compilation.** C++'s lack of a standard build system means cross-compilation requires project-specific configuration. CMake's cross-compilation support requires manually specified toolchain files; there is no `cpp target add aarch64-linux-gnu` equivalent to Rust's `rustup target add`. Major embedded systems projects (automotive, IoT, aerospace) have invested significantly in toolchain infrastructure that languages with first-class cross-compilation support provide by default.

---

## 11. Governance and Evolution

WG21's governance model is thorough, representative of major industry stakeholders, and significantly too slow.

The three-year release cadence has been stable since 2012. This sounds reasonable until applied to the question of deployment: a feature entering discussion in 2022 targets C++26 at earliest, reaches compiler implementations by 2026–2027, achieves widespread toolchain adoption by 2028–2030, and becomes the default expectation for new codebases by 2032. A ten-year horizon from proposal to expectation is not a release cadence; it is a geological epoch.

The modules story is the clearest demonstration. Modules were first proposed to WG21 in 2012, standardized in C++20 (2020), and as of early 2026 have incomplete compiler support across GCC and Clang, incomplete build system integration, and zero adoption in the major C++ projects (Chrome, LLVM, TensorFlow). The feature that was supposed to fix C++'s most-discussed practical problem — compilation speed and header proliferation — has been in the standard for four years without becoming usable for most practitioners.

Stroustrup himself warned in 2018 of the risk of feature proliferation: "C++ could crumble under the weight of these — mostly not quite fully-baked — proposals," and noted fears that C++17 "added significant surface complexity and increased the number of features people need to learn" [STROUSTRUP-REGISTER-2018]. This is the language's creator, in print, expressing concern that the language committee's output is degrading the language. That concern has not produced structural reform.

The backward compatibility commitment is the governance constraint that locks all other problems in. The committee cannot remove `reinterpret_cast`, cannot regularize initialization, cannot redesign the standard library containers, cannot simplify the template error model — because doing so would break existing code. This is, in isolation, a defensible position. The practical consequence is that C++ accumulates features without retiring the features they supersede. Every standard adds; nothing is ever simplified. The resulting language requires more expertise to use safely than any single programmer can fully hold in memory.

The ABI stability question has been raised explicitly within the community. At CppCon 2019, several contributors proposed an ABI break for C++23 or C++26 to allow standard library improvements. The proposal was rejected. The opportunity to fix `std::unordered_map`, `std::string`, and other performance-critical types passed without action. Google subsequently published a case for why an ABI break would improve performance across the ecosystem; the committee decided continuity was more important [ABI-BREAK-DISCUSSION-2020].

The corporate-heavy composition of WG21 has mixed effects. Deep expertise in language implementation is brought by engineers from Google, Microsoft, Apple, and Intel. But corporate priorities (backward compatibility to protect large existing codebases; feature requests for domain-specific needs) can dominate decisions that would otherwise favor simplicity or correctness. The committee has no structural mechanism for prioritizing "reduce overall complexity" over "add feature X that solves use case Y."

---

## 12. Synthesis and Assessment

### Greatest Strengths

It would be dishonest to ignore C++'s genuine strengths:

**Performance ceiling.** For compute-intensive code written by experts with full knowledge of the language's cost model, C++ achieves performance indistinguishable from C — the acknowledged hardware-proximity champion. This ceiling matters in specific domains: high-frequency trading, real-time game physics, ML kernel implementations.

**Domain coverage.** The combination of low-level system access, high-level abstraction, and zero-overhead principle covers a uniquely broad space. No current alternative covers game engines, embedded systems, ML infrastructure, and high-performance databases simultaneously.

**Mature tooling.** GCC and Clang represent 40+ years of compiler engineering investment. The sanitizers (ASan, UBSan, TSan, MSan) are genuinely excellent at catching bugs during development. cppreference.com is one of the highest-quality language reference resources in existence.

**Improving trajectory.** C++11 genuinely transformed the language. C++20's Concepts and Ranges are real improvements. `std::expected` in C++23 is a step toward value-based error handling. The trajectory is upward; the rate of improvement is too slow.

### Greatest Weaknesses

**Memory unsafety is structural.** C++'s memory model cannot be made safe without breaking changes. The 70% CVE statistics from Microsoft and Google, the 1,000x vulnerability density differential from Android's Rust migration, and the NSA/CISA recommendation to move away from C/C++ all point to the same conclusion: C++'s memory safety problem is not solvable within the current language model. Tooling mitigates it; the language cannot eliminate it.

**Undefined behavior is pervasive and compilers exploit it.** The ~200+ UB instances in the standard are not edge cases; they include integer overflow, null pointer arithmetic, uninitialized reads, and data race access. Compiler UB exploitations produce code that removes security checks added by careful programmers [WANG-STACK-2013][CHECKPOINT-OPTOUT-2020]. No amount of expertise fully protects against UB in code that calls third-party libraries.

**Feature accretion without coherence.** C++ is now three languages superimposed: C-style procedural code (still valid, still common in legacy codebases and kernel interfaces), C++11-era modern OOP with RAII and smart pointers, and C++20+ template metaprogramming with Concepts and Ranges. These layers coexist without a common error handling convention, common concurrency model, or common resource management discipline. New developers must learn which layer applies to their context; experts must understand all three to read arbitrary C++ code.

**Ecosystem fragmentation is severe.** No official package manager, no standard build system, module adoption stalled at four years post-standardization. This is not an annoyance — it is a structural impediment to library ecosystem growth and supply chain security.

**Governance is too slow for the language's threat environment.** The ABI stability decision, the module adoption gap, and the 10-year proposal-to-expectation timeline are not failures of individual decisions but structural features of a governance process designed for a less competitive era.

### Structural vs. Fixable Problems

| Problem | Structural | Fixable |
|---|---|---|
| Memory unsafety | ✓ (cannot retrofit borrow checking) | |
| Undefined behavior pervasiveness | ✓ (baked into C compatibility) | |
| ABI instability across compilers | ✓ (no standards body governs ABI) | |
| Package management fragmentation | | ✓ (a standards decision could create one) |
| Module adoption delay | | ✓ (toolchain investment could accelerate) |
| Error handling fragmentation | ✓ (cannot remove exceptions or error codes) | partial |
| Build system proliferation | | ✓ (community consensus possible) |
| Compilation speed | | ✓ (modules, if adopted) |
| Coroutine ecosystem fragmentation | | ✓ (std::execution in C++26 is a step) |
| Template error message complexity | | ✓ (Concepts help; more work possible) |

The structural problems are the ones that matter for language design lessons: they cannot be fixed without abandoning C++ for a successor (which Carbon and Rust represent in different ways).

---

### Lessons for Language Design

**Lesson 1: Backward compatibility with an unsafe predecessor language is not free — name the cost and design around it.**
C++ inherited C's unsafe type conversions, C's pointer arithmetic, C's memory model, and C's undefined behavior. The cost was paid by every developer who ever wrote C++ with the assumption that "valid C++" meant "correct program." A new systems language that claims C compatibility should specify exactly which C features it inherits, which it rejects, and what guarantees it makes about the remainder. Claiming compatibility while disclaiming its consequences is dishonest to users.

**Lesson 2: "You don't pay for what you don't use" is not a safety model — it is a contract that the compiler can void.**
When a language permits undefined behavior to enable compiler optimizations, the programmer's mental model of what their code does diverges from what the compiler produces. A language that exposes undefined behavior as a performance mechanism is delegating compiler correctness obligations to programmers who cannot fulfill them. Safety-correctness guarantees must be statically enforced by the compiler, not left to programmer discipline.

**Lesson 3: Error handling must be unified at design time — retrofitting multiple systems produces fragmentation that compounds permanently.**
C++ began with C's error codes, added exceptions, and added `std::expected` 25 years later. None of these supersedes the others; all persist in the same codebases. A language must choose a primary error propagation model at inception. Adding additional models later creates permanent interoperability friction.

**Lesson 4: Language features without standardized propagation sugar are used incorrectly at scale.**
`std::expected` without a `?` operator makes error propagation more verbose than error-code handling. Coroutines without a standard executor require every library to implement scheduling independently. A language feature that is formally correct but ergonomically painful will be misused or avoided in proportion to its verbosity overhead. Propagation ergonomics must be designed alongside the feature, not left to future standards.

**Lesson 5: A feature standardized without ecosystem adoption infrastructure is not a feature — it is a specification.**
C++ modules were standardized in 2020. As of 2026, GCC support is still experimental. A language standard that specifies a feature before the major implementations can support it creates a documentation/deployment gap that misleads new users and fragments adoption. A language standard should certify features only when at least two major implementations demonstrate correct behavior.

**Lesson 6: Package management and build infrastructure must be first-class language concerns, not afterthoughts.**
Rust shipped cargo at 1.0. Go shipped the `go` tool at 1.0. C++ has shipped 8 ISO standards without specifying any of: a package management format, a build description standard, or a module distribution mechanism. The cost is not merely aesthetic — it is a security risk (no centralized vulnerability tracking), a productivity cost (per-project toolchain configuration), and a library ecosystem size limiter (library authors must support multiple systems). Any new language must treat build and package tooling as part of the language specification.

**Lesson 7: ABI stability as an invariant calcifies the standard library.**
Committing to never breaking binary compatibility means the standard library cannot improve. C++'s `std::unordered_map`, `std::string`, and `std::shared_ptr` have known performance problems that are fixable in principle but unaddressable in practice because changing them would break binary-level callers. A language that wants an evolvable standard library must either specify ABI break policies explicitly (with versioning) or accept that "stable ABI" and "improving stdlib" are permanently in tension.

**Lesson 8: "Do not use this dangerous feature" is not a substitute for removing it.**
C++ Core Guidelines prohibit C-style casts, recommend against `reinterpret_cast`, discourage raw pointer arithmetic, and advise against `goto`. The features remain in the language and in production code. Guidelines that cannot be statically enforced are advisory, not safety mechanisms. A language with dangerous features it cannot remove should at minimum provide compiler-enforced dialects that reject them — not expect developers to police themselves against features the compiler is willing to accept.

**Lesson 9: A language must know what it is trying to be and resist pressure to become everything.**
C++ added templates for generics, added exceptions for error handling, added OOP for abstraction, added functional features for expressiveness, added coroutines for async, added parallel algorithms for data parallelism, added modules for compilation speed, and is now adding reflection and contracts. Each addition addressed a real problem. The aggregate result is a language of extraordinary breadth and extraordinary complexity — a language that no developer can know completely and that AI-assisted code generation regularly misuses because no training corpus captures its full, consistent semantics. Scope decisions compound over decades; a language committee must hold the line on coherence or accept the consequences of its absence.

**Lesson 10: Memory safety cannot be an expert-only property.**
If only expert programmers can write memory-safe code in a language, then any production system that employs non-expert programmers — which is every production system — will have memory unsafety proportional to its non-expert contribution. C++'s requirement that every developer understand RAII, smart pointer ownership, lifetime rules, and undefined behavior to write safe code is not a reasonable contract with its user population. Memory safety must be the default, with unsafe operations requiring explicit opt-in and compiler-enforced acknowledgment.

### Dissenting View

The apologist position on C++ — that it remains indispensable because no alternative covers its full domain — deserves honest acknowledgment. As of early 2026, no language covers game engine development, embedded systems, ML kernel infrastructure, and high-frequency trading with comparable performance and ecosystem depth. Rust is the strongest challenger but has not yet displaced C++ in these domains at scale. The detractor position is not "use something else today for everything." It is: (a) recognize that C++'s safety record makes it inappropriate for new security-sensitive code, where better alternatives now exist; (b) understand that every year spent in C++'s problem space is a year of preventable vulnerabilities in existing systems; and (c) ensure that any language design drawing lessons from C++ learns from its structural failures rather than repeating them under a different name.

---

## References

[STROUSTRUP-DNE-1994] Stroustrup, B. *The Design and Evolution of C++*. Addison-Wesley, 1994. https://www.stroustrup.com/dne.html

[STROUSTRUP-CACM-2025] Stroustrup, B. "21st Century C++." *Communications of the ACM*, February 2025. https://cacm.acm.org/blogcacm/21st-century-c/

[STROUSTRUP-REGISTER-2018] "Bjarne Stroustrup Fears C++ Could 'Crumble Under the Weight' of Complexity." *The Register*, June 2018. https://theregister.com/2018/06/18/bjarne_stroustrup_c_plus_plus/

[STROUSTRUP-FAQ] Stroustrup, B. "Bjarne Stroustrup's FAQ." https://www.stroustrup.com/bs_faq.html

[MSRC-2019] Miller, M. "A Proactive Approach to More Secure Code." Microsoft Security Response Center, 2019. https://www.microsoft.com/en-us/msrc/blog/2019/07/a-proactive-approach-to-more-secure-code/

[GOOGLE-CHROME-SECURITY] Google Chrome Security Team. "Memory Safety." https://www.chromium.org/Home/chromium-security/memory-safety/

[GOOGLE-MIRACLEPTR-2024] Google Security Blog. "Safer with Google: Advancing Memory Safety." October 2024. https://security.googleblog.com/2024/10/safer-with-google-advancing-memory.html

[CISA-MEMORY-SAFE-2025] NSA/CISA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://media.defense.gov/2025/Jun/23/2003742198/-1/-1/0/CSI_MEMORY_SAFE_LANGUAGES_REDUCING_VULNERABILITIES_IN_MODERN_SOFTWARE_DEVELOPMENT.PDF

[TECHREPUBLIC-CISA-2024] "Software Makers Encouraged to Stop Using C/C++ by 2026." *TechRepublic*. https://www.techrepublic.com/article/cisa-fbi-memory-safety-recommendations/

[GOOGLE-ANDROID-RUST-2025] Google Security Blog. "Rust in Android: Move Fast, Fix Things." November 2025. https://security.googleblog.com/2025/11/rust-in-android-move-fast-fix-things.html

[ANDROID-MEMSAFETY-2025] "Rust Adoption Drives Android Memory Safety Below 20%." *The Hacker News*, November 2025. https://thehackernews.com/2025/11/rust-adoption-drives-android-memory.html

[WANG-STACK-2013] Wang, X., Chen, H., Cheung, A., Jia, Z., Zeldovich, N., Kaashoek, M.F. "Towards Optimization-Safe Systems: Analyzing the Impact of Undefined Behavior." *SOSP 2013*. MIT CSAIL. https://people.csail.mit.edu/nickolai/papers/wang-stack.pdf

[CHECKPOINT-OPTOUT-2020] Check Point Research. "OptOut: Compiler Undefined Behavior Optimizations." 2020. https://research.checkpoint.com/2020/optout-compiler-undefined-behavior-optimizations/

[CARBON-FAQ] Google. "Carbon Language FAQ." GitHub. https://github.com/carbon-language/carbon-lang/blob/trunk/docs/project/faq.md

[TORVALDS-CPP] Torvalds, L. "Re: C++ for kernel development." Linux Kernel Mailing List, September 2007. Archived at: https://harmful.cat-v.org/software/c++/linus

[PIKE-GO-2012] Pike, R. "Less is exponentially more." Talk at SPLASH 2012. https://go.dev/talks/2012/splash.article

[NDSS-VTABLE-2017] Payer, M., et al. "TypeSan: Practical Type Confusion Detection." *NDSS 2017*. https://www.ndss-symposium.org/wp-content/uploads/2017/09/14_2.pdf

[CVE-CHROME-2024] OPSWAT/Rapid7 CVE analysis. CVE-2024-0517, CVE-2024-7971 (V8 type confusion). https://www.opswat.com/blog/remediating-the-cve-2024-0517-vulnerability-in-google-chrome ; https://www.rapid7.com/db/vulnerabilities/google-chrome-cve-2024-7971/

[MITRE-CWE-TOP25-2024] "CWE Top 25 Most Dangerous Software Weaknesses 2024." MITRE. https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html

[RUNSAFE-KEVS] "Memory Safety KEVs Are Increasing." RunSafe Security. https://runsafesecurity.com/blog/memory-safety-kevs-increasing/

[CODE-INTELLIGENCE-2025] "Top Six Most Dangerous Vulnerabilities in C and C++." Code Intelligence, 2025. https://www.code-intelligence.com/blog/most-dangerous-vulnerabilities-cwes-in-c-2025

[MODULES-SKEPTICAL-2025] "C++ Modules in 2026: Game-Changer or Overhyped?" Whole Tomato, 2025. https://www.wholetomato.com/blog/c-modules-what-it-promises-and-reasons-to-remain-skeptical/

[MOMTCHEV-EXCEPTIONS] Momtchev, M. "The true cost of C++ exceptions." *Medium*. https://mmomtchev.medium.com/the-true-cost-of-c-exceptions-7be7614b5d84

[EXCEPTION-BLOAT] Game Developer Network / GameDev.net forum documentation on exception handling overhead. https://www.gamedev.net/forums/topic/689321-performance-with-using-exceptions-in-c-game-programming/

[VELDHUIZEN-1995] Veldhuizen, T. "Using C++ Template Metaprograms." *C++ Report*, 1995. (Established Turing-completeness of C++ templates by demonstration.)

[CPPREFERENCE-ATOMIC] "std::memory_order — cppreference.com." https://en.cppreference.com/w/cpp/atomic/memory_order.html

[INFOWORLD-CPP20] "What's new in C++20: modules, concepts, and coroutines." *InfoWorld*. https://www.infoworld.com/article/2259480/whats-new-in-c-plus-plus-20-modules-concepts-and-coroutines.html

[TWDEV-PKGMGMT] "The State of C++ Package Management: The Big Three." twdev.blog, August 2024. https://twdev.blog/2024/08/cpp_pkgmng1/

[MODERNCPP-DEVOPS-2024] "Breaking down the 2024 Survey Results." Modern C++ DevOps. https://moderncppdevops.com/2024-survey-results/

[BENCHMARKS-PILOT] "Performance Benchmark Reference: Pilot Languages." evidence/benchmarks/pilot-languages.md. Penultima Evidence Repository, February 2026.

[CVE-C-DATA] "CVE Pattern Summary: C Programming Language." evidence/cve-data/c.md. Penultima Evidence Repository, February 2026. *Note: C and C++ share substantially identical vulnerability patterns.*

[SO-SURVEY-2024] "Stack Overflow Developer Survey 2024." https://survey.stackoverflow.co/2024/

[GCC-ABI-POLICY] "ABI Policy and Guidelines." GCC Libstdc++ Manual. https://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html

[ABI-BREAK-DISCUSSION-2020] "To ABI or not to ABI." isocpp.org discussion thread, 2020. (Referenced in community coverage.) See also: Orr, R., "To ABI or not to ABI, that is the question." WG21 paper P1863R1.

[INCREDIBUILD-BUILD] "Choosing the Right C++ Build System: Comprehensive Guide for Developers." Incredibuild. https://incredibuild.com/blog/choosing-the-right-c-build-system-comprehensive-guide-developers/

[RESEARCH-BRIEF-SECURITY] "C++ — Research Brief." Section: Security Data. research/tier1/cpp/research-brief.md. Penultima Research Repository, February 2026.

[RESEARCH-BRIEF-DX] "C++ — Research Brief." Section: Developer Experience Data. research/tier1/cpp/research-brief.md. Penultima Research Repository, February 2026.
