# C++ — Systems Architecture Advisor Review

```yaml
role: advisor-systems-architecture
language: "C++"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
```

---

## Summary

C++ exhibits a fundamental tension at the systems-architecture level: the language's design achieves its stated performance goals with extraordinary fidelity, but the accumulated tooling debt, ABI instability, and governance pace create costs that compound with organizational scale. A team of five using C++ faces a different language than a team of five hundred maintaining a multi-million-line codebase across decades. The council perspectives collectively capture the language's individual features accurately, but underweight the *organizational* and *operational* costs that dominate large-scale deployment decisions.

Three observations recur across the review. First, the package management and build system gap is not a developer-convenience problem — it is a supply chain security vulnerability and a reproducibility constraint that forces large organizations to invest in dedicated build engineering infrastructure. No other mainstream language requires this investment at this scale. Second, the C++ ABI's non-standardization is a deeper architectural constraint than most council members acknowledge: it has frozen performance-critical standard library implementations at their original designs and created a structural maintenance tax on every polyglot system that includes C++ as a component. Third, the governance timeline — a feature entering WG21 discussion in 2022 cannot realistically become a default expectation until approximately 2030–2032 — means that language design decisions today will not reflect in deployed production systems for nearly a decade. This makes C++ an unusually risky platform for new greenfield systems where the long-term architecture requires features not yet standardized.

None of this negates the language's genuine strengths in performance-critical infrastructure. But a systems architect evaluating C++ for a new long-lived system must account for these structural costs, not merely the language's runtime characteristics.

---

## Section-by-Section Review

### Section 6: Ecosystem and Tooling

**Accurate claims:**

- All five council members correctly identify the absence of an official package manager as a genuine weakness. The realist's framing is most precise: "The absence of a single authoritative registry means there is no equivalent to `cargo`'s curated package security advisories or `npm audit`" [REALIST-S6].
- The practitioner's per-engineer time cost comparison is empirically grounded: "A Rust engineer adding a dependency spends five minutes. A C++ engineer adding a dependency in a mature project with vcpkg spends between 30 minutes and several hours" [PRACTITIONER-S6]. This is consistent with my observations from engineering blog posts and CI pipeline case studies.
- The detractor's point on module adoption is well-evidenced and important: as of early 2026, GCC's module support has "pretty much stalled until very recently," and MSVC is the only compiler with mature module support [DETRACTOR-S6, MODULES-SKEPTICAL-2025].
- The practitioner correctly notes that CI pipelines for serious C++ projects typically maintain three build configurations (debug, release, sanitizer), which triples compute requirements [PRACTITIONER-S6].
- AI tooling risk is flagged by the realist and detractor: AI assistants generate pre-C++11 patterns from training data skew, introducing the vulnerabilities modern C++ was designed to prevent [REALIST-S6, DETRACTOR-S6]. This is correct and under-discussed relative to its practical impact.

**Corrections needed:**

- The apologist's framing of CMake as "effectively a portability achievement" [APOLOGIST-S6] overstates the case. CMake achieves nominal cross-platform support, but cross-platform C++ builds remain a significant engineering investment. Porting a CMakeLists.txt that works on Linux to Windows with MSVC regularly requires nontrivial modification for Windows-specific linker behavior, MSVC's distinct flag naming conventions, and the `__declspec` ABI annotations absent from GCC/Clang. The portability story is better described as "achievable with effort" than "it just works."
- The historian's claim that Chrome's full rebuild took "hours" [HISTORIAN-S6] is imprecise. The research brief cites 15–30 minutes on a developer workstation [RESEARCH-BRIEF]; the "hours" characterization applied to pre-distributed-build configurations and does not reflect modern CI infrastructure.

**Additional context from a systems architecture perspective:**

The council perspectives focus appropriately on the developer experience of tooling fragmentation, but underweight its organizational and operational dimensions at scale.

**The configuration-expert tax.** Large C++ organizations employ dedicated build engineers — individuals whose primary job is maintaining CMake configurations, vcpkg manifests, toolchain files, and CI pipeline build matrices. This is not a vanity role; it is a necessity imposed by the ecosystem's complexity. Google maintains Bazel, which itself requires significant internal infrastructure investment. Meta, Microsoft, and other large C++ shops have equivalent investments. The cost is invisible in small-team analyses but becomes a first-order concern at organizational scale. No comparable ecosystem (Rust, Go, Java) requires this level of dedicated investment for build infrastructure.

**Reproducibility and hermetic builds.** Production systems require reproducible builds: given the same source, the same binary is produced at any point in time. Achieving this in C++ requires either Bazel (with its hermetic toolchain model) or significant vcpkg/Conan configuration discipline, combined with pinned compiler versions and sysroot management. The Linux/macOS default (picking up system libraries from the environment) makes reproducibility fragile. Hermetic C++ builds are achievable but require non-trivial infrastructure — infrastructure that Rust's `cargo` and Go's module system provide by default.

**The modules adoption trough.** The detractor correctly notes that C++20 modules have been in the standard for four years without achieving practical adoption [DETRACTOR-S6]. From a systems architecture perspective, this creates an uncomfortable liminal state: teams cannot yet migrate to modules without accepting early-adopter risk, but the compilation speed problems modules address remain severe. The correct systems recommendation for any new C++ project in 2026 is to architect for future modules migration — keeping public APIs in module-friendly form — without depending on modules today. This creates architectural debt from day one.

**CI/CD integration cost.** The practitioner notes the tripling of CI compute from multiple build configurations [PRACTITIONER-S6]. In practice, large C++ projects run: debug build (developer iteration), optimized build (performance testing), AddressSanitizer build (memory error detection), UndefinedBehaviorSanitizer build (UB detection), ThreadSanitizer build (concurrency correctness), and coverage build (test coverage reporting). That is six distinct build configurations, each with separate compilation and test execution. The compute cost is significant; more importantly, the *maintenance* cost of keeping six build configurations in sync as the codebase evolves is a continuous engineering burden with no equivalent in languages that provide safety guarantees statically.

---

### Section 10: Interoperability

**Accurate claims:**

- The realist's assessment of the C ABI interoperability story is accurate: `extern "C"` is "genuine and valuable" and makes C++ a natural choice for high-performance library implementations with thin C-API wrappers [REALIST-S10].
- The practitioner correctly identifies pybind11/nanobind as the mature, widely-deployed solution for Python/C++ interoperability [PRACTITIONER-S10]. TensorFlow's and PyTorch's binding layers are well-documented production examples.
- The detractor's analysis of ABI fragility's consequence on standard library performance is correct and underappreciated: "The ABI stability commitment that was meant to enable interoperability has calcified performance-critical infrastructure" [DETRACTOR-S10]. `std::unordered_map`'s chained-bucket design and `std::string`'s small-buffer-optimization implementation are frozen at their original designs because changing them would break binary compatibility. Every major C++ organization that cares about performance has replaced these with internal alternatives (folly::F14Map, LLVM's StringRef, etc.), creating maintenance burden.
- The historian's Static Initialization Order Fiasco section is accurate and historically grounded [HISTORIAN-S10].

**Corrections needed:**

- The apologist's claim that "cross-compiler C++ FFI requires `extern "C"` interfaces" [APOLOGIST-S10] is correct but understates the structural consequence: this means C++ cannot serve as a *module* in a polyglot system in the way that, e.g., a Rust crate can. It can only serve as a *library* with a degraded C-compatible API surface. Rich C++ abstractions — classes with virtual functions, STL containers, RAII wrappers — become opaque to callers. This is not merely an inconvenience; it constrains the architectural patterns available when integrating C++ into larger systems.
- The realist's framing of cross-compilation as having "complexity" but being "mature and well-documented for common targets" [REALIST-S10] is optimistic for embedded and automotive contexts. AUTOSAR C++ profile compliance for safety-critical automotive systems requires not just cross-compilation but verified toolchain stacks with specific qualification documentation. The "well-documented" characterization fits x86/ARM Linux development but not safety-critical embedded targets, where toolchain selection is often dictated by certification requirements rather than quality.

**Additional context from a systems architecture perspective:**

**The ABI stability decision and its long-term consequences.** At CppCon 2019, the C++ committee considered an ABI break for C++23 or C++26 that would have enabled significant standard library performance improvements. The proposal was rejected. Google subsequently published analysis showing that ABI stability in the Linux ecosystem blocks performance improvements that would benefit essentially every C++ binary on the platform [ABI-BREAK-DISCUSSION-2020]. From a systems architecture perspective, this decision means that performance improvements in the standard library must be pursued through non-standard replacements — folly, abseil, LLVM's libc++, custom allocators — each of which introduces its own maintenance burden and interoperability constraints. Large organizations effectively maintain a *parallel standard library* of performance-critical components, which is a structural cost the ABI stability commitment imposes indefinitely.

**Polyglot system integration patterns.** The dominant pattern for integrating C++ into modern systems — C++ performance core, Python/TypeScript orchestration layer, thin C API at the boundary — is mature and battle-tested (TensorFlow, PyTorch, OpenCV). However, it carries ongoing costs that systems architects must budget: (1) every type that crosses the language boundary must be translated, imposing serialization overhead or binding maintenance; (2) debugging issues that span the language boundary requires expertise in both languages' debugging tools simultaneously; (3) API evolution on the C++ side may require corresponding changes to bindings on the Python side, creating release coupling. These are manageable costs, but they are costs, and they compound with codebase age and team turnover.

**Wasm/embedded deployment as a bright spot.** Emscripten's compilation of C++ to WebAssembly is one area where C++ interoperability has genuinely improved. For compute-intensive workloads (image processing, audio codecs, PDF rendering) that need browser deployment, C++ via Wasm is a practical production pattern used by Google (Docs), Adobe (Acrobat web), and others. This deployment model does not require the `extern "C"` dance — Emscripten manages the boundary — and extends C++'s operational footprint to browser environments without language rewrite.

---

### Section 11: Governance and Evolution

**Accurate claims:**

- The realist's analysis of the governance timeline is accurate: "A feature entering discussion in 2022 targets C++26 at earliest, reaches compiler implementations by 2026–2027, achieves widespread toolchain adoption by 2028–2030, and becomes the default expectation for new codebases by 2032" [REALIST-S11]. This ten-year horizon is the correct mental model for planning C++ system evolution.
- The detractor's identification of the modules adoption failure as a governance illustration is well-evidenced [DETRACTOR-S11]. Modules were first proposed to WG21 in 2012, standardized in C++20, and as of 2026 have no adoption in major C++ projects.
- The historian's backward compatibility analysis — "The billions of lines of C++ in production systems can be compiled with current compilers, receiving security patches, optimization improvements, and tooling benefits without rewriting" [HISTORIAN-S11] — correctly frames this as a genuine value, not merely a conservative instinct.
- Stroustrup's warning about feature proliferation ("C++ could crumble under the weight of these — mostly not quite fully-baked — proposals") is accurately cited by the detractor [DETRACTOR-S11, STROUSTRUP-REGISTER-2018].

**Corrections needed:**

- The apologist's framing of the ISO process as "the right process for a language used in systems where correctness is non-negotiable" [APOLOGIST-S11] conflates the *rigor* of the process with its *pace*. The argument that conservative governance prevents mistakes is defensible; the argument that a 10-year feature deployment horizon is an appropriate response to the mission-criticality of deployed systems is weaker. Mission-critical systems require *stability* from the language, which backward compatibility provides; they do not require *slowness* in feature adoption, which the current cadence imposes. The two properties are not the same.
- The practitioner's characterization of C++20 coroutine adoption — "roughly half or more of developers in these domains are not yet using C++20" — requires clarification. The JetBrains data cited [JETBRAINS-2024] shows 39% adoption in gaming and 37% in embedded for C++20 features, which means adoption is in the range of 37–39%, not a simple "roughly half." More importantly, adoption of *any* C++20 feature differs from adoption of coroutines specifically, which requires additional library support (executors) that does not arrive until C++26.

**Additional context from a systems architecture perspective:**

**The version fragmentation problem in large teams.** The backward compatibility guarantee means that C++ organizations frequently maintain codebases with heterogeneous version targets. A 10-year-old codebase may have legacy components targeting C++11, recent components targeting C++17, and new greenfield modules targeting C++23. These components must interoperate, which they do at the binary level through C ABI boundaries, but the team must maintain expertise in multiple generations of idioms simultaneously. This is a human capital cost: engineers who know modern C++23 must recognize and reason about C++11 code without introducing incompatible patterns. No tooling enforces "this translation unit must use only C++17 idioms." Code review becomes the mechanism, which is imperfect and expensive.

**Upgrade economics in large organizations.** The practical cost of a C++ version migration in a large organization is significant. Migrating from C++14 to C++17 in a 2-million-line codebase involves: (1) compiler upgrade validation (verifying no behavioral regressions from compiler changes); (2) third-party dependency updates (any dependency that used implementation-defined behavior now checked against new standard); (3) build system changes for new flag requirements; (4) linter configuration updates for new idioms; (5) team training for new features. Google, Microsoft, and Apple have dedicated infrastructure teams that manage C++ version migrations as multi-year projects. This is not a failure of those organizations — it is the expected cost of the language's backward-compatibility-first governance model applied at scale.

**The safety profiles question and deployment horizon.** Stroustrup's 2025 CACM article describes C++ Core Guidelines Profiles as the path to language-level memory safety [STROUSTRUP-CACM-2025]. Even granting that profiles can work as designed, the governance timeline gives reason for caution: profiles would need to be proposed, studied, standardized (earliest C++26, likely C++29), implemented in compilers (2028–2030 for widespread support), and adopted by large codebases (2030+). The government guidance recommending memory-safe languages for new development [CISA-MEMORY-SAFE-2025] implies a constraint that the C++ governance timeline cannot satisfy. Organizations building new systems today cannot wait until 2030+ for language-level safety guarantees; they must make architectural decisions now.

**Corporate influence and feature prioritization.** The practitioner's observation that WG21's corporate composition prioritizes large-organization features over ergonomics improvements deserves elaboration. The absence of a standard networking library — deferred from C++17 through C++23 — has concrete systems implications: C++ network services require third-party libraries (Asio, Poco, custom), each with different API conventions, deployment models, and maintenance states. This creates fragmentation not just at the language level but at the service boundary level. C++ HTTP services at different organizations may be built on fundamentally incompatible async execution models, making code reuse and developer mobility harder than necessary.

---

### Other Sections (Systems Architecture Concerns)

**Section 2: Type System — Large-Team Refactoring**

The council adequately covers the type system from a feature perspective but underweights its implications for large-scale refactoring. C++'s combination of header files, template instantiation, and lack of a module system makes refactoring across translation unit boundaries expensive. Renaming a type that appears in widely-included headers cascades compilation across the entire codebase. Moving a type between headers requires updating all includers. This is a well-understood problem (it motivated modules), but its practical impact on the cost of architectural evolution in large codebases deserves explicit mention. Languages with proper module systems (Java, Rust, Go) allow architectural refactoring at lower cost precisely because type visibility is better encapsulated.

**Section 3: Memory Model — Production Operational Characteristics**

The council focuses on memory safety from a correctness and security perspective, which is appropriate. From an operational perspective, C++'s deterministic memory management (RAII, smart pointers) is a genuine operational advantage for long-running services: predictable memory usage, no GC pauses, consistent tail-latency characteristics. For latency-sensitive services (HFT, real-time systems, game servers), the absence of GC-induced pauses is a reliability property, not merely a performance property. Services with GC-based runtimes must tune GC parameters to avoid tail-latency spikes; C++ services have no such tuning dimension. This is worth noting as a positive operational characteristic.

**Section 4: Concurrency — Production Data Race Detection**

No council member adequately addresses the operational gap: ThreadSanitizer detects data races *only in test execution*, not in production. A race that exists only on specific hardware or under specific load patterns may never appear in testing. Languages with compile-time race prevention (Rust) provide a qualitatively different operational guarantee: races that reach production are genuinely surprising. C++ races that reach production are expected — the question is whether the test harness found them first. This is a meaningful operational risk for any service with complex concurrent access patterns.

**Section 8: Developer Experience — Onboarding Cost at Scale**

The council correctly notes that C++ has high onboarding cost. At organizational scale, this becomes a persistent recruiting and retention constraint. C++ expertise is scarce relative to demand [SO-SURVEY-2024], which creates both compensation pressure (commanding $120,000–$140,000+ median [RESEARCH-BRIEF]) and organizational fragility (losing a senior C++ developer represents significant institutional knowledge loss). Organizations that choose C++ for long-lived systems must budget for this ongoing talent constraint as a structural cost, not a one-time hiring event.

---

## Implications for Language Design

The following lessons are generic — applicable to any language designer — derived from C++'s systems-scale experience:

**1. Package management and build systems are language design problems, not ecosystem afterthoughts.**
C++ demonstrates the cost of treating packaging and build as external concerns. Languages that ship without official package management and build tooling create ecosystem vacuums that are filled by competing solutions, producing fragmentation that compounds indefinitely. The window for establishing an official standard tool is narrow — it exists before the community has already committed to alternatives. Once CMake, vcpkg, and Conan each have hundreds of thousands of users, no centralized solution can displace them without a migration cost that no single actor will absorb. Language designers must treat packaging as a first-class feature with the same care applied to syntax and semantics.

**2. ABI stability versus language evolution is a zero-sum decision that must be made explicitly.**
C++'s de facto choice — compiler-specific ABI, no standardized binary interface — imposes permanent costs: standard library implementations frozen at initial designs, polyglot integration restricted to C-API boundaries, binary distribution requiring per-compiler packaging. The alternative — a stable ABI with cross-compiler guarantees — constrains language evolution. Neither choice is free, but the costs of implicit non-standardization (accumulated as technical debt rather than paid up front) are harder to audit and harder to reverse. Language designers should make this tradeoff explicitly and communicate the long-term consequences.

**3. The upgrade story is part of the language design.**
How users migrate from one version of a language to the next is not a documentation problem — it is a language design problem. C++ demonstrates the downstream costs of a backward-compatibility-first governance model: multi-dialect codebases, persistent legacy idioms, multi-year version migration projects at scale. A language designer should specify the migration path for breaking changes before making them, define a deprecation and removal timeline that balances user burden against accumulated complexity, and provide tooling (linters, codemods, compilers with warning modes) that makes migration executable rather than merely documented.

**4. Compilation speed compounds into team productivity loss at organizational scale.**
C++'s compile time problem — 15–30 minutes for a full Chrome build [RESEARCH-BRIEF] — is not a performance benchmark limitation; it is a team productivity tax that affects feedback loop speed, experimental iteration rate, and CI infrastructure cost. Language designers should treat compilation speed as a first-class design constraint from the start. Incremental compilation, the module boundary model, and separate compilation semantics are all compilation speed decisions, not implementation details. Languages that retrofit faster compilation (via modules, as C++ is attempting) face ecosystem-wide adoption problems; languages that design for compilation speed from the beginning avoid the retrofit entirely.

**5. Large-team coding standards enforcement requires language mechanisms, not just community guidelines.**
C++'s C++ Core Guidelines and the Safety Profiles proposal represent efforts to enforce safety standards through tooling rather than language guarantees. The historical pattern — the Core Guidelines have been public since 2015 with incomplete adoption — suggests that guidelines without language-level enforcement produce partial, inconsistent compliance at organizational scale. Language designers should consider which safety properties are important enough to enforce at the language level rather than the guideline level. The difference between "the compiler refuses unsafe patterns" (Rust's ownership model) and "the linter warns about unsafe patterns" (C++ Core Guidelines) is the difference between structural safety and aspirational safety.

**6. Government and regulatory pressure on security creates an external forcing function that governance processes must account for.**
NSA/CISA guidance recommending migration away from memory-unsafe languages [CISA-MEMORY-SAFE-2025] and the Android memory safety data showing Rust reducing memory vulnerabilities by approximately 78% [ANDROID-MEMSAFETY-2025] represent external pressure that C++'s governance timeline cannot respond to within normal standardization cycles. Language designers building languages for regulated industries (finance, defense, medical devices, critical infrastructure) should budget for evolving regulatory requirements and build governance mechanisms capable of responding to external safety mandates on timescales faster than a standard ISO committee. A language that cannot adapt its safety model to external regulatory pressure within five years risks mandated exclusion from regulated domains.

**7. The 10-year horizon from proposal to deployment expectation is too long for the current pace of threat evolution.**
Security threats, hardware architectures, and software distribution models change faster than C++'s governance timeline allows. A language that requires 8–10 years from identifying a class of vulnerabilities to standardizing mitigations cannot keep pace with adversaries who exploit those vulnerabilities in the interim. Language designers should build governance mechanisms that allow security-relevant features to be fast-tracked — possibly through a separate security-focused track with shorter standardization cycles — without requiring every safety enhancement to compete with performance and expressiveness features in a single annual or triennial committee vote.

---

## References

[APOLOGIST-S6] "C++ — Apologist Perspective," Section 6. research/tier1/cpp/council/apologist.md, February 2026.

[APOLOGIST-S10] "C++ — Apologist Perspective," Section 10. research/tier1/cpp/council/apologist.md, February 2026.

[APOLOGIST-S11] "C++ — Apologist Perspective," Section 11. research/tier1/cpp/council/apologist.md, February 2026.

[REALIST-S6] "C++ — Realist Perspective," Section 6. research/tier1/cpp/council/realist.md, February 2026.

[REALIST-S10] "C++ — Realist Perspective," Section 10. research/tier1/cpp/council/realist.md, February 2026.

[REALIST-S11] "C++ — Realist Perspective," Section 11. research/tier1/cpp/council/realist.md, February 2026.

[DETRACTOR-S6] "C++ — Detractor Perspective," Section 6. research/tier1/cpp/council/detractor.md, February 2026.

[DETRACTOR-S10] "C++ — Detractor Perspective," Section 10. research/tier1/cpp/council/detractor.md, February 2026.

[DETRACTOR-S11] "C++ — Detractor Perspective," Section 11. research/tier1/cpp/council/detractor.md, February 2026.

[PRACTITIONER-S6] "C++ — Practitioner Perspective," Section 6. research/tier1/cpp/council/practitioner.md, February 2026.

[PRACTITIONER-S10] "C++ — Practitioner Perspective," Section 10. research/tier1/cpp/council/practitioner.md, February 2026.

[HISTORIAN-S6] "C++ — Historian Perspective," Section 6. research/tier1/cpp/council/historian.md, February 2026.

[HISTORIAN-S10] "C++ — Historian Perspective," Section 10. research/tier1/cpp/council/historian.md, February 2026.

[HISTORIAN-S11] "C++ — Historian Perspective," Section 11. research/tier1/cpp/council/historian.md, February 2026.

[RESEARCH-BRIEF] "C++ — Research Brief." research/tier1/cpp/research-brief.md, February 2026.

[STROUSTRUP-CACM-2025] Stroustrup, B. "21st Century C++." *Communications of the ACM*, February 2025. https://cacm.acm.org/blogcacm/21st-century-c/

[STROUSTRUP-REGISTER-2018] Stroustrup, B., quoted in "C++ creator: My language now 'too complicated'." *The Register*, January 2018. https://www.theregister.com/2018/01/06/bjarne_stroustrup_c_plus_plus/

[MSRC-2019] Miller, M. "A Proactive Approach to More Secure Code." Microsoft Security Response Center, 2019. https://www.microsoft.com/en-us/msrc/blog/2019/07/a-proactive-approach-to-more-secure-code/

[CISA-MEMORY-SAFE-2025] CISA/NSA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://www.cisa.gov/news-events/alerts/2025/06/24/new-guidance-released-reducing-memory-related-vulnerabilities

[ANDROID-MEMSAFETY-2025] Google Security Blog. "Eliminating Memory Safety Vulnerabilities at the Source." February 2025. https://security.googleblog.com/2025/02/eliminating-memory-safety-vulnerabilities-Android.html

[ABI-BREAK-DISCUSSION-2020] Kuhlins, V. et al. "To ABI or not to ABI, that is the question." WG21 Paper P1863R1 and related discussion at CppCon 2019/2020. https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2019/p1863r1.html

[MODULES-SKEPTICAL-2025] Corentin, J. "C++20 Modules Are Not Ready." Developer experience observations aggregated from GCC module tracker and Clang module bug reports, 2024–2025.

[CMAKE-MODULES-2024] "CMake 3.28 Release Notes: C++20 Module Support." https://cmake.org/cmake/help/latest/release/3.28.html

[WG21-SITE] "ISO/IEC JTC1/SC22/WG21 — The C++ Standards Committee." https://www.open-std.org/jtc1/sc22/wg21/

[JETBRAINS-2024] JetBrains. "The State of Developer Ecosystem 2024." https://www.jetbrains.com/lp/devecosystem-2024/

[SO-SURVEY-2024] "Stack Overflow Developer Survey 2024." https://survey.stackoverflow.co/2024/

[MODERNCPP-DEVOPS-2024] "Modern C++ DevOps Survey 2024." Cited in research brief and multiple council documents.

[BENCHMARKS-PILOT] "Performance Benchmark Reference: Pilot Languages." evidence/benchmarks/pilot-languages.md, February 2026.
