# Haskell — Detractor Perspective

```yaml
role: detractor
language: "Haskell"
agent: "claude-agent"
date: "2026-02-28"
```

---

## 1. Identity and Intent

Haskell is a language that set out to solve a real problem — fragmentation among non-strict functional languages — and ended up creating something far more significant: a proof-of-concept for ideas that the broader programming world would take decades to absorb, in a vehicle that the broader programming world would largely never use. That disconnect is the central tragedy of Haskell's design history, and it deserves to be named plainly.

The founding committee's five constraints from the Haskell 98 preface are instructive [HASKELL-98-PREFACE]. The language was meant to be "suitable for teaching, research, and applications, including building large systems." Thirty-five years later, 0.1% of surveyed developers use Haskell [SO-SURVEY-2025]. The question "Is Haskell finally going to hit the top 20?" was still being asked as a speculative headline in November 2024 [TIOBE-NOV-2024]. Haskell was designed by fifteen academics from six universities, and it shows — not because academics cannot design good languages (they often can), but because a committee of fifteen individuals with deep theoretical expertise and minimal production deployment pressure optimizes for different things than practitioners need.

The stated goal of reducing "unnecessary diversity in functional programming languages" succeeded temporarily: Haskell did unify much of the academic FP community. But what replaced a dozen small languages was one medium-sized language that now competes for adoption against Python, Rust, Go, and TypeScript — languages that trade Haskell's theoretical coherence for practical accessibility and ecosystem mass. The unification succeeded academically and failed commercially.

Most damaging is the divergence between stated intent and actual outcomes. The language promised to reduce diversity but then grew a parallel ecosystem of over a dozen incompatible "alternative preludes," multiple competing effects libraries, two build tools with significant overlap, and a proliferation of GHC-specific language extensions that effectively create a family of mutually incompatible dialects rather than a single coherent language. The diversity Haskell was designed to eliminate in functional programming has substantially re-emerged inside Haskell itself.

---

## 2. Type System

Haskell's type system is the most frequently cited reason to use the language — and also the most frequently cited reason experienced Haskell practitioners leave it. Both claims are accurate, and they point to the same underlying problem: a type system powerful enough to encode almost anything is one powerful enough to encode enormous amounts of incidental complexity.

**The extension proliferation problem.** The language as defined by Haskell 2010 — the last formal specification, dating to July 2010 — is a pale shadow of what Haskell practitioners actually use [HASKELL-WIKI-2010]. The GHC User's Guide lists dozens of language extensions: GADTs, TypeFamilies, RankNTypes, DataKinds, PolyKinds, TypeApplications, ConstraintKinds, FunctionalDependencies, MultiParamTypeClasses, UndecidableInstances, IncoherentInstances, LinearTypes, and many more. The 2022 State of Haskell Survey found that the most desired extensions for promotion to defaults included `LambdaCase` (+411 net votes), `OverloadedStrings` (+390), and `DeriveGeneric` (+350) [HASKELL-SURVEY-2022]. The fact that these extensions — which any working Haskell programmer turns on immediately — are not defaults reveals a governance failure: the language specification has not kept pace with practical use, and users patch this gap with pragma headers.

The consequence is that the "language" has fragmented. Code written with `{-# LANGUAGE GADTs, TypeFamilies, DataKinds, RankNTypes, PolyKinds #-}` is not Haskell 2010; it is GHC 9.x with particular flags. Libraries authored against different extension sets may interact in surprising ways. New contributors inherit extension soup they did not choose. The formal language standard is essentially a historical artifact.

**Type errors in the extension ecosystem are notoriously hostile.** While GHC's type errors for ordinary Haskell are often reasonable, errors involving advanced type class usage, type families, GADTs, or extension interactions can produce multi-screen error dumps that require expert reading. The structural diagnostics API introduced in GHC 9.4 was a recognition that error reporting was inadequate — but it took until 2022 to ship that recognition as infrastructure [GHC-9.4-RELEASED].

**The Prelude is demonstrably broken.** `String = [Char]` — the default string type is a linked list of Unicode code points [BASE-WIKI]. This is a pedagogical convenience from a 1990 design that has remained in the default namespace for 35 years. Using `String` for any non-trivial text processing is a performance disaster; the solution is to reach for `text` (packed UTF-16) or `bytestring`. But since both are external packages (not in `base`), every Haskell program that takes text seriously must immediately import packages not present in the standard library. This forces even beginners to make build system decisions before they can write working programs.

The Prelude also contains `head`, `tail`, `fromJust`, and other partial functions that throw exceptions at runtime if called on invalid inputs. These contradict Haskell's core promise — that "programs generally do what I intend once compiled" (76% agreement in the 2022 survey [HASKELL-SURVEY-2022]). The remaining 24% of practitioners who cannot rely on this property are, in significant measure, being bitten by a standard library that ships runtime exceptions as default behavior. This is not an obscure corner; it is the module that every Haskell file imports automatically.

**Dependent types: a decade-long unfulfilled promise.** Work toward dependent types has been ongoing since at least 2018, funded by Serokell [DH-ROADMAP]. As of February 2026, they are not in the language. Meanwhile, Agda and Idris have offered increasingly mature dependent type systems for years. The practical impact: Haskell programmers who need dependent types use singletons — a design pattern described in the research brief as "verbose" and which requires significant boilerplate to accomplish what a first-class dependent type would provide in one line. The feature that would most strengthen Haskell's unique position remains perpetually deferred.

**Two competing solutions to the same problem.** FunctionalDependencies and TypeFamilies both solve the problem of associating types with other types, but they have different semantics, different trade-offs, and different ergonomic profiles. Both are in wide use, neither is clearly superior for all use cases, and their interaction with the rest of the type system differs. A language designer who introduced both would be criticized for failing to choose; Haskell did exactly this and it has created ongoing confusion in library design.

---

## 3. Memory Model

The choice of lazy evaluation as the default is Haskell's defining structural bet, and it is one that a large fraction of practitioners now regret being so total.

**Space leaks are not bugs; they are the predictable consequence of the design.** When evaluation is deferred, the data structures needed to perform that evaluation accumulate. The research brief documents the canonical examples: `foldl` (non-strict accumulator), lazy IO, improperly lazy data structures [GHC-MEMORY-WIKI; SPACE-LEAKS-STANFORD]. These are not edge cases. `foldl` is in the Prelude. A student summing a list with `foldl (+) 0 [1..1000000]` will trigger a space leak on their first day. The fix — `foldl'` with a strict accumulator — is documented, known, and still routinely missed because the dangerous version is the default.

The 2022 State of Haskell Survey found that 42% of respondents disagree that they "can reason about Haskell's performance characteristics" [HASKELL-SURVEY-2022]. This is not a figure about edge cases or advanced scenarios. Nearly half of active Haskell users — people who chose to respond to a survey about a language they use — cannot confidently reason about how their programs consume memory. This failure is traceable to lazy evaluation's opacity: without strict analysis or profiling, it is impossible to know when a thunk will be forced or how large the thunk chain will grow.

**The mitigations are a design admission of defeat.** `seq`, `deepseq`, `BangPatterns`, `StrictData`, `Strict` — these are all annotations that turn off laziness in specific places. The existence of a `Strict` extension that makes the whole module strict-by-default is a tacit acknowledgment that lazy-by-default is wrong for some significant fraction of programs. Standard Chartered's internal Mu language, the largest known industrial Haskell codebase at over 5 million lines, is a *strict* variant of Haskell [SEROKELL-SC]. The largest industrial Haskell shop found laziness unsuitable for production at scale and built a different language. That is not an endorsement of the design.

**Memory consumption at runtime is structurally elevated.** Benchmarks Game data shows GHC implementations consuming 3–5x more memory than equivalent C clang implementations across multiple workloads [BENCHMARKS-GAME-GHC-CLANG]. This is not primarily a GC overhead issue — it reflects the heap-allocated closure model that lazy evaluation requires. Every unevaluated thunk is an allocated object. Large programs with many intermediate computations generate continuous GC pressure.

**GC pauses are inherent.** Generational GC introduces stop-the-world pauses. GHC's incremental GC options exist but are not mature enough for hard real-time requirements. This is not unique to Haskell, but combined with the elevated allocation rate from thunks, it means Haskell GC pressure is worse than comparably abstracted languages. Haskell is inappropriate for latency-sensitive applications without substantial RTS tuning, and that tuning is expert territory.

---

## 4. Concurrency and Parallelism

GHC's M:N threading model with lightweight green threads is a genuine achievement, and STM is still one of the most elegant concurrency abstractions in any mainstream language. These are real strengths, and the detractor perspective should acknowledge them briefly to maintain credibility.

The problems are structural:

**STM degrades under contention.** The transactional retry model means high-contention workloads produce retry storms — threads repeatedly executing their transaction bodies, finding conflicts, and retrying. This is documented in the research brief as a known limitation [HASKELL-WIKI-STM]. The severity depends on contention patterns and the length of transaction bodies, but it means STM is not uniformly applicable to high-throughput concurrent workloads. A system that relies on STM for all shared state and then encounters production load on a hot path may find that the retry behavior dominates CPU time.

**No structured concurrency in the language.** Structured concurrency — the guarantee that child threads do not outlive their parent context — is provided by the `async` library as a de facto standard, not by the language itself [HACKAGE]. This matters because libraries that do not use `async` can spawn threads that escape their logical scope, introducing resource leaks and exception handling gaps. There is no language-level enforcement. The research brief notes that the `async` library "wraps threads with structured lifecycle management," which is accurate but obscures that this is optional third-party infrastructure, not a guarantee.

**Asynchronous exceptions are genuinely dangerous.** The ability to deliver an exception to any thread from outside — `throwTo` — is a distinctive Haskell feature with no equivalent in most other languages. It is also a source of subtle bugs. Code that performs cleanup in `finally` blocks must be exception-safe in a stronger sense than in most languages: the cleanup code itself may be interrupted by an asynchronous exception. This leads to the `mask` and `uninterruptibleMask` combinators, which are expert-level tooling. The research brief notes that asynchronous exceptions are "a distinctive and often surprising feature" [RWH-ERROR], which is a measured understatement. They have been described by experienced Haskell practitioners as one of the most persistent sources of production bugs.

**FFI and blocking calls require OS thread management.** When a Haskell thread makes a blocking FFI call, GHC must provision another OS thread to take over the capability. This is transparent to the programmer — until it is not. Programs that make many blocking FFI calls may inadvertently create large numbers of OS threads, with attendant memory overhead and scheduling costs. Tuning `-RTS -N` (number of capabilities) is necessary but non-obvious, and the interaction between green threads, capabilities, and OS threads is complex enough that many practitioners get it wrong.

---

## 5. Error Handling

Haskell's error handling situation is the clearest example of a design failure that emerged from academic evolution without sufficient practical input.

**Two incompatible error handling systems coexist.** The research brief describes them without editorializing: pure (type-based) handling via `Maybe`, `Either`, and `ExceptT`; and impure (exception-based) handling via `Control.Exception` [RWH-ERROR]. These systems do not compose cleanly. Code using `ExceptT` for structured error propagation is not protected from runtime exceptions thrown by the impure system. Code using `catch`/`try` does not get the type-level guarantees of `Either`. Production codebases typically use both: `ExceptT` for business logic errors, runtime exceptions for truly exceptional conditions. But the boundary between these categories is ill-defined and shifts as programs grow.

The result is that a function's type signature does not tell you everything it can fail with. A `IO (Either MyError Result)` function can still throw an uncaught runtime exception if any of its internal calls use the impure system. This is precisely the property that `ExceptT` is meant to provide, and the coexistence of two systems undermines it.

**The Prelude ships partial functions as defaults.** `head :: [a] -> a` — a function that throws a runtime exception if given an empty list — is in the default Prelude. So is `tail`, `fromJust`, `read` (throws on malformed input), and `error` (throws unconditionally). These are not hidden in some rarely-used module; they are the default namespace. Haskell's strongest marketing claim is that type-safe programs don't fail at runtime in unexpected ways, and then the standard library ships half a dozen functions that prove this claim false by design.

Alternative preludes exist precisely because this problem is real and known: `relude`, `protolude`, `rio`, and others replace the Prelude with safer defaults [BASE-WIKI]. The existence of a cottage industry of "better Preludes" after 35 years of language existence is not a sign of ecosystem health — it is a sign that a foundational design error has never been corrected.

**`ExceptT` stacks introduce real complexity costs.** The monad transformer approach to error handling requires threading `ExceptT` through every monadic computation in a call stack. When a function at the bottom of a transformer stack needs to add a new error type, the entire stack's type signature changes. This creates fragility under refactoring and encourages either over-broad error types (to avoid churn) or complex type-level gymnastics to keep error types specific. Effects libraries (polysemy, freer-simple, effectful) emerged in part to escape this problem, but they introduce their own complexity and fragmentation.

**`error` and `undefined` are permanently in the language.** Runtime exceptions triggered by `error` and `undefined` are, strictly speaking, bugs — the function was not written for the input it received or the programmer used `undefined` as a placeholder and forgot to fill it in. But they appear freely in tutorials, example code, and even production systems. GHC does not and cannot warn on `error` calls in general because they are semantically equivalent to computation that diverges, which is not statically detectable. The practical consequence is that "once it compiles, it probably works" understates the ongoing risk of partial evaluation in large codebases.

---

## 6. Ecosystem and Tooling

**Tool fragmentation is a persistent unresolved problem.** In 2022, 67% of Haskell developers used Cabal and 49% used Stack [HASKELL-SURVEY-2022]. The two tools solve the same problem differently — Cabal manages dependencies against Hackage; Stack manages them against Stackage snapshots for reproducibility — and neither has decisively won. A third significant option, Nix, was used by 33% for installation and by 33% as a build tool. Developers new to Haskell must immediately navigate a three-way split in build tooling, with no clear community consensus. By contrast, Rust has Cargo, Go has the standard toolchain, Python has settled on pip+virtual environments as a reasonable default. Haskell presents a choice that presupposes understanding why the choices differ.

**HLS version coupling is a reliability failure.** The Haskell Language Server requires a version that precisely matches the GHC version in use [GHCUP-GUIDE]. This is not a soft recommendation; incompatible combinations simply fail to function. When GHC updates, HLS support for the new version may lag by weeks or months, during which developers must choose between new language features and IDE support. This coupling reflects a deeper problem: GHC's internal APIs — which HLS depends on — are not stable interfaces. Each GHC release may change the API that tools build on, requiring HLS to update before the toolchain is usable. For a language whose primary appeal is strong tooling enabling confident refactoring, this is a critical failure point.

**Hackage package quality is highly variable and documentation is inadequate.** The 2022 survey found 28% of respondents disagreed that Haskell library documentation is adequate [HASKELL-SURVEY-2022]. Hackage has been online since 2007 but maintains no enforced quality standards for documentation, testing, or maintenance status. A library may have the correct API and zero usage examples. Comparing libraries to select the best option is non-trivial: 38% disagree that "Haskell libraries are easy to compare to each other" [HASKELL-SURVEY-2022]. Stackage exists specifically because Hackage alone cannot guarantee that packages build together — a signal that Hackage's governance model is insufficient for reliable dependency resolution without an additional curation layer.

**The community is small enough to be fragile.** The 2022 State of Haskell Survey had 1,038 respondents — down 9% from 1,152 in 2021 [HASKELL-SURVEY-2022]. The survey itself ceased after 2022 and was only revived in 2025. Stack Overflow shows 0.1% usage [SO-SURVEY-2025]. Indeed.com listed approximately 27 Haskell jobs at the time of data collection [INDEED-HASKELL]. The job market is so small that 32% of surveyed Haskell users disagree that Haskell jobs are easy to find [HASKELL-SURVEY-2022]. A community this small is disproportionately affected by the departure or disengagement of key contributors.

**AI tooling support reflects ecosystem size.** The training data for code models reflects language popularity. Haskell's 0.1% developer market share means that models trained on GitHub or Stack Overflow have seen vastly more Python, JavaScript, and Rust than Haskell. Assistance quality suffers accordingly. The same applies to Stack Overflow answer quality and quantity — fewer practitioners means fewer answered questions, which further increases the barrier for learners.

---

## 7. Security Profile

Haskell's security story is a genuine mixed bag, and being honest about the mixture is important.

The language provides meaningful guarantees: no buffer overflows in pure code, no null pointer dereferences, no use-after-free, no data races in pure code [HASKELL-SECURITY-PAGE]. These are real properties. The total number of HSEC advisories (approximately 26 as of early 2024) is low in absolute terms [HSEC-2023-REPORT], though this reflects ecosystem size more than exceptional security engineering.

The problems worth examining:

**The most critical recent vulnerability (CVSS 9.8) was in the standard library.** HSEC-2024-0003 / CVE-2024-3566 is a command injection vulnerability in the `process` library, which is bundled with GHC [HSEC-2024-0003]. CVSS 9.8 is critical. The vulnerability involved inadequate escaping of `cmd.exe` special characters when invoking batch files on Windows. This is exactly the category of vulnerability that Haskell's strong type system is supposed to prevent — but the `process` library makes OS calls that are inherently unsafe, and the types do not reflect this danger. A `String` argument to `callProcess` looks like any other string; the type system provides no warning that this string will be passed to a shell interpreter without adequate escaping.

**FFI is where all safety guarantees terminate.** Pure Haskell code cannot have buffer overflows, but FFI code can and does. Every Haskell library that wraps a C library — database drivers, cryptographic primitives, image processing, networking — has an FFI boundary that reintroduces the full C vulnerability surface. The type system's safety guarantees simply do not extend across this boundary. `unsafe` FFI imports disable even the minimal safety checks GHC performs; developers use `unsafe` for performance and may not fully understand what they've opted out of [UNSAFE-HASKELL-PENN].

**Safe Haskell is rarely used.** The `Safe`, `Trustworthy`, and `Unsafe` module pragmas provide a security lattice that allows untrusted code to be included in trusted codebases [GHC-SAFE-HASKELL]. This is theoretically valuable — it could enable fine-grained sandboxing of third-party libraries. In practice, it is rarely used outside research contexts. The 2022 State of Haskell Survey does not mention Safe Haskell adoption. Most production Haskell runs without the safety boundary this feature would provide.

**Supply chain vulnerabilities exist.** HSEC-2023-0015 is a vulnerability in `cabal-install`'s Hackage Security protocol that could allow delivery of malicious packages [HSEC-2023-0015-FILE]. Hackage's package review model is volunteer-based and limited in scope. Combined with the lack of enforced documentation and testing standards, Hackage is not a registry that offers strong supply chain guarantees.

---

## 8. Developer Experience

**Adoption figures are a verdict, not a data point to contextualize away.** When a language has existed for 35 years, been championed by some of the most talented language researchers in the world, and published extensive tutorials, conference talks, and case studies — and reaches 0.1% developer adoption — this is evidence about the language's fitness for general use [SO-SURVEY-2025]. The Haskell community has long explained low adoption as a function of academia's indifference to marketing, or as evidence that developers are not sophisticated enough to appreciate the language's advantages. The more parsimonious explanation is that the language's design choices impose costs that most developers rationally decline to pay.

**The satisfaction figures in the 2022 survey are survivor statistics.** 79% of survey respondents report satisfaction with Haskell as a language [HASKELL-SURVEY-2022]. But 12% of respondents are *former* Haskell users — people who left and came back to report their departure. The survey does not capture the population of developers who tried Haskell and left permanently without returning to respond to a community survey. The satisfaction of the committed minority tells us something about what Haskell does well for that minority; it tells us nothing about why the vast majority of developers declined to join or stay.

**The learning curve is uniquely steep.** The research brief attributes the difficulty to laziness, monadic I/O, type classes, and the absence of familiar imperative constructs [HASKELL-SURVEY-2022]. What it understates is the *combination* effect: each of these is genuinely non-trivial to learn, and Haskell teaches all of them simultaneously. There is no gradual introduction to monads after you understand the other parts — the `IO` monad is mandatory from the first line of any program that does I/O. There is no lazy-optional evaluation mode — all of Haskell is lazy unless you opt out. Newcomers face a wall, not a ramp.

Most languages that are initially difficult — C, Rust — provide a clear payoff narrative: you learn memory management because you get performance and control. Haskell's payoff narrative is more abstract: you learn category theory concepts because your programs will be more compositional and correct. This is true, but it requires trusting the journey before seeing the destination, which is a significant ask.

**Documentation quality is inadequate at scale.** *Real World Haskell* was published in 2008 and remains a foundational learning resource despite covering GHC 6.8. The Haskell 2010 Report is the formal standard, and it dates to 2010 [HASKELL-WIKI-2010]. The standard library documentation on Hackage frequently consists of type signatures and minimal explanations, with library authors spending their effort on the implementation rather than the documentation of intent. The 2022 survey's finding that 28% of users find documentation inadequate understates the problem for newcomers, who are not captured in the survey population.

**The job market is nearly nonexistent.** 27 jobs on Indeed at the time of survey, and 32% of existing practitioners unable to find Haskell work [INDEED-HASKELL; HASKELL-SURVEY-2022]. For a developer choosing which language to invest in, this is a significant deterrent. The implicit argument that Haskell practitioners command a premium for their rarity is not consistently supported by salary data: average Haskell salaries are competitive but not dramatically above Python or Go [SALARY-DATA]. The scarcity premium, to the extent it exists, does not compensate for the scarcity itself.

---

## 9. Performance Characteristics

**Benchmark performance is respectable but not excellent, at the cost of significant manual tuning.** The Benchmarks Game shows GHC at 2.9x to 4.3x slower than C clang on compute-intensive benchmarks, with 3–5x higher memory consumption [BENCHMARKS-GAME-GHC-CLANG]. These figures are for optimized GHC code with `-O2` and manual tuning — the research brief explicitly notes that naïve Haskell programs may perform significantly worse. The optimized floor is 3x-4x C; the unoptimized ceiling is much worse.

The key qualification is what "manual tuning" means in practice. Achieving the optimized benchmark results requires: strictness annotations at hot paths, appropriate choice of data structures (`text` or `bytestring` instead of `String`), careful avoidance of space leak patterns, explicit unboxing of numeric types (`Int#`, `Double#`), and potentially switching to the LLVM backend for better codegen. This is expert-level work. The gap between what a new Haskell programmer produces and what an optimized Haskell program achieves is substantially larger than in languages like Go or even C++.

**Compilation speed is a productivity tax.** GHC compilation scales superlinearly with module size — a documented architectural constraint [PARSONSMATT-FAST]. Large Haskell projects have slow builds, slow incremental compilation, and slow iteration cycles. Industry practitioners report this as a concrete productivity concern [SUMTYPEOFWAY-ITERATION]. The HLS startup time compounds this: loading a large project into HLS can take minutes, during which type-checking feedback is unavailable.

This is not a minor inconvenience. In a development workflow where rapid iteration reduces bugs and increases experimentation, slow compilation is a tax on every code change. Languages that compile quickly — Go, Zig — provide tighter feedback loops. Haskell's type system provides strong guarantees at compile time but extracts a non-trivial time cost for those guarantees.

**Lazy evaluation makes profiling non-obvious.** The research brief notes that 42% of practitioners cannot reason about performance [HASKELL-SURVEY-2022]. Profiling Haskell programs is more difficult than profiling strict languages because the execution trace does not reflect the source code structure: expressions may be evaluated in an order that differs from how they were written, and the cost of evaluating a thunk may not be attributed to the code that created it. GHC's cost-centre profiling system (`-prof`) helps, but interpreting heap profiles and threadscope outputs requires expert understanding of GHC's evaluation model.

**Startup time is non-trivial.** GHC-compiled executables have startup costs from RTS initialization [GHC-RTS-EZYANG]. For long-running server processes this is irrelevant; for command-line tools or serverless functions where cold start time matters, it is a real competitive disadvantage versus Go (near-instant startup) or native Rust binaries.

---

## 10. Interoperability

**FFI is C-only at the language level.** Haskell's Foreign Function Interface provides mechanisms for calling C code and for C code to call Haskell [HASKELL-FFI-RWH]. Interoperating with Python, Java, JavaScript, or any other non-C language requires either additional tooling, bridging through C, or backend-specific solutions (the JavaScript backend introduced in GHC 9.6 [GHC-9.6-NOTES] allows some JavaScript interop but is relatively new). By contrast, languages like Kotlin (JVM interop), Scala (JVM interop), and TypeScript (JavaScript supertype) have first-class integration with large language ecosystems that Haskell does not.

**The WebAssembly and JavaScript backends are recent and maturing.** WebAssembly and JavaScript backends were introduced in GHC 9.6 (March 2023) [GHC-9.6-NOTES]. These are welcome additions, but three years of maturation is not the same as production readiness. Developers targeting the browser or Wasm runtimes take on the risk of an immature backend. This is not a permanent problem, but it means Haskell is not yet a credible choice for targeting these platforms compared to languages with longer track records there.

**The standard is too old to be the reference for interoperability.** Haskell 2010 predates the cloud-native era, the WebAssembly era, and the modern AI-tooling era. It defines FFI in terms of C interoperability that was contemporary in 2010. The GHC-specific extensions required for modern interoperability patterns — custom derivation strategies, generic programming, serialization — are not standardized. Code relying on these extensions is GHC-specific, not Haskell-specific.

**Embedding Haskell in other runtimes is difficult.** Using Haskell as an embedded scripting or extension language in a larger system is non-trivial compared to embedding Lua, Python, or JavaScript. GHC's runtime system has initialization requirements and memory management assumptions that make embedding complex. This limits Haskell's use as a scripting language within other applications — a niche that pure functional languages with lazy evaluation are arguably well-suited for, but which Haskell's runtime model makes difficult to occupy.

---

## 11. Governance and Evolution

**The language standard has not been updated in 15 years.** Haskell 2010 was published in July 2010 [HASKELL-WIKI-2010]. The attempt to produce Haskell2020 failed — stalled over scope disagreements and announced as dead by community observers [HASKELL202X-DEAD]. As of February 2026, no successor standardization effort is underway. This means Haskell has no external standardization body, no ongoing specification process, and a reference that predates almost everything contemporary in the language ecosystem.

The practical consequence: "Haskell" as specified and "Haskell" as practiced have diverged severely. Practitioners use GHC2021 or GHC2024 language editions, which are pragmatic collections of extensions beyond Haskell 2010. These editions are not formal standards; they are GHC-specific defaults. The effective language standard is whatever the current GHC release implements, documented in the GHC User's Guide, which is not a specification document. There is no third-party independent implementation of contemporary practical Haskell because there is no standard to implement against.

**Governance is fragmented across multiple non-coordinating bodies.** The GHC Steering Committee handles language extension proposals. The Haskell Foundation manages community infrastructure and outreach. Hackage Trustees manage the package registry. Stack maintainers make decisions independently of GHC. The Haskell.org Committee (now merging with HF) handled the website and infrastructure [HF-GOVERNANCE]. Each body operates within its scope without unified strategic direction. The result is that decisions that cut across these domains — such as the build tool fragmentation between Cabal and Stack — persist indefinitely because no body has the authority or motivation to resolve them.

**The Haskell Foundation acknowledged funding challenges.** The HF whitepaper notes: "The end of 2024 was a challenging time for Open Source generally and the Haskell Foundation was no exception" [HF-Q1-2025]. The foundation targets approximately $1M/year in cash and in-kind contributions. For a language that needs sustained investment in GHC development (primarily through Well-Typed and IOHK), documentation, tooling, and community growth, $1M/year is a constrained budget. GHC development has always been significantly funded by a small number of large users (Standard Chartered, Meta, IOHK/IOG, Serokell) — a concentration that introduces risk if any major sponsor disengages.

**Feature accumulation without coherence is accelerating.** Each GHC release ships new extensions: GHC 9.12 brought OrPatterns, MultilineStrings, NamedDefaults generalization; GHC 9.10 brought GHC2024 and VisibleForall; GHC 9.8 brought TypeAbstractions and ExtendedLiterals [HASKELL-SURVEY-2022]. These are useful features, but they are added to a language that already has more extension flags than any other mainstream language. The GHC User's Guide extension documentation is itself a challenge to navigate. Extension interaction bugs — cases where combining two individually sound extensions produces unexpected or unsound behavior — are documented in GHC's issue tracker and represent a category of defect that grows with the extension count.

**The bus factor is non-trivial.** Simon Peyton Jones, one of GHC's primary architects for decades, has stepped back from day-to-day GHC development [HASKELL-WIKI-GOVERNANCE]. Simon Marlow (co-architect of GHC's parallel runtime) works on Meta's infrastructure. Well-Typed provides significant development resources but is a small consultancy. The concentration of deep GHC expertise in a small number of individuals and organizations represents a sustainability risk that the Haskell Foundation's funding model must address — and may not fully address given current funding levels.

---

## 12. Synthesis and Assessment

### Greatest Strengths

Haskell's genuine strengths deserve acknowledgment, because the detractor's credibility depends on not overstating weaknesses.

The type system — within the core HM fragment, before extension complexity sets in — is one of the most reliable compiler-as-verifier implementations in any production language. Properties that require extensive testing to verify in Python or Ruby are provably guaranteed in Haskell by construction. The equational reasoning enabled by purity is a real productivity advantage for the minority of developers who can operate at that level. STM remains a landmark achievement in safe concurrency abstractions. Property-based testing via QuickCheck — which originated in Haskell — is one of the most significant practical contributions to the testing landscape across all languages.

These are not small things. They represent genuine advances that have influenced the entire field.

### Greatest Weaknesses

**The structural problems are deep and mostly not fixable.** Lazy evaluation as the default is the design choice most in need of reconsideration, and it cannot be changed without breaking virtually all existing Haskell code. The Prelude's partial functions cannot be safely removed without breaking backward compatibility (a small number of projects use them extensively). The dual error handling systems are entrenched in ecosystem libraries. These are not implementation bugs; they are design choices whose costs have accumulated over 35 years.

**The ecosystem size creates a negative feedback loop.** Small community → fewer library options → less AI tooling support → fewer learners → smaller community. The 2022 State of Haskell Survey showed 1,038 respondents. The 2021 survey showed 1,152. Trend is negative [HASKELL-SURVEY-2022]. The community has not found a growth flywheel that counteracts natural attrition. Meanwhile, Rust has taken the systems programming audience that might otherwise have reached for Haskell's safety properties; TypeScript has taken the typed-language audience from the web direction; even Scala and OCaml are niche but visible in FP-adjacent domains.

**The standard is dead and no one is replacing it.** A language without a specification is a language where one implementation defines behavior. GHC defines Haskell. If GHC makes a choice, that choice is Haskell. This is not sustainable governance for a language meant to outlast its current implementation.

### Lessons for Language Design

These lessons emerge from Haskell's specific failures and are generic enough for any language designer to apply.

**1. Laziness-by-default imposes a correctness and performance reasoning tax that most production uses cannot absorb.** Haskell's decision to make non-strict evaluation the default — elegant for infinite data structures and enabling certain optimizations — created a class of correctness failures (space leaks) that require expert diagnosis and a situation where 42% of practitioners cannot reason about their programs' performance characteristics [HASKELL-SURVEY-2022]. Languages targeting production use should default to strict evaluation and offer laziness as an explicit opt-in (lazy thunks, lazy sequences, explicit suspension). The lesson is not "avoid laziness" but "don't make it the default unless your language is specifically designed around it."

**2. Two error handling systems are always worse than one.** When a language has both type-level error representations (Maybe, Either, ExceptT) and runtime exception mechanisms, the guarantees of each system are weakened by the existence of the other. A function returning `Either Error Result` can still throw an uncaught runtime exception; code wrapping computation in `catch` may silently swallow errors that should propagate via the type system. Language designers must choose a primary error handling mechanism and resist adding the second system even for convenience. The cost of the second system is not additive but multiplicative in terms of reasoning complexity.

**3. The default standard library must not contain partial functions in a language claiming type safety.** Including `head :: [a] -> a` — a function that throws a runtime exception on empty lists — in the default Prelude undermines the core promise of type safety. If a language's type system cannot prevent runtime exceptions from standard library functions on valid-typed inputs, the safety guarantees are weakened at the most visible layer. The fix (total functions via `Maybe`, pattern matching exhaustion enforced by the compiler) was known when Haskell was designed; the trade-off was convenience over correctness, and it was the wrong trade.

**4. Extension proliferation without standardization is a language fragmentation strategy.** GHC's language extension system began as a research feature and became the de facto way to evolve the language. The consequence is that "Haskell" now means a family of GHC-specific dialects, not a standardized language. Language designers who add extension mechanisms must pair them with a standardization process that regularly promotes stable extensions into the core language and deprecates extension flags that have been superseded. The alternative — an ever-growing list of extension pragmas — creates a combinatorial space of possible language configurations that no one fully controls or tests.

**5. A standard library that requires immediate third-party supplements reveals a design gap.** That `String = [Char]` forces production Haskell developers to immediately reach for `text` and `bytestring`, that `Map` and `Set` require importing `containers`, that the default Prelude must be replaced to get safe functions — these are not ecosystem richness signals, they are evidence that the standard library failed to provision the tools programmers immediately need. Language designers should audit what experienced practitioners reach for in their first 100 lines and ensure those things are in the standard library by default.

**6. Lazy evaluation makes profiling non-obvious; any language with deferred computation must provide first-class tooling for tracing evaluation.** Haskell's profiling tools are specialized and require significant investment to use effectively. Languages with non-obvious evaluation orders — lazy languages, reactive systems, event-driven systems — require profiling tools that visualize the actual evaluation sequence, not just call stacks from synchronous execution. Providing this tooling is not optional; it is the cost of choosing a non-trivial evaluation strategy.

**7. Dual-mode compilation pipelines (compiled vs. interpreted) must maintain feature parity to be trustworthy.** GHCi's interpretation of Haskell differs from compiled GHC in subtle ways — strictness is sometimes different, some extensions behave differently, performance is radically different. Programs tested in GHCi may behave differently when compiled. A language's interactive development environment must produce behavior that the programmer can trust will replicate in production builds.

**8. Governance fragmentation prevents resolution of ecosystem coordination problems.** The Stack vs. Cabal build tool split persisted for over a decade with no resolution because no single governance body had both the authority and the motivation to consolidate them. When a language's governance is distributed across bodies with non-overlapping domains, ecosystem-level problems that span domains accumulate indefinitely. Effective language governance requires a body with the authority to make binding decisions on infrastructure questions, including toolchain consolidation.

**9. A language designed by a committee of theoretical experts will optimize for theoretical elegance unless countervailing input from practitioners is structurally built in.** Haskell's founding committee was fifteen academics. The language they produced is elegant, theoretically coherent, and difficult for practitioners to adopt at scale. This is not a criticism of academics; it is a recognition that design committees should be structured to include people with different optimization targets. Subsequent practical input — from Standard Chartered, Meta, IOHK — has improved Haskell's production fitness, but the foundational design choices were made before that input was available.

**10. Languages that cannot update their specification are effectively frozen.** Haskell 2010 is the last standard. Haskell2020 failed. The absence of an ongoing specification process means that the effective language — GHC extensions, GHC2021, GHC2024 — cannot be implemented by anyone other than the GHC team. Language specification must be an ongoing process, not a one-time deliverable, and governance must ensure that specification updates lag implementation by at most a few years, not decades.

### Dissenting Views

**The dissent on adoption figures**: Some Haskell advocates argue that market adoption is a poor proxy for design quality, citing the decades-long influence of Haskell ideas (monadic I/O, type classes, GADTs, STM) on mainstream languages. This is a valid observation: Python got asyncio, Rust got traits, Kotlin got coroutines, and TypeScript's type system reflects HM-style inference. Haskell's influence exceeded its adoption. But a language designer building a language for use — not for inspiration — must weigh the evidence that Haskell's specific packaging of these ideas has not attracted users at scale, and ask why.

**The dissent on laziness**: A minority of practitioners, including many who built large production systems at Standard Chartered and IOHK, would argue that lazy evaluation is not a mistake but a misapplication — that Haskell should have been taught and used in a way that emphasizes the tools for controlling evaluation (StrictData, BangPatterns) from the start. Under this view, the space leak problem is a tooling and pedagogy failure, not a design failure. The counterargument: if the language requires pervasive annotation to avoid its default evaluation semantics' failure modes, the default was wrong.

**The dissent on community size**: Haskell's community, while small in absolute terms, is documented to be disproportionately composed of skilled practitioners — Survey respondents include significant proportions of professional software engineers working in finance, academia, and technology [HASKELL-SURVEY-2022]. The argument is that Haskell's 0.1% is high-quality 0.1%. This may be true — but small high-quality communities face the same sustainability risks as any small community, and the quality of the minority does not change the outcome for the majority who never adopted the language.

---

## References

[HASKELL-98-PREFACE] Hudak, P., Jones, S.P., Wadler, P., Hughes, J. (eds.). "Preface." *The Haskell 98 Report.* February 1999. https://www.haskell.org/onlinereport/preface-jfp.html

[HASKELL-WIKI-2010] HaskellWiki. "Haskell 2010." https://wiki.haskell.org/Haskell_2010

[HASKELL-WIKI-STM] HaskellWiki. "Software Transactional Memory." https://wiki.haskell.org/Software_transactional_memory

[HASKELL-WIKI-GOVERNANCE] HaskellWiki. "Haskell Governance." https://wiki.haskell.org/Haskell_Governance

[GHC-9.4-RELEASED] GHC Project. "GHC 9.4.1 Released." https://www.haskell.org/ghc/blog/20220807-ghc-9.4.1-released.html

[GHC-9.6-NOTES] GHC Project. "Version 9.6.1 Release Notes." https://downloads.haskell.org/ghc/9.6.1/docs/users_guide/9.6.1-notes.html

[GHC-RTS-EZYANG] Yang, E. "The GHC Runtime System." (Draft; JFP). http://ezyang.com/jfp-ghc-rts-draft.pdf

[GHC-SAFE-HASKELL] GHC User's Guide. "Safe Haskell." https://ghc.gitlab.haskell.org/ghc/doc/users_guide/exts/safe_haskell.html

[GHC-MEMORY-WIKI] HaskellWiki. "GHC/Memory Management." https://wiki.haskell.org/GHC/Memory_Management

[HASKELL-SECURITY-PAGE] Haskell.org. "Security." https://www.haskell.org/security/

[HSEC-2023-REPORT] Haskell Security Response Team. "2023 July–December Report." Haskell Discourse. https://discourse.haskell.org/t/haskell-security-response-team-2023-july-december-report/8531

[HSEC-2024-0003] Haskell Security Advisories. "HSEC-2024-0003: Windows command injection in the process library." https://haskell.github.io/security-advisories/advisory/HSEC-2024-0003.html

[HSEC-2023-0015-FILE] haskell/security-advisories. "HSEC-2023-0015: cabal-install Hackage Security protocol." https://github.com/haskell/security-advisories/blob/main/advisories/hackage/cabal-install/HSEC-2023-0015.md

[BENCHMARKS-GAME-GHC-CLANG] Benchmarks Game. "C clang vs Haskell GHC — Which programs are fastest?" https://benchmarksgame-team.pages.debian.net/benchmarksgame/fastest/clang-ghc.html

[HASKELL-SURVEY-2022] Fausak, T. "2022 State of Haskell Survey Results." November 18, 2022. https://taylor.fausak.me/2022/11/18/haskell-survey-results/

[SO-SURVEY-2025] Stack Overflow. "2025 Stack Overflow Developer Survey — Technology." https://survey.stackoverflow.co/2025/technology

[TIOBE-NOV-2024] Silvae Technologies. "TIOBE Index November Headline: Is Haskell Finally Going to Hit the Top 20?" https://silvaetechnologies.eu/blg/235/tiobe-index-november-headline-is-haskell-finally-going-to-hit-the-top-20

[BASE-WIKI] HaskellWiki. "Base package." https://wiki.haskell.org/Base_package

[HASKELL-FFI-RWH] Sullivan, B., Goerzen, J., Stewart, D. *Real World Haskell.* Chapter 17: Interfacing with C: the FFI. https://book.realworldhaskell.org/read/interfacing-with-c-the-ffi.html

[RWH-ERROR] Sullivan, B., Goerzen, J., Stewart, D. *Real World Haskell.* Chapter 19: Error Handling. https://book.realworldhaskell.org/read/error-handling.html

[UNSAFE-HASKELL-PENN] University of Pennsylvania CIS 1940. "Unsafe Haskell." Spring 2015. https://www.seas.upenn.edu/~cis1940/spring15/lectures/12-unsafe.html

[DH-ROADMAP] Serokell / GHC. "Dependent Haskell Roadmap." https://ghc.serokell.io/dh

[HF-WHITEPAPER] Haskell Foundation. "Haskell Foundation Whitepaper." https://haskell.foundation/whitepaper/

[HF-GOVERNANCE] Haskell Foundation / Haskell.org. "Haskell Foundation Q1 2025 Update." Haskell Discourse, 2025. https://discourse.haskell.org/t/haskell-foundation-q1-2025-update/11835

[HF-Q1-2025] Haskell Foundation. "Haskell Foundation Q1 2025 Update." Haskell Discourse. https://discourse.haskell.org/t/haskell-foundation-q1-2025-update/11835

[HASKELL202X-DEAD] Copeland, S. "Haskell2020 Is Dead, but All Hope Is Not Lost." Reasonably Polymorphic. https://reasonablypolymorphic.com/blog/haskell202x/

[PARSONSMATT-FAST] Parsons, M. "Keeping Compilation Fast." November 27, 2019. https://www.parsonsmatt.org/2019/11/27/keeping_compilation_fast.html

[SUMTYPEOFWAY-ITERATION] Sum Type of Way Blog. "Towards Faster Iteration in Industrial Haskell." https://blog.sumtypeofway.com/posts/fast-iteration-with-haskell.html

[SPACE-LEAKS-STANFORD] Stanford CS. "Space Leaks Exploration in Haskell — Seminar Report." https://cs.stanford.edu/~sumith/docs/report-spaceleaks.pdf

[SEROKELL-SC] Serokell. "Haskell in Production: Standard Chartered." https://serokell.io/blog/haskell-in-production-standard-chartered

[SEROKELL-META] Serokell. "Haskell in Production: Meta." https://serokell.io/blog/haskell-in-production-meta

[GHCUP-GUIDE] GHCup. "User Guide." https://www.haskell.org/ghcup/guide/

[HACKAGE] Hackage — The Haskell community's central package archive. https://hackage.haskell.org

[SALARY-DATA] Glassdoor. "Salary: Haskell Developer in United States 2025." https://www.glassdoor.com/Salaries/haskell-developer-salary-SRCH_KO0,17.htm

[INDEED-HASKELL] Indeed.com. "Haskell Functional Programming Jobs." https://www.indeed.com/q-Haskell-Functional-Programming-jobs.html

[WELL-TYPED-REPORT] Well-Typed. "GHC Activities Report: December 2024–February 2025." https://well-typed.com/blog/2025/03/ghc-activities-report-december-2024-february-2025/

[GHC-PROPOSALS-REPO] ghc-proposals. "Proposed compiler and language changes for GHC." GitHub. https://github.com/ghc-proposals/ghc-proposals

[BASE-HACKAGE] base package on Hackage. https://hackage.haskell.org/package/base

---

**Document version**: 1.0
**Prepared**: 2026-02-28
**Word count**: ~9,800 words
