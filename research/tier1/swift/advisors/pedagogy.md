# Swift — Pedagogy Advisor Review

```yaml
role: advisor-pedagogy
language: "Swift"
agent: "claude-sonnet-4-6"
date: "2026-02-28"
schema_version: "1.1"
```

---

## Summary

Swift presents one of the most instructive pedagogy case studies in modern language design, precisely because it was marketed as approachable while achieving genuine complexity. Apple invested substantially in pedagogical infrastructure — Swift Playgrounds for iPad, interactive Xcode Playgrounds, a visual REPL, curated documentation, and a steady stream of WWDC education sessions — yet the Stack Overflow 2024 admired rating of 43.3% (among the lowest of modern mainstream languages) reveals serious learner dissatisfaction. The 2025 recovery to 65.9%, attributed partly to Swift 6.2's concurrency approachability improvements, is the clearest available evidence that specific language design decisions have measurable effects on learner experience. The lesson is not "Swift failed at accessibility" but rather "Swift achieved approachability at level one while creating steep cliffs at levels two and three."

The council perspectives capture this duality well overall, though several specific claims warrant correction or amplification. The apologist overstates the consistency of the type system's pedagogical benefits without grappling with the `some`/`any` semantic split, which represents a genuine teaching hazard. The detractor accurately identifies the error handling multiplicity problem but frames it purely as design failure without acknowledging what each mechanism solves. The historian offers the most pedagogically coherent historical account, particularly on the Protocol-Oriented Programming overclaim — a canonical case of conference talk becoming misapplied teaching canon. The practitioner and realist perspectives collectively provide the clearest picture of where Swift's learning model succeeds and where it breaks down in production contexts.

The three deepest pedagogical findings: (1) the `some P` / `any P` distinction violates the principle that visual similarity should imply semantic similarity; (2) the Sendable/actor isolation model represents a concurrency teachability crisis that required Apple to produce a parallel documentation layer (migration guides, WWDC sessions, migration tools) to remediate what the language itself failed to communicate; and (3) the Protocol-Oriented Programming era is a historical lesson in how authoritative conference talks become bad teaching documents at scale. These findings yield important lessons for language design broadly.

---

## Section-by-Section Review

### Section 1: Identity and Intent (accessibility goals)

**Accurate claims:**

All five perspectives correctly identify the tension between Apple's "approachability" claim and learner experience. The research brief's citation of Lattner's explicit pedagogical ambition — "I hope that by making programming more approachable and fun, we'll appeal to the next generation of programmers and to help redefine how Computer Science is taught" [SWIFT-WIKIPEDIA] — is a significant primary source that most perspectives reference or imply. The historian accurately notes that approachability was a genuine design goal, not retroactive marketing.

The apologist is correct that Swift's initial design choices (type inference, optionals, clean syntax) are genuinely approachable compared to Objective-C and C++. For the specific audience Swift replaced Objective-C for, the learning improvement was real. The practitioner's observation that Swift is "essentially two languages" — the iOS/macOS language and the aspirational general-purpose language — maps precisely onto a two-tier learning experience: the iOS/macOS track is well-served by documentation, tutorials, and tooling; the server-side/systems track has sparse pedagogical resources.

**Corrections needed:**

The apologist conflates approachability for experienced developers coming from Python or Java with approachability for beginners. These are different claims. Swift's clean syntax and type inference lower the barrier for experienced developers; the evidence that Swift is accessible to true beginners is weaker. The frequently-cited "Why is Swift so difficult to learn when Apple claims it is easy?" question [QUORA-SWIFT-DIFFICULTY] is not merely a perception gap — it reflects a real structural issue: the "happy path" of Swift tutorials (variables, optionals, basic control flow, simple structs) is genuinely clean, but the moment a learner tries to extend a collection protocol, create a reusable generic component, or adopt Swift concurrency, they encounter complexity that the beginner materials do not prepare them for.

The detractor's claim that Swift's four design goals ("general purpose, safe, performant, approachable") are inherently in conflict is partially accurate pedagogically but understated in its precision. The conflict is not between all four simultaneously — it is specifically between the sophistication required for "performant" and "safe" advanced features and the "approachable" goal. The type system features needed for zero-cost abstractions and protocol-driven generic programming are the same features that make Swift hard to learn past the beginner stage.

**Additional context:**

Swift Playgrounds for iPad deserves explicit recognition as a genuine pedagogical innovation. The ability to write and run Swift code on an iPad with immediate visual feedback — without installing a development environment — lowered the beginner barrier significantly. Apple's "Everyone Can Code" curriculum, built around Swift Playgrounds, reached educational institutions and introduced Swift to learners who would not otherwise encounter it. This is a concrete, underappreciated contribution. However, Swift Playgrounds targets a beginner audience whose Swift eventually hits a hard wall when transitioning to professional iOS development in Xcode with full project structures, targets, schemes, and provisioning profiles — a transition that no amount of Playgrounds polish prepares learners for.

---

### Section 2: Type System (learnability)

**Accurate claims:**

All perspectives correctly identify that Swift's optional system (`T?` / `Optional<T>`) is pedagogically well-designed. The explicit unwrapping requirement creates a clear mechanical ritual (if let, guard let, ??, !) that mirrors the conceptual reality: you must choose what to do when the value is absent. Compared to null pointer exceptions in Java or Java's historically uncontrolled null handling, this is a genuine pedagogical advance. Learners who correctly internalize optionals develop a transferable safety mindset. The historian's framing of this as "teaching safe programming by construction" is accurate.

The realist's identification of the generics ceiling (no higher-kinded types) as something that forces workarounds is accurate and pedagogically relevant: learners who come to Swift from Haskell or Scala expecting type-level functional abstractions encounter a dead end that requires understanding why the ceiling exists, not just how to work around it.

**Corrections needed:**

The most significant pedagogy concern in Section 2 that the council underweights is the `some` / `any` keyword distinction. This is a genuine teaching hazard that deserves stronger treatment.

`some P` (opaque type, SE-0244) and `any P` (existential, SE-0309/SE-0352) are visually nearly identical — a single word preceding a protocol name — but represent fundamentally different runtime semantics. `some P` is resolved at compile time to a single concrete type the caller cannot see; `any P` boxes a type-erased value with runtime dispatch overhead. The differences matter for performance, generics capabilities, and protocol conformance behavior. Swift 5.7 made the `any` keyword mandatory to force explicit acknowledgment of this distinction, which is the right decision for clarity in experienced code but adds a required conceptual burden for learners who must now understand existential boxing before writing simple protocol-based code.

The apologist acknowledges the complexity of associated types but treats it as justified by the power they enable, without addressing the pedagogical cost. Protocols with associated types (PATs) are a fundamental Swift concept — they underpin `Collection`, `Sequence`, `Codable`, and most standard library protocols — yet they are notoriously difficult to teach. The concept of a protocol that cannot be used directly as a type (pre-Swift 5.7: "Protocol 'P' can only be used as a generic constraint because it has Self or associated type requirements") generates one of Swift's most confusing error messages, one that has been a widespread stumbling block for learners for years. The improved Swift 5.7 semantics with `any` are better, but the underlying conceptual complexity remains.

**Additional context:**

Swift's approach to type inference deserves specific pedagogical evaluation. Strong local inference is a learner benefit — `let x = 42` is unambiguous, and the IDE shows inferred types on hover. But complex generic expressions can produce type inference failures with error messages that explain what the compiler concluded but not why it failed. Consider: an expression involving nested generic functions, protocol conformances, and conditional extensions can produce error messages that accurately identify a type mismatch but provide no guidance on which of three possible fixes is correct. The compiler becomes a teacher who can diagnose but not prescribe. This is a category of error message quality that the council perspectives mention but do not analyze with sufficient depth.

The `Codable` protocol (Encoder/Decoder synthesis, SE-0166, Swift 4.0) is one of Swift's clearest pedagogical successes in the type system. It demonstrates how a sophisticated type system feature (conditional conformance, derived implementations) can be surfaced with zero-ceremony ergonomics: add `Codable` to a struct, get automatic JSON encoding/decoding. This is the type system serving learners rather than intimidating them, and it represents the correct design philosophy: make the common case trivially expressible, and only surface complexity when the user needs customization.

---

### Section 5: Error Handling (teachability)

**Accurate claims:**

The research brief correctly identifies four distinct error handling mechanisms in Swift: `throws`/`try`/`catch`, `Result<Success, Failure>`, Optional returns (returning `nil` for failure), and termination functions (`fatalError`, `precondition`, `assert`). All perspectives acknowledge this multiplicity; the detractor most explicitly identifies it as a design problem.

The historian's observation that the `throws`/`try`/`catch` system (Swift 2.0) was a deliberate departure from Objective-C's `NSError**` out-parameter pattern is accurate and pedagogically relevant — Swift's error handling is genuinely more learnable than what it replaced.

The practitioner accurately notes that `defer` is pedagogically unusual: it is a powerful cleanup tool that requires understanding scope exit semantics before it makes intuitive sense. Learners who encounter `defer` in unfamiliar code often misread its execution timing.

**Corrections needed:**

The council perspectives collectively underweight the teachability cost of error handling multiplicity. When a language provides multiple mechanisms for similar goals, learners and teachers face a "which one?" problem that the language itself does not resolve. Swift's situation:

- `throws`: synchronous throwing; caught with `try`/`do`/`catch`; must be propagated or explicitly caught
- `Result<S, F>`: explicit success/failure representation; enables typed failures before SE-0413; required for callback-based async APIs; useful in contexts where throwing is awkward
- Optional return (returning `nil`): used for "absence as failure" in collection lookups, conversions; does not carry error information
- `fatalError`/`precondition`/`assert`: programmer-error termination; not catchable; debug vs. release behavior differs

A learner building a networking function must decide which mechanism to use at each boundary. The standard library itself is inconsistent: `Int("abc")` returns `nil` (Optional), `FileManager.default.createDirectory(...)` throws, and URLSession completion handlers historically used `Result<Data, Error>`. No canonical decision rule is provided in Swift documentation. The practitioner acknowledges this inconsistency but does not frame it as a pedagogy problem; the detractor identifies it as a design failure without offering the learner perspective.

The introduction of typed throws in Swift 6.0 (SE-0413) adds a fifth configuration — `throws(MyError)` — which is ergonomically beneficial for advanced uses (especially Embedded Swift) but adds another decision point for learners: when should I use typed throws? The Swift documentation and community guidance have not yet converged on this question.

**Additional context:**

One pedagogically positive feature of Swift's error handling that is underemphasized: `try?` and `try!` as explicit, syntactically distinct escape hatches teach learners that error handling has a cost that must be consciously paid. `try?` silences errors to Optional, and `try!` forces success (crashing on failure). Unlike exceptions that can be silently swallowed by catching and ignoring them, Swift's escape hatches are visible at each call site. This is a pedagogical advance: the code reviews can be searched for `try!` and `try?` to audit error handling decisions.

The `async`/`throws` combination in Swift 5.5+ creates a fourth dimension of function signatures that learners must master: `async`, `throws`, `async throws`, or neither. While the semantics are consistent, the error messages when these signatures are mismatched ("call is 'async' but is not marked with 'await'") are generally clear. The combination of concurrency and error handling is a teachability cliff that the concurrency section addresses in more detail.

---

### Section 8: Developer Experience

**Accurate claims:**

All perspectives correctly report the Stack Overflow survey data: 43.3% admired in 2024, recovering to 65.9% in 2025 [SO-SURVEY-2024, SO-SURVEY-2025]. The council's collective interpretation — that the 2024 score reflected Swift 6 migration pain and the 2025 recovery reflected Swift 6.2 approachability improvements — is plausible and consistent with the timeline, though no direct causal evidence links the score specifically to concurrency ergonomics vs. other factors.

The apologist's identification of Xcode Playgrounds as a genuine pedagogical tool is correct. The immediate feedback loop, inline results, and visualization capabilities make Playgrounds superior to terminal-based REPLs for learners. The practitioner's observation that the Playgrounds-to-production transition is abrupt is equally accurate: Playgrounds do not expose learners to the module system, build targets, provisioning profiles, or the Xcode project structure that professional development requires.

The realist correctly notes that Swift's error messages are generally better than Objective-C's but have known failure modes in complex generic contexts. This is an accurate characterization.

The historian's observation about WWDC talks becoming de facto pedagogical canon is important and underdeveloped across the council. The 2015 "Protocol-Oriented Programming in Swift" talk [WWDC-2015-408] became so widely cited as the definitive Swift design philosophy that developers began using protocols where simpler solutions (concrete types, subclasses, plain functions) were appropriate. This is a documented pattern in the Swift community, and Apple only explicitly addressed it years later. The lesson for language design is that official conference talks function as authoritative teaching documents and carry corresponding responsibility.

**Corrections needed:**

The apologist overstates the quality of Swift's error messages broadly. While Swift's messages for common errors are good — optionals produce clear "value of optional type must be unwrapped to a value of type 'T'" messages; mismatched types produce readable diagnostics — protocol-related errors remain problematic. The error "type 'MyType' does not conform to protocol 'P'" often does not identify *which* protocol requirement is not satisfied in complex protocol hierarchies, leaving learners to manually inspect the protocol definition. Contrast with Rust's compiler errors, which typically identify the specific missing implementation and suggest what needs to be added. Swift's diagnostic infrastructure has improved substantially since the Swift 3 era but has not reached parity with Rust for protocol conformance errors.

The practitioner's claim that Swift is "approachable for beginners" is too unqualified. The evidence supports a more precise claim: Swift is approachable for beginners within the scope of Swift tutorial content, which typically covers single-file programs, struct definitions, optionals, and basic control flow. Once learners attempt to build anything requiring generics, protocols with associated types, or concurrent code, the complexity ramps sharply. This cliff is documented — the frequently-asked "Why is Swift hard to learn?" question is evidence of the gap between tutorial-level and production-level mental models.

The council does not adequately address AI-assisted learning as a distinct learner profile. Large language models trained on public code have substantial Swift training data for iOS patterns (UIKit, SwiftUI), but Swift 6 concurrency patterns (actors, structured concurrency, Sendable conformance) are recent enough to be underrepresented and frequently hallucinated incorrectly. A learner using an AI assistant to learn Swift concurrency is likely to receive confidently-stated but incorrect guidance on Sendable conformance requirements and actor isolation semantics. This is a current, concrete pedagogy risk.

**Additional context:**

Swift's argument label system (inherited from Objective-C's Smalltalk-derived selector syntax) is an underappreciated pedagogical asset. Swift API guidelines require argument labels that read naturally at the call site: `addSubview(childView)`, `insert(element, at: index)`, `makeIterator()`. This produces APIs that are self-documenting at the call site, which benefits learners reading unfamiliar code. Surveys of API usability have consistently found that named arguments improve comprehension of unfamiliar APIs. This design choice — essentially imposing Objective-C's verbose naming conventions on a modern language — proved its pedagogical worth.

Conversely, the multi-syntax property observer system (`willSet`/`didSet`), computed properties (`get`/`set`), property wrappers (`@propertyWrapper`), and `lazy` properties create four distinct property declaration patterns that beginners encounter in tutorial code without a clear conceptual framework for choosing among them. Each serves different use cases, but the visual similarity of `var x: Int { get { ... } set { ... } }` and `var x: Int { didSet { ... } }` creates confusion about what is being defined.

The structured concurrency model (Swift 5.5, SE-0304) deserves extended discussion. The `async`/`await` syntax itself has a gentle learning curve — the semantics parallel structured control flow, and the compiler enforces correct usage. But the surrounding model — Sendable conformance, actor isolation, Task cancellation, TaskGroup, AsyncSequence, continuation-based bridging from callback APIs — creates a substantial learning cliff. Apple's response was to produce a parallel documentation layer: WWDC 2021 sessions on Swift concurrency, the Concurrency Migration Guide for Swift 6, SE proposals linked from error messages, and the `@preconcurrency` migration attribute. This parallel documentation layer is evidence that the language's own diagnostic infrastructure was insufficient to guide learners — the language failed to teach itself.

---

### Other Sections (Pedagogy-Relevant Flags)

**Section 4: Concurrency and Parallelism**

This is the highest-priority current pedagogy concern. The structured concurrency model's complexity has been acknowledged by Apple through the creation of the Concurrency Migration Guide, dedicated WWDC sessions across 2021–2024, and the `@preconcurrency` attribute explicitly designed to ease migration. When a language requires a companion migration guide to use its own concurrency model, the teachability of that model has failed. Swift 6.2's partial restoration of `nonisolated(unsafe)` safety valves and reduced strict concurrency enforcement in foundational modes is a retreat from Swift 6's ambitious Sendable requirements, confirmed by the admired score recovery. The lesson: concurrency teachability is not separable from concurrency correctness, and a model that developers cannot reason about will not be adopted correctly regardless of its formal safety guarantees.

**Section 6: Ecosystem and Tooling**

The Swift Package Manager (SPM) is more learnable than legacy CocoaPods/Carthage workflows: a single `Package.swift` file with a declarative API replaces multi-tool configurations. The council correctly identifies SPM as a pedagogical improvement. However, the interaction between SPM, Xcode, and signing/provisioning remains opaque to beginners: why does a package build fine in `swift build` but fail in Xcode with a code-signing error? The mental model gap between command-line Swift and Xcode-integrated Swift is a persistent learner stumbling block not addressed in any council perspective.

**Section 11: Governance and Evolution**

The rate of change is a pedagogy concern that the council underweights. Swift 1.0 to Swift 3.0 involved source-breaking migrations that required tutorials to be entirely rewritten. Learners following pre-Swift 3 tutorials encountered code that did not compile. The Swift 5.0 ABI stability milestone stabilized the runtime, and source compatibility has been maintained since Swift 5, which significantly improved the durability of learning resources. However, Swift 6's strict concurrency introduced new warning-to-error promotions that broke existing code without preserving tutorial validity. The implication for pedagogy: source stability is necessary but not sufficient for learning resource durability; semantic stability (same code produces same behavior under new safety rules) is a distinct requirement that Swift has not consistently delivered.

---

## Implications for Language Design

The following implications are grounded in specific Swift findings and stated as principles applicable to language design generally.

**1. Tiered complexity requires tiered on-ramps, not cliff transitions.**

Swift achieves genuine beginner approachability through clean syntax, type inference, and interactive Playgrounds, then presents sharp complexity cliffs at generics, protocols with associated types, and concurrency. The gap between beginner and intermediate documentation is enormous. Language designers should map the complexity tiers in their language and design explicit conceptual bridges — intermediate-level primitives or API surfaces that can be understood without mastering the full advanced model. The "happy path" and the "production path" should not require a conceptual leap.

**2. Visual similarity must track semantic similarity.**

`some P` and `any P` are visually nearly identical — one modifier word before a protocol name — but semantically completely different in runtime behavior, performance implications, and type system capabilities. This violates the principle that code that looks similar should behave similarly. When language designers introduce new modifiers or keywords that syntactically resemble existing ones, they must assess whether the visual similarity creates false intuitions. The `any` keyword was introduced to make existentials explicit, which is the right goal; but the solution introduced a new visual hazard rather than resolving the underlying semantic complexity.

**3. Multiple error handling mechanisms require a canonical decision framework.**

When a language provides several error handling strategies (Swift: `throws`, `Result`, Optional, termination), learners face a "which one?" problem. The language must provide authoritative decision guidance, preferably at the documentation and tooling layer. Without it, learner code is inconsistent, and the inconsistency is transmitted to the code they read and learn from. The framework should be teachable in a single diagram or decision tree. Swift documentation does not provide this, and the community has produced conflicting conventions as a result.

**4. Interactive environments dramatically lower the beginner barrier and should be a primary design investment.**

Swift Playgrounds for iPad demonstrates that immediate visual feedback, no-setup execution, and visual REPL output are not aesthetic niceties — they are determinative for learner retention in the beginner phase. Language designers should treat the interactive feedback environment as a first-class design artifact, not an afterthought. The most pedagogically harmful moment in a learner's journey is their first encounter with a build error in a production-like environment. The environment should be designed to delay this encounter until the learner has built sufficient mental models to interpret it.

**5. Type system sophistication accrues a learnability debt payable in production.**

Every advanced type system feature added to serve expert users — higher-kinded types, associated type constraints, existential boxing, conditional conformances — creates a concept that beginners must eventually learn to read expert code and standard library documentation. Swift's sophisticated generics system is a genuine design achievement, and its absence would be a real limitation. But language designers should track the cumulative conceptual surface of their type system and ask: can a developer become productive in the language in two days without understanding this concept? If not, it adds to the learnability debt. Swift's answer for many concepts is no.

**6. Concurrency teachability is separable from concurrency correctness, and both must be designed.**

Swift's structured concurrency model is formally sound. It is also undeniably difficult to teach and adopt. Apple's creation of a parallel documentation layer (migration guides, WWDC sessions, migration attributes) to remediate the language's own diagnostic failures demonstrates this separation. The implication: a concurrency model can be provably correct in academic terms while failing learners in production. Language designers should evaluate concurrency models along both axes independently. A model that developers cannot mentally simulate will not be adopted correctly regardless of its formal properties. Error messages for concurrency violations must identify not just what is wrong but why the invariant exists and what the correct pattern is.

**7. Conference talks and authoritative presentations function as pedagogical documents and should be held to documentation standards.**

Swift's Protocol-Oriented Programming era demonstrates that when language designers or core teams produce widely-watched presentations framed as design philosophy, those presentations become teaching canon. Developers build mental models from WWDC sessions. When those mental models are inaccurate — when POP is presented as universally superior to subclassing for situations where subclassing is appropriate — the community adopts bad practices at scale. Language designers should treat official technical presentations as teaching documents, verify their prescriptions against real-world use cases before publication, and provide clear guidance on scope and limitations of demonstrated patterns.

**8. Argument labels are an underappreciated pedagogical design choice.**

Swift's argument label system — requiring labels at call sites that read naturally in context — produces APIs that are self-documenting and readable to learners encountering unfamiliar code. This is a transferable lesson: API naming conventions that serve readability at the call site, even at the cost of verbosity, serve learners who read code more than they write it. The convention is learnable in minutes but provides compounding benefits throughout a developer's career. Language designers should consider call-site readability as a first-class API design criterion, not merely a style preference.

---

## References

[LATTNER-ATP-205] Lattner, C. Interview. Accidental Tech Podcast, Episode 205. 2017. (Referenced in research brief for Objective-C memory safety impossibility.)

[MACRUMORS-2014] MacRumors. "Craig Federighi Introduces Swift Programming Language at WWDC 2014." June 2, 2014.

[SWIFT-WIKIPEDIA] Wikipedia. "Swift (programming language)." Retrieved February 2026. (Source for Lattner approachability quote.)

[SO-SURVEY-2024] Stack Overflow Annual Developer Survey 2024. N=65,000+. https://survey.stackoverflow.co/2024/

[SO-SURVEY-2025] Stack Overflow Annual Developer Survey 2025. N=49,000+. https://survey.stackoverflow.co/2025/

[JETBRAINS-2024] JetBrains State of Developer Ecosystem Survey 2024. N=23,262. https://www.jetbrains.com/lp/devecosystem-2024/

[QUORA-SWIFT-DIFFICULTY] Quora. "Why is Swift so difficult to learn when Apple claims it is easy?" Referenced in Swift research brief as evidence of approachability gap.

[SWIFT-COMPILER-PERF] Swift bug tracker and community discussion: type constraint solving compilation performance. Referenced in research brief.

[SWIFT-FORUMS-JETBRAINS-2024] Swift Forums discussion on 2024 Stack Overflow admired rating (43.3%). Referenced in research brief.

[HACKINGWITHSWIFT-60] Hudson, P. "What's new in Swift 6.0." HackingWithSwift. 2024. (Source for typed throws / SE-0413.)

[MACSTADIUM-IOS-SURVEY] MacStadium iOS Developer Survey. "More than 80% of iOS developers rated satisfaction with Swift at 8/10 or better." Referenced in research brief.

[INFOWORLD-TIOBE-2025] InfoWorld. "Swift declining in TIOBE rankings, cross-platform alternatives capturing share." April 2025.

[WWDC-2015-408] Apple. "Protocol-Oriented Programming in Swift." WWDC 2015, Session 408. June 2015.

[SE-0244] Swift Evolution. SE-0244: "Opaque Result Types." Swift 5.1. 2019.

[SE-0309] Swift Evolution. SE-0309: "Unlock existentials for all protocols." 2022.

[SE-0352] Swift Evolution. SE-0352: "Implicitly opened existentials." Swift 5.7. 2022.

[SE-0413] Swift Evolution. SE-0413: "Typed throws." Swift 6.0. 2024.

[SE-0304] Swift Evolution. SE-0304: "Structured Concurrency." Swift 5.5. 2021.

[OLEB-LATTNER-2019] Ole Begemann interview with Chris Lattner. "Lattner on Swift's design goals." 2019. (Referenced in research brief for general-purpose language ambitions.)

[SIMPLILEARN-SALARY] Simplilearn. "iOS Developer Salary in the US." 2025.

[ZIPRECRUITER-SALARY] ZipRecruiter. "Swift Developer Salary." 2025.

[JETBRAINS-APPCODE-SUNSET] JetBrains. "AppCode Is Discontinued." December 2023.
