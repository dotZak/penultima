# Go — Pedagogy Advisor Review

```yaml
role: advisor-pedagogy
language: "Go"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
```

---

## Summary

Go presents a remarkably instructive case study in pedagogical trade-offs: a language whose initial learning experience is among the easiest of any systems language, but whose mastery curve conceals a second, steeper ramp that beginners are unlikely to anticipate. The design philosophy of radical simplicity — one way to write an if statement, mandatory formatting, a small specification — genuinely delivers on its promise for the first week of use. The problems emerge in weeks two and three, when learners must simultaneously acquire goroutines, channels, `context.Context`, the `select` statement, error wrapping, and the counter-intuitive nil-interface semantics, with no compiler to guide them toward correct concurrent behavior and no static enforcement of error handling discipline.

The cognitive load architecture of Go is unusual: incidental complexity is aggressively minimized (no build system choice, mandatory formatting, single cross-platform toolchain), but essential complexity is not mediated by the type system in the ways learners expect from modern statically typed languages. Null dereferences that experienced developers from Rust or Kotlin know as compile-time errors are, in Go, runtime panics discovered in production. Error handling that in other languages is either invisible (exceptions) or enforced (result types) is in Go explicit but un-enforced — learners must develop discipline rather than relying on the compiler to develop it for them. These are deliberate design choices, but they represent a significant pedagogical cost that Go's marketing consistently undercounts.

Go's performance as a teachable language for AI coding assistants is notably strong: the language's explicit, imperative structure, minimal syntax ambiguity, mandatory formatting, and lack of operator overloading make generated code predictable and easily verified. The 70%+ AI tool adoption rate among Go developers [GO-SURVEY-2025] reflects this: Go's structural clarity means AI-generated Go code integrates cleanly and is auditable in ways that dynamically typed or heavily macro-expanded languages are not.

---

## Section-by-Section Review

### Section 8: Developer Experience

**Accurate claims:**

- The high satisfaction figures (91% in 2025 [GO-SURVEY-2025], 93% in 2024 H2 [GO-SURVEY-2024-H2]) are genuine and reflect real-world practitioner sentiment, not survey design artifacts. The population is large enough (thousands of professional developers) to be meaningful.
- The compiler error messages are precise and actionable. The apologist's claim that error messages "include goroutine stack traces that identify the fault location immediately" is accurate for runtime panics. The realist's characterization of these as generally good holds up.
- The integrated toolchain (single `go` command, no build system choice) is a legitimate pedagogical advantage. New contributors to any Go project face approximately zero toolchain onboarding friction.
- The claim that developers from C-family backgrounds can write useful Go within days for basic usage is supported by Go's adoption pattern in organizations transitioning from C++ and Java.

**Corrections needed:**

- The apologist's framing that "the places where Go requires adjustment are concentrated" understates the extent of the second-ramp problem. Goroutines and channels are introduced in the tour and appear simple, but production-quality concurrent Go — including context propagation, goroutine leak prevention, `select` with timeouts, `sync.WaitGroup` coordination, and `errgroup` patterns — represents a significant conceptual surface area that beginners discover incrementally and painfully. The detractor's observation that "the learning curve is described as short but the stack depth required for production-quality concurrent Go code is significantly higher than the marketing implies" is more accurate to the evidence.
- The apologist's claim that "there is no decision about which test framework to adopt" deserves qualification. The standard library `testing` package is sufficient for unit tests, but `testify` is effectively a community standard for assertions and mocking [BRIEF-TESTIFY]. Newcomers encounter this as a decision point, and the prevalence of `testify` in open-source Go code creates an implicit expectation that the official toolchain does not satisfy by default.
- The claim that error messages from `gopls` surface errors "with sufficient context to diagnose them" is accurate for type errors. However, `gopls` messages for generic type constraint violations are frequently cited by practitioners as difficult to parse, particularly for complex type constraint combinations — a gap that has grown as generic code has proliferated since 1.18.

**Additional context:**

Go's developer experience ratings deserve a demographic caveat. The official Go Developer Survey draws from developers who have chosen Go and are actively using it; those who tried Go and left are not represented. The Detractor correctly identifies that 43% of respondents in the 2023 H2 survey found error handling tedious [GO-SURVEY-2023-H2] — a figure that coexists with the 91% satisfaction rate, suggesting that Go developers learn to tolerate verbosity they recognize as a cost, not that they have found the verbosity to be a non-issue.

For the specific learner profile of experienced developers transitioning from exception-based languages (Java, Python, C#), the error handling mental model shift is the single largest pedagogical obstacle. Exceptions allow errors to be deferred and composed; Go requires them to be handled at every call site immediately. The discipline this enforces is arguably beneficial in the long run, but the initial adjustment period is longer than Go documentation typically acknowledges.

**AI tooling pedagogical note:**

The 2025 survey reports 70%+ AI tool usage among Go developers [GO-SURVEY-2025]. From a pedagogy-of-AI-assisted-development perspective, Go is unusually well-suited: AI-generated Go code is highly legible because Go prohibits unused variables and imports (producing compiler errors that are trivially actionable), uses mandatory formatting (so AI-generated code is structurally consistent with hand-written code), and has no operator overloading or implicit conversions (so AI-generated arithmetic is semantically transparent). These properties make Go an excellent language for learners using AI assistance precisely because verification of generated code is low-effort.

---

### Section 2: Type System (learnability)

**Accurate claims:**

- The structural interface system is genuinely easier to learn than Java/C#'s explicit declaration model for everyday use. The apologist's observation that "you can define an interface after the fact to describe behavior that existing types already exhibit" captures a real ergonomic advantage that learners from Java backgrounds often find liberating.
- The absence of operator overloading and function overloading is a net pedagogical positive. Code that uses `+` always means built-in addition; calling `process(x)` always refers to exactly the function named `process`. Learners do not need to track context-dependent operator meanings.
- The detractor's description of the nil interface problem as "documented as a 'gotcha' in the official Go FAQ, rediscovered in production engineering blogs repeatedly" is accurate. This is a well-documented learning hazard.

**Corrections needed:**

- The apologist's assertion that "you learn [structural typing] once and it works consistently thereafter" is incomplete. The nil interface problem — where a typed nil pointer assigned to an interface is not `nil` at the interface level — is structurally counter-intuitive in a way that affects even experienced developers. The canonical example from the detractor's perspective (a function returning a typed nil `*MyError` cast to `error` that the caller cannot detect as nil via `== nil`) is a genuine cognitive trap that the type system does not prevent and the compiler does not warn about. This remains a first-week gotcha that recurs throughout a Go developer's career.
- The discussion of generics (Go 1.18+) across council perspectives underestimates the pedagogical cost of the current type constraint syntax. The syntax `[T interface{ constraints.Ordered | ~string }]` is expressible but creates a significant reading burden. The absence of type inference in many cases means that callers must sometimes supply explicit type arguments. Library authors working with complex generic constraints report that the restrictions on parameterized methods force API designs that are less legible than they would be in other generic systems [DOLTHUB-GENERICS-2024]. For learners encountering generic Go code in libraries for the first time, the constraint syntax is a non-trivial reading obstacle.
- Council members note the absence of sum types as a type system gap but do not fully address the pedagogical consequence: without sum types, the idiomatic Go approach to multi-case results requires learners to choose among four imperfect patterns (empty interface with type switch, sealed interface with unexported method, struct with optional fields, or a manual `Result` type) — none of which have compiler-enforced exhaustiveness. This produces inconsistency across codebases that learners must navigate without a clear authoritative answer.

**Additional context:**

The transition from "interfaces are implicit" to "interface nil semantics are not intuitive" represents a specific learning cliff worth characterizing precisely. In week one, structural interfaces appear simpler than Java interfaces because there is no `implements` declaration. In week two or three, learners discover that the `== nil` comparison on interface values behaves differently from their expectation, that you cannot compare interfaces for equality, and that the type assertion syntax (`x.(T)`) panics if the type is wrong unless the two-return form (`x, ok := y.(T)`) is used. These are not difficult concepts individually, but they form a cluster of counter-intuitive behaviors that all involve the same `interface{}` mechanism, arriving close together in the learning arc.

For learners from Python or Ruby backgrounds, Go's static typing is initially the biggest adjustment — but the type system is small enough that the adjustment happens quickly. The more persistent challenge for these learners is the concurrency model and the error handling discipline.

---

### Section 5: Error Handling (teachability)

**Accurate claims:**

- The apologist's argument that exceptions allow errors to be invisible while Go's explicit return value makes "every function that can fail declares it in its signature" is pedagogically sound as a statement about code readability. A student reading a Go function can identify every error path without understanding exception propagation rules.
- The realist's observation that `errors.Is` and `errors.As` provide a workable mechanism for error chain inspection is accurate. These are learnable APIs with clear semantics for typical use cases.
- The detractor's characterization of error silencing as "trivially easy" via `result, _ := call()` is accurate and pedagogically important: the mechanism that enforces explicit error handling also permits silent discarding. Learners do not receive a gradual escalation from "you should handle this" to "you must handle this" — both behaviors are syntactically identical effort.

**Corrections needed:**

- The apologist's assertion that Rob Pike's "Errors are values" essay demonstrates that "idiomatic Go error handling can be factored and reused" overstates its practical impact for everyday learners. Pike's essay shows patterns like an `errWriter` type that accumulates errors through multiple write operations — genuinely useful patterns, but ones that require significant design upfront. Most beginning Go programmers write repetitive `if err != nil` chains because the idiomatic factoring patterns are non-obvious and require API design decisions that newcomers are not equipped to make. The essay is valuable but does not eliminate the verbosity problem for the majority of Go programs.
- Several council members describe error handling as a "tax on writing, not on reading." This framing is accurate for code authors but incomplete for code learners. For learners reading unfamiliar codebases, extensive `if err != nil` chains create visual noise that makes it harder to identify the actual logic flow. The operational concern is that learners normalize scanning over error handling blocks, increasing the probability of missing subtly incorrect error handling patterns — exactly the failure mode the explicit approach was meant to prevent.
- The detractor notes that the Go team's 2024 formal closure of error handling syntax proposals included the statement "we neither have a shared understanding of the problem, nor do we all agree that there is a problem in the first place" [GO-ERROR-SYNTAX-2024] — despite 43% of surveyed developers identifying the verbosity as a real problem [GO-SURVEY-2023-H2]. From a pedagogical standpoint, this decision sends a signal: the language will not evolve toward the learner's intuition; instead, the learner must evolve toward the language's idiom. This is a defensible choice, but educators should communicate it clearly rather than implying Go's error handling is an easier system than it is.

**Additional context:**

The teachability of error handling in Go depends substantially on which comparison class the learner comes from. For learners from C (where forgetting to check return codes is a historical CVE category), Go's explicit error returns are an improvement in both teachability and practice — the pattern is familiar but syntactically cleaner and type-safe. For learners from Rust (where the `?` operator propagates errors with zero boilerplate and the type system enforces that all error cases are handled), Go's verbosity is a step backward.

The most pedagogically under-documented failure mode is errors launched into goroutines without collection mechanisms. The pattern `go func() { result, err := operation(); if err != nil { log.Error(...) } }()` looks idiomatic and handles the error. The pattern `go operation()` where `operation()` returns an error — that error is silently discarded. Learners must understand goroutines, error values, and function signatures simultaneously to recognize this hazard.

The `fmt.Errorf` / `%w` / `errors.As` chain is teachable in isolation but creates compounding complexity in practice. Learners must understand: (1) that `%w` wraps whereas `%s` does not, (2) that wrapped errors are unwrapped via `errors.As`, (3) that the chain is checked via `errors.Is` for sentinel comparison, and (4) that adding context at each layer is a discipline the type system does not enforce. These form a coherent system, but the fact that forgetting `%w` in favor of `%s` silently loses the wrapped error — with no compiler warning — is a recurring point of confusion.

---

### Section 1: Identity and Intent (accessibility goals)

**Accurate claims:**

- Go's stated goal of "ease of programming of an interpreted, dynamically typed language with the efficiency and safety of a statically typed, compiled language" [GO-FAQ] accurately describes the intended accessibility target. The language does succeed at being accessible to engineers familiar with C-family syntax.
- The small specification ("just one way to write an if statement") is a genuine pedagogical advantage. The Go specification is short enough that a developer can read it in a sitting, unlike C++ or Rust's specifications.
- The historian's characterization of Go as "simple on purpose" — with omissions that are documented intellectual positions rather than oversights — is accurate and important. Learners who understand the deliberateness of Go's constraints adjust more readily than learners who expect missing features to arrive eventually.

**Corrections needed:**

- The FAQ's claim that Go's simplicity "makes it easy to learn Go and harder to accidentally misunderstand what a program does" [GO-FAQ] is partially accurate and partially aspirational. The simplicity of syntax genuinely reduces misunderstanding in sequential code. In concurrent code, the simplicity enables misunderstanding of a different kind: a goroutine leak looks like correct code (`go func() { ... }()`); a nil interface check failure looks like correct code (`if err != nil`); an unguarded map access looks like correct code (`m[key]`). The simplicity of the surface language does not prevent subtle semantic errors in concurrent or error-handling contexts.
- The research brief's characterization of the learning curve as a list of adjustment points (goroutines, explicit error handling, structural typing) presents these as sequential learning events. The pedagogy reality is that they must often be learned simultaneously when writing any non-trivial networked service. A developer building their first HTTP handler in Go must simultaneously handle: routing, error propagation from database calls, context threading for timeouts, goroutine safety for shared state, and interface satisfaction for dependency injection. The compounding of these unfamiliarities creates a steeper effective initial ramp than the individual components suggest.

**Additional context:**

The detractor's framing that Go's design was driven by Google's specific institutional constraints (large rotating engineering teams, C++ compile time frustration, monorepo deployment) — and that these constraints were elevated to universal virtues — has a pedagogical implication: Go is genuinely well-suited for the learner profile of engineers joining large organizations with existing Go codebases, where "reading programs is more important than writing them" is a real day-to-day requirement. For this learner profile, Go's opinionated simplicity is exactly right. For learner profiles who value expressiveness, type-level guarantees, or ergonomic error handling, the simplicity is experienced as constraint rather than liberation.

The explicit design goal that "reading programs is more important than writing them" (per Pike's SPLASH 2012 keynote) has direct pedagogical value: Go code written by one developer is genuinely more accessible to another developer than equivalent code in many alternatives. This makes Go an unusually good language for pair programming, code review pedagogy, and organizational knowledge transfer.

---

### Other Sections (pedagogy-relevant notes)

#### Section 4: Concurrency (teachability)

The concurrency model is Go's most significant pedagogical innovation and its most significant pedagogical risk.

**The innovation:** Goroutines produce concurrent code that reads as sequential code, which is a genuine pedagogical simplification. A developer new to concurrency can write a goroutine, write a channel receive, and produce working concurrent code without understanding OS thread scheduling, mutex semantics, or callback composition. This is a meaningful reduction in the incidental complexity of concurrent programming. Languages that require explicit thread management (C, Java pre-Loom), callback patterns (JavaScript), or the `async/await` distinction (Rust, Python, C#) impose higher initial cognitive load for concurrent programs.

**The risk:** The `go` keyword launches a goroutine with no lifecycle attachment and no automatic cleanup. Learners who understand goroutines syntactically but not semantically produce goroutine leaks that are invisible until they cause resource exhaustion. The detractor's observation that goroutine leaks are significant enough that the community built `goleak` specifically to detect them, and that Go 1.26 added experimental goroutine leak profiling fourteen years after Go 1.0, reflects a real gap: the language provides no default mechanism to help learners understand that goroutines have resource implications.

The `context.Context` pattern — passing a context as the first argument to every function that might block — is a pedagogy anti-pattern in the sense that it requires understanding several things simultaneously: the context API, the cancellation mechanism, and the propagation requirement. Forgetting to pass context — or passing `context.Background()` where a cancellable context should go — silently breaks cancellation for entire goroutine subtrees with no compiler warning. This is a systemic learning hazard that the research brief and council members acknowledge but do not fully address as a teaching design problem.

**Recommendation for section 4:** Council perspectives should note that the "no colored functions" advantage (Go goroutines look like regular functions, unlike async/await in Rust or Python) has a hidden cost for learners: the absence of coloring means there is no visual signal when code is concurrent. In async/await languages, the `await` keyword marks where concurrency happens; a learner can identify concurrent paths by scanning for keywords. In Go, concurrent execution paths are launched with `go` but may be buried in helper functions or middleware, providing no visual signal at call sites.

#### Section 6: Ecosystem and Tooling (onboarding)

The module system's history provides a pedagogical lesson about the cost of GOPATH. The pre-modules GOPATH model — which required all Go code to reside in a specific directory structure and conflated installation with development — was a significant onboarding obstacle that delayed new developers for hours. The detractor notes that the tool dependency management gap (the `tools.go` blank import hack) existed for approximately six years before the `tool` directive was added in Go 1.24. These are cases where simplicity in the language design did not extend to the ecosystem tooling, creating onboarding friction that was inconsistent with Go's reputation for approachability.

`gofmt` deserves specific pedagogical praise. By making formatting non-configurable, Go eliminates a category of micro-decision that new contributors to existing codebases face. A learner contributing to a Go open-source project does not need to match the project's formatting preferences; they run `gofmt` and the result is automatically correct. This is a meaningfully lower barrier than contributing to C++, Python, or JavaScript projects where style varies by project.

#### Section 11: Governance and Learning Stability

The Go 1 Compatibility Promise is an underappreciated pedagogical benefit. Tutorials, books, and video courses written for Go 1.x remain accurate for current Go 1.x. A learner following a five-year-old tutorial can expect the code to compile and run on current Go. This is not true for Python (2→3 breakage), JavaScript (perpetual ecosystem churn), or Rust (frequent edition-boundary changes). For self-directed learners relying on non-curated resources, Go's compatibility guarantee means that a Stack Overflow answer from 2016 is likely still correct — a property with significant practical educational value.

---

## Implications for Language Design

These observations from Go's pedagogical profile yield the following design implications, framed generically for language designers:

**1. The "two ramps" problem: initial simplicity can mask a subsequent complexity cliff.** Go's week-one experience and week-three experience are qualitatively different in difficulty. Languages that advertise a short learning curve should distinguish between time-to-first-program and time-to-production-quality-code. A language with genuinely short time-to-production is pedagogically different from one with short time-to-first-program. Designing the language so that the gap between these is small — by having the type system enforce production-quality constraints from the beginning — is pedagogically superior to a design where learners discover late-stage complexity as surprises rather than deliberate gates.

**2. Explicit but un-enforced discipline creates a false sense of safety.** Go's explicit error returns are intended to make errors visible and force handling. But the same mechanism permits silent discarding with a `_` assignment, and goroutine-launched functions silently drop errors by default. The discipline is explicit in the language's intent but not enforced by the type system. This creates a situation where learners who believe they are writing correct error-handling code may be making the same category of mistake the mechanism was designed to prevent. Language designers should distinguish between *explicit* discipline (the programmer must write the code) and *enforced* discipline (the compiler rejects incorrect code). Enforced discipline is pedagogically superior because it catches learner errors early.

**3. Un-enforceable patterns propagated through context parameters accumulate as technical debt.** The `context.Context` threading pattern is the canonical Go example: a convention that is universal, mandatory for correctness, but not enforced by the type system. Every function that accepts context must be called with a non-background context in production; there is no compiler error for passing `context.Background()`. Language designers who require convention-based correctness (rather than type-system-based correctness) should recognize that learners will violate conventions accidentally and that linters added after the fact are a weaker pedagogical intervention than type system constraints present at the start.

**4. Mandatory tooling eliminates a class of friction at low cost.** `gofmt` is the clearest example: by eliminating formatting choice entirely, Go made all Go code readable in the same style and eliminated a category of contribution barrier. The pedagogical implication is that mandatory tooling — controversial among experienced developers who have style preferences — dramatically reduces friction for new participants who lack confidence in their style choices. Language designers should consider that formatting wars are experienced most painfully by learners, not experts.

**5. Compatibility guarantees have substantial pedagogical value that is rarely enumerated in design discussions.** The Go 1 Compatibility Promise means that educational resources do not decay. A language design team that commits to compatibility is also committing to the continued validity of every tutorial, book, and course written in the language. This compounding benefit for learners grows with time. Language designers who maintain compatibility earn a learner ecosystem that grows richer over time; those who break compatibility periodically see their educational resources bifurcate and decay.

**6. Concurrency models that look sequential lower the entry barrier but require new failure-mode pedagogy.** Go's goroutines read as simple function calls (`go fn()`), which lowers the barrier to writing concurrent code. But the failure modes of concurrent programs — goroutine leaks, data races, unbounded channel operations — are not visible in the sequential-looking syntax. A language that hides concurrency complexity in the syntax must invest proportionally in helping learners develop mental models for the failure modes. Go's race detector is a good example of this investment; the absence of structured concurrency primitives that would prevent goroutine leaks is the corresponding gap. Designers of concurrent languages should design failure modes to be as visible as the happy path.

**7. Runtime errors that could be compile-time errors carry a multiplicative pedagogy cost.** The nil interface problem, the goroutine leak pattern, and the silently-dropped goroutine error are all cases where Go produces a correct-looking program that exhibits wrong behavior at runtime. Runtime failures are pedagogically harder than compile-time failures because they require: (1) constructing a test case that exercises the failure path, (2) interpreting a runtime error message, and (3) understanding the relationship between the failure and the code that caused it — often separated by call frames or goroutine boundaries. Language designers should treat each case of "this could be a compile error but is a runtime error" as a specific pedagogical cost that requires justification.

---

## References

[GO-FAQ] The Go Programming Language. "Frequently Asked Questions (FAQ)." https://go.dev/doc/faq

[GO-SURVEY-2024-H2] "Go Developer Survey 2024 H2 Results." The Go Programming Language Blog. https://go.dev/blog/survey2024-h2-results

[GO-SURVEY-2025] "Results from the 2025 Go Developer Survey." The Go Programming Language Blog. https://go.dev/blog/survey2025

[GO-SURVEY-2023-H2] "Go Developer Survey 2023 H2 Results." The Go Programming Language Blog. https://go.dev/blog/survey2023-h2-results

[GO-SURVEY-2024-H1] "Go Developer Survey 2024 H1 Results." The Go Programming Language Blog. https://go.dev/blog/survey2024-h1-results

[GO-SURVEY-2022-Q2] "Go Developer Survey 2022 Q2 Results." The Go Programming Language Blog. https://go.dev/blog/survey2022-q2-results

[GO-SURVEY-2020] Go Developer Survey 2020 Results. https://go.dev/blog/survey2020-results

[GO-ERROR-SYNTAX-2024] "On | No syntactic support for error handling." The Go Programming Language Blog, 2024. https://go.dev/blog/error-syntax

[GO-1-COMPAT] "Go 1 and the Future of Go Programs." The Go Programming Language. https://go.dev/doc/go1compat

[GO-124-RELEASE] "Go 1.24 Release Notes." The Go Programming Language. https://go.dev/doc/go1.24

[GO-126-RELEASE] "Go 1.26 Release Notes." The Go Programming Language. https://go.dev/doc/go1.26

[COX-CACM-2022] Cox, Russ, Robert Griesemer, Rob Pike, Ian Lance Taylor, and Ken Thompson. "The Go Programming Language and Environment." *Communications of the ACM*, 65(5):70–78, May 2022. https://cacm.acm.org/research/the-go-programming-language-and-environment/

[PIKE-ERRORS-2015] Pike, Rob. "Errors are values." The Go Programming Language Blog, January 12, 2015. https://go.dev/blog/errors-are-values

[PIKE-SPLASH-2012] Pike, Rob. "Go at Google: Language Design in the Service of Software Engineering." SPLASH 2012 keynote. https://go.dev/talks/2012/splash.article

[DOLTHUB-GENERICS-2024] "Why I'm Not Excited About Go Generics." DoltHub Blog, 2024. (Referenced via Detractor perspective — specific URL not available in brief.)

[PLANETSCALE-GENERICS-SLOWER] PlanetScale. "Go generics can make your Go code slower." 2022. (Referenced via Detractor perspective — specific URL not available in brief.)

[ARDANLABS-GOROUTINE-LEAKS] Ardan Labs. "Goroutine Leaks — The Forgotten Sender." (Referenced via Detractor perspective — specific URL not available in brief.)

[BOURGON-CONTEXT] Bourgon, Peter. "Context should go away for Go 2." 2017. (Referenced via Detractor perspective — specific URL not available in brief.)

[REDNAFI-STRUCTURED] Rednafi. "Structured concurrency in Go." (Referenced via Detractor perspective — specific URL not available in brief.)

[GOSURF-2024] "GoSurf: Identifying Software Supply Chain Attack Vectors in the Go Ecosystem." arXiv:2407.04442, 2024. (Referenced via Detractor perspective.)

[YOURBASIC-NIL] "The Go interface nil trap." yourbasic.org. (Referenced via Detractor perspective — specific URL not available in brief.)

[BENDERSKY-ADT] Bendersky, Eli. "Algebraic data types in Go." 2020. (Referenced via Detractor perspective — specific URL not available in brief.)

[GO-ERROR-WRAPPING] "Working with Errors in Go 1.13." The Go Programming Language Blog. https://go.dev/blog/go1.13-errors

[BRIEF-TESTIFY] Research brief notes `testify` as "community-standard assertion and mock library." https://pkg.go.dev/github.com/stretchr/testify

[BRIEF-RACE-DETECTOR] Research brief: race detector via `-race` flag using ThreadSanitizer. https://go.dev/doc/articles/race_detector

[GO-SURVEY-2024-H2-RESULTS] (Note: survey 2024 H2 is the same as GO-SURVEY-2024-H2 above — 93% satisfaction figure.)

---

*Document version: 1.0 | Prepared: 2026-02-27 | Role: Pedagogy Advisor | Language: Go*
