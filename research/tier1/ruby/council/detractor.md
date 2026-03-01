# Ruby — Detractor Perspective

```yaml
role: detractor
language: "Ruby"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## 1. Identity and Intent

Ruby's origin story is worth examining critically, because it reveals a design philosophy that explains both the language's enduring appeal and its structural limitations. Matsumoto designed Ruby to minimize his own surprise and maximize his joy. "I want to have fun in programming myself" [ARTIMA-PHILOSOPHY]. This is an aesthetic mission statement, not an engineering one.

The distinction matters. A language designed around programmer happiness will make different tradeoffs than a language designed around programmer correctness, or team maintainability, or system security, or operational predictability. Ruby consistently made the former tradeoffs. The result is a language that is genuinely delightful to write for one person for one day, and genuinely problematic to maintain for ten people over ten years.

The "principle of least surprise" that Matz invokes sounds rigorous but is not. Surprise is subjective. What surprises a Perl programmer differs from what surprises a Python programmer. The actual principle in practice was: "surprises Matz least." This produced a language where methods silently return the last evaluated expression, where any class can be reopened and modified by any code anywhere, where `nil` is a valid object that propagates through computation silently, and where exceptions are routinely used for control flow. Whether these behaviors are "surprising" depends entirely on your prior experience.

The lack of institutional sponsorship during Ruby's formative years is notable. Perl, Python, C, and Java all had varying degrees of institutional support that imposed engineering discipline alongside aesthetic preferences. Ruby was a personal project, and it shows. The language accumulated features that felt right without requiring that they be provably sound, statically analyzable, or consistently safe. This is not a moral failing on Matsumoto's part — he built what he wanted and shared it. It becomes a problem when organizations deploy Ruby at scale and discover that "designed for programmer happiness" does not translate to "designed for organizational reliability."

Ruby's success rode on Rails, not on the language itself. DHH built Rails, and Rails succeeded because of Rails' conventions — convention over configuration, database migrations, ActiveRecord — not because Ruby has superior language properties. The language benefited from being in the right place when a framework innovator needed a host. The question a language designer must ask is: if the next DHH chooses a different host, what are Ruby's independent merits?

The honest answer, from a detractor's position, is that Ruby's independent merits are real but narrower than the language's peak popularity implied. Ruby is an excellent scripting language with good metaprogramming facilities. It is a poor choice for systems programming, high-concurrency services, large-scale statically-analyzed codebases, or performance-sensitive applications. These were not use cases Matsumoto was targeting. The problem is that Rails' success drew Ruby into all of them.

---

## 2. Type System

Ruby's type system — or absence of one — is the correct starting point for any serious critique of the language. Ruby is dynamically typed by design, and this decision has compounded into a growing maintenance crisis for large Ruby codebases.

The core problem is not that dynamic typing is theoretically unsound. It is that Ruby's approach to dynamic typing includes a cluster of mutually reinforcing features that make static analysis systematically difficult:

**Open classes.** Any class — including Integer, String, Array, and every class from every gem — can be reopened and modified by any code in any file loaded at any point during program initialization. This means a type checker cannot reason about what methods are available on any object without first executing all the code that might modify those objects. The entire class hierarchy is mutable until the program ends. This is not a minor inconvenience for type inference; it is a fundamental barrier [RUBY-TYPING-2024].

**Method missing.** Objects can respond to arbitrary method calls by implementing `method_missing`. The canonical example is ActiveRecord's `find_by_name` / `find_by_email` interface — a beautiful DSL that is completely opaque to static analysis because the methods do not exist until `method_missing` is invoked. Every Rails codebase relies on this pattern.

**Dynamic dispatch everywhere.** `send`, `public_send`, and `respond_to?` create runtime-only dispatch paths. Code that routes through `send(method_name)` where `method_name` is a variable cannot be analyzed statically without knowing all possible values of `method_name`.

The consequence of this design is that Ruby generated two competing static analysis attempts that took 25+ years to materialize and have not achieved mainstream adoption. Sorbet (Stripe, 2019) uses inline type annotations (`T.sig`). RBS (Ruby 3.0, 2020) uses separate `.rbs` files. These approaches are architecturally incompatible — if your organization uses Sorbet, community-published RBS definitions are useful; if you use Steep + RBS, Sorbet's type signatures are irrelevant. Brandur Leach documented in 2024 that adoption of both remains limited and the ecosystem is fragmented between the two approaches [RUBY-TYPING-2024].

This fragmentation is itself a consequence of the language design. Because the language never made types a first-class citizen, the community splintered around two different retrofit approaches. Neither has the momentum to become the standard. Contrast this with TypeScript, which succeeded by creating a single canonical path to types for JavaScript, or Kotlin, which adopted a coherent type system from day one rather than retrofitting.

TypeProf — the official type inference tool bundled with Ruby — attempts to infer types from untyped code. The tool is real and working, but type inference over open classes with method_missing is not a tractable problem. TypeProf necessarily produces incomplete or conservative results on real Rails codebases.

The practical consequence for large Ruby teams is that refactoring is more dangerous than it needs to be. A developer changing a method signature in a Ruby codebase without type annotations must rely on test coverage to discover all call sites. Test coverage in Ruby codebases is famously uneven; the academic study of Stack Overflow data found that "Application Quality and Security was challenging for over 40% of experienced developers" [ARXIV-RUBY-2025]. Experienced developers, not beginners. The type system is not just a beginner problem.

There are no generics, no interfaces, no formal trait mechanism. Modules serve as informal interfaces, but they are not enforced. A class can `include Comparable` without implementing `<=>`, and the error occurs at runtime when comparison is attempted, not at load time.

**Structural assessment:** These are not fixable without breaking the language. Open classes, method_missing, and dynamic dispatch are not incidental features — they are how Rails works. Removing them would require rewriting the most important framework in the ecosystem. The type system problems are permanent.

---

## 3. Memory Model

Ruby's memory model is automatic GC — sensible in principle, problematic in the specific implementation details that compound over time.

The most immediate cost is object overhead. Every Ruby object (RVALUE) is 40 bytes on 64-bit systems regardless of its content [RUBY-GC]. An integer in Ruby is a full 40-byte heap-allocated RVALUE (for values that don't fit in a fixnum pointer tag). An array of 10,000 integers carries 400KB of object overhead before accounting for the array structure itself. Ruby does use pointer tagging for small integers (fixnums) and some symbols, but the baseline overhead for any heap-allocated value is substantial.

This overhead shows up directly in production: Rails applications typically consume 200–600MB per process at steady state [RUBY-RESEARCH-BRIEF]. A single Rails process serving moderate traffic represents a meaningful cloud infrastructure cost. Organizations running many Rails processes must budget significantly more memory than equivalent Go or Java services for the same workload.

The GC evolution tells a story of reactive improvement rather than proactive design. Ruby pre-2.1 used non-generational mark-and-sweep, causing full GC pauses for every collection. Ruby 2.1 added generational collection. Ruby 2.2 added incremental collection to reduce maximum pause time. Ruby 3.4 introduced a modular GC framework because the default GC had known limitations that justified a plugin architecture [RUBY-3-4-RELEASE]. This is 20+ years of iteration on a problem that other languages (Java, Go, .NET) had addressed more systematically earlier.

GC pause unpredictability remains a real production problem. Production Rails teams regularly tune GC parameters (`GC.compact`, `RUBY_GC_HEAP_GROWTH_FACTOR`, `RUBY_GC_HEAP_INIT_SLOTS`) to reduce latency spikes. This tuning requires expertise. The research brief notes that `memory_profiler` and Datadog's allocations profiler are commonly used to diagnose memory issues [DATADOG-RUBY-ALLOC] — a healthy tool ecosystem around a persistent problem.

`GC.compact`, introduced in Ruby 2.7, compacts the heap to reduce fragmentation. Its existence is an acknowledgment that the GC's fragmentation was bad enough to require a dedicated compaction step. Compaction is not free: it must be called explicitly, it requires the heap to be in a consistent state, and it introduces its own pause.

C extensions represent a systematic GC blindspot. CRuby has no visibility into memory allocated by C extensions outside the Ruby heap. A leaking C extension leaks from Ruby's perspective — the GC cannot collect what it cannot see. Memory profiling in codebases with C extensions requires native debugging tools in addition to Ruby-level profiling.

The modular GC introduced in Ruby 3.4 is the most honest recent acknowledgment of these problems: the default GC is not optimal for all workloads, and users need a way to swap it out without patching CRuby. This is reasonable engineering, but it also means that Ruby's memory story requires more user configuration than it should for a language premised on minimal developer friction.

**Structural assessment:** High per-object overhead is structural — it is tied to the RVALUE representation and would require pervasive changes to CRuby to address. GC pause behavior is improvable but not eliminable. The C extension blindspot is a consequence of the FFI architecture.

---

## 4. Concurrency and Parallelism

The Global VM Lock (GVL, historically GIL) is Ruby's most consequential structural limitation. It deserves extended treatment because it exemplifies the pattern of a design decision that seemed acceptable in 1993 and became a strategic liability by 2010.

The GVL ensures that only one thread executes Ruby bytecode at a time. Threads can run in parallel during blocking I/O (the GVL is released during I/O, sleep, and some C extension calls), but not during CPU-bound computation [GVL-SPEEDSHOP]. For a language primarily used for web applications — which are I/O bound — this is a real but mitigatable limitation. For any CPU-bound workload, it is a hard ceiling.

Matsumoto has declined to remove the GVL. Jean Boussier (byroot), a Shopify core contributor who thinks carefully about Ruby performance, published a detailed technical analysis in January 2025 explaining the barriers: per-object locks, atomic reference counting, and widespread C extension refactoring would be required [BYROOT-GVL-2025]. Boussier's conclusion was not that removal is impossible but that it is prohibitively expensive given the current C extension ecosystem. This is honest engineering analysis. It is also an admission that the GVL is permanent for practical purposes.

The response to the GVL has been Ractors, introduced experimentally in Ruby 3.0 in December 2020 [RUBY-3-0-RELEASE]. Ractors provide parallel execution by running in separate GVL domains, enabling true CPU parallelism. The constraints are severe: Ractors cannot share mutable state; objects must be frozen or explicitly moved/copied between Ractors; most C extensions are incompatible.

Five years after introduction, Ractors are not production-ready for most use cases [DEVCLASS-RUBY-4]. This is not a minor delay. Ruby 4.0 (December 2025) changed the Ractor communication API — removing `Ractor.yield`/`Ractor#take` in favor of `Ractor::Port` — which signals that the design was still fluid enough to require breaking API changes [RUBY-4-0-RELEASE]. An experimental feature whose API is still changing after five years of availability is not a feature being stabilized; it is a research direction.

The C extension compatibility problem is the core Ractor barrier, and it is self-reinforcing. Many popular gems include C extensions (nokogiri, mysql2, pg, bcrypt, etc.). These gems cannot be used inside Ractors without significant porting work. Until the gems are ported, production systems cannot use Ractors for their most common workloads. Until there is production demand, gem maintainers have limited incentive to do the porting work. Ractors are stuck in this loop.

The M:N thread scheduler introduced in Ruby 3.3 maps M Ruby threads to N native OS threads [RUBY-3-3-RELEASE]. This reduces thread management overhead and is a genuine improvement. It is also disabled on the main Ractor by default due to — C extension compatibility concerns. The same root problem.

Alternative implementations solve the GVL problem. JRuby (JVM) has no GVL and achieves true thread parallelism. TruffleRuby (GraalVM) achieves similar results. Both are production-ready for many workloads. The problem is that JRuby and TruffleRuby have their own compatibility challenges, require different deployment infrastructure, and the Ruby community largely develops and tests against CRuby. The "just use JRuby" answer is technically valid but practically unsatisfying — it means that the canonical implementation of the language cannot use multiple CPU cores for Ruby computation.

Fibers provide cooperative concurrency within a single thread. The Fiber Scheduler interface (Ruby 3.0) enables transparent async I/O switching via gems like `async`. For I/O-bound workloads, this is genuinely useful. But cooperative concurrency is not parallelism, and it requires opt-in from the entire call stack — every library that makes network or file I/O calls needs to be fiber-aware for the scheduler to work properly. Adoption remains incomplete.

**Structural assessment:** The GVL is permanent in CRuby for practical purposes. Ractors are a five-year-old experiment that remains pre-production. Ruby is not a good choice for CPU-parallel workloads. This is a structural limitation that language designers should design around from the start, not retrofit.

---

## 5. Error Handling

Ruby's error handling model is exception-based, and the problems with this model are well-documented in theory and observable in practice.

The core mechanism uses `raise` and `rescue`. The inline rescue modifier — `value = risky_call rescue default` — is the most dangerous feature in this section: it silently catches any StandardError from `risky_call` and returns `default`, with no information about what went wrong, no logging, no re-raise. It is a syntax-level encouragement to swallow errors. The fact that it is documented as a common anti-pattern [RUBY-ERROR-HANDLING] does not change that it is available, commonly taught to beginners, and routinely misused.

The exception hierarchy introduces a specific and common mistake: `rescue Exception` catches `SignalException`, `SystemExit`, and `Interrupt`, which means code using `rescue Exception` will catch Ctrl-C and process kill signals, preventing normal program termination. This is documented as bad practice [RUBY-SECURITY], but the language provides no syntax to prevent it. The correct form (`rescue StandardError`) is non-obvious to beginners. The incorrect form (`rescue Exception`) appears in tutorials, blog posts, and production code.

Ruby lacks a `Result` type. Error communication conventions are informal: a method might raise an exception, return `nil`, return `false`, or raise a domain-specific error — depending on the gem author's preferences. The `!`-suffix convention (e.g., `save` returns false on failure, `save!` raises on failure) provides some signal, but it is convention, not enforcement. A caller cannot know from a method's type signature whether that method can fail and what form failures take without reading documentation.

The nil propagation problem is related. Ruby does not have an `Option` type. Nil is a valid object with methods (`nil.class # => NilClass`, `nil.nil? # => true`), but it does not compose safely. Calling a non-nil method on nil raises `NoMethodError`. In practice this means that nil propagates silently through a chain of method calls until something attempts to use the nil result, producing an error that is often far from the nil-producing call. Ruby 2.3 added the safe navigation operator (`&.`) to propagate nil explicitly (`user&.profile&.avatar_url`), which is a genuine improvement but teaches the wrong lesson — it normalizes nil as a plausible return value rather than making absence explicit.

Pattern matching, stabilized in Ruby 3.0 and expanded since, enables result-like deconstruction:

```ruby
case risky_operation
in { success: value }
  use(value)
in { error: msg }
  handle(msg)
end
```

This is useful, but it requires gem authors to adopt a consistent result-shape convention, and the Ruby ecosystem has not converged on one. ActiveRecord raises exceptions; other ORMs return nil; custom service objects use various result patterns. The ecosystem fragmentation means developers encounter all three error communication styles in a single application.

**Structural assessment:** Exceptions as primary error mechanism is a design choice that composes poorly at scale. The nil problem is partially mitigated by `&.` but not solved. The lack of a standard Result type is an ecosystem problem that could be addressed by community convergence but has not been. The inline rescue modifier is a footgun that cannot be removed.

---

## 6. Ecosystem and Tooling

The Ruby ecosystem has real strengths (RubyGems, Bundler, RuboCop, RSpec) alongside persistent structural weaknesses.

**Dependency management complexity.** Gem Installation and Configuration Issues was identified as the most challenging topic for Ruby developers in the academic study of Stack Overflow data [ARXIV-RUBY-2025]. This is the most commonly cited challenge — not concurrency, not performance, not type safety, but installing gems. The problems are well-known: native extensions require system-level build tools; version constraints create dependency conflicts; the `Gemfile.lock` mechanism works well but produces "it works on my machine" situations during environment setup. After 20+ years of maturation, gem installation remains the top developer complaint.

**Ruby version proliferation.** The proliferation of Ruby version managers (rbenv, asdf, RVM, chruby) is symptomatic of a tooling ecosystem that evolved organically rather than by design. In 2024, RVM is explicitly declining while rbenv and asdf are ascending [RAILS-SURVEY-2024]. The existence of four actively used version managers for a single language represents fragmentation that forces developers to navigate compatibility between version managers, shell integrations, and CI/CD environments. This is a solved problem in languages with official version management tooling.

**Governance dispute.** In October 2025, the Ruby core team — led by Matz — assumed stewardship of RubyGems and Bundler from Ruby Central following a governance dispute [RUBY-RUBYGEMS-TRANSITION]. The community reception was "generally positive" but "trust in Ruby Central as a steward organization was damaged" [SOCKET-RUBYGEMS-STEWARDSHIP]. The fact that the primary steward of the Ruby package ecosystem required a leadership intervention to resolve a governance failure is not a minor incident. It reveals that the institutional infrastructure around Ruby is fragile in ways that do not become visible until they break.

**No formal RFC process.** Language changes are discussed on the ruby-core mailing list and Ruby issue tracker without a structured proposal and review process [RUBY-RESEARCH-BRIEF]. Compare with Rust's RFC process, Python's PEP process, or Kotlin's KEEP process. An unstructured discussion process tends to produce decisions driven by the most vocal participants or, in a BDFL model, by Matz's personal aesthetic preferences. This is fine when the BDFL is available and engaged; it is a bottleneck when the BDFL is unavailable and a risk when the BDFL's preferences differ from the engineering consensus.

**IDE support inferiority.** Ruby's metaprogramming features that make Rails DSLs beautiful make IDE tooling difficult. The Ruby LSP project and Solargraph provide language server support, but the fundamental problem is that IDEs cannot reliably determine what methods are available on an object when those methods may be defined dynamically or inherited from modules mixed in at runtime. Autocomplete, go-to-definition, and refactoring tools are systematically less reliable in Ruby than in statically-typed languages. Developers who switch from Java, Kotlin, or TypeScript to Ruby frequently cite the quality degradation in tooling as a significant adjustment.

**Rails monoculture.** The Ruby ecosystem is Rails-centric to a degree that is unusual among languages. 83% of Rails developers in 2024 felt the core team was shepherding the project correctly; 93% felt confident about security [RAILS-SURVEY-2024]. These are positive sentiments, but they mask a deeper dependence: Ruby as a language is largely perceived through the Rails lens. Languages that are primarily known for one framework are fragile — if Rails declines, Ruby's relevance declines with it. There is no dominant non-Rails use case that would sustain Ruby's community if Rails lost market share significantly.

---

## 7. Security Profile

Ruby's security profile has two distinct layers: the language's inherent vulnerability patterns, and the ecosystem's supply chain exposure. Both warrant critical attention.

**Language-level attack surfaces.** Ruby's design philosophy of "everything is callable, everything is modifiable" creates attack surfaces that do not exist in less dynamic languages:

`Kernel#open` is the canonical example. Called with user-supplied input beginning with `|`, it executes an arbitrary OS command. This is documented, well-known, and continues to appear in production codebases [BISHOPFOX-RUBY]. The method has existed for decades and cannot be removed without breaking backward compatibility.

`Object#send` with untrusted input allows arbitrary method invocation on any object. `object.send(user_input, *args)` where `user_input` is attacker-controlled can invoke any public method, including `eval`, `system`, `exec`, or custom administrative methods. Again: documented, well-known, structurally impossible to eliminate without removing send [BISHOPFOX-RUBY].

YAML deserialization has been a persistent RCE vector. YAML's default parser in Ruby supports arbitrary object construction — loading YAML from untrusted input can result in arbitrary Ruby code execution. This is not a theoretical concern; it was the basis of significant Rails vulnerabilities (pre-Rails 4 mass assignment combined with YAML serialization created widely-exploited RCE chains) [RAILS-RCE-CODECLIMATE].

ReDoS is a recurring pattern in the standard library. The CVE record shows multiple ReDoS vulnerabilities in standard library components: the `date` gem through 3.2.0, the `uri` component before 0.12.2, and others [RUBY-CVE-REDOS]. These arise because Ruby's regex engine supports backtracking, and the standard library has repeatedly failed to sanitize regex patterns applied to user input. The pattern is structural — any dynamically constructed regex applied to untrusted input is a potential ReDoS vector.

**The $SAFE failure.** Ruby 1.x and 2.x included `$SAFE` taint tracking — a mechanism to restrict operations on data derived from untrusted sources. Ruby 3.0 removed $SAFE entirely, with the official explanation that "it did not provide reliable security guarantees" [RUBY-3-0-RELEASE]. This is an acknowledgment that a 20-year-old security feature was security theater. For any codebase that relied on $SAFE for isolation, Ruby 3.0 was a forced security audit. The $SAFE failure is also a lesson in incomplete security mechanisms: a taint system that tracks taints but cannot enforce safety at the execution level is not a security primitive — it is a documentation mechanism.

**Open class as attack surface.** The open class mechanism creates a supply chain attack surface that does not exist in languages with sealed class hierarchies. A malicious gem that is loaded into a Ruby process can reopen String, Integer, Array, or any other class and inject malicious behavior into any method. This is not a theoretical concern — it is the mechanism by which sophisticated supply chain attacks operate.

**Supply chain incidents.** The RubyGems.org supply chain record is poor:

- February 2020: 700+ malicious gems uploaded over approximately one week; typosquatted variants of legitimate names; contained cryptocurrency wallet address hijacking malware; downloaded 95,000+ times before removal [THN-TYPOSQUAT-2020].
- 2023–2025: 60+ malicious packages posing as social media/messaging automation tools; active since at least March 2023; cumulative downloads exceeding 275,000; designed to steal credentials [REVERSINGLABS-GEMS].
- 2025: Malicious gems exploiting developers circumventing Vietnam's Telegram ban; intercepted CI/CD pipeline credentials [SOCKET-MALICIOUS-GEMS].
- August 2025: Simultaneous RubyGems and PyPI malicious package campaign [THN-GEMS-2025].

The frequency and scale of these incidents reflects both the attractiveness of RubyGems as a supply chain attack surface and the insufficiency of the defenses deployed. As of early 2026, RubyGems does not require two-factor authentication for all gem publishers, does not provide reproducible builds, and has limited automated malware detection.

---

## 8. Developer Experience

Ruby's developer experience is genuinely good along several dimensions and genuinely poor along others. The split maps predictably onto the language's design philosophy.

**Where it's good.** The language is readable, expressive, and fast to prototype in. The block/closure syntax enables DSLs (like Rails routing, RSpec test definitions, Rake tasks) that read like natural language. Irb and Pry provide interactive development loops. RuboCop, once configured, provides consistent style enforcement. The community is mature and has produced extensive documentation, tutorials, and conference talks.

**The expressiveness trap.** Ruby's expressiveness has a cost that becomes visible at scale. The same features that make Rails DSLs readable — open classes, method_missing, extensive use of blocks and procs — make code difficult to reason about as a codebase grows. A developer new to a Rails codebase encounters patterns like:

```ruby
class User < ApplicationRecord
  has_many :orders
  validates :email, presence: true, uniqueness: true
  scope :active, -> { where(active: true) }
  before_save :normalize_email
end
```

The methods `has_many`, `validates`, `scope`, and `before_save` are defined by ActiveRecord via metaprogramming. None of them appear in any source file that IDE tooling can navigate to. "Go to definition" leads nowhere. What do they return? What do they accept? What happens when `normalize_email` raises? These questions require understanding multiple layers of Rails metaprogramming to answer.

**The learning curve paradox.** Ruby is marketed as easy to learn, and initial syntax acquisition is genuinely accessible. But the research brief notes that "Core Ruby Concepts was found particularly difficult by 31.6% of developers" and "Gem Installation and Configuration Issues was identified as the most challenging topic" [ARXIV-RUBY-2025]. The language is easy to start and hard to master. The gap between "writing Ruby" and "writing good Ruby" is larger than it appears because the language allows many ways to do the same thing, all of which will produce working code in happy-path scenarios and diverge in error-handling and edge cases.

**The satisfaction reversal.** In the 2022 Stack Overflow survey, 49.99% of Ruby respondents "loved" the language and 50.01% "feared" it — an even split [TMS-RUBY-STATS]. This contrasts with Ruby's earlier reputation as a beloved language. By 2024, Ruby no longer appears in the top lists for "most loved" or "most admired" languages [ARXIV-RUBY-2025]. JetBrains classified Ruby as in "long-term decline" alongside PHP and Objective-C [JETBRAINS-2025]. TIOBE ranked Ruby 24th in April 2025, described as having "fallen out of the top 20" and being "unlikely to return anytime soon" [TIOBE-2025].

The trajectory is clear: Ruby peaked in developer satisfaction and community engagement around 2012, when the Stack Overflow data shows approximately 6% user engagement, and declined to approximately 2% by 2020 [ARXIV-RUBY-2025]. New developers are choosing Python, TypeScript, and Go instead. Ruby's job market remains strong relative to its developer population size (Stack Overflow 2024 ranked Ruby 5th for compensation [ARXIV-RUBY-2025]) — but this reflects the supply of Ruby developers shrinking faster than the demand from existing Rails shops.

**Tooling inferiority.** Developers who switch from Kotlin, TypeScript, or Java to Ruby consistently report degraded tooling quality. The Ruby LSP extension for VS Code (44% of Rails developers in 2024 [RAILS-SURVEY-2024]) provides basic language server support, but the fundamental limitation is that the language's dynamism makes many IDE features — precise autocomplete, reliable refactoring, type-aware navigation — best-effort rather than precise.

---

## 9. Performance Characteristics

Ruby's performance characteristics are a significant weakness, and the framing around recent improvements deserves critical examination.

**The baseline problem.** Ruby is consistently 5–50× slower than C on computational benchmarks [CLBG]. YJIT's headline number — "92% faster than interpreter on x86-64 benchmarks" [RAILSATSCALE-YJIT-3-4] — sounds dramatic but is misleading as a standalone claim. A 92% speedup over the interpreter means YJIT runs approximately 2× faster than the interpreter. If the interpreter was 40× slower than C, YJIT is now 20× slower than C. The gap has narrowed; it has not closed.

The TechEmpower Framework Benchmarks (Round 23, March 2025) are more relevant for production web applications. Ruby frameworks (Rails, Sinatra) occupy the lower performance tiers alongside Python Django and PHP Laravel, while Rust-based frameworks dominate the top positions [TECHEMPOWER-ROUND-23]. This is not a cherry-picked benchmark — TechEmpower measures multiple test categories (plaintext, JSON, database queries, fortunes, data updates) and the pattern is consistent across categories.

**Startup time.** Rails application startup time of 1–10 seconds [RUBY-RESEARCH-BRIEF] is catastrophic for serverless deployment models. AWS Lambda, Google Cloud Functions, and Azure Functions optimize for millisecond-scale cold starts. A 5-second Rails startup time means a Lambda function cannot be practically built on Rails — every cold invocation adds seconds of latency. This is not a theoretical concern; it is why Ruby/Rails is largely absent from the serverless ecosystem, and why organizations building cloud-native, event-driven architectures choose Go, Java, or Node.js instead.

**Memory footprint.** Rails applications at 200–600MB per process [RUBY-RESEARCH-BRIEF] are expensive in cloud economics. Container-based deployments (Kubernetes, ECS) price per pod memory. A fleet of Rails processes serving moderate traffic can cost significantly more than an equivalent Go or Java service stack. The 40-byte per-object overhead [RUBY-GC] is a direct contributor that cannot be addressed without changing the core object representation.

**YJIT's actual production impact.** Shopify's YJIT results are real and impressive within their context. Shopify processed $11.5 billion in sales during Black Friday/Cyber Monday 2024 using YJIT [RAILSATSCALE-YJIT-3-4]. YJIT is a genuine engineering achievement. However, the production improvement numbers are calibrated against unoptimized Ruby: 15–25% for real-world Rails applications, with some CPU-intensive workloads exceeding 40% [UPDOWN-RUBY-3-3]. These are meaningful improvements that reduce Shopify's infrastructure costs. They do not change Ruby's fundamental performance positioning relative to compiled languages.

**ZJIT is not ready.** ZJIT, the new experimental method-based JIT introduced in Ruby 4.0, is explicitly "not production ready" according to the Ruby 4.0 release commentary [DEVCLASS-RUBY-4]. Ruby 4.0 was released in December 2025. The major new JIT compiler is not production ready. This pattern — headline feature, "experimental" label, years to stabilization — has repeated with YJIT (introduced experimentally in 3.1, production-ready in 3.2) and now with ZJIT.

**Alternative implementations address performance, at a cost.** JRuby and TruffleRuby achieve significantly better performance on many workloads. TruffleRuby's peak performance often exceeds CRuby with YJIT [TRUFFLERUBY-CEXT]. But alternative implementations require different deployment infrastructure, have different gem compatibility profiles, and are not the default. The existence of higher-performance implementations is not an argument that CRuby is fast; it is an argument that the performance problems are solvable at the cost of ecosystem fragmentation.

---

## 10. Interoperability

Ruby's interoperability story is functional but carries systematic costs.

**C extension compatibility as a perpetual constraint.** The GVL, Ractor limitations, M:N scheduler defaults, and every other concurrency improvement in recent Ruby history has been constrained by C extension compatibility. The CRuby C extension API gives C code direct access to Ruby internals: RVALUEs, the GVL, the object heap. This enables high-performance native extensions but creates a coupling that makes the interpreter difficult to evolve. Every architectural change must be threaded through C extension compatibility, or it will break gems that production systems depend on.

JRuby and TruffleRuby have addressed this by re-implementing the C extension API: JRuby includes native C extension support via CRuby API emulation; TruffleRuby uses Sulong (an LLVM interpreter) to run C extensions [TRUFFLERUBY-CEXT]. These solutions work, but they introduce indirection that affects performance and compatibility.

**FFI.** The `ffi` gem provides Foreign Function Interface support — the ability to call native shared libraries from Ruby without writing a C extension. JRuby and TruffleRuby ship with FFI built-in; CRuby requires the gem [FFI-README]. FFI is a genuine improvement over raw C extensions for straightforward library wrapping, but it does not cover all use cases (particularly where Ruby objects need to be accessible from C code).

**Rails as an interoperability surface.** Ruby's primary interoperability story in practice is "Rails interoperates with other web services via HTTP." This is true but narrow. Ruby is not a language you embed in other systems, use for systems programming, or drop into polyglot data pipelines without significant friction. The language's strength is monolithic web applications; it is not a composable building block in heterogeneous architectures.

**WebAssembly.** Ruby 3.2 added WebAssembly support via WASI [RUBY-3-2-RELEASE]. This is a genuine expansion of Ruby's deployment targets. However, YJIT does not work in WebAssembly environments, meaning WASM Ruby runs without the primary performance improvement. The startup time and memory footprint problems are compounded in a WASM context.

**The ISO standard drift.** Ruby's ISO standard (ISO/IEC 30170:2012) covers Ruby as of the 1.8/1.9 era and has not been updated [ISO-30170]. CRuby 3.x and 4.x diverge significantly from the standardized subset. For organizations that require language-level standardization (government contracts, certain regulated industries), this means Ruby is effectively unstandardized. This contrasts with C (C17, C23 standards actively maintained), Java (JLS updated with each LTS release), and C++ (C++23 finalized). The Ruby standard exists primarily as a historical artifact.

---

## 11. Governance and Evolution

Ruby's governance structure is a benevolent dictatorship with a single point of failure. Understanding this structure is essential for assessing Ruby's long-term trajectory.

**BDFL model.** Matsumoto holds final authority over Ruby's direction. He stated explicitly in 2025: "Version numbering decisions are completely a decision for Matz to make as he wishes." [RUBY-ISSUE-21657]. This is clear, consistent, and historically functional. It is also a fragility: a language whose design authority rests entirely with one person has a bus factor of one. Matz's long-term engagement is not in question — he has been actively involved for 30+ years. But the BDFL model means that Ruby's direction can diverge from engineering consensus if Matz's aesthetic preferences conflict with what the community needs. The GVL decision is the clearest example: the engineering community broadly agrees that true parallelism is necessary; Matz has declined to prioritize GVL removal.

**No formal proposal process.** Ruby lacks the equivalent of Rust's RFCs, Python's PEPs, or Kotlin's KEEPs. Language changes are discussed on the ruby-core mailing list and the bug tracker. This produces decisions that emerge from informal consensus and BDFL approval rather than from a structured review process with defined acceptance criteria. The lack of a formal process makes it difficult for the broader community to participate meaningfully in language design, and makes it harder to understand why specific decisions were made or rejected.

**Ruby Central governance failure.** The October 2025 governance dispute that led to Matz and the Ruby core team assuming control of RubyGems.org and Bundler from Ruby Central is a significant event. The details of the dispute are not public, but the outcome — a forced leadership transition in the organization responsible for the language's package infrastructure — reveals institutional fragility [RUBY-RUBYGEMS-TRANSITION]. Trust in Ruby Central was damaged [SOCKET-RUBYGEMS-STEWARDSHIP]. A language ecosystem where the package infrastructure requires a BDFL intervention to remain functional is not a robust institutional structure.

**Rate of change.** Ruby's annual December 25 release cadence is disciplined and predictable. The 3.x era delivered meaningful improvements: YJIT, Ractors, pattern matching, RBS, Fiber scheduler, M:N threading. The pace of fundamental improvement is real. However, the pattern of releasing features as "experimental" and requiring multiple release cycles for stabilization (Ractors, YJIT, ZJIT) means that the advertised features often lag actual usability by 2–3 years.

**Backward compatibility inconsistency.** Ruby does not have a Go 1 Compatibility Promise or equivalent. The 3.x → 4.0 transition removed $SAFE, SortedSet, Ractor.yield/Ractor#take, and various 3.x deprecations. These are not large breakages, but they require upgrade work. More significantly, the minor-to-minor upgrade path (3.2 → 3.3 → 3.4) has occasionally introduced behavioral changes that break gems with strong assumptions about internal behavior. The community characterizes Ruby 4.0 as "a lot of restructuring under the hood, few new features" [HEISE-RUBY-4], which is an accurate description and also a sign that the language is managing accumulated technical debt rather than advancing its capabilities.

**Shopify dependency.** Shopify is the primary patron for YJIT and ZJIT development, employing Jean Boussier, John Hawthorn, and the YJIT team [SHOPIFY-YJIT]. This is healthy corporate contribution in one sense; in another sense, it means that CRuby's JIT strategy is significantly driven by one company's production needs. Shopify's needs are large-scale monolithic Rails; this shapes what YJIT and ZJIT optimize for. Other Ruby use cases are less represented.

---

## 12. Synthesis and Assessment

### Greatest Strengths

Ruby's genuine strengths should be stated plainly. The language is expressive, readable, and productive for web application development. Rails remains one of the most productive web frameworks in existence for conventional CRUD applications. The RubyGems ecosystem has real breadth, particularly for web-adjacent tooling. YJIT represents significant engineering investment and real performance improvement. The community is mature and the language has survived 30 years, which is non-trivial.

### Greatest Weaknesses

**The GVL is the most important structural failure.** Ruby cannot execute Ruby code in parallel on multiple CPU cores in the canonical implementation. Ractors are five years old and not production-ready. This is a permanent limitation for CRuby that makes Ruby a poor choice for any CPU-parallel workload. Alternative implementations (JRuby, TruffleRuby) solve it at the cost of ecosystem fragmentation.

**The type system is structurally hostile to static analysis.** Open classes, method_missing, and dynamic dispatch are not incidental features — they are how the most important frameworks work. Static type checking for real Ruby codebases is incomplete by definition. Two competing toolchains (RBS+Steep and Sorbet) have fragmented the community without achieving mainstream adoption in either direction. Large Ruby codebases carry significant maintenance risk from undetected type errors.

**The ecosystem is in long-term decline relative to alternatives.** JetBrains' 2025 classification of Ruby as in "long-term decline" alongside PHP and Objective-C [JETBRAINS-2025] matches the TIOBE trajectory (dropped from top 20 [TIOBE-2025]) and the Stack Overflow engagement data (6% peak in 2012, ~2% by 2020 [ARXIV-RUBY-2025]). The compensation premium reflects shrinking supply, not growing demand.

**Security posture is poor by design.** `Kernel#open`, `Object#send`, open classes, YAML deserialization, $SAFE removal — Ruby's security vulnerabilities cluster around deliberate design decisions (maximum flexibility, everything callable). The supply chain record is significantly worse than peer languages: multiple large-scale malicious gem campaigns with 275,000+ total downloads [REVERSINGLABS-GEMS].

**Governance is fragile.** Single-person BDFL authority, no formal proposal process, Ruby Central governance dispute requiring Matz intervention in 2025 — these are institutional fragilities that become visible under stress.

### Dissenting Views

*On the GVL:* The apologist position is that most production Ruby workloads are I/O bound, and the GVL's practical impact on web applications is limited. This is partially true. But it ignores that web application workloads are evolving — more CPU-intensive computation (image processing, ML inference, data aggregation) is moving into application servers, and the GVL becomes a bottleneck precisely as workloads evolve.

*On static typing:* The apologist position is that Rails applications can be written to production quality without static types, and teams with good test discipline manage refactoring safely. This is true for teams with exceptional discipline. It does not account for the long tail of real codebases where test discipline is imperfect and refactoring safety is a real cost.

*On performance:* The apologist will note that most Rails applications are database-bound, not CPU-bound, and that YJIT's improvements are meaningful in production. This is true and fair. But startup time and memory footprint are not database-bound; they affect cloud economics and deployment models regardless of where the bottleneck is.

### Lessons for Language Design

**1. Aesthetic design philosophy requires engineering guardrails.**
Designing a language around programmer happiness without complementary constraints on correctness and maintainability produces a language that is delightful at small scale and difficult at large scale. The specific lesson: design decisions should be evaluated not only for individual-developer ergonomics but for team-scale maintainability over time. A feature that makes one developer happy today can make a team of twenty developers frustrated for years.

**2. Static type systems must be designed in, not retrofitted.**
Ruby's RBS + Sorbet situation illustrates the failure mode of bolted-on typing: two incompatible approaches, neither achieving mainstream adoption, 25 years after the language shipped. A language that might need to scale to large teams should provide a coherent static type story from the beginning. The retrofit cost is not just technical — it is social; competing toolchains fragment community effort and create ecosystem incompatibilities.

**3. Open class semantics make sound static analysis impossible.**
The ability to reopen any class at runtime is fundamentally incompatible with precise static type checking. Any language that wants both metaprogramming expressiveness and static safety must draw the line explicitly — either with sealed classes, explicit extension points, or a type system that models open classes while preserving soundness guarantees. Ruby chose full openness; the cost is a permanently incomplete type story.

**4. Concurrency primitives require first-class design, not afterthought retrofitting.**
The GVL was acceptable in 1995 when multi-core machines were rare and web servers were single-threaded. By 2010, it was a strategic liability. Retrofitting parallelism via Ractors onto a language designed around mutable shared state took 5+ years of development and still produced a feature that is pre-production a decade after the need was obvious. New language designs should treat concurrency and parallelism as first-class concerns from the beginning, with a coherent memory model that enables safe parallel execution.

**5. "Result type vs. exception" is a false choice if you fail to commit.**
Ruby uses exceptions for control flow, nil for soft failures, and domain-specific conventions (e.g., `!` methods) for predictable failures. The lack of a standard Result type means that error handling conventions vary across every library and are invisible to the type system. A language designer should commit to a coherent error propagation model and enforce it. Languages that mix exception-based and value-based error handling without a clear hierarchy create codebases where error handling is inconsistent by default.

**6. Supply chain security requires institutional design, not incident response.**
The repeated RubyGems supply chain incidents (2020, 2023–2025) reveal that the package registry was not designed with adversarial supply chain attacks as a threat model. Publisher verification, automated malware scanning, and reproducible builds should be designed into package registries from the beginning, not added reactively after incidents that affect hundreds of thousands of downloads. The attack surface for malicious packages scales with ecosystem size; defenses must scale proactively.

**7. BDFL governance is a bus-factor risk and an engineering constraint.**
Single-person authority over a language produces fast decisions and aesthetic coherence. It also means that one person's preferences can override engineering consensus — the GVL situation being the clearest example. A language with institutional ambitions should design a governance process that can outlast any individual, accept input from multiple stakeholders, and make decisions transparently. Rust's RFC process is a model; it adds friction but produces more durable decisions.

**8. Version management should be a first-class language concern.**
The proliferation of Ruby version managers (RVM, rbenv, asdf, chruby) is a symptom of the language not specifying how its runtime should be managed. Each version manager implements slightly different behaviors, creates different shell integrations, and introduces different failure modes. Languages that grow beyond scripting use should specify version management as part of their distribution strategy.

**9. Startup time and memory footprint are first-class performance concerns.**
Ruby's 1–10 second Rails startup time and 200–600MB process footprint are not interesting problems for traditional long-lived server processes. They are blocking problems for serverless deployment models, container-dense Kubernetes clusters, and CLI tool development. A language designed today should treat startup time and memory footprint as primary optimization targets alongside throughput, particularly given that serverless and container-based deployment have become the dominant infrastructure model.

**10. Deprecation without removal is not backward compatibility.**
Ruby's history of deprecation warnings that precede removal by multiple release cycles is healthier than no deprecation at all. But the absence of a formal compatibility promise means that each upgrade carries unknown friction. Go's 1.0 Compatibility Promise enabled confident, predictable upgrades. Ruby's less formal approach creates upgrade risk that teams must absorb independently. Language designers should formalize their compatibility guarantees explicitly and as early as possible.

**11. A language's security posture reflects its design philosophy.**
Ruby's most persistent security vulnerabilities (`Kernel#open`, `Object#send`, YAML deserialization, open classes as supply chain attack surface) arise directly from its design philosophy of maximum flexibility and dynamism. A language that maximizes developer freedom necessarily creates larger attack surfaces. This is not unique to Ruby, but Ruby's case illustrates the principle clearly: when designing a language, explicitly model the security consequences of each flexibility-granting feature. The privilege of allowing `eval` carries a proportional security cost that should be visible in the design, not discovered in production.

---

## References

[ARTIMA-PHILOSOPHY] Shaughnessy, P. "The Philosophy of Ruby: A Conversation with Yukihiro Matsumoto." Artima.com. https://www.artima.com/articles/the-philosophy-of-ruby

[ARXIV-RUBY-2025] "Unveiling Ruby: Insights from Stack Overflow and Developer Survey." arXiv:2503.19238v2. March 2025. https://arxiv.org/html/2503.19238v2

[BISHOPFOX-RUBY] Bishop Fox. "Ruby Vulnerabilities: Exploiting Open, Send, and Deserialization." https://bishopfox.com/blog/ruby-vulnerabilities-exploits

[BRANDUR-RACTORS] Leach, B. "Ruby 3's Ractors." brandur.org/nanoglyphs/018-ractors

[BYROOT-GVL-2025] Boussier, J. "So You Want To Remove The GVL?" byroot.github.io, January 29, 2025. https://byroot.github.io/ruby/performance/2025/01/29/so-you-want-to-remove-the-gvl.html

[CLBG] Computer Language Benchmarks Game. https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html

[CVEDETAILS-RUBY] CVEDetails.com. "Ruby-lang Ruby: Security vulnerabilities, CVEs." https://www.cvedetails.com/product/12215/Ruby-lang-Ruby.html?vendor_id=7252

[DATADOG-RUBY-ALLOC] Datadog. "Optimize Ruby garbage collection activity with Datadog's allocations profiler." https://www.datadoghq.com/blog/ruby-allocations-profiler/

[DEVCLASS-RUBY-4] DevClass. "Ruby 4.0 released – but its best new features are not production ready." January 6, 2026. https://devclass.com/2026/01/06/ruby-4-0-released-but-its-best-new-features-are-not-production-ready/

[FFI-README] ffi/ffi GitHub repository. https://github.com/ffi/ffi

[GVL-SPEEDSHOP] Hoffman, N. "The Practical Effects of the GVL on Scaling in Ruby." speedshop.co, May 11, 2020. https://www.speedshop.co/2020/05/11/the-ruby-gvl-and-scaling.html

[HEISE-RUBY-4] Heise Online. "Ruby 4.0: A lot of restructuring under the hood, few new features." https://www.heise.de/en/background/Ruby-4-0-A-lot-of-restructuring-under-the-hood-few-new-features-11121859.html

[ISO-30170] ISO. "ISO/IEC 30170:2012 — Information technology — Programming languages — Ruby." https://www.iso.org/standard/59579.html

[JETBRAINS-2025] JetBrains. "State of Developer Ecosystem 2025." https://devecosystem-2025.jetbrains.com/

[RAILS-RCE-CODECLIMATE] Code Climate. "Rails' Remote Code Execution Vulnerability Explained." https://codeclimate.com/blog/rails-remote-code-execution-vulnerability-explained

[RAILS-SURVEY-2024] Planet Argon / railsdeveloper.com. "2024 Ruby on Rails Community Survey Results." https://railsdeveloper.com/survey/2024/

[RAILSATSCALE-YJIT-3-3] Shopify Engineering. "Ruby 3.3's YJIT: Faster While Using Less Memory." railsatscale.com, December 4, 2023. https://railsatscale.com/2023-12-04-ruby-3-3-s-yjit-faster-while-using-less-memory/

[RAILSATSCALE-YJIT-3-4] Shopify Engineering. "YJIT 3.4: Even Faster and More Memory-Efficient." railsatscale.com, January 10, 2025. https://railsatscale.com/2025-01-10-yjit-3-4-even-faster-and-more-memory-efficient/

[RACTORS-BYROOT-2025] Boussier, J. "What's The Deal With Ractors?" byroot.github.io, February 27, 2025. https://byroot.github.io/ruby/performance/2025/02/27/whats-the-deal-with-ractors.html

[REVERSINGLABS-GEMS] ReversingLabs. "Mining for malicious Ruby gems." https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems

[RUBY-2-0-RELEASE] ruby-lang.org. "Ruby 2.0.0-p0 Released." February 24, 2013. https://www.ruby-lang.org/en/news/2013/02/24/ruby-2-0-0-p0-is-released/

[RUBY-2-2-RELEASE] ruby-lang.org. "Ruby 2.2.0 Released." December 25, 2014.

[RUBY-3-0-RELEASE] ruby-lang.org. "Ruby 3.0.0 Released." December 25, 2020. https://www.ruby-lang.org/en/news/2020/12/25/ruby-3-0-0-released/

[RUBY-3-1-RELEASE] ruby-lang.org. "Ruby 3.1.0 Released." December 25, 2021. https://www.ruby-lang.org/en/news/2021/12/25/ruby-3-1-0-released/

[RUBY-3-2-RELEASE] ruby-lang.org. "Ruby 3.2.0 Released." December 25, 2022. https://www.ruby-lang.org/en/news/2022/12/25/ruby-3-2-0-released/

[RUBY-3-3-RELEASE] ruby-lang.org. "Ruby 3.3.0 Released." December 25, 2023. https://www.ruby-lang.org/en/news/2023/12/25/ruby-3-3-0-released/

[RUBY-3-4-RELEASE] ruby-lang.org. "Ruby 3.4.0 Released." December 25, 2024. https://www.ruby-lang.org/en/news/2024/12/25/ruby-3-4-0-released/

[RUBY-4-0-RELEASE] ruby-lang.org. "Ruby 4.0.0 Released." December 25, 2025. https://www.ruby-lang.org/en/news/2025/12/25/ruby-4-0-0-released/

[RUBY-ABOUT] ruby-lang.org. "About Ruby." https://www.ruby-lang.org/en/about/

[RUBY-CVE-REDOS] ruby-lang.org Security page. Various ReDoS CVEs. https://www.ruby-lang.org/en/security/

[RUBY-ERROR-HANDLING] BetterStack. "Understanding Ruby Error Handling." https://betterstack.com/community/guides/scaling-ruby/ruby-error-handling/

[RUBY-GC] Stackify. "How Does Ruby Garbage Collection Work?" https://stackify.com/how-does-ruby-garbage-collection-work-a-simple-tutorial/

[RUBY-HISTORY] Wikipedia. "History of Ruby." https://en.wikipedia.org/wiki/History_of_Ruby

[RUBY-HISTORY-WIKI] Wikipedia. "Ruby (programming language)." https://en.wikipedia.org/wiki/Ruby_(programming_language)

[RUBY-ISSUE-21657] Ruby Issue Tracker. "Misc #21657: Question: Is Ruby 4.0 planned for December 2025 or later?" https://bugs.ruby-lang.org/issues/21657

[RUBY-RESEARCH-BRIEF] Internal. Ruby Research Brief. research/tier1/ruby/research-brief.md. 2026-02-27.

[RUBY-RUBYGEMS-TRANSITION] ruby-lang.org. "The Transition of RubyGems Repository Ownership." October 17, 2025. https://www.ruby-lang.org/en/news/2025/10/17/rubygems-repository-transition/

[RUBY-SECURITY] ruby-lang.org. "Security." https://www.ruby-lang.org/en/security/

[RUBY-TYPING-2024] Leach, B. "Ruby typing 2024: RBS, Steep, RBS Collections, subjective feelings." brandur.org. https://brandur.org/fragments/ruby-typing-2024

[SHOPIFY-YJIT] Shopify Engineering. "Ruby YJIT is Production Ready." https://shopify.engineering/ruby-yjit-is-production-ready

[SOCKET-MALICIOUS-GEMS] Socket.dev. "Malicious Ruby Gems Exfiltrate Telegram Tokens and Messages." https://socket.dev/blog/malicious-ruby-gems-exfiltrate-telegram-tokens-and-messages-following-vietnam-ban

[SOCKET-RUBYGEMS-STEWARDSHIP] Socket.dev. "Who Will Steward RubyGems?" https://socket.dev/blog/who-will-steward-rubygems

[TECHEMPOWER-ROUND-23] TechEmpower. "Framework Benchmarks Round 23." March 2025. https://www.techempower.com/blog/2025/03/17/framework-benchmarks-round-23/

[THN-GEMS-2025] The Hacker News. "RubyGems and PyPI Hit Simultaneously by Malicious Packages." August 2025.

[THN-TYPOSQUAT-2020] The Hacker News. "700+ Malicious Typosquatted Libraries Found On RubyGems Repository." February 2020. https://thehackernews.com/2020/04/rubygems-malware-packages.html

[TIOBE-2025] TIOBE Index. "Ruby Programming Language." April 2025. https://www.tiobe.com/tiobe-index/ruby/

[TMS-RUBY-STATS] The Mightyhand. "Ruby Programming Language Statistics and Facts 2024." https://themightyhand.com/ruby-programming-language-statistics/

[TRUFFLERUBY-CEXT] TruffleRuby. "C Extension support." https://www.graalvm.org/ruby/reference/extensions/

[UPDOWN-RUBY-3-3] Updown.io Blog. "Real-world Ruby 3.3 performance improvements." 2024. https://blog.updown.io/2024/01/ruby-3-3-performance.html
