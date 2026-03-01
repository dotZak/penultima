# Ruby — Practitioner Perspective

```yaml
role: practitioner
language: "Ruby"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## 1. Identity and Intent

Ruby's core promise — "designed to make programmers happy" — is not marketing copy. It is a genuine design principle that shapes everything from method naming to error message phrasing to how the standard library is organized. Practitioners who dismiss this as rhetoric miss something important: it actually works, and understanding *how* it works explains both Ruby's strengths and its failure modes.

The happiness philosophy produces a language where code reads like considered prose. `5.times.map { |i| i * 2 }` is not just syntactically pleasant — it models the programmer's mental intent more directly than `for i in range(5): result.append(i * 2)`. The convention of methods that ask questions ending in `?` and methods that mutate ending in `!` is a naming discipline that reduces cognitive load when reading unfamiliar code. These are small things that compound across a 200,000-line codebase.

But the happiness philosophy also bakes in assumptions that cause friction at scale. It assumes the programmer is the primary reader — the human sitting with the code. It is less attentive to the runtime reader, the deployment engineer, the person who needs to understand this code without an interactive REPL at 2 AM when something is on fire. Code that is pleasant to write is not always pleasant to debug, monitor, or reason about when its execution is distributed across 80 Puma workers in a Kubernetes cluster.

The "designed for humans, not machines" framing is accurate but incomplete. Ruby is designed for *individual* humans writing code in a single session. Scaled to teams and time — twenty engineers across five years on a single codebase — some of the tradeoffs feel different. Dynamic dispatch, open classes, and pervasive metaprogramming mean that reading code requires running it in your head with all its possible runtime states. That cognitive model does not scale the way type annotations scale.

Rails amplified both the best and worst of this philosophy. DHH's "convention over configuration" and "opinionated software" gave teams an extraordinary productivity advantage over the framework alternatives of 2004–2012. Those conventions also created a generation of Rails developers who learned patterns without understanding the layers beneath them. The Rails magic that delights beginners becomes the Rails mystery that frustrates maintainers. Understanding `after_commit` versus `after_save`, callback ordering, `ActiveSupport::Concern` hook sequencing, or how Rails autoloading interacts with Zeitwerk in production requires knowing not just Rails conventions but the careful sequence in which Rails wires its stack together at boot. That knowledge gap is real and it shows up in production incidents.

The intent was productivity. The reality is productivity for greenfield development and increasing complexity for maintenance at scale. Ruby is a language where you go fast early and work hard later. Whether that trade is worth it depends heavily on your application's lifecycle stage.

## 2. Type System

Dynamic typing is Ruby's most consequential design decision for practitioners. It shapes every refactoring, every API change, every onboarding experience, and every production incident investigation.

The benefits in early-stage development are genuine. Duck typing means you can swap a `User` for a `Guest` object in a test without elaborate interface declarations. Open classes mean you can extend `String` with `.to_slug` directly on the class rather than wrapping it in utility functions. The ability to pass any callable object where a block is expected makes the language genuinely composable in ways that static-typed languages struggle to replicate without algebraic effect systems.

The costs compound with scale. A method that accepts "anything that responds to `#serialize`" is fine when the method has three callers and you wrote it. It becomes a maintenance hazard when it has thirty callers spread across five contributors who joined after you left. The implicit contract is invisible in the source — it exists only in the tests, in the documentation if you wrote it, and in the mental model of whoever wrote the original code.

The typing ecosystem response to this — RBS and Sorbet — represents a genuine attempt to address the scale problem, but practitioners encounter it as a fragmented and ergonomically costly solution. Brandur Leach's 2024 assessment captures the practitioner reality: two competing annotation formats (RBS separate files vs. Sorbet inline), three type checkers (Steep, Sorbet, RBS inline), limited IDE tooling outside of RubyMine, and no clear winner [BRANDUR-TYPING-2024]. The dual-file requirement for RBS — maintaining `.rb` and `.rbs` files that must stay in sync — is a maintenance burden that most teams find prohibitive. Steep's inability to type code using RSpec or most Rails DSLs means the most-tested parts of a codebase remain the least-typed.

Sorbet, originated at Stripe and heavily used at Shopify, represents the more pragmatic path. Shopify's internal data shows 80% of developers want more code typed for readability, and 71% support typing more codebases [RAILSATSCALE-RBS-SORBET-2025]. That 71% versus 100% gap is telling: even at a well-resourced, typing-positive organization, some portion of the codebase remains economic to leave untyped. Shopify's April 2025 integration of RBS syntax into Sorbet — allowing RBS-style annotations inline in `.rb` files while keeping Sorbet's type checking engine — is the most promising convergence development, but it is too recent to assess production adoption outside its originators [RAILSATSCALE-RBS-SORBET-2025].

Outside Stripe and Shopify, the honest practitioner assessment is that static typing adoption in Ruby remains low. The ergonomic costs of either system are high relative to what TypeScript delivers for JavaScript teams. Most Ruby teams have informal typing disciplines: naming conventions, comprehensive test suites, and careful API design rather than formal type checking. This works until it doesn't — until the refactoring that touched something unexpected, the method that started accepting nil in production, the third-party gem that changed its return type across a patch version.

The practical implication: Ruby type-checking tools are currently best suited for public API surfaces in library code, or for specific hot paths where the type discipline pays for itself. Applying either Sorbet or RBS comprehensively to a 200k-line Rails application is a multi-year investment that most organizations will not make.

## 3. Memory Model

Ruby's garbage collector is transparent to most practitioners on most days, and this is genuinely a good thing. You do not think about memory allocation when writing Ruby the way you think about it in C or Rust. The GC handles it.

But production Ruby applications have memory behavior that practitioners learn the hard way, and this learning comes with operational cost.

The first lesson is memory bloat. Rails applications running under Puma in cluster mode typically start each worker process at 50–80MB and grow to 200–600MB under traffic, stabilizing at a process size that depends heavily on what code paths have been executed [RESEARCH-BRIEF]. This growth is partly legitimate (caches warming, memoized structures filling in) and partly fragmentation. The fragmentation problem was well-analyzed by Brandur Leach: Ruby's object allocation pattern — including memoized class variables and interned strings — dirties heap pages that would otherwise be shared read-only between forked worker processes via Copy-on-Write semantics [BRANDUR-RUBY-MEMORY]. Workers that initially share memory with their parent process inflate toward their own independent footprint within minutes of receiving traffic.

The second lesson is that jemalloc is no longer optional. The default glibc malloc allocator's thread-arena behavior causes significant memory fragmentation in multi-threaded Ruby processes. Running without jemalloc can result in 50% or more additional memory usage even with YJIT enabled [UPDOWN-YJIT-WEIRD]. The Rails 8 default Dockerfile now includes jemalloc installation — recognition that this is standard operational practice, not an advanced optimization [RAILS-DEPLOYMENT-GUIDE]. Teams deploying on Ubuntu or Alpine without jemalloc are leaving substantial memory efficiency on the table.

The third lesson is `GC.compact`. Available since Ruby 2.7 and improved through the 3.x series, compaction reduces heap fragmentation by relocating live objects to contiguous pages. The recommended production pattern is calling `GC.compact` after application boot but before forking worker processes, so long-lived class-level objects are compacted into shareable read-only pages before workers inherit them [DATADOG-RUBY-ALLOC]. This is not widely known and not documented in beginner tutorials, but it meaningfully extends CoW sharing lifetimes.

The fourth lesson — and the one most likely to cause a production incident for teams new to containerized Ruby deployment — is that Puma's worker count auto-detection is dangerous in Kubernetes environments. Puma uses `Concurrent.physical_processor_count` by default to determine worker count. On Kubernetes, where pods land on nodes of varying sizes, the same pod configuration can produce 4 workers on a 4-CPU node and 32 workers on a 32-CPU node, tripling or octupling memory usage [PREFAB-OOM]. The fix is simple — always set `WEB_CONCURRENCY` explicitly in container environments — but the failure mode is an OOM kill that is difficult to trace to its source without knowing this specific footgun exists.

Ruby 3.4's modular GC framework is an architectural step forward, enabling alternative GC implementations to be loaded dynamically [RUBY-3-4-RELEASE]. No alternative GC has achieved production-ready status as of early 2026, but the architecture opens the door to specialized collectors (lower-latency, throughput-optimized) that could meaningfully address the GC pause problems that affect real-time or latency-sensitive Ruby workloads.

## 4. Concurrency and Parallelism

The Global VM Lock (GVL, historically GIL) is the most-discussed constraint in Ruby's production story. The honest practitioner assessment: the GVL is a real limitation that has shaped deployment architecture for twenty years, the alternatives offered so far are not production-viable, and most Rails applications do not actually need to remove it.

The practical production strategy for parallelism in Ruby has been stable and consistent: **multiple processes, not multiple threads**. Puma's cluster mode — or Shopify's Pitchfork fork of Unicorn — runs N worker processes, each with its own GVL, providing true parallelism at the process level while accepting the memory overhead of process isolation [BYROOT-PITCHFORK-2025]. This is not an elegant solution. It means N copies of your loaded application in memory, N copies of your database connection pool, N copies of your in-process caches. But it works reliably, its failure modes are understood, and the tooling around it (Puma, Pitchfork, Unicorn) is mature.

Puma threads within a single worker provide real concurrency for I/O-bound work. The GVL is released during blocking I/O operations — database queries, network calls, file I/O — so multiple threads can be waiting on external systems simultaneously. For a typical Rails application where most request time is spent waiting on the database, threading within a worker provides meaningful concurrency without parallelism. The practical recommendation is 2–5 threads per worker, depending on the fraction of request time spent on I/O versus Ruby computation.

Ractors, Ruby's answer to the GVL parallelism problem, are not production-viable as of early 2026. Jean Boussier's February 2025 analysis is definitive: 74 open Ractor issues including segfaults and deadlocks, C-based database drivers incompatible with Ractor boundaries, VM-wide locks on the interned string table causing a parallel JSON-parsing benchmark to perform 2.5x *worse* than serial execution [BYROOT-RACTORS-2025]. Something as idiomatic as a constant with default values breaks Ractor compatibility. "Not production-ready" understates the situation — Ractors are not yet safe for anything beyond isolated experiments.

GVL removal is not on the horizon. Boussier's January 2025 analysis of the technical costs explains why: every mutable object would require atomic reference counting (adding ~16 bytes per object), atomic operations force cache-line synchronization across cores with measurable single-thread regression, and every C extension would require explicit lock management made harder by Ruby's use of `setjmp/longjmp` for exceptions [BYROOT-GVL-2025]. The conclusion: GVL removal would degrade single-threaded performance for Ruby's primary use case (web apps) to an extent that makes the effort-to-benefit ratio unfavorable. Ruby 4.0, released December 2025, did not remove the GVL.

The Fiber/async model via the `async` gem and Samuel Williams's Falcon web server represents a third path for I/O-bound workloads. Fibers are lightweight cooperative coroutines that yield during I/O operations, allowing many requests to be in-flight simultaneously without OS thread overhead. The `async` gem provides a scheduler that integrates with Ruby 3.0's Fiber Scheduler interface, making fiber switching transparent in compatible libraries. For workloads that spend the vast majority of time waiting on external I/O, the async model can provide substantial throughput improvements. For typical Rails applications with a mix of computation and I/O, the benefits are more modest and the operational model (Falcon vs. Puma) is less familiar to most teams.

Shopify's Pitchfork, which adds a "reforking" feature to the classic Unicorn process model, represents the current state of the art for high-scale Ruby deployments. Pitchfork periodically promotes a warmed-up worker as the new template before forking additional workers, maximizing CoW sharing of filled inline caches and memoized structures. Shopify observed 30% memory reduction and 9% P99 latency reduction versus Puma at their scale [BYROOT-PITCHFORK-2025]. For teams operating at sub-Shopify scale, Puma cluster mode provides equivalent architectural properties with simpler configuration.

The practitioner bottom line on concurrency: if you need to run CPU-intensive work in parallel in Ruby, use multiple processes, sidekiq workers, or a separate service. The threading model is excellent for I/O concurrency. Ractors are not ready. GVL removal is not coming.

## 5. Error Handling

Ruby's exception-based error handling is familiar and ergonomically smooth for common cases. It is also a source of recurring production problems that practitioners encounter in mature codebases.

The basic mechanism — `begin/rescue/ensure` with inheritance-based exception matching — works well. Ruby's distinction between `Exception` and `StandardError` in the exception hierarchy is important and documented: bare `rescue` catches `StandardError` and subclasses, not signals or system exits. In practice, this distinction is violated regularly in production code. Grepping a large Rails codebase for `rescue Exception` will find it, often in places where the author intended to catch "everything" [RUBY-SECURITY].

The inline `rescue` modifier is a persistent footgun. `result = expensive_call rescue nil` is syntactically convenient and semantically dangerous — it silently swallows exceptions, converting an error condition into a nil return that propagates through the call stack until something unexpected happens much later. It appears frequently in tutorials as a convenience and in production code as technical debt.

The deeper problem is that Ruby's error handling encourages implicit error propagation through nil. Methods that "fail softly" often return nil rather than raising, because callers write code that works when the method succeeds and accidentally works (or fails silently) when it returns nil. `user&.profile&.settings&.theme` chains the safe navigation operator three levels deep, making "I got nil somewhere in this chain" invisible at the call site. This nil-propagation pattern is idiomatic Ruby, but it produces bugs where the failure origin is far removed from the observable symptom.

The absence of a `Result` type — a first-class value encoding either success or failure — means every library makes its own choice. Some raise on failure. Some return nil. Some return false. Some return the object but populate an `errors` collection (ActiveRecord's pattern). Some return a Result-like object via dry-rb. Integrating multiple libraries means understanding each library's error communication convention, and forgetting which one you're using produces silent failures. This fragmentation is not accidental — it reflects Ruby's "multiple ways to do things" philosophy — but it has a real maintenance cost in large codebases.

ActiveRecord's validation model (`errors`, `valid?`, `save` vs. `save!`) is a well-designed exception to this fragmentation: the convention is consistent, widely understood, and correctly separates validation failures from unexpected errors. It is also frequently copied by other Rails-ecosystem libraries, producing a recognizable pattern across the ecosystem. This is an example of Rails's opinionated conventions providing genuine coordination value in the ecosystem.

The error handling picture has improved meaningfully with recent Ruby versions. Ruby 3.1's enhanced error messages with `did you mean?` suggestions for `NoMethodError` and `NameError` materially reduce debugging time for the most common runtime errors [RUBY-3-1-RELEASE]. Ruby 3.2's continuation of this work means that the 2 AM "NoMethodError: undefined method 'foo' for nil:NilClass" experience, which gives you no information about where nil came from, is gradually being supplemented with more actionable output.

## 6. Ecosystem and Tooling

The Ruby ecosystem is mature, opinionated, and — for Rails-centric development — remarkably coherent. The tooling story in 2026 is substantially better than it was five years ago, though some rough edges remain.

**Bundler and RubyGems** represent one of the genuine ecosystem success stories. Bundler's dependency resolution with `Gemfile.lock` is reliable and reproducible. The workflow of `bundle install`, `bundle exec`, and locked dependencies is standard across the ecosystem and reduces "works on my machine" problems. The `bundle add`, `bundle update`, and `bundle outdated` commands give teams a workable dependency management workflow. RubyGems download metrics — over 4 billion monthly downloads as of mid-2025 — reflect an active ecosystem [RUBYGEMS-STATS-2025].

The October 2025 Ruby Central governance crisis damaged ecosystem trust. A governance dispute resulted in Ruby Central's director unilaterally removing longtime Bundler and RubyGems maintainers from repository access, prompting community outrage and ultimately Matz's intervention to transfer stewardship to the Ruby Core team [THEREGISTER-RUBYGEMS]. The incident was resolved in terms of repository control, but the institutional damage — particularly the loss of institutional knowledge held by the original maintainers and the chilling effect on community governance participation — is harder to quantify. Practitioners evaluating Ruby's long-term ecosystem health should weigh this as evidence that the governance structures supporting critical infrastructure remain fragile.

**Supply chain security** is a genuine concern that practitioners must actively manage. RubyGems has experienced repeated malicious package campaigns: 60 gems active for over 18 months executing credential theft (275,000+ downloads before detection in August 2025) [SOCKET-MALICIOUS-GEMS], typosquatting campaigns distributing cryptocurrency malware, and CI/CD pipeline attacks via Fastlane plugin impersonators [CSO-TELEGRAM]. RubyGems.org's own security response acknowledged catching 70–80% of malicious packages proactively — implicitly admitting a 20–30% detection gap [RUBYGEMS-SECURITY-2025]. The mitigation toolkit is familiar — gem checksums via `bundle install --frozen`, dependency auditing via `bundler-audit`, minimal permission deployment environments — but none of it is default behavior, and adoption is inconsistent across teams.

**RuboCop** is excellent and practitioners should use it. The auto-correction capabilities, the plugin ecosystem (`rubocop-rails`, `rubocop-rspec`, `rubocop-performance`), and the configuration inheritance model combine to provide a linting and formatting experience that is opinionated without being inflexible. StandardRB, a lower-friction RuboCop configuration, reduces the configuration burden for teams that want consistency without spending time on lint rule negotiation.

**Testing** is a practitioner strength. RSpec's DSL for BDD-style test writing — `describe`, `context`, `it`, `expect(...).to` — produces readable test suites that serve as documentation. Minitest provides a lighter alternative for teams that prefer simplicity. FactoryBot, VCR, and WebMock are well-established support libraries. The test coverage discipline in the Rails community is generally strong. This is one area where Ruby's cultural norms translate directly into practical quality benefits.

**IDE support** is adequate but not exceptional. Visual Studio Code with the Ruby LSP extension provides reasonable autocompletion, go-to-definition, and inline error highlighting — used by 44% of Rails developers [RAILS-SURVEY-2024]. RubyMine provides the most complete IDE experience, with better Rails-aware refactoring and debugging support. Neither approaches the IDE experience in TypeScript or Java, where type information drives comprehensive tooling. The gap is particularly visible in large codebases: go-to-definition frequently resolves to a monkey-patched version of a method rather than the intended implementation, and autocompletion for dynamically-generated methods (via `method_missing`, `define_method`, or Rails macros) is unreliable.

**Rails 8's "No PaaS Required" stack** — Kamal for deployment, Solid Queue for background jobs, Solid Cache for caching, Solid Cable for WebSockets — represents a significant practical evolution in the deployment story. 37signals validated these components in production before the Rails 8 release: Solid Queue runs 20 million jobs per day for HEY email; Solid Cache stores 10TB at Basecamp and cut P95 render times in half [RAILS8-RELEASE]. This is not vaporware — it is production-validated infrastructure. The caveat is that Kamal's deployment model (Docker-based, SSH-based orchestration) trades Heroku's developer experience for operational control, and teams accustomed to PaaS deployment face a meaningful learning curve.

## 7. Security Profile

Ruby's security profile is a function of its dynamism. The language's most powerful features — `eval`, `send`, `open`, `method_missing`, YAML deserialization — are also the source of its most serious vulnerability classes. These are not edge cases; they are central features that appear in tutorials and production code alike.

The `Kernel#open` footgun is the clearest example. `open(user_input)` is taught as a convenient file-opening method, but if user-supplied input begins with `|`, it executes the remainder as a shell command [BISHOPFOX-RUBY]. This is documented, known, and still found in real codebases because it is non-obvious to developers who learned `open` as "file opening." The mitigation — use `File.open` for file operations, never `Kernel#open` with untrusted input — is straightforward but requires awareness. Similarly, `Object#send` with untrusted method name arguments enables arbitrary method invocation; `YAML.load` with untrusted input enables arbitrary Ruby code execution through deserialization. Each of these features has a safe alternative (`public_send` for send, `YAML.safe_load` for YAML) but the unsafe version is the shorter one and appears in legacy code.

ReDoS (Regular Expression Denial of Service) is the most common CVE category in Ruby's recent history. Ruby's regex engine is capable of catastrophic backtracking on certain patterns applied to adversarial input. Multiple CVEs have affected the `date` gem (parsing `Date.parse` with untrusted input) and the `uri` library [RUBY-CVE-REDOS]. The mitigations — input length limits, timeout wrappers, use of non-backtracking regex patterns — are not automatic; they require developer awareness.

The removal of `$SAFE` in Ruby 3.0 simplified the security model. The taint tracking mechanism provided by `$SAFE` levels in Ruby 1.x and 2.x gave a false sense of security — it did not provide reliable sandboxing and was frequently misunderstood as doing more than it did [RUBY-3-0-RELEASE]. Removing it was the correct call, but it means codebases that relied on `$SAFE` for any security properties need review.

Rails's historical mass assignment vulnerability — where `ActiveRecord` would accept any user-supplied parameter as an attribute in versions before Rails 4's strong parameters requirement — produced significant real-world security incidents. The current strong parameters model (`params.require(:user).permit(:name, :email)`) is a correct solution that has been the default for over a decade, but legacy Rails codebases migrated from pre-4.x may have incomplete whitelist coverage.

Supply chain security, discussed in section 6, warrants emphasis here: the 275,000+ downloads of confirmed malicious gems in 2025 represent a real attack surface. Practitioners managing dependencies in security-sensitive environments should treat dependency auditing (`bundler-audit`, Dependabot, GitHub's dependency scanning) as baseline operational hygiene rather than optional enhancement. The RubyGems.org registry's acknowledged 20–30% proactive detection gap for malicious packages means that defense-in-depth — monitoring for unexpected outbound network calls, secrets scanning, runtime anomaly detection — is necessary complement to package-level controls.

C extensions are a specific practitioner concern for security and stability. Many high-performance gems — database drivers, cryptography libraries, image processing — are implemented as C extensions. These operate outside the Ruby GC's visibility and can introduce memory safety vulnerabilities that the Ruby runtime cannot prevent. Practitioners should prefer pure-Ruby gems for security-sensitive operations where the performance difference is acceptable, and should treat C extension upgrades with the same caution as upgrading native dependencies.

## 8. Developer Experience

Ruby's developer experience is one of the most polarized in the ecosystem: frequently cited as a primary reason for choosing the language, and also frequently cited as a primary reason for accumulating technical debt that is hard to resolve.

The initial developer experience is genuinely excellent. Ruby's syntax is expressive and readable. Rails's scaffold generation, convention-based configuration, and opinionated defaults get a team from zero to working application faster than almost any alternative stack. The REPL (`irb`, or the superior `pry`) is excellent for exploration. The error messages in recent Ruby versions (3.1+) have improved substantially, with suggestions for common misspellings and better context for `nil`-related errors. The community documentation on Stack Overflow, RailsTutorial.org, and Gorails is comprehensive. Onboarding a new developer to an existing Rails application — assuming the application follows conventions — is typically measured in days, not weeks.

The sustained developer experience degrades in predictable ways. Dynamic dispatch means "find me the implementation of this method" requires running the code, not reading it — go-to-definition in IDEs is unreliable for Rails DSL methods, modules included dynamically, or `method_missing` implementations. Open classes and monkey-patching mean that reading a class's methods requires knowing every gem that might have extended that class. Metaprogramming-heavy codebases (Rails itself is an example) produce a gap between what the code says it does and what it actually does at runtime that widens with developer unfamiliarity.

The gem installation and configuration experience is the most challenging topic for developers per the Stack Overflow data analysis [ARXIV-RUBY-2025]. This corresponds to practitioner experience: native extension gems (Nokogiri, sassc, pg, mysql2) have historically required build toolchain dependencies that cause intermittent failures in fresh development environments and CI pipelines. Ruby version management — rbenv vs. asdf vs. RVM — adds another layer of environment configuration that must be correct before any code runs. The Rails 8 Docker development setup and the `devcontainer` ecosystem have reduced this friction for teams that adopt them, but for teams using native development without containers, the "getting started" experience remains more complex than Node.js or Python for new contributors.

The cognitive load of idiomatic Ruby at scale is higher than its proponents acknowledge. The Ruby idioms that make expert developers productive — method chaining, blocks and procs, symbol-to-proc, define_method, module prepending — are genuinely expressive but require familiarity to read fluently. A developer comfortable in Java reading Ruby code for the first time will not find it "English-like"; they will find it alien. The expressiveness is real for experienced Ruby developers and opaque for everyone else. Teams that hire from a broad developer pool and need to onboard quickly may find the Ruby learning curve underestimated.

Salary data suggests strong market validation: Ruby ranked 5th highest-paying technology in the 2024 Stack Overflow survey despite declining usage ranking [ARXIV-RUBY-2025]. This premium likely reflects the senior-skewed Ruby developer population (most remaining Ruby specialists have years of experience) combined with the concentration of Ruby in high-value web infrastructure companies. It does not indicate strong demand growth — the JetBrains 2025 classification of Ruby alongside PHP and Objective-C as "long-term declining" languages reflects genuine contraction in new Ruby adoption [JETBRAINS-2025].

## 9. Performance Characteristics

Ruby's performance story in 2026 is materially different from Ruby's performance story in 2020, and practitioners evaluating Ruby on outdated assumptions should update their model.

YJIT, the block-based JIT compiler developed by Shopify and shipped by default since Ruby 3.2, is the most significant practical change. The headline benchmark figure — 92% faster than the interpreter on synthetic benchmarks [RAILSATSCALE-YJIT-3-4] — represents a real improvement that manifests as measurable production gains in CPU-intensive workloads. Independent validation from updown.io's production deployment showed 32% CPU reduction and approximately 48% throughput increase on a Sidekiq-heavy workload after upgrading to Ruby 3.3.5 with YJIT [UPDOWN-YJIT]. These are not trivial gains.

The important calibration is that gains are workload-dependent. For a typical Rails request lifecycle — routing, parameter parsing, controller action, one or more database queries, template rendering — the database wait time dominates. YJIT accelerates the Ruby computation portions; it does nothing for database latency. A Rails application spending 80% of request time waiting on the database will see roughly 20% of its request time reduced by YJIT's gains. In practice, Rails teams report 10–25% overall application performance improvements with YJIT, with CPU-heavy operations (serialization, template rendering, complex business logic) seeing larger improvements [RESEARCH-BRIEF].

The memory overhead of YJIT is the practitioner's main concern. YJIT 3.3 increased process memory by 21% on average [RAILSATSCALE-YJIT-3-4]. YJIT 3.4 reduces this overhead, and Shopify reports that when measured as PSS (Proportional Set Size, accounting for shared memory across forked workers), the actual operational overhead is below 8% for their Storefront Renderer — substantially lower than the per-process figure suggests. The new `--yjit-mem-size=N` option in Ruby 3.4 provides a single knob to cap YJIT's total memory usage, replacing the previous harder-to-use option. The bottom line: YJIT is worth enabling in production (it is the default), and the memory overhead is manageable with jemalloc.

Startup time is a persistent operational constraint. CRuby without Rails starts in 50–150ms; a Rails application with a typical gem load starts in 1–10 seconds. This matters for several deployment scenarios: Lambda/serverless deployments where cold starts are billed and affect latency, CLI tools that start a new Ruby process per invocation, and CI/CD pipelines where test suite startup time compounds across many test runs. Teams building Lambda functions or CLI tools in Ruby pay a constant startup overhead that alternatives like Go or compiled languages eliminate entirely.

Memory footprint in production is significant. A Rails application's Puma worker pool at steady state typically consumes 200–600MB across all workers [RESEARCH-BRIEF]. At 5 workers × 300MB = 1.5GB, this is manageable on modern infrastructure but expensive on memory-constrained instances. Teams running dozens of microservices in Ruby compound this overhead across services. The Pitchfork server's reforking technique, which maximizes CoW sharing by forking from a warmed-up worker, represents the current best practice for reducing per-worker memory overhead at scale, with Shopify observing 30% memory reduction versus Puma [BYROOT-PITCHFORK-2025].

TechEmpower benchmarks place Ruby frameworks (Rails, Sinatra) in the lower throughput tiers alongside Python (Django) and PHP (Laravel), substantially below Rust, Go, and Node.js frameworks [TECHEMPOWER-ROUND-23]. The Computer Language Benchmarks Game shows Ruby 5–50× slower than C on computational benchmarks. For practitioners, the relevant question is not whether Ruby is slow in benchmarks (it is, relatively) but whether Ruby's performance is adequate for the workload in question. For the vast majority of web applications where database and network latency dominate, Ruby's computational overhead is not the constraint. For systems doing substantial in-process computation — parsing, serialization at high volume, image processing, machine learning inference — Ruby is the wrong tool and practitioners should not pretend otherwise.

The alternative implementations — JRuby (JVM) and TruffleRuby (GraalVM) — offer escape hatches for specific performance constraints. JRuby provides true thread parallelism without the GVL, relevant for CPU-bound multi-threaded workloads. TruffleRuby's peak throughput often exceeds CRuby with YJIT for long-running workloads, at the cost of longer warmup time. Both carry compatibility costs: not all gems work correctly on alternative implementations, and the C extension ecosystem is a particular challenge. These are specialized tools rather than general production recommendations.

## 10. Interoperability

Ruby's primary interoperability path is C extensions, and this path is functional but increasingly problematic for the language's forward trajectory.

C extensions are how Ruby gains access to native libraries: database drivers (pg, mysql2, trilogy), cryptography (openssl), image processing (rmagick, vips), protocol buffers (google-protobuf), and many performance-critical gems. The API for writing C extensions is documented and stable, the toolchain (`mkmf`, extconf.rb) is mature, and C extension gems can be distributed as pre-compiled binaries via `rake-compiler` and the binary gem infrastructure. For practitioners, C extensions mostly work transparently.

The problem is that C extensions are incompatible with YJIT optimization across extension call boundaries, incompatible with Ractors (which cannot use C extensions that touch shared state without modification), and incompatible with the GVL analysis that informs M:N scheduling decisions. Every C extension is a vector for memory safety issues outside the Ruby GC's visibility. And C extensions that rely on the internal Ruby C API are subject to breakage across Ruby versions in ways that pure Ruby code is not. The Prism parser project — building a new, portable, error-tolerant parser shared across CRuby, JRuby, TruffleRuby, and tooling — is a response to the fragility of parser-adjacent C code that had to be maintained separately for each implementation [RUBY-3-3-RELEASE].

The FFI gem provides a pure-Ruby approach to calling C shared libraries that does not require writing C extension code. JRuby and TruffleRuby ship with FFI support built-in [FFI-README]. FFI is slower than a native C extension but safer and more portable across Ruby implementations. For practitioners who need to call a C library without full C extension infrastructure, FFI is the better choice.

Interoperability with JVM ecosystems via JRuby is production-ready for applications that can accept the trade-offs: JVM startup overhead (~2–5 seconds), different C extension compatibility profile, and JVM memory model (where Java and Ruby objects live in the same heap but with different allocation characteristics). Shopify's Pitchfork and YJIT work on CRuby, not JRuby, so teams using JRuby do not benefit from those optimizations.

WebAssembly support, added in Ruby 3.2 via WASI, enables running Ruby in browser and edge environments. This is genuinely novel — running a Ruby application at the CDN edge without a traditional server deployment — but the ecosystem tooling and production use cases are nascent. For practitioners building standard Rails applications, WASM support is an interesting capability to monitor rather than something to deploy today.

Data interchange is straightforward: Ruby's JSON, CSV, and XML standard library coverage is comprehensive, and the gem ecosystem adds MessagePack, Protocol Buffers, Avro, and other serialization formats. Rails's JSON API support via `jbuilder` or `alba` (a faster alternative) is production-battle-tested.

## 11. Governance and Evolution

Ruby's BDFL model — Matz retains final authority over language decisions — has delivered remarkable consistency and intentionality in language design over thirty years. The Matz filter has kept Ruby from accumulating the kind of "design by committee" complexity visible in some competing languages. When Matz decides against mandatory static types or GVL removal, those decisions are coherent with the language's design philosophy even if practitioners might prefer different choices.

The BDFL model also creates institutional risk. A single point of failure for language direction, a lack of formal RFC process equivalent to Rust's, and no clear succession plan for the language's core identity beyond "Matz decides" are real governance vulnerabilities. The ruby-core mailing list and bugs.ruby-lang.org issue tracker provide community input, but the conversion of that input into language decisions is opaque compared to Rust's RFC process or Go's proposal process.

The Ruby Central governance crisis of September–October 2025 exposed how fragile the institutional structures supporting Ruby's ecosystem can be. A dispute over repository access to Bundler and RubyGems — critical infrastructure that the entire Ruby ecosystem depends on — resulted in abrupt personnel changes, public accusations, community outrage, and ultimately Matz's personal intervention to transfer stewardship to the Ruby Core team [THEREGISTER-RUBYGEMS]. The outcome (Ruby Core stewardship) is probably more stable than Ruby Central's governance model was, but the process was chaotic, the human cost (loss of longtime maintainers who resigned) was significant, and the incident demonstrates that "well-respected nonprofit manages critical infrastructure" is not a governance arrangement that scales through disputes.

Shopify's emergence as the primary corporate patron of Ruby performance work (YJIT, ZJIT, Pitchfork) creates a different kind of governance tension. Shopify employs a significant fraction of the most active Ruby performance contributors, including Jean Boussier (byroot), who has become arguably the most technically influential voice in Ruby's performance architecture. This is good for Ruby's performance trajectory — Shopify has every incentive to make Ruby fast and has the resources to invest significantly. It also means Ruby's performance roadmap tracks Shopify's production needs, which may not always align with the broader community's needs.

Ruby's annual December 25 release cadence is a genuine operational advantage for practitioners. The predictable schedule allows organizations to plan Ruby version upgrades, test compatibility in advance, and execute upgrades with confidence. The two-year support window (one year normal, one year security) is shorter than Java or Python's LTS tracks but provides clear end-of-life signals. The Ruby 3.x → 4.0 transition was remarkably undisruptive — characterized by the community as "a lot of restructuring under the hood, few new features" — suggesting that major version bumps in Ruby carry less migration cost than their numbers imply [HEISE-RUBY-4].

The lack of a formal compatibility promise equivalent to Go's Go 1 Compatibility Promise is a real operational cost. Deprecation warnings precede most removals, but the 3.x series occasionally included minor incompatible changes that required test suite updates even for applications not using deprecated features. Teams running large codebases do regression testing against Ruby release candidates before upgrading, which adds pipeline cost that Go's stronger compatibility guarantee avoids.

## 12. Synthesis and Assessment

### Greatest Strengths

**Productivity at human scale.** Ruby and Rails remain one of the fastest paths from idea to working web application in production. The convention-over-configuration discipline, the ecosystem coherence, and the expressive language design combine to make small-to-medium teams exceptionally productive. GitHub's ability to deploy a 2-million-line Rails monolith 20 times daily to 1,000+ engineers [RESEARCH-BRIEF] demonstrates that the productivity model scales further than skeptics claim.

**The ecosystem's mature fundamentals.** Bundler is excellent. RuboCop is excellent. RSpec is excellent. Rails's testing story is genuinely good. These tools work together coherently and have accumulated years of production hardening. Teams inheriting a Ruby codebase with good test coverage, consistent linting, and locked dependencies have a good foundation to work with.

**YJIT's genuine performance trajectory.** The performance gap between Ruby and compiled languages remains real, but YJIT represents a meaningful and continuing improvement. Ruby 3.4's 92% benchmark speedup over the interpreter, coupled with improved memory management and jemalloc adoption as the production default, has shifted the performance conversation from "Ruby is slow, accept it" to "Ruby is fast enough for most web workloads, and getting faster."

**Community culture.** The Ruby community's emphasis on code craft, testing discipline, and documentation quality produces a codebase culture that is often superior to faster-growing ecosystems. The Rails Community Survey's finding that 93% of respondents feel confident security vulnerabilities are being addressed [RAILS-SURVEY-2024] reflects genuine trust in the core team's stewardship of the primary framework.

### Greatest Weaknesses

**Scaling friction compounds with codebase size.** The lack of static typing, the pervasive dynamic dispatch, and the open class model that make Ruby productive for small teams become maintenance burdens for large teams over long timescales. Refactoring a large Ruby codebase without comprehensive test coverage is nerve-wracking in ways that well-typed languages avoid. The tooling response (RBS, Sorbet) has not achieved mainstream adoption and requires significant investment to deploy comprehensively.

**The concurrency model is architecturally stuck.** The GVL limits single-process parallelism to I/O concurrency via threads or fiber scheduling. Ractors are years away from production viability at best. The workaround — multiple processes, each with their own GVL — is operationally expensive in memory and connection overhead and architecturally limits options for future optimization. Languages designed with shared-memory concurrency from the start (Go, Java, C#) have a structural advantage for CPU-bound parallel workloads that Ruby cannot easily replicate.

**Memory overhead in production is real and requires active management.** 200–600MB per Rails worker, significant startup overhead, jemalloc required for efficient allocation, Kubernetes auto-detection footguns — the operational complexity of deploying Ruby correctly is higher than the language's ease-of-use would suggest. Teams that treat Ruby deployment like deployment of a static binary will hit production incidents.

**Ecosystem governance fragility.** The Ruby Central crisis demonstrated that the institutions supporting critical Ruby infrastructure are not robust to internal disputes. RubyGems's supply chain security track record — multiple large-scale malicious gem campaigns in 2025, an admitted 20–30% detection gap — indicates that the security culture around package distribution needs significant investment. For organizations with supply chain security requirements, Ruby's package ecosystem requires active mitigation strategies.

**Declining adoption trajectory.** JetBrains' "long-term decline" classification alongside PHP and Objective-C [JETBRAINS-2025] reflects real trends: fewer new developers choosing Ruby as a first language, fewer organizations starting new projects in Rails, a shrinking hiring pool. This is not an imminent crisis for existing Ruby organizations — the language remains well-supported, the ecosystem is active, and the salary premium for Ruby expertise suggests strong demand from the existing Ruby infrastructure base. But it is a signal about long-term talent acquisition and community vitality that practitioners in organizations making ten-year technology bets should factor.

### Lessons for Language Design

**1. Convention over configuration is a genuine productivity multiplier, but it has a discovery cost that scales with codebase age.** Rails demonstrated that a sufficiently opinionated framework could eliminate whole categories of decisions for development teams, compressing time-to-value dramatically. The lesson is not "be opinionated" in the abstract but specifically: pre-configure to eliminate common decision points, make conventions *discoverable* (Rails's naming conventions encode routing, template lookup, and class loading all in the same naming system), and accept that the same conventions that help initial developers will puzzle those who join later. Language and framework designers should model how conventions age — conventions that encode implicit knowledge become documentation debt.

**2. Optimizing for the write path at the expense of the read path is a trade that compounds negatively over time.** Ruby prioritizes code that is pleasant to write — expressive, low-ceremony, fluid. The cost is code that is harder to read without running it. Every method call is a potential dispatch to any object implementing a compatible interface; every block argument might be a Proc, a lambda, or a block captured from a different scope. Implicit information — types, which module's method is being called, what state has been modified — lives in runtime context rather than source text. Languages designed for long-lived, multi-contributor codebases should weight readability more heavily than writeability, even at some cost to initial ergonomics.

**3. Gradual typing retrofitted onto a dynamic language is harder than it looks, and ecosystem fragmentation multiplies the difficulty.** Ruby's typing story — RBS separate files, Sorbet inline annotations, Steep, TypeProf — demonstrates that adding type checking to a mature dynamic ecosystem requires more than providing tools; it requires convergence on a single annotation format and IDE integration that developers experience as helpful rather than burdensome. The 2025 Shopify initiative integrating RBS syntax into Sorbet is a step toward convergence, but the five-year timeline to reach that point illustrates the coordination cost. Future languages planning gradual type adoption should architect the annotation format before the ecosystem grows, making it easier to retrofit tooling to existing code rather than retrofitting multiple incompatible annotation systems to each other.

**4. The Global VM Lock is a global state decision that cannot be cheaply reversed.** Ruby's GVL prevented a class of concurrency bugs and simplified interpreter implementation. It also created a concurrency model that cannot be changed without either accepting single-thread performance regressions (from atomic operations on every object) or a complete rewrite of the extension ecosystem. Jean Boussier's analysis [BYROOT-GVL-2025] is required reading for language designers: the true cost of a design decision like the GVL includes the future cost of every path that becomes impossible when you need to evolve the model. Decide your concurrency model early and make it evolvable.

**5. Separating namespace control from performance optimization is an architectural mistake.** Ruby's open class system — where any gem can reopen and modify any class including built-ins — was designed for expressiveness. It is also why implementing truly safe Ractor boundaries is architecturally difficult: any code path might have modified a built-in class in ways that violate thread safety. The expressiveness benefit of open classes comes at a cost to the ability to reason statically about an object's behavior, implement safe parallel execution, or provide reliable IDE tooling. Languages that want both expression flexibility and safe parallelism need a design that separates "can be extended" from "can be modified without warning."

**6. REPL-first design produces better incremental developer experience but misleads about production semantics.** Ruby's REPL (irb, pry) enables an exploratory programming style where developers build up programs incrementally, testing each piece interactively. This is genuinely valuable for learning and prototyping. It also creates a mental model mismatch with production: code written REPL-first tends to be written and tested in a REPL's single-process, warm-state context, not a forked multi-process, cold-start production context. The GC pauses that appear in production, the memory overhead of multiple processes, the startup time of Rails — none of these appear in a REPL session. Languages should design their production feedback loops to be as accessible as their interactive feedback loops.

**7. Package manager trust is a public good that requires institutional investment proportional to ecosystem size.** RubyGems's supply chain security incidents — 275,000+ downloads of confirmed malicious gems in 2025 — reflect a gap between the ecosystem's scale (4 billion monthly downloads) and its security investment. The trust developers extend to `gem install` is a collective resource that bad actors will exploit at whatever rate countermeasures permit. Ecosystem designers should treat package manager trust as public infrastructure requiring security investment commensurate with adoption, not as a solved problem.

**8. Process-level isolation is a legitimate concurrency model, not an admission of failure.** Ruby's practical solution to the GVL — run multiple isolated processes — is often characterized as a workaround. But for web server workloads, process isolation provides benefits that thread-based models do not: crash isolation (a worker crash does not take down the server), memory isolation (no shared mutable state bugs), and clean-slate request handling (no accumulated state from previous requests). Shopify's Pitchfork, with its CoW-optimized reforking, demonstrates that process-based concurrency can be highly optimized for production web workloads. Language designers considering concurrency models should take process isolation seriously as a design target rather than a fallback position.

**9. Corporate patronage of language performance can accelerate development but concentrates roadmap power.** Shopify's investment in YJIT, ZJIT, and Pitchfork has materially improved Ruby's performance trajectory in ways that the community could not have funded independently. The cost is that Ruby's performance roadmap is shaped by Shopify's production needs — large-scale Rails web serving. Language performance priorities that diverge from the primary patron's needs (scientific computing, CLI tooling, embedded systems) receive less investment. Ecosystems should model their patronage structures to either distribute corporate influence across a consortium or ensure that community-direction mechanisms exist independent of the primary patron.

**10. An expressive language that optimizes for programmer happiness creates cultural debt that is distinct from technical debt.** Ruby's culture of expressiveness — "there's more than one way to do it," metaprogramming as first-class tool, aesthetic code as goal — produces communities that value craft but struggle with standardization. Technical debt is code that could be better; cultural debt is the accumulated expectation that code should be beautiful in a way that imposes opinions on contributors who join later. Languages should consider the cultural norms their design choices select for, and whether those norms are sustainable across organizational growth.

---

## References

[ARXIV-RUBY-2025] "Unveiling Ruby: Insights from Stack Overflow and Developer Survey." arXiv:2503.19238v2. March 2025. https://arxiv.org/html/2503.19238v2

[BISHOPFOX-RUBY] Bishop Fox. "Ruby Vulnerabilities: Exploiting Open, Send, and Deserialization." https://bishopfox.com/blog/ruby-vulnerabilities-exploits

[BRANDUR-RUBY-MEMORY] Leach, B. "The Limits of Copy-on-write: How Ruby Allocates Memory." brandur.org. https://brandur.org/ruby-memory

[BRANDUR-TYPING-2024] Leach, B. "Ruby typing 2024: RBS, Steep, RBS Collections." brandur.org/fragments/ruby-typing-2024. 2024.

[BYROOT-GVL-2025] Boussier, J. "So You Want To Remove The GVL?" byroot.github.io, January 29, 2025. https://byroot.github.io/ruby/performance/2025/01/29/so-you-want-to-remove-the-gvl.html

[BYROOT-PITCHFORK-2025] Boussier, J. "The Pitchfork Story." byroot.github.io, March 4, 2025. https://byroot.github.io/ruby/performance/2025/03/04/the-pitchfork-story.html

[BYROOT-RACTORS-2025] Boussier, J. "What's The Deal With Ractors?" byroot.github.io, February 27, 2025. https://byroot.github.io/ruby/performance/2025/02/27/whats-the-deal-with-ractors.html

[CSO-TELEGRAM] "Supply chain attack hits RubyGems to steal Telegram API data." CSO Online, June 2025. https://www.csoonline.com/article/4002437/supply-chain-attack-hits-rubygems-to-steal-telegram-api-data

[DATADOG-RUBY-ALLOC] "Optimize Ruby garbage collection activity with Datadog's allocations profiler." Datadog Blog. https://www.datadoghq.com/blog/ruby-allocations-profiler/

[FFI-README] ffi gem README. https://github.com/ffi/ffi

[HEISE-RUBY-4] "Ruby 4.0 Delivers More Than Expected." Heise Online, December 2025.

[IVOANJO-MN-2025] Anjo, I. "M:N scheduling and how the Ruby GVL impacts app performance." ivoanjo.me, March 30, 2025. https://ivoanjo.me/blog/2025/03/30/mn-scheduling-and-how-the-ruby-gvl-impacts-app-perf/

[JETBRAINS-2025] JetBrains. "State of Developer Ecosystem 2025." https://devecosystem-2025.jetbrains.com/

[MENSFELD-RUBYGEMS] Mensfeld, K. "When Responsibility and Power Collide: Lessons from the RubyGems Crisis." mensfeld.pl, September 2025. https://mensfeld.pl/2025/09/ruby-central-rubygems-takeover-analysis/

[PREFAB-OOM] "A Ruby on Rails OOM Mystery: The Case of the Hungry Hippo." Prefab Engineering Blog, 2024. https://prefab.cloud/blog/rails-oom-killed/

[RAILS-DEPLOYMENT-GUIDE] "Tuning Performance for Deployment." Ruby on Rails Guides. https://guides.rubyonrails.org/tuning_performance_for_deployment.html

[RAILS-SURVEY-2024] Rails Community Survey 2024. 2,700+ respondents, 106 countries. https://rails-hosting.com/2024/

[RAILS8-RELEASE] "Rails 8.0: No PaaS Required." rubyonrails.org, November 7, 2024. https://rubyonrails.org/2024/11/7/rails-8-no-paas-required

[RAILSATSCALE-RBS-SORBET-2025] Shopify Engineering. "RBS support for Sorbet." railsatscale.com, April 23, 2025. https://railsatscale.com/2025-04-23-rbs-support-for-sorbet/

[RAILSATSCALE-YJIT-3-4] Shopify Engineering. "YJIT 3.4: Even Faster and More Memory-Efficient." railsatscale.com, January 10, 2025. https://railsatscale.com/2025-01-10-yjit-3-4-even-faster-and-more-memory-efficient/

[RAILSATSCALE-PACKWERK] Shopify Engineering. "A Packwerk Retrospective." railsatscale.com, January 26, 2024. https://railsatscale.com/2024-01-26-a-packwerk-retrospective/

[RESEARCH-BRIEF] Ruby — Research Brief. research/tier1/ruby/research-brief.md. 2026-02-27.

[RUBY-3-0-RELEASE] Ruby 3.0.0 Release Notes. ruby-lang.org, December 25, 2020.

[RUBY-3-1-RELEASE] Ruby 3.1.0 Release Notes. ruby-lang.org, December 25, 2021.

[RUBY-3-3-RELEASE] Ruby 3.3.0 Release Notes. ruby-lang.org, December 25, 2023.

[RUBY-3-4-RELEASE] Ruby 3.4.0 Release Notes. ruby-lang.org, December 25, 2024.

[RUBY-CVE-REDOS] Ruby Security Advisories. ruby-lang.org/en/security/

[RUBY-SECURITY] "Ruby Security." ruby-lang.org/en/security/

[RUBYGEMS-SECURITY-2025] "How RubyGems.org Protects Our Community's Critical OSS Infrastructure." RubyGems Blog, August 25, 2025. https://blog.rubygems.org/2025/08/25/rubygems-security-response.html

[RUBYGEMS-STATS-2025] RubyGems.org Monthly Stats. rubygems.org/stats, April–May 2025.

[SOCKET-MALICIOUS-GEMS] Socket Threat Research. "60 Malicious Ruby Gems Used in Targeted Credential Theft Campaign." socket.dev, August 2025. https://socket.dev/blog/60-malicious-ruby-gems-used-in-targeted-credential-theft-campaign

[TECHEMPOWER-ROUND-23] TechEmpower. "Framework Benchmarks Round 23." techempower.com, March 2025.

[THEREGISTER-RUBYGEMS] The Register. "Ruby Central tries to make peace after 'hostile takeover'." October 18, 2025. https://www.theregister.com/2025/10/18/ruby_central_taps_ruby_core/

[UPDOWN-YJIT] updown.io. "The performance improvements in Ruby 3.3 with YJIT." updown.io/blog/the-performance-improvements-in-ruby-3-3-with-yjit

[UPDOWN-YJIT-WEIRD] updown.io. "Weird results comparing Ruby 3.1/3.2/3.3 with jemalloc and YJIT." updown.io/blog/weird-results-comparing-ruby-3-1-3-2-3-3-with-jemalloc-and-yjit
