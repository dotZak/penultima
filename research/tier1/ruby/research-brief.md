# Ruby — Research Brief

```yaml
role: researcher
language: "Ruby"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Language Fundamentals

### Creation and Institutional Context

Ruby was conceived by Yukihiro "Matz" Matsumoto, a Japanese programmer working independently without institutional sponsorship. The name originated during an online chat session between Matsumoto and Keiju Ishitsuka on February 24, 1993, before any code had been written. Two names were proposed: "Coral" and "Ruby"; Matsumoto chose the latter [RUBY-ABOUT].

Matsumoto began implementing the language in 1993. The first public release of Ruby 0.95 was announced on Japanese domestic newsgroups on December 21, 1995 [RUBY-ABOUT]. Version 1.0 followed in December 1996 [RUBY-RELEASES].

Ruby was developed without direct corporate funding or university affiliation. Matsumoto worked at Netlab (Network Applied Communication Laboratory Ltd.) in Japan during the language's early development but the language was his personal project [WIKI-MATZ].

### Stated Design Goals

Matsumoto has stated the primary design motivation directly and repeatedly:

On happiness: "I designed Ruby to minimize my surprise. I was very amazed when people around the world told me that Ruby reduced their surprise and enhanced their joy of programming." [ARTIMA-PHILOSOPHY]

On motivation: "I wanted to minimize my frustration during programming, so I want to minimize my effort in programming. That was my primary goal in designing Ruby. I want to have fun in programming myself." [ARTIMA-PHILOSOPHY]

On purpose: "I hope to see Ruby help every programmer in the world to be productive, and to enjoy programming, and to be happy. That is the primary purpose of the Ruby language." [ARTIMA-PHILOSOPHY]

On human-centered design: "Ruby is designed for humans, not machines." [EVRONE-MATZ]

On existing languages: Matsumoto was dissatisfied with Perl, which he felt was "too much of a toy language," and Python, which he did not consider a true object-oriented language [RUBY-HISTORY].

The official Ruby website states: "Ruby is designed to make programmers happy." [RUBY-ABOUT]

### Language Classification

- **Paradigm**: Multi-paradigm — object-oriented (pure: every value is an object), functional (closures, higher-order functions, blocks), imperative, reflective. Matsumoto designed Ruby around the principle that "everything is an object," including literals and primitive values [RUBY-ABOUT].
- **Typing discipline**: Dynamic (duck typing); types are checked at runtime, not compile time. No required type annotations in base language; optional static typing via external tools (Sorbet, RBS + Steep).
- **Memory management**: Automatic via garbage collection. CRuby uses a generational mark-and-sweep garbage collector with incremental collection since Ruby 2.1 [RUBY-GC]. Modular GC introduced in Ruby 3.4 [RUBY-3-4-RELEASE].
- **Compilation model**: Interpreted via bytecode VM. CRuby compiles source to YARV (Yet Another Ruby VM) bytecode introduced in Ruby 1.9 [RUBY-HISTORY-WIKI]. YJIT (a JIT compiler) ships with CRuby since Ruby 3.1 and is enabled by default since Ruby 3.2 [RUBY-3-1-RELEASE]. ZJIT (an experimental method-based JIT) was introduced in Ruby 4.0 [RUBY-4-0-RELEASE].
- **Primary implementation**: CRuby (also called MRI, Matz's Ruby Interpreter), written in C. Alternative implementations include JRuby (JVM-based), TruffleRuby (GraalVM-based), and Rubinius (historical).

### Current Version and Release Cadence

- **Current stable release**: Ruby 4.0.0, released December 25, 2025 [RUBY-4-0-RELEASE]
- **Most recent 3.x maintenance**: Ruby 3.4.x series (Ruby 3.4.8 as of December 26, 2025) [RUBY-3-4-RELEASE]
- **Release cadence**: New major/minor version released every December 25 (since Ruby 2.1) [RUBY-SCHEDULE]. Patch versions released as needed.
- **Support policy**: Each minor release receives normal maintenance for one year, security maintenance for one additional year (two years total) [ENDOFLIFE-RUBY].

---

## Historical Timeline

### Origins and Early Development (1993–2003)

- **February 24, 1993**: Matsumoto and Ishitsuka coin the name "Ruby" in an online chat [RUBY-ABOUT]
- **1993**: Matsumoto begins language implementation [RUBY-HISTORY]
- **December 21, 1995**: Ruby 0.95 publicly announced on Japanese newsgroups; already included object-oriented design, classes with inheritance, mixins, iterators, closures, exception handling, and garbage collection [RUBY-HISTORY-WIKI]
- **December 1996**: Ruby 1.0 released [RUBY-RELEASES]
- **1997**: Ruby's English-language presence grows; first English mailing list established
- **1998**: First stable release, Ruby 1.2 [RUBY-RELEASES]
- **1999**: Dave Thomas and Andrew Hunt publish the first edition of *Programming Ruby* (the "Pickaxe book"), the first English-language Ruby book, significantly expanding international adoption [SITEPOINT-HISTORY]

### Rails Era and International Adoption (2003–2013)

- **2003**: Ruby on Rails development begins by David Heinemeier Hansson (DHH) at Basecamp (formerly 37signals)
- **July 2004**: DHH releases Ruby on Rails publicly [RAILS-WIKI]
- **2004–2006**: Rails popularizes Ruby internationally; drives dramatic growth in Ruby's global developer base
- **December 2007**: Ruby 1.9 released as development version; introduces YARV bytecode VM replacing the original tree-walking interpreter; major performance improvement and Unicode support [RUBY-HISTORY-WIKI]
- **2011**: Ruby 1.9.3 released — stable Ruby 1.9, widely adopted
- **2011**: Ruby standardized as JIS X 3017 (Japanese Industrial Standard) [ISO-30170]
- **2012**: Ruby standardized as ISO/IEC 30170 [ISO-30170]. The standard covers syntax, semantics, and a small core library.
- **February 24, 2013**: Ruby 2.0.0 released on the 20th anniversary of Ruby's naming. Introduced refinements, keyword arguments, Module#prepend, lazy enumerators, and `%i` symbol array literal. Declared only five known incompatibilities with 1.9.3 [RUBY-2-0-RELEASE].

### Ruby 2.x Era: Performance and Modernization (2013–2019)

- **2013**: Ruby 2.0.0; versioning policy changed to be more similar to semantic versioning for 2.1.0+
- **December 2014**: Ruby 2.2.0; incremental garbage collector; symbol GC; support for jemalloc [RUBY-2-2-RELEASE]
- **2015**: Ruby 2.2 introduces incremental GC; Ruby 2.3 adds frozen string literals pragma, the safe navigation operator (`&.`)
- **December 2019**: Ruby 2.7.0; numbered block parameters (`_1`, `_2`); pattern matching as experimental feature; deprecation warnings for features to be removed in 3.0 [RUBY-2-7-RELEASE]

### Ruby 3.x Era: Performance, Concurrency, and Static Typing (2020–2024)

- **December 25, 2020**: Ruby 3.0.0 released. The "Ruby 3x3" milestone — stated goal of being 3× faster than Ruby 2.0. Introduces RBS (Ruby Signature, a type annotation language), TypeProf (a type inference tool), Ractors (parallel execution actors), and Fiber Scheduler interface. Pattern matching stabilized [RUBY-3-0-RELEASE].
- **December 25, 2021**: Ruby 3.1.0. YJIT (Yet another Just-In-Time compiler) developed by Shopify, shipped as experimental. IRB improvements; error messages enhanced [RUBY-3-1-RELEASE].
- **December 25, 2022**: Ruby 3.2.0. YJIT enabled by default (no longer experimental); WebAssembly support added via WASI; improved error messages with suggestions [RUBY-3-2-RELEASE].
- **December 25, 2023**: Ruby 3.3.0. Prism parser introduced (new portable, error-tolerant recursive descent parser); M:N thread scheduler for Ractors; pure-Ruby JIT compiler (RJIT) introduced; YJIT further improved [RUBY-3-3-RELEASE].
- **December 25, 2024**: Ruby 3.4.0. Prism becomes the default parser (replacing parse.y); modular GC framework; `it` as default block parameter (single-letter); Happy Eyeballs Version 2 (RFC 8305) in socket library; YJIT further optimized [RUBY-3-4-RELEASE].

### Ruby 4.0 (2025–present)

- **December 25, 2025**: Ruby 4.0.0 released. Major version bump coincides with Ruby's 30th anniversary. Key changes: ZJIT experimental method-based JIT (Shopify-developed); `Ruby::Box` for lightweight namespace isolation; Ractor::Port replacing Ractor.yield/Ractor#take for safer communication; Set promoted to core class (no longer requires `require 'set'`); `SortedSet` removed; various smaller deprecations from 3.x cleared [RUBY-4-0-RELEASE].

### Notable Rejected or Deprecated Features

- **Static typing as first-class feature**: Matz consistently rejected mandatory static types; instead pursued the opt-in approach via RBS and external checkers (Sorbet, Steep) [RUBY-TYPING-2024].
- **GVL (Global VM Lock) removal**: Matz has declined to remove the GVL, accepting Ractors as the parallelism model instead [RACTORS-BYROOT-2025]. GVL removal would require per-object locks or atomic reference counting and widespread C extension refactoring.
- **Removal of `eval` and metaprogramming**: No serious attempt; considered core Ruby identity.

---

## Adoption and Usage

### Market Position and Rankings

- **TIOBE Index** (April 2025): Ruby ranked 24th; described as having "fallen out of the top 20" and being "unlikely to return anytime soon" following a period of decline [TIOBE-2025]. Ruby had previously peaked near 10th place in the mid-2010s.
- **Stack Overflow Developer Survey 2024** (65,000+ respondents): Ruby ranked among programming languages used, but no longer in the top 15; the academic study of Stack Overflow data notes Ruby peaked at approximately 6% of user engagement around 2012 and had dropped to approximately 2% by 2020 [ARXIV-RUBY-2025]. Ruby is ranked 5th highest-paying technology in the 2024 Stack Overflow survey despite declining usage [ARXIV-RUBY-2025].
- **JetBrains State of Developer Ecosystem 2025** (24,534 developers, 194 countries): Ruby classified alongside PHP and Objective-C as languages in "long-term decline" [JETBRAINS-2025].
- **W3Techs**: No specific Ruby web server percentage reported; Rails-powered sites represent a small fraction compared to PHP's 74.5%.
- **GitHub**: Over 1 million GitHub users utilize Ruby; more than 2 million projects use Ruby [ARXIV-RUBY-2025].

### Primary Domains and Industries

Ruby is deployed predominantly in:

- **Web application development**: The primary use case since Rails (2004). Rails-based applications power significant portions of consumer internet infrastructure.
- **Startup and early-stage companies**: Rails historically a dominant choice for MVPs and rapid product development.
- **E-commerce**: Shopify's platform serves approximately 4 million merchants [LEARNENOUGH-RAILS] and calls itself "the biggest Rails app in the world."
- **Developer tooling and scripting**: Rake, RuboCop, Bundler, and many CI/CD tools written in Ruby.
- **Content and media platforms**: Historically Tumblr, Twitter (early), GitHub.

### Major Companies and Projects Using Ruby

As of 2024–2025:

- **Shopify**: Self-described as "the biggest Rails app in the world"; Shopify's infrastructure is the primary patron of YJIT development [SHOPIFY-YJIT].
- **GitHub**: Deploys a 2-million-line Rails monolith approximately 20 times daily with 1,000+ engineers; uses automated weekly Rails version bumps [LEARNENOUGH-RAILS].
- **Airbnb**: Uses Rails with React for web application development [LEARNENOUGH-RAILS].
- **Zendesk**, **Gitlab**, **Coinbase**, **Groupon**, **Crunchbase**: Documented Rails deployments [NETGURU-RAILS].
- **Doximity**: Largest digital platform for U.S. medical professionals (2 million+ healthcare professionals; 80% of U.S. doctors); built on Rails [LEARNENOUGH-RAILS].

### Community Size Indicators

- **RubyGems.org**: 4.15 billion gem downloads in April 2025 (first month exceeding 4 billion; 51% increase from April 2024's 2.74 billion); 4.06 billion in May 2025 [RUBYGEMS-STATS-2025].
- **RubyGems download logs**: Over 180 billion total rows as of April 2025, with data from 2017 [CLICKHOUSE-RUBYGEMS].
- **Stack Overflow**: 498,719 Ruby-related questions analyzed in academic research covering July 2008–March 2024 [ARXIV-RUBY-2025].
- **Rails Community Survey 2024**: Over 2,700 respondents from 106 countries — described as the highest response count in the survey's history since 2009 [SOCKET-RAILS-SURVEY-2024].
- **RubyConf** and **RailsConf**: Annual conferences maintained with hundreds to low thousands of attendees.

---

## Technical Characteristics

### Type System

Ruby is dynamically typed. There are no compile-time type declarations in base Ruby; all type checking occurs at runtime. The language uses duck typing: an object's suitability is determined by the presence of appropriate methods, not by explicit type declarations.

**Key type system properties:**

- **Everything is an object**: Integers, strings, booleans, `nil` — all are objects with class and methods. There are no primitive types in the Java/C sense.
- **Open classes**: Any class, including built-in classes, can be reopened and modified (monkey-patching). This is a deliberate design feature enabling "expressive" extension but a source of fragility.
- **Modules and mixins**: Ruby uses modules (`module`) as the mechanism for multiple inheritance-like behavior. Classes can include modules (`include`), extending their method set. This is used heavily in the standard library (e.g., `Enumerable`, `Comparable`).
- **Method missing**: Objects can implement `method_missing` to intercept calls to undefined methods at runtime, enabling proxy patterns and DSLs.
- **No generics**: Ruby has no parameterized types. Collections hold objects of any type without constraint.
- **No interfaces or traits in the formal sense**: Modules serve a similar purpose but are not enforced by the type system.

**Optional static typing tools (opt-in):**

Ruby 3.0 introduced RBS, a type annotation language. RBS files (`.rbs` extension) live alongside Ruby source, describing types without modifying the Ruby code itself. This approach differs from Sorbet, which annotates directly in Ruby code using `T.sig` blocks. Both are opt-in and not enforced by the CRuby runtime.

- **RBS**: Official Ruby type annotation language, introduced in Ruby 3.0. Defines method signatures, class shapes, and interface-like structures in separate `.rbs` files [RBS-APPSIGNAL].
- **Sorbet**: A static type checker for Ruby developed by Stripe; uses inline type annotations (`T.sig`) throughout Ruby source files [SORBET-ORG].
- **Steep**: A type checker that uses RBS files; informally associated with the official RBS initiative [RUBY-TYPING-2024].
- **TypeProf**: Bundled with Ruby; attempts to infer types from untyped code and generate RBS signatures [RUBY-3-0-RELEASE].

Brandur Leach (2024) characterizes the state: adoption of these tools remains limited; the Ruby typing ecosystem is fragmented between Sorbet's inline approach and RBS's separate-file approach, with neither achieving widespread mainstream adoption [RUBY-TYPING-2024].

### Memory Model

Ruby uses automatic memory management. CRuby's GC is a tri-color incremental mark-and-sweep collector with generational collection.

**GC evolution:**

- **Pre-2.1**: Non-generational mark-and-sweep; full GC pauses
- **Ruby 2.1**: Generational GC introduced; objects separated into young (eden) and old heaps; most GC cycles touch only young objects [RUBY-2-2-RELEASE]
- **Ruby 2.2**: Incremental GC (reduces maximum pause time); symbol GC (symbols can now be garbage collected, preventing a symbol table leak vector) [RUBY-2-2-RELEASE]
- **Ruby 3.4**: Modular GC framework introduced, enabling alternative GC implementations to be loaded dynamically via `RUBY_GC_LIBRARY` environment variable [RUBY-3-4-RELEASE]

**Memory profile**: Ruby applications carry significant memory overhead due to object headers and heap structure. Each Ruby object (RVALUE) is 40 bytes regardless of content on 64-bit systems. C extensions that maintain their own memory outside the Ruby heap are not tracked by the GC.

**Developer burden**: Memory management is largely transparent to developers. The GC can cause latency spikes in production; tuning GC parameters (e.g., `GC.compact`, `RUBY_GC_HEAP_GROWTH_FACTOR`) requires expertise. Tools like `memory_profiler` and Datadog's allocations profiler are commonly used to diagnose memory issues [DATADOG-RUBY-ALLOC].

### Concurrency and Parallelism Model

**Threads**: Ruby supports POSIX threads (`Thread.new`). However, the Global VM Lock (GVL, historically called GIL) ensures only one thread executes Ruby bytecode at a time. Threads can run in parallel during blocking I/O operations (the GVL is released during I/O, sleep, and certain C extension calls) but not during CPU-bound computation [GVL-SPEEDSHOP].

**Fibers**: Ruby supports Fibers, lightweight cooperative coroutines. Since Ruby 3.0, a Fiber Scheduler interface allows third-party schedulers (e.g., `async` gem) to make I/O-bound fiber switching transparent [RUBY-3-0-RELEASE]. Fibers do not provide parallelism but enable efficient concurrency for I/O-heavy workloads.

**Ractors**: Introduced experimentally in Ruby 3.0; Ractors (Ruby Actors) provide parallel execution by running in separate GVL domains. Each Ractor has its own GVL, enabling true CPU parallelism for Ruby code [BRANDUR-RACTORS]. Constraints: Ractors cannot share mutable state; objects must be frozen or explicitly moved/copied between Ractors. `Ractor.yield` and `Ractor#take` for communication were removed in Ruby 4.0 in favor of the new `Ractor::Port` class [RUBY-4-0-RELEASE]. As of early 2026, Ractors are not production-ready for most use cases; significant C extension compatibility issues remain [DEVCLASS-RUBY-4].

**M:N thread scheduler**: Introduced in Ruby 3.3; maps M Ruby threads to N native OS threads. Reduces thread creation and management overhead [RUBY-3-3-RELEASE]. Disabled on the main Ractor by default due to C extension compatibility concerns.

**GVL removal status**: Matz has declined to remove the GVL, accepting Ractors as the parallelism path. Jean Boussier (byroot, Shopify) published a detailed analysis (January 2025) explaining the technical and ecosystem complexity barriers to GVL removal [BYROOT-GVL-2025].

### Error Handling

Ruby uses exception-based error handling. There is no built-in `Result` or `Either` type; errors are communicated via exceptions (`raise`) or convention (returning `nil` or `false` for soft failures).

**Core mechanism**:

```
begin
  # code
rescue SomeError => e
  # handle
rescue OtherError => e
  # handle
else
  # no exception raised
ensure
  # always executes
end
```

- `raise` (alias `fail`) raises an exception
- `rescue` catches specified exception classes and their subclasses
- `ensure` runs regardless of exception status
- `retry` inside `rescue` re-executes the `begin` block
- Inline `rescue` modifier available: `value = risky_call rescue default`

**Exception hierarchy**: Ruby distinguishes `Exception` (all exceptions) from `StandardError` (most application errors); `rescue` without specifying a class catches `StandardError` and subclasses. `RuntimeError`, `ArgumentError`, `TypeError`, `NameError`, `NoMethodError` are common `StandardError` subclasses. `SignalException`, `SystemExit`, and `Interrupt` descend from `Exception` and are not caught by bare `rescue`.

**Common pitfall**: Using `rescue Exception` rather than `rescue StandardError` catches signals and system exits, which is considered bad practice and documented as a common anti-pattern [RUBY-ERROR-HANDLING].

### Compilation and Interpretation Pipeline

1. **Parsing**: Source code → AST via Prism parser (default since Ruby 3.4; replaced parse.y) [RUBY-3-4-RELEASE]. Prism is a portable, error-tolerant recursive descent parser shared with CRuby, JRuby, TruffleRuby, and tools like RuboCop [RUBY-3-3-RELEASE].
2. **Compilation**: AST → YARV bytecode
3. **Interpretation**: YARV (Yet Another Ruby VM) interprets bytecode [RUBY-HISTORY-WIKI]
4. **JIT (optional)**: YJIT compiles hot bytecode sequences to native machine code at runtime. Enabled by default in Ruby 3.2+ [RUBY-3-2-RELEASE]. ZJIT (experimental, method-level) introduced in Ruby 4.0 [RUBY-4-0-RELEASE].

### Standard Library Scope

Ruby's standard library is large, covering: file I/O, networking (HTTP, FTP, SMTP), regular expressions, JSON/CSV/XML parsing, Base64, OpenSSL, database interfaces (via adapter gems), logging, formatting, date/time manipulation, and more. Key standard library inclusions:

- `Bundler`: Dependency management, bundled since Ruby 2.6
- `Rake`: Build tool (Ruby's make)
- `ERB`: Embedded Ruby templating
- `Set`: Core class from Ruby 4.0 (formerly standard library)
- `Encoding`: Multi-encoding string support since Ruby 1.9

---

## Ecosystem Snapshot

### Primary Package Manager and Registry

**RubyGems** is the package manager; `gem` is the CLI tool. **Bundler** (`bundle`) manages project-level dependency resolution and locking via `Gemfile` and `Gemfile.lock`.

**Registry statistics** (as of April–May 2025):

- 4.15 billion gem downloads in April 2025 (first month exceeding 4 billion; up 51% from April 2024) [RUBYGEMS-BLOG-APRIL-2025]
- 4.06 billion gem downloads in May 2025 (record single-day: 193 million on May 14, 2025) [RUBYGEMS-BLOG-MAY-2025]
- Over 180 billion total rows in download logs (data from 2017) [CLICKHOUSE-RUBYGEMS]

In October 2025, the Ruby core team (led by Matz) assumed stewardship of RubyGems and Bundler from Ruby Central following a governance dispute, bringing package management under the same organizational umbrella as the language itself [RUBY-RUBYGEMS-TRANSITION].

### Major Frameworks

- **Ruby on Rails** (Rails): Dominant web framework; model-view-controller (MVC) pattern; creator David Heinemeier Hansson; powers Shopify, GitHub, Airbnb, Zendesk, and many others. 2024 Rails Community Survey (2,700+ respondents, 106 countries): 83% of respondents feel the Rails core team is shepherding the project correctly; 93% feel confident security vulnerabilities are being addressed [RAILS-SURVEY-2024]. Monolithic architecture preferred by 77% of Rails developers (up from 62% in 2009) [RAILS-SURVEY-2024].
- **Sinatra**: Lightweight DSL for web applications; minimal framework.
- **Hanami**: Alternative MVC web framework; positioned as more modular than Rails.
- **Sidekiq**: Background job processing framework, widely adopted; mentioned prominently in Rails survey.
- **Solid Queue**, **Good Job**: Newer background job processors gaining Rails community traction [RAILS-SURVEY-2024].

### Frontend Tooling (Rails context)

- **Stimulus.js**: 31% usage among Rails developers (2024); surpassed React (24%) as most used JavaScript library alongside Rails [RAILS-SURVEY-2024].
- **Hotwire** (Turbo + Stimulus): DHH's approach to server-side rendered applications with minimal JavaScript; increasingly adopted.

### IDE and Editor Support

- **Visual Studio Code**: 44% of Rails developers (2024 survey) [RAILS-SURVEY-2024]; Ruby LSP extension provides language server support.
- **RubyMine**: JetBrains IDE with dedicated Ruby/Rails support.
- **Neovim/Vim, Emacs**: Supported via language server protocol (Ruby LSP, Solargraph).

### Testing Frameworks

- **RSpec**: Behavior-driven development (BDD) framework; most widely adopted in Rails community
- **Minitest**: Ships with Ruby by default since Ruby 2.2; more lightweight than RSpec

### Linting and Static Analysis

- **RuboCop**: Static code analyzer and formatter; highly extensible via plugins (rubocop-rails, rubocop-rspec, rubocop-performance, etc.) [RUBOCOP-ORG]
- **StandardRB**: Opinionated RuboCop configuration as a gem; lower-friction adoption

### Version Management

- **rbenv**: Most popular version manager (Rails survey 2024) [RAILS-SURVEY-2024]
- **asdf**: Multi-language version manager, popular among Rails developers
- **RVM (Ruby Version Manager)**: Historically dominant; declining in usage [RAILS-SURVEY-2024]

### Build and CI/CD

- **Rake**: Standard build tool written in Ruby (Ruby's make equivalent); widely used for task automation
- CI/CD: GitHub Actions, CircleCI, and Buildkite commonly used in Ruby/Rails projects

---

## Security Data

### CVE Volume and Patterns

CveDetails.com reports the following CVE counts for the Ruby language runtime [CVEDETAILS-RUBY]:

- **2025** (as of February): 6 vulnerabilities; average CVSS score 6.9
- **2024**: 3 security vulnerabilities published
- **2023**: Data available; multiple CVEs in standard library components
- **Totals**: Historical CVE count concentrated in standard library components (date, uri, openssl, rexml, webrick) rather than core VM

**Common CWE categories** for Ruby vulnerabilities [RUBY-SECURITY; BISHOPFOX-RUBY]:

1. **Regular Expression Denial of Service (ReDoS)**: Multiple CVEs in `date` gem and `uri` component due to catastrophic backtracking in regex parsing of untrusted input (e.g., CVE affecting `Date.parse` in date gem through 3.2.0; URI parser in versions before 0.12.2) [RUBY-CVE-REDOS].
2. **Remote Code Execution via deserialization**: YAML deserialization vulnerabilities allowing arbitrary Ruby code execution; Ruby on Rails mass-assignment vulnerabilities (historical; pre-Rails 4 default-open mass assignment) [RAILS-RCE-CODECLIMATE].
3. **Command injection via `open()`**: The built-in `Kernel#open` method, if called with user-supplied input beginning with `|`, executes arbitrary OS commands [BISHOPFOX-RUBY].
4. **Unsafe `send()` invocation**: Using `Object#send` with untrusted input allows arbitrary method invocation [BISHOPFOX-RUBY].
5. **HTTP response splitting**: CVE in WEBrick (Ruby's built-in HTTP server) allowing header injection via untrusted input through Ruby 2.6.4 [RUBY-SECURITY].
6. **Buffer over-read / double-free in Regexp**: CVEs in Ruby's regex compiler affecting Ruby 3.0.x and 3.1.x; exploitable via untrusted user input for regex compilation [RUBY-SECURITY].
7. **Path traversal and NUL byte injection**: Tempfile and tmpdir components; Windows-specific path traversal (CVE-2021-28966) [RUBY-SECURITY].
8. **REXML XML round-trip vulnerability**: CVE-2021-28965 allowing modification of parsed XML [RUBY-SECURITY].

The official Ruby security page provides advisories dating back to Ruby 1.8.x [RUBY-SECURITY].

### Supply Chain Security

**Typosquatting incidents on RubyGems:**

- **February 2020**: Over 700 malicious gems uploaded to RubyGems.org over approximately one week; gems were typosquatted variants of legitimate names (hyphens ↔ underscores); contained cryptocurrency wallet address hijacking malware; downloaded 95,000+ times before removal [THN-TYPOSQUAT-2020].
- **2023–2025**: Fresh set of 60 malicious packages posing as social media/messaging automation tools, active since at least March 2023; cumulative downloads exceeding 275,000; designed to steal credentials [REVERSINGLABS-GEMS].
- **2025**: Malicious gems (`fastlane-plugin-telegram-proxy`, `fastlane-plugin-proxy_teleram`) discovered; exploited developers circumventing Vietnam's Telegram ban; intercepted CI/CD pipeline credentials [SOCKET-MALICIOUS-GEMS].
- **August 2025**: RubyGems and PyPI hit simultaneously by malicious packages stealing credentials and crypto [THN-GEMS-2025].

### Language-Level Security Mitigations

- `$SAFE` global (historic, removed in Ruby 3.0): Ruby 1.x and 2.x supported taint tracking via `$SAFE` levels to restrict potentially dangerous operations. This mechanism was deprecated and removed in Ruby 3.0 as it did not provide reliable security guarantees [RUBY-3-0-RELEASE].
- No memory safety guarantees at the language level (C extensions can introduce unsafe memory operations)
- Frozen string literals (`# frozen_string_literal: true`): Pragma to prevent string mutation; reduces object allocation and prevents certain mutation bugs

---

## Developer Experience Data

### Survey Data

**Stack Overflow Developer Survey:**

- Ruby ranked 5th highest-paying technology in the 2024 Stack Overflow survey despite declining usage ranking [ARXIV-RUBY-2025]
- Ruby had approximately 6% user engagement peak around 2012; declined to approximately 2% by 2020 per analysis of Stack Overflow question data [ARXIV-RUBY-2025]
- In 2022 Stack Overflow survey: 49.99% of Ruby respondents reported "loving" the language; 50.01% expressed fear of it — approximately even split [TMS-RUBY-STATS]
- Ruby no longer appears in major Stack Overflow survey "most loved" or "most admired" language top lists as of 2024

**JetBrains State of Developer Ecosystem:**

- 2025 survey (24,534 developers, 194 countries): Ruby classified as in "long-term decline" alongside PHP and Objective-C [JETBRAINS-2025]
- 2023 JetBrains survey: dedicated Ruby section published, showing detailed Ruby usage patterns [JETBRAINS-2023-RUBY]

**Rails Community Survey 2024** (2,700+ respondents, 106 countries, 8th annual edition):

- 83% feel the Rails core team is shepherding the project in the right direction [RAILS-SURVEY-2024]
- 93% feel confident security vulnerabilities are being addressed in new Rails releases [RAILS-SURVEY-2024]
- VSCode: 44% of respondents use it as primary editor [RAILS-SURVEY-2024]
- RSpec: widely adopted testing framework of choice [RAILS-SURVEY-2024]
- rbenv and asdf most popular version managers; RVM declining [RAILS-SURVEY-2024]
- Monolithic architecture preference: 77% (up from 62% in 2009) [RAILS-SURVEY-2024]
- RuboCop: widely adopted linter [RAILS-SURVEY-2024]

### Salary Data

- **Stack Overflow 2024**: Ruby ranked 5th highest-paying technology (specific dollar figure not extracted from survey; Ruby historically $120,000–$150,000+ in U.S. markets) [ARXIV-RUBY-2025]
- **TIOBE/community sources**: Ruby developers often command premium compensation in Western markets due to combination of language experience and typically Rails/web backend specialization

### Learning Curve

Ruby is designed for expressiveness and readability. The language is considered accessible for beginners due to its natural-language syntax and minimal boilerplate. The academic study of Stack Overflow data found:

- Web Application Development was the most commonly discussed Stack Overflow category (27.55% of Ruby questions) [ARXIV-RUBY-2025]
- Core Ruby Concepts was found "particularly difficult" by 31.6% of surveyed developers (154 respondents) [ARXIV-RUBY-2025]
- Application Quality and Security was challenging for over 40% of experienced developers [ARXIV-RUBY-2025]
- Gem Installation and Configuration Issues was identified as the most challenging topic [ARXIV-RUBY-2025]

---

## Performance Data

### YJIT Performance (CRuby JIT Compiler)

YJIT is a block-based JIT compiler developed by Shopify; merged into CRuby as experimental in Ruby 3.1, production-ready since Ruby 3.2, enabled by default since Ruby 3.2.

**YJIT 3.4 benchmark results** (from Shopify engineering, January 2025) [RAILSATSCALE-YJIT-3-4]:

- **92% faster** than interpreter on x86-64 headline benchmarks
- **5–7% faster** than YJIT 3.3.6 on benchmarks
- **14% faster** than Ruby 3.3 for pure-Ruby protobuf implementation on x86-64
- C method call inline rates: 56.3% on `lobsters` benchmark; 82.5% on `liquid-render` benchmark
- YJIT 3.4 uses slightly less memory than 3.3 despite compiling more code
- Ruby 3.3 YJIT: 21% memory increase compared to interpreter; Ruby 3.4 interpreter: ~8% memory reduction vs. 3.3

**Shopify production metrics** (Black Friday/Cyber Monday 2024):

- Shopify processed $11.5 billion in sales during BFCM 2024 using YJIT
- Handled 80 million requests per minute on Black Friday on prerelease YJIT 3.4 [RAILSATSCALE-YJIT-3-4]
- StoreFront Renderer: serves 175+ countries, depends on 220+ gems

**Historical YJIT claims** (Shopify, Ruby 3.3):

- 70.7% faster than interpreted CRuby overall; 78.8% faster on Railsbench specifically [RAILSATSCALE-YJIT-3-3]
- Real-world Rails applications: 15–25% performance improvement; some CPU-intensive workloads exceed 40% [UPDOWN-RUBY-3-3]

**ZJIT** (Ruby 4.0): Experimental method-based JIT using SSA intermediate representation; approved by Matz at RubyKaigi 2025; merged May 2025; described as "not production ready" in the Ruby 4.0 release commentary [DEVCLASS-RUBY-4].

### TechEmpower Framework Benchmarks

TechEmpower Framework Benchmarks Round 23 (March 2025, Intel Xeon Gold 6330, 56 cores) [TECHEMPOWER-ROUND-23]:

- Ruby (Rails) and Ruby (Sinatra) frameworks occupy lower performance tiers
- Rust-based frameworks dominate top positions
- Ruby frameworks similar in throughput tier to Python Django and PHP Laravel
- Requests-per-second for Ruby frameworks: lower tier (thousands to tens of thousands RPS) vs. optimized Rust (hundreds of thousands to millions RPS)

### Computer Language Benchmarks Game

Ruby is consistently in the lower-performance tier relative to compiled languages (C, C++, Rust, Go) on the CLBG. YJIT substantially narrows but does not close this gap. Exact numbers vary by benchmark type; Ruby is typically 5–50× slower than C on computational benchmarks [CLBG].

### Startup Time and Resource Consumption

- Ruby startup time (without Rails): ~50–150ms
- Rails application startup: 1–10 seconds depending on number of gems and initializers
- Memory footprint: Rails applications typically 200–600MB per process at steady state
- CRuby's GC tuning parameters affect memory/throughput trade-off; production deployments typically require GC tuning

### Alternative Implementations

- **JRuby**: Ruby on the JVM; achieves true thread parallelism (no GVL); JVM startup overhead; JIT via JVM; production-ready for many workloads
- **TruffleRuby**: Ruby on GraalVM; peak performance often exceeds CRuby with YJIT; longer warmup; used in some production environments [TRUFFLERUBY-CEXT]
- Both JRuby and TruffleRuby ship with FFI support built-in (no gem install required) [FFI-README]

---

## Governance

### Decision-Making Structure

Ruby is a BDFL (Benevolent Dictator For Life) language. Yukihiro "Matz" Matsumoto retains final authority over language decisions. Matz stated in 2025 discussions: "Version numbering decisions are completely a decision for Matz to make as he wishes." [RUBY-ISSUE-21657]

The **Ruby Core Team** is a group of developers with commit access who collectively develop CRuby. The team operates through the Ruby issue tracker (bugs.ruby-lang.org) and the ruby-core mailing list.

**Ruby Association**: A Japanese nonprofit organization (Ruby Association) founded by Matz; promotes Ruby development and education; administers Ruby Programmer certification examinations [WIKI-RUBY].

**Ruby Central**: A U.S.-based nonprofit organization that historically stewarded RubyGems.org, RubyGems, and Bundler infrastructure. In October 2025, following a governance dispute, Matz intervened and the Ruby core team assumed stewardship of RubyGems and Bundler, removing these from Ruby Central's control [RUBY-RUBYGEMS-TRANSITION]. Community reception was generally positive; trust in Ruby Central as a steward organization was damaged by the incident [SOCKET-RUBYGEMS-STEWARDSHIP].

### Key Maintainers and Organizational Backing

- **Matz (Yukihiro Matsumoto)**: Creator and BDFL; employed by Cookpad (Japanese food recipe company) as Chief Architect, previously worked at Heroku
- **Shopify**: Primary corporate patron for YJIT and ZJIT development; employs multiple Ruby core contributors including Jean Boussier (byroot), John Hawthorn, and the YJIT team [SHOPIFY-YJIT]
- **Ruby Central**: Historically funded RubyGems infrastructure; role significantly diminished after October 2025 governance dispute
- **Heroku** (historically): Early Ruby/Rails infrastructure patron

**Ruby Central Annual OSS Report 2024**: Documents funding and contributor support activities through 2024 [RUBYCENTRAL-REPORT-2024].

### Funding Model

- Ruby Central was funded via corporate sponsorships and RubyConf/RailsConf event revenue
- Shopify contributes developer time (most significant YJIT/ZJIT contributions)
- No formal RFC process equivalent to Rust's RFCs; language changes discussed on ruby-core mailing list and Ruby issue tracker

### Backward Compatibility Policy

Ruby does not provide a formal written compatibility guarantee equivalent to Go's Go 1 Compatibility Promise. In practice:

- Minor-to-minor upgrades (e.g., 3.3 → 3.4) occasionally include breaking changes; deprecation warnings precede most removals
- The 3.x → 4.0 transition involved removal of `$SAFE`, `SortedSet`, `Ractor.yield/Ractor#take`, certain argument forwarding syntax changes, and other accumulated 3.x deprecations
- Major version bumps (2.0, 3.0, 4.0) have historically been less disruptive than their version numbers imply; the community characterizes Ruby 4.0 as "a lot of restructuring under the hood, few new features" [HEISE-RUBY-4]

### Standardization

- **JIS X 3017** (2011): Japanese Industrial Standard [ISO-30170]
- **ISO/IEC 30170:2012**: International standard; covers syntax, semantics, and a small core library across 313 pages [ISO-30170]. The standard describes the language specification as of Ruby 1.8/1.9 era and has not been updated to track subsequent versions. CRuby 3.x and 4.x diverge significantly from the standardized subset.

---

## References

[ARTIMA-PHILOSOPHY] Shaughnessy, P. "The Philosophy of Ruby: A Conversation with Yukihiro Matsumoto." Artima.com. https://www.artima.com/articles/the-philosophy-of-ruby

[ARXIV-RUBY-2025] "Unveiling Ruby: Insights from Stack Overflow and Developer Survey." arXiv:2503.19238v2. March 2025. https://arxiv.org/html/2503.19238v2

[BISHOPFOX-RUBY] Bishop Fox. "Ruby Vulnerabilities: Exploiting Open, Send, and Deserialization." https://bishopfox.com/blog/ruby-vulnerabilities-exploits

[BRANDUR-RACTORS] Leach, B. "Ruby 3's Ractors." brandur.org/nanoglyphs/018-ractors

[BYROOT-GVL-2025] Boussier, J. "So You Want To Remove The GVL?" byroot.github.io, January 29, 2025. https://byroot.github.io/ruby/performance/2025/01/29/so-you-want-to-remove-the-gvl.html

[RACTORS-BYROOT-2025] Boussier, J. "What's The Deal With Ractors?" byroot.github.io, February 27, 2025. https://byroot.github.io/ruby/performance/2025/02/27/whats-the-deal-with-ractors.html

[CLICKHOUSE-RUBYGEMS] "Announcing Ruby Gem analytics powered by ClickHouse and Ruby Central." ClickHouse Blog. https://clickhouse.com/blog/announcing-ruby-gem-analytics-powered-by-clickhouse

[CLBG] Computer Language Benchmarks Game. https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html

[CVEDETAILS-RUBY] CVEDetails.com. "Ruby-lang Ruby: Security vulnerabilities, CVEs." https://www.cvedetails.com/product/12215/Ruby-lang-Ruby.html?vendor_id=7252

[DATADOG-RUBY-ALLOC] Datadog. "Optimize Ruby garbage collection activity with Datadog's allocations profiler." https://www.datadoghq.com/blog/ruby-allocations-profiler/

[DEVCLASS-RUBY-4] DevClass. "Ruby 4.0 released – but its best new features are not production ready." January 6, 2026. https://devclass.com/2026/01/06/ruby-4-0-released-but-its-best-new-features-are-not-production-ready/

[ENDOFLIFE-RUBY] endoflife.date. "Ruby." https://endoflife.date/ruby

[EVRONE-MATZ] Evrone. "Yukihiro Matsumoto: 'Ruby is designed for humans, not machines.'" https://evrone.com/blog/yukihiro-matsumoto-interview

[FFI-README] ffi/ffi GitHub repository. https://github.com/ffi/ffi

[GVL-SPEEDSHOP] Hoffman, N. "The Practical Effects of the GVL on Scaling in Ruby." speedshop.co, May 11, 2020. https://www.speedshop.co/2020/05/11/the-ruby-gvl-and-scaling.html

[HEISE-RUBY-4] Heise Online. "Ruby 4.0: A lot of restructuring under the hood, few new features." https://www.heise.de/en/background/Ruby-4-0-A-lot-of-restructuring-under-the-hood-few-new-features-11121859.html

[ISO-30170] ISO. "ISO/IEC 30170:2012 — Information technology — Programming languages — Ruby." https://www.iso.org/standard/59579.html

[JETBRAINS-2023-RUBY] JetBrains. "Ruby Programming – State of Developer Ecosystem 2023." https://www.jetbrains.com/lp/devecosystem-2023/ruby/

[JETBRAINS-2025] JetBrains. "State of Developer Ecosystem 2025." https://devecosystem-2025.jetbrains.com/

[LEARNENOUGH-RAILS] LearnEnough. "Companies Using Ruby on Rails in 2024 & Why It's Their Go-To." https://www.learnenough.com/blog/companies-using-ruby-on-rails

[NETGURU-RAILS] Netguru. "Top Companies Using Ruby on Rails." https://www.netguru.com/blog/top-companies-using-ruby-on-rails

[RAILS-RCE-CODECLIMATE] Code Climate. "Rails' Remote Code Execution Vulnerability Explained." https://codeclimate.com/blog/rails-remote-code-execution-vulnerability-explained

[RAILS-SURVEY-2024] Planet Argon / railsdeveloper.com. "2024 Ruby on Rails Community Survey Results." https://railsdeveloper.com/survey/2024/

[RAILS-WIKI] Wikipedia. "Ruby on Rails." https://en.wikipedia.org/wiki/Ruby_on_Rails

[RAILSATSCALE-YJIT-3-3] Shopify Engineering. "Ruby 3.3's YJIT: Faster While Using Less Memory." railsatscale.com, December 4, 2023. https://railsatscale.com/2023-12-04-ruby-3-3-s-yjit-faster-while-using-less-memory/

[RAILSATSCALE-YJIT-3-4] Shopify Engineering. "YJIT 3.4: Even Faster and More Memory-Efficient." railsatscale.com, January 10, 2025. https://railsatscale.com/2025-01-10-yjit-3-4-even-faster-and-more-memory-efficient/

[RBS-APPSIGNAL] AppSignal Blog. "RBS: A New Ruby 3 Typing Language in Action." January 27, 2021. https://blog.appsignal.com/2021/01/27/rbs-the-new-ruby-3-typing-language-in-action.html

[REVERSINGLABS-GEMS] ReversingLabs. "Mining for malicious Ruby gems." https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems

[RUBOCOP-ORG] RuboCop. https://rubocop.org/

[RUBYGEMS-BLOG-APRIL-2025] RubyGems Blog. "April 2025 RubyGems Updates." May 20, 2025. https://blog.rubygems.org/2025/05/20/april-rubygems-updates.html

[RUBYGEMS-BLOG-MAY-2025] RubyGems Blog. "May 2025 RubyGems Updates." June 16, 2025. https://blog.rubygems.org/2025/06/16/may-rubygems-updates.html

[RUBYGEMS-STATS-2025] RubyGems.org Stats. https://rubygems.org/stats

[RUBY-2-0-RELEASE] ruby-lang.org. "Ruby 2.0.0-p0 Released." February 24, 2013. https://www.ruby-lang.org/en/news/2013/02/24/ruby-2-0-0-p0-is-released/

[RUBY-2-2-RELEASE] ruby-lang.org. "Ruby 2.2.0 Released." December 25, 2014.

[RUBY-2-7-RELEASE] ruby-lang.org. "Ruby 2.7.0 Released." December 25, 2019.

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

[RUBY-RELEASES] ruby-lang.org. "Ruby Releases." https://www.ruby-lang.org/en/downloads/releases/

[RUBY-RUBYGEMS-TRANSITION] ruby-lang.org. "The Transition of RubyGems Repository Ownership." October 17, 2025. https://www.ruby-lang.org/en/news/2025/10/17/rubygems-repository-transition/

[RUBY-SCHEDULE] Medium / Ashish Garg. "Ruby Release Schedule." https://medium.com/@01ashishgarg/ruby-release-schedule-ecc281346dd3

[RUBY-SECURITY] ruby-lang.org. "Security." https://www.ruby-lang.org/en/security/

[RUBY-TYPING-2024] Leach, B. "Ruby typing 2024: RBS, Steep, RBS Collections, subjective feelings." brandur.org. https://brandur.org/fragments/ruby-typing-2024

[RUBYCENTRAL-REPORT-2024] Ruby Central. "Ruby Central's First Annual OSS Report (2024)." https://rubycentral.org/news/ruby-centrals-first-annual-oss-report-2024/

[SHOPIFY-YJIT] Shopify Engineering. "Ruby YJIT is Production Ready." https://shopify.engineering/ruby-yjit-is-production-ready

[SITEPOINT-HISTORY] SitePoint. "The History of Ruby." https://www.sitepoint.com/history-ruby/

[SOCKET-MALICIOUS-GEMS] Socket.dev. "Malicious Ruby Gems Exfiltrate Telegram Tokens and Messages." https://socket.dev/blog/malicious-ruby-gems-exfiltrate-telegram-tokens-and-messages-following-vietnam-ban

[SOCKET-RAILS-SURVEY-2024] Socket.dev. "Highlights from the 2024 Rails Community Survey." https://socket.dev/blog/highlights-from-the-2024-rails-community-survey

[SOCKET-RUBYGEMS-STEWARDSHIP] Socket.dev. "Ruby Core Team Assumes Stewardship of RubyGems and Bundler." https://socket.dev/blog/ruby-core-team-assumes-stewardship-of-rubygems-and-bundler

[SORBET-ORG] Sorbet. "A static type checker for Ruby." https://sorbet.org/

[TECHEMPOWER-ROUND-23] TechEmpower. "Framework Benchmarks Round 23." March 2025. https://www.techempower.com/blog/2025/03/17/framework-benchmarks-round-23/

[THN-GEMS-2025] The Hacker News. "RubyGems, PyPI Hit by Malicious Packages Stealing Credentials, Crypto." August 2025. https://thehackernews.com/2025/08/rubygems-pypi-hit-by-malicious-packages.html

[THN-TYPOSQUAT-2020] The Hacker News. "Over 700 Malicious Typosquatted Libraries Found On RubyGems Repository." April 2020. https://thehackernews.com/2020/04/rubygem-typosquatting-malware.html

[TIOBE-2025] TIOBE Index, April 2025. https://www.tiobe.com/tiobe-index/ (Ruby ranked 24th; InfoWorld coverage: https://www.infoworld.com/article/3956262/kotlin-swift-and-ruby-losing-popularity-tiobe-index.html)

[TMS-RUBY-STATS] TMS Outsource. "Ruby Statistics: Key Insights Every Developer Should Know." https://tms-outsource.com/blog/posts/ruby-statistics/

[TRUFFLERUBY-CEXT] Seaton, C. "Very High Performance C Extensions For JRuby+Truffle." chrisseaton.com. https://chrisseaton.com/truffleruby/cext/

[UPDOWN-RUBY-3-3] updown.io. "The performance improvements in Ruby 3.3 with YJIT." https://updown.io/blog/the-performance-improvements-in-ruby-3-3-with-yjit

[WIKI-MATZ] Wikipedia. "Yukihiro Matsumoto." https://en.wikipedia.org/wiki/Yukihiro_Matsumoto

[WIKI-RUBY] Wikipedia. "Ruby (programming language)." https://en.wikipedia.org/wiki/Ruby_(programming_language)
