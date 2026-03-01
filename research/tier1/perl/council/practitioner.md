# Perl — Practitioner Perspective

```yaml
role: practitioner
language: "Perl"
agent: "claude-agent"
date: "2026-02-28"
schema_version: "1.1"
```

---

## 1. Identity and Intent

Perl's origin story is genuinely unusual in programming language history: it was built by a linguist, not a computer scientist, to solve a concrete operational problem (parsing distributed log files) at a specific time (the late 1980s) when the alternatives were equally ugly but less capable. That origin shapes everything about what Perl is like to use in production.

The TIMTOWTDI ("There Is More Than One Way To Do It") motto [TIMTOWTDI-WIKI] sounds liberating in a language specification but is often a liability in a software team. When a senior Perl developer writes `grep { $_ =~ /foo/ } @list` and a junior reaches for a `for` loop with an `if` inside, both are idiomatic Perl, both produce the same result, and code review becomes a negotiation about aesthetics rather than correctness. Over a 200k-line codebase maintained by rotating personnel, this compounds into genuine maintenance overhead.

What Perl actually delivers well in production — still, in 2026 — is text processing. The regex engine is not just capable; it is the regex engine that inspired an entire category of tooling (PCRE's name acknowledges this [PERL-RC-ARTICLE]). Systems that read log files, parse biological sequence data, mangle structured text into other structured text: these remain genuine Perl strongholds, and not because of inertia alone. The language genuinely excels at the task it was designed for.

What Perl promised but did not fully deliver is the universal glue language. The web aspirations of the CGI era are long over. The systems administration use case is being displaced by Python in new deployments. Bioinformatics is gradually fragmenting toward R and Python. The niches Perl occupies are defensible but contracting. As a practitioner, you need to be honest with yourself about whether you are building on a foundation or maintaining a stranded asset.

---

## 2. Type System

In day-to-day production Perl, the absence of a declared type system means that your error surface at runtime is larger than it would be in a statically-typed language. This is manageable with discipline — `use strict` and `use warnings` catch the most common mistakes [PERLDOC-PERLPOLICY] — but "manageable with discipline" is a phrase that always sounds better in documentation than it does at 2 AM when a production system is misbehaving.

The practical consequence of context sensitivity is a distinctive class of bugs. When `$array[0]` gives you a scalar and `@array[0]` (before `use warnings`) silently returns a one-element list, the distinction matters in ways that bite. The sigil-shifting behavior — where accessing elements of `@array` uses `$array[0]` — surprises every developer who comes to Perl from another language [PERL-RC-ARTICLE], and that surprise often manifests as a defect in production code written by someone who was still learning.

Type::Tiny [METACPAN-TYPETINY] is genuinely useful for codebases that adopt it. The performance story is good (80% faster than Moose type checking without XS; ~400% faster with `Type::Tiny::XS`), and it integrates with Moose, Mouse, and Moo. The problem is adoption. In practice, most Perl codebases I have encountered have inconsistent type constraint usage — some modules enforce them carefully, others rely entirely on the caller to pass reasonable values. You cannot trust type discipline in a Perl codebase the way you can trust it in, say, a Rust or Haskell codebase, because the type system is optional and the enforcement is cultural, not mechanical.

The Corinna project (`class`/`method`/`field` keywords, experimental since 5.38, continuing development in 5.42) [PHORONIX-538] [PERLDOC-5420DELTA] is a genuine step forward for OOP discipline. But "experimental" means you should not build new production systems on it yet unless you are prepared to deal with syntax changes in future releases. The three-generation OOP situation — bless-based, Moose/Moo, and now Corinna — means that any codebase with significant history will contain all three approaches, and integrating them requires understanding all three.

---

## 3. Memory Model

Reference counting with deterministic destruction [PERL-RC-ARTICLE] has a real practical advantage that is often overlooked in the language-design literature: file handles, database connections, and other resources are cleaned up predictably when they go out of scope. You do not need `finally` blocks or context managers if your resource is wrapped in an object — it gets destroyed when it goes out of scope, and DESTROY runs. This is a genuine ergonomic win in systems code that manages lots of external resources.

The circular reference problem [PERL-RC-TROUBLE] is real but manageable. `Scalar::Util::weaken()` is the fix, it works, and Moose/Moo handle back-references correctly if you declare them with weak roles. The risk is code that does not use Moose, does not know about weak references, and builds complex object graphs — bioinformatics code is notorious for this. Memory leak debugging in Perl requires either Devel::NYTProf (which catches CPU costs but requires interpretation to find memory issues) or careful instrumentation. The tooling exists but it is not as ergonomic as a GC with heap profiling support.

One thing practitioners often do not mention: Perl's memory consumption is notably higher than systems languages because every scalar is boxed. A hash with 100,000 keys uses considerably more memory than the equivalent C struct array. For long-running servers processing large datasets, this matters. If you are running Perl under PSGI/Starman with a worker-per-request model, each forked worker carries the full memory footprint of the parent, and that footprint grows over time if the code has any memory leaks. This is not unique to Perl, but Perl's dynamism means the footprint is harder to reason about statically.

---

## 4. Concurrency and Parallelism

The concurrency situation in Perl is the most significant limitation for modern production work, and the documentation is admirably honest about it. The official `perlthrtut` documentation explicitly states that ithreads "are not recommended for performance; they should be used for asynchronous jobs only where not having to wait for something slow" [PERLTHRTUT]. The GitHub issue tracking Thread::Queue being 20x slower than Unix pipes [GITHUB-THREADQUEUE] is not a footnote — it represents a real architectural constraint.

In practice, Perl production systems use `fork()` for CPU parallelism and event loops (AnyEvent, IO::Async, Mojolicious's built-in loop) for I/O concurrency. Both approaches work; neither is ergonomically modern. Fork-based concurrency has legitimate costs: each forked process carries the parent interpreter's memory footprint (copy-on-write helps on Linux but does not eliminate the overhead), IPC is done via pipes or shared memory mechanisms that require explicit design, and debugging multi-process systems is harder than debugging multi-threaded ones.

The absence of native `async`/`await` syntax is a genuine pain point when you compare the development experience to Node.js or Python's asyncio. Mojolicious has an excellent non-blocking I/O model for web workloads, but it requires buying into Mojolicious's patterns throughout your code — AnyEvent callbacks work but are less readable than structured async/await, and mixing synchronous library calls into an async event loop causes the entire loop to stall. These are solvable problems, but they require architectural discipline that newer languages build in by default.

For most legacy Perl systems, concurrency is either irrelevant (batch processing jobs that run sequentially) or handled at the infrastructure level (multiple Starman workers behind a load balancer). This works fine until you have a workload that needs tight coordination between concurrent operations, at which point you discover that Perl's concurrency primitives require significantly more engineering effort than you would spend in Go or Elixir.

---

## 5. Error Handling

The `$@` contamination problem [PERLMAVEN-EVAL] is one of those language bugs that you encounter, find incomprehensible, then encounter a second time in someone else's code and realize the language has a known defect that the community spent years working around. When `eval` succeeds and clears `$@`, it can clobber an error caught by an outer scope. The result is code that silently swallows errors that were carefully caught.

Try::Tiny [MVPKABLAMO-TRYCATCH] was the standard fix for years: a pure-CPAN module with proper `$@` handling. It is approximately 2.6x slower than raw `eval()`, which mattered in tight loops but was acceptable in most web request handlers. Stable `try`/`catch` syntax landed in Perl 5.40.0 [PERLDOC-5400DELTA], which is good news for new code — but the CPAN ecosystem still contains enormous amounts of raw `eval`/`$@` code that was written before 5.34 (when `try`/`catch` was first introduced experimentally) or by developers who did not want to take a CPAN dependency for such a basic feature.

The lack of a built-in exception hierarchy is a practical annoyance. When you `die` with a string in one part of the system and try to catch specific exception types in another, you are doing string matching on error messages — a brittle pattern that breaks when someone changes the error message text. Exception::Class and similar CPAN modules provide proper exception hierarchies, but again: adoption is uneven. A codebase inherited from a team that did not use Exception::Class has string-based error matching baked into its exception-handling code, and retrofitting is expensive.

What works well: Perl's error handling does give you clear information when something fails. `die` with a hash reference gives you a structured exception object. `Carp::croak` gives you the caller's stack frame rather than the implementation's. The tooling is there. The gap is that none of it is enforced — the language does not require structured exceptions, so codebases contain a mix of `die "string"`, `die { ... }`, and blessed object exceptions, and code that handles one style silently mishandles the others.

---

## 6. Ecosystem and Tooling

CPAN is Perl's most important production asset, and the numbers are remarkable: 220,000+ modules, 45,500+ distributions, 14,500+ contributors accumulated since the early 1990s [CPAN-WIKI]. For text processing, bioinformatics, network protocols, finance, and system administration, CPAN has mature, well-tested modules that took decades to develop. When you need to parse GenBank files, decode financial message formats, or interact with an ancient SNMP implementation, CPAN probably has a module.

The concerning indicators are the trajectory, not the current state. New PAUSE accounts in 2025: 108 — near the lowest since 1997. First-time CPAN releasers in 2025: 65 [CPANREPORT-2026]. The CPAN contribution community is stable but aging, and the "new status quo" framing by the community's own data analyst acknowledges that growth has stopped. A package registry with 220,000 modules but a declining contributor base will eventually develop maintenance gaps, and some already exist.

The package management tooling is functional but fragmented. `cpanm` (App::cpanminus) is the practical default for installation. `Carton` with `cpanfile` gives you reproducible, locked environments analogous to Bundler in Ruby or npm with a lock file [PERL-RC-ARTICLE]. `cpm` provides parallel installation for faster CI builds. But there is no canonical `pip install` equivalent with a single authoritative recommendation; the documentation trails the practice; and setting up a fresh project involves choices (which installer? cpanfile or META.json?) that should have settled into a single blessed workflow by 2026.

IDE support is where the practitioner experience is most noticeably worse than competing languages. The Padre IDE was abandoned. The VS Code Perl Navigator extension and PerlLS language server provide go-to-definition, syntax highlighting, and limited diagnostics — but code completion, refactoring support, and real-time type inference are all weaker than what Python, TypeScript, or Kotlin developers take for granted [PERL-RC-ARTICLE]. This has a real cost: large Perl codebases are harder to navigate and refactor safely because the tooling cannot tell you what a variable's type is or where a method is defined. You lean on `grep` and `perldoc` rather than "go to definition."

The testing story is genuinely strong. Perl invented TAP (Test Anything Protocol), and `Test::More` and its modern successor `Test2::Suite` [GITHUB-TESTMORE] are capable test frameworks. `prove` integrates cleanly with CI. `Devel::Cover` provides coverage. `Perl::Critic` enforces best practices. `Devel::NYTProf` (developed at the New York Times, hence the name) produces detailed profiling reports that rival what you get from Python's cProfile. For a language this old, the test tooling is surprisingly good — better than what PHP had for most of its history.

The build and distribution tooling is dated. `ExtUtils::MakeMaker` generates Makefiles and works, but its interface is from another era. `Dist::Zilla` is powerful but complex. Compared to `cargo build` or `go build`, the Perl build system requires more configuration for what should be simple cases. Deploying a CPAN distribution requires understanding the Makefile.PL/Build.PL distinction, which is irrelevant context for application developers but unavoidable when contributing to or forking CPAN modules.

---

## 7. Security Profile

Taint mode (`-T` flag) [PERLDOC-PERLSEC] is Perl's most distinctive security feature and one that other languages have not replicated well. Information flow tracking from external inputs — command-line arguments, environment variables, file input, network data — prevents tainted data from reaching shell commands, file operations, or process control without first passing through a regex-based sanitization step. For CGI scripts and system administration tools that run with elevated privileges, taint mode is a meaningful defense against shell injection.

The practical problem is that taint mode is opt-in and frequently disabled in production code. Legacy CGI applications often run without `-T` because enabling it retroactively on old code breaks things — not because taint mode is wrong, but because old code assumed tainted data could flow freely. The security mechanism exists, but the friction of enabling it on an existing codebase means many production systems do not use it.

The supply chain story is concerning in a way that the CVE numbers do not fully capture. CVE-2023-31484 — CPAN.pm not verifying TLS certificates when downloading distributions from HTTPS mirrors — represents a fundamental supply chain vulnerability that existed for years in the core distribution tool [STACKWATCH-PERL]. CPAN modules are not cryptographically signed by default. There is no mandatory security review process for CPAN uploads. The security posture is better than it was (Carton with locked hashes provides reproducible dependency auditing), but it is behind what modern language ecosystems have built as table stakes.

The CVE history for the core interpreter concentrates in the regex engine and Unicode handling — buffer overflows in `regcomp.c` appear repeatedly [IBM-AIX-CVE-2023]. This is an inherent risk of a complex, C-implemented regex engine with decades of accumulated feature additions. The base rate is low (single-digit CVEs per year in recent years [STACKWATCH-PERL]), which is acceptable for most production contexts. The concern is that regex-heavy code that processes untrusted input — precisely where Perl is most often deployed — is the attack surface where these vulnerabilities matter.

For bioinformatics and internal sysadmin tools where input is trusted and there is no external attack surface, the security profile is adequate. For internet-facing applications processing arbitrary user input, the security investment required in Perl is higher than in languages with safer-by-default semantics.

---

## 8. Developer Experience

The "write-only language" reputation [SO-2025-ANALYSIS] is both unfair and partly deserved. Unfair, because modern Perl with `use strict; use warnings; use v5.36` and the idioms from *Modern Perl* [MODERN-PERL-2014] is readable and maintainable. Partly deserved, because the code you encounter when maintaining existing systems often was not written with those idioms, and reading it requires reconstructing the author's intent from a style that may have been idiomatic in 2002 but is opaque today.

Onboarding a new team member onto a Perl codebase has a distinctive arc. The core language is learnable — basic Perl syntax is not dramatically harder than Python or Ruby. The difficulties accumulate: sigil-shifting surprises novices; TIMTOWTDI means reading existing code requires broader pattern knowledge; three generations of OOP (bless-based, Moose/Moo, Corinna) coexist and must all be understood; the lack of IDE support means navigating the codebase relies on text search rather than IDE-assisted navigation. A junior developer who is productive in their first week on a Python codebase might take three to four weeks to reach equivalent fluency in an unfamiliar Perl codebase.

The admiration rate data from Stack Overflow is striking in its variance: approximately 61.7% in 2024, dropping to approximately 24% in 2025 [SO-2024-TECH] [SO-2025-TECH]. The research brief correctly notes that year-on-year sampling variance likely accounts for much of this swing. But the 2025 figure, if taken at face value, would suggest that most Perl users — people who actively use the language — do not particularly like it. That aligns with a pattern in mature languages with large legacy deployment bases: the people using the language are often doing so because they must, not because they chose it.

The error messages are inconsistent. Core Perl errors are often clear (`Undefined subroutine &main::foo called at script.pl line 12`), but errors from CPAN modules vary wildly. Moose-related errors can produce stack traces that run for screens before identifying the actual problem. Regex compilation errors, particularly in complex patterns, require knowledge of regex internals to interpret. The ecosystem has never standardized on an error message quality bar the way Rust has, and it shows.

The salary premium [GLASSDOOR-PERL-2025] deserves honest interpretation. $150,491/year average on Glassdoor reflects scarcity economics, not demand growth. If you are being paid a premium to maintain a Perl system, you are almost certainly doing work that is difficult to hand off, difficult to modernize, and in a codebase where your institutional knowledge is the primary asset. The compensation is fair for the difficulty. The career risk is that specializing deeply in Perl narrows your options in a market moving toward Python, Go, and TypeScript.

---

## 9. Performance Characteristics

The benchmark picture is clear and the research brief presents it honestly: Perl is in the "purely interpreted" tier alongside CPython, slower than JIT-compiled implementations like PHP 8.x (opcache + JIT) and Ruby with YJIT [PLB-PERL-2025]. The 15-queens benchmark analysis shows system languages (C, Rust) more than 50 times faster than interpreted languages including Python and Perl, while JIT languages come in between [PLB-ANALYSIS]. This is not a competitive problem for most Perl workloads, because most Perl workloads are I/O-bound — they wait on file systems, databases, and network — and the interpreter overhead is lost in the noise.

The performance issues that actually matter in production Perl are more specific:

**Moose startup overhead** is real and consequential for short-lived scripts. A script that uses Moose extensively can take 1-3 seconds to start up due to metaclass construction at `use` time. For CGI-style deployments (one Perl process per request) this adds latency to every request. PSGI/Plack with a persistent Starman or Hypnotoad server eliminates this by keeping the interpreter warm between requests. But any deployment model that spawns new processes — cron jobs, command-line tools, system administration scripts — pays the Moose tax on every invocation.

**Regex performance** is genuinely good for the domain. Perl's NFA-based engine is highly optimized for the text-heavy workloads where Perl lives. The fact that PCRE2 (via `re::engine::PCRE2`) is approximately 50% faster [PCRE2-WIKI] is interesting but rarely a bottleneck in practice — regex compilation is cached, and the bottleneck is usually I/O rather than regex matching speed.

**Memory consumption** matters for long-running server processes. Perl's boxed scalars and dynamic type system mean baseline memory usage is higher than systems languages. A worker pool of Starman processes processing 50k-record batches can consume several gigabytes of RAM that a C or Go equivalent would handle in a fraction of the space. This is real operational cost, particularly in cloud environments where RAM translates directly to money.

No JIT exists in core Perl 5 [PLB-PERL-2025]. This is a fundamental constraint — unlike PHP 8.x, Ruby (YJIT), Python (various PyPy and CPython 3.13+ JIT efforts), or LuaJIT, Perl has no runtime compilation path. Community efforts to add JIT have not shipped. For compute-bound workloads, this means the ceiling is the interpreter speed, and the interpreter speed is what it is.

---

## 10. Interoperability

Perl's XS extension system (C extensions linked into the interpreter) is mature and widely used in the CPAN ecosystem — modules like `JSON::XS`, `Cpanel::JSON::XS`, `re::engine::PCRE2`, and many of the highest-performance CPAN modules are XS-based. The performance benefits are real: XS implementations consistently outperform pure-Perl equivalents by significant margins.

The production cost of XS dependencies is compilation at installation time. Deploying a Perl application with XS dependencies requires a C compiler on the target system, which is usually available on Linux but can be missing or version-mismatched in restricted environments. Docker images that include Perl with XS modules are larger than pure-Perl equivalents because they need the compilation toolchain or pre-compiled binaries. CI builds are slower because XS modules must be compiled. This is not a dealbreaker, but it adds friction to deployment pipelines.

`FFI::Platypus` provides a pure-Perl FFI mechanism that avoids the XS compilation requirement when you need to call C libraries. It is adequate for interfacing with system libraries and well-maintained shared libraries. For cases where you need to call into a C library that does not already have an XS binding, FFI::Platypus is the practical path.

PSGI/Plack [PERL-ORG-CATALYST] is the interoperability success story for Perl web applications. The PSGI specification decouples Perl web applications from the web server, enabling the same application to run under Starman (multi-process), Twiggy (AnyEvent-based), Gazelle (C-based), or any other PSGI-compatible server. This is Perl's equivalent of Python's WSGI and works well in practice. A Mojolicious application can also run as a PSGI application if needed, giving you flexibility at the deployment layer.

Embedding Perl in non-Perl applications (the reverse direction) is possible but uncommon in 2026. The historical use case — embedding Perl as a scripting engine in C++ applications — has largely been displaced by Lua and Python, which have simpler embedding APIs and more active communities building embedding use cases.

---

## 11. Governance and Evolution

The governance situation is worth honest assessment. The Perl 7 saga — announced in June 2020, generating significant community conflict, and effectively abandoned by 2023 [RELEASED-BLOG-PERL7] — was a governance failure that revealed both the difficulty of making breaking changes in a language with Perl's backward-compatibility commitments and the toxicity that drove Sawyer X out of the Perl Steering Committee in 2021 [THEREGISTER-SAWYER]. The aftermath is a language that continues to improve incrementally, with the Perl Steering Council (PSC) model [PERLGOV] providing more stable governance than the previous pumpking model, but no clear narrative about where Perl is going.

The annual release cadence (stable release each May/June, with point releases every three months) [ENDOFLIFE-PERL] is reliable. Perl 5.42.0 in July 2025 delivered incremental improvements [PERLDOC-5420DELTA]. The Corinna project (class syntax, stable in the future, experimental since 5.38) is the biggest structural change in Perl's OOP story in decades. But the pace of improvement is dictated by volunteer effort, with no primary corporate sponsor providing sustained engineering resources [THEREGISTER-SAWYER].

The no-corporate-sponsor situation is not automatically bad — Perl maintained itself for decades without one — but it creates fragility in a competitive landscape where Go (Google), Rust (Rust Foundation with broad corporate membership), Python (PSF with substantial corporate funding), and Swift (Apple) all have institutional backing. The Perl and Raku Foundation (TPRF) funds grants and events but does not sustain the equivalent of a full-time engineering team [TPRF].

Backward compatibility is both a strength and a constraint. Code from the 1990s runs on Perl 5.42, which is genuinely remarkable. The cost is that cleanup of historical mistakes is slow. The `$@` contamination behavior existed for decades before stable `try`/`catch` addressed it [PERLDOC-5400DELTA]. The `.` in `@INC` security issue was known for years before 5.26 removed it [PERL-5VH-WIKI]. The language moves carefully around its installed base, which is appropriate given the scale of existing Perl code, but means practitioners working in modern Perl live with legacy constraints for a long time.

---

## 12. Synthesis and Assessment

### Greatest Strengths

**Text processing competence is unmatched for the domain.** Regular expressions are first-class citizens of the language syntax, not library functions. The `/x` modifier for readable patterns, named captures, variable-length lookbehind (since 5.30), and the `/e` modifier for code-in-regex are capabilities that still exceed what most languages offer without reaching for external libraries. For log analysis, data extraction, bioinformatics pipelines, and format transformation, Perl remains the most productive choice for an experienced practitioner.

**CPAN depth is a genuine competitive advantage in specific domains.** BioPerl [BIOPERL-GENOME-2002], financial message parsing, network management tooling (RANCID, Netdisco), legacy CGI application support — these domains have Perl module coverage that represents decades of validated work. The value of a working bioinformatics module that has processed genomic data for 20 years is not easily replicated.

**Production stability under a strong backward-compatibility commitment** means that Perl systems, once deployed and working, tend to stay working. The operational burden of maintaining a Perl system that was correctly implemented is often lower than for languages with more aggressive versioning (Python 2→3, Ruby 2→3) or more rapid evolution.

**Testing infrastructure is excellent relative to the language's age.** TAP (invented in Perl), `Test2::Suite`, `Devel::NYTProf`, `Devel::Cover`, and `Perl::Critic` form a testing and quality toolchain that exceeds many newer languages.

### Greatest Weaknesses

**IDE and tooling support is the largest practical gap.** No abandoned IDE matters less than a bad refactoring experience over a long maintenance horizon. Perl developers navigating unfamiliar codebases rely on `grep`, `perldoc`, and institutional knowledge. The PerlLS language server improves the situation but does not achieve parity with what TypeScript, Kotlin, or Python developers experience in modern IDEs.

**Concurrency is not fit for modern workloads.** The official documentation advises against using ithreads for performance [PERLTHRTUT]. Fork-based parallelism works but requires explicit IPC design. There is no native async/await. For building new high-concurrency services, Perl requires more engineering effort than Go, Node.js, or Python with asyncio.

**Community contraction creates a talent gap.** 65 first-time CPAN releasers in 2025 [CPANREPORT-2026]. No JetBrains tracking. 3.8% Stack Overflow usage share with 24% admiration [SO-2025-TECH]. The community is real and active, but it is not replenishing itself with new developers. Hiring Perl developers is difficult and getting more difficult; onboarding developers from other languages to Perl takes time; the premium salary ($140K–$150K [GLASSDOOR-PERL-2025]) reflects this scarcity.

**The TIMTOWTDI culture generates long-term maintenance debt.** Freedom to express the same computation in multiple idioms is fine for individual scripts but costly for team codebases. When a maintainer inherits code that mixes bless-based OOP, Moose, early Corinna experiments, procedural style, and functional pipelines — all valid Perl, all legitimately different — the cognitive overhead of context-switching between idioms accumulates. Python's "one obvious way" philosophy has real practical value for team software.

### Lessons for Language Design

1. **First-class syntax for a domain-specific capability creates lasting ecosystem advantage.** Perl's regex-as-syntax (not regex-as-library) drove adoption by making text processing qualitatively easier. Languages that want to dominate a domain should consider what first-class syntax for that domain's core operations would look like, not just library coverage.

2. **TIMTOWTDI appears liberating in design but is costly at scale.** When multiple valid idioms produce identical results, every reader of the code must understand all idioms, and every code review becomes a style negotiation. Languages designed for team use benefit from "one obvious way" enforcement — or at minimum, a canonical formatter (`perltidy` exists; adoption is cultural, not mechanical).

3. **Optional safety features are often not used.** Taint mode [PERLDOC-PERLSEC] is a meaningful security mechanism that production systems frequently omit because enabling it retroactively breaks things. `use strict` and `use warnings` were optional for decades before feature bundles made them implicit in `use v5.36`. Security and correctness mechanisms that require opt-in will be omitted by production code under delivery pressure. Language designers should consider what the safe default looks like and design toward it.

4. **The gap between "designed to be used" and "actually used" grows over time without active maintenance.** CGI.pm was in core Perl until 5.20 and present in millions of deployments; bless-based OOP remains common despite Moose being available since 2006. Languages accumulate deployment inertia, and features added to improve the experience coexist with the old way for decades. Design decisions about what goes in core and what is opt-in have consequences measured in years.

5. **A language without corporate backing can sustain itself but cannot accelerate.** Perl's volunteer community has maintained the language for nearly 40 years. But the pace of JIT development (none), concurrency improvement (incremental), and IDE support (limited) reflects the realities of volunteer-only engineering capacity. Languages that need to compete in capability with well-funded alternatives require institutional backing.

6. **Error handling mechanisms that require workarounds signal unfinished design.** The `$@` contamination bug [PERLMAVEN-EVAL] was documented, widely known, and worked around in production code (via Try::Tiny) for years before stable `try`/`catch` landed in 5.40 [PERLDOC-5400DELTA]. When the community's response to a language defect is a CPAN module that becomes the de facto standard, the defect belongs in the language specification and should be addressed with priority.

7. **Package registry health is a leading indicator of language health.** CPAN's 65 first-time releasers in 2025 [CPANREPORT-2026] — near the lowest since 1997 — is a signal that deserves more attention than it often gets. The absolute size of the registry (220,000+ modules) is a lagging indicator; the rate of new contributor entry is a leading indicator of the ecosystem's long-term sustainability.

8. **Concurrency design should not be deferred.** Perl's threading model was effectively declared unfit for performance use in its own documentation [PERLTHRTUT], leaving a production gap filled by fork() and event loops that work but are architecturally awkward. A language that will be used for server applications needs a concurrency model that is genuinely competitive, designed-in rather than bolted-on.

9. **Strong backward compatibility is valuable but requires active governance to prevent it from becoming stagnation.** Perl's ability to run 1990s code on a 2026 interpreter is admirable, but the cost is that cleaning up known mistakes (`$@`, `.` in `@INC`, legacy OOP) requires decades. Languages can maintain compatibility while creating clear migration paths and deprecation timelines — but doing so requires explicit governance decisions, not just passive compatibility maintenance.

10. **The write-only reputation damages adoption even when the modern language is readable.** Perl's association with cryptic one-liners and unreadable CGI scripts persists despite the substantial improvements in modern idioms. Language designers should understand that a language's reputation is shaped by its worst deployed code, not its best — which makes it important to make the good idioms easy and the bad idioms slightly harder, and to invest in the community-visible documentation of best practices.

### Dissenting View

The framing of Perl as a "legacy" language in decline may be misleading for practitioners in specific domains. Bioinformatics pipelines, network management tooling, and financial data processing with Perl are not legacy by mistake — they are the product of institutional investment in CPAN modules that represent real accumulated knowledge. A bioinformatics team running BioPerl [BIOPERL-GENOME-2002] on actively maintained EnsEMBL infrastructure is not running legacy software in the pejorative sense; they are running software that works and is actively maintained. The practitioner experience in these niches is better than the language's aggregate survey numbers suggest, because the ecosystem coverage in those niches remains genuinely strong.

---

## References

[BIOPERL-GENOME-2002] Stajich, J. et al. "The Bioperl Toolkit: Perl Modules for the Life Sciences." *Genome Research* 12(10): 1611–1618, 2002. https://genome.cshlp.org/content/12/10/1611.full.

[BYTEIOTA-TIOBE] ByteIota. "Perl's TIOBE Comeback: #27 to #9 Isn't What It Seems." 2025. https://byteiota.com/perls-tiobe-comeback-27-to-9-isnt-what-it-seems/

[CPANREPORT-2026] Bowers, N. "CPAN Report 2026." January 13, 2026. https://neilb.org/2026/01/13/cpan-report-2026.html

[CPAN-WIKI] Wikipedia. "CPAN." https://en.wikipedia.org/wiki/CPAN

[GITHUB-TESTMORE] GitHub. "Test-More/test-more." https://github.com/Test-More/test-more

[GITHUB-THREADQUEUE] GitHub. "perl/perl5: performance bug: perl Thread::Queue is 20x slower than Unix pipe." Issue #13196. https://github.com/perl/perl5/issues/13196

[GLASSDOOR-PERL-2025] Glassdoor. "Salary: Perl Developer in United States 2025." https://www.glassdoor.com/Salaries/perl-developer-salary-SRCH_KO0,14.htm

[IBM-AIX-CVE-2023] IBM Support. "Security Bulletin: AIX is vulnerable to arbitrary command execution due to Perl (CVE-2023-47038, CVE-2023-47100)." https://www.ibm.com/support/pages/security-bulletin-aix-vulnerable-arbitrary-command-execution-due-perl-cve-2024-25021-cve-2023-47038-cve-2023-47100

[METACPAN-TYPETINY] MetaCPAN. "Type::Tiny." https://metacpan.org/pod/Type::Tiny

[MODERN-PERL-2014] chromatic. *Modern Perl 2014*. "The Perl Philosophy." https://www.modernperlbooks.com/books/modern_perl_2014/01-perl-philosophy.html

[MVPKABLAMO-TRYCATCH] Minimum Viable Perl. "Handling exceptions with try/catch." http://mvp.kablamo.org/essentials/try-catch/

[PCRE2-WIKI] Wikipedia. "Perl Compatible Regular Expressions." https://en.wikipedia.org/wiki/Perl_Compatible_Regular_Expressions

[PERL-ORG-CATALYST] perl.org. "Perl Web Framework - Catalyst." https://www.perl.org/about/whitepapers/perl-webframework.html

[PERL-RC-ARTICLE] dnmfarrell. "The Trouble with Reference Counting." https://blog.dnmfarrell.com/post/the-trouble-with-reference-counting/

[PERL-RC-TROUBLE] Perl.com. "The Trouble with Reference Counting." https://www.perl.com/article/the-trouble-with-reference-counting/

[PERL-WIKI] Wikipedia. "Perl." https://en.wikipedia.org/wiki/Perl

[PERLGOV] Perldoc Browser. "perlgov - Perl Rules of Governance." https://perldoc.perl.org/perlgov

[PERLMAVEN-EVAL] Perlmaven. "Exception handling in Perl: How to deal with fatal errors in external modules." https://perlmaven.com/fatal-errors-in-external-modules

[PERLDOC-5400DELTA] Perldoc Browser. "perl5400delta - what is new for perl v5.40.0." https://perldoc.perl.org/perl5400delta

[PERLDOC-5420DELTA] MetaCPAN. "perldelta - what is new for perl v5.42.0." https://metacpan.org/dist/perl/view/pod/perldelta.pod

[PERLDOC-PERLPOLICY] Perldoc Browser. "perlpolicy - Various and sundry policies and commitments related to the Perl core." https://perldoc.perl.org/perlpolicy

[PERLDOC-PERLSEC] Perldoc Browser. "perlsec - Perl security." https://perldoc.perl.org/perlsec

[PERLTHRTUT] Perldoc Browser. "perlthrtut - Tutorial on threads in Perl." https://perldoc.perl.org/perlthrtut

[PHORONIX-538] Phoronix. "Perl 5.38 Released With Experimental Class Feature, Unicode 15." July 2023. https://www.phoronix.com/news/Perl-5.38-Released

[PLB-ANALYSIS] Programming Language Benchmarks / community analysis. "Analyzing the Computer Language Benchmarks Game." https://janejeon.dev/analyzing-the-the-computer-language-benchmarks-game/

[PLB-PERL-2025] Programming Language Benchmarks. "Perl benchmarks." (Generated August 1, 2025; Perl v5.40.1 on AMD EPYC 7763.) https://programming-language-benchmarks.vercel.app/perl

[RELEASED-BLOG-PERL7] blog.released.info. "The Evolution of Perl - From Perl 5 to Perl 7." August 1, 2024. https://blog.released.info/2024/08/01/perl-versions.html

[SO-2024-TECH] Stack Overflow. "Technology | 2024 Stack Overflow Developer Survey." https://survey.stackoverflow.co/2024/technology

[SO-2025-ANALYSIS] DEV Community. "My Thoughts on the 2025 Stack Overflow Survey." https://dev.to/dev_tips/my-thoughts-on-the-2025-stack-overflow-survey-the-hype-the-reality-the-gap-26e3

[SO-2025-TECH] Stack Overflow. "Technology | 2025 Stack Overflow Developer Survey." https://survey.stackoverflow.co/2025/technology

[STACKWATCH-PERL] stack.watch. "Perl Security Vulnerabilities in 2025." https://stack.watch/product/perl/perl/

[THEREGISTER-SAWYER] The Register. "Key Perl Core developer quits, says he was bullied for daring to suggest programming language contained 'cruft'." April 13, 2021. https://www.theregister.com/2021/04/13/perl_dev_quits/

[TIMTOWTDI-WIKI] Perl Wiki (Fandom). "TIMTOWTDI." https://perl.fandom.com/wiki/TIMTOWTDI

[TPRF] The Perl & Raku Foundation. "TPRF." https://perlfoundation.org/
