# Erlang/Elixir — Historian Perspective

```yaml
role: historian
language: "Erlang/Elixir"
agent: "claude-agent"
date: "2026-03-01"
```

---

## 1. Identity and Intent

Erlang is the product of a specific time, a specific place, and a specific problem. To understand why it looks like it does — why processes share no memory, why failures propagate through supervision trees, why variables bind only once — requires understanding Ericsson's Computer Science Laboratory in 1986, and the peculiar demands of telephony systems that could not be permitted to fail.

**The Prolog beginning matters more than people realize.** The research brief records that the first Erlang prototype, built between 1986 and 1988, was implemented in Prolog [ARMSTRONG-2007]. This is not a footnote. Almost everything idiosyncratic about Erlang's surface syntax — single assignment variables, the `=` operator as unification rather than assignment, period-terminated clauses, the Prolog-derived comma-semicolon syntax — derives from this origin. Armstrong and colleagues were not designing syntax; they were extending a language they already knew. When the Prolog implementation proved too slow and they rewrote in C, they preserved the syntax almost verbatim. This is a recurring pattern in language history: syntax choices made for prototype convenience harden into permanent constraints through backward compatibility.

**The industrial context of 1986 must be held clearly in mind.** The alternative programming models available to a systems programmer building telephone exchange software in 1986 were: C (with manual memory management and no concurrency abstractions), Ada (with tasks and rendezvous, but heavyweight), and various Prolog dialects. Java was eight years away. Threads as a general programming model existed in research but were not mainstream. The concept of async/await was not yet articulated. The Erlang designers were not choosing the actor model over alternatives — they were independently discovering principles that satisfied constraints imposed by their problem domain.

**The telecom constraints drove every major decision.** Armstrong's 2007 HOPL paper is explicit about what Ericsson needed: software that handled concurrency (telephony serves multiple simultaneous calls), software that continued operating when hardware or software components failed, software that could be updated without halting the system [ARMSTRONG-2007]. These were not aspirational goals. They were requirements for a system where downtime was measured in regulatory penalties and customer loss. Each design choice traces back to one of these requirements. Shared-nothing processes exist because shared state cannot be safely recovered after a node failure. Per-process garbage collection exists because a stop-the-world GC pause would interrupt ongoing calls. Pattern matching exists because telephone exchange code was deeply message-dispatch-oriented and the alternative — nested conditionals — was error-prone. The supervision hierarchy exists because someone had to restart failed components, and that someone needed a formal protocol.

**Armstrong's independent convergence with Hewitt is historically significant.** Carl Hewitt, Peter Bishop, and Richard Steiger proposed the Actor model in 1973 as a theoretical framework for AI computation [HEWITT-1973]. Hoare published CSP in 1978. Yet when the Erlang designers arrived at their process-based, message-passing model in 1986, they were apparently unaware of Hewitt's work [HEWITT-ACTORS-HIST]. Armstrong did not describe Erlang as an actor language in his HOPL paper — the word "actor" does not appear. This is one of the more striking cases of parallel discovery in computing: theoretical models and practical engineering arriving at the same place by different routes. The historian's lesson is that certain solutions are not invented but discovered, and the discovery happens independently wherever the same constraints apply.

**What Armstrong said about shared memory deserves direct quotation.** In his blog and thesis, Armstrong was explicit: "Shared data structures in a distributed system have terrible properties in the presence of failures. If a data structure is shared by two physical nodes and if one node fails, then failure recovery is often impossible." And more pointedly: "Shared-nothing and single assignment isolates a process' memory, avoiding locks (a lock could happen to not be unlocked during a crash, keeping other processes from accessing the data or leaving data in an inconsistent state)" [ARMSTRONG-BLOG]. This was not a theoretical preference; it was an engineering conclusion drawn from observing failure modes in distributed systems. The shared-nothing model was a solution to a real problem that shared-memory concurrency could not solve cleanly.

**The OTP framework was not planned; it was discovered.** The research brief places OTP's origins in 1995 [ERLANG-WIKI]. But the more significant historical point is that OTP formalized patterns that had already emerged in successful Erlang systems — the ACS/Dunder project and others. The GenServer abstraction, the supervisor hierarchy, the application model — these were not designed top-down as a framework. They were observed patterns in working code that were then systematized. This has profound implications for language design: the right abstractions often emerge from practice before they are named. OTP is a post-hoc recognition of what good Erlang code had already been doing.

**Elixir's origin story is a lesson about syntax as adoption barrier.** José Valim was not dissatisfied with Erlang's concurrency model or its reliability guarantees. He was dissatisfied with its syntax and its tooling. His stated motivations included Erlang's cumbersome `if` construct, limited metaprogramming, limited polymorphism support, and poor Unicode handling [VALIM-SITEPOINT]. Valim had come from Ruby on Rails, where productivity tooling and ergonomic syntax were design priorities. The mismatch between Erlang's power and its surface presented him with an opportunity: preserve the BEAM and OTP, rebuild the programming interface. Crucially, the first prototype (April 2011) diverged too far from Erlang idioms and was abandoned. The October 2011 redesign, in collaboration with Yehuda Katz, moved Elixir back toward Erlang's fundamentals with a Ruby-influenced surface [ELIXIR-HISTORY]. This iteration — prototype, fail, redesign — is itself historically instructive. Languages that try to replace what exists often fail by changing too much at once. Elixir succeeded because it changed only what was necessary.

---

## 2. Type System

The Erlang type system's history is a forty-year argument about what a type system is for in a language built on dynamic behavior and fault recovery. That argument has not been resolved — it has merely been shifted from Erlang to Elixir, where a more recent answer is being attempted.

**The 1997 attempt and why it failed.** Simon Marlow and Philip Wadler — both distinguished researchers in type theory — attempted to add a static type system to Erlang in 1997 [MARLOW-WADLER-1997]. Their paper, "Practical Subtyping for Erlang," proposed adding types in a manner compatible with the language. The proposal did not succeed in convincing the community. The reasons are instructive: Erlang's dynamic nature, its reliance on pattern matching with guards (which depends on runtime type information), and its message-passing semantics made traditional Hindley-Milner inference awkward. More fundamentally, the community was skeptical that static types would preserve the properties they valued — the ability to run arbitrary code, to load modules without type annotations, to upgrade code live. The failure of the 1997 proposal established a baseline: adding conventional static types to Erlang required either changing the language or accepting significant limitations.

**Dialyzer as a pragmatic response.** Kostis Sagonas and his team at Uppsala University developed Dialyzer through the HiPE (High Performance Erlang) project as a response to the typing problem that explicitly rejected false positives [SAGONAS-INFOQ]. The design philosophy of success typing — "never raise a false alarm, accept some false negatives" — was not a technical limitation but a deliberate choice aligned with Erlang's culture. Erlang developers routinely relied on dynamic dispatch, dynamic module loading, and runtime type checks. A type system that flagged correct programs as incorrect would be rejected. By accepting false negatives, Sagonas made Dialyzer adoptable without code modifications. The `-spec` annotations that Dialyzer uses as hints are optional; the tool works without them. This is the historically important design choice: respect the language as it exists rather than the language as it might theoretically be.

**Forty years of incremental refinement.** Dialyzer shipped in OTP and was gradually adopted. The EEP process added `-type` and `-spec` declarations as standard syntax. OTP 28 implements EEP 69 (Nominal Types), and EEP-0061 adds `dynamic/0` to facilitate gradual typing [EEP-0061] [OTP-28-HIGHLIGHTS]. This incremental path — from no types (1986), to optional analysis (2000s), to gradual types (2020s) — mirrors the path taken by Python, JavaScript, and PHP. The pattern suggests that dynamically-typed languages, when they mature and gain large codebases, inevitably evolve toward optional static guarantees. Erlang's path is distinctive in arriving at this destination with minimal disruption to existing code.

**Elixir's 2023–2026 type system is a different kind of bet.** Beginning with the 2023 paper by Castagna, Valim et al. [ELIXIR-TYPES-PAPER] and implemented incrementally from v1.17 (June 2024) through v1.20 (January 2026), Elixir is building a set-theoretic type system that supports union, intersection, and negation types with full type inference, no required annotations, and backward compatibility guarantees. This design is theoretically richer than Dialyzer's success typing. The historical significance is that Elixir is attempting to solve in a formal, academic partnership what Erlang's community rejected in 1997 — and it is doing so by building incrementally rather than as a single proposal, and by guaranteeing that existing code remains valid. The lesson from 1997 is that type systems must earn adoption, not demand it.

---

## 3. Memory Model

The per-process heap design is the most historically consequential decision in Erlang's architecture, and it was made at a time when its implications were not fully understood.

**Why per-process heaps in 1986.** Java's garbage collector did not exist yet. The dominant approach to memory management was C's manual allocation, with the attendant use-after-free and double-free bugs. Prolog had its own GC, but it was designed for a single-process world. When Armstrong and team built Erlang's C implementation, they needed garbage collection that would not interrupt ongoing processes in a system where processes represented active telephone calls. A global stop-the-world GC was ruled out immediately: pausing the entire system to collect garbage in a telephony exchange meant dropping calls. Per-process heaps were the solution that matched the isolation model. Each process owned its memory; collecting that memory paused only that process. The design that emerged from practical necessity in 1988 anticipated by fifteen years what the Java Virtual Machine would eventually need to build (concurrent, low-pause GC) to serve high-availability workloads.

**The message-copying trade-off.** The choice to copy message data between process heaps rather than pass pointers has costs — inter-process communication has allocation cost proportional to message size — and was not inevitable. Armstrong was explicit about the reasoning: because Erlang data is immutable, copying is semantically equivalent to sharing a reference, and sharing a reference between process heaps would require either cross-heap pointer tracking (which complicates GC) or giving up independent per-process collection [ARMSTRONG-2007]. The large-binary optimization (binaries larger than 64 bytes go to a shared heap with reference counting) shows that the designers recognized the trade-off and addressed it where it mattered most. Understanding this design requires understanding that it was chosen to make GC implementation tractable for a small team, not because copying was theoretically optimal.

**The large-binary special case reveals the boundary of the design.** When binaries are small, copying is cheap. When binaries are large (video, audio, large messages), copying is expensive. The special case — store large binaries in a shared heap with reference counting, pass references rather than copies — is the system's acknowledgment of where the pure per-process model breaks down. Reference counting shared binaries creates a different failure mode: a process accumulating many references to large binaries can hold memory alive longer than expected. This is a known Erlang operational hazard. It is historically interesting because it shows that the "clean" design (pure per-process heaps) had to accommodate reality through an exception, and that exception has its own operational consequences.

---

## 4. Concurrency and Parallelism

Erlang solved, in 1986, a problem that would not be named until 2015: the colored function problem.

**The historical context of concurrency in 1986.** When the Erlang team was building their concurrency model, the dominant alternatives were: OS threads (heavyweight, with shared memory, requiring locks), Ada's rendezvous model (explicit synchronization points, typed channels), and CSP (Hoare's 1978 theoretical model, not widely implemented). The actor model was theoretical. Practical concurrent programming meant managing shared state with mutexes, which in failure scenarios could leave locks permanently acquired — exactly the failure mode Armstrong identified as unacceptable for fault-tolerant systems.

**The reduction-based preemptive scheduler was ahead of its time.** BEAM processes are scheduled preemptively using a reduction count: each process gets approximately 2,000 reductions per timeslice before being preempted [BEAM-BOOK]. This was unusual in 1988. Most concurrent systems used cooperative scheduling or OS threads. Preemptive scheduling at the language runtime level meant that a single slow process could not starve others — critical for telephony, where one computationally intensive call must not delay others. The design predates by two decades the "green threads" and "goroutines" that Go would make mainstream, and the "virtual threads" that Java would introduce in Java 21 (2023).

**"Function coloring" and why Erlang avoids it.** Bob Nystrom's 2015 blog post "What Color Is Your Function?" named the problem: in languages with async/await (JavaScript, Python, Rust, C#), functions are "colored" synchronous or asynchronous, and async functions cannot call synchronous functions freely and vice versa. This imposes a viral constraint on codebases. Erlang was designed in 1986 without async/await, and the actor model makes all functions uniform: every function executes synchronously within its process; concurrency is expressed by spawning processes and passing messages, not by marking functions asynchronous [HN-COLORED]. The absence of function coloring was not a deliberate design choice against a known alternative — it was the natural consequence of the actor model predating async/await by decades. Erlang avoided the problem by solving a different problem first.

**The OTP behaviors formalized the right abstractions.** The GenServer, Supervisor, and Application abstractions emerged from practical Erlang programming in the early 1990s. Their historical significance is that they represent a formal encoding of concurrency patterns: the client-server interaction, the state machine, the process lifecycle. These patterns existed implicitly in Erlang programs before OTP named them. By 1996, when OTP was formalized, Ericsson had enough production Erlang to know which patterns recurred [OTP-WIKI]. OTP is not a framework imposed on Erlang — it is the distillation of what working Erlang systems had independently discovered.

**The distribution model's design reveals 1988 network assumptions.** The built-in distributed Erlang model uses a fully meshed topology: every node connects to every other node [DIST-ERLANG]. This was appropriate when the language was designed for small clusters of telephone exchange machines within a single data center. The mesh model does not scale to large dynamic clusters — connection count grows quadratically. This is not a design failure given 1988 network conditions; it is a design constraint that became visible as the deployment model changed. The 2010s brought Kubernetes, dynamic cluster membership, and deployments in dozens of geographically distributed nodes. The community response — libcluster, Horde — worked around the mesh limitation rather than redesigning distribution. This is a characteristic pattern: core designs that were appropriate at design time accumulate workarounds as deployment contexts evolve.

---

## 5. Error Handling

"Let it crash" is now treated as an obvious principle. In 1986, it was a radical inversion of the prevailing wisdom.

**What defensive programming meant in 1986.** The software engineering culture of the 1980s emphasized defensive programming: validate all inputs, catch all errors, return error codes, log failures, and attempt recovery at the point of failure. This approach produced code where error handling was entangled with business logic — nested conditionals, explicit error-code checking at every call site. It also produced code where errors were commonly swallowed silently, because the defensive checks were written as boilerplate rather than as meaningful recovery logic.

**Armstrong's inversion.** Armstrong's PhD thesis articulates the alternative as a formal principle: separate "normal code" from "recovery code," let processes crash when they encounter unexpected state, and delegate recovery to supervisors [ARMSTRONG-2003]. The crucial insight was that recovery code written by the same programmer who wrote the normal code tends to be wrong: it cannot anticipate failure modes that the programmer did not foresee. Supervisors, by contrast, implement simple, testable recovery strategies: restart the process, restart all children, shut down. These strategies are independent of the normal code and can be reasoned about separately.

**The link mechanism enables observable crashes.** In Erlang, a process crash propagates by default to all linked processes (which also crash) unless the linked process traps exits explicitly. This design makes crashes visible rather than silent. The alternative — crashes that silently terminate a process while parent processes remain unaware — produces "process leak" failure modes where the system continues running with increasingly missing components. The link-based propagation forces programmers to decide explicitly what to do with a crash rather than allowing the default to be silence.

**The `catch Expr` syntax as cautionary tale.** OTP 28 (2025) introduced the first deprecation warning for the old-style `catch Expr` syntax [OTP-28-HIGHLIGHTS]. This syntax, present since Erlang's creation, catches all exceptions including programming errors that should propagate. It is a "swallow everything" construct — the opposite of "let it crash" — and its presence in the language since 1986 represents a design inconsistency. The community used it; it was convenient; it survived for nearly four decades before formal deprecation. The historian's observation: even languages built around strong design philosophies accumulate escape hatches that contradict those philosophies, and removing them requires patience measured in decades, not years.

---

## 6. Ecosystem and Tooling

The Erlang ecosystem in 1998 was an internal Ericsson tool with no public package repository, no community build tooling, and no documentation infrastructure beyond internal Ericsson materials. The ecosystem that exists today was built in the twenty-five years since open-sourcing — and that open-sourcing itself was not a planned community strategy but an act of desperation following a corporate ban.

**The 1998 ban and its unintended consequence.** Ericsson's February 1998 ban cited preference for "non-proprietary languages" — officially, concern that Erlang was too novel and required too much specialist knowledge [WILLIAMS-TALK]. Armstrong later compressed the real reason: "it wasn't Java." The ban was issued just weeks before the March 1998 AXD301 announcement: a telephone switch containing over a million lines of Erlang that achieved 99.9999999% availability (nine nines) [ERLANG-WIKI]. The management decision to ban the most successful software Ericsson had ever deployed for reliability purposes is a study in how institutional forces override technical evidence. The open-source release of December 1998 was not the original plan; it was negotiated by the team as a condition of not simply shutting down the project entirely. Jane Walerud convinced Ericsson management to release the source [ERLANG-OSS-20YRS]. Without that negotiation, there would be no WhatsApp story, no RabbitMQ, no Phoenix, no Elixir.

**The fifteen years before WhatsApp.** Between 1998 and 2009, Erlang was an open-source language with a small community and no commercial momentum. WhatsApp's engineers discovered Erlang through Anton Lavrik's encounter with Armstrong's PhD thesis during his own research [LAVRIK-INTERVIEW]. WhatsApp chose Erlang because it matched their architectural problem: one lightweight process per connected user, message passing for routing, no shared state, transparent distribution. The scale WhatsApp achieved — 2 million simultaneous TCP connections per server (2011), 2 billion users by Facebook-era operation — validated every claim the Erlang team had made in 1986 and every claim Ericsson management had dismissed in 1998. The fifteen-year gap between the ban and WhatsApp's proof is historically significant: languages designed for specific domains often wait a long time for the world to generalize that domain.

**The Elixir ecosystem as an accelerant.** Mix, Phoenix, Hex.pm, ExUnit, ExDoc — these tools all arrived with or shortly after Elixir v1.0 (2014). The Erlang ecosystem in 2014 still relied on Rebar and erlang.mk, lacked a clean package registry, and had documentation scattered across OTP manual pages. Elixir's introduction of a unified toolchain was a qualitative change for BEAM ecosystem adoption. Hex.pm (shared with Erlang through Rebar3 integration) gave the entire ecosystem a modern package repository. Phoenix's 2015 release gave Elixir a web framework that competed on ergonomics with Rails while exceeding it on concurrency characteristics. The historian's observation: ecosystem tooling matters to adoption at least as much as language design. Erlang had better concurrency semantics than Ruby in 2011; Elixir won Ruby developers partly by giving them comparable tooling ergonomics.

**Discord and the validation of Phoenix LiveView.** Discord's 2020 blog post described handling 5 million concurrent users across 400-500 Elixir nodes with a five-person infrastructure team [DISCORD-ELIXIR]. This is a qualitatively different kind of validation from WhatsApp: Discord showed that Elixir, not just Erlang, could achieve the scale properties the BEAM promised, and with a modern toolchain and framework. Phoenix LiveView — server-rendered reactive UIs without client JavaScript — was released in this same era. LiveView is historically significant because it represents a genuine architectural innovation enabled by BEAM's concurrency: cheap server-side state (one process per connected user) makes what would be an expensive commitment on a thread-per-request server trivially cheap on the BEAM.

---

## 7. Security Profile

The April 2025 SSH vulnerability (CVE-2025-32433, CVSS 10.0) is historically instructive precisely because it represents a failure mode that Erlang's design philosophy was supposed to prevent — and did not.

**The BEAM's structural security guarantees are real.** Memory safety vulnerabilities — buffer overflows, use-after-free, double-free — are structurally impossible in BEAM languages. No pointer arithmetic, no manual memory management, no shared mutable state between processes, process isolation that prevents one crash from corrupting another process's memory [RESEARCH-BRIEF]. These are genuine historical achievements. The vulnerability profile of Erlang/OTP over its history reflects this: there are no buffer overflow CVEs, no heap corruption bugs in the runtime language itself. The CVSS scores for Erlang vulnerabilities historically clustered below 5.0 until 2025.

**The SSH implementation vulnerability exposes a different failure class.** CVE-2025-32433 allowed unauthenticated remote code execution through Erlang's built-in SSH daemon [CVE-2025-32433]. The vulnerability was not in the language or the BEAM — it was in the protocol state machine implementation of the SSH application. An attacker could send connection protocol messages (codes ≥ 80) before authentication completed, achieving arbitrary code execution. This is a protocol logic error, not a memory safety error. The BEAM's process isolation and managed memory provided no defense against incorrect protocol handling.

**The historical significance: bundled protocol implementations create blast radius.** Erlang's design decision to ship a full SSH implementation as part of OTP reflects 1990s distributed systems design: build everything needed to run a distributed system in the runtime. This decision maximized convenience and minimized dependencies. The 2025 vulnerability showed the other side of that trade-off: when the bundled SSH implementation has a critical flaw, every OTP-based system with SSH enabled is affected simultaneously. The "include everything in OTP" philosophy that made Erlang powerful in 1996 became a security supply chain risk in 2025, when every MQTT broker, message queue, and telephone switch running default configurations shared the same vulnerable SSH daemon.

---

## 8. Developer Experience

Erlang's developer experience problem is as old as Erlang itself, and it was not solved for forty years. Elixir is the answer to the question: what would Erlang look like if it had been designed by someone who thought carefully about developer ergonomics?

**The Prolog syntax as original sin.** The research brief documents that Erlang's syntax derives directly from its Prolog prototype [ARMSTRONG-2007]. Variables start with uppercase. Atoms start with lowercase. Clauses end with periods. Operators include commas for sequencing and semicolons for alternation. The `if` expression in Erlang is not what programmers from C-family languages expect. These choices were natural when the language was a Prolog extension used by its own creators. They became barriers when Erlang was open-sourced to a developer community that had grown up on C, Java, and Python.

**Why Erlang never fixed its own syntax.** The answer is backward compatibility. Any syntax change that made Erlang more approachable to newcomers would break existing Erlang code. Ericsson's OTP team maintained strong backward compatibility guarantees — the `deprecated` mechanism exists precisely because removing things is politically and practically difficult. The community that used Erlang had internalized the syntax; they would resist changes that invalidated their expertise. The result was a language that was simultaneously very powerful and very inaccessible, with little path to fix the accessibility problem without fracturing the community.

**Elixir's October 2011 redesign is historically decisive.** The first Elixir prototype (April 2011) had diverged too far from Erlang to be useful — it was more Ruby than Erlang [ELIXIR-HISTORY]. The October 2011 redesign with Yehuda Katz established Elixir's fundamental direction: Erlang semantics and OTP compatibility with Ruby-influenced syntax and metaprogramming. This compromise proved correct. Elixir can call any Erlang function directly. Any Erlang OTP behavior works in Elixir. But the syntax is palatable to developers from Ruby, Python, and JavaScript backgrounds. The pipe operator `|>` (borrowed from functional programming), the `with` macro for error chaining, `defmacro` for hygienic macros — these are ergonomic improvements that do not change the underlying BEAM semantics.

**Error messages as a compounding investment.** Elixir v1.14 introduced data-flow tracing in compiler diagnostics. Prior to this, compile-time errors in Elixir (and Erlang) were often obscure. The improvement in error message quality was not a one-time change but an ongoing investment across multiple releases. The historical pattern across languages — C's cryptic errors, Java's NullPointerExceptions without line-of-null-dereference tracking, Python's improved tracebacks in 3.11+ — suggests that error message quality correlates with language maturity and that the investment compounds: better errors reduce the cost of debugging, which increases adoption, which creates more feedback about confusing errors, which drives further improvements.

---

## 9. Performance Characteristics

Erlang's performance story is the story of a language that was designed for a performance target — 40× faster than the Prolog prototype — hitting that target and then optimizing incrementally for thirty-five years.

**The 40× requirement.** The research brief and OTP history both document that the Prolog prototype was too slow for production use; early estimates required a 40× speedup [OTP-WIKI]. The 1988 C reimplementation achieved this. The historical lesson: performance requirements that seem impossibly demanding often clarify rather than prevent good design. The 40× target forced the team to compile to native C-compatible bytecode rather than interpret Prolog. That compiled architecture was the foundation for every subsequent optimization.

**The JIT arrived thirty-five years late.** BeamAsm, the native code JIT compiler for BEAM, shipped in OTP 24 (2021) — thirty-five years after the language's creation [BEAMJIT-BLOG]. This is an extraordinarily long gap. Java got HotSpot in 1999 (four years after Java 1.0). V8's JIT shipped in 2008 (thirteen years after JavaScript's creation). The BEAM JIT arrived because the BEAM's design made JIT compilation architecturally possible but not straightforward: the process-scheduling model, the hot code loading requirement, and the reduction-counting scheduler all had to be accommodated in a JIT. The 50% throughput improvement and targeted optimizations (type-based arithmetic in OTP 25, binary encoding in OTP 26) show that thirty-five years of interpreted execution left significant performance on the table.

**The performance profile reflects domain optimization.** Go delivers 2-3× faster execution for CPU-intensive tasks [INDEX-DEV-COMPARISON]. The BEAM is not designed for CPU-intensive tasks. It is designed for concurrent I/O-bound workloads with millions of lightweight processes. WhatsApp's 2 million simultaneous TCP connections per server, Discord's 5 million concurrent users on 400-500 nodes — these numbers represent the domain Erlang was designed for, and in that domain it outperforms general-purpose languages. Comparing BEAM to Go on CPU-bound benchmarks is like comparing a ship to a truck on land speed.

---

## 10. Interoperability

The NIF (Native Implemented Function) mechanism is historically interesting because it represents the exact boundary between Erlang's safety guarantees and the reality that sometimes you need C.

**The port and NIF design philosophy reflects Erlang's process isolation commitment.** Early Erlang communicated with external C code through ports — a separate OS process that communicated with the BEAM over standard I/O [ERLANG-DOCS]. This preserved process isolation completely: a crash in the C process could not affect the BEAM. Ports were slow. NIFs were added as a faster alternative: C code called directly within the BEAM scheduler, running in the same OS process. NIFs are fast but bypass all BEAM safety guarantees. A NIF crash brings down the entire VM. This trade-off — safety versus performance — recurs in every language's approach to native interop (Python's C extensions, Ruby's C extensions, JavaScript's N-API). Erlang made the safer choice first and the faster choice later, which is historically the correct order.

**Dirty NIFs (OTP 17) as a partial solution.** Dirty NIFs, introduced in OTP 17 (2014), run on separate scheduler threads outside the normal BEAM scheduler [NIF-INTEROP]. This allows long-running C computations to avoid blocking BEAM schedulers. The "dirty" label is historically significant: the Erlang team was explicit that NIFs that block the scheduler are "dirty" — a deliberate choice of terminology to mark them as aberrations from the pure model. The dirty NIF design acknowledges that perfect isolation is aspirational; the practical concession is a degraded mode that preserves some of the model's properties.

**The 2025 interoperability blog post signals maturity.** The August 2025 elixir-lang.org blog post on interoperability explored mechanisms beyond NIFs — ports, port drivers, and emerging patterns for external language integration [NIF-INTEROP-2025]. This is historically significant: after forty years of "Erlang is self-contained," the community is actively reconsidering its interoperability story. The Nx project — which calls XLA/MLIR backends for GPU computation — is driving this reconsidering. GPU computing cannot be done in pure Erlang/Elixir; it requires native libraries. The community is adapting its interoperability model to support ML workloads without abandoning BEAM safety principles.

---

## 11. Governance and Evolution

The governance history of Erlang and Elixir is a study in contrasts: a corporate-controlled language that open-sourced involuntarily versus a BDFL language started by a single engineer who had to build an institution around it.

**Ericsson's governance model: industrial dependency.** Ericsson's OTP Product Unit funds and controls OTP development. This model has provided stability: OTP has strong backward compatibility, a formal EEP process, and a predictable release cadence. It has also created constraints: major language changes require corporate approval at Ericsson, the OTP team is small (a few dozen engineers), and language evolution is slow compared to languages with larger contributor bases. The Apache License 2.0 adoption in OTP 18 (May 2015) was a significant governance milestone — it removed the Erlang Public License's requirement that modifications be made available, enabling commercial products without source disclosure [ERLANG-APACHE]. This change, driven by the Industrial Erlang User Group, reflects the community's maturation: commercial users need license clarity to deploy Erlang in proprietary products.

**The 1998 team resignation as governance crisis.** When Ericsson banned Erlang in 1998, "most of the Erlang team resigned to form Bluetail AB" [ERLANG-WIKI]. This moment — the language's creators leaving the company — could have been catastrophic. It was not, for two reasons: the open-source release that accompanied the crisis gave the language a life beyond Ericsson, and the OTP framework was sufficiently formalized that the departing team's expertise was encoded in the codebase rather than being purely tacit knowledge. The governance lesson: languages that are well-documented and have their core patterns encoded in formal abstractions survive institutional crises better than those that depend on key individuals.

**The EEP process as community governance.** The Erlang Enhancement Proposal process, modeled on Python's PEP, was established after open-sourcing [EEP-0001]. EEPs require community consensus and a reference implementation. The rejection of EEP-0012 (a module system extension) on grounds of complexity demonstrates the process working as intended: preventing feature accumulation for its own sake. Forty years of Erlang core design have added relatively few features to the base language — maps (2014), nominal types (2025) — compared to the feature velocity of languages like C# or Scala. This conservatism is a consequence of the governance model as much as a design philosophy.

**The EEF (2019) as ecosystem maturation.** The Erlang Ecosystem Foundation's formation in 2019, with over 1,000 members and backing from Ericsson, Cisco, and Erlang Solutions [EEF-ORG], represents the community's recognition that OTP's corporate governance model could not steward the entire BEAM ecosystem. The EEF funds documentation, security working groups, interoperability work, and educational initiatives that Ericsson has no commercial reason to prioritize. Its formation follows a pattern seen in mature language ecosystems: corporate governance of the core language coexists with community governance of the surrounding ecosystem (compare Rust Foundation, Python Software Foundation, Java Community Process).

**Elixir's BDFL model and its fragility.** José Valim as Benevolent Dictator For Life represents the highest-velocity governance model: one person makes decisions, progress is fast, design coherence is high. The weakness is bus factor: Valim's departure, incapacity, or changed priorities would destabilize Elixir's direction. Plataformatec's closure in 2021 and the formation of Dashbit illustrates the fragility — the institutional home for Elixir's core development changed within the language's first decade [DASHBIT-10YRS]. Elixir currently has no formal succession mechanism. This is historically typical for young languages (Python's Guido van Rossum was BDFL from 1991 to 2018) but becomes a governance liability as the language matures and the community grows beyond the founder's direct oversight.

---

## 12. Synthesis and Assessment

### The Arc of the Story

Erlang and Elixir together trace an arc that is almost uniquely instructive for programming language history. A language is invented to solve a specific industrial problem. It solves that problem exceptionally well. Its corporate owner bans it anyway. It is open-sourced by accident. It survives fifteen years in obscurity. The internet generalizes the problem the language was designed to solve, and the language becomes suddenly valuable. A syntax-aware successor appears that inherits the core design and adds tooling ergonomics. The successor achieves the adoption that the original could not. Through it all, the core VM — the BEAM — accumulates thirty-five years of production hardening and emerges as one of the most robust concurrency substrates available.

### Greatest Strengths (Historical Assessment)

**The process model is proven in production at civilizational scale.** WhatsApp's 2 billion users, Discord's millions of concurrent connections, the global instant payment system through RabbitMQ — these are not benchmark numbers. They are production deployments that have run for years under real failure conditions. The BEAM's per-process GC, lightweight processes, and link-based failure propagation have been validated at a scale and duration that most concurrency models have not approached.

**OTP's encoding of design patterns is irreplaceable.** The GenServer, Supervisor, and Application abstractions are not framework opinions — they are formalized distillations of how to build reliable concurrent systems. Languages that acquire concurrency later must either rediscover these patterns or adopt inferior ones. Go's goroutines and channels are powerful but lack OTP's formalized supervision semantics. Java's virtual threads arrived fifty years after BEAM processes. The BEAM ecosystem begins with OTP.

**The "no function coloring" property has compounded in value.** Erlang was designed before async/await; it avoided function coloring as a side effect of the actor model. As async/await has become standard in JavaScript, Python, Rust, and C#, the accidental advantage of Erlang/Elixir's uniform concurrency model has become more visible. In 2026, developers migrating from async JavaScript to Elixir consistently cite the absence of colored functions as a relief.

### Greatest Weaknesses (Historical Assessment)

**The syntax barrier cost the language its first twenty years.** If Erlang had a more accessible syntax in 1998 when it was open-sourced, the community that built Rails, Django, and Spring might have built BEAM-native frameworks instead. The Prolog heritage that made Erlang easy to build in 1986 made it hard to adopt in the 2000s. Elixir corrected this but arrived twenty-five years later.

**The corporate governance model creates long-term institutional risk.** Erlang's fate is structurally tied to Ericsson's commercial priorities. The 1998 ban demonstrated that institutional decisions can override technical merit. Ericsson's continued funding of OTP is the main institutional dependency for the language's survival. The EEF provides ecosystem support but cannot replace Ericsson's role in OTP development.

**The small ecosystem remains a structural constraint.** The BEAM ecosystem is orders of magnitude smaller than Python, JavaScript, or Java. This gap has narrowed with Elixir's growth but has not closed. Libraries that exist in multiple versions for Python (HTTP clients, database drivers, ML frameworks) exist in one or two versions for the BEAM. This is not a design failure but an adoption consequence: smaller community means fewer maintained packages.

### Lessons for Language Design

**1. Design for your most demanding operational requirement.** Erlang's reliability properties derive entirely from designing for the worst case: hardware failures, software errors, live code updates, non-stop operation. Relaxing any of these requirements would have produced a simpler language with less resilience. The operational demands of 1980s telephony — more demanding than most modern web services — produced design discipline that generalized to the internet era.

**2. Independently discovered solutions to the same problem indicate that the solution is correct.** Erlang's designers independently arrived at actor-like concurrency without knowledge of Hewitt's theoretical work. When theory and practice converge independently, it suggests both are tracking something real. Language designers should investigate where multiple independent efforts have produced similar designs before inventing yet another alternative.

**3. Syntax is adoption; semantics is correctness.** Erlang had better concurrency semantics than Java in 1996 and better fault-tolerance semantics than Python in 2005. It gained less adoption than either. Elixir demonstrated that surface syntax and tooling ergonomics are not secondary concerns: they are the primary adoption mechanism. A language with correct semantics and hostile syntax may be correct and unused.

**4. Pattern-encoding in the standard library creates leverage.** OTP's GenServer, Supervisor, and Application behaviors encode design patterns that application programmers must otherwise rediscover. Every framework built on OTP inherits these patterns; every programmer who learns OTP internalizes them. The investment in formalizing patterns into library abstractions compounds across the entire ecosystem over decades.

**5. Backward compatibility is slow poison and necessary medicine simultaneously.** Erlang's strong backward compatibility allowed Ericsson to deploy Erlang at scale; it also prevented the community from ever fixing Erlang's syntax. The `catch Expr` syntax was present from 1986 and deprecated only in 2025. Language designers must decide early how much they will accept this trade-off, because once a language has production deployments, backward compatibility pressure becomes effectively permanent.

**6. Open-sourcing under duress can create more value than planned open-sourcing.** The 1998 Erlang open-source release was not a community strategy — it was a survival move following a corporate ban. Without the ban, Erlang might have remained internal to Ericsson, and the BEAM ecosystem as it exists today would not exist. This is historically ironic: the decision that nearly killed Erlang enabled everything that followed. The lesson for language stewards is not that duress creates value, but that removing barriers to community access, even involuntarily, can have compounding effects that no internal deployment model can match.

**7. Languages designed for a narrow problem domain should be evaluated on that domain.** Erlang performs 5-20× worse than C on CPU-bound benchmarks. Erlang handles millions of concurrent connections with single-digit millisecond latency where C-based servers struggle with thread scheduling overhead. Evaluating BEAM languages on CPU benchmarks is like evaluating PostgreSQL on write throughput without considering transactional correctness. The domain for which a language was designed is the appropriate evaluation domain.

**8. A language's second life can be more important than its first.** Erlang's first life was as an Ericsson internal tool. Its second life, following open-sourcing, produced WhatsApp, RabbitMQ, and an entire ecosystem. Elixir gave Erlang's semantics a third life by making them accessible to a new generation of developers. Languages with strong foundational designs can experience multiple adoption waves as the world's problems evolve to match the language's strengths.

**9. The gradual type system path is inevitable for adopted dynamic languages.** Erlang (Dialyzer, success typing), Python (mypy, PEP 484), JavaScript (TypeScript), PHP (PHPStan), and now Elixir (set-theoretic gradual types) have all followed the same trajectory: dynamic language adopted widely, codebases grow, optional static analysis tools emerge, type annotations gradually become standard practice. Language designers who anticipate this trajectory can build type system extension points from the beginning rather than retrofitting them decades later.

**10. The "let it crash" principle only works with observable crashes.** Armstrong's insight was that recovery code separate from normal code is more reliable than entangled defensive programming. But this only holds if crashes are observable and supervised. The link-based propagation in Erlang is the mechanism that makes crashes visible. A language that adopted "let it crash" without crash observability would just have a lot of silently failing processes. The principle and its implementation mechanism are inseparable.

**11. A runtime shared between two languages is more valuable than either language alone.** Erlang and Elixir are distinct languages with different syntaxes, tooling ecosystems, and community cultures, but they share the BEAM, OTP, and Hex.pm. This arrangement — one VM, multiple language surfaces — has historical precedent in the JVM (Java, Kotlin, Scala, Clojure) and CLR (.NET's C#, F#, VB.NET). The BEAM case is distinct because the two languages have nearly identical concurrency semantics and can directly call each other's functions without bridging overhead. The historical lesson is that a well-designed VM can become a platform on which language experiments run cheaply, and that runtime sharing accelerates adoption of successor languages by giving them mature infrastructure immediately. Elixir did not need to build a GC, a scheduler, or a distributed protocol; it inherited these from forty years of Erlang engineering. Language designers building new VMs should consider multi-language support as a first-class design goal rather than an afterthought.

**12. The interval between design and validation can span decades.** Erlang was designed in 1986 for telephony reliability requirements. Its design was not validated at internet scale until WhatsApp (2009–2014). The fifteen-year gap between open-sourcing (1998) and widespread validation was not a failure of the language — it was the time required for the world's problems to generalize to match the language's strengths. Language designers who build for demanding operational requirements should not interpret slow adoption as evidence that the requirements were wrong. The WhatsApp story is an argument for patience and for the value of designs whose excellence only becomes apparent when constraints are extreme.

### Dissenting View

**On the claim that Elixir "fixed" Erlang:** Elixir improved Erlang's syntax and tooling. It did not fix Erlang's fundamental limitations: the BEAM's message-copying overhead, the mesh distribution topology's scaling ceiling, the NIF hazard, the small ecosystem. Elixir is a better-dressed BEAM language. That is valuable but should not be confused with resolving the underlying constraints.

---

## References

[ARMSTRONG-2007] Armstrong, J. "A History of Erlang." Proceedings of HOPL III, 2007. https://dl.acm.org/doi/10.1145/1238844.1238850

[ARMSTRONG-2003] Armstrong, J. "Making Reliable Distributed Systems in the Presence of Software Errors." PhD Thesis, KTH Stockholm, 2003. https://erlang.org/download/armstrong_thesis_2003.pdf

[ARMSTRONG-BLOG] Armstrong, J. "Why I Don't Like Shared Memory." armstrongonsoftware.blogspot.com, 2006. http://armstrongonsoftware.blogspot.com/2006/09/why-i-dont-like-shared-memory.html

[HEWITT-1973] Hewitt, C., Bishop, P., Steiger, R. "A Universal Modular ACTOR Formalism for Artificial Intelligence." IJCAI 1973.

[HEWITT-ACTORS-HIST] "A History of Actors." eighty-twenty.org, 2016. https://eighty-twenty.org/2016/10/18/actors-hopl

[MARLOW-WADLER-1997] Marlow, S. and Wadler, P. "A practical subtyping system for Erlang." ICFP 1997.

[SAGONAS-INFOQ] "Interview with Kostis Sagonas on Erlang Types and Dialyzer." InfoQ. https://www.infoq.com/interviews/sagonas-erlang/

[WILLIAMS-TALK] Williams, M. "The True Story About Why We Open Sourced Erlang." Erlang Factory presentation. https://www.erlang-factory.com/upload/presentations/416/MikeWilliams.pdf

[LAVRIK-INTERVIEW] "20 years of open source Erlang: OpenErlang interview with Anton Lavrik from WhatsApp." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/20-years-of-open-source-erlang-openerlang-interview-with-anton-lavrik-from-whatsapp/

[ERLANG-WIKI] "Erlang (programming language)." Wikipedia. https://en.wikipedia.org/wiki/Erlang_(programming_language)

[ERLANG-OSS-20YRS] "20 years of open source Erlang." Erlang Solutions, Medium. https://erlangsolutions.medium.com/20-years-of-open-source-erlang-the-openerlang-parties-2ae50d3f932c

[ERLANG-APACHE] Erlang/OTP 18.0 Release Notes. erlang.org.

[OTP-WIKI] "Open Telecom Platform." Wikipedia. https://en.wikipedia.org/wiki/Open_Telecom_Platform

[EEP-0001] "EEP Purpose and Guidelines." erlang.org. https://www.erlang.org/eeps/eep-0001.html

[EEP-0061] "EEP 61: Gradual Types — dynamic/0." erlang.org. https://www.erlang.org/eeps/eep-0061

[OTP-28-HIGHLIGHTS] "Erlang/OTP 28 Highlights." erlang.org, May 2025. https://www.erlang.org/blog/highlights-otp-28/

[ELIXIR-HISTORY] "The Story of Elixir." osshistory.org. https://osshistory.org/p/elixir

[VALIM-SITEPOINT] "An Interview with Elixir Creator José Valim." SitePoint, 2013. https://www.sitepoint.com/an-interview-with-elixir-creator-jose-valim/

[DASHBIT-10YRS] Valim, J. "10 years(-ish) of Elixir." Dashbit Blog. https://dashbit.co/blog/ten-years-ish-of-elixir

[ELIXIR-TYPES-PAPER] Castagna, G., Valim, J., et al. "The Design Principles of the Elixir Type System." arXiv:2306.06391, 2023.

[BEAM-BOOK] Stenmans, E. "The BEAM Book." https://blog.stenmans.org/theBeamBook/

[BEAMJIT-BLOG] "Performance testing the JIT compiler for the BEAM VM." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/performance-testing-the-jit-compiler-for-the-beam-vm/

[CVE-2025-32433] "CVE-2025-32433: Unauthenticated RCE in Erlang/OTP SSH." GHSA-37cp-fgq5-7wc2. https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2

[DISCORD-ELIXIR] DeBenedetto, S. "Real time communication at scale with Elixir at Discord." elixir-lang.org, October 2020. http://elixir-lang.org/blog/2020/10/08/real-time-communication-at-scale-with-elixir-at-discord/

[WHATSAPP-1M-BLOG] "1 million is so 2011." WhatsApp Blog. https://blog.whatsapp.com/1-million-is-so-2011

[EEF-ORG] "Erlang Ecosystem Foundation." erlef.org. https://erlef.org/

[DIST-ERLANG] "Distributed Erlang." Erlang System Documentation. https://www.erlang.org/doc/system/distributed.html

[HN-COLORED] Hacker News thread on function coloring in Erlang. https://news.ycombinator.com/item?id=28914506

[NIF-INTEROP] Leopardi, A. "Using C from Elixir with NIFs." https://andrealeopardi.com/posts/using-c-from-elixir-with-nifs/

[NIF-INTEROP-2025] "Interoperability in 2025: beyond the Erlang VM." elixir-lang.org, August 2025. http://elixir-lang.org/blog/2025/08/18/interop-and-portability/

[INDEX-DEV-COMPARISON] "Erlang vs Elixir vs Go for Backend Development." index.dev, 2026. https://www.index.dev/skill-vs-skill/backend-elixir-vs-erlang-vs-go

[ERLANG-DOCS] Erlang System Documentation. https://www.erlang.org/doc/

[SO-2025] "Stack Overflow Developer Survey 2025." https://survey.stackoverflow.co/2025/technology

[RESEARCH-BRIEF] Erlang/Elixir Research Brief. research/tier1/erlang-elixir/research-brief.md, 2026.
