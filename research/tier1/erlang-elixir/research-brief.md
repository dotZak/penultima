# Erlang/Elixir — Research Brief

```yaml
role: researcher
language: "Erlang/Elixir"
agent: "claude-agent"
date: "2026-03-01"
```

---

## Language Fundamentals

### Erlang

**Creation and Creators**

Erlang was invented in 1986 at Ericsson's Computer Science Laboratory by Joe Armstrong, Robert Virding, and Mike Williams [ARMSTRONG-2007]. The earliest documented work appears in an Ericsson internal report from March 3, 1986: "Telephony Programming in Prolog" (Report T/SU 86 036) [ERLANG-FAQ]. Armstrong and Williams presented "Using Prolog for Rapid Prototyping of Telecommunication Systems" at SETSS '89 (Bournemouth, July 3–6, 1989) [ARMSTRONG-2007].

The initial Prolog-based version was developed between 1986 and 1988 for rapid prototyping. By 1988 it was rewritten in C for production performance, producing the first self-hosting Erlang compiler [ARMSTRONG-2007].

**Stated Design Goals (primary sources)**

Armstrong described the origin in his 2007 HOPL paper: "In the 1980s there was a project at the Ericsson Computer Science Laboratory which aimed to find out what aspects of computer languages made it easier to program telecommunications systems, and Erlang emerged in the second half of the 80s as the result of taking those features which made writing such systems simpler and avoiding those which made them more complex or error prone" [ARMSTRONG-2007].

Key requirements driving the design [ARMSTRONG-2007]:
- Must handle concurrency: telephony systems service multiple simultaneous activities
- Must handle hardware faults and software errors without system restart
- Must support non-stop operation
- Must be able to update running code without halting the system

Armstrong's PhD thesis (2003) formalized the philosophy as: "if there is an error, let the process die and let a supervisor handle the recovery" — the origin of the "let it crash" idiom [ARMSTRONG-2003].

**Open-Source Release**

Erlang was proprietary within Ericsson until December 2, 1998, when "Open-Source Erlang" was announced [ERLANG-OSS]. In 1998, most of the Erlang team resigned to form Bluetail AB [ERLANG-WIKI]. Jane Walerud convinced Ericsson management to release the source code [ERLANG-OSS-20YRS]. The license was changed from the Erlang Public License (EPL) to Apache License 2.0 in May 2015 with OTP 18.0, driven by the Industrial Erlang User Group [ERLANG-APACHE].

**Classification**

- **Paradigm:** Functional, concurrent, declarative
- **Typing discipline:** Dynamic, strongly typed; no implicit type coercions
- **Memory management:** Automatic (per-process generational garbage collection)
- **Compilation model:** Source → bytecode (BEAM bytecode); since OTP 24, native code via JIT (BeamAsm)
- **Distribution:** Natively distributed; nodes communicate transparently via the Erlang Distribution Protocol

### Elixir

**Creation and Creator**

Elixir was created by José Valim, a core contributor to Ruby on Rails and co-founder of Plataformatec, beginning in early 2011 [ELIXIR-WIKI]. Development started as an R&D project at Plataformatec [VALIM-INTERVIEW]. An initial prototype (v0.3.0) was released in April 2011, but it diverged too far from Erlang idioms; Valim redesigned it in October 2011 in San Francisco in collaboration with Yehuda Katz [ELIXIR-HISTORY]. The first stable release was v1.0.0 in September 2014 [ELIXIR-WIKI].

**Stated Design Goals (primary sources)**

Valim stated his goals as: "enable higher extensibility and productivity in the Erlang VM while maintaining compatibility with Erlang's ecosystem" [VALIM-SITEPOINT]. He was motivated by frustrations with Ruby's concurrency limitations and Erlang's cumbersome syntax despite the language's powerful VM [ELIXIR-HISTORY].

Elixir's design pillars [VALIM-SITEPOINT]:
- Full compatibility with and interoperability with the Erlang ecosystem
- A more approachable syntax (Ruby-influenced)
- Extensibility via metaprogramming and macros
- Productivity tooling built into the standard distribution (Mix, ExUnit, ExDoc)

**Classification**

- **Paradigm:** Functional, concurrent, meta-programming
- **Typing discipline:** Dynamic (as of v1.17+, with optional gradual set-theoretic type checking at compile time)
- **Memory management:** Automatic (inherits BEAM per-process GC)
- **Compilation model:** Elixir source → Erlang AST → BEAM bytecode → (optionally) native code via JIT

---

## Historical Timeline

### Erlang Timeline

| Year | Event |
|------|-------|
| 1986 | Erlang project begins at Ericsson CSL; Prolog prototype created [ARMSTRONG-2007] |
| 1988 | First Erlang compiler written in Erlang (self-hosting) [ARMSTRONG-2007] |
| 1989 | AXE-N project: first major internal deployment in telephone exchange software [ARMSTRONG-2007] |
| 1995 | Open Telecom Platform (OTP) prototype started by Ericsson; delivered in prototype May 1996 [ERLANG-WIKI] |
| 1996 | OTP unit created within Ericsson to commercialize and stabilize Erlang [ERLANG-OTP-17YRS] |
| 1998 | Ericsson bans Erlang for new internal products; team resigns and forms Bluetail AB [ERLANG-WIKI] |
| Dec 1998 | Open-Source Erlang announced; source released [ERLANG-OSS] |
| 2004 | Erlang/OTP R10B: first significant OTP release under open-source governance [ERLANG-WIKI] |
| 2014 | Erlang/OTP 17: maps (key-value store) added to the language [ERLANG-WIKI] |
| May 2015 | OTP 18.0: Apache License 2.0 adopted; EEP process formalizes [ERLANG-APACHE] |
| 2021 | OTP 24.0: BeamAsm JIT compiler introduced; ~50% throughput improvement on benchmarks [BEAMJIT-BLOG] |
| 2022 | OTP 25.0: JIT extended with type-based optimizations from compiler [BEAMJIT-BLOG] |
| 2023 | OTP 26.0: Binary syntax JIT optimizations; Base64 encoding 4× faster [BEAMJIT-BLOG] |
| Dec 2024 | OTP 27.2 released (maintenance patch) [OTP-27-2] |
| May 2025 | OTP 28.0 released: priority messages, zip generators, EEP 69 nominal types, EEP 75 based float literals [OTP-28-HIGHLIGHTS] |
| 2025 | OTP 28.3 (current as of early 2026) [OTP-28-RELEASES] |

**Key inflection point:** The 1998 Ericsson ban forced open-sourcing. Mike Williams later recounted that the ban was issued because "Erlang was too risky to use" — meaning Ericsson management believed it was too novel and required too much specialist knowledge [WILLIAMS-TALK]. This had the opposite effect: open-sourcing enabled the broader ecosystem and eventual WhatsApp adoption.

**Feature rejections documented:** The EEP process (modeled on Python's PEP) has rejected proposals including EEP-0012 (a module system extension) on grounds of complexity. The EEP process requires community consensus and a reference implementation before acceptance [EEP-0001].

### Elixir Timeline

| Year | Event |
|------|-------|
| 2011 | Valim begins Elixir at Plataformatec; v0.3.0 prototype released April 2011 [ELIXIR-HISTORY] |
| Oct 2011 | Redesign with Yehuda Katz; Elixir moves closer to Erlang idioms [ELIXIR-HISTORY] |
| Sep 2014 | Elixir v1.0.0 stable release [ELIXIR-WIKI] |
| 2015 | Phoenix Framework 1.0 released by Chris McCord [PHOENIX-HISTORY] |
| 2016 | Nerves (embedded systems) joins Elixir ecosystem; GenStage introduced [DASHBIT-10YRS] |
| 2019 | Broadway (data pipelines over GenStage) announced [DASHBIT-10YRS] |
| 2021 | Numerical Elixir (Nx) project launched for ML/AI [NX-V01] |
| 2022 | Livebook (Jupyter-style notebooks) production release [NX-V01] |
| Jun 2024 | Elixir v1.17.0: set-theoretic type foundations introduced [ELIXIR-117] |
| Dec 2024 | Elixir v1.18.0: type checking of function calls, LSP listeners, built-in JSON [ELIXIR-118] |
| Oct 2025 | Elixir v1.19.0: type inference of anonymous functions; up to 4× faster compilation [ELIXIR-119] |
| Jan 2026 | Elixir v1.20.0-rc: type inference of all language constructs; 2× compilation speedup [ELIXIR-120] |

**Release cadence:** Elixir publishes one backwards-compatible minor release every 6 months, with patch releases for bug fixes and security patches [ELIXIR-ENDOFLIFE].

---

## Adoption and Usage

### Erlang Adoption

**Production deployments (documented)**

- **WhatsApp:** Used Erlang as primary server-side language. At peak pre-acquisition scale (2014), a single Erlang server handled over 2 million concurrent TCP connections [WHATSAPP-1M-BLOG]. WhatsApp served 900 million users with approximately 50 engineers as of early Facebook-era operation [WHATSAPP-SCALE]. As of 2024, WhatsApp reports 2 billion users worldwide [WHATSAPP-SCALE].
- **RabbitMQ:** Written in Erlang; one of the most widely deployed message brokers globally. Used at Goldman Sachs and Vocalink (global instant payment systems) [ERLANG-FINTECH].
- **Ericsson:** Continues to use Erlang in AXE and newer network infrastructure [ERLANG-WIKI].
- **EMQ Technologies:** EMQX MQTT broker, written in Erlang, claims to handle 100 million concurrent MQTT connections [EEF-SPONSORSHIP].

**Survey presence:** Erlang is not separately tracked in Stack Overflow or JetBrains annual surveys; it is too small to appear in headline categories [ERLANG-SO-ABSENCE].

**TIOBE ranking:** Erlang appears in the TIOBE index but below position 40 as of early 2026 [TIOBE-2026].

### Elixir Adoption

**Stack Overflow Developer Survey (2025)**
- 2.7% of respondents use Elixir (up from 2.1% in 2024) [SO-2025]
- 3rd most admired programming language at 66% (behind Rust 72% and Gleam 70%) [SO-2025]
- Phoenix is the most admired web framework in the 2025 survey [SO-2025]

**Stack Overflow Developer Survey (2024)**
- 2.1% of respondents report using Elixir [SO-2024]

**Production deployments (documented)**

- **Discord:** Uses Elixir for real-time chat infrastructure. As of 2020 blog post, Discord ran 400–500 Elixir machines with a chat infrastructure team of 5 engineers [DISCORD-ELIXIR].
- **Fly.io:** Primary platform infrastructure uses Elixir [FLY-ELIXIR].
- **Supabase:** Uses Elixir for real-time subscription infrastructure [CURIOSUM-ADOPTION].
- **Bleacher Report:** Used Elixir to handle 8× traffic growth without proportional infrastructure growth [CURIOSUM-ADOPTION].
- **Wistia:** Uses Elixir for video platform infrastructure [CURIOSUM-ADOPTION].

### Community Size Indicators

- **Hex.pm** (shared package registry for Elixir and Erlang): Primary registry for BEAM ecosystem packages. Current package count visible at hex.pm/packages [HEX-PM].
- **Elixir Forum:** Active community forum at elixirforum.com [ELIXIR-FORUM].
- **Erlang Forums:** Active community at erlangforums.com [ERLANG-FORUM].
- **Conferences:** Code BEAM (previously Erlang Factory) runs annual conferences in Europe, North America, and occasionally other regions [CODE-BEAM].
- **GitHub activity (Elixir):** elixir-lang/elixir has 24,000+ stars as of early 2026 [ELIXIR-GH].
- **GitHub activity (OTP):** erlang/otp has 11,000+ stars as of early 2026 [OTP-GH].

### Primary Domains

**Erlang:** Telecommunications, messaging infrastructure, MQTT brokers, message queuing (RabbitMQ), financial transaction processing.

**Elixir:** Web applications (via Phoenix), real-time systems, IoT/embedded (via Nerves), data pipelines (Broadway), ML/AI infrastructure (Nx ecosystem).

---

## Technical Characteristics

### BEAM Virtual Machine

Both Erlang and Elixir compile to BEAM (Bogdan's Erlang Abstract Machine) bytecode, which executes inside the Erlang Runtime System (ERTS). ERTS is written in C and designed to be portable across platforms [BEAM-BOOK].

**Process model:**
- BEAM processes are not OS threads; they are lightweight (initial heap ~300 words; approximately 2,000× lighter than OS processes) [BEAM-VS-JVM]
- The BEAM runs one scheduler per CPU core (configurable); each scheduler preemptively schedules BEAM processes using a reduction-count mechanism (approximately 2,000 reductions per timeslice) [BEAM-BOOK]
- Processes share no memory; all communication is via message passing (copying data between process heaps) [BEAM-BOOK]
- On multicore systems, multiple schedulers run simultaneously providing true parallelism [BEAM-VS-JVM]

**JIT compiler (OTP 24+):** BeamAsm generates native machine code at load time (not at runtime profiling). Performance improvements measured against interpreter-only BEAM [BEAMJIT-BLOG]:
- ~50% more work per unit time on the estone synthetic benchmark suite
- 30–130% increase in iterations per second for JSON benchmarks (average ~70%)
- RabbitMQ: 30–50% more messages/second
- OTP 25 added type-based optimizations; OTP 26 improved binary-syntax code generation (Base64 encoding 4× faster, decoding 3× faster) [BEAMJIT-BLOG]

### Type System

**Erlang:** Dynamically typed. No static type annotations required. Type specifications (`-spec` and `-type` declarations) are optional metadata used by external tools, not enforced by the compiler [ERLANG-TYPESPEC].

**Dialyzer:** The primary static analysis tool, introduced in Erlang. Uses *success typing* — a conservative analysis that only reports errors guaranteed to be type violations; it never raises false positives by design [DIALYZER-LYSE]. "A type checker for a language like Erlang should work without type declarations being there, should be simple and readable, should adapt to the language (and not the other way around), and only complain on type errors that would guarantee a crash" [ERLANG-SOLUTIONS-TYPING].

**Gradual typing in Erlang:** EEP-0061 adds `dynamic/0` type to facilitate gradual typing; OTP 28 implements EEP 69 (Nominal Types) [EEP-0061] [OTP-28-HIGHLIGHTS].

**Elixir type system evolution:**
- v1.17.0 (June 2024): Set-theoretic type foundations; introduced union, intersection, and negation type composition [ELIXIR-117]
- v1.18.0 (December 2024): Type checking of function calls; broader type inference [ELIXIR-118]
- v1.19.0 (October 2025): Type inference of anonymous functions; compile-time warnings for type violations in protocols [ELIXIR-119]
- v1.20.0-rc (January 2026): Full type inference of all language constructs including cross-clause inference, enhanced map key tracking [ELIXIR-120]

The Elixir type system is based on set-theoretic subtyping with gradual typing. Types are composed with `or` (union), `and` (intersection), and `not` (negation). The system targets warnings at compile time without requiring annotations and without breaking existing code [ELIXIR-TYPES-PAPER].

**Academic basis:** The Elixir type system design is formalized in "The Design Principles of the Elixir Type System" (arXiv:2306.06391, 2023) by Castagna, Valim et al. [ELIXIR-TYPES-PAPER]. A related academic proposal is "Guard Analysis and Safe Erasure Gradual Typing: A Type System for Elixir" (arXiv:2408.14345, 2024) [ELIXIR-TYPES-GRADUAL].

### Memory Model

**Per-process heaps:** Each Erlang/Elixir process has its own private stack and heap allocated in the same memory block. The stack and heap grow toward each other; GC triggers when they meet [ERLANG-GC-DOC].

**Garbage collection strategy:** Per-process generational semi-space copying collector using Cheney's algorithm, plus a global large object space [ERLANG-GC-DOC]. Generations: young heap (frequently collected) and old heap (promoted survivors; collected less frequently) [ERLANG-GC-DETAILS].

**No stop-the-world pauses:** Because each process has its own GC, garbage collection of one process does not pause others. This provides soft real-time latency characteristics: GC pauses are bounded by the heap size of a single process, not the total application heap [ERLANG-GC-DETAILS].

**Large binaries:** Binaries larger than 64 bytes are stored in a shared binary heap (outside individual process heaps) and reference-counted. Smaller binaries (≤64 bytes) are stored inline on the process heap [ERLANG-GC-DOC].

**Message passing overhead:** Sending a message between processes involves copying the data (except for large binaries, which pass by reference with a copy of the reference). This means inter-process communication has memory allocation cost proportional to message size [BEAM-BOOK].

### Concurrency Model

**Actor model:** BEAM processes are actors: isolated, communicate only by message passing, spawned and destroyed dynamically [BEAM-VS-JVM]. Process creation is fast (microseconds) and processes are cheap (initial ~2 KB memory) [BEAM-BOOK].

**Absence of "function coloring":** All Erlang/Elixir functions are synchronous. The spawn family of functions runs synchronous functions in a new process context. There is no async/await distinction — all code reads sequentially; concurrency is expressed through process spawning and message passing [HN-COLORED]. "Erlang doesn't have function colors because every function is async" [HN-COLORED].

**OTP behaviors:** The OTP framework provides structured patterns [OTP-WIKI]:
- `gen_server`: Generic client/server interaction
- `gen_statem`: Generic finite state machine (replaces deprecated gen_fsm)
- `gen_event`: Generic event manager
- `supervisor`: Process lifecycle management with configurable restart strategies
- `application`: OTP application lifecycle

**Supervision trees:** Hierarchical supervisor trees monitor and restart child processes. Restart strategies include `:one_for_one` (restart only the failed child), `:one_for_all` (restart all children), and `:rest_for_one` (restart failed child and all started after it) [SUPERVISOR-OTP].

**Distribution:** Built-in distributed Erlang. Nodes communicate transparently; `Node.spawn/2` and remote process registration work the same as local equivalents [DIST-ERLANG]. Default topology is a fully meshed network (all nodes connected to all others); mesh scales to tens of nodes before connection count becomes problematic [DIST-GUIDE]. Libraries like libcluster and Horde provide Kubernetes-aware clustering and distributed process registration [DIST-GUIDE].

**Hot code loading:** The BEAM supports running two versions of any module simultaneously. Processes using old code continue to do so until they exit or explicitly request the new version; newly spawned processes use the updated module. State migration is handled by the `code_change/3` callback in `gen_server` [HOT-CODE]. Only 2 concurrent code versions per module are supported [HOT-CODE].

### Error Handling

**"Let it crash" philosophy:** Coined by Armstrong in his 2003 PhD thesis. The principle is to separate "normal code" from "recovery code" — let a process crash when it encounters an unexpected state, and let the supervisor handle restarting [ARMSTRONG-2003]. This is distinct from silently swallowing errors: crashes are always observed by linked processes or supervisors.

**Erlang error types:**
- Exceptions: `throw/1`, `error/1`, `exit/1` — caught with `try...catch...end`
- Exits: propagated to linked processes or caught by monitoring processes
- Errors: tagged with error class, reason, and stack trace

**Elixir error handling:**
- Exceptions via `raise/1` and `rescue`
- The `{:ok, value}` and `{:error, reason}` tuple convention (tagged-union idiom) for expected errors
- `with/1` special form for composing sequences of operations that may fail
- No mandatory checked exceptions; convention-based error propagation

**OTP 28 deprecation warning:** OTP 28 introduces a warning for using the old-style `catch Expr` syntax (which catches all exceptions and can hide bugs) in favor of `try...catch...end` [OTP-28-HIGHLIGHTS].

---

## Ecosystem Snapshot

### Package Management

**Hex.pm:** Shared package manager for the BEAM ecosystem, serving both Elixir (via Mix) and Erlang (via Rebar3 or erlang.mk) [HEX-ABOUT]. Hex provides the HTTP API, web interface, package repository, and HexDocs documentation hosting. Package statistics are available at hex.pm/packages [HEX-PM].

**Build tools:**
- **Mix** (Elixir): Project manager, build tool, test runner, dependency manager. Ships with Elixir.
- **Rebar3** (Erlang): Most widely used Erlang build tool; Hex integration via plugin [REBAR3-HEX].
- **erlang.mk** (Erlang): Alternative Makefile-based build system.

### Major Frameworks and Libraries

**Web:**
- **Phoenix Framework:** Primary Elixir web framework; Rails-inspired; includes Plug (middleware), Ecto (database ORM), and Phoenix LiveView [PHOENIX]. LiveView enables server-rendered real-time interactive UIs without client-side JavaScript. LiveView 1.1 released with colocated hooks and keyed comprehensions [LIVEVIEW-11].
- Phoenix is cited as the most admired web framework in Stack Overflow's 2025 Developer Survey [SO-2025].

**Data pipelines:**
- **GenStage:** Backpressure-aware producer/consumer pipeline library [DASHBIT-10YRS]
- **Broadway:** High-level data ingestion pipeline library built on GenStage; supports RabbitMQ, Google Cloud PubSub, Apache Kafka, and Amazon SQS producers [DASHBIT-10YRS]
- **Flow:** Parallel computation on unbounded data using GenStage [DASHBIT-10YRS]

**Machine learning / numerical computing:**
- **Nx (Numerical Elixir):** Multi-dimensional tensors library with multi-stage compilation to CPU and GPU (via XLA/MLIR backends) [NX-V01]. Analogous to NumPy.
- **Axon:** Neural network library built on Nx
- **Bumblebee:** Transformer model serving built on Nx; integrates HuggingFace models
- **Explorer:** DataFrames for Elixir (analogous to Pandas; uses Apache Arrow via Polars backend) [ELIXIR-ML-2024]
- **Scholar:** Traditional ML algorithms on Nx
- **Livebook:** Web-based interactive notebook (analogous to Jupyter); runs Elixir code [ELIXIR-ML-2024]
- As of 2024, Nx ported XLA bindings to MLIR [ELIXIR-ML-2024]

**IoT / Embedded:**
- **Nerves:** Embedded Linux platform for Elixir; produces minimal self-contained firmware images; handles OTA updates [NERVES]. Runs on Raspberry Pi, BeagleBone, and other Linux-capable ARM/x86 hardware.

**Databases:**
- **Ecto:** Database wrapper and query language; works with PostgreSQL, MySQL, SQLite, and others. Provides changesets (validation pipelines), associations, and composable queries.
- **Mnesia:** Distributed in-memory/on-disk database built into OTP. ACID-compliant, supports table locks and transactions across nodes. Used in RabbitMQ and WhatsApp.

### Testing Tooling

- **ExUnit** (Elixir): Built-in unit testing framework; async test support; doctests.
- **EUnit** (Erlang): Unit testing framework included in OTP.
- **Common Test** (Erlang): Integration and system testing framework included in OTP.
- **Dialyzer:** Static analysis for type errors (both Erlang and Elixir).
- **Credo:** Elixir static code analysis tool (style and anti-pattern checks).

### IDE and Editor Support

- **ElixirLS:** Language Server Protocol (LSP) implementation for Elixir; provides IDE features across VS Code, Vim, Emacs, and others. v1.18 added LSP listener API [ELIXIR-118].
- **Erlang LS:** LSP implementation for Erlang.
- **JetBrains IntelliJ IDEA:** Erlang and Elixir plugins available (community-maintained).
- **VS Code:** Primary editor for most Elixir developers per community surveys [ELIXIR-FORUM].

### Profiling and Debugging

- `:observer` (OTP): GUI for process tree visualization, memory inspection, live metrics — ships with OTP.
- **Recon** (Fred Hébert): Production-safe diagnostic library; introspects running systems without stopping processes.
- `:debugger` (OTP): GUI debugger for Erlang/Elixir.
- **ExProf** / `:eprof` / `:fprof` / `:cprof`: Various profiling tools with different overhead/accuracy trade-offs.

---

## Security Data

### CVE Overview

**CVE-2025-32433 (Critical — CVSS 10.0):** Unauthenticated Remote Code Execution in Erlang/OTP's SSH implementation. An unauthenticated attacker can send SSH connection protocol messages (codes ≥ 80) before authentication completes, achieving arbitrary code execution. Disclosed April 2025. Affects Erlang/OTP prior to OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20 [CVE-2025-32433]. Patches available in OTP-27.3.3, OTP-26.2.5.11, OTP-25.3.2.20.

**SSH KEX hardening bypass (2025):** In versions prior to OTP-27.3.4, OTP-26.2.5.12, and OTP-25.3.2.21, Erlang/OTP SSH fails to enforce strict KEX handshake hardening, allowing a Man-in-the-Middle attacker to inject optional messages during handshake [CVE-SSH-MITM].

**SSH resource exhaustion (2025):** Allocation of resources without limits or throttling in ssh_sftp modules; affects OTP 17.0 through OTP 28.0.3, fixed in OTP-27.3.4.3 and OTP-26.2.5.15 [CVE-SSH-RESOURCE].

**Historical:** Erlang/OTP 18.x contained a heap overflow in compiled regular expression generation [CVEDETAILS-ERLANG]. Erlang/OTP before OTP 18.0-rc1 did not properly check CBC padding bytes, enabling padding oracle attacks [CVEDETAILS-ERLANG].

### CVE Pattern Analysis

The most significant vulnerability class in Erlang/OTP has been the **SSH implementation** — the `ssh` application ships as part of OTP and is widely used to provide remote management interfaces for BEAM-based systems. The SSH vulnerabilities (2025) affected a very large attack surface because any system using the built-in SSH daemon with default configurations was vulnerable [CVE-2025-32433-UNIT42].

**Common vulnerability patterns in Erlang/Elixir:**
- SSH protocol implementation errors (SSH module, multiple CVEs 2025)
- Resource exhaustion without throttling limits (CWE-400)
- Improper input validation in protocol handling (CWE-20)
- Memory safety is not a concern: the BEAM's managed memory and process isolation prevent the buffer overflow and use-after-free classes common in C/C++

**Language-level mitigations:**
- No pointer arithmetic; no manual memory management
- No shared mutable state between processes; data races are structurally prevented
- Process isolation: a crash in one process cannot corrupt another process's memory
- The BEAM has no equivalent of C's buffer overflows or use-after-free vulnerabilities

**Elixir-specific security:**
- Ecto parameterized queries prevent SQL injection at the framework level
- Phoenix CSRF protection built in
- No native code execution path by default (NIFs must be explicitly added)

**Supply chain:** Hex.pm package signatures via hex registry signatures. Package ownership is individual-account-based; no organizational account requirement. The ecosystem is small enough that the supply chain risk surface is narrower than npm or PyPI, but dependency auditing tooling is less mature.

**NIF security risk:** Native Implemented Functions (NIFs) written in C run in the same OS process as the BEAM and bypass all BEAM safety guarantees. A NIF crash or memory corruption can bring down the entire VM. Dirty NIFs (introduced in OTP 17) run on separate scheduler threads and can be interrupted, reducing but not eliminating this risk [NIF-INTEROP].

---

## Developer Experience Data

### Survey Data

**Stack Overflow Developer Survey 2025 (49,000+ respondents):**
- Elixir used by 2.7% of respondents (up from 2.1% in 2024) [SO-2025]
- 3rd most admired language (66% of users want to continue using it) [SO-2025]
- Phoenix ranked as most admired web framework [SO-2025]

**Stack Overflow Developer Survey 2024 (65,000+ respondents):**
- Elixir used by 2.1% of respondents [SO-2024]

**Elixir-specific:** The "admired" metric (66%) indicates a high satisfaction-to-usage ratio: most developers who use Elixir want to continue. By comparison, many higher-adoption languages score lower on admiration.

### Salary Data (United States, 2025–2026)

- Average annual salary for Elixir developer: $116,759 [ZIPRECRUITER-ELIXIR]
- Senior Elixir developer average: $152,250 [SALARY-COM-ELIXIR]
- Startup-focused average: $127,000 [WELLFOUND-ELIXIR]
- Entry-level: ~$112,500; experienced: up to $166,400 [ZIPRECRUITER-ELIXIR]
- Remote positions average: $140,000 [ZIPRECRUITER-ELIXIR]

No systematic salary data for Erlang developers was found in major surveys; anecdotal reports suggest premium salaries due to scarcity of expertise.

### Learning Curve

Documented characteristics [ELIXIR-COMMUNITY]:
- Erlang's syntax (Prolog-derived) is widely reported as an initial barrier; Elixir's Ruby-influenced syntax is generally rated more accessible
- Functional programming paradigm (immutability, pattern matching, recursion instead of loops) represents a learning curve for developers from imperative backgrounds
- The OTP framework (GenServer, Supervisor, application structure) is the primary intermediate-level learning challenge; understanding supervision trees and process design requires paradigm shift
- Pattern matching is consistently cited as a productivity advantage after the learning curve
- Elixir's `with/1` macro and pipe operator `|>` are praised for readable sequential code
- Error messages in Elixir improved significantly in v1.14+ with data-flow tracing in compiler diagnostics

---

## Performance Data

### Concurrency and Latency

**BEAM vs. JVM comparison:** In low-concurrency settings, both perform similarly; under high concurrency (thousands of concurrent connections), the BEAM maintains stable latency while JVM-based applications experience increased variance and instability [ERLANG-VS-JAVA]. Java 21 virtual threads share similarities with BEAM processes but were introduced decades later [ERLANG-VS-JAVA].

**Throughput comparison:** Go delivers 2–3× faster execution than BEAM for CPU-intensive computational tasks [INDEX-DEV-COMPARISON]. BEAM languages outperform in concurrent connection handling and predictable latency under high load [INDEX-DEV-COMPARISON].

**WhatsApp scale data:** 2 million simultaneous TCP connections per Erlang server achieved in 2014 [WHATSAPP-HIGHSCAL]. This required kernel parameter tuning (file descriptors, socket buffers) on FreeBSD [WHATSAPP-HIGHSCAL]. Each connection managed by a dedicated Erlang process requiring kilobytes of RAM.

**Discord scale data (2020):** 5 million concurrent users handled by 400–500 Elixir nodes with a 5-person team [DISCORD-ELIXIR].

### JIT Performance (OTP 24+)

BeamAsm (the BEAM JIT compiler, introduced OTP 24):
- estone benchmark suite: ~50% more operations per unit time vs. interpreter [BEAMJIT-BLOG]
- Pattern matching operations: 170% improvement in estone [BEAMJIT-BLOG]
- RabbitMQ message throughput: 30–50% improvement [BEAMJIT-BLOG]
- JSON benchmarks: 30–130% improvement (average ~70%) [BEAMJIT-BLOG]
- OTP 25 type-based optimizations: integer arithmetic without overflow checks where types are known [BEAMJIT-BLOG]
- OTP 26 binary encoding: Base64 encoding 4×, decoding 3× faster [BEAMJIT-BLOG]
- Message-passing-heavy workloads show minimal JIT benefit [BEAMJIT-BLOG]

### Computer Language Benchmarks Game

The Computer Language Benchmarks Game (benchmarksgame-team.pages.debian.net) includes Erlang entries. BEAM languages are not competitive with C, C++, or Rust for CPU-intensive algorithmic work. They occupy a middle tier, typically 5–20× slower than optimized C for compute-bound benchmarks [BENCHMARKS-GAME]. However, BEAM benchmarks are not representative of production workloads, which are heavily I/O-bound and concurrent.

### Compilation Speed

- Erlang: fast compilation; the BEAM compiler is lightweight and compiles modules independently
- Elixir: v1.19 delivered up to 4× faster compilation for large projects [ELIXIR-119]; v1.20 adds a further 2× speedup [ELIXIR-120]
- Elixir v1.20 compiles with the type checker enabled with minimal overhead above baseline [ELIXIR-120]

### Startup Time

BEAM applications start in milliseconds for small projects. OTP applications with many dependencies may take 1–3 seconds to start. BEAM is not a serverless-friendly runtime due to lack of extremely fast cold starts compared to languages with small binaries (Go, Rust). Releases (Elixir `mix release`) include the full BEAM runtime and are self-contained but large.

---

## Governance

### Erlang Governance

**Decision-making structure:** Ericsson's OTP Product Unit retains primary control of the Erlang/OTP codebase. The OTP unit, headed by Kenneth Lundin as of last documented reporting, is responsible for releases and core decisions [OTP-GOVERNANCE]. This is a corporate-controlled model with community input.

**Erlang Enhancement Proposals (EEPs):** Modeled on Python's PEP process. EEPs are design documents proposing new features or process changes. The EEP author is responsible for building community consensus; final acceptance requires both community approval and a working reference implementation. EEPs are maintained in a GitHub repository (github.com/erlang/eep) [EEP-0001].

**Erlang Ecosystem Foundation (EEF):** A 501(c)(3) non-profit organization, launched in 2019 at Code BEAM SF. Over 1,000 members. Backed by Ericsson, Cisco, Erlang Solutions, and other companies. Sponsors working groups in documentation, interoperability, security, and performance [EEF-ORG]. The EEF does not control OTP releases; it supports the broader ecosystem.

**Funding:** Ericsson funds OTP development directly. EEF receives sponsorship from member companies. Erlang Solutions is a primary commercial consulting and training company for the ecosystem.

**Backward compatibility policy:** Erlang has a strong backward compatibility tradition. The `deprecated` mechanism gives advance warning before removal. OTP 28 introduced the first formalized deprecation warning for the `catch Expr` syntax (present since Erlang's creation) [OTP-28-HIGHLIGHTS].

**Standardization:** Erlang is not an ISO or ECMA standard. There is no external standards body. The OTP Unit at Ericsson is the de facto standard authority.

**License:** Apache License 2.0 (since OTP 18.0, May 2015) [ERLANG-APACHE].

### Elixir Governance

**Decision-making structure:** José Valim is the Benevolent Dictator For Life (BDFL) of Elixir. Dashbit (Valim's current company, co-founded after Plataformatec closed in 2021) employs core contributors [DASHBIT-10YRS].

**Core team:** Elixir has a small core team; contributions via GitHub pull requests and Elixir Forum discussions. No formal RFC/EEP process, but significant features are discussed publicly on the Elixir Forum before implementation.

**Elixir Foundation:** No separate foundation exists for Elixir. The EEF serves the broader BEAM ecosystem and includes Elixir.

**Backward compatibility policy:** Elixir follows semantic versioning. Breaking changes are introduced only in major versions; the language has been in v1.x since 2014. The type system is being introduced with explicit backwards-compatibility guarantees: existing code runs unchanged, and warnings are emitted rather than errors for type violations (graduated adoption).

**Release schedule:** Minor release every 6 months; patch releases on demand [ELIXIR-ENDOFLIFE].

**License:** Apache License 2.0 [ELIXIR-WIKI].

---

## References

[ARMSTRONG-2007] Armstrong, J. "A History of Erlang." Proceedings of the Third ACM SIGPLAN Conference on History of Programming Languages (HOPL III), 2007. https://dl.acm.org/doi/10.1145/1238844.1238850

[ARMSTRONG-2003] Armstrong, J. "Making Reliable Distributed Systems in the Presence of Software Errors." PhD Thesis, Royal Institute of Technology (KTH), Stockholm, 2003.

[ERLANG-FAQ] "Erlang — Academic and Historical Questions." erlang.org. https://www.erlang.org/faq/academic.html

[ERLANG-WIKI] "Erlang (programming language)." Wikipedia. https://en.wikipedia.org/wiki/Erlang_(programming_language)

[ERLANG-OSS] "Open Source Erlang Story." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/twenty-years-of-open-source-erlang/

[ERLANG-OSS-20YRS] "20 years of open source Erlang: The OpenErlang Parties." Erlang Solutions, Medium. https://erlangsolutions.medium.com/20-years-of-open-source-erlang-the-openerlang-parties-2ae50d3f932c

[ERLANG-APACHE] "Erlang/OTP 18.0 released under Apache 2.0." erlang.org. Referenced in erlang.org/news and Erlang OTP release notes.

[ERLANG-OTP-17YRS] "Erlang/OTP - 17 Years of Open Source." erlang.org. https://www.erlang.org/news/96

[OTP-WIKI] "Open Telecom Platform." Wikipedia. https://en.wikipedia.org/wiki/Open_Telecom_Platform

[ELIXIR-WIKI] "Elixir (programming language)." Wikipedia. https://en.wikipedia.org/wiki/Elixir_(programming_language)

[ELIXIR-HISTORY] "The Story of Elixir." osshistory.org. https://osshistory.org/p/elixir

[VALIM-INTERVIEW] "An Interview with Elixir Creator José Valim." SitePoint, 2013. https://www.sitepoint.com/an-interview-with-elixir-creator-jose-valim/

[VALIM-SITEPOINT] Same as [VALIM-INTERVIEW].

[OTP-27-2] "Erlang/OTP 27.2 Release." erlang.org, December 11, 2024. https://www.erlang.org/news/172

[OTP-28-HIGHLIGHTS] "Erlang/OTP 28 Highlights." erlang.org, May 20, 2025. https://www.erlang.org/blog/highlights-otp-28/

[OTP-28-RELEASES] GitHub Releases for erlang/otp. https://github.com/erlang/otp/releases

[EEP-0001] "Erlang Enhancement Proposal 0001: EEP Purpose and Guidelines." erlang.org. https://www.erlang.org/eeps/eep-0001.html

[EEP-0061] "EEP 61: Gradual Types — dynamic/0." erlang.org. https://www.erlang.org/eeps/eep-0061

[ERLANG-TYPESPEC] "Types and Function Specifications." Erlang System Documentation. https://www.erlang.org/doc/system/typespec.html

[DIALYZER-LYSE] Hébert, F. "Type Specifications and Erlang." Learn You Some Erlang. https://learnyousomeerlang.com/dialyzer

[ERLANG-SOLUTIONS-TYPING] "Type-checking Erlang and Elixir." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/type-checking-erlang-and-elixir/

[ELIXIR-117] "Elixir v1.17 released: set-theoretic data types, calendar durations, and Erlang/OTP 27 support." elixir-lang.org, June 12, 2024. https://elixir-lang.org/blog/2024/06/12/elixir-v1-17-0-released/

[ELIXIR-118] "Elixir v1.18 released: type checking of calls, LSP listeners, built-in JSON, and more." elixir-lang.org, December 19, 2024. http://elixir-lang.org/blog/2024/12/19/elixir-v1-18-0-released/

[ELIXIR-119] "Elixir v1.19 released: enhanced type checking and up to 4x faster compilation for large projects." elixir-lang.org, October 16, 2025. http://elixir-lang.org/blog/2025/10/16/elixir-v1-19-0-released/

[ELIXIR-120] "Elixir v1.20.0-rc: type inference of all constructs." Elixir Forum, January 2026. https://elixirforum.com/t/elixir-v1-20-0-rc-0-and-rc-1-released-type-inference-of-all-constructs/73927; "Type inference of all constructs and the next 15 months." elixir-lang.org, January 9, 2026. http://elixir-lang.org/blog/2026/01/09/type-inference-of-all-and-next-15/

[ELIXIR-ENDOFLIFE] "Elixir." endoflife.date. https://endoflife.date/elixir

[ELIXIR-TYPES-PAPER] Castagna, G., Valim, J., et al. "The Design Principles of the Elixir Type System." arXiv:2306.06391, 2023. https://arxiv.org/pdf/2306.06391

[ELIXIR-TYPES-GRADUAL] "Guard Analysis and Safe Erasure Gradual Typing: A Type System for Elixir." arXiv:2408.14345, 2024. https://arxiv.org/abs/2408.14345

[BEAM-BOOK] Stenmans, E. "The BEAM Book: Understanding the Erlang Runtime System." https://blog.stenmans.org/theBeamBook/

[BEAM-VS-JVM] "Optimising for Concurrency: Comparing and Contrasting the BEAM and JVM Virtual Machines." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/optimising-for-concurrency-comparing-and-contrasting-the-beam-and-jvm-virtual-machines/

[ERLANG-GC-DOC] "Erlang Garbage Collector." Erlang System Documentation. https://www.erlang.org/doc/apps/erts/garbagecollection

[ERLANG-GC-DETAILS] Soleimani, H. "Erlang Garbage Collection Details and Why It Matters." 2015. https://hamidreza-s.github.io/erlang%20garbage%20collection%20memory%20layout%20soft%20realtime/2015/08/24/erlang-garbage-collection-details-and-why-it-matters.html

[BEAMJIT-BLOG] "Performance testing the JIT compiler for the BEAM VM." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/performance-testing-the-jit-compiler-for-the-beam-vm/; "The Road to the JIT." erlang.org blog. https://www.erlang.org/blog/the-road-to-the-jit/

[SO-2025] "Technology — 2025 Stack Overflow Developer Survey." Stack Overflow. https://survey.stackoverflow.co/2025/technology

[SO-2024] "Stack Overflow Developer Survey 2024." Stack Overflow. https://survey.stackoverflow.co/2024/

[DISCORD-ELIXIR] DeBenedetto, S. "Real time communication at scale with Elixir at Discord." elixir-lang.org blog, October 8, 2020. http://elixir-lang.org/blog/2020/10/08/real-time-communication-at-scale-with-elixir-at-discord/

[WHATSAPP-1M-BLOG] "1 million is so 2011." WhatsApp Blog. https://blog.whatsapp.com/1-million-is-so-2011

[WHATSAPP-SCALE] "How WhatsApp Grew to Nearly 500 Million Users, 11,000 cores, and 70 Million Messages a Second." High Scalability. https://highscalability.com/how-whatsapp-grew-to-nearly-500-million-users-11000-cores-an/

[WHATSAPP-HIGHSCAL] Same as [WHATSAPP-SCALE].

[ERLANG-FINTECH] "Erlang and Elixir in FinTech: 4 use cases." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/erlang-elixir-in-fintech-use-cases/

[EEF-SPONSORSHIP] "EMQ announces official sponsorship of the Erlang Ecosystem Foundation (EEF)." emqx.com. https://www.emqx.com/en/news/emq-announces-official-sponsorship-of-the-erlang-ecosystem-foundation

[EEF-ORG] "Erlang Ecosystem Foundation." erlef.org. https://erlef.org/

[CURIOSUM-ADOPTION] "Elixir Production Adoption: Top Companies Case Studies." Curiosum. https://www.curiosum.com/blog/adoption-of-elixir-by-top-companies

[PHOENIX] Phoenix Framework. https://www.phoenixframework.org/

[PHOENIX-HISTORY] Referenced in [DASHBIT-10YRS].

[LIVEVIEW-11] "LiveView 1.1." Phoenix Framework blog. Referenced in Elixir community sources.

[DASHBIT-10YRS] Valim, J. "10 years(-ish) of Elixir." Dashbit Blog. https://dashbit.co/blog/ten-years-ish-of-elixir

[NERVES] Nerves Project. https://nerves-project.org/

[NX-V01] "Elixir and Machine Learning: Nx v0.1 released!" Dashbit Blog. https://dashbit.co/blog/elixir-and-machine-learning-nx-v0.1

[ELIXIR-ML-2024] Valim, J. "Elixir and Machine Learning in 2024 so far: MLIR, Apache Arrow, structured LLM, and more." Dashbit Blog, June 2024. https://dashbit.co/blog/elixir-ml-s1-2024-mlir-arrow-instructor

[HEX-PM] "Hex — A package manager for the Erlang ecosystem." hex.pm. https://hex.pm/

[HEX-ABOUT] "About Hex." hex.pm. https://hex.pm/about

[REBAR3-HEX] "Hex Package Management." Rebar3 Documentation. https://www.rebar3.org/docs/package_management/

[CVE-2025-32433] "CVE-2025-32433: Unauthenticated Remote Code Execution in Erlang/OTP SSH." GHSA-37cp-fgq5-7wc2. https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2

[CVE-2025-32433-UNIT42] "Keys to the Kingdom: Erlang/OTP SSH Vulnerability Analysis and Exploits Observed in the Wild." Palo Alto Unit 42. https://unit42.paloaltonetworks.com/erlang-otp-cve-2025-32433/

[CVE-SSH-MITM] Erlang OTP SSH KEX hardening bypass. cvedetails.com. https://www.cvedetails.com/product/20874/Erlang-Erlang-otp.html?vendor_id=9446

[CVE-SSH-RESOURCE] Erlang OTP SSH resource exhaustion. cvedetails.com. Same URL as above.

[CVEDETAILS-ERLANG] "Erlang: Security vulnerabilities." cvedetails.com. https://www.cvedetails.com/vulnerability-list/vendor_id-9446/Erlang.html

[NIF-INTEROP] "Using C from Elixir with NIFs." Leopardi, A. https://andrealeopardi.com/posts/using-c-from-elixir-with-nifs/; "Interoperability in 2025: beyond the Erlang VM." elixir-lang.org, August 2025. http://elixir-lang.org/blog/2025/08/18/interop-and-portability/

[HOT-CODE] "A Guide to Hot Code Reloading in Elixir." AppSignal Blog. https://blog.appsignal.com/2021/07/27/a-guide-to-hot-code-reloading-in-elixir.html

[DIST-ERLANG] "Distributed Erlang." Erlang System Documentation. https://www.erlang.org/doc/system/distributed.html

[DIST-GUIDE] "Distributed Elixir (Erlang) Guide." monkeyvault.net. https://www.monkeyvault.net/distributed-elixir-erlang-guide/

[SUPERVISOR-OTP] "Supervisor." Erlang OTP Documentation. Referenced in OTP application documentation.

[HN-COLORED] Hacker News discussion on function coloring in Erlang. https://news.ycombinator.com/item?id=28914506

[INDEX-DEV-COMPARISON] "Erlang vs Elixir vs Go for Backend Development | Performance & Comparison 2026." index.dev. https://www.index.dev/skill-vs-skill/backend-elixir-vs-erlang-vs-go

[ERLANG-VS-JAVA] "Comparing Elixir vs Java." Erlang Solutions Blog. https://www.erlang-solutions.com/blog/comparing-elixir-vs-java/

[BENCHMARKS-GAME] "Computer Language Benchmarks Game." benchmarksgame-team.pages.debian.net. https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html

[OTP-GOVERNANCE] "Erlang/OTP - 17 Years of Open Source." erlang.org. https://www.erlang.org/news/96

[TIOBE-2026] "TIOBE Index." tiobe.com. https://www.tiobe.com/tiobe-index/ [accessed March 2026]

[ELIXIR-GH] "elixir-lang/elixir." GitHub. https://github.com/elixir-lang/elixir

[OTP-GH] "erlang/otp." GitHub. https://github.com/erlang/otp

[WILLIAMS-TALK] Williams, M. "The True story about why we open-sourced Erlang." Erlang Factory presentation. https://www.erlang-factory.com/upload/presentations/416/MikeWilliams.pdf

[ERLANG-SO-ABSENCE] Stack Overflow Developer Surveys 2024–2025 (Erlang not in top-category breakdowns). https://survey.stackoverflow.co/2024/ and https://survey.stackoverflow.co/2025/

[ZIPRECRUITER-ELIXIR] "Salary: Elixir Developer (February 2026) United States." ZipRecruiter. https://www.ziprecruiter.com/Salaries/Elixir-Developer-Salary

[SALARY-COM-ELIXIR] "Sr Elixir Developer Salary (February 2026)." Salary.com. https://www.salary.com/research/salary/opening/sr-elixir-developer-salary

[WELLFOUND-ELIXIR] "Elixir Developer Salary and Equity Compensation in Startups 2025." Wellfound. https://wellfound.com/hiring-data/s/elixir-1

[CODE-BEAM] Code BEAM conference series. https://codebeameurope.com/

[ELIXIR-FORUM] Elixir Programming Language Forum. https://elixirforum.com/

[ERLANG-FORUM] Erlang Programming Language Forum. https://erlangforums.com/

[FLY-ELIXIR] Fly.io uses Elixir. Referenced in various community sources including curiosum.com/blog/adoption-of-elixir-by-top-companies.

[ELIXIR-COMMUNITY] General community experience and learning curve characteristics. Referenced across multiple community blog posts and Elixir Forum discussions.
