# Haskell — Research Brief

```yaml
role: researcher
language: "Haskell"
agent: "claude-agent"
date: "2026-02-28"
```

---

## Language Fundamentals

### Creation and Institutional Context

Haskell emerged from a committee formed at the conference on Functional Programming Languages and Computer Architecture (FPCA '87) in Portland, Oregon, in September 1987. The impetus was fragmentation: over a dozen non-strict, purely functional programming languages existed — notably Miranda, Hope, and several ML dialects — without a common standard, which was seen as impeding wider adoption of the paradigm [HASKELL-98-PREFACE].

The founding committee comprised fifteen members from universities in the United States, the United Kingdom, and Sweden: Paul Hudak (Yale University), Philip Wadler (University of Glasgow), Arvind (MIT), Brian Boutel (Victoria University of Wellington), Jon Fairbairn (University of Cambridge), Joseph Fasel (Los Alamos National Laboratory), Kevin Hammond (University of Glasgow), John Hughes (Chalmers University of Technology), Thomas Johnsson (Chalmers), Dick Kieburtz (OGI), Rishiyur Nikhil (MIT), Simon Peyton Jones (University of Glasgow), Mike Reeve (Imperial College), David Wise (Indiana University), and Jonathan Young (Yale) [HISTORY-HUDAK-2007].

The language is named after logician Haskell Brooks Curry (1900–1982), whose work on combinatory logic and the Curry–Howard correspondence provides theoretical underpinnings for functional programming [HASKELL-98-PREFACE].

Miranda, the most widely used of the predecessor languages, was proprietary software from Research Software Ltd. The committee's choice to create an open standard addressed this directly. Three initial meetings established the project: September 1987 (Portland), December 1987 (University College London), and January 1988 (Yale University) [HISTORY-SEROKELL].

### Stated Design Goals

From the Haskell 98 Report preface, the committee established five constraints the language must satisfy [HASKELL-98-PREFACE]:

1. "It should be suitable for teaching, research, and applications, including building large systems."
2. "It should be completely described via the publication of a formal syntax and semantics."
3. "It should be freely available. Anyone should be permitted to implement the language and distribute it to whomever they please."
4. "It should be based on ideas that enjoy a wide consensus."
5. "It should reduce unnecessary diversity in functional programming languages."

The committee identified the main motivating concern as follows: "More widespread use of this class of functional languages was being hampered by the lack of a common language. It was decided that a committee should be formed to design such a language, providing faster communication of new ideas, a stable foundation for real applications development, and a vehicle through which others would be encouraged to use functional languages." [HASKELL-98-PREFACE]

### Language Classification

- **Paradigm(s)**: Purely functional (all computation expressed as evaluation of expressions; no statements); non-strict (lazy by default — expressions not evaluated until their values are required)
- **Typing discipline**: Static, strong, with full Hindley-Milner type inference; extended by GHC with higher-kinded types, type classes, GADTs, type families, rank-N polymorphism, DataKinds, and more
- **Memory management**: Garbage collected; GHC uses generational GC (allocations in a ~512KB nursery; minor GC scans nursery; major GC traverses older generations) [GHC-RTS-EZYANG]
- **Compilation model**: Primarily compiled via GHC to native machine code (via an intermediate C-- representation) or LLVM IR; also supports JavaScript and WebAssembly backends (GHC 9.6+); interpreted via GHCi (REPL/interpreter)
- **Purity enforcement**: Side effects tracked at the type level via the `IO` monad; pure functions cannot perform I/O or mutation without type-level annotation [HASKELL-WIKI-IO]

### Current Stable Version (as of February 2026)

- **GHC 9.14.1**: Released December 19, 2025 — the first GHC Long-Term Support (LTS) release under the new LTS policy [ENDOFLIFE-GHC]
- **GHC 9.12.3**: Released December 27, 2025 — current non-LTS stable release
- The GHC LTS policy (introduced with 9.14): minimum two years of support, bugfix minor releases only, no new features backported [ENDOFLIFE-GHC]
- Release cadence: approximately two major releases per year

---

## Historical Timeline

### Pre-Release and First Reports (1987–1992)

- **September 1987**: Founding committee formed at FPCA '87, Portland, Oregon [HASKELL-98-PREFACE]
- **December 1987**: Subgroup meeting, University College London
- **January 1988**: Multi-day committee meeting at Yale University
- **April 1, 1990**: Haskell 1.0 Report published — the first definition of the language [HISTORY-SEROKELL]
- **1991**: Haskell 1.1 Report; Haskell 1.2 in March 1992; appeared in SIGPLAN Notices accompanied by Hudak and Fasel's "Gentle Introduction to Haskell" [HISTORY-SEROKELL]
- **1992**: Simon Peyton Jones announces GHC version 0.10 — the Glasgow Haskell Compiler's first public release [HISTORY-SEROKELL]; type classes had been introduced as part of the language design (originally proposed by Philip Wadler and Stephen Blott as a principled solution to operator overloading) [TYPECLASS-WIKIPEDIA]

### Haskell 1.3 and the Monadic I/O Turn (1996)

- **May 1996**: Haskell 1.3 Report published, edited by Hammond and Peterson. This version introduced monadic I/O with `do` notation syntax, generalized type classes, standard library support, and extended algebraic data types [HISTORY-SEROKELL]. The shift from stream-based I/O to monadic I/O (via Wadler's formulation of monads for functional programming) was a major inflection point in the language's design.

### Haskell 98 Stabilization (1997–2002)

- **1997**: At the Haskell Workshop in Amsterdam, the committee decided a stable, named variant was needed — "Haskell 98" — to serve as a reference for teaching and implementations [HASKELL-WIKI-2010]
- **February 1999**: Haskell 98 standard originally published as *The Haskell 98 Report* [HASKELL-WIKI-2010]
- **2002**: Minor bugs fixed; *Revised Haskell 98 Report* released [HASKELL-WIKI-2010]

### The GHC Extension Era (2000–2009)

During this period, GHC accumulated language extensions well beyond Haskell 98: type families (2005), GADTs, Template Haskell (compile-time metaprogramming), and multi-parameter type classes. Software Transactional Memory (STM) was implemented in GHC 6.4 [HASKELL-WIKI-STM]. The community operated largely on GHC extensions rather than standardized language features.

### Haskell 2010 and the Modular Standard (2009–2010)

- **November 24, 2009**: Haskell 2010 announced [HASKELL-WIKI-2010]
- **July 2010**: Haskell 2010 Language Report published — the last formal language specification as of February 2026. Notable additions: the Foreign Function Interface (FFI), hierarchical module organization, and pattern guards [HASKELL-WIKI-2010]. The committee adopted an explicitly incremental approach: "a single monolithic revision of the language was too large a task, and the best way to make progress was to evolve the language in small incremental steps" [HASKELL-WIKI-2010]

### Haskell Foundation and Governance Reform (2020–present)

- **November 2020**: Haskell Foundation founded as a nonprofit — "to advance the Haskell programming language, related tools, education, and research by broadening understanding of Haskell's benefits, increasing adoption, and eliminating barriers to use" [HF-WHITEPAPER]
- **2024–2025**: Haskell.org Committee and Haskell Foundation directors announced a merger into a single nonprofit corporation [HF-GOVERNANCE]

### GHC 9.x Series: Major Features by Version

| GHC Version | Release Date | Key Introductions |
|-------------|--------------|-------------------|
| 9.0.1 | December 2020 | Linear types (experimental, `LinearTypes` extension) |
| 9.2.1 | October 2021 | GHC2021 language edition; RecordDotSyntax; AArch64 native code generator; BoxedRep/UnliftedDataTypes |
| 9.4.1 | August 2022 | Structured diagnostic API (IDE support improvement); tag-check elision optimization; improved CPR analysis |
| 9.6.1 | March 2023 | WebAssembly backend (wasm32-wasi); JavaScript backend; TypeData extension; GADT record update support |
| 9.8.1 | October 2023 | TypeAbstractions (preliminary); ExtendedLiterals; GHC.TypeError.Unsatisfiable; export deprecation |
| 9.10.1 | May 2024 | GHC2024 language edition; VisibleForall (partial) |
| 9.12.1 | December 2024 | OrPatterns; MultilineStrings; NamedDefaults generalization |
| 9.14.1 | December 2025 | First LTS release; specialization improvements |

[Sources: GHC release notes per version; ENDOFLIFE-GHC; GHC-9.6-NOTES; GHC-9.2-FEATURES]

### Language Editions (Dialect Standardization)

- **Haskell98**: Original stable standard
- **Haskell2010**: Last formal spec (July 2010); added FFI, hierarchical modules, pattern guards
- **GHC2021**: Introduced with GHC 9.2.1 (October 2021); not a formal language standard but a curated set of stable, widely-used GHC extensions beyond Haskell2010 (EmptyCase, TupleSections, RankNTypes, TypeApplications, PolyKinds, etc.); currently the GHC default if no edition specified [GHC-EXTENSIONS-CTRL]
- **GHC2024**: Introduced with GHC 9.10 (2024); adds DataKinds, DerivingStrategies, GADTs (with implied MonoLocalBinds), LambdaCase, RoleAnnotations to GHC2021 [GHC-2024-PROPOSAL]

### Proposed and Rejected/Deferred Features

- **Haskell2020 standardization effort**: Announced in 2015–2016, never completed; stalled over scope disagreements [HASKELL202X-DEAD]
- **Dependent types**: Under active development by Serokell-funded GHC team since 2018; described as an "unclear" timeline; polishing existing type-level programming features is a prerequisite [DH-ROADMAP]
- **Full linear types**: Shipped experimentally in GHC 9.0 (2020); described as "expect bugs, warts, and bad error messages; everything down to the syntax is subject to change" as of the GHC documentation [GHC-LINEAR-TYPES]

---

## Adoption and Usage

### Market Share and Language Rankings

- **Stack Overflow Developer Survey 2025** (49,000+ respondents): Haskell appears only in "write-ins" with **0.1% "Have Used"** and **0.1% "Want to Use"** — below the threshold for inclusion in the main language ranking table [SO-SURVEY-2025]
- **Stack Overflow Developer Survey 2024**: Similar — not listed in primary rankings (JavaScript 62%, Python 51%, TypeScript 38% were top languages) [SO-SURVEY-2024]
- **TIOBE Index**: Historically fluctuating around 20th–30th place; TIOBE November 2024 headline asked "Is Haskell finally going to hit the top 20?" — indicating it remained below [TIOBE-NOV-2024]
- **JetBrains State of Developer Ecosystem 2024–2025**: No dedicated Haskell data published

### State of Haskell Surveys (Community-Specific)

The annual State of Haskell Survey, run from 2017 through 2022 (six editions), ceased after 2022 and was revived in 2025 [STATEOFHASKELL-2025]. The 2022 survey (the most recent with published results) had:

- **Total respondents**: 1,038 (down 9% from 2021's 1,152) [HASKELL-SURVEY-2022]
- **Active users**: 85% (879 respondents currently use Haskell)
- **Former users**: 12% (121)
- **Professional usage**: 33% use Haskell at work "most of the time"; 16% "some of the time"; 36% "would like to use at work" [HASKELL-SURVEY-2022]
- **Industry use**: Web 20%, Academia 17%, Banking/Finance 13%, Education 11% [HASKELL-SURVEY-2022]
- **Home vs. work**: 76% home use; 49% industry; 18% academia [HASKELL-SURVEY-2022]

### Primary Domains and Industries

Haskell sees documented production use in:

- **Financial services and banking**: Standard Chartered's proprietary Mu dialect (a strict variant of Haskell) powers trading and quantitative analysis tools; the codebase contains at least 5 million lines of Mu code and 1 million lines of Haskell code [SEROKELL-SC]
- **Anti-abuse and trust-and-safety at scale**: Meta's Sigma system processes over 1 million requests per second and is implemented in Haskell [SEROKELL-META]
- **Code analysis infrastructure**: GitHub's Semantic (code analysis tool); Meta's Glean (code-fact indexing system) [SEROKELL-TOP11]
- **Data fetching frameworks**: Meta's Haxl library, a framework for efficient and concise data fetching [SEROKELL-META]
- **Cross-platform serialization**: Microsoft Bond framework [SEROKELL-TOP11]
- **Blockchain and smart contracts**: IOHK / IOG (the company behind the Cardano blockchain) sponsors significant Haskell development; Plutus (the Cardano smart contract language) is embedded in Haskell [HF-WHITEPAPER]
- **Compiler and formal methods tooling**: Niche but documented use at language research groups

The GitHub repository [`erkmos/haskell-companies`](https://github.com/erkmos/haskell-companies) maintains a curated list; the commercially-oriented [`commercialhaskell/commercialhaskell`](https://github.com/commercialhaskell/commercialhaskell) repository serves as a special-interest group [GITHUB-HASKELL-COMPANIES].

### Community Size Indicators

- **Hackage**: The central package registry has been online since January 2007 and contains tens of thousands of packages; exact current count unavailable from public-facing statistics pages as of February 2026 [HACKAGE]
- **State of Haskell 2022**: Survey respondents use Reddit (51%), GitHub (50%), Twitter (23%), Stack Overflow (21%) as primary community channels [HASKELL-SURVEY-2022]
- **GHC Steering Committee proposals**: The `ghc-proposals` GitHub repository is the primary venue for language change proposals; formed 2017 [GHC-PROPOSALS-REPO]
- **Conference ecosystem**: ZuriHac (annual, Zurich), Haskell Symposium (co-located with ICFP), Compose Conference, Haskell eXchange (London)

---

## Technical Characteristics

### Type System

Haskell's type system is based on the Hindley–Milner (HM) algorithm, which infers the most general type of an expression without requiring explicit annotations. Key properties:

- **Complete type inference** within the HM fragment: well-typed programs can be compiled without any type annotations (though annotations are considered good practice)
- **Type classes**: A mechanism for principled overloading, originally proposed by Wadler and Blott and introduced in early Haskell versions [TYPECLASS-WIKIPEDIA]. Type classes define a set of operations; types become instances of a class. Standard classes: `Eq`, `Ord`, `Show`, `Functor`, `Monad`, `Foldable`, `Traversable`, etc.
- **Algebraic data types (ADTs)**: Sum types (enumerations/tagged unions), product types (records), and recursive types are first-class constructs
- **Parametric polymorphism**: Generic functions quantified over type variables
- **Higher-kinded types**: Types parameterized by other types (e.g., `Functor f` where `f :: * -> *`); this enables abstractions like `Monad`, `Applicative`, and `Foldable` to be expressed generically [SEROKELL-HKT]

GHC extends HM with a large optional extension ecosystem:

| Extension | Description |
|-----------|-------------|
| `GADTs` | Generalized Algebraic Data Types — constructors can specify their return type precisely |
| `TypeFamilies` | Type-level functions mapping types to types |
| `RankNTypes` | Higher-rank polymorphism — functions that take polymorphic arguments |
| `DataKinds` | Promotes data constructors to the kind level, enabling richer type-level programming |
| `PolyKinds` | Kind polymorphism |
| `TypeApplications` | Explicit type arguments at call sites |
| `LinearTypes` | Functions that consume their argument exactly once (GHC 9.0+, experimental) |
| `TemplateHaskell` | Compile-time metaprogramming and code generation |
| `FunctionalDependencies` | Specifies dependencies between type class parameters |

[Source: GHC User's Guide, various versions; GHC-EXTENSIONS-CTRL]

**Escape hatches**: `unsafeCoerce` (re-type any value); FFI `unsafe` imports (bypass GHC's safety checks); `unsafePerformIO` (execute IO in a "pure" context — explicitly marked as unsafe but usable) [UNSAFE-HASKELL-PENN].

**Dependent types**: Not yet in Haskell as of February 2026; under active development. A workaround using singletons (a design pattern) exists but is considered verbose [DH-ROADMAP].

### Memory Model

GHC uses an automatically managed heap with generational garbage collection [GHC-MEMORY-WIKI]:

- **Nursery**: ~512KB allocation area for new objects; undergoes "minor GC" frequently
- **Generations**: Objects surviving minor GC are promoted to older generations, which are collected less often
- **Thunks**: Unevaluated expressions (closures) are heap-allocated objects; a key consequence of lazy evaluation is that a chain of thunks can accumulate in memory before being forced
- **Space leaks**: A documented failure mode in Haskell programs. Lazy evaluation causes thunks to accumulate instead of being evaluated, consuming memory that a strict language would not retain. Common causes: `foldl` (non-strict accumulator), lazy IO, improperly lazy data structures. Mitigations: `foldl'`, `seq`, `deepseq`, `BangPatterns`, `StrictData`/`Strict` extensions [GHC-MEMORY-WIKI; SPACE-LEAKS-STANFORD]
- **No null pointers**: Haskell's type system has no null references; optionality is represented with `Maybe a`
- **Immutability by default**: All values are immutable by default; mutation requires explicit use of mutable references (`IORef`, `STRef`, `MVar`, `TVar`)
- **FFI memory**: When calling C code via the FFI, manual memory management is required for data passed across the boundary; GHC provides `Foreign.Marshal.Alloc` and `Storable` for this purpose [HASKELL-FFI-RWH]

### Concurrency Model

GHC implements an M:N threading model [GHC-SCHEDULER-EZYANG]:

- **Haskell threads**: Lightweight "green" threads managed by the GHC Runtime System (RTS); can number in the millions; scheduled cooperatively within capabilities
- **Capabilities (HECs — Haskell Execution Contexts)**: Units of parallel execution, each with a nursery and a work queue. The number of capabilities equals the number of OS threads that can run Haskell code simultaneously (configured with `+RTS -N`); defaults to number of CPU cores [GHC-CONCURRENT-GUIDE]
- **OS threads**: Each capability is backed by one or more OS threads; when a Haskell thread makes a blocking FFI call, another OS thread takes over the capability
- **Software Transactional Memory (STM)**: Implemented in GHC 6.4; allows atomic blocks (`atomically`) over `TVar` (transactional variables); automatically retried on conflict; composable by design [HASKELL-WIKI-STM]
- **Sparks**: Speculative parallel computation hints (`par`/`seq`); evaluated by idle capabilities via work-stealing; cheaper than full threads but semantics are advisory [GHC-CONCURRENT-GUIDE]
- **`async` library**: The standard approach to concurrent IO programming; wraps threads with structured lifecycle management and exception propagation [HACKAGE]
- **No "colored functions" problem in the same sense**: Because all effectful code is typed as `IO`, there is a fundamental type-level distinction, but it does not create the JS async/sync split in the same way — all Haskell threads are uniform

Known limitations: STM retry loops under high contention; no built-in actor model in the language (though libraries exist); no structured concurrency in the language itself (the `async` library provides a de facto standard).

### Error Handling

Haskell has two distinct error handling regimes [RWH-ERROR]:

**Pure (type-based) error handling**:
- `Maybe a`: Represents the presence (`Just a`) or absence (`Nothing`) of a value; used for functions that might fail without a useful error description
- `Either e a`: Represents success (`Right a`) or failure (`Left e`); `e` carries error information; standard for recoverable errors with context
- `ExceptT e m a`: A monad transformer adding `Either`-style error handling to other monads; the standard approach in production Haskell stacks
- These compose via `>>=` (monadic bind); `do` notation provides sugar for sequential operations

**Impure (exception-based) error handling**:
- `Control.Exception`: Runtime exceptions that propagate outside the normal monadic flow; can be thrown with `throwIO`, caught with `catch`/`try`
- Synchronous exceptions: thrown and caught in the same thread
- Asynchronous exceptions: can be delivered to any thread from outside; a distinctive and often surprising feature
- `error` and `undefined`: Partial functions that throw exceptions at runtime if evaluated; documented anti-pattern in production code

The coexistence of two regimes is an acknowledged complexity in Haskell design. Industry guidance generally favors `ExceptT`-based or `Either`-based error handling in library code, with runtime exceptions reserved for truly exceptional conditions [RWH-ERROR].

### Compilation and Interpretation Pipeline

GHC's compilation pipeline [GHC-PIPELINE-MEDIUM]:

1. **Parse**: Haskell source → parse tree
2. **Rename**: Resolve identifiers, scope checking
3. **Typecheck**: HM type inference + extension-specific checks
4. **Desugar**: Surface Haskell → Core (a typed lambda calculus based on System F_ω)
5. **Simplify**: Series of source-to-source transformations on Core; the main optimization pass
6. **Core → STG**: Core transformed to Spineless Tagless G-machine (STG) language — a low-level functional language modeling heap-allocated closures
7. **STG → C--**: A portable low-level imperative intermediate representation
8. **Backends**: C-- compiled to native machine code (native code generator), LLVM IR (LLVM backend), JavaScript (GHC 9.6+), or WebAssembly (GHC 9.6+)
9. **GHCi** (interactive mode): Interprets Core/bytecode directly without full native code generation

Optimization flags: `-O` (basic optimizations), `-O2` (more aggressive; significantly longer compile times). GHC documentation notes that `-O2` is "nearly indistinguishable from -O" in many cases but takes significantly longer [GHC-SOONER].

**Known compilation speed issues**: Compilation time scales superlinearly with module size. Large projects in Haskell are documented as slow to compile, particularly at `-O2`. Industry practitioners have reported compile times as a source of reduced iteration speed [PARSONSMATT-FAST]. GHC 9.4 introduced structured diagnostics aimed at improving IDE integration and incremental compilation support [GHC-9.4-RELEASED].

### Standard Library

- **`base`**: The core library; provides `Prelude` (imported by default), standard types (`Bool`, `Int`, `Integer`, `Double`, `Char`, `String`, `[]`, `Maybe`, `Either`, `IO`), numeric classes, `Data.List`, `Data.Map`/`Data.Set` (not in base; in `containers`), `Control.Exception`, `System.IO`, `Control.Concurrent`, `Data.IORef` [BASE-HACKAGE]
- **`Prelude`**: Auto-imported module containing basic functions; criticized for containing partial functions (`head`, `tail`, `fromJust`) and for `String` being `[Char]` (a linked list of characters, inefficient for text); multiple "alternative preludes" exist (e.g., `relude`, `protolude`) [BASE-WIKI]
- **`containers`**: Standard library for `Map`, `Set`, `Sequence`, `IntMap` — not in `base` but considered near-standard
- **`text`**: Efficient Unicode text handling (replaces `String` in performance-sensitive code)
- **`bytestring`**: Efficient byte sequences

---

## Ecosystem Snapshot

### Package Manager and Registry

- **Hackage**: The Haskell community's central package archive, online since January 2007 [HACKAGE]. Packages are `.cabal`-format distributions
- **Stackage**: A curated subset of Hackage packages organized into versioned "snapshots" where all included packages are known to build together with a specific GHC version [STACKAGE]
- **Cabal**: The build system and package management tool; used by 67% of respondents in the 2022 State of Haskell Survey [HASKELL-SURVEY-2022]
- **Stack**: An alternative build tool that uses Stackage snapshots for reproducibility; used by 49% in 2022 [HASKELL-SURVEY-2022]; relies on the Cabal library internally
- **Nix**: The Nix package manager with `nixpkgs` Haskell packages is used for installation by 35% and as a build tool by 33% [HASKELL-SURVEY-2022]
- **GHCup**: The recommended GHC toolchain installer (GHC, Cabal, HLS, Stack); used by 55% of respondents for GHC installation [HASKELL-SURVEY-2022]

### Major Frameworks and Libraries

**Web development**:
- **Yesod**: Full-stack web framework with type-safe routing and templates
- **Servant**: Type-level DSL for defining and serving web APIs; widely used in production; API type drives server implementation, client generation, and documentation [SERVANT-GITHUB]
- **Warp**: High-performance HTTP/1.x and HTTP/2 server library; the underlying server for Servant and WAI-based applications [AOSABOOK-WARP]
- **WAI (Web Application Interface)**: Standard interface between web servers and Haskell web applications
- **Scotty**: Lightweight, Sinatra-inspired web framework

**Streaming and data processing**:
- **Conduit**: Stream processing library with resource safety; used by WAI [CONDUIT-HACKAGE]
- **Pipes**: Alternative streaming library

**Effects and concurrency**:
- **`async`**: Standard library for structured concurrent programming; built on GHC threads and STM
- **`stm`**: Software Transactional Memory primitives (`TVar`, `TMVar`, `TChan`, `atomically`) [STM-HACKAGE]
- **`mtl`** (Monad Transformer Library): Standard approach to monad transformer stacks (`StateT`, `ReaderT`, `ExceptT`, `WriterT`)

**Parsing and serialization**:
- **Parsec / Megaparsec**: Parser combinator libraries
- **Aeson**: De facto standard JSON parsing and encoding library
- **binary / cereal / store**: Binary serialization

**Testing**:
- **HUnit**: Unit testing framework (xUnit-style)
- **QuickCheck**: Property-based testing; originated in Haskell (by Koen Claessen and John Hughes); widely influential across other languages
- **Hedgehog**: Alternative property-based testing with integrated shrinking
- **Tasty**: Test runner integrating multiple test frameworks

### IDE and Editor Support

- **Haskell Language Server (HLS)**: LSP implementation for Haskell; used by 68% of 2022 survey respondents [HASKELL-SURVEY-2022]
- **VS Code**: Primary editor at 43% (2022); HLS integration via `haskell-language-server` extension
- **Vim/Neovim**: 40% of respondents
- **Emacs**: 30%; historically dominant in the Haskell community; `haskell-mode` and `dante` are common setups

### Build and CI Patterns

- Cabal and Stack are the primary build tools; both integrate with GitHub Actions, CircleCI, and similar CI systems
- HLS requires matching GHC version; toolchain management via GHCup is the current recommended approach [GHCUP-GUIDE]

---

## Security Data

### Language-Level Security Properties

Haskell's type system eliminates several categories of vulnerability by construction:

- **No buffer overflows** in pure Haskell code: bounds-checked arrays; no pointer arithmetic
- **No null pointer dereferences**: `Maybe a` replaces nullable references; the type system requires explicit handling
- **No use-after-free** in pure code: GC manages lifetime; no manual deallocation
- **No data races in pure code**: Immutability by default; shared mutable state requires explicit `MVar`/`TVar`/`IORef` with type-level visibility
- **Type-enforced effect tracking**: The `IO` type tags all effectful code; pure code is referentially transparent

### Safe Haskell

Safe Haskell (introduced in GHC 7.2) is an extension that restricts the features of Haskell available to a module, enabling untrusted code to be included safely in a trusted codebase [GHC-SAFE-HASKELL]:

- The `Safe` pragma disallows: `unsafePerformIO`, Template Haskell, pure FFI functions, `RULES` pragma
- The `Trustworthy` pragma allows carefully audited modules to use unsafe features while being usable from `Safe` contexts
- The `Unsafe` pragma (default for modules using unsafe features) prevents use from `Safe` contexts

### Known Vulnerability Patterns

The Haskell Security Response Team (SRT) was established within the Haskell Foundation and maintains the `haskell/security-advisories` database using the HSEC identifier scheme [HASKELL-SECURITY-PAGE; HSEC-GITHUB]:

- As of late 2023/early 2024, the database contained approximately **26 advisories**: 23 affecting Hackage packages and 3 for GHC toolchain components [HSEC-2023-REPORT]
- 2025 Q1 saw first advisories published for GHC toolchain components themselves [HSEC-2025-Q1]
- Advisories are cross-referenced with CVEs where applicable and browsable on OSV.dev

**Notable vulnerability — HSEC-2024-0003 / CVE-2024-3566**:
- **Package**: `process` (part of GHC's bundled libraries)
- **Platform**: Windows only
- **Issue**: Command injection via inadequate escaping of `cmd.exe` special characters when invoking `.bat`/`.cmd` files with arguments from untrusted input
- **CVSS 3.1**: 9.8 (Critical)
- **CWE**: CWE-150 (Improper Neutralization of Input Leaders)
- **Fix**: `process-1.6.19.0` (initial fix); `process-1.6.23.0` (edge-case follow-up); included in GHC 9.10.1-alpha3, GHC 9.8.3, GHC 9.6.5 [HSEC-2024-0003]

**HSEC-2023-0015**: `cabal-install` vulnerability in the Hackage Security protocol — could allow an attacker to deliver malicious packages (supply chain vector) [HSEC-2023-0015-FILE]

### Common CWE Categories for Haskell

Based on available HSEC data, vulnerability patterns in Haskell ecosystem packages tend toward:
- **Supply chain / dependency management**: Packaging tool vulnerabilities (cabal, Stack)
- **Input validation**: Vulnerabilities in FFI-boundary code or OS-interaction libraries (as with CVE-2024-3566)
- **Memory safety violations in FFI code**: Pure Haskell is safe; C interop via FFI reintroduces memory safety concerns at the boundary

The language's purity and strong typing eliminate many CWE categories prevalent in C/C++ (buffer overflow, use-after-free, format string bugs) and dynamic languages (injection via eval, type confusion). Historical GHC RTS-level memory issues have been documented but patched in older versions (e.g., large array allocation integer overflow in pre-6.8.x) [HASKELL-WIKI-UNTRUSTED].

---

## Developer Experience Data

### 2022 State of Haskell Survey Results

All figures from [HASKELL-SURVEY-2022] (1,038 respondents; data collected November 2022):

**Satisfaction ratings (% Strongly Agree + Agree)**:
- "I am satisfied with Haskell as a language": 79%
- "I would recommend Haskell to a colleague": 79%
- "I prefer Haskell for my next project": 77%
- "Haskell programs generally do what I intend once compiled": 76%
- "Software written in Haskell is easy to maintain": 69%
- "I am satisfied with GHC's performance": 78%
- "Haskell's performance meets my needs": 70%

**Known pain points (% Disagree + Strongly Disagree, indicating difficulty)**:
- "I can reason about Haskell's performance characteristics": 42% disagree
- "Haskell libraries are easy to compare to each other": 38% disagree
- "It is easy to find Haskell jobs": 32% disagree
- "Haskell library documentation is adequate": 28% disagree

**Tool adoption (% of respondents using)**:
- GHC: 96%
- Cabal: 67%
- Stack: 49%
- Nix: 33%
- GHCup (installation): 55%
- HLS: 68%

**Extensions most commonly desired as defaults** (by community vote):
- `LambdaCase` (+411 net votes)
- `OverloadedStrings` (+390)
- `DeriveGeneric` (+350)

### Learning Curve

Haskell is widely documented as having a steep learning curve, attributed to:
- Laziness and its non-obvious performance implications (space leaks)
- Monadic I/O requiring conceptual adjustment
- The type class system and abstraction depth (Monad/Applicative/Functor hierarchy)
- Lack of familiar imperative constructs
- Space leak diagnosis difficulty: 42% of survey respondents report difficulty reasoning about performance [HASKELL-SURVEY-2022]

### Salary and Job Market

- **Average salary (Glassdoor, 2025)**: Approximately $106,373/year (United States)
- **Range**: $79,779 (25th percentile) to $148,922 (75th percentile)
- **Highest-paying Haskell sectors (2023 data)**: Blockchain/Cryptocurrency ($95,000 avg), Financial Services ($90,000 avg) [SALARY-DATA]
- **Job availability**: 32% of 2022 survey respondents disagree that Haskell jobs are easy to find; Indeed.com listed approximately 27 Haskell functional programming jobs at time of data collection [INDEED-HASKELL]

---

## Performance Data

### Computer Language Benchmarks Game

Benchmarks Game data (benchmarksgame-team.pages.debian.net; hardware: Ubuntu 24.04, x86-64, Intel i5-3330 quad-core, 3.0 GHz, 15.8 GiB RAM) comparing GHC (optimized) to C clang [BENCHMARKS-GAME-GHC-CLANG]:

| Benchmark | GHC Fastest (seconds) | C clang Fastest (seconds) | Ratio (GHC/C) |
|-----------|----------------------|--------------------------|----------------|
| fasta | 0.87 | 0.78 | ~1.1x slower |
| mandelbrot | 1.39 | 1.23 | ~1.1x slower |
| n-body | 6.41 | 2.20 | ~2.9x slower |
| spectral-norm | 1.49 | ~0.39 | ~3.8x slower |
| k-nucleotide | 23.30 | 6.34 | ~3.7x slower |
| fannkuch-redux (best) | 9.69 | 2.25 | ~4.3x slower |
| binary-trees | Varies | Varies | Typically 2-4x slower |

**Memory consumption**: GHC implementations consistently require 3–5x more memory than equivalent C clang implementations across benchmarks [BENCHMARKS-GAME-GHC-CLANG].

These figures reflect well-optimized GHC code (with `-O2` and manual tuning); naïve Haskell programs may perform significantly worse.

### Compilation Speed

- GHC compilation is substantially slower than languages like Go or C
- Compilation time scales superlinearly with module size — documented as a known architectural constraint [PARSONSMATT-FAST]
- Industry practitioners report slow iteration cycles in large Haskell codebases; team leads at startups have cited this as a productivity concern [SUMTYPEOFWAY-ITERATION]
- GHC 9.4 introduced improvements to compile-time memory consumption and a structured diagnostics API aiding incremental compilation in IDEs

### Runtime Performance Profile

- **Strengths**: Pure functional workloads; numeric algorithms with good cache locality; parallel workloads benefiting from cheap green threads and STM
- **Weaknesses**: Memory-intensive workloads (GC pressure, thunk accumulation); startup time (GHC-compiled executables have non-trivial startup costs from RTS initialization); string processing (default `String = [Char]` is a linked list; `text` and `bytestring` mitigate this for performance-critical paths)
- **GC pauses**: Generational GC introduces pause times; not suitable for hard real-time requirements without explicit tuning or use of GHC's incremental GC options
- **Lazy evaluation overhead**: Each unevaluated thunk requires a heap allocation; strictness annotations (`!`, `BangPatterns`, `StrictData`) are commonly used to reduce this overhead in performance-sensitive code

### Optimization Story

- Primary optimization: GHC's simplifier performs extensive source-to-source transformations on Core (inlining, common-subexpression elimination, let-floating, case-of-case, worker/wrapper transformation)
- The LLVM backend (`-fllvm`) can produce faster code than the native code generator for some workloads at the cost of longer compile times
- Profiling tools: `-prof` flag enables cost-centre profiling; `eventlog` profiling; `hp2ps` for heap profiling; `threadscope` for parallel profiling

---

## Governance

### Decision-Making Structure

Haskell's governance is distributed across several bodies [HASKELL-WIKI-GOVERNANCE]:

- **GHC Steering Committee (GSC)**: Formed January 2017; responsible for approving GHC language extension proposals. Approximately 10 members serving 3-year renewable terms; nomination process triggered when unexpired members drop below 9. Proposals submitted as pull requests to `github.com/ghc-proposals/ghc-proposals`; community discussion followed by committee shepherding and vote [GHC-PROPOSALS-REPO; GHC-STEERING-BYLAWS]
- **Haskell Foundation (HF)**: Nonprofit (merged with Haskell.org in 2024–2025); coordinates community infrastructure, funding, and outreach; goal of approximately $1M/year in combined cash and in-kind contributions [HF-WHITEPAPER]
- **GHC development team**: Maintained primarily by Well-Typed (a Haskell consultancy), with significant contributions from Meta, IOHK/IOG, Serokell, Tweag, and community contributors; GHC development occurs on GitLab (`gitlab.haskell.org/ghc/ghc`)
- **Haskell.org Committee**: Historically managed the haskell.org domain and infrastructure; merging with Haskell Foundation as of 2024–2025 [HF-GOVERNANCE]
- **Hackage Trustees**: Volunteer group responsible for the package registry administration
- **Stack maintainers**: Separate team responsible for the Stack build tool; decisions made independently of GHC

### Key Maintainers and Organizational Backing

- **Simon Peyton Jones** (Microsoft Research, later Epic Games): One of GHC's primary architects for decades; described as one of "the Simons" who chaired the GHC Steering Committee; has stepped back somewhat from day-to-day GHC development
- **Simon Marlow** (Meta): Co-architect of GHC's parallel runtime; co-author of the GHC RTS; currently works on Haskell infrastructure at Meta (Glean, Haxl)
- **Well-Typed**: A UK-based consultancy that provides significant GHC development resources; publishes quarterly ecosystem activity reports [WELL-TYPED-REPORT]
- **IOG/IOHK**: Funding Haskell development for the Cardano blockchain; Gold-level Haskell Foundation sponsor [HF-WHITEPAPER]
- **Serokell**: Funds dependent types work in GHC since 2018 [DH-ROADMAP]
- **Meta**: Gold-level HF sponsor; operates Sigma, Glean, Haxl; significant Haskell Foundation backer [SEROKELL-META]
- **Standard Chartered**: Gold-level HF sponsor; operates the largest known industrial Haskell codebase [HF-WHITEPAPER; SEROKELL-SC]

### Funding Model

Haskell Foundation sponsors (as of HF whitepaper, updated periodically) [HF-WHITEPAPER]:
- **Gold level**: IOHK, Juspay, Mercury, Standard Chartered
- **Silver level**: Tweag, Well-Typed
- **Bronze level**: Channable, DigitalOcean, Google, QBayLogic, TripShot

The HF whitepaper notes: "The end of 2024 was a challenging time for Open Source generally and the Haskell Foundation was no exception" in the context of funding challenges [HF-Q1-2025].

### Backward Compatibility Policy

- **Haskell 98** and **Haskell 2010**: Implementations remain committed to supporting these standards; GHC supports both via the `{-# LANGUAGE Haskell2010 #-}` pragma
- **GHC extensions**: Not backward-compatible; extensions evolve and can break between GHC major versions; the `ghc-version` field in `.cabal` files and the `base` library version bounds encode compatibility constraints
- **PVP (Package Versioning Policy)**: A Haskell-specific semantic versioning convention for Hackage packages; not universally followed but recommended [HACKAGE]
- **No ISO/ECMA/ANSI standard**: Haskell has no external standardization body; Haskell 2010 is the last published formal specification

### Standardization Status

Haskell is not standardized by an external body (ISO, ECMA, ANSI). The last formal language specification is the Haskell 2010 Language Report (July 2010). GHC's language editions (GHC2021, GHC2024) are pragmatic extensions of this base, not formal standards. Efforts to produce "Haskell 2020" stalled; no successor standardization effort is underway as of February 2026 [HASKELL202X-DEAD].

---

## References

[HASKELL-98-PREFACE] Hudak, P., Jones, S.P., Wadler, P., Hughes, J. (eds.). "Preface." *The Haskell 98 Report.* February 1999. https://www.haskell.org/onlinereport/preface-jfp.html

[HISTORY-HUDAK-2007] Hudak, P., Hughes, J., Peyton Jones, S., Wadler, P. "A History of Haskell: Being Lazy With Class." *Proceedings of the Third ACM SIGPLAN Conference on History of Programming Languages (HOPL III).* June 2007. https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/history.pdf (PDF content not directly accessible; metadata and citations verified via ACL/ResearchGate)

[HISTORY-SEROKELL] Serokell. "History of the Haskell Programming Language." Serokell Blog. https://serokell.io/blog/haskell-history

[HASKELL-WIKI-2010] HaskellWiki. "Haskell 2010." https://wiki.haskell.org/Haskell_2010

[HASKELL-WIKI-STM] HaskellWiki. "Software Transactional Memory." https://wiki.haskell.org/Software_transactional_memory

[HASKELL-WIKI-GOVERNANCE] HaskellWiki. "Haskell Governance." https://wiki.haskell.org/Haskell_Governance

[HASKELL-WIKI-IO] HaskellWiki. "IO Inside." https://wiki.haskell.org/IO_inside

[HASKELL-WIKI-UNTRUSTED] HaskellWiki. "Safely Running Untrusted Haskell Code." http://wiki.haskell.org/Safely_running_untrusted_Haskell_code

[ENDOFLIFE-GHC] endoflife.date. "Glasgow Haskell Compiler (GHC)." https://endoflife.date/ghc (data current as of February 2026)

[GHC-EXTENSIONS-CTRL] GHC User's Guide. "Controlling editions and extensions." GHC 9.15 development branch. https://ghc.gitlab.haskell.org/ghc/doc/users_guide/exts/control.html

[GHC-2024-PROPOSAL] ghc-proposals. "GHC2024 Proposal #613." https://github.com/ghc-proposals/ghc-proposals/blob/master/proposals/0613-ghc2024.rst

[GHC-9.6-NOTES] GHC Project. "Version 9.6.1 Release Notes." https://downloads.haskell.org/ghc/9.6.1/docs/users_guide/9.6.1-notes.html

[GHC-9.4-RELEASED] GHC Project. "GHC 9.4.1 Released." https://www.haskell.org/ghc/blog/20220807-ghc-9.4.1-released.html

[GHC-9.2-FEATURES] Fedora Project Wiki. "Changes/Haskell GHC 9.2 and Stackage 20." https://fedoraproject.org/wiki/Changes/Haskell_GHC_9.2_and_Stackage_20

[GHC-RTS-EZYANG] Yang, E. "The GHC Runtime System." (Draft; JFP). http://ezyang.com/jfp-ghc-rts-draft.pdf

[GHC-SCHEDULER-EZYANG] Yang, E. "The GHC Scheduler." ezyang's blog, January 2013. https://blog.ezyang.com/2013/01/the-ghc-scheduler/

[GHC-CONCURRENT-GUIDE] GHC User's Guide. "Using Concurrent Haskell." GHC 9.14.1. https://downloads.haskell.org/ghc/latest/docs/users_guide/using-concurrent.html

[GHC-MEMORY-WIKI] HaskellWiki. "GHC/Memory Management." https://wiki.haskell.org/GHC/Memory_Management

[GHC-SAFE-HASKELL] GHC User's Guide. "Safe Haskell." https://ghc.gitlab.haskell.org/ghc/doc/users_guide/exts/safe_haskell.html

[GHC-LINEAR-TYPES] GHC User's Guide. "Linear types." https://ghc.gitlab.haskell.org/ghc/doc/users_guide/exts/linear_types.html

[GHC-SOONER] GHC User's Guide (8.x). "Advice on: sooner, faster, smaller, thriftier." https://mpickering.github.io/ghc-docs/build-html/users_guide/sooner.html

[GHC-PIPELINE-MEDIUM] Ho, J. "Haskell Compilation Pipeline and STG Language." Medium / Superstring Theory. https://medium.com/superstringtheory/haskell-compilation-pipeline-and-stg-language-7fe5bb4ed2de

[GHC-PROPOSALS-REPO] ghc-proposals. "Proposed compiler and language changes for GHC." GitHub. https://github.com/ghc-proposals/ghc-proposals

[GHC-STEERING-BYLAWS] ghc-proposals. "GHC Steering Committee Bylaws." https://ghc-proposals.readthedocs.io/en/latest/committee.html

[DH-ROADMAP] Serokell / GHC. "Dependent Haskell Roadmap." https://ghc.serokell.io/dh

[HF-WHITEPAPER] Haskell Foundation. "Haskell Foundation Whitepaper." https://haskell.foundation/whitepaper/

[HF-GOVERNANCE] Haskell Foundation / Haskell.org. "Haskell Foundation Q1 2025 Update." Haskell Discourse, 2025. https://discourse.haskell.org/t/haskell-foundation-q1-2025-update/11835

[HF-Q1-2025] Haskell Foundation. "Haskell Foundation Q1 2025 Update." Haskell Discourse. https://discourse.haskell.org/t/haskell-foundation-q1-2025-update/11835

[HASKELL-SURVEY-2022] Fausak, T. "2022 State of Haskell Survey Results." November 18, 2022. https://taylor.fausak.me/2022/11/18/haskell-survey-results/

[STATEOFHASKELL-2025] Haskell Foundation. "State of Haskell 2025." Haskell Discourse. https://discourse.haskell.org/t/state-of-haskell-2025/13390

[SO-SURVEY-2025] Stack Overflow. "2025 Stack Overflow Developer Survey — Technology." https://survey.stackoverflow.co/2025/technology

[SO-SURVEY-2024] Stack Overflow. "2024 Stack Overflow Developer Survey." https://survey.stackoverflow.co/2024/

[TIOBE-NOV-2024] Silvae Technologies. "TIOBE Index November Headline: Is Haskell Finally Going to Hit the Top 20?" https://silvaetechnologies.eu/blg/235/tiobe-index-november-headline-is-haskell-finally-going-to-hit-the-top-20

[SEROKELL-TOP11] Serokell. "11 Companies That Use Haskell in Production." https://serokell.io/blog/top-software-written-in-haskell

[SEROKELL-META] Serokell. "Haskell in Production: Meta." https://serokell.io/blog/haskell-in-production-meta

[SEROKELL-SC] Serokell. "Haskell in Production: Standard Chartered." https://serokell.io/blog/haskell-in-production-standard-chartered

[GITHUB-HASKELL-COMPANIES] erkmos. "haskell-companies: A gently curated list of companies using Haskell in industry." GitHub. https://github.com/erkmos/haskell-companies

[HACKAGE] Hackage — The Haskell community's central package archive. https://hackage.haskell.org

[STACKAGE] Stackage Server. https://www.stackage.org/

[GHCUP-GUIDE] GHCup. "User Guide." https://www.haskell.org/ghcup/guide/

[SERVANT-GITHUB] haskell-servant. "Servant." GitHub. https://github.com/haskell-servant/servant

[AOSABOOK-WARP] Yamamoto, K., Snoyman, M. "The Performance of Open Source Software: Warp." *The Architecture of Open Source Applications.* https://aosabook.org/en/posa/warp.html

[CONDUIT-HACKAGE] conduit package on Hackage. https://hackage.haskell.org/package/conduit

[STM-HACKAGE] stm package on Hackage. https://hackage.haskell.org/package/stm

[BASE-HACKAGE] base package on Hackage. https://hackage.haskell.org/package/base

[BASE-WIKI] HaskellWiki. "Base package." https://wiki.haskell.org/Base_package

[HASKELL-FFI-RWH] Sullivan, B., Goerzen, J., Stewart, D. *Real World Haskell.* Chapter 17: Interfacing with C: the FFI. https://book.realworldhaskell.org/read/interfacing-with-c-the-ffi.html

[RWH-ERROR] Sullivan, B., Goerzen, J., Stewart, D. *Real World Haskell.* Chapter 19: Error Handling. https://book.realworldhaskell.org/read/error-handling.html

[UNSAFE-HASKELL-PENN] University of Pennsylvania CIS 1940. "Unsafe Haskell." Spring 2015. https://www.seas.upenn.edu/~cis1940/spring15/lectures/12-unsafe.html

[HASKELL-SECURITY-PAGE] Haskell.org. "Security." https://www.haskell.org/security/

[HSEC-GITHUB] haskell/security-advisories. GitHub. https://github.com/haskell/security-advisories

[HSEC-2023-REPORT] Haskell Security Response Team. "2023 July–December Report." Haskell Discourse. https://discourse.haskell.org/t/haskell-security-response-team-2023-july-december-report/8531

[HSEC-2025-Q1] haskell/security-advisories. "Q1 2025 Report." https://github.com/haskell/security-advisories/blob/main/reports/2025-04-04-Q1-report.md

[HSEC-2024-0003] Haskell Security Advisories. "HSEC-2024-0003: Windows command injection in the process library." https://haskell.github.io/security-advisories/advisory/HSEC-2024-0003.html

[HSEC-2023-0015-FILE] haskell/security-advisories. "HSEC-2023-0015: cabal-install Hackage Security protocol." https://github.com/haskell/security-advisories/blob/main/advisories/hackage/cabal-install/HSEC-2023-0015.md

[BENCHMARKS-GAME-GHC-CLANG] Benchmarks Game. "C clang vs Haskell GHC — Which programs are fastest?" https://benchmarksgame-team.pages.debian.net/benchmarksgame/fastest/clang-ghc.html

[PARSONSMATT-FAST] Parsons, M. "Keeping Compilation Fast." November 27, 2019. https://www.parsonsmatt.org/2019/11/27/keeping_compilation_fast.html

[SUMTYPEOFWAY-ITERATION] Sum Type of Way Blog. "Towards Faster Iteration in Industrial Haskell." https://blog.sumtypeofway.com/posts/fast-iteration-with-haskell.html

[SPACE-LEAKS-STANFORD] Stanford CS. "Space Leaks Exploration in Haskell — Seminar Report." https://cs.stanford.edu/~sumith/docs/report-spaceleaks.pdf

[TYPECLASS-WIKIPEDIA] Wikipedia. "Type class." https://en.wikipedia.org/wiki/Type_class

[SEROKELL-HKT] Serokell. "Kinds and Higher-Kinded Types in Haskell." https://serokell.io/blog/kinds-and-hkts-in-haskell

[SALARY-DATA] Glassdoor. "Salary: Haskell Developer in United States 2025." https://www.glassdoor.com/Salaries/haskell-developer-salary-SRCH_KO0,17.htm

[INDEED-HASKELL] Indeed.com. "Haskell Functional Programming Jobs." https://www.indeed.com/q-Haskell-Functional-Programming-jobs.html

[WELL-TYPED-REPORT] Well-Typed. "GHC Activities Report: December 2024–February 2025." https://well-typed.com/blog/2025/03/ghc-activities-report-december-2024-february-2025/

[HASKELL202X-DEAD] Copeland, S. "Haskell2020 Is Dead, but All Hope Is Not Lost." Reasonably Polymorphic. https://reasonablypolymorphic.com/blog/haskell202x/

---

**Document version**: 1.0
**Prepared**: 2026-02-28
**Data coverage**: Current through February 2026 (GHC 9.14.1, December 2025)
**Word count**: ~8,500 words
