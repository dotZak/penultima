# Penultima Common Report Schema

**Version:** 1.0
**Status:** Draft
**Last updated:** 2026-02-26

This document defines the structure, content requirements, and evidence standards for all documents produced during the Penultima deliberation process. It covers three document types:

1. **Internal Council Report** — produced by each Tier 1 language council (Phase 2)
2. **Cross-Review Document** — produced by one council reviewing another language (Phase 4)
3. **Integrative Response** — produced by a council in response to cross-reviews of its language (Phase 5)

Tier 2 languages use a condensed version of the Internal Council Report (see Appendix A). Tier 3 languages use a brief template (see Appendix B).

---

## Part I: Internal Council Report

This is the primary document produced by each Tier 1 language council. It represents the consensus of all five council members (Apologist, Realist, Detractor, Historian, Practitioner). Where consensus cannot be reached, dissenting views are included inline, clearly labeled with the dissenting role.

### Document Metadata

Every report begins with a metadata block:

```yaml
language: "<Language Name>"
version_assessed: "<Primary version under review, e.g., Python 3.12>"
council_members:
  apologist: "<agent identifier>"
  realist: "<agent identifier>"
  detractor: "<agent identifier>"
  historian: "<agent identifier>"
  practitioner: "<agent identifier>"
schema_version: "1.0"
date: "<YYYY-MM-DD>"
```

---

### Section 1: Identity and Intent

**Purpose:** Establish what the language *is* — its stated goals, intended audience, and design philosophy as articulated by its creators.

**Required content:**

- **Origin and context.** When was the language created, by whom, and in response to what problems? What was the state of the art at the time? What were the designers explicitly reacting to or improving upon?
- **Stated design philosophy.** What principles did the creators articulate? Quote primary sources where available (conference talks, papers, documentation, interviews).
- **Intended use cases.** What domains was the language designed for? Has it drifted beyond those domains, and if so, how successfully?
- **Key design decisions.** Identify the 5–10 most consequential decisions the designers made (e.g., "garbage collected," "no inheritance," "whitespace-significant"). For each, state the rationale as the designers expressed it.

**Evidence expectations:** Primary sources preferred (designer statements, original papers, RFCs). Secondary sources (books, retrospectives) acceptable. Community folklore is not evidence — if a claim about designer intent is commonly repeated but unsourced, say so.

---

### Section 2: Type System

**Purpose:** Assess the language's approach to types — not just what the type system *does*, but what it *enables and prevents*.

**Required content:**

- **Classification.** Static vs. dynamic. Strong vs. weak. Nominal vs. structural. Gradual typing support. Describe where the language falls on each axis and any nuances (e.g., TypeScript is structural but has branded types).
- **Expressiveness.** What can the type system represent? Generics, algebraic data types, dependent types, higher-kinded types, type-level computation. Where does expressiveness hit its ceiling?
- **Type inference.** How much can the compiler infer? Where does the developer need to annotate? Is inference local or global? Are there known cases where inference produces surprising results?
- **Safety guarantees.** What classes of errors does the type system prevent at compile time? What slips through? Provide specific examples of bugs the type system catches and bugs it cannot.
- **Escape hatches.** `any` in TypeScript, `unsafe` in Rust, casts in Java. How easy is it to bypass the type system, and how often does production code do so?
- **Impact on developer experience.** Does the type system help or hinder readability? Onboarding? Refactoring? IDE support?

**Evidence expectations:** Cite language specification for classification claims. Cite CVE data or published research for safety guarantee claims. Developer experience claims should reference surveys, user studies, or practitioner literature.

---

### Section 3: Memory Model

**Purpose:** Describe how the language manages memory, and the consequences of that approach for safety, performance, and developer burden.

**Required content:**

- **Management strategy.** Manual (malloc/free), garbage collected (which algorithm?), reference counted, ownership/borrowing, arena-based, or hybrid. Describe the primary mechanism and any secondary mechanisms.
- **Safety guarantees.** Does the language prevent use-after-free? Double-free? Buffer overflows? Null pointer dereferences? Data races on shared memory? For each: is the guarantee enforced by the compiler, the runtime, or not at all?
- **Performance characteristics.** GC pause times. Allocation overhead. Memory fragmentation patterns. Cache behavior. Provide benchmarks or reference published measurements where available.
- **Developer burden.** How much does the developer need to think about memory? What is the cognitive load? What are common mistakes even experienced developers make?
- **FFI implications.** How does the memory model interact with foreign function interfaces? Is it easy or difficult to share memory with code written in other languages?

**Evidence expectations:** Safety claims must reference either the language specification, formal verification results, or CVE pattern data. Performance claims must reference reproducible benchmarks with stated hardware and methodology. Anecdotal "it's fast" or "GC pauses are bad" claims are insufficient.

---

### Section 4: Concurrency and Parallelism

**Purpose:** Assess how the language supports concurrent and parallel execution, and where its model breaks down.

**Required content:**

- **Primitive model.** Threads, goroutines, async/await, actors, channels, STM, coroutines, or other. Describe the primary abstraction and how it maps to OS-level primitives.
- **Data race prevention.** Does the language prevent data races at compile time, at runtime, or not at all? What is the mechanism (ownership, immutability by default, actor isolation, etc.)?
- **Ergonomics.** How difficult is it to write correct concurrent code? What are the common pitfalls? Are they well-documented? Does the compiler help?
- **Colored function problem.** Does the language have the async/sync divide (function coloring)? If so, how severe is it in practice? If not, what mechanism avoids it?
- **Structured concurrency.** Does the language support structured concurrency? If so, how? If not, what patterns emerge in practice to manage task lifetimes?
- **Scalability.** How does the concurrency model perform under high load? What are the known bottlenecks? Reference production-scale deployments where possible.

**Evidence expectations:** Cite language specification or runtime documentation for model descriptions. Cite production case studies or benchmarks for scalability claims. Cite developer surveys or community discussions for ergonomics assessments.

---

### Section 5: Error Handling

**Purpose:** Evaluate the language's approach to errors — how they are represented, propagated, and recovered from.

**Required content:**

- **Primary mechanism.** Exceptions, result types, error codes, panics, monadic error handling, or hybrid. Describe the primary pattern and any secondary patterns.
- **Composability.** How easy is it to propagate errors through call chains? Does the language provide syntactic support (e.g., `?` in Rust, `try`/`catch` in many languages)?
- **Information preservation.** Does the error model preserve context (stack traces, error chains, structured metadata)? Or is information lost during propagation?
- **Recoverable vs. unrecoverable.** Does the language distinguish between recoverable errors and programming bugs? If so, how? If not, what problems does this cause?
- **Impact on API design.** How does the error model affect function signatures, API boundaries, and library design? Does it encourage or discourage fine-grained error types?
- **Common mistakes.** What error handling anti-patterns does the language enable or encourage? Swallowed exceptions, ignored error codes, overly broad catch blocks, etc.

**Evidence expectations:** Cite language documentation and standard library design for mechanism descriptions. Cite static analysis studies or code survey data for anti-pattern prevalence.

---

### Section 6: Ecosystem and Tooling

**Purpose:** Assess the practical environment surrounding the language — not the language in isolation, but the language as developers actually experience it.

**Required content:**

- **Package management.** What is the primary package manager? How mature is it? What are its known limitations? How does it handle versioning, dependency resolution, and security auditing?
- **Build system.** What is the standard build toolchain? How complex is the build configuration for non-trivial projects? How fast are builds?
- **IDE and editor support.** Quality of language server protocol implementation. Code completion, refactoring tools, inline error reporting. Which editors are well-supported?
- **Testing ecosystem.** Built-in testing support. Third-party testing frameworks. Property-based testing, fuzzing, mutation testing availability. Test ergonomics and convention.
- **Debugging and profiling.** Debugger quality. Profiling tools. Observability primitives (tracing, logging, metrics). How easy is it to diagnose production issues?
- **Documentation culture.** Quality of official documentation. Community documentation norms. API documentation generation tools.
- **AI tooling integration.** How well does the language work with AI-assisted development tools? Code generation quality, training data availability, LSP integration with AI assistants.

**Evidence expectations:** Cite package registry statistics where available. Reference IDE marketplace ratings or developer survey data. Tool quality claims should reference specific capabilities or known issues, not general impressions.

---

### Section 7: Security Profile

**Purpose:** Provide an empirical assessment of the language's security characteristics, grounded in vulnerability data.

**Required content:**

- **CVE class exposure.** Which CWE categories appear most frequently in software written in this language? Provide data from NVD, language-specific advisory databases, or published research. Compare rates to the cross-language baseline maintained by the Security Analyst advisory body.
- **Language-level mitigations.** What security-relevant guarantees does the language provide? Memory safety, type safety, bounds checking, taint tracking, sandboxing primitives. For each, assess how complete the guarantee is.
- **Common vulnerability patterns.** What are the most common security mistakes developers make in this language? Injection, deserialization, path traversal, etc. Are these structurally enabled by language design or merely possible?
- **Supply chain security.** How does the package ecosystem handle vulnerability disclosure, dependency auditing, and malicious package detection?
- **Cryptography story.** Quality of standard library cryptographic primitives. Availability of audited third-party cryptography libraries. Known historical cryptographic footguns.

**Evidence expectations:** CVE data must reference specific databases with query methodology stated. Claims about vulnerability rates should include time period and scope. Comparisons across languages must control for codebase size and domain.

---

### Section 8: Developer Experience

**Purpose:** Assess the subjective and empirical dimensions of what it is like to use this language.

**Required content:**

- **Learnability.** How long does it take a competent programmer to become productive? What are the steepest parts of the learning curve? What resources exist for learners?
- **Cognitive load.** How much does the developer need to hold in their head at any given time? What are the sources of incidental complexity vs. essential complexity?
- **Error messages.** Quality, clarity, and actionability of compiler/runtime error messages. Provide specific examples of good and bad error messages.
- **Expressiveness vs. ceremony.** How much boilerplate does typical code require? How concise can idiomatic solutions be? Is conciseness achieved at the cost of readability?
- **Community and culture.** What is the community like? Is it welcoming? Is there a strong convention culture (e.g., gofmt, Black for Python) or is style contested? How is conflict resolved?
- **Job market and career impact.** Prevalence in industry. Salary data where available. Hiring difficulty. Risk of language obsolescence.

**Evidence expectations:** Reference developer surveys (Stack Overflow, JetBrains, etc.) for satisfaction and adoption data. Learnability claims should reference user studies or structured onboarding data where available. Community assessments should reference observable indicators (moderation policies, CoC enforcement, contribution rates) rather than personal impressions.

---

### Section 9: Performance Characteristics

**Purpose:** Provide a grounded assessment of the language's performance profile across relevant dimensions.

**Required content:**

- **Runtime performance.** Throughput, latency, and resource consumption for workloads representative of the language's intended use cases. Reference established benchmarks (TechEmpower, Computer Language Benchmarks Game, or domain-specific benchmarks) and note their limitations.
- **Compilation speed.** Time to compile representative projects. Incremental compilation support. Impact on developer iteration speed.
- **Startup time.** Cold start performance. Relevance to serverless, CLI tools, and other latency-sensitive deployment models.
- **Resource consumption.** Memory footprint, CPU utilization patterns, and I/O characteristics. How does the language behave under resource constraints?
- **Optimization story.** How does performance-critical code differ from idiomatic code? How much does the developer sacrifice readability for performance? Are there language-level features that make optimization ergonomic (e.g., value types, zero-cost abstractions)?

**Evidence expectations:** Benchmark data must include hardware specifications, compiler versions, and optimization flags. Avoid microbenchmarks without context. Cite published benchmark suites and note known biases.

---

### Section 10: Interoperability

**Purpose:** Assess how well the language plays with others — both at the FFI level and at the system integration level.

**Required content:**

- **Foreign function interface.** Ease of calling into C, C++, or other languages. Safety of the FFI boundary. Overhead.
- **Embedding and extension.** Can the language be embedded in other systems? Can it be extended with native modules? How ergonomic is this?
- **Data interchange.** JSON, protobuf, gRPC, GraphQL support. Serialization/deserialization performance and ergonomics.
- **Cross-compilation.** Support for targeting multiple platforms and architectures. WebAssembly compilation support.
- **Polyglot deployment.** How well does the language coexist with other languages in the same project or system? Microservice boundaries, shared libraries, build system integration.

**Evidence expectations:** Cite FFI documentation and known limitations. Reference production examples of polyglot deployment where available.

---

### Section 11: Governance and Evolution

**Purpose:** Assess how the language changes over time and how decisions are made.

**Required content:**

- **Decision-making process.** Who controls the language's evolution? BDFL, committee, RFC process, corporate sponsor, community vote, or other? How transparent is the process?
- **Rate of change.** How frequently does the language introduce breaking changes? How is backward compatibility managed? What is the deprecation policy?
- **Feature accretion.** Has the language suffered from feature bloat? Are there features that are widely regarded as mistakes? How does the governance process handle removal or deprecation of bad ideas?
- **Bus factor.** How dependent is the language on specific individuals or organizations? What happens if the primary sponsor withdraws support?
- **Standardization.** Is the language formally standardized (ISO, ECMA, etc.)? Are there multiple implementations? How do they diverge?

**Evidence expectations:** Reference governance documents, RFC repositories, and published decision-making records. Bus factor assessments should cite contributor statistics and organizational backing.

---

### Section 12: Synthesis and Assessment

**Purpose:** The council's integrated judgment.

**Required content:**

- **Greatest strengths.** The 3–5 things this language does better than most or all alternatives. Be specific.
- **Greatest weaknesses.** The 3–5 things this language does worse than alternatives or gets fundamentally wrong. Be specific.
- **Lessons for Penultima.** What should a new language learn from this language? What should it avoid? What remains an open question?
- **Dissenting views.** Any significant disagreements within the council that were not resolved. State each position and the reasoning behind it.

---

## Part II: Cross-Review Document

Produced by one language council reviewing another language's Internal Council Report.

### Document Metadata

```yaml
reviewing_council: "<Reviewing Language>"
target_language: "<Target Language>"
relevance_rating: "high | medium | low"
relevance_rationale: "<1-2 sentences explaining the relationship between these languages>"
schema_version: "1.0"
date: "<YYYY-MM-DD>"
```

### Structure

The cross-review has two parts:

#### Part A: Independent Assessment

The reviewing council's own perspective on the target language, *before* reading the target council's report. This is written from the reviewing language's vantage point: what does a C expert see when they look at Rust? What does a Python expert see when they look at Go?

**Required content:**

- **Relationship statement.** How does the reviewing council's language relate to the target language? Competitors, complements, ancestors, successors, or unrelated? What is the basis for this assessment?
- **Perceived strengths.** What does the reviewing council believe the target language does well, especially relative to their own language?
- **Perceived weaknesses.** What does the reviewing council believe the target language gets wrong, especially where their own language does better?
- **Envy list.** Features or design choices the reviewing council wishes their own language had adopted. This is a critical section — it captures cross-pollination opportunities that self-assessment often misses.
- **Warnings.** Mistakes or pitfalls in the target language that the reviewing council recognizes from their own experience or from watching the target language's community.

#### Part B: Response to Internal Report

A section-by-section response to the target language council's Internal Council Report.

For each of the 12 sections of the Internal Council Report, the reviewing council provides:

- **Agreement.** Where they agree with the target council's self-assessment.
- **Disagreement.** Where they believe the target council is mistaken, overly generous, or overly harsh — with reasoning and evidence.
- **Missing context.** Information or perspectives that the target council's report omits.
- **Comparative notes.** How the reviewing council's own language handles the same problem, and what the comparison reveals.

Not every section requires substantial commentary. If the reviewing council has little to add on a particular section, a brief note stating so is acceptable. The relevance negotiation phase should have identified the sections most likely to produce substantive cross-review.

---

## Part III: Integrative Response

Produced by each language council after reading all cross-reviews of its language.

### Document Metadata

```yaml
language: "<Language Name>"
cross_reviews_received: <number>
schema_version: "1.0"
date: "<YYYY-MM-DD>"
```

### Structure

#### Summary of Cross-Review Themes

A synthesis of the major themes that emerged across all cross-reviews. What did multiple reviewers agree on? Where did reviewers diverge? Were there patterns in who praised what and who criticized what?

#### Section-by-Section Response

For each section of the original Internal Council Report, the council addresses:

- **Validated findings.** Points from the original report that cross-reviewers confirmed or strengthened.
- **Revised assessments.** Points where cross-review feedback caused the council to revise its position. State the original position, the feedback that prompted revision, and the new position.
- **Defended positions.** Points where the council considered cross-review criticism and maintained its original assessment, with additional evidence or reasoning.
- **New insights.** Points raised by cross-reviewers that the council had not considered, and the council's assessment of their validity.

#### Updated Lessons for Penultima

Revised synthesis reflecting what the council now believes Penultima should learn from its language, informed by the full deliberation.

---

## Evidence Standards

### General Principles

Claims must be supported by evidence. The strength of evidence required scales with the strength of the claim. Asserting that "this language is memory-safe" requires specification-level or formal-verification-level evidence. Asserting that "developers find this syntax readable" requires survey data or user studies.

### Evidence Categories

| Category | Description | Examples |
|----------|-------------|----------|
| **Specification** | The language's official spec or documentation | ISO standards, language reference manuals, RFCs |
| **Empirical research** | Peer-reviewed or published studies | Academic papers, industry research reports |
| **Vulnerability data** | CVE databases and security advisories | NVD, language-specific advisory databases, GHSA |
| **Developer surveys** | Structured surveys of developer populations | Stack Overflow Annual Survey, JetBrains Developer Ecosystem, State of JS/CSS/Rust/Go/etc. |
| **Benchmark data** | Reproducible performance measurements | TechEmpower, CLBG, domain-specific benchmarks |
| **Production case studies** | Published accounts of real-world usage | Conference talks, engineering blog posts, postmortems |
| **Primary sources** | Statements by language designers | Papers, talks, interviews, commit messages |
| **Community indicators** | Observable metrics from the language community | Package registry statistics, GitHub stars/contributors, forum activity |

### Citation Format

Use inline citations with a references section at the end of each document:

```
Memory safety issues account for approximately 70% of Microsoft's CVEs [MSRC-2019].
```

```
## References

[MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the
Software Vulnerability Mitigation Landscape." Microsoft Security Response
Center, BlueHat IL 2019.
```

### Evidence Anti-Patterns

The following do not constitute acceptable evidence:

- **Unattributed community consensus.** "Everyone knows that X is slow" is not evidence. Find the benchmark.
- **Microbenchmarks without context.** A tight loop comparing two languages tells you about that loop, not about the languages.
- **Outdated data.** Evidence older than five years should be flagged as potentially outdated, and the council should check for more recent data.
- **Conflation of language and ecosystem.** "Python is good for data science" is a statement about Python's ecosystem (NumPy, pandas), not about Python the language. Distinguish clearly.
- **Marketing materials.** Language landing pages and promotional content are not evidence of actual characteristics.

---

## Schema Versioning

This schema is versioned. Changes follow this process:

1. Any council or advisory body may propose a schema amendment.
2. The amendment is reviewed by the cross-cutting advisors.
3. If accepted, the schema version is incremented and all councils are notified.
4. Existing reports produced under the previous schema version are assessed for compliance with the new schema. Councils may be asked to add sections or update content, but existing content is not invalidated.

The current schema version is **1.0**. All documents must reference the schema version they were produced under.

---

## Appendix A: Tier 2 Condensed Report Template

Tier 2 languages receive a single-analyst report using the following condensed structure:

```yaml
language: "<Language Name>"
tier: 2
analyst: "<agent identifier>"
schema_version: "1.0"
date: "<YYYY-MM-DD>"
```

### Sections

1. **Identity and Intent** — Same as Tier 1, Section 1. Abbreviated.
2. **Key Innovations** — What ideas did this language introduce or popularize that influenced subsequent languages? What remains relevant today?
3. **Key Failures** — What did this language get wrong, and what can be learned from those failures?
4. **Transferable Insights** — Specific design decisions, patterns, or approaches that Penultima should consider adopting, adapting, or avoiding.
5. **References** — Sources cited.

Target length: 2,000–4,000 words.

---

## Appendix B: Tier 3 Honorable Mention Template

Tier 3 languages receive a brief entry:

```yaml
language: "<Language Name>"
tier: 3
schema_version: "1.0"
```

### Content

A single section of 200–500 words covering:

- What the language is and why it exists.
- The one to three insights it offers that are relevant to Penultima's design.
- Why it does not warrant deeper analysis.

---

## Appendix C: Relevance Negotiation Template

Published by each council before the cross-review phase:

```yaml
language: "<Language Name>"
date: "<YYYY-MM-DD>"
```

### Outbound Relevance

Languages this council intends to review, with brief rationale:

```
- Rust: Direct competitor in systems programming; memory model comparison is critical.
- Go: Competing concurrency models; shared focus on compilation speed.
- Assembly: Relevant to our FFI and low-level optimization story.
```

### Inbound Requests

Languages whose review of this language the council particularly values, with rationale:

```
- Python: Want their perspective on our developer experience tradeoffs.
- Haskell: Want their assessment of our type system limitations.
```

### Low-Relevance Declarations

Languages this council believes it has little substantive commentary on, with brief explanation:

```
- COBOL: Minimal overlap in problem domain or design philosophy.
```
