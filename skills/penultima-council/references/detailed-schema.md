# Detailed Schema Reference

This file contains the full evidence expectations for each of the 12 report sections. The consensus agent should read this before writing. Council members and advisors can refer to it for detailed requirements on specific sections.

## Section-by-Section Evidence Expectations

### Section 1: Identity and Intent
- **Required**: Origin context, stated design philosophy (quoted from primary sources), intended use cases, 5-10 key design decisions with designer-articulated rationale
- **Evidence**: Primary sources preferred (designer statements, original papers, RFCs). If a claim about designer intent is commonly repeated but unsourced, say so.

### Section 2: Type System
- **Required**: Classification (static/dynamic, strong/weak, nominal/structural, gradual), expressiveness ceiling, inference scope, safety guarantees (what's caught vs. what slips through with examples), escape hatches and their production usage, DX impact
- **Evidence**: Language specification for classification. CVE data or published research for safety claims. Surveys or user studies for DX claims.

### Section 3: Memory Model
- **Required**: Management strategy (manual/GC/RC/ownership/arena/hybrid), safety guarantees per category (use-after-free, double-free, buffer overflow, null deref, data races — compiler vs. runtime vs. none), performance characteristics with benchmarks, developer burden, FFI implications
- **Evidence**: Language spec or formal verification for safety claims. Reproducible benchmarks with hardware/methodology for performance. No "it's fast" or "GC pauses are bad."

### Section 4: Concurrency and Parallelism
- **Required**: Primitive model and OS-level mapping, data race prevention mechanism, ergonomics and pitfalls, colored function problem assessment, structured concurrency support, scalability evidence
- **Evidence**: Spec/runtime docs for model. Production case studies for scalability. Surveys for ergonomics.

### Section 5: Error Handling
- **Required**: Primary mechanism, composability (syntactic support for propagation), information preservation (stack traces, error chains), recoverable vs. unrecoverable distinction, API design impact, common anti-patterns
- **Evidence**: Language docs and stdlib for mechanisms. Static analysis or code surveys for anti-pattern prevalence.

### Section 6: Ecosystem and Tooling
- **Required**: Package management (maturity, limitations, security auditing), build system (complexity, speed), IDE/LSP quality, testing ecosystem, debugging/profiling, documentation culture, AI tooling integration
- **Evidence**: Package registry statistics. IDE marketplace data. Developer surveys. Specific capabilities or known issues, not general impressions.

### Section 7: Security Profile
- **Required**: CVE class exposure with CWE categories and cross-language comparison, language-level mitigations (completeness of each guarantee), common vulnerability patterns (structurally enabled vs. merely possible), supply chain security, cryptography story
- **Evidence**: CVE data with query methodology and time period. Vulnerability rates must control for codebase size and domain.

### Section 8: Developer Experience
- **Required**: Learnability (time to productivity, steepest curves, available resources), cognitive load (incidental vs. essential complexity), error message quality with specific examples, expressiveness vs. ceremony, community character, job market data
- **Evidence**: Developer surveys for satisfaction/adoption. User studies for learnability. Observable indicators for community (moderation, CoC, contribution rates).

### Section 9: Performance Characteristics
- **Required**: Runtime performance for representative workloads, compilation speed (including incremental), startup time (serverless/CLI relevance), resource consumption, optimization story (perf-critical vs. idiomatic code)
- **Evidence**: Benchmarks with hardware specs, compiler versions, optimization flags. Cite published suites and note biases.

### Section 10: Interoperability
- **Required**: FFI (ease, safety, overhead), embedding/extension, data interchange (JSON, protobuf, gRPC, GraphQL), cross-compilation and WASM, polyglot deployment patterns
- **Evidence**: FFI documentation and known limitations. Production polyglot examples.

### Section 11: Governance and Evolution
- **Required**: Decision-making process and transparency, breaking change frequency and backward compatibility, feature accretion/bloat, bus factor, standardization status
- **Evidence**: Governance documents, RFC repositories, contributor statistics, organizational backing.

### Section 12: Synthesis and Assessment
- **Required**: 3-5 greatest strengths (specific), 3-5 greatest weaknesses (specific), Lessons for Language Design (generic, specific, prioritized, balanced, evidence-grounded), dissenting views with reasoning
- **This section must be ≥20% of total output**

## Output Template

The consensus report uses this exact structure:

```yaml
language: "<Language Name>"
version_assessed: "<Primary version under review>"
council_members:
  apologist: "claude-agent"
  realist: "claude-agent"
  detractor: "claude-agent"
  historian: "claude-agent"
  practitioner: "claude-agent"
schema_version: "1.1"
date: "<YYYY-MM-DD>"
```

Followed by sections 1-12 with the subsection headings shown in `templates/tier1/internal-report.md`.

## Cross-Review Structure (Phase 4)

Two parts:
- **Part A: Independent Assessment** — Reviewing council's perspective before reading the target report (relationship statement, perceived strengths/weaknesses, envy list, warnings)
- **Part B: Response to Internal Report** — Section-by-section response (agreement, disagreement, missing context, comparative notes)

## Integrative Response Structure (Phase 5)

- Summary of cross-review themes
- Section-by-section response (validated findings, revised assessments, defended positions, new insights)
- Updated Lessons for Language Design
