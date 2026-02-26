# Internal Council Report: [Language Name]

```yaml
language: ""
version_assessed: ""
council_members:
  apologist: ""
  realist: ""
  detractor: ""
  historian: ""
  practitioner: ""
schema_version: "1.0"
date: "YYYY-MM-DD"
```

## 1. Identity and Intent

### Origin and Context

<!-- When was the language created, by whom, in response to what problems? What was the state of the art at the time? -->

### Stated Design Philosophy

<!-- What principles did the creators articulate? Quote primary sources where available. -->

### Intended Use Cases

<!-- What domains was the language designed for? Has it drifted? How successfully? -->

### Key Design Decisions

<!-- The 5–10 most consequential decisions. For each: the decision and the designers' rationale. -->

---

## 2. Type System

### Classification

<!-- Static/dynamic, strong/weak, nominal/structural, gradual typing support. -->

### Expressiveness

<!-- Generics, ADTs, dependent types, HKTs, type-level computation. Where does the ceiling hit? -->

### Type Inference

<!-- How much is inferred? Where must the developer annotate? Surprising inference behaviors? -->

### Safety Guarantees

<!-- What does the type system prevent at compile time? What slips through? Specific examples. -->

### Escape Hatches

<!-- Mechanisms to bypass the type system. How often does production code use them? -->

### Impact on Developer Experience

<!-- Effect on readability, onboarding, refactoring, IDE support. -->

---

## 3. Memory Model

### Management Strategy

<!-- Manual, GC (which algorithm?), reference counted, ownership/borrowing, arena-based, hybrid. -->

### Safety Guarantees

<!-- Use-after-free, double-free, buffer overflow, null deref, data race prevention. Compiler vs. runtime vs. none. -->

### Performance Characteristics

<!-- GC pause times, allocation overhead, fragmentation, cache behavior. Cite benchmarks. -->

### Developer Burden

<!-- How much must the developer think about memory? Common mistakes by experienced devs. -->

### FFI Implications

<!-- How does the memory model interact with foreign code? -->

---

## 4. Concurrency and Parallelism

### Primitive Model

<!-- Threads, goroutines, async/await, actors, channels, STM, coroutines. OS-level mapping. -->

### Data Race Prevention

<!-- Compile time, runtime, or not at all. What mechanism? -->

### Ergonomics

<!-- Difficulty of writing correct concurrent code. Common pitfalls. Compiler help. -->

### Colored Function Problem

<!-- Does async/sync divide exist? How severe in practice? -->

### Structured Concurrency

<!-- Supported? If so, how? If not, what patterns emerge? -->

### Scalability

<!-- Performance under high load. Known bottlenecks. Production-scale evidence. -->

---

## 5. Error Handling

### Primary Mechanism

<!-- Exceptions, result types, error codes, panics, monadic, hybrid. -->

### Composability

<!-- Ease of error propagation through call chains. Syntactic support. -->

### Information Preservation

<!-- Stack traces, error chains, structured metadata. Information loss during propagation? -->

### Recoverable vs. Unrecoverable

<!-- Does the language distinguish? How? Problems caused by not distinguishing? -->

### Impact on API Design

<!-- Effect on function signatures, API boundaries, library design. -->

### Common Mistakes

<!-- Anti-patterns the language enables or encourages. -->

---

## 6. Ecosystem and Tooling

### Package Management

<!-- Primary package manager. Maturity, limitations, versioning, dependency resolution, security auditing. -->

### Build System

<!-- Standard build toolchain. Configuration complexity. Build speed. -->

### IDE and Editor Support

<!-- LSP quality. Code completion, refactoring, inline errors. Which editors are well-supported? -->

### Testing Ecosystem

<!-- Built-in testing. Third-party frameworks. Property-based, fuzzing, mutation testing. Ergonomics. -->

### Debugging and Profiling

<!-- Debugger quality. Profiling tools. Observability primitives. Production diagnosis. -->

### Documentation Culture

<!-- Official documentation quality. Community norms. API doc generation. -->

### AI Tooling Integration

<!-- Code generation quality. Training data availability. LSP integration with AI assistants. -->

---

## 7. Security Profile

### CVE Class Exposure

<!-- Most frequent CWE categories. Data from NVD or language-specific databases. Cross-language comparison. -->

### Language-Level Mitigations

<!-- Memory safety, type safety, bounds checking, taint tracking, sandboxing. Completeness of each. -->

### Common Vulnerability Patterns

<!-- Most common security mistakes. Structurally enabled vs. merely possible. -->

### Supply Chain Security

<!-- Vulnerability disclosure, dependency auditing, malicious package detection. -->

### Cryptography Story

<!-- Standard library crypto quality. Audited third-party libraries. Historical footguns. -->

---

## 8. Developer Experience

### Learnability

<!-- Time to productivity. Steepest learning curve points. Available resources. -->

### Cognitive Load

<!-- How much must be held in working memory. Incidental vs. essential complexity. -->

### Error Messages

<!-- Quality, clarity, actionability. Specific good and bad examples. -->

### Expressiveness vs. Ceremony

<!-- Boilerplate requirements. Conciseness vs. readability tradeoffs. -->

### Community and Culture

<!-- Community character. Convention culture. Conflict resolution. -->

### Job Market and Career Impact

<!-- Industry prevalence. Salary data. Hiring difficulty. Obsolescence risk. -->

---

## 9. Performance Characteristics

### Runtime Performance

<!-- Throughput, latency, resource consumption for representative workloads. Cite benchmarks. -->

### Compilation Speed

<!-- Time to compile representative projects. Incremental compilation. Developer iteration impact. -->

### Startup Time

<!-- Cold start performance. Serverless/CLI/latency-sensitive relevance. -->

### Resource Consumption

<!-- Memory footprint, CPU patterns, I/O characteristics. Behavior under constraints. -->

### Optimization Story

<!-- How does perf-critical code differ from idiomatic code? Zero-cost abstractions? -->

---

## 10. Interoperability

### Foreign Function Interface

<!-- Ease of calling into C/C++/others. Safety at FFI boundary. Overhead. -->

### Embedding and Extension

<!-- Can it be embedded? Extended with native modules? Ergonomics. -->

### Data Interchange

<!-- JSON, protobuf, gRPC, GraphQL. Serialization performance and ergonomics. -->

### Cross-Compilation

<!-- Multi-platform/architecture support. WebAssembly. -->

### Polyglot Deployment

<!-- Coexistence with other languages. Microservice boundaries. Build system integration. -->

---

## 11. Governance and Evolution

### Decision-Making Process

<!-- Who controls evolution? BDFL, committee, RFC, corporate, community? Transparency. -->

### Rate of Change

<!-- Breaking change frequency. Backward compatibility. Deprecation policy. -->

### Feature Accretion

<!-- Feature bloat? Widely-regarded mistakes? Removal/deprecation of bad ideas. -->

### Bus Factor

<!-- Dependency on individuals or organizations. Withdrawal risk. -->

### Standardization

<!-- Formal standards? Multiple implementations? Divergence? -->

---

## 12. Synthesis and Assessment

### Greatest Strengths

<!-- 3–5 things this language does better than most or all alternatives. Be specific. -->

### Greatest Weaknesses

<!-- 3–5 things this language does worse than alternatives or gets fundamentally wrong. Be specific. -->

### Lessons for Language Design

<!-- What should a new language learn from this? Avoid? What remains open? Lessons must be generic to language design, not specific to any one project. -->

### Dissenting Views

<!-- Unresolved council disagreements. Each position and its reasoning. -->

---

## References

<!-- All sources cited in the report. Use [KEY] inline, listed here. -->
