# C# — Systems Architecture Advisor Review

```yaml
role: advisor-systems-architecture
language: "C#"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

C# is among the most systems-architecture-ready managed languages in production use. Its toolchain has genuine depth — Roslyn as compiler-as-a-service, MSBuild with Central Package Management for monorepo governance, NuGet Audit integrated into the SDK build pipeline, and NativeAOT for container-native deployment — and the breadth of its production deployment patterns (ASP.NET Core microservices, Unity game scripting, Azure serverless functions, Windows enterprise applications) places unusual demands on its interoperability and upgrade stories. The council has done solid work identifying the major strengths and failure modes, but with uneven depth. The apologist undersells the .NET Framework migration burden; the realist correctly identifies it as a multi-year project for large codebases; the practitioner's "three types of C#" framing is the most practically useful for a systems analysis.

The most underemphasized systems-level concern across all five council members is **GC tail latency variability**. Documented production regressions — including a measured 8× increase in average GC pause time following a .NET 8 patch-level change at Roblox [DOTNET-101746] — establish that GC pause behavior is not a stable contract that production services can rely on across runtime updates. For latency-sensitive systems, this is a first-order operational concern that the council discusses but does not weight proportionately. Separately, the governance section accurately describes the .NET Foundation independence question but underemphasizes the operational consequence: the LTS/STS release cadence creates non-trivial CI/CD and dependency management decisions for enterprise teams that must be made consciously and revisited annually.

The interoperability picture is accurately characterized as strong within the .NET ecosystem and meaningfully weaker at ecosystem boundaries. The council's treatment of COM interoperability as "Windows-specific technical debt" is correct, and the Blazor WebAssembly download size and startup latency concerns are accurately documented. What is missing from most council perspectives is the emergence of `LibraryImport` (source-generated P/Invoke, .NET 7+) as a material improvement to native interop ergonomics and performance, and the weakness of the Python/ML interop story as a practical limitation now that AI workloads demand C# code calling Python data pipelines or vice versa.

---

## Section-by-Section Review

### Section 6: Ecosystem and Tooling

**Accurate claims:**

The council correctly identifies the Roslyn toolchain quality as a differentiator. The historian, apologist, and practitioner all note that IDE integration through Roslyn's semantic model API — rather than heuristic text parsing — produces a qualitatively different refactoring and code navigation experience than ecosystems where the compiler is a black box. This is accurate and undersells a specific implication: custom Roslyn analyzers can enforce architectural rules at compile time with full semantic accuracy. A team that has modeled its layering rules as Roslyn diagnostic analyzers gets automatic, IDE-integrated enforcement across all PRs without runtime tests or external tools. This is a capability most languages cannot match [ROSLYN-GH].

The practitioner's identification of NuGet as having meaningful supply chain vulnerability — with specific campaigns (time-delayed logic bombs, JIT-hooking credential theft, 60-package batch attacks in July 2024) — is the most accurate characterization of the NuGet security posture [HACKERNEWS-LOGICBOMB] [HACKERNEWS-60PKG]. The realist's balanced treatment (NuGet Audit is a genuine improvement since .NET 8; it does not eliminate risk) is also accurate.

The claim that incremental Roslyn compilation is "seconds, not minutes" for large solutions is accurate for incremental rebuilds. Full clean builds of solutions with 100+ projects remain measured in minutes, which is accurate and appropriately noted.

**Corrections needed:**

The apologist describes NuGet as providing "robust package management" with "vulnerability scanning built in" without noting the organizational engineering required to realize that security. NuGet Audit (enabled by default since .NET 8 SDK) scans only for packages with known CVE registrations — it does not detect novel malicious packages, time-delayed logic bombs, or JIT-hooking attacks [NUGET-ENTERPRISE]. The council's collective characterization slightly overstates the default protection level. The accurate description: NuGet Audit is a necessary baseline, not sufficient enterprise security.

The historian's section 6 does not address **Central Package Management (CPM)**, which became stable in NuGet 6.2 (2022) and represents a significant improvement in large-codebase dependency governance. CPM allows all package versions to be managed in a single `Directory.Packages.props` file at the repository root, eliminating per-project version declarations and the associated diamond-dependency conflicts that plague monorepos. For the systems-architecture question — how does C# perform at scale in teams? — CPM is a relevant and accurate answer to a real problem that the council largely ignores.

**Additional context:**

MSBuild's project graph complexity at scale deserves more treatment than any council member provides. The XML-based project file format, while much improved by SDK-style "short form" `.csproj` files, exposes a build property inheritance model that becomes difficult to reason about as solution complexity grows. `Directory.Build.props` and `Directory.Build.targets` enable centralizing MSBuild property definitions, but the property evaluation order (import sequence, override precedence, conditional evaluation) is non-obvious. Teams maintaining solutions with 50+ projects routinely report surprising build behaviors from property inheritance issues. This is not a fundamental design flaw — MSBuild is capable — but it represents a scaling surface where the mental model breaks down for developers who do not specialize in build engineering.

The CI/CD integration story (GitHub Actions `actions/setup-dotnet`, Azure DevOps pipelines, Docker multi-stage build support) is genuinely strong and none of the council members are wrong about it. The missing dimension is **reproducible builds**. .NET's deterministic compilation flag (`/deterministic`) produces byte-identical artifacts for identical inputs, which enables supply chain verification. Enabling it requires explicit configuration and discipline around embedding source information (SourceLink, source-mapped PDBs), and adoption across enterprise teams is inconsistent. For a language with C#'s supply chain attack surface, reproducible builds should be a default — it is not.

### Section 10: Interoperability

**Accurate claims:**

The practitioner's characterization of P/Invoke as "functional but requiring marshaling discipline" is accurate. The detractor's identification of COM interoperability as Windows-specific technical debt that generates "inscrutable error messages" when something goes wrong is accurate and reflects real production experience. The detractor's analysis of Blazor WebAssembly — 15–20 MB download for a minimal application, with startup latency and browser-sandbox debugging limitations — is accurate and well-supported. None of these characterizations require correction.

The historian's note that the ECMA-335 CIL specification enables intra-.NET-ecosystem polyglot interoperability (F#, VB.NET, C# interoperating at the assembly boundary with zero overhead) is accurate and underemphasized. In practice, this means a C# codebase can consume F# modules for domain modeling — where F# discriminated unions, railway-oriented error handling, and immutability-first design are natural — without any cross-language overhead. This is a genuine architectural option that most council members do not mention.

**Corrections needed:**

Three council members treat P/Invoke as essentially unchanged from its .NET Framework form. This is outdated. The `LibraryImport` attribute and source-generated P/Invoke, introduced in .NET 7 (2022) and recommended as the default in .NET 7+ documentation [MS-LIBRARYIMPORT], represent a material change in how native interop works. Runtime-based P/Invoke uses reflection to determine marshaling at call time, generates some managed-to-native transition overhead, and prevents trimming (because the marshaling code cannot be statically analyzed). `LibraryImport` generates all marshaling code at compile time, eliminates the runtime overhead, and makes the native interop layer AOT-and-trim-safe. For a systems architecture review, this matters: NativeAOT deployment — the dominant model for container-native C# applications — requires `LibraryImport` or will fall back to unsupported patterns.

The practitioner correctly notes that Blazor WASM has download size problems but does not address the **server-side Blazor scalability concern** in adequate depth from a systems architecture perspective. Blazor Server maintains a persistent WebSocket connection and server-side DOM state for each connected client. A server hosting 1,000 simultaneous Blazor Server users maintains 1,000 active SignalR connections and their associated server-side memory state. This is not a browser-side problem; it is a server resource scaling problem with no equivalent in JavaScript/TypeScript web architectures. The detractor mentions "obvious scalability implications" but the mechanism deserves explicit framing for the consensus report.

**Additional context:**

The **Python/ML interoperability gap** is underrepresented across all council perspectives. The dominant trajectory in AI development in 2025–2026 is Python toolchains for training, evaluation, and serving (PyTorch, Hugging Face, LangChain). C# has Semantic Kernel [CS-BRIEF] as an AI orchestration framework and ML.NET for inference, but teams building systems that must call Python models or integrate with Python pipelines face a non-trivial boundary. Python.NET (pythonnet) provides Python embedding, but it requires distributing a Python runtime, managing the GIL, and accepting that the integration is not native [PYTHONNET]. For enterprise systems teams evaluating C# for AI-adjacent workloads in 2026, the Python interop story is weaker than either the Java world (via JVM-native Python runtimes) or the Rust world (via native Python C extension patterns). This is not a fatal limitation — most teams use HTTP/gRPC boundaries rather than in-process embedding — but it is a real systems design constraint.

The **Unity ecosystem split** identified by the practitioner and noted briefly by the detractor deserves emphasis from a systems architecture perspective: Unity currently runs on Mono (a fork of the .NET runtime from ~2012) for most targets, with CoreCLR adoption planned for Unity 6 and later [UNITY-CORECLR]. This means Unity C# developers cannot use most BCL improvements from the past decade — no `Span<T>`, no `IAsyncEnumerable<T>`, no `System.IO.Pipelines`, and limited async/await support. A developer who writes C# for Unity and C# for ASP.NET Core is working in two languages that share syntax but have materially different standard library surfaces. For organizations whose C# footprint spans both game development and services, this creates a team knowledge partitioning problem that is underacknowledged.

### Section 11: Governance and Evolution

**Accurate claims:**

The detractor's account of the .NET Foundation governance crisis (2020 board resignations, including Nate McMaster's statement that "The .NET Foundation does not have sufficient independence from Microsoft to act in the best interests of the broader .NET community" [FOUNDATION-RESIGN]) is accurate and appropriately weighted. The realist's assessment that this represents a "governance risk" for enterprise adopters is correct.

The historian's framing of the annual release cadence as providing predictable innovation is accurate. The LDM meeting notes being publicly accessible on GitHub is accurate and is a genuine differentiator for understanding language design decisions. The backward compatibility commitment — no features removed since C# 1.0, breaking changes documented and explicitly managed — is accurately characterized as a hard institutional constraint rather than a best-effort policy [MS-BREAKING].

The primary constructors controversy (C# 12, 2023) and its reception is accurately described by the detractor [DEVCLASS-PRIMARYCTOR]. The case is well-made that the annual release cadence can pressure features to ship with underresolved design tensions.

**Corrections needed:**

The apologist's characterization of the .NET Foundation as providing "independent nonprofit stewardship" overstates the foundation's independence. The 2020 governance crisis is a matter of documented public record, and the foundation's formal governance structure does not provide the community with recourse over Microsoft's technical direction, patent decisions, or resource allocation. The accurate characterization is that the .NET Foundation provides licensing, trademark governance, and community coordination for the .NET ecosystem while Microsoft retains effective control over language and runtime direction. Some council perspectives (realist, historian) are accurate about this; the apologist is not.

Several council members present the LTS/STS cadence as a simple good (predictable upgrade cycle). This underrepresents the operational complexity it creates. LTS releases (every two years, three-year support: .NET 6, .NET 8, .NET 10) are the appropriate targets for enterprise organizations. STS releases (18-month support: .NET 7, .NET 9) are appropriate for teams that want early access to performance improvements and language features but accept more frequent upgrade cycles. For an organization running 50+ microservices, tracking which services are on LTS vs. STS, planning support end-of-life migrations, and managing differential upgrade schedules between services is non-trivial operational work. The practitioner acknowledges this ("teams run C# 8 features in a C# 10 compiler on .NET 6") without naming the governance mechanism that drives it.

**Additional context:**

The **.NET Framework to .NET Core migration burden** is the most systems-significant governance issue that the council treats inconsistently. The apologist frames the open-source/cross-platform transition as a success story. The practitioner frames it accurately: "many organizations are stuck in this gap, running workloads on .NET Framework that cannot receive new language features or performance improvements and that will eventually lose support." .NET Framework 4.8.1 receives security patches only; all new feature development and most performance work targets .NET Core (.NET 5+). Organizations whose codebase depends on .NET Framework technologies that have no .NET Core equivalents — WCF server-side hosting (replaced by CoreWCF, a community project), certain Windows-specific APIs, some Web Forms functionality — face a genuine rewrite decision, not a migration. The realist's "multi-year project for large codebases" characterization is accurate. The practical implication for a 500,000-line enterprise codebase on .NET Framework 4.8 in 2026 is that it is running on a platform that will never receive new language features, will not improve in performance, and will eventually lose even security support.

**The bus factor concern** raised by the detractor ("single-vendor control is a concentration risk") is legitimate but has a specific systems-architecture expression that none of the council members articulate: if Microsoft's organizational priorities shift substantially — toward Python for AI, toward TypeScript for frontend, toward any other platform — the consequence is not that C# stops receiving security patches. The consequence is that C#'s development roadmap shifts toward Microsoft's product priorities rather than the community's architectural needs. The discriminated union gap (24 years, now closing in C# 15) is the clearest historical evidence: it delayed because it was not priority for Microsoft's immediate product surface, despite consistent community demand. For an organization making a 10-year platform bet on C#, this is the relevant risk — not abandonment, but misalignment.

### Other Sections: Systems-Architecture Concerns

**Section 4: Concurrency (async/await at production scale)**

The council's treatment of async/await failure modes is accurate at the individual-feature level but does not address the **team-scale migration problem**. When a codebase begins as synchronous and async/await is introduced, the colored-function property means that every async method in the call chain requires its callers to become async. In a 500,000-line codebase, this propagation can span hundreds of files and create a multi-quarter migration project. The alternative — mixing sync and async with `.Result`/`.Wait()` bridging — creates deadlock risk under specific execution contexts (WPF, ASP.NET classic, Blazor Server). David Fowler's ASP.NET Core diagnostic scenarios repository documents this class of failure explicitly [FOWLER-ASYNCDIAG].

The practical consequence for large-team development: in C# codebases that started before C# 5 (2012), the async/await migration is still incomplete in 2026. Teams operating in this partial-migration state are in the highest-risk configuration — they have async code that cannot be safely bridged to the synchronous caller model they have not yet migrated. This is not an abstract concern; the practitioner's description of "enterprise line-of-business C#" with "`async/await` layer applied inconsistently over a codebase that started synchronous" is an accurate description of production systems in this state.

**Section 9: Performance (GC tail latency as a production contract)**

The detractor's GC analysis is the most technically accurate perspective on a systems-architecture concern that receives insufficient weight from other council members. The specific Roblox regression (dotnet/runtime #101746) deserves explicit emphasis: a `.NET 8` patch-level release changed the Gen0 budget behavior in a way that produced an **8× increase in average GC pause** at Roblox's production workload scale [DOTNET-101746]. The change was not documented as a breaking change. It was discovered via profiling under production load. It was eventually fixed, but the timeline from discovery to fix required the affected team to maintain an instrumentation and alerting capability that most enterprise teams do not have.

The systems-architecture implication is direct: GC pause behavior is not a stable contract for production services built on .NET. The runtime team does not formally commit to GC pause behavior in minor or patch releases, yet production SLOs for latency-sensitive services depend on it. Language designers and runtime teams should treat GC pause guarantees as a first-class SLO that requires the same breaking-change discipline as API surface changes.

**Section 7: Security (NativeAOT and observability)**

The council's security analysis focuses primarily on the NuGet supply chain and the managed memory safety guarantee. A systems-architecture concern that none of the council members raise: **NativeAOT's impact on production observability**. NativeAOT-compiled deployments eliminate JIT compilation but also eliminate or restrict several runtime diagnostics mechanisms that production engineering teams rely on. Dynamic instrumentation tools (`dotnet-trace`, some diagnostic event providers), runtime profiling via reflection-based profilers, and some APM agent implementations do not function or function with reduced capability against NativeAOT binaries [MS-NATIVEAOT]. Teams adopting NativeAOT for container deployment — which Microsoft promotes as a production pattern since .NET 8 — must evaluate their observability stack for NativeAOT compatibility. This is a production readiness requirement, not a security concern per se, but it falls in the operational systems architecture domain and is worth flagging for the consensus report.

---

## Implications for Language Design

The C# production record across large-scale, long-running systems offers eight clear lessons for language designers evaluating systems-level tradeoffs.

**1. Build system complexity is a long-term ownership cost that compounds with codebase size — design for it explicitly.**

MSBuild is capable, and the SDK-style project file format substantially improved on the verbose XML of early .csproj files. But MSBuild's property evaluation model — import order, conditional expressions, property overrides via `Directory.Build.props`, target execution sequencing — is not learnable from first principles by most developers. Teams building large .NET solutions encounter MSBuild complexity as they grow, not when they start, and by the time the complexity bites they have significant investment in the existing structure. Language designers should consider whether the build system model — which is often a language design decision (Cargo for Rust, go build for Go, Gradle for Kotlin) — has a clearly teachable mental model that remains valid at repository scale.

**2. Package management at enterprise scale requires structural controls that must be designed in, not bolted on.**

NuGet's documented attack surface — time-delayed logic bombs, JIT-hooking credential theft, wallet-stealing packages, batch supply chain attacks — reflects what happens when a widely-adopted package registry grows without assuming adversarial pressure on its publication pipeline [HACKERNEWS-LOGICBOMB] [OFFSEQ-NUGET]. NuGet Audit, package signing, and source mapping are all reactive additions. Central Package Management is a governance improvement for large codebases. But none of these were part of the initial NuGet design. Language ecosystems that anticipate reaching a scale where supply chain attacks become economically motivated should design package registry security controls — publisher verification, delayed publication with automated behavioral analysis, organizational dependency approval workflows — before the ecosystem is large enough to make such controls contentious to add.

**3. GC pause behavior should be treated as a language contract, not an implementation detail.**

The Roblox .NET 8 regression — 8× GC pause increase from a patch-level change — was not documented as a breaking change because GC pause behavior is not a formal part of the .NET runtime contract [DOTNET-101746]. This is incorrect for latency-sensitive production services, which build SLOs around observed GC behavior. Language designers building managed runtimes should define GC pause guarantee tiers (best-effort, advisory, contractual), publish them as part of the runtime specification, and apply breaking-change review discipline to regressions against any committed tier. The cost of this rigor is engineering discipline; the cost of its absence is silent production degradation that teams discover through alerting.

**4. The async colored-function problem is a migration cliff, not just an ergonomic inconvenience.**

Async/await's viral propagation through call chains is widely documented [NYSTROM-COLOR]. What is underemphasized in language design discussions is the systems consequence: codebases that were built synchronously and have `async`/`await` added incrementally are in the most dangerous operational configuration — they have async code that cannot be safely composed with their unadapted synchronous callers without creating deadlock risk. Languages that introduce concurrency after a codebase has accumulated must offer either transparent concurrency (no function coloring) or a safe, mechanical migration path. C#'s `ConfigureAwait(false)` discipline and Stephen Cleary's widely-referenced guidance [CLEARY-DONTBLOCK] are evidence that the current model requires expert knowledge for safe migration. Language designers should treat the partial-migration state as a primary failure mode to design around.

**5. Compiler-as-a-service is architecture enforcement infrastructure — design the compiler API as a first-class deliverable.**

Roslyn's semantic API enables not just IDE intelligence but enforcement: teams write custom Roslyn analyzer diagnostics that enforce layering rules, disallow specific patterns, require specific logging calls, or detect architecture violations at compile time [ROSLYN-GH]. This is a capability that most language ecosystems cannot match because their compilers do not expose semantic models to tooling. For large-team C# development, custom analyzers function as living architecture documentation — the rules are executable, integrated into the IDE, and enforced in CI. Language designers should treat the compiler's programmatic interface as first-class infrastructure with the same backward-compatibility commitment as the language itself.

**6. A layered compilation model (source → bytecode → native) enables runtime diversity at the cost of deployment complexity.**

C#'s compilation model — source to CIL, CIL to native via JIT or NativeAOT — means that runtime alternatives (Mono for Unity, NativeAOT for containers, Wasm for browser) do not require language changes. Adding NativeAOT to .NET did not require a new language; it required a new CIL-to-native compiler backend. This architectural layering is a genuine design success. The systems cost is that each deployment target has different capability profiles: reflection works in JIT, is limited in NativeAOT; certain diagnostic tools work in JIT, fail against NativeAOT; COM interop works on Windows CLR, is unsupported in NativeAOT. Language designers adopting a bytecode intermediate should make capability profiles per deployment target an explicit, queryable, and documented part of the platform contract.

**7. Single-vendor governance enables rapid roadmap execution but creates feature priority misalignment risk for communities.**

C#'s 24-year discriminated union gap is not evidence that DUs are hard to design — F# (which runs on the same CLR) had them at launch in 2005. It is evidence that a language controlled by a single vendor delivers features on the vendor's product timeline, not the community's. The feature was consistently prioritized below what served Microsoft's immediate product surface. For language designers evaluating governance models: single-vendor control produces rapid execution on features the vendor needs (async/await drove Azure's success; records drove JSON serialization performance) and slow execution on features the community needs that don't align with current vendor priorities. The choice between vendor control and community governance is a systems-level decision about whose priorities the language serves, not just a process question.

**8. Backward compatibility as a constraint must be explicitly funded — it is not free.**

C#'s 24-year commitment to never removing features and always compiling old code has enabled organizational confidence in platform upgrades. The cost is explicit: `async void` cannot be removed despite being a documented footgun; nullable reference types cannot be made runtime-enforced without a type system break; old collection APIs persist alongside modern equivalents. Language designers must decide whether backward compatibility is a hard constraint (C#'s model) or a versioned commitment (Python 2/3's model) and fund it accordingly. The "never break" model requires that every new feature be designed around all existing features, which scales in difficulty with language age. The "periodic break" model requires investment in migration tooling. Neither is free; the choice should be deliberate and explicitly funded.

---

## References

[ROSLYN-GH] "dotnet/roslyn." GitHub. https://github.com/dotnet/roslyn

[NUGET-ENTERPRISE] "NuGet in the Enterprise, in 2025 and Beyond." Inedo Blog. https://blog.inedo.com/nuget/nuget-in-the-enterprise

[HACKERNEWS-LOGICBOMB] "Hidden Logic Bombs in Malware-Laced NuGet Packages Set to Detonate Years After Installation." The Hacker News, November 2025. https://thehackernews.com/2025/11/hidden-logic-bombs-in-malware-laced.html

[HACKERNEWS-60PKG] "60 New Malicious Packages Uncovered in NuGet Supply Chain Attack." The Hacker News, July 2024. https://thehackernews.com/2024/07/60-new-malicious-packages-uncovered-in.html

[OFFSEQ-NUGET] "Four Malicious NuGet Packages Target ASP.NET Developers With JIT Hooking." OffSeq Threat Radar, August 2024. https://radar.offseq.com/threat/four-malicious-nuget-packages-target-aspnet-develo-3558d828

[DOTNET-101746] dotnet/runtime GitHub Issue #101746 — .NET 8 P99 GC pause regression at Roblox. https://github.com/dotnet/runtime/issues/101746

[MS-LIBRARYIMPORT] "LibraryImport attribute — .NET interop source generation." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke-source-generation

[FOUNDATION-RESIGN] Multiple public resignation statements, August–November 2020. McMaster, Nate; Galloway, Jon. Documented on GitHub dotnet/foundation issues and public blog posts.

[DEVCLASS-PRIMARYCTOR] "New C# 12 feature proves controversial: Primary constructors 'worst feature I've ever seen implemented'." DevClass, April 2024. https://devclass.com/2024/04/26/new-c-12-feature-proves-controversial-primary-constructors-worst-feature-ive-ever-seen-implemented/

[FOWLER-ASYNCDIAG] Fowler, David. "ASP.NET Core Diagnostic Scenarios — Async Guidance." GitHub. https://raw.githubusercontent.com/davidfowl/AspNetCoreDiagnosticScenarios/master/AsyncGuidance.md

[CLEARY-DONTBLOCK] Cleary, Stephen. "Don't Block on Async Code." blog.stephencleary.com, 2012. https://blog.stephencleary.com/2012/07/dont-block-on-async-code.html

[NYSTROM-COLOR] Nystrom, Bob. "What Color Is Your Function?" stuffwithstuff.com, 2015. https://journal.stuffwithstuff.com/2015/02/01/what-color-is-your-function/

[UNITY-CORECLR] "CoreCLR and .NET Modernization — Unite 2024." Unity Discussions. https://discussions.unity.com/t/coreclr-and-net-modernization-unite-2024/1519272

[PYTHONNET] "Python for .NET (pythonnet)." GitHub. https://github.com/pythonnet/pythonnet

[MS-NATIVEAOT] "Native AOT deployment overview — .NET." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/

[MS-BREAKING] ".NET Breaking Changes Guide." Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/core/compatibility/breaking-changes

[CS-BRIEF] C# Research Brief, Penultima Project, 2026-02-27. research/tier1/cs/research-brief.md

[TECHEMPOWER-R23] "TechEmpower Framework Benchmarks — Round 23." February 24, 2025. https://www.techempower.com/benchmarks/

[SO-2024] "Stack Overflow Annual Developer Survey 2024." Stack Overflow. https://survey.stackoverflow.co/2024/
