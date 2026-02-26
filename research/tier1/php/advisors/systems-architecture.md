# PHP — Systems Architecture Advisor Review

```yaml
role: advisor-systems-architecture
language: "PHP"
agent: "claude-agent"
date: "2026-02-26"
```

## Summary

PHP's systems architecture story is one of accretion, remediation, and surprising resilience. The language was designed for a single developer's personal website in 1994 and now powers approximately 77% of server-side websites on the internet — a dominance that creates both an unassailable installed base and an enormous technical debt burden that constrains every architectural decision. For teams building new systems in 2026, the question is not whether PHP can work at scale (it demonstrably can) but whether the costs of operating it at scale — the compensatory toolchain, the upgrade burden, the fragmented concurrency models, the security vigilance required — are worth bearing relative to alternatives.

The council perspectives collectively identify PHP's systems-level strengths accurately: Composer is a genuinely mature dependency manager, Laravel and Symfony are production-ready frameworks, PHP-FPM's shared-nothing process model provides automatic fault isolation, and the deployment story is among the simplest in the industry. What the council underweights, particularly from a systems perspective, is the *second-order cost* of operating PHP at scale: the static analysis tax (PHPStan/Psalm as compensatory infrastructure), the observability gap (no language-native tracing primitives; APM must be bolted on), the version adoption lag that leaves 38% of production deployments on end-of-life PHP versions [PHP-VERSION-STATS], and the concurrency model fragmentation that makes high-throughput PHP architectures require framework lock-in that the language itself cannot resolve.

The governance picture has improved materially since the PHP Foundation's formation in 2021. With ten funded core developers and $627,000 in annual developer compensation [PHP-FOUNDATION-2024], PHP is no longer a volunteer-dependent project whose trajectory could be altered by one contributor's departure. But the governance model's conservative backward-compatibility commitment means that known design mistakes — type juggling, inconsistent standard library naming, no output escaping by default — are now permanent features of the language. A systems architect must plan for them rather than expect them to be fixed.

---

## Section-by-Section Review

### Section 6: Ecosystem and Tooling

**Accurate claims:**

- **Composer is mature and functional.** All council members correctly identify Composer as a genuine success. The lock file model, PSR-4 autoloading, and semantic versioning support are production-grade. Composer 2.x's parallel downloads dramatically improved installation performance [COMPOSER-V2]. Packagist hosts approximately 500,000+ packages (the "400,000+" figure cited by the apologist and realist is now an undercount as of 2026).

- **PHPStorm is industry-leading.** The practitioner and apologist correctly note that PhpStorm provides comprehensive IDE support. This is accurate and matters operationally — code review ergonomics in large PHP codebases are substantially better than the language's type system would suggest, precisely because the IDE does significant compensatory work.

- **PHPStan adoption is real and growing.** The historian and realist both note PHPStan adoption jumped 9 percentage points to 36% in the 2025 JetBrains survey [JETBRAINS-PHP-2025]. This is accurate and significant as a systems signal (see "Additional Context" below).

- **Testing ecosystem is adequate.** PHPUnit is mature. Pest has genuine adoption in modern Laravel codebases. The practitioner's observation that testing culture is bimodal (Laravel/Symfony projects at 60-80% coverage; WordPress plugins often at 0%) is accurate and operationally important.

**Corrections needed:**

- **The "no built-in `composer audit`" claim is outdated.** Both the detractor and realist state that Composer has no built-in security auditing command and that teams rely on third-party tools like Roave Security Advisories. This was accurate until Composer 2.4 (released September 2022), which added a native `composer audit` command that queries the GitHub Advisory Database. The claim as written is no longer accurate for teams running Composer 2.4+. The practical gap (integration with CI, enforcement, package signing) remains real, but the specific factual claim needs correction.

- **The apologist understates monorepo support gaps.** The apologist does not address monorepo support at all. The practitioner notes it briefly as a pain point. At scale, this is a significant systems concern: there is no first-class PHP monorepo story comparable to Cargo workspaces, Nx, or Turborepo. Available workarounds (symplify/monorepo-builder, beberlei/composer-monorepo-plugin, PMU) work but require non-trivial configuration and introduce tooling fragility. Teams building large internal package ecosystems pay a real price here [MONOREPO-PHP].

- **No council member adequately addresses the observability gap.** PHP has no language-native tracing or metrics primitives. All observability requires external APM tooling. OpenTelemetry PHP's tracing instrumentation reached stability and PHP 8+ added `zend_observer` hooks enabling automatic instrumentation of native extensions [OTEL-PHP-AUTO], but the absence of built-in observability primitives is architecturally significant — particularly for distributed systems where consistent trace propagation across service boundaries requires careful coordination across multiple packages. This is not a critical failure but is a real operational cost that no council member fully surfaces.

**Additional context:**

*The static analysis tax.* The 36% PHPStan adoption figure [JETBRAINS-PHP-2025] should be read as a systems architecture signal: PHPStan and Psalm are not optional enhancements for professional PHP development — they are *compensatory infrastructure* that substitutes for guarantees the language itself cannot provide. Teams operating PHP at scale who do not run static analysis at maximum strictness are accepting a type-safety posture that would be unacceptable in Go, TypeScript, or Rust by default. The direct and indirect costs of this toolchain — initial configuration, per-project baseline files, CI integration, developer education, performance on large codebases (1-5 second analysis latency reported by practitioners [PRACTITIONER-STATIC]) — represent a real systems-level overhead that the language design creates.

*Build system fragmentation as an onboarding cost.* The absence of a standardized build system (noted by the practitioner and detractor) has systems implications beyond convenience. Every project accumulates bespoke invocation sequences in Makefile, `composer.json` scripts, or CI configuration. In a 40-engineer team context, this means onboarding documentation must be maintained separately per project, runbooks diverge, and the institutional knowledge required to operate the system is non-transferable. This is a solvable organizational problem, but it is a structural cost that languages with unified build systems (Go's `go build`, Rust's Cargo, or Java's Gradle/Maven conventions) do not impose.

*Deployment simplicity is genuinely competitive.* Counterbalancing the above: PHP's interpreted, shared-nothing deployment model — `composer install`, configure web server, deploy — remains one of the simplest in production computing. The practitioner's observation that PHP-FPM containers are lightweight (100-200MB) and HTTP-native is accurate [PRACTITIONER-DEPLOY]. For containerized Kubernetes deployments, PHP's operational profile compares favorably to JVM-based alternatives. This is a genuine strength that the detractor undersells.

---

### Section 10: Interoperability

**Accurate claims:**

- **FFI is available but rarely used in production.** All council members correctly characterize FFI as a PHP 7.4+ feature that works but sees low production adoption. The safety concerns (manual memory management, segfaults bypass PHP's memory model, crashes produce C-level stack traces) are real and correctly identified.

- **JSON interoperability is excellent.** The apologist and practitioner correctly note that `json_encode()`/`json_decode()` are fast, reliable, and handle UTF-8 correctly. PHP arrays map naturally to JSON structures, which is a genuine ergonomic advantage for JSON-heavy API services.

- **Polyglot deployment via HTTP is the practical pattern.** The practitioner's observation that PHP naturally occupies the "boring web tier" in polyglot architectures — serving APIs and rendering HTML while delegating computation to Go/Rust/Python microservices — is accurate and reflects real production practice. This is PHP's natural interoperability boundary.

- **gRPC support is real but requires configuration.** The `grpc` extension enables gRPC service communication and is used in production microservice architectures. The practitioner's note that adoption is moderate (teams staying within PHP ecosystem use HTTP+JSON; polyglot teams use gRPC) reflects accurate production patterns.

**Corrections needed:**

- **The realist overstates JSON performance concerns.** The realist describes PHP's JSON encode/decode as "relatively slow compared to dedicated parsers." For typical web payloads (sub-100KB JSON objects), PHP's JSON performance is competitive. The real performance consideration is large payloads (multi-MB responses) or high-frequency serialization, not typical API patterns. This characterization is potentially misleading for architects evaluating PHP for standard API services.

- **The C extension model is PHP's actual primary interoperability story, not FFI.** The historian briefly identifies this correctly, but no council member adequately explains that PHP's production-scale C library integration has always been via compiled extensions, not FFI. The extension ecosystem is mature: `ext-pdo`, `ext-redis`, `ext-amqp`, `ext-gd`, `ext-imagick`, `ext-swoole` — these are the actual interoperability mechanism PHP uses at scale. FFI is an escape hatch for edge cases, not the primary integration story. This distinction matters for architects evaluating PHP's integration surface.

- **Thread-safety model complexity is unaddressed.** No council member discusses the ZTS (Zend Thread Safety) vs. non-ZTS build distinction, which affects embedding scenarios and some concurrency models. This is a deployment consideration for teams that embed PHP or use thread-based concurrency approaches (pthreads extension requires ZTS builds). While niche, it is architecturally relevant for systems architects.

**Additional context:**

*The Facebook/Meta case study is the canonical evidence for PHP interoperability at scale.* Facebook ran PHP alongside C++, Hack, and other languages for years. They chose to scale their PHP monolith rather than break into microservices precisely to maintain development velocity [FACEBOOK-PHP-KEITH]. When the performance ceiling became architecturally blocking, they built HHVM (a custom PHP runtime) rather than rewrite in another language. When HHVM's divergence from standard PHP became maintenance overhead, they created Hack — a PHP-derived language with a static type system. This trajectory is the definitive case study: PHP can coexist in polyglot systems at massive scale, but crossing the performance ceiling requires either custom runtime infrastructure or language migration, not PHP tuning. The realist's reference to this case study is accurate; it deserves greater architectural weight.

*Slack's PHP-to-Hack migration reveals the interoperability ceiling.* Slack launched with a PHP 5 backend, migrated to HHVM in 2016, and progressively adopted Hack [SLACK-HACKLANG]. Their motivation was static type checking, not raw performance — demonstrating that at team scale (hundreds of developers), type system deficiencies become an interoperability problem within the codebase itself. The absence of generics and sound type system forces teams toward either compensatory toolchain investment (PHPStan at maximum strictness) or bespoke type annotation conventions. Both impose team-scale coordination overhead.

*WebAssembly is genuinely not production-ready.* The council members who note this (practitioner: "not production-ready as of 2025") are correct. The php-wasm approach compiles the entire PHP interpreter to WASM — a ~20MB+ payload — which is architecturally unsuitable for most WASM use cases (edge runtimes, browser embedding). PHP's design as a server-side, process-per-request language is fundamentally misaligned with WASM's deployment model. This is likely a permanent limitation, not a temporary gap.

---

### Section 11: Governance and Evolution

**Accurate claims:**

- **RFC process is transparent and public.** All members accurately describe the 2/3 majority voting requirement, public RFC archive, and mailing list discussion model. This governance model is well-documented and consistent with the evidence [PHP-RFC-WIKI].

- **PHP Foundation has materially improved sustainability.** The realist and practitioner correctly note that the Foundation formation in 2021 (following Nikita Popov's reduced involvement) reduced the bus factor from "handful of volunteers" to "funded institution." The Foundation's 2024 impact report confirms 10 funded developers at $627,000 annually, with additional Sovereign Tech Agency project funding [PHP-FOUNDATION-2024]. This is a genuine governance improvement.

- **Annual release cadence and deprecation cycles are accurate.** The realist's claim that PHP 8.0 through 8.4 have released on annual cadence (2020-2024) is correct. The 2-3 year deprecation cycle before removal is accurately documented across council members.

- **Backward compatibility is effectively absolute.** The historian's and detractor's characterization that known mistakes (type juggling, inconsistent function naming) are permanently unfixable due to backward compatibility constraints is accurate. The "Consistent Function Names" RFC [RFC-CONSISTENT-NAMES] is the canonical example: community agreement that the problem is real, no viable path to fixing it.

**Corrections needed:**

- **The detractor overstates PHP's burden from 1998-era design.** The claim that "PHP 8.3 carries the design decisions of PHP 3 from 1998" is accurate in spirit but misleading as written. PHP has removed significant legacy decisions: `register_globals` (removed 5.4), `mysql_*` functions (removed 7.0), `magic_quotes` (removed 5.4), `ereg` functions (removed 7.0). The remaining legacy debt (type juggling in `==`, inconsistent stdlib naming) is real and significant, but characterizing it as "PHP 3 design decisions" without acknowledging the removals understates PHP's cleanup progress.

- **The apologist understates the governance risk in "features accumulate faster than they are removed."** The apologist frames PHP's governance as effective at cleaning house. The historian's evidence is more accurate: PHP has ~1,300 functions in 8.0 versus ~1,000 in 5.0. Removals have occurred, but net function count grew. More importantly, the governance model has a structural asymmetry: adding features requires 2/3 majority; keeping existing features requires no vote at all. This asymmetry systematically biases toward accumulation.

- **No member adequately addresses Rector as a governance tool.** The automated code transformation tool Rector [RECTOR] is a significant but underappreciated aspect of PHP's evolution story. Rector can automate version migrations, compress 6-month manual migrations to days [RECTOR-DOCS], and enforce coding standards at scale. For systems architects evaluating PHP upgrade costs, Rector changes the calculus substantially. MyHeritage's PHP 7.2→8.4 migration (1,300+ files, 190+ commits, spanning 2018-2025 [MYHERITAGE-MIGRATION]) was managed incrementally partly via automated tooling. This tooling should be considered part of the governance infrastructure.

**Additional context:**

*Version adoption lag is a real operational risk.* The practitioner notes that 38% of teams deploy EOL PHP versions (7.4 or earlier) [PHP-SURVEYS]. Zend's PHP version stats (January 2025) confirm PHP 7.4 still at 38.68% adoption [PHP-VERSION-STATS]. This is not merely a developer preference issue — it is an operational security posture issue at industry scale. PHP 7.4 has been end-of-life since November 2022; systems running it are unpatched against vulnerabilities discovered since then. CVE-2024-4577 (PHP-CGI argument injection, CVSS 9.8) affected PHP versions below 8.1.29/8.2.20/8.3.8 and exposed approximately 458,800 instances [CVE-2024-4577]. The combination of slow adoption and PHP's enormous installed base means critical vulnerabilities have outsized blast radius. This is a governance failure not of language design but of upgrade incentive structure.

*The PHP Foundation's Sovereign Tech Agency engagement is a positive governance signal.* The German government's Sovereign Tech Agency commissioned the PHP Foundation to complete four major PHP infrastructure projects in 2024, all successfully delivered [PHP-FOUNDATION-2024]. This public-sector engagement represents a qualitatively different sustainability model than pure corporate sponsorship — it acknowledges PHP as critical public infrastructure and creates funding independence from commercial PHP ecosystem players. No council member references this development.

*The scalar types governance episode defines PHP's fundamental tension.* The historian correctly identifies the 2015 scalar types RFC (108-48 vote, dual-mode weak/strict compromise) as the canonical governance-under-stress example [RFC-SCALAR-TYPES]. The dual-mode `declare(strict_types=1)` design that resulted is simultaneously PHP's most successful recent governance output and its most revealing constraint: the community could not reach consensus on a single type discipline, so it implemented both. Systems architects should understand this not as indecision but as genuine governance under pressure from irreconcilable constituencies (PHP's beginner-friendly legacy base versus its enterprise-scale users). Every major PHP governance decision will carry this tension.

*The 10-year longevity outlook is strong but not unlimited.* PHP powers 77% of server-side websites, which creates extraordinary ecosystem inertia. WordPress alone (43% of all websites [DEVSURVEY]) represents billions of dollars of business logic that cannot be migrated cheaply. The PHP Foundation provides institutional continuity. For a system built in PHP today, 10-year viability is well-supported. The risk is not PHP's abandonment but its perception decline creating talent pipeline challenges: PHP is classified as "stable but in long-term decline" by JetBrains [JETBRAINS-PHP-2025], declining in developer mindshare surveys even as production dominance holds. Teams hiring PHP engineers in 2030 may face increasing competition for diminishing new-entrant talent.

---

### Other Sections: Systems Architecture Concerns

**Section 5 / Concurrency Model (cross-cutting)**

No council section is dedicated to this, but it surfaces in Sections 8 and 12 as a weakness. From a systems architecture perspective, this deserves explicit treatment.

PHP's request-scoped, shared-nothing model (PHP-FPM) is simultaneously its greatest operational simplicity advantage and its primary performance ceiling. Each request spins up a PHP process (or FPM worker) with no shared state, providing automatic fault isolation and eliminating entire categories of race conditions. The practitioner correctly identifies this as "the killer feature" for web application reliability.

But the concurrency picture beyond PHP-FPM is genuinely fragmented. As of 2026, PHP offers five production-capable concurrency approaches: PHP-FPM (synchronous processes), Swoole (coroutine-based, C extension), ReactPHP (event loop, pure PHP), Amp v3 (Fibers-based), and FrankenPHP (worker mode via Go goroutines). These models are architecturally incompatible — libraries designed for one model may not work with another, and switching concurrency model mid-project can require significant refactoring. Benchmarks suggest FrankenPHP worker mode and Swoole can achieve >10x throughput improvement over FrankenPHP + PHP-FPM for I/O-bound workloads [FRANKENPHP-BENCH], but this performance comes with framework coupling that prevents easy migration.

For systems architects: PHP is architecturally suitable for request-response web workloads at significant scale using standard PHP-FPM. It is architecturally inappropriate as a primary language for systems requiring high-frequency event processing, persistent connections at scale, or low-latency stream processing. The async extensions exist and perform well in benchmarks, but the ecosystem fragmentation means you are choosing not just a concurrency model but a framework ecosystem.

**Section 9 / Type System (cross-cutting)**

The gradual type system has systems implications that no council member fully develops. PHP's `declare(strict_types=1)` is per-file, which means type discipline in a large codebase is enforced by convention rather than by language design. A file missing the declaration can silently coerce types when calling into strictly-typed code. In a 500k-line codebase maintained by 40 engineers, enforcing consistent type discipline requires:

1. Linter/CI rule mandating `declare(strict_types=1)` in all files
2. PHPStan or Psalm at a configured strictness level
3. PR review enforcement
4. Baseline management (PHPStan ignores for legacy code)

This is manageable, but it is four layers of process to achieve what statically-typed languages provide by default. The 64% of PHP projects not running PHPStan [JETBRAINS-PHP-2025] are accepting meaningful type-safety debt at each engineer's workstation, silently.

---

## Implications for Penultima

PHP's systems-level story yields several high-confidence design principles for Penultima:

**1. Compensatory toolchains are a language design failure.** PHP requires PHPStan, Psalm, Rector, and a quality IDE to be professionally productive at scale. Each represents a gap in the language's own guarantees. Penultima should provide static type safety, automated upgrade paths, and high-quality error messages as language-level features, not as afterthoughts addressed by ecosystem tooling. The cost is paid once by language designers; without it, every project pays it independently.

**2. Build and deployment story must be first-class.** PHP's lack of a standard build system creates per-project bespoke tooling that fragments team knowledge and increases onboarding cost. Penultima should have an opinionated, extensible build system with workspace/monorepo support built in. The lesson from PHP (and npm/pip before Cargo) is that retrofitting build tooling is harder than designing it in.

**3. Observability primitives belong in the language runtime, not in bolted-on APM.** PHP has no native tracing or metrics primitives; all observability requires third-party instrumentation. Modern production systems require distributed tracing, structured logging, and metrics collection. Penultima should define standard interfaces for these in the standard library, with optional pluggable implementations, rather than leaving each project to negotiate APM vendor lock-in independently.

**4. Backward compatibility must have an escape valve.** PHP's governance cannot fix type juggling, cannot fix inconsistent stdlib naming, cannot fix insecure output defaults — because backward compatibility is effectively absolute. Penultima needs a principled answer to the question "how do we break things that need breaking?" — whether via edition-based evolution (Rust's approach), explicit deprecation windows with compiler-enforced migration, or formal breakage budgets. The cost of a wrong answer is permanent: live with the mistake, or fragment the language.

**5. Security-by-default is non-negotiable at web scale.** PHP's security profile — no output escaping by default, permissive file inclusion semantics, type coercion enabling authentication bypasses — demonstrates the cost of designing for convenience rather than safety. The CVE-2024-4577 case (458,800 exposed instances within months of disclosure [CVE-2024-4577]) illustrates what happens when a language with 77% market share has a critical vulnerability in its CGI implementation. Penultima must make secure patterns the path of least resistance: output escaping as default, parameterized queries as the only first-class database API, type-safe comparisons that eliminate coercion-based bypasses.

**6. Governance structure should encode the ability to evolve.** PHP's RFC process is transparent and broadly fair, but its 2/3 majority requirement combined with a large voting electorate of diverse constituencies produces conservative outcomes. Penultima's governance should include a mechanism for breaking changes that bypasses the inertia — perhaps a smaller core committee with explicit authority to make backward-incompatible improvements on a defined cadence, with community RFC process reserved for additive changes.

**7. Talent pipeline is a long-term systems risk.** JetBrains classifies PHP as "stable but in long-term decline" in developer mindshare. A language built today should have a clear story for attracting new developers over a 10-year horizon. PHP's experience suggests that production dominance does not inoculate against talent pipeline decline if the language's reputation does not match its current quality. Penultima must be designed to be attractive to new engineers, not just serviceable for those already invested.

---

## References

- **[PHP-FOUNDATION-2024]** PHP Foundation. "The PHP Foundation: Impact and Transparency Report 2024." https://thephp.foundation/blog/2025/03/31/transparency-and-impact-report-2024/
- **[PHP-FOUNDATION-2023]** PHP Foundation. "The PHP Foundation: Impact and Transparency Report 2023." https://thephp.foundation/blog/2024/02/26/transparency-and-impact-report-2023/
- **[JETBRAINS-PHP-2025]** JetBrains. "The State of PHP 2025." https://blog.jetbrains.com/phpstorm/2025/10/state-of-php-2025/
- **[JETBRAINS-DEVECOSYSTEM-2025]** JetBrains. "State of Developer Ecosystem 2025." https://devecosystem-2025.jetbrains.com/
- **[DEVSURVEY]** Cross-Language Developer Survey Aggregation. Evidence file: `evidence/surveys/developer-surveys.md`
- **[CVE-PHP]** CVE Pattern Summary: PHP. Evidence file: `evidence/cve-data/php.md`
- **[CVE-2024-4577]** Censys. "June 10, 2024: PHP-CGI Argument Injection Vulnerability (CVE-2024-4577)." https://censys.com/cve-2024-4577/
- **[SLACK-HACKLANG]** Slack Engineering. "Hacklang at Slack: A Better PHP." https://slack.engineering/hacklang-at-slack-a-better-php/
- **[SLACK-PHP]** Slack Engineering. "Taking PHP Seriously." https://slack.engineering/taking-php-seriously/
- **[FACEBOOK-PHP-KEITH]** Software Engineering Daily. "Facebook PHP with Keith Adams." https://softwareengineeringdaily.com/2019/07/15/facebook-php-with-keith-adams/
- **[MYHERITAGE-MIGRATION]** MyHeritage Engineering. "How AI Transformed Our PHP Upgrade Journey." https://medium.com/myheritage-engineering/how-ai-transformed-our-php-upgrade-journey-c4f96a09c840
- **[PHP-VERSION-STATS]** Stitcher.io. "PHP Version Stats June 2025." https://stitcher.io/blog/php-version-stats-june-2025
- **[RECTOR]** Rector Project. "Fast PHP Code Upgrades." https://getrector.com/
- **[RECTOR-DOCS]** Rector Documentation. https://getrector.com/documentation
- **[OTEL-PHP-AUTO]** OpenTelemetry. "PHP Auto-Instrumentation." https://opentelemetry.io/blog/2023/php-auto-instrumentation/
- **[OTEL-PHP]** OpenTelemetry. "PHP Documentation." https://opentelemetry.io/docs/languages/php/
- **[COMPOSER-V2]** Composer. "Composer 2.0 Release Notes." https://blog.packagist.com/composer-2-0-is-now-available/
- **[MONOREPO-PHP]** LogRocket. "Hosting all your PHP packages together in a monorepo." https://blog.logrocket.com/hosting-all-your-php-packages-together-in-a-monorepo/
- **[RFC-SCALAR-TYPES]** PHP Wiki. "Scalar Type Hints RFC." https://wiki.php.net/rfc/scalar_type_hints
- **[RFC-CONSISTENT-NAMES]** PHP Wiki. "Consistent Function Names RFC." https://wiki.php.net/rfc/consistent_function_names
- **[PHP-RFC-WIKI]** PHP Wiki. "Requests for Comments." https://wiki.php.net/rfc
- **[FRANKENPHP-BENCH]** Dev.to. "Performance benchmark of PHP runtimes." https://dev.to/dimdev/performance-benchmark-of-php-runtimes-2lmc
- **[PHP-SURVEYS]** Zend/Perforce PHP Landscape Report 2025. https://www.zend.com/resources/php-landscape-report
- **[ZEND-MIGRATION]** Zend. "PHP Migration Trends 2025." https://www.zend.com/blog/php-migration-trends
- **[PRACTITIONER-STATIC]** Practitioner council member evidence, citing PHPStan inline error reporting latency: `research/tier1/php/council/practitioner.md`
- **[PRACTITIONER-DEPLOY]** Practitioner council member evidence, citing container size: `research/tier1/php/council/practitioner.md`
- **[BETTERSTACK-PHP-APM]** Better Stack. "Best PHP Application Monitoring Tools in 2026." https://betterstack.com/community/comparisons/php-application-monitoring-tools/
