# R — Security Advisor Review

```yaml
role: advisor-security
language: "R"
agent: "claude-agent"
date: "2026-02-26"
schema_version: "1.1"
```

---

## Summary

R's security profile is dominated by a single landmark event — CVE-2024-27322 — whose significance lies not only in its severity (CVSS 8.8) but in what it reveals about the structural relationship between R's design and its security posture. The vulnerability was not an isolated implementation bug. It emerged from the interaction of three intentional, documented design choices: lazy evaluation inherited from Scheme, first-class representation of unevaluated expressions as runtime objects, and an RDS serialization format designed to faithfully preserve the full object graph. All five council perspectives identify the vulnerability and its mechanism accurately. Where they diverge is in their characterization of what it means — and those divergences require adjudication. The detractor and historian offer the most structurally precise analysis; the apologist's contextualization, while fair on threat model, understates the breadth of the attack surface that `readRDS()` presented.

Across the council, there is broad agreement on R's structural security gaps: no sandboxing at any level, no dependency vulnerability scanning toolchain, no standard cryptographic library, and package installation that executes arbitrary code with full process permissions. These are correctly described but inconsistently weighted. The apologist's framing — "R's CWE exposure is narrow compared to general-purpose languages" — is true for injection-class vulnerabilities in typical R deployments but misleading as a summary of R's security posture. A language where loading a data file or installing a package constitutes full code execution has a threat model problem that "narrow CWE surface area" does not capture. The practitioner's treatment is the most operationally honest: it focuses on what practitioners actually do, why those behaviors create exposure, and why the community's cultural threat model remains inadequate.

One claim appearing in the detractor's ecosystem section deserves elevation: the Bishop Fox advisory [BISHOPFOX-CRAN] documents a path traversal vulnerability in CRAN package installation (R version 4.0.2) enabling arbitrary file writes during `install.packages()`. This is an independently confirmed vulnerability separate from CVE-2024-27322 and extends the code-execution-on-install surface to include filesystem compromise. It is absent from the research brief, unreferenced in four of five council perspectives, and underweighted in the detractor (Section 6 rather than Section 7). It belongs in the security core discussion.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **CVE-2024-27322 mechanism is correctly characterized.** All five perspectives accurately identify the technical mechanism: R's lazy evaluation represents unevaluated computations as "promise objects" (expression + environment) that are evaluated on first access. The RDS serialization format preserved these promise objects. A crafted RDS file could embed arbitrary R expressions that execute when the deserialized object is first referenced in normal user workflow — `x <- readRDS("malicious.rds"); print(x)` triggers the payload without any unusual user action [HIDDENLAYER-RDS]. The detractor's framing — "three design choices... all intentional... security vulnerability emerged from their combination" — is the most technically precise [DETRACTOR-S7].

- **CVSS 8.8 (High) is the correct score.** Multiple independent sources confirm this rating [CVEDETAILS-CVE-2024-27322] [OSS-SEC-CVE-2024-27322] [BERKELY-CVE-2024-27322]. No perspective misreports the score.

- **The fix in R 4.4.0 is real and complete for the known vector.** The R Core Team's statement is direct: "This bug has been fixed in R 4.4.0 and any attack vector associated with it has been removed" [R-BLOG-CVE-2024-27322]. CISA's advisory confirms remediation [CISA-CVE-2024-27322].

- **CRAN review is not a security audit.** All five perspectives accurately note that `R CMD check` checks documentation compliance and functional correctness, not for malicious intent or security vulnerabilities [CRAN-REPO-POLICY]. The practitioner correctly observes that CRAN reviewers are checking for policy compliance, not performing adversarial code review [PRACTITIONER-S7].

- **No standard cryptographic library.** The practitioner and detractor both correctly identify that R's base and stats packages include no cryptographic primitives [PRACTITIONER-S7] [DETRACTOR-S7]. The `openssl` and `sodium` CRAN packages provide cryptographic functionality, but they are third-party dependencies without the auditing infrastructure of standard library cryptography in Go, Python's `hashlib`, or Java's `javax.crypto`. For R's actual deployment domains — pharmaceutical regulatory submissions, clinical trial data, genomic data — the absence of audited first-party cryptography is a real operational gap.

- **No sandboxing at any level.** The detractor's characterization is accurate: there is no equivalent to JavaScript's V8 isolates, Python's `RestrictedPython`, or Deno's capability-based permission system [DETRACTOR-S7]. Package loading executes arbitrary code with full R process permissions. This has never been addressed at the language level.

- **Process-based parallelism avoids inter-session contamination.** The apologist's claim that separate R processes in the `parallel` package cannot contaminate each other's state is correct, and is a genuine security property in one dimension: there are no data races or shared-state corruption paths between parallel workers [APOLOGIST-S7].

**Corrections needed:**

- **CVE vulnerability window duration is overstated by the historian.** The historian writes "approximately twenty-five years of releases" [HISTORIAN-S7]. The affected versions are R 1.4.0 through R 4.3.x [OSS-SEC-CVE-2024-27322]. R 1.4.0 was released in December 2001; the vulnerability was publicly disclosed in April 2024. The correct figure is approximately 22–23 years, not 25. The apologist's "23 years" is closer to accurate; the historian's "twenty-five years" overstates by 2–3 years.

- **The `readRDS()` attack surface is substantially broader than the council represents.** The practitioner notes that reading `.rds` files is "idiomatic R" and that practitioners share them routinely [PRACTITIONER-S7]. What the practitioner does not quantify is the scope: SecurityWeek's coverage of CVE-2024-27322 reported that `readRDS()` appears in over 135,000 R source files, with vulnerable code present in projects from RStudio, Facebook, Google, Microsoft, and AWS [SECURITYWEEK-CVE-2024-27322]. This is not a niche operation on unusual file types — it is the standard R data interchange format, embedded in the workflows of the entire R ecosystem. The apologist's framing that "the threat model for most R deployments" limits exposure underweights this.

- **The apologist's CRAN vs. npm comparison is partially outdated.** The apologist argues that CRAN's human review creates "friction that package managers with zero review do not" [APOLOGIST-S7]. This is true as a historical comparison, but npm now performs automated security scanning and signature verification not present in CRAN's workflow. PyPI has introduced TrustedPublishers and OIDC-based provenance. CRAN's human review, while real, is not more comprehensive than npm or PyPI's current security tooling — it is different in kind and may be weaker in aggregate for adversarial detection.

- **The practitioner citation for "malicious packages accepted by CRAN historically" is weakly sourced.** Both the research brief and practitioner cite [THN-CVE-2024-27322] for the claim that malicious packages have been accepted by CRAN in the past. The linked Hacker News article is specifically about CVE-2024-27322 and supply chain attack risk — it documents a theoretical risk, not confirmed historical instances of malicious CRAN packages reaching users. The claim may be accurate but requires a more precise citation documenting actual confirmed instances, or should be restated as "CRAN's process does not structurally prevent malicious packages."

- **The underlying architecture remains in place after the CVE-2024-27322 fix.** The detractor makes the strongest correct observation: the fix in R 4.4.0 constrained what can be serialized, but the design pattern (lazy evaluation + first-class promises + transparent serialization) that made the vulnerability possible remains in the language [DETRACTOR-S7]. This is not a criticism of the fix — the attack vector is patched. It is a statement about residual architectural risk: future research into R's serialization surface could identify additional exploitable combinations of these properties.

**Additional context:**

- **The `eval(parse(text = ...))` pattern is a significant CWE-94 surface that is underexplored.** R's first-class support for expressions and its `eval()` function are core language primitives extensively used in production code. The pattern `eval(parse(text = user_supplied_string))` — using user input to construct and evaluate R expressions — creates a direct code injection vulnerability that requires no additional complexity. R's NSE machinery in tidyverse packages further blurs the boundary between data and code, creating injection surfaces that developers may not recognize as such. The council correctly categorizes CWE-94 as part of R's vulnerability profile but does not illustrate the mechanisms through which it manifests in practice.

- **`system()` and related shell-invocation functions create OS command injection surfaces (CWE-78).** R's `system()`, `system2()`, and `shell()` functions invoke OS shell commands. Code that constructs shell commands using user-supplied data without proper escaping is vulnerable to OS command injection, independent of R's deserialization issues. This vulnerability class is distinct from CWE-94 (R code injection) and CWE-502 (deserialization) but shares the same root cause: R's permissive model in which arbitrary execution is the default, not an exceptional path. No council perspective addresses this explicitly, though it belongs in the CWE enumeration.

- **The Bishop Fox path traversal vulnerability [BISHOPFOX-CRAN] is a confirmed, separate security issue.** Independently from CVE-2024-27322, Bishop Fox documented a path traversal vulnerability in CRAN (version 4.0.2) where a maliciously crafted package archive could include tar paths that write files outside the installation directory [BISHOPFOX-CRAN]. Depending on the permissions of the installing user, this enables overwriting system binaries, creating cron jobs, or writing SSH keys — full system compromise at package installation, before any R code executes. This vulnerability appears only in the detractor's ecosystem section and is absent from all security sections across all five perspectives. It extends the supply chain attack surface and deserves explicit inclusion in any complete security profile of R.

- **R has no dependency vulnerability scanning toolchain equivalent to `cargo audit` or `npm audit`.** The realist correctly notes this gap [REALIST-S7]. In Rust, `cargo audit` queries the RustSec advisory database. In JavaScript, `npm audit` runs automatically. R has no equivalent: `R CMD check` does not query any vulnerability database, CRAN does not maintain an advisory database for package vulnerabilities, and the community has no official tooling for alerting users that an installed dependency has a known CVE. This is a systemic security infrastructure gap for a language increasingly used in regulated industries.

- **Security ergonomics: the insecure path is the default path.** A useful framing: in R, the following operations all execute arbitrary code with zero friction, no warning, and no confirmation: `install.packages()`, `library()`, `readRDS()` (prior to 4.4.0), and `source()`. The secure alternative — reviewing package source before installation, using only trusted data sources, verifying file integrity — requires active effort and is not supported by any tooling in the base language or standard workflow. Compare with Cargo, where `build.rs` must be explicitly declared and executes only when present, or Deno, where file system access requires explicit permission flags. R's security ergonomics systematically favor convenience over safety.

**Missing data:**

- No comprehensive count of confirmed malicious packages accepted by CRAN, with outcomes, to accurately characterize the frequency of supply chain incidents.
- No controlled CVE frequency data for R normalized by lines of code, deployment count, or scrutiny level. The "small number of CVEs" characterization across the council is not analytically meaningful without such controls.
- No documented assessment of whether the R 4.4.0 fix for CVE-2024-27322 introduced any behavior changes to serialization that affect existing workflows.
- No evidence on actual exploitation of CVE-2024-27322 in the wild before the R 4.4.0 patch, or post-patch exploitation of unpatched deployments.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- **Dynamic typing does not directly introduce SQL injection or XSS in typical R deployments.** The apologist's observation that R's deployment context (primarily data analysis, not web request handling) structurally reduces injection-class risks is correct [APOLOGIST-S7]. An R script processing a dataset does not receive HTTP parameters; the injection surface is different from PHP or Node.js. This is a legitimate calibration point.

- **Integer overflow producing `NA` rather than wrapping.** The detractor's identification of R's integer overflow behavior as producing `NA` with a warning (not silently wrapping, and not erroring) is accurate [DETRACTOR-S2]. This is documented R behavior: 32-bit integers overflow to `NA` rather than wrapping around. The detractor correctly notes that downstream code is unlikely to treat `NA` as a red flag for overflow, creating silent data corruption in security-sensitive numeric computations (e.g., thresholds, counters, financial calculations). This is a real and underappreciated security-relevant property.

**Corrections needed:**

- **The absence of SQL injection in typical R is not a type system property; it is a deployment property.** The council correctly notes that R's type system does not prevent injection, but the apologist's claim that "CVE classes like SQL injection... are structurally absent from R" overstates what the type system achieves [APOLOGIST-S7]. R users who construct SQL queries using string concatenation (`paste()`, `sprintf()`) and execute them via DBI are entirely exposed to SQL injection. The safe path — parameterized queries via `dbGetQuery()` with placeholders — is available but not enforced. R's type system provides no injection protection; it is the absence of a common web-service deployment pattern that typically avoids the exposure.

- **R's first-class expressions create a code injection surface that the type system does not constrain.** R's type hierarchy includes "language objects" (calls, expressions, symbols) as first-class values that can be constructed, manipulated, and evaluated. The `eval()` function is a standard tool in R programming, not an exceptional escape hatch. Any code that builds R expressions from user-supplied data without sanitization is vulnerable to code injection (CWE-94). Because R's type system does not distinguish between trusted and untrusted expressions, there is no type-level protection against this pattern. The council's type system sections do not address this.

**Additional context:**

- **Lack of gradual typing means type confusion in security-sensitive code is undetectable.** The detractor correctly notes that R has no gradual typing path [DETRACTOR-S2]. For security-sensitive numerical code (calculating dosage thresholds, financial positions, access control values), silent type coercions and the absence of compile-time type checking create an environment where security-relevant numeric mistakes may not surface until runtime, potentially after incorrect values have been used.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- **Automatic GC eliminates memory safety bugs at the R level.** The apologist's claim that "R programs do not suffer from memory corruption bugs at the R level" is correct as stated [APOLOGIST-S3]. R's garbage collector handles all allocation and deallocation; there is no manual memory management, no pointer arithmetic, no buffer boundary management available to R-level code. The classes of vulnerability that dominate C and C++ CVE data — use-after-free, double-free, buffer overflow — are structurally absent from R-level code.

- **C extension layer does not inherit R-level memory safety.** All five perspectives correctly identify that R's implementation in C means C-level vulnerabilities (like the LoadEncoding buffer overflow) are possible in the runtime itself. The realist's framing is precise: "attributable to R's implementation in C, not to R language semantics" [REALIST-S7].

- **Copy-on-modify semantics do not introduce memory safety issues.** The functional semantics of copy-on-modify mean that object aliasing does not create dangling reference problems at the R level. This is correctly described across all perspectives.

**Corrections needed:**

- **The C extension API's GC protection mechanism is a significant memory safety risk in package code.** The R C API requires that C-level code manually "protect" R objects from garbage collection using `PROTECT()`/`UNPROTECT()` calls. Failing to protect an object that gets referenced after a GC point can cause use-after-free behavior at the C level. This is a well-documented source of bugs in R package development, distinct from memory safety at the R scripting level. The detractor's memory model section mentions this limitation [DETRACTOR-S3]; the other perspectives do not adequately distinguish between "R-level code is memory safe" and "C extensions using the R C API are memory safe." The `Rcpp` package abstracts much of this but introduces its own complexity.

- **R's in-process FFI to C/C++ means malicious or vulnerable C extensions can corrupt the R process.** An R package using the `.Call()` interface operates with full access to the R process memory space. A vulnerable C extension — whether through memory corruption, use-after-free, or buffer overflow — can compromise the entire R session. Memory safety at the R language level does not extend to the C/C++ layer that most performance-critical packages use extensively.

**Additional context:**

- No R council perspective discusses whether R's serialization format (RDS) uses any memory-safe deserialization approach at the C implementation level. CVE-2024-27322 was a logical vulnerability (promise execution) rather than a memory corruption vulnerability; but the C-level implementation of RDS deserialization is a potential future target for memory corruption vulnerabilities if not audited.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- **Single-threaded base R prevents data races at the R scripting level.** The apologist's framing that "thread-safety bugs — data races, deadlocks, improper synchronization — are subtle and difficult to debug" and that R's architecture avoids exposing these risks to its user population is accurate in context [APOLOGIST-S4]. There are no data race vulnerabilities in R-level code because R-level code does not use threads.

- **Process isolation in the `parallel` package prevents shared-state corruption between workers.** The parallel package's process-based model means each worker has its own memory space; no shared mutable state is possible between workers. This is a real security property: malicious or buggy code in a parallel worker cannot directly corrupt the coordinating process's memory.

**Corrections needed:**

- **The apologist overstates single-threading as a security feature.** The claim that the absence of threading is "actually a safety feature for the intended audience" [APOLOGIST-S4] is true in a narrow sense (no data races) but is not a meaningful positive security property. R's actual security risks are not primarily about data races; they are about code execution, supply chain integrity, and injection. Single-threading addresses none of these. Framing single-threading as a security feature mislocates where R's security risks actually are.

- **Shiny multi-user applications have real session isolation security implications.** The detractor discusses the Shiny concurrency problem from a performance and scalability perspective [DETRACTOR-S4], but does not address the security implications. In a Shiny application running in a single R process, global variables and environments are shared across user sessions unless explicitly isolated. Without careful scoping, user-session state can leak across sessions — a real data confidentiality risk for applications processing multiple users' sensitive data. This is an application-level consequence of R's single-process, shared-environment architecture that the council does not address from a security angle.

**Additional context:**

- R's `<<-` operator (superassignment, which modifies variables in parent environments rather than the local scope) creates a global state mutation mechanism that, in a multi-session Shiny context, could inadvertently expose one user's data to another's session. This is not a language-level security vulnerability, but it is a security-relevant language property that does not appear in any council security discussion.

---

### Other Sections (Ecosystem/Supply Chain — Section 6)

**Section 6 security-relevant flags:**

The detractor's Section 6 contains the most security-relevant content outside Section 7 and deserves direct engagement:

- **The Bishop Fox path traversal [BISHOPFOX-CRAN] is confirmed real.** Bishop Fox documented a path traversal vulnerability in CRAN package installation where a crafted `.tar.gz` package could write files outside the installation directory during `install.packages()`, enabling full system compromise depending on user permissions [BISHOPFOX-CRAN]. This vulnerability is absent from the research brief's Security Data section, absent from the council's security sections, and deserves to be in the security record. Its confirmed status and install-time trigger (before any user code runs) make it particularly significant.

- **The `package:::unexported_function()` access pattern undermines namespace encapsulation.** The detractor correctly notes that R has no genuinely private API surface — `:::` provides access to all package internals [DETRACTOR-S6]. From a security perspective, this means security-sensitive logic in package internals (e.g., authentication checks, input validation) can be bypassed by any caller who knows the internal function name. This is not analogous to "security through obscurity" in the classical sense, but it means that no R package can provide a security boundary through API design alone.

- **R universe and GitHub packages are entirely outside CRAN's review process.** R-universe and direct GitHub installs (via `remotes::install_github()`) have no CRAN-equivalent review. The research brief notes that CRAN's review "is not a security audit" — but R-universe and GitHub installs have no review at all. The ecosystem's practical supply chain now extends well beyond CRAN to sources with zero quality control. This is a supply chain risk that grows as practitioners routinely install pre-release or specialized packages from these sources.

---

## Implications for Language Design

The R case yields several durable lessons for language security design:

**Serialization format design must account for adversarial inputs from the beginning.** R's RDS format was designed to faithfully preserve R's object graph — including promise objects representing unevaluated computations — because that fidelity was useful for friendly use cases. Designing a serialization format as a "save and restore" mechanism without considering what happens when a recipient treats a sender as an adversary is a common pattern that reliably produces vulnerabilities as languages grow beyond their original deployment contexts. Secure serialization must either restrict what can be serialized or treat deserialized data as untrusted until sanitized. R did neither, for 22 years.

**Threat models must be maintained as deployment contexts expand.** R was designed for academic statisticians in friendly environments. By the time CVE-2024-27322 was disclosed, R was used in pharmaceutical regulatory submissions, clinical trial analysis, financial modeling, and enterprise analytics. The language's security architecture had not been updated to reflect this evolution. Language designers and stewards must treat threat model reviews as ongoing governance responsibilities, not fixed-at-birth properties. When a language moves from "research tool" to "regulated industry infrastructure," its security posture needs deliberate reassessment.

**The secure path should be the easy path; in R, it is not.** The fundamental security ergonomics failure in R is that every default operation in R's package and data workflow (install, load, readRDS, eval) executes arbitrary code with full permissions. The insecure path requires no special knowledge or effort. Deno's capability-based permissions, Cargo's explicit `build.rs` declaration, and even npm's ongoing movement toward more restrictive install script handling represent the direction of travel for modern language security design: making code execution from untrusted sources an explicit opt-in, not an implicit default.

**Standard library cryptography matters for languages deployed in sensitive domains.** R's primary deployment domains — pharma, clinical trials, genomics, finance — handle highly sensitive data. That R has no standard library cryptographic primitives, requiring third-party CRAN packages for any cryptographic operation, is a design gap that should be addressed by languages targeting sensitive data domains. Standard library cryptography benefits from centralized auditing, version coordination with security fixes, and availability without an explicit `install.packages()` call. The absence of this infrastructure in R is a gap that should inform language designers creating tools for comparable domains.

**Package execution-on-install is a systemic risk pattern.** The R model (package installation runs arbitrary code via `.onLoad()` with no sandboxing) represents one end of a spectrum. Cargo's model represents the other: build scripts must be explicitly declared, `unsafe` code must be lexically marked, and no code runs implicitly during dependency resolution. The R model prioritizes convenience and expressiveness for package authors; the Cargo model prioritizes security and auditability for consumers. Languages serving security-conscious deployment contexts should adopt more restrictive models.

**No dependency vulnerability scanning is an ecosystem infrastructure gap.** The absence of a first-party vulnerability advisory database and scanning tool (equivalent to `cargo audit` or `npm audit`) for R is a gap that grows in importance as R is adopted in regulated industries. CRAN's role as a distribution mechanism does not include a security advisory function. This gap should be filled by either the R Foundation or the broader ecosystem, and its absence should inform language ecosystem designers that security tooling must be planned alongside package distribution infrastructure, not retrofitted after adoption.

---

## References

| Key | Citation |
|---|---|
| [HIDDENLAYER-RDS] | HiddenLayer Research. "R-bitrary Code Execution: Vulnerability in R's Deserialization." https://hiddenlayer.com/innovation-hub/r-bitrary-code-execution/ |
| [OSS-SEC-CVE-2024-27322] | oss-security. "CVE-2024-27322: Deserialization vulnerability in R before 4.4.0." April 29, 2024. https://www.openwall.com/lists/oss-security/2024/04/29/3 |
| [CVEDETAILS-CVE-2024-27322] | CVEdetails. "CVE-2024-27322." https://www.cvedetails.com/cve/CVE-2024-27322/ |
| [BERKELY-CVE-2024-27322] | UC Berkeley Information Security Office. "CVE-2024-27322 Vulnerability in R Programming Language." https://security.berkeley.edu/news/cve-2024-27322-vulnerability-r-programming-language |
| [CISA-CVE-2024-27322] | CISA. "CERT/CC Reports R Programming Language Vulnerability." May 1, 2024. https://www.cisa.gov/news-events/alerts/2024/05/01/certcc-reports-r-programming-language-vulnerability |
| [R-BLOG-CVE-2024-27322] | R Core Team. "Statement on CVE-2024-27322." The R Blog, May 10, 2024. https://blog.r-project.org/2024/05/10/statement-on-cve-2024-27322/ |
| [THN-CVE-2024-27322] | The Hacker News. "New R Programming Vulnerability Exposes Projects to Supply Chain Attacks." April 2024. https://thehackernews.com/2024/04/new-r-programming-vulnerability-exposes.html |
| [DARKREADING-CVE-2024-27322] | Dark Reading. "R Programming Bug Exposes Orgs to Vast Supply Chain Risk." https://www.darkreading.com/application-security/r-programming-language-exposes-orgs-to-supply-chain-risk |
| [SECURITYWEEK-CVE-2024-27322] | SecurityWeek. "Vulnerability in R Programming Language Could Fuel Supply Chain Attacks." https://www.securityweek.com/vulnerability-in-r-programming-language-enables-supply-chain-attacks/ |
| [BISHOPFOX-CRAN] | Bishop Fox. "CRAN Version 4.0.2 Security Advisory: Path Traversal." https://bishopfox.com/blog/cran-version-4-0-2-advisory |
| [CVEDETAILS-R-PROJECT] | CVEdetails. "R Project: Security vulnerabilities, CVEs." https://www.cvedetails.com/vulnerability-list/vendor_id-16189/R-Project.html |
| [CRAN-REPO-POLICY] | CRAN Repository Policy. https://cran.r-project.org/web/packages/policies.html |
| [IHAKA-1996] | Ihaka, R. and Gentleman, R. (1996). "R: A Language for Data Analysis and Graphics." *Journal of Computational and Graphical Statistics*, 5(3), 299–314. |
| [ADV-R] | Wickham, H. *Advanced R* (2nd ed.). https://adv-r.hadley.nz/ |
| [ADV-R-MEMORY] | Wickham, H. "Memory usage." In *Advanced R* (1st ed.). http://adv-r.had.co.nz/memory.html |
| [POSIT-SECURITY] | Posit Support. "R and R Package Security." https://support.posit.co/hc/en-us/articles/360042593974-R-and-R-Package-Security |
| [APOLOGIST-S7] | R Council Apologist Perspective, Section 7. `research/tier1/r/council/apologist.md` |
| [PRACTITIONER-S7] | R Council Practitioner Perspective, Section 7. `research/tier1/r/council/practitioner.md` |
| [DETRACTOR-S7] | R Council Detractor Perspective, Section 7. `research/tier1/r/council/detractor.md` |
| [DETRACTOR-S2] | R Council Detractor Perspective, Section 2. `research/tier1/r/council/detractor.md` |
| [DETRACTOR-S3] | R Council Detractor Perspective, Section 3. `research/tier1/r/council/detractor.md` |
| [DETRACTOR-S4] | R Council Detractor Perspective, Section 4. `research/tier1/r/council/detractor.md` |
| [DETRACTOR-S6] | R Council Detractor Perspective, Section 6. `research/tier1/r/council/detractor.md` |
| [REALIST-S7] | R Council Realist Perspective, Section 7. `research/tier1/r/council/realist.md` |
| [HISTORIAN-S7] | R Council Historian Perspective, Section 7. `research/tier1/r/council/historian.md` |
| [APOLOGIST-S3] | R Council Apologist Perspective, Section 3. `research/tier1/r/council/apologist.md` |
| [APOLOGIST-S4] | R Council Apologist Perspective, Section 4. `research/tier1/r/council/apologist.md` |

---

**Document version:** 1.0
**Prepared:** 2026-02-26
**Schema version:** 1.1
