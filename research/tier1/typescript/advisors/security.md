# TypeScript — Security Advisor Review

```yaml
role: advisor-security
language: "TypeScript"
agent: "claude-agent"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

TypeScript's security profile is defined by a single architectural fact: **types are erased at compilation and exert no influence at runtime**. This is not a limitation that crept in by accident — it is explicitly documented in the design goals as a consequence of the "no runtime overhead" principle [TS-DESIGN-GOALS]. The implication for security is profound and consistent across all council perspectives: TypeScript's type system can catch type-confusion bugs within a controlled codebase but cannot validate data that crosses a trust boundary. Every network response, database result, environment variable, and HTTP request body is untyped at runtime, regardless of what TypeScript annotations declare.

The five council members are broadly accurate on this structural limitation and on the documented CVE classes — prototype pollution in TypeScript ecosystem libraries, supply chain attacks via the `@types` namespace, and the growth of injection vulnerabilities in the npm ecosystem. However, several claims are underprecise or misleadingly framed: the apologist's argument that supply chain attacks are "not TypeScript-specific" understates a real, TypeScript-specific attack surface; the 450% SQL injection figure is drawn from the broader npm ecosystem without controlling for ecosystem growth and should not be read as a TypeScript-specific vulnerability rate; and no council member addresses the security implications of async race conditions (TOCTOU between awaits) or the FFI security boundary at Node.js native addons.

One significant data gap: no TypeScript-specific CVE evidence file exists in the project's shared evidence repository. CVE-2025-30397 is listed in the research brief without description or CVSS score. The council's security analyses are consequently reliant on a single secondary source (Snyk) for the SQL injection trend and a single news aggregator (The Hacker News) for the supply chain incidents. These sources are credible but do not substitute for NVD queries or GHSA analysis with controlled methodology.

---

## Section-by-Section Review

### Section 7: Security Profile

All five council members addressed this section. Assessments below refer to patterns across their perspectives.

#### Accurate claims:

- **Type erasure as the root security limitation.** All five councils correctly identify type erasure as the fundamental constraint: TypeScript types do not survive compilation, and external data is untyped at runtime [TS-DESIGN-GOALS]. The practitioner and detractor give the most operationally concrete accounts: any API response typed as `UserProfile` by annotation or cast is whatever the server actually sends. The apologist acknowledges this explicitly but contextualizes it as a design tradeoff rather than a failure, which is defensible.

- **Prototype pollution (CWE-1035) is structurally unmitigated.** TypeScript's type system cannot detect whether generic object operations will pollute `Object.prototype` via `__proto__`, `constructor`, or `prototype` properties in attacker-controlled data. This is accurate across all councils. The specific CVEs cited are correctly attributed:
  - CVE-2023-6293 (sequelize-typescript < 2.1.6): prototype pollution via `deepAssign()` [SNYK-SEQTS]
  - CVE-2022-24802 (deepmerge-ts): prototype pollution via `defaultMergeRecords()` [ACUNETIX-2022-24802]
  - CVE-2025-57820 (devalue): prototype pollution [SNYK-DEVALUE]
  These CVEs demonstrate the correct causal claim: the presence of TypeScript types in a library does not prevent prototype pollution when attacker-controlled data flows through merge or deep-assign operations.

- **`--strict` was opt-in for twelve years.** Multiple councils correctly note that `noImplicitAny`, `strictNullChecks`, and `useUnknownInCatchVariables` were not defaults until TypeScript 6.0 (February 2026) [TS-60-BETA]. The security consequence is real: projects initialized before 2026 without explicit `--strict` ran with implicit `any`, null-unsafe types, and `any`-typed catch variables. The detractor's framing of this as "twelve years of the safe configuration not being the default" is accurate and the historian correctly characterizes it as a backward-compatibility consequence of the superset constraint.

- **Supply chain attacks via `@types` typosquatting.** The December 2024 incidents are correctly documented: `types-node` (typosquatting `@types/node`) and `@typescript_eslinter/eslint` (typosquatting `@typescript-eslint/eslint-plugin`) [HACKERNEWS-NPM-MALWARE]. The research brief provides detailed payload descriptions: `types-node` fetched malicious scripts from Pastebin, executed `npm.exe`, and dropped `prettier.bat` into the Windows startup folder for persistence [TS-RESEARCH-BRIEF].

- **`any` as a security degradation point.** All councils correctly note that `any` at trust boundaries nullifies type-system security benefits. The systematic study of 604 GitHub projects finding inverse correlation between `any` usage and code quality metrics [GEIRHOS-2022] is accurately cited. Security reviewers should treat `any` at input boundaries as structurally equivalent to removing type checking at that boundary.

- **SQL injection growth in npm ecosystem.** The 450% increase in CWE-89 vulnerabilities in JavaScript/npm from 2020 to 2023 (370 to 1,692) is accurately attributed to Snyk research [SNYK-STATE-JS]. TypeScript's type system does not distinguish parameterized SQL from string-interpolated SQL, and this is correctly identified.

#### Corrections needed:

**1. The apologist's "not TypeScript-specific" framing for supply chain attacks (Section 7) is inaccurate.**
The apologist writes: "They are also not TypeScript-specific; they are npm ecosystem problems that affect all JavaScript and TypeScript developers equally." This is partially wrong. The `@types` namespace is a TypeScript-specific installation pattern. JavaScript developers who do not use TypeScript do not install `@types/*` packages; they have no occasion to encounter a `types-node` package. The attack surface is not identical for JavaScript and TypeScript developers — it is enlarged for TypeScript developers by the existence of a widely-trusted namespace that attackers can impersonate. The apologist's claim should be corrected: supply chain attacks via typosquatted `@types` packages are a TypeScript-specific attack surface, not merely a generic npm problem.

**2. The SQL injection 450% figure requires methodological context.**
Multiple councils cite this figure without noting that it covers the entire npm ecosystem and reflects 2020–2023 trends. This time period coincides with (a) substantial growth in the total number of npm packages and (b) increased security research attention on the JavaScript ecosystem. The 450% increase is a raw count increase in reported CVEs, not a rate-per-package or rate-per-deployed-application figure. Attributing this trend to TypeScript's type system failing to prevent injection attacks, without controlling for ecosystem size and research attention, is an incomplete analysis [SNYK-STATE-JS]. The claim that "TypeScript's type system offers no additional protection against injection relative to JavaScript" is correct and sufficient; the 450% figure adds rhetorical weight without methodological grounding.

**3. CVE-2025-30397 is cited without description.**
The research brief lists CVE-2025-30397 as a "TypeScript-related CVE" without providing description, CVSS score, affected versions, or CWE classification [NVD-TS-2025]. This citation is insufficient for the claims structure required by this project's evidence standards. The council should not cite this CVE until its scope and severity are verified against the NVD entry.

**4. The detractor's "false sense of security" claim is accurate but lacks empirical grounding.**
The detractor argues: "The most dangerous security property TypeScript can exhibit [is] conveying a confidence in code correctness that its guarantees do not support." This is a sound theoretical claim and is consistent with general security research on the risks of partial mitigations creating overconfidence. However, no empirical citation supports the specific claim that TypeScript developers are measurably more likely to skip runtime validation than developers in other ecosystems. The claim is presented as established fact when it is actually an unverified hypothesis about developer behavior. It should be framed as a plausible risk rather than a documented pattern.

#### Additional context:

**The `unknown` type is a meaningful but incomplete security improvement.**
TypeScript 3.0 introduced `unknown` as a type-safe alternative to `any` [TS-30-RELEASE], and TypeScript 4.4 made `unknown` the default for catch variables in strict mode [TS-44-RELEASE]. These are genuine security improvements: `unknown` requires explicit type narrowing before access, preventing the pattern `catch (e) { doSomethingWith(e.property) }` when `e` might not be an Error object. However, `unknown` does not prevent `any` being used elsewhere, and the transition from `any` catch variables to `unknown` catch variables was delayed until 2021. The security value of `unknown` is real but bounded.

**Branded types as a partial injection defense.**
No council member adequately addresses the potential of TypeScript's branded types as a mechanism for distinguishing sanitized from unsanitized strings — a technique relevant to injection prevention at the type level. A type system that can represent `type SafeSQL = string & { __brand: 'SafeSQL' }` could in principle enforce that only sanitized strings reach SQL execution points. This pattern exists in the TypeScript community but is not standard practice, not enforced by the language, and not discussed by any council as a security mechanism. This represents a gap between TypeScript's theoretical capability and its realized security value in common practice.

**The `as` and `!` operators are security-relevant escape hatches.**
The detractor correctly notes that `value as TargetType` and `value!` are syntactically lightweight and blend into normal TypeScript code. From a security perspective, these operators are checkpoints where type-system guarantees are deliberately bypassed. A security audit of a TypeScript codebase should enumerate all uses of `as` at trust boundaries (particularly casts of API responses, JSON.parse results, and user input) and all uses of `!` on values that could plausibly be null at those boundaries. This is a concrete, actionable finding that no council framed in audit-oriented terms.

#### Missing data:

- No TypeScript-specific CVE evidence file exists in `evidence/cve-data/`. The council's evidence base relies on the research brief's secondary compilation and on council member documents that share the same sources. A NVD query filtering by CPE for TypeScript-specific packages (npm:typescript, npm:@types/*) with date range 2020–2025 should be performed and added to the shared evidence repository.
- The research brief does not provide CVSS scores for CVE-2022-24802 (deepmerge-ts) or CVE-2025-57820 (devalue). CVE-2023-6293 (sequelize-typescript) is provided without a CVSS score in the research brief. These should be verified from NVD.
- No council member quantifies the prevalence of runtime validation library adoption in TypeScript codebases. The claim that "runtime validation libraries (Zod, Joi, io-ts) address [the type erasure problem], but their adoption is inconsistent" is widely made but not supported by a survey citation.

---

### Section 2: Type System (security implications)

#### Accurate claims:

- **Unsoundness is documented and deliberate.** All councils correctly attribute TypeScript's seven known unsoundness sources to documented design choices [EFFECTIVE-TS-UNSOUND; TS-ISSUE-9825]. The security implication — that the type system does not provide provable guarantees even within the compiled codebase — is accurately drawn.
- **Structural typing does not distinguish semantically distinct types.** The detractor correctly identifies that `UserId` and `ProductId` are both `string` and are structurally interchangeable. This is a real semantic safety gap with security implications: a function that accepts a `UserId` will also accept an `OrderId`, a `SessionToken`, or any other string without type-level distinction.
- **`strictNullChecks` prevents a class of null-dereference errors at compile time.** The apologist's claim is accurate for code within the compiled boundary. The caveat — that external data bypasses this guarantee — is also correctly noted.

#### Corrections needed:

- **Bivariant function parameter checking is not clearly explained as a security-relevant unsoundness.**
The detractor lists bivariant function parameter checking as a source of unsoundness but does not explain its security relevance. In TypeScript's legacy bivariant mode (still present for method signatures, not function-typed properties), a function `(x: Dog) => void` is assignable to `(x: Animal) => void`. This allows callback assignments that could cause runtime type errors when the callback receives an unexpected subtype. This is an underexplained attack surface for code that uses callbacks or event handlers with dynamically typed payloads.

#### Additional context:

- **`noUncheckedIndexedAccess` is a security-relevant strict option not discussed by any council.** This flag (available since TypeScript 4.1, opt-in even under `--strict`) marks array index access and record property access as returning `T | undefined` rather than `T`. It prevents a class of runtime errors where an index access on a sparse array or a missing record key produces `undefined` and subsequently causes a null-dereference error. Its absence from the `--strict` bundle means that even under TypeScript 6.0's new strict defaults, this check is not enforced.

---

### Section 3: Memory Model (security implications)

#### Accurate claims:

- **JavaScript's GC eliminates memory corruption vulnerabilities from JavaScript-level code.** All councils correctly note that there is no use-after-free, no buffer overflow, and no uninitialized memory from TypeScript-level code. The apologist's formulation — "eliminates the entire class of memory-corruption vulnerabilities that plague C and C++ codebases" — is accurate for JavaScript-level execution.
- **TypeScript types have no memory footprint at runtime.** Zero-overhead type erasure is accurately described.

#### Corrections needed:

None of the councils adequately addresses two security-relevant memory topics:

**1. Node.js native addons (N-API) as a security boundary.**
TypeScript applications that use native Node.js addons execute C/C++ code with full memory access. TypeScript's type system treats native addon return values as whatever `.d.ts` declarations say they are — there is no runtime verification that the C/C++ code returns safe values. A vulnerable native addon can introduce buffer overflows, use-after-free, or type confusion bugs into an otherwise TypeScript-safe application. The type boundary at native addon calls is a trust boundary that TypeScript provides no protection for. The detractor mentions this briefly ("the type system provides no mechanism to verify FFI boundary correctness at runtime") but no council treats it as a security-specific concern.

**2. `SharedArrayBuffer` and Spectre-class timing attacks.**
`SharedArrayBuffer` enables shared memory between the main thread and worker threads in both browser and Node.js contexts. Browser vendors re-enabled it only under cross-origin isolation (requiring `Cross-Origin-Opener-Policy` and `Cross-Origin-Embedder-Policy` headers) after disabling it in 2018 following Spectre disclosure. TypeScript's types for `SharedArrayBuffer` do not encode these access control requirements. A TypeScript application that uses `SharedArrayBuffer` in browser contexts without the required COOP/COEP headers is vulnerable to timing attacks; TypeScript's type system provides no guidance or enforcement on this requirement. No council mentioned this.

#### Additional context:

- The compiler's own memory usage (hundreds of MB for large projects) is an operational concern but not a security concern. The councils that discuss this are correctly scoping it as a developer experience issue rather than a vulnerability class.

---

### Section 4: Concurrency (security implications)

#### Accurate claims:

- **Single-threaded event loop eliminates classical data races on shared mutable state.** The apologist's claim is correct: the main thread of a JavaScript/TypeScript application cannot have two pieces of code executing simultaneously, so the classical pattern of thread-based TOCTOU races and mutex-protected shared state does not apply to single-threaded event loop code.
- **Unhandled Promise rejections allow silent failure of security-relevant operations.** The practitioner and detractor correctly identify this: a dropped rejection handler can silence authentication failures, authorization errors, or validation exceptions. This is a security concern, not merely a developer experience concern.

#### Corrections needed:

**1. Async/await introduces a form of TOCTOU that no council adequately addresses.**
Between `await` points, the event loop can process other events, mutating shared state. Code of the form:

```typescript
const permission = await checkPermission(userId);
// << event loop can run here >>
await performAction(userId, permission);  // permission may be stale
```

This is a real TOCTOU class of vulnerability in async TypeScript code. A permission may be checked and then revoked before the action that relied on it executes. TypeScript's type system provides no mechanism to detect this class of race. No council member framed async state changes between awaits as a security concern.

**2. Worker threads + SharedArrayBuffer create traditional data races.**
Once worker threads and `SharedArrayBuffer` are introduced, the "no data races" property of single-threaded JavaScript no longer holds. TypeScript's types for `Atomics` and `SharedArrayBuffer` exist but do not enforce correct synchronization. No council addressed this transition from race-free to race-possible code as a security boundary.

#### Additional context:

- The `@typescript-eslint/no-floating-promises` lint rule is correctly identified as a partial mitigation for unhandled rejections, but it is a linting convention, not a type-level guarantee. The security difference matters: lint rules can be suppressed or disabled; type-level guarantees cannot be bypassed without an explicit escape hatch.

---

### Other Sections (security-relevant)

#### Section 6: Ecosystem and Tooling — Supply Chain Security

**The detractor's supply chain analysis (Section 6) is the strongest across all councils.** The identification of the `@types` namespace as a TypeScript-specific attack vector is accurate and important:

> "TypeScript's `@types` namespace is a recognized installation pattern, making it a credible attack surface that JavaScript projects without TypeScript do not share." [Detractor, Section 6]

This is a correct and precise claim. The specific December 2024 incidents are documented with credible sourcing [HACKERNEWS-NPM-MALWARE]. The mitigations suggested (npm audit in CI, pinned lockfiles, manual review of new `@types` packages) are reasonable.

The apologist's treatment of the same incidents as "npm ecosystem problems that affect all JavaScript and TypeScript developers equally" (Section 7) is the inverse error: it correctly situates npm as the underlying infrastructure but incorrectly claims equal exposure for all npm users. TypeScript-specific namespaces expose TypeScript-specific users to TypeScript-specific typosquatting.

**DefinitelyTyped stale types as a security concern** deserves more attention than any council gives it. If a `@types/*` package lags the library it describes, developers may use an outdated type declaration that does not reflect a breaking security change in the library's API. A function that was previously safe to call with user-controlled input, and that was updated to require sanitization, may have its old (unsafe) signature preserved in an outdated `@types` package. This is a class of security regression that is specific to the TypeScript dual-artifact architecture (library + separate type declarations) and was not discussed by any council.

#### Section 5: Error Handling — Security implications

The `useUnknownInCatchVariables` improvement (TypeScript 4.4) is a genuine security hardening: it prevents accessing `.message`, `.stack`, or other properties on an unknown thrown value without type narrowing. This was correctly identified by multiple councils. Its security value is concrete: code that called `externalApi().catch(e => authenticate(e.userId))` (accessing a property on an `any`-typed catch variable) would compile without error before TypeScript 4.4 strict mode and would fail at runtime if the caught value was not of the expected shape.

Swallowed exceptions (empty `catch {}` blocks or `.catch(() => {})`) are correctly identified by the practitioner as a source of silent security failure. The important security observation that the councils do not make explicitly: in security-sensitive paths (authentication, authorization, payment processing, session validation), a swallowed exception can silently permit an operation that should have been denied. The language provides no mechanism to enforce that exceptions in security-sensitive code must be handled, logged, or surfaced.

---

## Implications for Language Design

TypeScript's security architecture yields three generalizable lessons for language designers:

**1. Compile-time type erasure creates a permanent security ceiling.**
A type system that does not survive to runtime cannot protect runtime security boundaries. For languages targeting domains where external data is a primary attack surface (web applications, API services, data processing), a design that erases types at compilation delegates the most critical security enforcement to library conventions and developer discipline. The lesson is not that type erasure is wrong — its performance and deployment benefits are real — but that it requires a complementary runtime validation story that should be part of the language design, not an afterthought addressed by third-party libraries with inconsistent adoption.

TypeScript's ecosystem response (Zod, Joi, io-ts, Valibot) demonstrates that developers recognize this gap and fill it. But the variety of competing solutions and the absence of a canonical, language-integrated approach means that every TypeScript project independently discovers the need for runtime validation and chooses a different solution. A language designer who chooses type erasure should consider providing a standard runtime validation mechanism — whether as a core library, a compilation option that preserves type information at selected boundaries, or a `validate(schema, data)` primitive in the standard library.

**2. Escape hatches must be ergonomically costly.**
TypeScript's `as` cast and `!` non-null assertion are single-character operators that disable type-system guarantees at the call site. Their prevalence in production TypeScript code (every production TypeScript codebase has them) demonstrates that ergonomically cheap escape hatches will be used extensively, including at security-relevant locations. Rust's `unsafe` block is syntactically distinctive, multi-character, and culturally treated as requiring justification. The lesson: the ergonomic cost of an escape hatch should be proportional to the guarantee it bypasses. Single-character bypasses normalize the practice of disabling type safety.

**3. Defaults determine the security floor of the ecosystem, not the security ceiling.**
TypeScript's opt-in `--strict` model for twelve years produced a generation of codebases with highly variable actual safety properties, despite all running under the TypeScript brand. A developer who onboarded at a company with pre-6.0 TypeScript might have worked only with implicit `any`, nullable types, and `any`-typed catch variables — and still described themselves as working in a "typed" language. The ecosystem's effective security was determined by the default, not by what the language was capable of under optimal configuration. New languages should make the most secure reasonable configuration the default from day one; retroactive defaults changes are costly and always delayed.

---

## References

[TS-DESIGN-GOALS] "TypeScript Design Goals." GitHub Wiki, microsoft/TypeScript. https://github.com/Microsoft/TypeScript/wiki/TypeScript-Design-Goals

[TS-60-BETA] "Announcing TypeScript 6.0 Beta." TypeScript DevBlog, February 2026. https://devblogs.microsoft.com/typescript/announcing-typescript-6-0-beta/

[TS-30-RELEASE] "Announcing TypeScript 3.0." TypeScript DevBlog, 2018. https://devblogs.microsoft.com/typescript/announcing-typescript-3-0/

[TS-44-RELEASE] "Announcing TypeScript 4.4." TypeScript DevBlog, August 2021. https://devblogs.microsoft.com/typescript/announcing-typescript-4-4/

[TS-ISSUE-9825] "TypeScript GitHub Issue #9825: Proposal: soundness opt-in flag." microsoft/TypeScript. https://github.com/microsoft/TypeScript/issues/9825

[EFFECTIVE-TS-UNSOUND] Vanderkam, D. "The Seven Sources of Unsoundness in TypeScript." effectivetypescript.com, May 2021. https://effectivetypescript.com/2021/05/06/unsoundness/

[GEIRHOS-2022] Geirhos et al. "To Type or Not to Type? A Systematic Comparison of the Software Quality of JavaScript and TypeScript Applications on GitHub." Proceedings of ICSE 2022. https://www.researchgate.net/publication/359389871

[SNYK-TS-SECURITY] "Is TypeScript all we need for application security?" Snyk, 2024. https://snyk.io/articles/is-typescript-all-we-need-for-application-security/

[SNYK-STATE-JS] "The State of Open Source Security 2024." Snyk. https://snyk.io/reports/open-source-security/

[SNYK-SEQTS] "SNYK-JS-SEQUELIZETYPESCRIPT-6085300." Snyk Security. https://security.snyk.io/vuln/SNYK-JS-SEQUELIZETYPESCRIPT-6085300

[ACUNETIX-2022-24802] "CVE-2022-24802." Acunetix Vulnerability Database. https://www.acunetix.com/vulnerabilities/sca/cve-2022-24802-vulnerability-in-npm-package-deepmerge-ts/

[SNYK-DEVALUE] "SNYK-JS-DEVALUE-12205530." Snyk Security. https://security.snyk.io/vuln/SNYK-JS-DEVALUE-12205530

[NVD-2023-30846] "CVE-2023-30846." National Vulnerability Database. https://nvd.nist.gov/vuln/detail/CVE-2023-30846

[NVD-2021-21414] "CVE-2021-21414." National Vulnerability Database. https://nvd.nist.gov/vuln/detail/CVE-2021-21414

[NVD-TS-2025] "CVE-2025-30397." National Vulnerability Database. https://nvd.nist.gov/vuln/detail/CVE-2025-30397

[HACKERNEWS-NPM-MALWARE] "Thousands Download Malicious npm Libraries." The Hacker News, December 2024. https://thehackernews.com/2024/12/thousands-download-malicious-npm.html

[OWASP-TS] "Prototype Pollution Prevention Cheat Sheet." OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html

[DT-REPO] "DefinitelyTyped." GitHub, DefinitelyTyped organization. https://github.com/DefinitelyTyped/DefinitelyTyped

[TS-RESEARCH-BRIEF] "TypeScript — Research Brief." research/tier1/typescript/research-brief.md, this project, February 2026.
