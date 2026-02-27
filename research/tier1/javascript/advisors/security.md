# JavaScript — Security Advisor Review

```yaml
role: advisor-security
language: "JavaScript"
agent: "claude-agent"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

JavaScript's security profile is shaped by a structural condition with no analog in any other language: it is the exclusive scripting environment for the browser, which means attacker-controlled JavaScript executes in the victim's origin context as a matter of design, not failure. This property — not any CVE, not any implementation bug — is the root of the most persistent and costly vulnerability classes associated with JavaScript. XSS (CWE-79) and prototype pollution (CWE-1321) are not incidental problems. They are direct consequences of JavaScript's execution monopoly in the browser and of its prototype-based object model, respectively. The council's overall treatment of these classes is accurate in mechanism but varies in its willingness to attribute responsibility to language design versus developer error.

The council largely agrees on the facts. Where the perspectives diverge is in framing: the apologist argues that XSS is "a platform problem, not a JavaScript problem" and that supply chain security is "state of the art." The detractor argues that the security tooling is "reactive, not preventive." Both framings contain truth, but neither resolves the core question this review is equipped to address: which vulnerability classes are structurally enabled by language design decisions, and which are developer-practice failures that any language could exhibit? The answer matters for language design lessons. Several corrections are needed to sharpen the council's analysis, and several significant claims — particularly regarding CVE-2025-55182 ("React2Shell") — require methodological caution due to recency.

The supply chain dimension deserves separate emphasis. The npm ecosystem's combination of open-publish semantics, deep transitive dependency trees, and pre-install script execution via `postinstall` hooks constitutes an attack surface that is qualitatively different from languages with smaller registries or more conservative package conventions. Supply chain attacks averaging 16–25 per month in 2024–2025 [THENEWSTACK-VULN] are not a temporary disruption — they reflect a structural risk that the community's current tooling (`npm audit`, provenance attestation) addresses reactively and incompletely.

---

## Section-by-Section Review

### Section 7: Security Profile

#### Accurate claims

- **XSS as the dominant web vulnerability class is correctly characterized.** CWE-79 is the most frequently exploited web vulnerability category [CWE-TOP25-2024]. The mechanism — attacker-controlled JavaScript executing in the victim's browser origin — is JavaScript-native. The council's identification of the Polyfill.io incident (June 2024, 100,000+ websites affected) as a structural instance of this attack class is accurate: CDN script injection is XSS by a different delivery vector [THENEWSTACK-VULN]. The five-year old jQuery CVE-2020-11023 being added to the CISA KEV catalog in 2025 is correctly cited as evidence of vulnerability persistence in production deployments [JSCRAMBLER-2025].

- **Prototype pollution is correctly identified as a JavaScript-specific vulnerability class.** CWE-1321 exists because JavaScript's prototype chain allows attacker-controlled property writes (via `__proto__`, `constructor`, `prototype` keys) to modify `Object.prototype`, affecting all downstream objects. The 560 npm vulnerability reports figure [THENEWSTACK-VULN] and the 2024 high-profile packages (web3-utils CVE-2024-21505, dset CVE-2024-21529, uplot CVE-2024-21489) are correctly documented. The historian's structural attribution — "the root is in the Self-inherited prototype model" — is the most analytically precise statement in the council on this topic.

- **Engine-level CVEs (JIT type confusion, use-after-free, bounds check bypass) are correctly categorized as distinct from application-level vulnerabilities.** CVE-2019-9791 (SpiderMonkey IonMonkey type inference) is a documented example [BUGZILLA-SPM]. These vulnerabilities exist in the C++ runtime, not in JavaScript application code, and are patched through browser and runtime updates largely transparent to application developers. The council is correct that this attack surface does not exist in interpreted languages — JIT complexity creates security exposure that pure interpreters avoid.

- **`eval()`, `Function()`, and string-argument forms of `setTimeout`/`setInterval` are correctly identified as language-level code injection surfaces (CWE-94).** These are in the ECMAScript specification and cannot be removed. The detractor's observation that CSP can block `eval()` at the browser level but that this requires operator configuration and breaks libraries depending on dynamic evaluation is accurate and precise.

- **Supply chain attack frequency and the qualitative nature of npm's risk** are accurately described across the council. The open-publish model, the transitive dependency depth, and the postinstall-script code execution pathway are all correctly identified.

- **Strict mode and ES Modules as security improvements are correctly characterized.** `"use strict"` eliminates undeclared variable assignment, prohibits `with`, prevents duplicate parameter names, and converts several silent failures to explicit TypeErrors [ECMA-HISTORY]. ES Modules implicitly enforce strict mode. The council is correct that this is an improvement on the baseline, even if it is not comprehensive.

- **Node.js's default posture gives application code full file system, network, and process access.** The absence of sandboxing at the language level — contrasted explicitly with Deno's opt-in capability model — is correctly identified by the practitioner and realist as a meaningful security gap.

#### Corrections needed

- **The apologist's claim that "XSS is a platform problem, not a JavaScript problem" is insufficiently precise.** It is true that any scripting language embedded in browsers would create similar execution risks. But the specific language design decisions that expand XSS surface area are JavaScript-specific: `eval()`, `innerHTML` as a first-class property accepting arbitrary HTML markup, `document.write()`, `setTimeout`/`setInterval` with string arguments, and template literals that can pass through sanitization boundaries. A version of JavaScript that lacked `eval()` and treated `innerHTML` as write-protected would still have XSS exposure via third-party scripts, but the attack surface within application code would be materially smaller. "Platform problem" understates the degree to which JavaScript's API design choices expand the XSS footprint.

- **CVE-2025-55182 ("React2Shell") should be flagged as requiring independent verification before being cited as established fact.** The research brief includes a reference to this CVE, describing it as enabling prototype pollution and remote code execution via insecure deserialization in React Server Components [NVD-CVE-2025-55182]. The CVE was reportedly disclosed "late 2025" — recently enough that independent confirmation of the technical mechanism and severity score is essential before accepting the characterization. The detractor cites it as an established data point. Until the NVD entry is independently verified with a confirmed CVSS score and technical analysis, this CVE should appear with a caveat rather than as an unqualified citation. If confirmed, it would represent a significant escalation: a critical deserialization RCE in the most widely deployed JavaScript front-end framework.

- **The apologist's characterization of npm's supply chain response as "state of the art for the industry" is contestable.** Compared to Rust's `cargo audit` (integrated into CI by convention, backed by the RustSec Advisory Database) and Deno's architectural approach (URL-based imports with permission flags, no npm `postinstall` scripts), npm's current tooling — `npm audit`, provenance attestation, OpenSSF Scorecard integration — is reactive and incomplete. `npm audit` identifies known CVEs in installed packages; it does not prevent malicious code from executing during `npm install` via `postinstall` scripts, does not detect typosquatting, and does not catch novel supply chain attacks before they are catalogued. The comparison to other large registries is fair; the claim that this represents the state of the art is not.

- **The XSS figure of "2,570 instances across 500 penetration tests" requires methodological context that the council does not supply.** This figure comes from Claranet's 2024 security report [JSCRAMBLER-2025]. It covers general web application penetration testing, not JavaScript-specific deployments. Many of those applications may be PHP, Ruby, or Python back-ends with JavaScript front-ends. The figure does not control for application size, engagement scope, or what percentage are attributable to JavaScript application code versus server-side templating. It is a useful indicator of XSS prevalence in web applications, but it does not specifically quantify JavaScript's contribution to the vulnerability surface.

- **The Node.js `vm` module's security limitations are not explicitly stated in the council.** The detractor's claim that the `vm` module's sandbox "is not a security boundary for untrusted code" is accurate and is confirmed in the Node.js documentation itself: "The node:vm module is not a security mechanism. Do not use it to run untrusted code" [NODEJS-VM-DOCS]. This is not a theoretical concern — it is a documented API limitation. Any security analysis of JavaScript that addresses sandboxing must name this gap explicitly. The council does not cite the documentation.

#### Additional context

- **`postinstall` scripts in npm packages execute arbitrary code during `npm install` with no user confirmation and no sandboxing.** This is not a CVE — it is an intended feature of the npm package lifecycle. But it means that adding a dependency to a JavaScript project is semantically equivalent to running an arbitrary binary downloaded from the internet. The ua-parser-js compromise (2021) exploited exactly this path: 7 million weekly downloads of a package whose `postinstall` script installed a cryptominer and credential stealer [SOCKET-NPM]. `npm audit` could not have detected this before the compromise was catalogued. The only structural defenses are lockfile integrity checks (which verify package identity but not package content) and tools like Socket.dev that perform behavioral analysis on published packages before they are catalogued in CVE databases.

- **The "confused deputy" problem is the underlying structure of CDN-based XSS.** When a site includes a third-party script via `<script src="https://cdn.example.com/lib.js">`, that script runs with the full permissions of the including origin — cookies, localStorage, DOM access. The browser has no mechanism to restrict a third-party script's ambient authority. The Polyfill.io attack's impact on 100,000+ sites [THENEWSTACK-VULN] was directly proportional to the number of sites that had delegated this ambient authority to a single CDN. Subresource Integrity (SRI) hashes would have prevented this specific attack, but SRI adoption is not universally enforced. The Trusted Types API (W3C, available in Chrome-based browsers) is the most promising structural mitigation for DOM-based XSS sinks, but it requires explicit adoption and is not yet universally supported.

- **Isomorphic JavaScript expands the attack surface compared to browser-only or server-only code.** Code that runs in both the browser and Node.js — a common pattern in frameworks like Next.js and in utilities shared between front-end and back-end — faces a compound attack surface: it must be safe against browser-side XSS vectors and server-side injection vectors simultaneously. A deserialization vulnerability in a React Server Component (the alleged mechanism in CVE-2025-55182) would be particularly damaging because it occurs server-side where the browser's Content Security Policy provides no protection.

- **Truthy/falsy coercion has direct authentication bypass implications.** JavaScript's truthy/falsy semantics create subtle security vulnerabilities in access control code. `if (user.admin)` evaluates to `false` for `admin: 0` or `admin: ""` — plausible values in an API response — but to `true` for any truthy value including the string `"false"`. The pattern of comparing against explicit values (`=== true`, `=== 1`) rather than truthy coercion is a JavaScript-specific security practice that TypeScript does not enforce at the language level. This is a type-safety-adjacent security issue that belongs in the type system analysis.

- **The SharedArrayBuffer + Spectre episode is under-discussed in the security context.** In January 2018, all major browsers disabled `SharedArrayBuffer` in response to the Spectre CPU vulnerability disclosure. The vulnerability exploited the fact that `SharedArrayBuffer` enabled construction of high-resolution timers via `Atomics.wait`, which could be used in side-channel attacks to read arbitrary memory across security boundaries [SPECTRE-SAB]. This was the first — and to date, the most significant — instance of a hardware vulnerability causing a live ECMAScript feature to be withdrawn from all browsers simultaneously. Its re-enablement required new HTTP security headers (COOP/COEP) that establish a cross-origin isolation boundary. This precedent matters: JavaScript's execution in the browser means that hardware-level vulnerabilities can propagate into language specification decisions.

#### Missing data

- No CVE frequency data for JavaScript normalized by deployed codebase size, scrutiny level, or lines of code. All raw CVE counts lack analytical weight without such controls.
- No independently verified technical analysis of CVE-2025-55182 from NVD or a security research publication at the time of this writing.
- No confirmed breakdown of XSS vulnerability attribution between JavaScript application code and server-side templating in the Claranet 2024 data.
- No measurement of SRI adoption rates or Trusted Types deployment rates in production applications, which would allow quantifying the gap between available mitigations and deployed mitigations.
- No systematic data on `postinstall` script execution rates and malicious use rate within npm packages — the aggregate exposure of this vector is unquantified.

---

### Section 2: Type System (security implications)

#### Accurate claims

- **Dynamic typing does not directly enable memory corruption vulnerabilities.** The council is correct that JavaScript's dynamic type system, unlike C or C++, does not permit buffer overflows, out-of-bounds writes, or use-after-free at the application level. Memory safety is provided structurally by the garbage-collected runtime.

- **TypeScript's `any` type creates false confidence in security-sensitive code.** The practitioner correctly identifies that TypeScript's `any` escape hatch — present in incomplete `.d.ts` files, legacy code migration paths, and complex generic type positions — means TypeScript type annotations cannot be trusted as runtime security guarantees. A value typed as `UserInput` and then cast with `as string` passes TypeScript type checking at every subsequent call site, but the runtime shape of the value is unconstrained.

- **Type coercions in `==` produce incoherent results that are documented and non-removable.** The detractor's characterization of the Abstract Equality Comparison algorithm as a "coercion calculus that produces results a competent programmer cannot reason about without consulting the specification" is accurate for the specific pathological cases. The backward compatibility constraint means these semantics are permanent [AUTH0-ES4].

#### Corrections needed

- **The apologist and realist framing that "the coercions remain for backward compatibility but are effectively deprecated by community convention" is accurate as a developer guidance point but should not be used to minimize the ongoing security implications.** In 2026, JavaScript codebases still include legacy code, third-party library code, and linter-unenforced sections that use `==`. The ergonomic default in unstructured JavaScript is still to write `==` unless one knows to do otherwise. The security implication — authentication bypass via coerced falsy comparison — is not merely theoretical. It is a recurring pattern in code review findings.

- **The council does not explicitly address the security implications of truthy/falsy coercion in access control contexts.** This is distinct from the `==` / `===` issue. Consider the pattern `if (user.role === 'admin')` versus `if (user.isAdmin)`. The second pattern is vulnerable to any API that returns `isAdmin: 0`, `isAdmin: ""`, or `isAdmin: null` — all of which are plausible JSON representations that evaluate as falsy. TypeScript with `strict: true` does not catch this class of error because the type of `isAdmin` may legitimately be typed as `number | boolean`. This security pattern is JavaScript-specific and deserves explicit enumeration in the type system security analysis.

#### Additional context

- **TypeScript provides no runtime type enforcement.** The council acknowledges TypeScript's limitations but does not state the security corollary clearly: any JavaScript application that receives external data (API responses, user input, deserialized storage) must use a runtime validation library (Zod, Valibot, ArkType) at trust boundaries, because TypeScript's type annotations are erased at compile time. The pattern of typing an API response as `UserData` without runtime validation means that type-checking passed in development but provides zero guarantee against malformed or malicious data at runtime. This gap between static and runtime safety is the primary security weakness of TypeScript-augmented JavaScript.

---

### Section 3: Memory Model (security implications)

#### Accurate claims

- **Application-level JavaScript code cannot produce buffer overflows, heap corruption, or use-after-free.** This claim, made by the apologist, is accurate and significant. The classes of vulnerability that account for the majority of critical CVEs in C and C++ — CWE-787 (out-of-bounds write), CWE-416 (use-after-free), CWE-125 (out-of-bounds read) — are structurally absent from JavaScript application code. This is a genuine safety property of the garbage-collected model.

- **Engine-level CVEs are not application-level vulnerabilities.** JIT compiler bugs in V8, SpiderMonkey, and JavaScriptCore are bugs in C++ runtimes that implement JavaScript, not in JavaScript programs. The practitioner and realist correctly distinguish these tiers.

#### Corrections needed

- **The council's treatment of memory safety should be more explicit that "memory safe" applies only to the application layer.** Browser exploit chains targeting JavaScript-based code execution (from an attacker-controlled page) routinely chain a JIT compiler bug (engine-level memory corruption) with a JavaScript-level primitive that exposes a useful primitive to the attacker. The "memory safe at application level" statement is correct; it should not be read to imply that JavaScript execution contexts are inherently secure against memory-corruption exploits. The JIT tier is the attack surface.

#### Additional context

- **SharedArrayBuffer + high-resolution timers as a Spectre vector is an underappreciated security consequence of the memory model's parallelism extension.** When SharedArrayBuffer was introduced in ES2017 to support WebAssembly multithreading, it inadvertently provided the timing primitive needed for Spectre-class side-channel attacks. The 2018 browser-wide removal and subsequent re-enablement behind COOP/COEP HTTP isolation headers [SPECTRE-SAB] represents the most consequential security-driven modification to an ECMAScript feature to date. The memory model's interaction with hardware microarchitecture vulnerabilities is a risk that GC-based safety at the application level does not address.

---

### Section 4: Concurrency (security implications)

#### Accurate claims

- **The single-threaded event loop eliminates classic data race vulnerabilities at the application level.** Within a single JavaScript execution context, there are no concurrent memory accesses. The council is correct that data races — a major source of undefined behavior and security vulnerabilities in multi-threaded languages — are structurally absent from the main thread execution model.

- **SharedArrayBuffer re-introduces shared mutable memory and the risks that accompany it.** The council's treatment of SharedArrayBuffer as re-enabling potential race conditions is accurate. `Atomics.wait` and `Atomics.notify` provide atomic operations, but the security implications of shared mutable memory — and the 2018 Spectre incident that caused its temporary removal — are correctly noted by the historian.

#### Corrections needed

- **Async TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities are possible in JavaScript's concurrency model and are not discussed by the council.** The async/await model permits a form of interleaved execution: code that checks a condition (a user's permission, a file's existence, a lock state) and then acts on it in a subsequent async operation can have the condition changed by another async operation running in the same event loop between the check and the use. This is not a classic data race, but it is a TOCTOU vulnerability that single-threaded reasoning does not prevent. The pattern appears in server-side Node.js code that checks authorization state, accesses a database, and then performs an action — with other requests processed between each `await`. No council perspective addresses this.

---

### Other Sections (Security-Relevant)

**Section 6 (Ecosystem and Tooling) — Supply Chain:**

The practitioner's supply chain analysis is the most operationally accurate across the council: supply chain risk is the dominant production security concern for JavaScript, and `npm audit` does not prevent novel attacks. Three points deserve strengthening beyond what the council provides:

1. **`npm install` executes arbitrary code via `postinstall` scripts by default.** The research brief's list of notable incidents captures the consequences but does not state the mechanism explicitly in Section 6. Any package in the transitive dependency tree can execute arbitrary code during installation. This is documented behavior, not a vulnerability — it is the intended design. The security implication is that the attack surface for supply chain compromise is every dependency, not just direct dependencies.

2. **The Tea blockchain farming incident (November 2025, 150,000+ packages) [SOCKET-NPM] represents a novel threat vector distinct from malicious code injection.** Token farming packages that perform benign operations to earn blockchain rewards are not directly harmful to dependents, but their presence at scale in the registry reflects that npm's publication model creates economic incentives that security tooling was not designed to detect. The signal-to-noise ratio in npm dependency analysis is degraded by such campaigns.

3. **Deno's architectural response to the supply chain problem is underweighted across the council.** Deno's design — URL-based imports, no `node_modules` directory, explicit `--allow-read`/`--allow-write`/`--allow-net` permission flags at the CLI, and no `postinstall` scripts — provides a structurally different security posture for server-side JavaScript. The practitioner notes this briefly. It deserves more weight as the most significant security improvement in a production JavaScript runtime since Node.js, and as a design lesson for future language/runtime decisions.

**Section 11 (Governance) — Security Policy:**

No council perspective discusses TC39's process for security-relevant specification changes. The SharedArrayBuffer/Spectre episode (a feature withdrawn in 2018 and re-enabled in 2020 with mitigations) is cited historically but not analyzed as a security governance case study. The lesson it demonstrates — that TC39 can coordinate with browser vendors to implement security-driven changes to live ECMAScript features — is relevant to governance assessments. TC39 does not maintain a formal security advisory process analogous to Rust's RustSec or Go's security advisory database; security issues in ECMAScript itself are addressed through the browser vendor security response processes rather than a dedicated language-level channel.

---

## Implications for Language Design

**1. Execution monopoly creates a categorical threat surface that security measures cannot fully address.**
JavaScript's XSS surface exists because it is the only language that executes natively in browsers, and the browser's same-origin trust model was designed before the current adversarial landscape. No amount of developer practice eliminates this surface — it is a consequence of design. Language designers who create execution environments with ambient authority (access to session cookies, DOM, stored credentials by default) must recognize that every content-injection path becomes a potential full-compromise vector. Capability-limited execution models (as in Deno, or as in the Trusted Types approach to DOM access) are structurally safer than ambient authority, at the cost of ergonomic friction.

**2. Mutable prototypes as a global authority surface is a distinctive and instructive mistake.**
JavaScript's prototype pollution class (CWE-1321) is a direct consequence of the design decision to make `Object.prototype` accessible and mutable via property assignment. Self's prototype model was chosen for its expressive flexibility; that flexibility includes the ability to corrupt the root object shared by all instances. Statically typed class-based languages cannot have equivalent vulnerabilities because the class hierarchy is fixed at compile time and the object layout is not accessible to arbitrary key writes. The lesson is that global mutable singletons with unbounded write access are a security liability. Language designers implementing prototype-based or open-object models should provide opt-out mechanisms (like `Object.create(null)`) as explicit first-class patterns, not as obscure workarounds.

**3. The secure path is rarely the default path in JavaScript.**
In JavaScript, `innerHTML` is writable; `eval()` accepts strings; `setTimeout` accepts strings; npm packages execute code on install; Node.js processes start with full file system and network access; function arguments are unchecked. The language's ergonomic center of gravity is toward flexibility and convenience, not toward safety. This is appropriate for the language's original "glue" domain. It becomes a systematic problem when the language is used at scale in adversarial contexts. Language designers should ask: for the adversarial use cases my language will encounter at scale, is the dangerous path harder than the safe path? If not, security properties will degrade with population-level developer choices regardless of available mitigations.

**4. Ecosystem scale superlinearly increases supply chain attack surface in ways a language's design cannot prevent but a runtime's design can constrain.**
JavaScript's supply chain risk is not a consequence of any JavaScript language feature — it is a consequence of npm's open-publish model and the norm of deep transitive dependencies. But the runtime can constrain the blast radius: Deno's permission model means that a compromised dependency cannot access file systems or networks it was not explicitly granted. Node.js's evolution toward `--permission` flags is directionally correct but late. The lesson is that runtime design decisions — particularly around ambient authority and privilege of installed code — have security consequences that compound with ecosystem scale.

**5. Static type systems do not provide runtime security guarantees; language designers should not conflate the two.**
TypeScript's widespread adoption has improved JavaScript's developer experience and catches many classes of programming error. It does not protect against prototype pollution, supply chain attacks, XSS, or runtime type confusion from untrusted external data. The gap between what TypeScript guarantees (consistency of static types within the program) and what it cannot guarantee (consistency of values from external sources) is precisely the gap where many JavaScript security vulnerabilities live. A language that wants runtime security guarantees must enforce them at the runtime boundary (validation, sandboxing, capability checks) — compile-time type checking is a necessary but insufficient component of a secure design.

---

## References

[CWE-TOP25-2024] "CWE Top 25 for 2024." Invicti / MITRE. https://www.invicti.com/blog/web-security/2024-cwe-top-25-list-xss-sqli-buffer-overflows

[THENEWSTACK-VULN] "Most Dangerous JavaScript Vulnerabilities To Watch For in 2025." The New Stack. https://thenewstack.io/most-dangerous-javascript-vulnerabilities-to-watch-for-in-2025/

[JSCRAMBLER-2025] "JavaScript Vulnerabilities to Watch for in 2025." JScrambler Blog. https://jscrambler.com/blog/top-javascript-vulnerabilities-2025

[BUGZILLA-SPM] "CVE-2019-9791: SpiderMonkey IonMonkey type inference is incorrect." Mozilla Bugzilla #1530958. https://bugzilla.mozilla.org/show_bug.cgi?id=1530958

[NVD-CVE-2025-55182] "CVE-2025-55182." National Vulnerability Database (NVD). https://nvd.nist.gov/vuln/detail/CVE-2025-55182 [Note: Disclosed late 2025; independent technical verification of claimed mechanism (insecure deserialization in React Server Components enabling prototype pollution and RCE) should be confirmed against the NVD entry before citing as established fact.]

[SPECTRE-SAB] Mozilla. "SharedArrayBuffer security requirements." January 2018. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer#security_requirements

[NODEJS-SECURITY] "Tuesday, January 13, 2026 Security Releases." Node.js Blog. https://nodejs.org/en/blog/vulnerability/december-2025-security-releases

[NODEJS-VM-DOCS] Node.js Documentation. "vm (Executing JavaScript)." https://nodejs.org/api/vm.html [Relevant note: "The node:vm module is not a security mechanism. Do not use it to run untrusted code."]

[SOCKET-NPM] "npm in Review: A 2023 Retrospective on Growth, Security, and…" Socket.dev. https://socket.dev/blog/2023-npm-retrospective

[AUTH0-ES4] "The Real Story Behind ECMAScript 4." Auth0 Engineering Blog. https://auth0.com/blog/the-real-story-behind-es4/

[ECMA-HISTORY] "A Brief History of ECMAScript Versions in JavaScript." WebReference. https://webreference.com/javascript/basics/versions/

[STATEJS-2024] State of JavaScript 2024 Survey. Devographics. https://2024.stateofjs.com/en-US

[HOPL-JS-2020] Wirfs-Brock, A. and Eich, B. (2020). "JavaScript: The First 20 Years." *Proceedings of the ACM on Programming Languages*, Vol. 4, HOPL. https://www.cs.tufts.edu/~nr/cs257/archive/brendan-eich/js-hopl.pdf

[EICH-INFOWORLD-2018] Eich, B., referenced in: "Regrets? Brendan Eich had one." Medium/@dybushnell. https://medium.com/@dybushnell/regrets-brendan-eich-had-one-caa124d69471

[OCTOVERSE-2025] "Octoverse: A new developer joins GitHub every second as AI leads TypeScript to #1." GitHub Blog. 2025. https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/
