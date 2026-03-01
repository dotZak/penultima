# Lua — Security Advisor Review

```yaml
role: advisor-security
language: "Lua"
agent: "claude-agent"
date: "2026-02-28"
```

---

## Summary

The council's collective security assessment is substantively accurate on the core structural facts: pure Lua is memory-safe by construction, the CVE record reflects C-implementation bugs rather than language-design vulnerabilities, and the sandboxing approach via `_ENV` manipulation is practical but informal. All five council members correctly distinguish between the security of the Lua language and the security of the C implementation, and between the Lua interpreter and its host integration code (illustrated by CVE-2024-31449's attribution to Redis, not Lua). These are not trivial distinctions, and the council handles them well.

However, the council's security analysis has three significant gaps. First, the `debug` library — a well-documented sandbox bypass vector — is mentioned by none of the five council members despite being security-critical in any sandboxed deployment. Second, the council conflates Lua's sandbox model (denylist subtraction) with effective sandboxing, without adequately analyzing why a denylist model is structurally weaker than an allowlist/capability model and what the consequences are. Third, one significant factual claim in the detractor's Section 7 — the LuaRocks 2019 infrastructure incident — cites a reference absent from the research brief and not corroborated by other council members; this should be flagged as unverified before inclusion in the consensus report.

The security ergonomics question — is the secure path the easy path in Lua? — receives insufficient attention. The answer across the relevant deployment contexts (game engine embedding, OpenResty infrastructure, IoT scripting) is consistently "no": the default Lua distribution is not sandboxed, sandbox construction requires correctly enumerating every dangerous function, and the LuaJIT FFI introduces a type-confusion surface that is invisible from Lua-level code. These are structural design issues that produce ongoing operational security costs, and they carry lessons for language designers that the council partially captures but does not sharply articulate.

---

## Section-by-Section Review

### Section 7: Security Profile

#### Accurate Claims

**Pure Lua memory safety.** All five council members correctly establish that pure Lua code cannot produce buffer overflows, use-after-free, or memory corruption. This is a genuine, categorical property of the language design, and the CVE record supports it: every published CVE against the Lua interpreter targets C-level implementation code — the parser (`lparser.c`), the GC (`lgc.c`), the runtime error handler (`luaG_runerror`), or the coroutine engine (`ldo.c`) — not anything accessible from Lua-level scripts [CVEDETAILS-LUA]. The distinction between a memory-safe language and a memory-safe implementation is important, and the council handles it correctly.

**CVE chronology and attribution.** The council accurately characterizes the 2021–2022 CVE cluster as concentrated in the early 5.4.x series (5.4.0–5.4.3), correctly identifies 0 CVEs in 2024 and 1 in 2023, and accurately attributes CVE-2022-28805 to the parser, CVE-2021-44964 to the GC, CVE-2021-43519 to the coroutine engine, and CVE-2022-33099 to the runtime error handler [CVEDETAILS-LUA].

**CVE-2024-31449 attribution.** The council correctly identifies that CVE-2024-31449 is a stack buffer overflow in Redis's Lua integration code (Redis's `eval.c`), not a bug in the Lua interpreter itself [CVE-2024-31449]. The vulnerability existed in Redis code that called into the Lua interpreter without adequately validating the Lua stack depth. This attribution matters for security analysis: Lua's interpreter was not vulnerable; Redis's C code was.

**`_ENV` sandboxing approach.** The council accurately describes Lua's sandbox mechanism: restrict the environment table (`_ENV`) passed to untrusted code, omitting access to `io`, `os`, `load`, `loadfile`, `dofile`, and the `debug` library. This is how game engines and embedded deployments standardly implement Lua sandboxing [LUA-MANUAL-5.4].

**`load()` as a code injection vector.** The practitioner correctly identifies `load()`, `loadstring()`, and `dofile()` as code injection points that must be excluded from sandboxed environments. This is accurate: any context where user-controlled input reaches these functions is equivalent to an `eval()` injection vulnerability [BRIEF-SEC].

**LuaRocks supply chain weakness.** The council accurately characterizes LuaRocks as lacking mandatory cryptographic package verification, with SHA256 support in newer rockspecs but no enforcement by default [LUAROCKS]. This comparison to Cargo (mandatory checksum verification via `Cargo.lock`) and npm (`integrity` field in `package-lock.json`) is fair.

#### Corrections Needed

**LuaRocks 2019 math.random incident [LUAROCKS-SECURITY].** The detractor's Section 7 asserts that LuaRocks used `math.random` (non-cryptographically-secure) for API key and password reset token generation, citing `[LUAROCKS-SECURITY]`. This reference does not appear in the research brief's reference list, is not corroborated by any other council member, and cannot be independently verified from the available sources. While this claim is plausible as a description of an infrastructure security failure at a small community-maintained registry, it should be treated as **unverified** until a primary source is established (e.g., a public post-mortem, security advisory, or GitHub issue from the LuaRocks project). It should not be included in the consensus report without verification.

**PS4 and game console Lua exploitation claim [PS4-VULN].** The detractor cites "game security researchers" finding Lua sandbox escape used in practice against gaming platforms, referencing `[PS4-VULN]`. This reference does not appear in the research brief and is not cited by any other council member. The underlying claim — that Lua interpreter CVEs (specifically CVE-2021-44964 or related) have been used in console security research or homebrewing — is historically plausible; Lua vulnerabilities have appeared in console security research contexts. However, the specific characterization as "used in practice against game engines" and the characterization of the attack vector as "game save data" needs primary source verification before being treated as established fact in the consensus report. The reference should be flagged as unverified.

**CVSS score for CVE-2021-44964.** The apologist states CVSS 6.3 (Medium) for CVE-2021-44964 without citing the source. The NVD entry for CVE-2021-44964 assigns a CVSS 3.x Base Score — reviewers should verify the score against the authoritative NVD record rather than citing a council member's assertion. A CVSS score of 6.3 is consistent with the NVD characterization, but should be directly cited as [NVD-CVE-2021-44964] in the consensus document.

**CVE-2022-28805 exploitation precondition.** The brief and all council members describe CVE-2022-28805 as a heap-based buffer over-read "when compiling untrusted Lua code." The qualifying phrase matters for threat modeling: this vulnerability requires the attacker to supply Lua source code that the interpreter compiles. Deployments that only load pre-compiled bytecode (`luac`-compiled `.luac` files) would not be exposed to this attack vector via the compilation path. Deployments that accept and compile arbitrary Lua source (OpenResty user scripts, Redis `EVAL` commands, game mod loaders) are fully exposed. The consensus report should preserve this distinction.

#### Additional Context

**The `debug` library as a sandbox bypass vector.** None of the five council members mentions the `debug` library's security implications, which is a significant omission. Lua's `debug` library provides functions — specifically `debug.getupvalue()`, `debug.setupvalue()`, `debug.getregistry()`, and `debug.sethook()` — that can read and modify the upvalues (captured variables) of any function in any closure, including functions that implement sandboxing restrictions. If the `debug` library is inadvertently included in a sandboxed environment, a script can use `debug.getupvalue` to read closure variables that the sandbox author intended to be private, and `debug.setupvalue` to overwrite function behavior. `debug.getregistry()` provides access to the Lua registry table, which contains references to all live objects and C-level Lua states. This is a documented sandbox escape vector that sandbox authors must explicitly exclude. The standard guidance (exclude `io`, `os`, `load`, `debug`) implicitly covers this, but the *reason* the `debug` library must be excluded — its ability to bypass closure isolation — deserves explicit documentation in any security treatment of Lua sandboxing.

**Denylist vs. allowlist security model.** Lua's sandbox approach is structurally a denylist (subtraction) model: the operator takes the full Lua standard library and removes dangerous capabilities. The security concern is not only that the implementation may have bugs, but that the design places the burden of correctly enumerating *all* dangerous capabilities on the operator. Missing any one dangerous function — `debug.getregistry`, `load`, an FFI pointer, an improperly restricted `table` function — creates a sandbox escape. Contrast this with an allowlist (addition) model, where the sandbox starts with nothing and grants only specific needed capabilities. Roblox's Luau achieves something closer to an allowlist model through its capability-based enforcement layer built atop the Lua runtime [LUAU-WIKI]. The detractor partially captures this when noting "sandboxing is security-by-subtraction," but doesn't analyze why this matters structurally. The realist and apologist are correct that `_ENV` restriction works in practice for well-configured deployments — but the operational burden of maintaining a correct denylist grows with every new Lua standard library addition.

**LuaJIT FFI type confusion.** The LuaJIT FFI, while ergonomically superior to the standard C API, introduces a type confusion attack surface that is absent from PUC-Lua. The FFI allows Lua code to declare C function signatures and call them directly. If a declared FFI signature does not match the actual C function's ABI (different argument types, wrong calling convention, incorrect pointer type), the result is undefined behavior at the C level, even though the code appears to be "Lua" code. In OpenResty deployments where developers write FFI calls to system or application libraries, signature mismatches are a real bug class that can produce exploitable memory corruption. This surface is unique to LuaJIT deployments; PUC-Lua's stack-based C API does not have an equivalent (the C compiler checks the wrapper function signature). None of the council members discusses FFI type confusion as a security concern.

**GC finalizers and security-sensitive state.** Lua's `__gc` finalizers run during garbage collection at times that are not fully predictable from the application's perspective. If finalizers access application state that could be in a partially-initialized or inconsistent state during GC execution, this creates potential TOCTOU (time-of-check/time-of-use) issues. More specifically, in coroutine-based architectures (OpenResty), GC may trigger during a coroutine's I/O yield. If a finalizer modifies shared tables or global state during this yield, it creates a window where a resuming coroutine sees unexpected state. This is a subtle but real concern for OpenResty applications that use finalizers for cleanup of security-sensitive resources.

**Missing CVE density comparison.** Multiple council members claim Lua has a "better record" or "lower CVE density" than comparable C-implemented interpreters. This claim as stated is not meaningful without normalization. Relevant confounds: (1) Lua's C implementation is small (~20,000 lines), reducing absolute attack surface compared to CPython (~500,000 lines); (2) Lua has historically attracted less security researcher attention than Python, Ruby, or PHP, which are higher-value targets due to broader deployment; (3) the deployment contexts for Lua (embedded in games, not publicly internet-facing in most cases) reduce security researcher incentive. The council should either provide a normalized comparison or drop the comparative claim. The more defensible claim — which the realist makes correctly — is that "CVEs in the Lua interpreter cluster in the C implementation rather than the language design, which is the expected pattern for a memory-safe scripting language."

**No independent security audit.** None of the council members notes that the Lua 5.4/5.5 codebase has not, to public knowledge, undergone an independent third-party security audit comparable to the audits conducted on OpenSSL (by NCC Group, Cure53), the Linux kernel (various), or the Rust standard library (by Cure53 in 2023). The 2021-2022 CVE cluster suggests the 5.4.x codebase had not been systematically audited before release. This is not unusual for an academic open-source project, but it is relevant for organizations making security-critical deployment decisions about Lua.

---

### Section 2: Type System (security implications)

#### Accurate Claims

**Metatable opacity complicates security analysis.** The detractor correctly identifies that metatable-based dispatch makes static analysis of Lua code difficult: `obj:method()` may dispatch through an `__index` chain that is only determinable at runtime. This is accurate, and it has a direct security implication: static security auditing tools cannot reliably trace the behavior of metatable-based code without runtime analysis. Any tool that attempts to verify that a sandbox is correctly configured by reading Lua source code faces this limitation.

**No algebraic data types or union types.** The council's observation that Lua cannot express typed error returns or discriminated unions at the type level is accurate. From a security perspective, this means functions that can fail in multiple ways (network error vs. permission error vs. data corruption) cannot communicate this distinction through the type system, increasing the probability that callers will handle errors incorrectly or silently swallow errors.

#### Corrections Needed

None. The type system security analysis in the council is structurally accurate.

#### Additional Context

**String coercions and injection risks.** The council notes string-to-number coercions (`"10" + 5 == 15`) as a footgun but does not connect this to security implications. The connection is indirect but real: in code that validates user input, an implicit coercion can allow a string that represents a number to pass a numeric validation check while still containing injection characters. For example, a Lua function that validates `type(x) == "number"` would correctly reject a string, but code that uses arithmetic operations to validate numeric input may coerce strings before the type check runs. This is a niche but documented source of input validation confusion in Lua web applications.

**LuaJIT FFI type annotations from Lua.** In LuaJIT FFI usage, Lua code specifies C type declarations for imported functions. These declarations are not validated at load time against the actual linked library. The type system claims (Section 2) should note this as an escape from even Lua's dynamic type safety: FFI pointer types are not verified, allowing type confusion at the C/Lua boundary in LuaJIT deployments.

---

### Section 3: Memory Model (security implications)

#### Accurate Claims

**Pure Lua memory safety.** The council correctly establishes that pure Lua scripts cannot produce memory corruption. The realist's formulation — "pure Lua is memory-safe by construction: no pointer arithmetic, no buffer operations, no way to corrupt the process from Lua-level code" — is accurate and appropriately conditional.

**C extension attack surface.** The practitioner correctly identifies C extensions as the primary real-world vulnerability surface: "The vulnerability surface is elsewhere. The Lua interpreter itself had concentrated CVE activity in 2021-2022... CVE-2024-31449 was a stack buffer overflow in Redis's embedded Lua scripting." This framing is correct.

**pcall/longjmp and C++ destructor interaction.** The detractor's analysis of `lua_pcall` using `longjmp` to unwind the stack, which skips C++ destructors and leaks RAII-managed resources, is accurate. This is documented behavior in the Lua C API manual [LUA-MANUAL-5.4]. The workaround — wrapping C++ entry points in a C++ `try`/`catch` before calling Lua — is described correctly.

#### Corrections Needed

None. The memory model security analysis is accurate.

#### Additional Context

**RAII resource leak is a security concern, not just a correctness concern.** The detractor frames the pcall/longjmp/C++ issue primarily as a memory/resource leak. It is also a security issue: if C++ RAII manages security-sensitive resources — file descriptor locks, mutexes preventing TOCTOU races, cryptographic keys held in locked memory, reference counts preventing use-after-free — a Lua error that unwinds through C++ code without triggering destructors can leave the application in an insecure state. An attacker who can trigger a Lua error at the right moment could cause the application to process a subsequent request with a partially-released lock or freed cryptographic material. The consensus report should elevate this from a "correctness concern" to a "security concern."

**`lua_State` thread safety as a security boundary.** The detractor mentions that `lua_State` is not thread-safe, but frames it as a documentation/operational concern. The security framing: if an embedding application violates this constraint (accessing the same `lua_State` from multiple threads without proper serialization), the result is heap corruption. Depending on the application, this can be exploitable for remote code execution by an attacker who controls the timing of requests to trigger concurrent Lua state access. This is not hypothetical; it is a known pattern in multi-threaded web application servers that embed Lua. The consensus report should note `lua_State` thread isolation as a security requirement, not just an operational recommendation.

---

### Section 4: Concurrency (security implications)

#### Accurate Claims

**Cooperative concurrency eliminates Lua-level data races.** The council correctly identifies that Lua's cooperative coroutine model prevents data races within a single Lua state: no coroutine switch occurs without an explicit `coroutine.yield()`, so shared state within a Lua state is accessed sequentially. This is a genuine security property for intra-state code.

**OpenResty's isolation model.** The realist's description of OpenResty's per-request coroutine model as preventing data races "by construction" is accurate within its scope: each request runs in its own coroutine, and Nginx's event loop serializes coroutine execution, so no two coroutines execute simultaneously [OR-DOCS].

#### Corrections Needed

None.

#### Additional Context

**Coroutine interleaving as a TOCTOU vector.** The council does not analyze an important security nuance: while Lua cooperative scheduling prevents simultaneous execution, it does not prevent TOCTOU vulnerabilities in coroutine-based architectures. In an OpenResty application, if a coroutine checks a condition (e.g., verifies a user's session token), yields to the event loop for a network operation, and then acts on that condition, another coroutine can modify shared state (the session table) between the check and the action. This is a classic check-then-act race condition, mediated not by threads but by coroutine yields. Secure OpenResty code must be careful about what shared state it reads before a yield vs. what it trusts after a yield. This is a subtler version of the TOCTOU problem that Go and async Rust developers face, but it is present in Lua's cooperative model.

**Denial of service via non-yielding coroutines.** A malicious or buggy Lua coroutine that never yields can starve other coroutines indefinitely in cooperative scheduling systems (including OpenResty). Standard Lua has no preemption and no timeout mechanism for coroutine execution. In contexts where untrusted Lua code runs alongside critical coroutines (e.g., health check endpoints alongside user request handling in OpenResty), a non-yielding coroutine is a denial-of-service vector. Some OpenResty deployments mitigate this with Nginx worker timeouts, but there is no Lua-language mechanism to enforce coroutine yield requirements.

---

### Other Sections (security-relevant flags)

**Section 6 (Ecosystem): LuaRocks and supply chain.** The council's characterization of LuaRocks supply chain weakness is accurate: SHA256 hashes are supported in newer rockspecs but are not verified by default in all configurations [LUAROCKS]. The correct implication for security-conscious deployments is: (1) pin all LuaRocks dependencies to specific versions with explicit SHA256 hashes in the rockspec; (2) run LuaRocks with `--pin` to generate a lockfile (available since LuaRocks 3.3.0, but opt-in). The council correctly notes this gap; the consensus report should add the actionable mitigation guidance.

**Section 6: Standard library cryptography gap.** None of the council members explicitly flags the absence of cryptographic primitives from Lua's standard library as a security design issue. Lua's deliberate exclusion of networking, TLS, and cryptography means that every Lua deployment that needs secure communication or authenticated operations must select and integrate a third-party cryptographic library. The common choices for OpenResty are `lua-resty-openssl` (OpenSSL bindings) and LuaJIT FFI-based cryptographic wrappers. For PUC-Lua standalone deployments, options include `lua-crypto` (OpenSSL), LuaCrypto, and others. This fragmentation means there is no single well-audited cryptographic implementation for Lua; security properties vary across the ecosystem, and the choice is left to the application developer. The consensus report should note this as a structural security concern for any Lua application requiring cryptographic operations.

**Section 8 (Developer Experience): Default insecurity of global scope.** The council's discussion of global-by-default variables is framed primarily as a correctness and ergonomics issue. The security framing is stronger: in any context where multiple Lua scripts run in a shared environment (shared global `_G`), accidental globals become an injection vector. A script that assigns to `result` (intending a local variable) can have its value overwritten by another script that also uses `result`. In a multi-script game engine where scripts from different mod authors share a Lua state, this creates an unintentional communication channel that can be exploited by a malicious mod to influence another mod's behavior. This is not a hypothetical; it is the actual threat model for game modding platforms, and it is why Lua 5.5's explicit `global` declarations (opt-in) and environment isolation are important for sandboxed deployments.

---

## Implications for Language Design

**1. Denylist sandboxes have irreducible maintenance burden; allowlist capability systems are structurally stronger.**
Lua's `_ENV` sandboxing requires operators to know and enumerate every dangerous function in the standard library, current and future. Each new Lua release that adds a function with security implications requires sandbox operators to update their exclusion lists. Lua 5.4's `__close` metamethod, for example, could in principle be misused if not properly understood. Contrast this with Roblox's Luau capability model, which grants specific permissions rather than removing specific capabilities. Language designers who intend their language to execute untrusted code should build a capability model from the start. Retrofitting capability-based isolation onto a language with global-by-default access (as Lua demonstrated) requires a separate enforcement layer and remains incomplete for standard deployments.

**2. Reflection and introspection libraries must be treated as security-critical capabilities, not debugging utilities.**
Lua's `debug` library is presented in documentation primarily as a debugging aid, but it provides the ability to bypass closure isolation and access the global registry — capabilities that destroy sandbox guarantees if made available to untrusted code. Language designers should treat reflection APIs (Lua's `debug`, Java's `Reflection`, Python's `inspect`) as security-sensitive capabilities subject to the same access controls as file system or network access. If the language will be used in sandboxed contexts, the design should ensure reflection can be fully excluded without impacting non-sandboxed use cases.

**3. The managed/C boundary is an ongoing security liability that scales with extension code volume.**
Lua's memory safety guarantee applies only to pure Lua code. Every C extension added to a Lua deployment extends the attack surface by the attack surface of that C extension. In large deployments (OpenResty with dozens of C-based `lua-resty-*` libraries), the aggregate C extension attack surface dwarfs the Lua interpreter itself. CVE-2024-31449 in Redis demonstrates that even mature, high-scrutiny projects introduce vulnerabilities at this boundary [CVE-2024-31449]. Language designers embedding managed languages in C hosts should provide:
- Strong type checking at the C boundary (LuaJIT FFI does not do this)
- Memory-safe C interop where feasible (Rust's `unsafe` blocks, Wasm's boundary model)
- Automated stack balance verification for stack-based C APIs

The more C code exists in the extension ecosystem, the more the managed language's memory safety guarantees are diluted.

**4. GC correctness is a security property, not just a performance property.**
CVE-2021-44964 — a use-after-free in Lua's GC enabling sandbox escape — demonstrates that GC bugs are security bugs, not just crash bugs. In any language that provides memory safety through GC, the GC's correctness is a security invariant: if the GC allows a Lua value to be freed while a reference to it remains accessible, the safety guarantee is broken. The 2021-2022 Lua CVE cluster coincided with the release of Lua 5.4 and its new generational GC mode. Language teams that ship new GC modes should treat GC correctness testing as security testing, applying adversarial inputs (crafted scripts designed to trigger GC at specific points) in addition to performance benchmarks.

**5. The secure path must be the default configuration.**
The default Lua distribution is not sandboxed. An embedding application that loads the standard Lua libraries without restriction exposes `io`, `os`, `load`, `debug`, and the package system to any Lua code it runs. Securing the default requires the operator to take affirmative action — omitting libraries, replacing `load`, restricting `_ENV`. This is the wrong default for any language used in untrusted-code execution contexts. Language designers should ask: "If a developer copies a 'Hello World' embed example from the documentation, how much damage can untrusted Lua code cause?" The answer for Lua is "complete system access." The documentation should make sandbox construction a first step, not an advanced topic.

**6. The absence of standard cryptography creates a fragmented and less-audited cryptographic ecosystem.**
Lua's design philosophy of excluding everything not needed for the embedding model produces a language with no standard cryptographic library. Every Lua deployment that requires cryptography assembles its own combination of FFI bindings, C extensions, and pure-Lua implementations. This creates fragmentation in which cryptographic algorithms are available, how they are called, and which have received security audits. Contrast with Go's `crypto/tls` and Python's `ssl` — standard library inclusions that receive ongoing community security attention and coordinated vulnerability disclosure. Language designers should include a standard, audited cryptographic foundation even for languages with minimal stdlib philosophies; the security cost of absence is borne by every downstream user.

**7. JIT implementations that diverge from the reference implementation create unequal security patching.**
LuaJIT's divergence from PUC-Lua (frozen at Lua 5.1) creates a situation where security patches applied to PUC-Lua do not reach LuaJIT users. The 2021-2022 CVE fixes were applied to PUC-Lua 5.4.4; LuaJIT users received community-maintained patches on a best-effort basis. Any language ecosystem that has a performance-critical alternative implementation must have a clear mechanism for security patch coordination. Languages should treat JIT implementation compatibility as a security concern, not just a feature compatibility concern.

---

## References

[HOPL-2007] Ierusalimschy, R., de Figueiredo, L.H., Celes, W. "The evolution of Lua." *Proceedings HOPL III*. ACM, June 2007. https://www.lua.org/doc/hopl.pdf

[NEEDLE-2011] Ierusalimschy, R., de Figueiredo, L.H., Celes, W. "Passing a language through the eye of a needle." *Communications of the ACM*, Vol. 54, No. 7, July 2011.

[LUA-MANUAL-5.4] Ierusalimschy, R. et al. "Lua 5.4 Reference Manual." lua.org. https://www.lua.org/manual/5.4/manual.html

[CVEDETAILS-LUA] CVE Details — LUA security vulnerabilities. Vendor ID 13641. https://www.cvedetails.com/vulnerability-list/vendor_id-13641/LUA.html

[CVE-2024-31449] "CVE-2024-31449 — Redis Lua scripting stack buffer overflow." Redis Security Advisory, October 2024. https://redis.io/blog/security-advisory-cve-2024-31449-cve-2024-31227-cve-2024-31228/

[NVD-CVE-2021-44964] NVD entry for CVE-2021-44964 (use-after-free in Lua GC). https://nvd.nist.gov/vuln/detail/CVE-2021-44964

[NVD-CVE-2022-28805] NVD entry for CVE-2022-28805 (heap buffer over-read in Lua parser). https://nvd.nist.gov/vuln/detail/CVE-2022-28805

[NVD-CVE-2021-43519] NVD entry for CVE-2021-43519 (stack overflow in lua_resume). https://nvd.nist.gov/vuln/detail/CVE-2021-43519

[NVD-CVE-2022-33099] NVD entry for CVE-2022-33099 (heap buffer overflow in luaG_runerror). https://nvd.nist.gov/vuln/detail/CVE-2022-33099

[LUAROCKS] LuaRocks project. https://luarocks.org/

[LUAROCKS-3.3] LuaRocks 3.3.0 changelog noting `--pin` lockfile support. https://github.com/luarocks/luarocks/blob/master/CHANGELOG.md

[LUAU-WIKI] "Luau (programming language)." Wikipedia. https://en.wikipedia.org/wiki/Luau_(programming_language)

[OR-DOCS] OpenResty documentation — Lua Nginx module. https://openresty.org/en/lua-nginx-module.html

[CF-BLOG] Cloudflare blog. "Pushing Nginx to its limit with Lua." https://blog.cloudflare.com/pushing-nginx-to-its-limit-with-lua/

[PIL] Ierusalimschy, R. *Programming in Lua*, 4th ed. 2016. https://www.lua.org/pil/

[BRIEF-SEC] Lua — Research Brief, Security Data section. `research/tier1/lua/research-brief.md`

[OWASP-TOCTOU] OWASP. "Time of check Time of use (TOCTOU) Race Conditions." https://owasp.org/www-community/vulnerabilities/Time_of_check_Time_of_use
