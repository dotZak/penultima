# Erlang/Elixir — Security Advisor Review

```yaml
role: advisor-security
language: "Erlang-Elixir"
agent: "claude-agent"
date: "2026-03-01"
```

---

## Summary

The BEAM ecosystem's security story is structurally bifurcated: the managed runtime genuinely eliminates entire vulnerability classes that dominate C/C++ CVE histories, while simultaneously introducing a small set of distinctive footguns that the council perspectives handle inconsistently. Process isolation, no pointer arithmetic, and immutable-by-default data structures collectively eliminate buffer overflows, use-after-free, and data races from pure BEAM code — these are genuine and significant security properties, accurately reported across most council perspectives.

What the council systematically underweights or misses entirely are three issues. First, the `binary_to_term/1` deserialization attack surface: unconstrained use of Erlang's external term format with attacker-controlled input can exhaust the atom table, crash the VM, and in older implementations execute arbitrary code — none of the five council perspectives mentions it. Second, the cookie-based distribution protocol's structural inadequacy: only the detractor treats this honestly as a 1986-era threat model that was never updated; others present operational mitigations (VPNs, firewalls) as though they resolve the underlying design problem rather than work around it. Third, the atom exhaustion DoS class: `String.to_atom/1` called with user-controlled data is a crasher with no runtime warning — a critical security footgun that the council's security sections do not address.

The 2025 SSH vulnerability cluster (CVE-2025-32433 and two companion SSH CVEs in the same release cycle) is covered with varying accuracy. The detractor's structural analysis is the most useful. The apologist's framing minimizes what the data actually shows: three significant SSH vulnerabilities in a single cycle is evidence of historically insufficient adversarial review of that implementation, not normal software maintenance. For designers, the lesson is that bundling a complex protocol implementation into the runtime's standard library creates a high-value, hard-to-patch attack surface that requires dedicated security resources proportional to its deployment exposure.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **Memory safety elimination of C/C++ vulnerability classes.** Every council perspective correctly identifies that the BEAM's managed memory eliminates buffer overflows, use-after-free, and heap corruption from pure BEAM code. This is empirically supported: CVE analysis of the Erlang/OTP vulnerability history at cvedetails.com shows no memory corruption CVEs attributable to BEAM VM internals in managed code; the SSH cluster and historical regex/CBC vulnerabilities all trace to C implementation code in OTP applications, not to BEAM bytecode execution [CVEDETAILS-ERLANG].

- **Process isolation and data races.** The claim that data races are structurally prevented in pure BEAM code is accurate. Process isolation via separate heaps with message-copying semantics means no two processes share mutable memory without explicit shared structures (ETS). This is a genuine, verifiable security property.

- **CVE-2025-32433 disclosure and patch timeline.** All perspectives accurately cite the CVSS 10.0 classification, the pre-authentication nature of the vulnerability (SSH connection protocol messages ≥ 80 sent before authentication completes), and the patched versions (OTP-27.3.3, OTP-26.2.5.11, OTP-25.3.2.20) [CVE-2025-32433-GHSA].

- **Ecto parameterized queries.** The apologist's and practitioner's claims that Ecto's query composition API structurally prevents SQL injection are accurate for the primary query interface. Ecto uses parameterized queries at the adapter level; string interpolation into queries requires explicit escape functions [ECTO-SECURITY].

- **Phoenix CSRF protection.** Phoenix includes CSRF token middleware enabled by default in web pipelines via `Plug.CSRFProtection`. This is accurate.

- **NIF crash propagation.** All perspectives that address NIFs accurately describe the crash semantics: a NIF that crashes takes the entire BEAM VM with it, because NIFs execute in the same OS process as the scheduler [ERL-NIF-DOC].

**Corrections needed:**

- **The apologist minimizes the 2025 SSH cluster.** The apologist frames CVE-2025-32433 as evidence that "fast patch response" demonstrates ecosystem security maturity. This inverts the actual signal. Three significant SSH vulnerabilities in a single release cycle — a pre-authentication RCE (CVSS 10.0), a KEX hardening bypass enabling man-in-the-middle injection, and a resource exhaustion bug affecting every OTP version from 17.0 through 28.0.3 — is evidence that the OTP SSH implementation was not receiving adversarial security review proportional to its attack surface [CVE-2025-32433-GHSA] [CVE-SSH-MITM] [CVE-SSH-RESOURCE]. The detractor's framing is more accurate: the structural exposure is that the `ssh` application ships embedded in the runtime itself, making every OTP deployment with SSH enabled part of the attack surface without a separate opt-in decision.

- **Unit 42 attribution needs contextualization.** The detractor cites the Unit 42 finding that nearly 70% of exploit attempts targeted sectors traditionally considered low-risk [CVE-2025-32433-UNIT42]. This requires a methodological note: "exploit attempts" in honeypot or scan data does not constitute confirmed compromises, and sector attribution in opportunistic scanning reflects deployment prevalence rather than attacker targeting decisions. The datum is still significant — it indicates widespread deployment of the vulnerable SSH implementation outside of security-hardened environments — but should be framed as evidence of deployment hygiene rather than adversarial intent.

- **Cookie MD5 authentication characterization.** The research brief describes cookie-based authentication without calling out the specific algorithm. The distribution protocol uses MD5 for challenge-response authentication — a cryptographic hash function that has been considered broken for collision resistance since 2004 and for security-critical applications since at least 2009 [RFC-6151]. For the specific use case (HMAC-like challenge-response where preimage resistance rather than collision resistance is the relevant property), MD5 is not known to be immediately exploitable, but its use in a 2026 authentication context is a security technical debt issue regardless. The real problem is cleartext distribution by default — the cookie is transmitted over an unencrypted TCP channel unless TLS distribution is explicitly configured [DIST-TLS].

**Additional context:**

- **`binary_to_term/1` deserialization — critical missing coverage.** None of the five council perspectives addresses the external term format (ETF) deserialization vulnerability class. Erlang's `:erlang.binary_to_term/1` function, when called with attacker-controlled input, can: (1) exhaust the atom table by creating arbitrary atoms (atoms are not garbage collected); (2) in older OTP versions, instantiate anonymous functions from the binary, enabling arbitrary code execution [ETF-SECURITY]. The safe pattern is `:erlang.binary_to_term(input, [:safe])`, which refuses to create new atoms or functions. In Elixir, Phoenix Channel serialization and many RPC/messaging libraries that accept arbitrary binary input must use this safe form. Libraries that accept serialized Erlang terms from external sources and use the unsafe form are in a vulnerability class analogous to Java's insecure deserialization — and this class has produced RCE vulnerabilities in other ETF-consuming systems. This omission in all five council perspectives is the most significant security coverage gap in the council output.

- **Atom exhaustion via `String.to_atom/1`.** In Erlang/Elixir, atoms are stored in a global atom table with a default limit of 1,048,576 atoms (OTP default). Atoms are never garbage collected. Calling `String.to_atom/1` or `:erlang.binary_to_atom/2` with user-controlled input can exhaust this table, crashing the entire VM. The safe alternative is `String.to_existing_atom/1`, which raises an error if the atom does not already exist in the table. This is a well-documented footgun: the official Elixir documentation for `String.to_atom/1` includes a warning; OTP documentation for `binary_to_atom/2` includes a warning; and practical Elixir security guides consistently identify it as a DoS vector [ELIXIR-DOCS-ATOM] [OWASP-ELIXIR]. The council's security sections do not address it.

- **ETS and application-level race conditions.** The claim that "data races are prevented" requires scope qualification when ETS is involved. ETS (Erlang Term Storage) provides in-memory tables that are genuinely shared between processes — unlike message-copied process state. ETS provides atomic reads and writes at the individual record level, but application-level check-then-act patterns on ETS are not atomic and can produce race conditions. For example: reading a counter from ETS, computing a new value, and writing it back is three non-atomic operations that concurrent writers can interleave. For security-relevant operations (rate limiting, session token validation, permission checks), ETS-based implementations require explicit atomic operations (`ets:update_counter/3`, `ets:update_element/3`, or ETS `select_replace`) rather than read-modify-write patterns [ETS-DOC].

- **Distribution TLS not default.** Erlang node distribution uses unencrypted TCP by default. Encrypted distribution requires explicit TLS configuration via `inet_tls_dist` with self-managed certificates [DIST-TLS]. In Kubernetes environments, BEAM nodes frequently communicate across pod boundaries without TLS, meaning the Erlang cookie (the sole authentication mechanism) traverses unencrypted network paths. This means an attacker with network access between pods can capture the cookie from a single distribution handshake and achieve RCE on all cluster nodes. The mitigations (Kubernetes network policies, mTLS service meshes, VPNs) are valid but are operational controls that must be explicitly applied — the secure configuration is not the default.

- **`:crypto` module inherits OpenSSL CVE surface.** The OTP `:crypto` module wraps OpenSSL (or LibreSSL, depending on platform configuration). While the Erlang layer is managed-memory safe, the underlying C library is not. OpenSSL CVEs (such as Heartbleed in 2014, and the more recent 2022–2023 critical vulnerabilities) propagate to any Erlang/OTP deployment using `:crypto`. Teams that rely on OTP's cryptographic implementations inherit OpenSSL's vulnerability surface without direct visibility [ERLANG-OPENSSL].

**Missing data:**

- The council does not address the EEF Security Working Group (SWG), established in 2021, which coordinates security responses across the BEAM ecosystem. Its existence and mandate are relevant to the governance of security issues [EEF-SWG].

- No council perspective addresses Elixir-specific web vulnerability classes beyond SQL injection and CSRF: mass assignment vulnerabilities in Phoenix (mitigated by Ecto changesets' explicit cast/validate pattern), XSS via unsafe HTML rendering in LiveView (mitigated by automatic HTML escaping except in explicit raw() calls), and HTTP response splitting risks in custom plug implementations.

- Hex.pm's package signing mechanism deserves more specificity: Hex uses package registry signatures (Ed25519 signatures on package tarballs as of Hex 0.18+). The `mix hex.audit` command (introduced in Hex 0.20+) checks for packages with known security vulnerabilities via the Erlang Ecosystem Foundation's security advisory database. This is more mature tooling than the council's "less mature than Rust" characterizations suggest, though still behind cargo-audit's integration with the RustSec advisory database [HEX-AUDIT].

---

### Section 2: Type System (security implications)

**Accurate claims:**

- The practitioner's observation that Dialyzer's "success typing" produces false negatives (it reports zero warnings for some codebases where type errors exist) is accurate and security-relevant. A tool that is silent when violations exist provides false confidence for security-critical code paths [DIALYZER-LYSE].

- The gradual nature of Elixir's type system rollout (v1.17–v1.20) means type coverage is incomplete during the transition. Security-critical code that relies on type annotations for argument validation guarantees should not assume full coverage in the current implementation.

**Corrections needed:**

- The apologist's Section 2 implies that set-theoretic types improve injection resistance by making wrong-shaped data fail at type-check time. This overstates what the current type system guarantees. Elixir v1.20's inference covers all constructs but the type system is not a security mechanism — it warns, does not enforce, and does not cover the runtime boundary with external data. Type annotations do not prevent injection if the external input reaches the function with the correct type signature (e.g., a string that is correctly typed as `String.t()` but contains SQL injection payload).

**Additional context:**

- The atom table exhaustion risk (see Section 7) is directly related to the type system's dynamic nature. In a statically typed language with closed atom-equivalent types (e.g., Rust enums, Haskell ADTs), atom exhaustion is impossible by construction because the closed set of atoms is fixed at compile time. Erlang's dynamic atoms as a first-class type enable expressive pattern matching but introduce an unbounded runtime DoS vector that static typing would prevent.

- Pattern matching as the primary type dispatch mechanism has a security implication: unhandled clauses (`function_clause` errors) crash the calling process, which is then restarted by the supervisor. This is the "let it crash" mechanism — it is correct behavior in Erlang's fault model, but if the crash boundary is reachable with attacker-controlled input, it becomes an amplified DoS vector. A function clause crash restarts the supervised process; repeated crashes against a supervisor with a high `max_restarts` can saturate supervisor restart budgets and permanently take down a subsystem.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- Per-process garbage collection means no stop-the-world GC pauses and no cross-process memory corruption — both accurate. The security implication is that a process handling malicious input that causes a GC storm is contained to that process's heap.

- The large binary optimization (binaries >64 bytes stored in a shared binary heap with reference counting) is accurately described. From a security perspective: shared binaries are read-only from the BEAM side; the reference counting is handled by the runtime, not user code. There is no user-space reference counting confusion that could lead to use-after-free.

- NIF crash semantics are accurately described: a crashing NIF kills the OS process that hosts the BEAM VM.

**Corrections needed:**

- The historian's Section 3 does not address NIFs from a security perspective. Since the historian frames Erlang's memory model as a departure from C's "unsafe" model, the NIF exception deserves explicit acknowledgment: the managed-memory guarantee is voided at every NIF boundary. A system that uses NIFs (and most production BEAM systems do, transitively through libraries like `fast_tls`, `ezstd`, codec libraries, and crypto wrappers) is operating a hybrid managed/unmanaged memory model. The security perimeter is the set of NIF calls in the dependency tree, not the managed BEAM code itself.

**Additional context:**

- Rustler-based NIFs (NIFs implemented in Rust) reduce but do not eliminate memory safety concerns. Rust's safety guarantees apply to the Rust code's memory management, but: (1) Rust panics in NIFs become BEAM crashes; (2) Rust code that uses `unsafe` blocks retains C-like vulnerability potential; (3) resource leak bugs in Rustler NIF resource objects can exhaust VM memory without triggering a crash. The characterization of Rustler as a security improvement over C NIFs is accurate in tendency but should not be treated as equivalent to BEAM-managed safety.

- The process mailbox as an unbounded queue (addressed in Section 4 of several perspectives) has a memory safety implication: a process that cannot keep up with its message rate will grow its heap unboundedly until the VM triggers an OOM condition. Depending on OS configuration, this can kill the VM process (Linux OOM killer) or cause allocator failures. GenStage and Broadway provide backpressure-aware pipeline abstractions, but they are opt-in libraries, not runtime guarantees.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- Data race elimination in pure BEAM code is accurate. The actor model with message-copying semantics means no two processes share mutable references. This eliminates TOCTOU (time-of-check to time-of-use) races that involve process-private memory.

- The no-colored-functions claim has a security-relevant implication that the practitioner alone touches: the synchronous-by-default model prevents the class of bugs where an async API is called from a sync context incorrectly. In BEAM, concurrency is always explicit (spawning a process or using Task), never implicit — reducing the class of concurrency bugs caused by implicit async call propagation.

**Corrections needed:**

- The cookie-based distribution authentication is the most significant security deficiency in Section 4. The detractor's treatment is accurate; the apologist and realist understate it. The specific concern is:
  1. Authentication is via a shared secret (the Erlang cookie) distributed across all nodes in a cluster.
  2. The cookie is stored in plaintext in `~/.erlang.cookie` (chmod 400) on development machines and typically in Kubernetes Secrets or environment variables in production.
  3. The challenge-response protocol uses MD5, which while not practically broken for this specific use case, represents technical debt against future cryptographic advances.
  4. Distribution traffic is unencrypted by default, meaning the cookie traverses the network in cleartext during the initial handshake.
  5. Compromise of a single node's cookie value grants RCE on all connected cluster nodes via `RemoteNode ! {spawn, shell}` patterns.
  6. The `erl-matter` toolset documents automated exploitation of exposed distribution ports, and Metasploit module `exploit/multi/misc/erlang_cookie_rce` provides turnkey exploitation [ERL-MATTER] [METASPLOIT-ERLANG].

  The cookie model is fundamentally a private-network authentication primitive deployed in environments (cloud, Kubernetes, multi-tenant infrastructure) with different threat models. This is a structural design deficiency inherited from 1986-era assumptions, not a misconfiguration issue.

- **ETS TOCTOU races.** As noted in Section 7, the claim that data races are prevented requires qualification. ETS read-modify-write patterns are not atomic and represent a TOCTOU race class for any security-relevant shared state (session validation, rate limiting, authorization caches). The council's "no data races" framing is accurate for process-private state but should not be extended to ETS-based shared state.

**Additional context:**

- The supervisor restart amplification risk. The detractor is the only perspective to briefly mention that repeated process crashes can exhaust supervisor restart budgets (`max_restarts`). From a security perspective: if attacker-controlled input can cause a supervised process to crash predictably, an attacker can repeatedly send that input to exhaust restart budgets and permanently disable a service subsystem. This is a DoS class that is structurally enabled by the "let it crash" philosophy when the crash boundary is reachable with attacker input. Robust BEAM application design must distinguish between crashes caused by unexpected internal state (where "let it crash" is appropriate) and crashes caused by invalid external input (where explicit input validation must occur before the computation that could crash).

- BEAM distribution as a lateral movement vector. In a compromised BEAM cluster, an attacker who gains RCE on one node can: spawn processes on any other connected node via `Node.spawn/2`; read the ETS tables of any node; access the file system via `File` module on any node; and execute arbitrary Elixir/Erlang code. BEAM distribution was not designed with the assumption that any cluster node might be adversarially controlled. There is no capability model or permission boundary between cluster nodes; the cookie provides all-or-nothing access. This is relevant for multi-tenant BEAM deployments or deployments where different trust domains share a BEAM cluster.

---

### Other Sections (security-relevant flags)

**Section 6: Ecosystem and Tooling**

- **Hex.pm package auditing.** The `mix hex.audit` command queries the Erlang Ecosystem Foundation's security advisory database and reports vulnerable packages in the dependency tree [HEX-AUDIT]. This tooling is more mature than the council characterizations suggest, though it requires deliberate invocation (it is not part of the default CI pipeline the way `cargo audit` is often integrated into Rust projects). Teams should integrate `mix hex.audit` into their CI pipelines.

- **Abandoned library security risk.** The practitioner accurately identifies that many Hex.pm libraries are maintained by single individuals and may go abandoned. From a security perspective, abandoned libraries accumulate unpatched vulnerabilities over time. The ecosystem's lack of organizational account requirements and no formal library transfer process means security-critical libraries can become unmaintained without any community notification mechanism. This is a supply chain risk that is structurally different from, but not necessarily worse than, npm's supply chain history.

**Section 5: Error Handling**

- The `with` macro's failure semantics have a security implication not mentioned in any council perspective: when a `with` clause fails and falls through to the `else` block, the error value can contain sensitive internal state (database error messages, file paths, query details). If this error information propagates to user-facing responses, it constitutes information disclosure. The convention of wrapping internal errors in opaque `{:error, :internal_error}` tuples at API boundaries is a security pattern that the ecosystem's documentation does not consistently promote.

**Section 11: Governance and Evolution**

- The EEF Security Working Group (established 2021) is not mentioned in the council perspectives' governance sections. It represents formal security governance infrastructure for the BEAM ecosystem, including coordinated disclosure processes, security advisory publication, and the advisory database queried by `mix hex.audit` [EEF-SWG]. Its existence is relevant to the council's assessment of the ecosystem's security maturity.

---

## Implications for Language Design

**1. Runtime-enforced memory safety eliminates classes of vulnerabilities that operational controls cannot reliably prevent.**
The BEAM's track record demonstrates that managing memory at the VM level — not as a library or convention but as a runtime invariant — fundamentally changes the CVE profile of applications built on it. Erlang/OTP's historical CVEs are dominated by protocol implementation errors in bundled C code (the SSH library) and design-era authentication choices, not memory corruption in BEAM-compiled code. This is a qualitatively different profile from C/C++ systems, where memory corruption CVEs are structural. Language designers should treat memory safety as a first-tier design constraint, not a performance trade-off.

**2. Bundling complex protocol implementations into the runtime's standard library creates a high-value attack surface that requires dedicated security resources.**
The 2025 SSH vulnerability cluster — three CVEs including a CVSS 10.0 pre-authentication RCE — demonstrates the risk of shipping a full SSH implementation as part of the runtime itself. The `ssh` OTP application is included in every BEAM installation by default, making every deployment's attack surface as large as the most complex thing in the standard library. This is distinct from a separately installable library, which users opt into and which can be audited independently. Runtime designers should consider whether complex protocol implementations (SSH, TLS, HTTP, DNS) belong in the core runtime or as well-audited external dependencies with explicit opt-in. When bundled, they require security review resources proportional to their deployment prevalence.

**3. Authentication mechanisms designed for closed networks do not safely generalize to open network environments; runtime distribution should support modern authentication by default.**
Erlang's cookie-based distribution was designed for a closed corporate intranet in 1986 and has not been updated to address modern deployment environments. The pattern — a shared secret with MD5 challenge-response, cleartext transmission by default — grants all-or-nothing cluster access and is exposed in cloud, Kubernetes, and containerized environments that differ from its original threat model. Language runtime designers who include built-in distribution capabilities should default to mutual TLS authentication (mTLS) with certificate-based identity, not shared secrets. Backward compatibility should not be a justification for maintaining insecure defaults.

**4. Dynamically unbounded identifier tables (atoms, symbols, interned strings) create a DoS vulnerability class that static type systems or bounded tables prevent by construction.**
Erlang's atom table — a global, never-garbage-collected store with a default limit of ~1M atoms — creates a language-level DoS when user-controlled input creates atoms. This class of vulnerability (symbol/atom DoS) affects any language with unbounded interned identifier tables (early Ruby symbols had the same issue; Ruby 2.2 introduced garbage-collected symbols). Language designers who use interning for performance (fast equality comparison, pattern dispatch) should: (a) make interned identifiers garbage-collectable, (b) enforce a bounded table with rejection rather than crash on overflow, or (c) prohibit runtime creation of new interned identifiers from arbitrary strings. Elixir's `String.to_existing_atom/1` as the safe API and `String.to_atom/1` as the unsafe default inverts good security ergonomics — the unsafe path should not be the shorter one.

**5. Deserialization of rich runtime terms from untrusted sources must be explicitly secured; safe-mode defaults should be the API default, not the safe variant.**
Erlang's `binary_to_term/1` can create atoms (atom exhaustion) and, in historical versions, instantiate anonymous functions (code execution) from untrusted binary input. The safe variant, `binary_to_term(input, [:safe])`, is the correct API for untrusted input but requires caller knowledge of the risk. This is the classic secure-coding inversion: the dangerous path is the default, the safe path requires opt-in. Language designers who provide serialization/deserialization facilities for rich runtime terms (objects, closures, code references) should make the untrusted-input-safe variant the default and require explicit opt-in for the capabilities that create security risks (new atom creation, function instantiation).

**6. Process crash boundaries must be designed with security in mind; the "let it crash" philosophy is not safe when crash boundaries are reachable with attacker-controlled input.**
The BEAM's supervision model is a robust fault-tolerance mechanism for unexpected internal failures, but it assumes that process crashes are exceptional events, not attacker-triggered conditions. When attacker-controlled input can reliably crash a supervised process, the supervisor's restart mechanism becomes a resource amplifier for denial-of-service attacks. Language/runtime designers who build on supervision-based fault tolerance should provide explicit guidance and tooling for distinguishing external input validation boundaries (where crashes must not be permitted) from internal state invariants (where "let it crash" is appropriate). The secure design principle is: validate external input at the system boundary before it enters the computation that could crash; crash on internal state violations only.

---

## References

[CVE-2025-32433-GHSA] "CVE-2025-32433: Unauthenticated Remote Code Execution in Erlang/OTP SSH." GitHub Security Advisory GHSA-37cp-fgq5-7wc2. https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2

[CVE-SSH-MITM] Erlang/OTP SSH KEX hardening bypass (2025). cvedetails.com. https://www.cvedetails.com/product/20874/Erlang-Erlang-otp.html?vendor_id=9446

[CVE-SSH-RESOURCE] Erlang/OTP SSH resource exhaustion without throttling in ssh_sftp. OTP 17.0 through OTP 28.0.3. Same source: cvedetails.com Erlang product page.

[CVE-2025-32433-UNIT42] "Keys to the Kingdom: Erlang/OTP SSH Vulnerability Analysis and Exploits Observed in the Wild." Palo Alto Unit 42, May 2025. https://unit42.paloaltonetworks.com/erlang-otp-cve-2025-32433/

[CVEDETAILS-ERLANG] "Erlang: Security vulnerabilities." cvedetails.com. https://www.cvedetails.com/vulnerability-list/vendor_id-9446/Erlang.html

[DIALYZER-LYSE] Hébert, F. "Type Specifications and Erlang." Learn You Some Erlang. https://learnyousomeerlang.com/dialyzer

[DIST-TLS] "Using SSL/TLS for Erlang Distribution." Erlang System Documentation. https://www.erlang.org/doc/apps/ssl/ssl_distribution.html

[ECTO-SECURITY] "Security Considerations." Ecto Documentation. https://hexdocs.pm/ecto/security.html

[EEF-SWG] "Erlang Ecosystem Foundation Security Working Group." erlef.org. https://erlef.org/wg/security

[ERL-MATTER] "gteissier/erl-matter — Erlang distribution attack tooling." GitHub. https://github.com/gteissier/erl-matter

[ERL-NIF-DOC] "erl_nif — Erlang Native Implemented Functions." Erlang System Documentation. https://www.erlang.org/doc/apps/erts/erl_nif.html

[ERLANG-OPENSSL] "Erlang `:crypto` module OpenSSL dependency." Erlang System Documentation. https://www.erlang.org/doc/apps/crypto/new_api.html

[ETF-SECURITY] Erlang External Term Format security considerations. "The Binary term format and security." Erlang System Documentation — Protocol Datatypes. https://www.erlang.org/doc/apps/erts/erl_ext_dist.html. See also: Dennis Marttinen, "Elixir/Phoenix Binary_to_term deserialization vulnerability." 2020.

[ETS-DOC] "ets — Erlang Term Storage." Erlang System Documentation. https://www.erlang.org/doc/apps/stdlib/ets.html

[ELIXIR-DOCS-ATOM] "String.to_atom/1." Elixir Documentation. https://hexdocs.pm/elixir/String.html#to_atom/1. See warning: "Atoms are not garbage collected; therefore, converting arbitrary strings to atoms is discouraged."

[HEX-AUDIT] "mix hex.audit." Hex documentation. https://hexdocs.pm/hex/Mix.Tasks.Hex.Audit.html

[METASPLOIT-ERLANG] Metasploit module `exploit/multi/misc/erlang_cookie_rce`. Exploit-DB entry 49418. Referenced via Exploit-DB and Metasploit module documentation.

[OWASP-ELIXIR] OWASP Community. "Elixir Security Cheat Sheet." Referenced in OWASP Cheat Sheet Series community contributions. Covers atom exhaustion, binary_to_term, SQL injection via Ecto.

[RFC-6151] Turner, S. and Chen, L. "Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms." RFC 6151, March 2011. https://www.rfc-editor.org/rfc/rfc6151
