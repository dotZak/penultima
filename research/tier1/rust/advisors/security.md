# Rust — Security Advisor Review

```yaml
role: advisor-security
language: "Rust"
agent: "claude-agent"
date: "2026-02-26"
```

---

## Summary

Rust's security case rests on a genuine and empirically validated achievement: compile-time elimination of the memory safety vulnerability classes that dominate C and C++ CVE data. The Android data (memory safety vulnerabilities dropping from 76% to 35% of total Android security vulnerabilities between 2019 and 2022, correlated with Rust adoption) and the ACSAC 2024 Linux kernel study (91% of safety violations eliminable by Rust alone) are credible, production-scale evidence that this is not a theoretical property [GOOGLE-SECURITY-BLOG-ANDROID] [MARS-RESEARCH-RFL-2024]. The council perspectives collectively document this accurately, and the strongest claims hold up against the evidence.

However, the memory safety guarantee is conditional, and that condition is systematically understated across four of the five council perspectives. "Safe Rust" is memory-safe if and only if all `unsafe` code it transitively depends on is correctly implemented. As of May 2024, 34.35% of significant crates on crates.io transitively call into crates that use `unsafe` [RUSTFOUNDATION-UNSAFE-WILD]. The RUDRA automated analysis tool, in a single scan of 43,000 crates, found 264 previously unknown memory safety bugs — representing 51.6% of all memory safety bugs ever reported to RustSec since 2016, yielding 76 CVEs and 112 advisories [RUDRA-PAPER]. Two of those bugs were in the Rust standard library itself. Over a three-year period, 57 soundness issues were filed in the standard library, with 28% discovered in 2024 alone [SANDCELL-ARXIV]. The council's apologist and historian do not adequately account for this; the detractor handles it most honestly.

Beyond memory safety, the council correctly identifies that Rust does not prevent logic errors, protocol violations, injection attacks, or incorrect cryptographic protocol implementation. But important nuances are underexplored: integer overflow semantics differ between debug and release builds (silent wrapping in release, panic in debug), creating a class of safety-relevant behavior that is not ergonomically enforced; the supply chain risk from crates.io is equivalent to npm or pip, not superior; and security ergonomics — whether the secure path is the easy path — is mixed: default-safe memory management is excellent, but error handling shortcuts (`.unwrap()`), opt-in supply chain auditing (`cargo audit`), and the absence of standard cryptographic primitives all require active discipline rather than passive protection.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- **Memory safety elimination is real and empirically demonstrated.** The ownership/borrowing system eliminates use-after-free, double-free, dangling pointers, and data races from safe Rust code at compile time. The mechanism is sound, and the Android longitudinal data [GOOGLE-SECURITY-BLOG-ANDROID] and Linux kernel classification study [MARS-RESEARCH-RFL-2024] confirm this translates to measurable vulnerability reduction at production scale. All five perspectives state this accurately.
- **`unsafe` is lexically bounded and auditable.** Unlike C, where unsafety is ambient and unannounced, Rust's `unsafe` keyword localizes the regions requiring expert scrutiny. This is a genuine security engineering improvement: auditors can focus their attention on `unsafe` blocks rather than an entire codebase. The detractor and realist both characterize this correctly.
- **Memory safety does not imply full security.** All five perspectives correctly note that logic errors, protocol violations, and semantic bugs remain possible in safe Rust. The ACSAC 2024 Linux kernel study specifically found that 44% of protocol violation vulnerabilities (82 of 240 total classified vulnerabilities) are not addressed by Rust alone [MARS-RESEARCH-RFL-2024]. The practitioner articulates this most practically.
- **Supply chain risk is equivalent to other package managers.** The detractor and practitioner are correct that crates.io's security posture (no mandatory code review, opt-in `cargo audit`, typosquatting risk) is comparable to npm and PyPI — not superior. The RustSec advisory database is well-maintained but reactive rather than preventive.
- **CVE-2025-68260 occurred.** The first CVE officially assigned to Rust code in the Linux kernel [PENLIGENT-CVE-2025] is correctly acknowledged across perspectives.

**Corrections needed:**

- **The "1,000× fewer bugs" claim requires methodological caveat.** The research brief and several council members (apologist, realist, practitioner) cite "approximately 1,000 times fewer bugs compared to equivalent C++ development" without adequately communicating the limits of the comparison [DARKREADING-RUST-SECURITY]. The Google Security Blog post (November 2025) makes a specific comparison involving Android's Rust versus C/C++ code density, controlling for code age — the figure reflects a particular methodology, not a universal claim. Presenting this number without context is advocacy, not analysis. The detractor correctly flags this; the other perspectives do not.
- **The CVE-2025-68260 ratio (1 Rust vs. 159 C CVEs on one day) is not a controlled comparison.** The Rust code in the Linux kernel at the time of this CVE's publication constituted a small fraction of total kernel code. No perspective adequately controls for code volume when presenting this ratio. The comparison is directionally instructive, but the raw ratio cannot be used as evidence of proportional safety improvement without knowing the relative code bases. The detractor partially addresses this; others present the comparison as near-proof.
- **The safety guarantee's conditionality is underemphasized.** The safety guarantee should be stated precisely: "Memory-safe for code in the safe subset, conditional on all transitively linked `unsafe` code being correctly implemented." This is meaningfully stronger than C but weaker than the unqualified "memory safe" framing used by the apologist and historian. The detractor and practitioner are more accurate.
- **RUDRA's ecosystem-scale findings should recalibrate confidence claims.** The RUDRA paper's single-scan finding of 264 previously unknown memory safety bugs — representing over half of all historical RustSec memory safety bugs — in 43,000 crates [RUDRA-PAPER] is not adequately reflected in any perspective's Section 7. This is not evidence the ecosystem is broken; it is evidence that the soundness of "safe" abstractions built on `unsafe` foundations requires active verification, not passive assumption. The detractor mentions RUDRA in its memory model section but does not carry its implications through to the security profile.

**Additional context:**

- **Integer overflow in release builds.** Rust detects integer overflow with a panic in debug mode (`overflow-checks = true` by default in debug). In release builds, integer overflow wraps silently by default — identical behavior to C. Developers must explicitly use `checked_add()`, `saturating_add()`, `wrapping_add()`, or configure `overflow-checks = true` in release to change this. The `clippy` linter can catch some cases. This is a meaningful security consideration: integer overflow leading to buffer allocation miscalculation is a well-documented C vulnerability class (CWE-190), and Rust's release-mode behavior does not automatically prevent this pattern unless developers are aware of the distinction. No council perspective addresses this.
- **RUSTSEC-2025-0028 and the cve-rs precedent.** The `cve-rs` crate, documented in the RustSec advisory database, demonstrated that adversarial code can exploit unsound compiler internals to introduce memory vulnerabilities in code that syntactically appears to be safe Rust [RUSTSEC-2025-0028]. This is a supply chain concern that goes beyond the standard "unsafe in the dependency tree" problem: an attacker can craft a crate that appears safe while exploiting undocumented compiler behavior. The practitioner mentions this correctly; others do not address it.
- **No formal aliasing rules specification.** The Rust Reference explicitly leaves aliasing rules for `unsafe` code undocumented. The Stacked Borrows model (Ralfj Jung, 2018–present) is the closest formal model but is a research project and is known to be incomplete — it was partially superseded by the Tree Borrows model. Developers writing `unsafe` code, particularly FFI wrappers, must rely on informal guidance, Miri output, and community consensus rather than a language specification. This creates a gap for security auditors: the rules that must be followed for `unsafe` code to be sound cannot be fully stated. The detractor notes the absence of formal aliasing rules; other perspectives do not address it.
- **Security ergonomics analysis.** The default-safe path in Rust is genuinely ergonomic for memory management — you get memory safety without doing anything special. For other security properties, the ergonomics are mixed:
  - *Error handling:* `Result<T, E>` and `?` are the idiomatic path. However, `.unwrap()` and `.expect()` are syntactically nearly as easy and the compiler provides no warning. The Cloudflare production incident (November 2025 global outage) in which a `.unwrap()` on a critical path caused a cascading service failure illustrates that memory-safe code can still fail dangerously [CLOUDFLARE-POSTMORTEM-2025]. This is an availability concern, not a memory safety concern, but availability is a security property.
  - *Supply chain auditing:* `cargo audit` must be explicitly added to CI pipelines. It is not run by `cargo build` or `cargo test` by default.
  - *Cryptography:* No cryptographic primitives in `std`. Correct TLS, hashing, and encryption require selecting and correctly configuring crates from the ecosystem (`rustls`, `ring`, `RustCrypto`). For experienced practitioners this is manageable; for less experienced teams it is an opportunity to make insecure choices.

**Missing data:**

- NVD/GHSA query methodology: no council perspective documents a systematic query of CVE databases for Rust-specific vulnerabilities with methodology (search terms, date range, exclusions). Aggregate CVE count claims reference CVE Details without documenting the query.
- RustSec advisory database statistics: a query of rustsec.org advisories by category, severity, and year would provide more granular data than the DarkReading summary.
- Miri adoption rate in production CI: Miri is the key tool for detecting unsafety in `unsafe` blocks, but no data exists on the fraction of crates with significant `unsafe` that run Miri in CI. Without this, the claim that `unsafe` is "auditable" in practice is partially theoretical.
- Formal security audit results for key ecosystem crates: the practitioner notes that `rustls` and `ring` are audited but does not cite specific audit reports. Formal third-party audit records for `tokio`, `serde`, `rustls`, and `ring` would substantiate the security quality claims.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- `Option<T>` eliminates null pointer dereferences at compile time. A function returning `Option<T>` cannot silently return null; the caller must handle both `Some(T)` and `None`. This eliminates a class of runtime errors that accounts for a substantial fraction of production defects in null-unsafe languages.
- `Result<T, E>` forces explicit acknowledgment of error paths. Combined with `#[must_use]` on `Result` (which generates a warning if the result is ignored), this creates compiler-level enforcement that error paths are addressed. This is stronger than Java's checked exceptions (which can be swallowed) or Go's multi-return error values (which can be silently discarded).
- Exhaustive pattern matching prevents unhandled variant bugs. Adding a new variant to a public `enum` breaks all downstream `match` expressions unless they use a wildcard — this is a breaking change, but it ensures code is updated to handle new states.
- No implicit numeric coercions with security implications. Unlike C's implicit integer promotions and signedness conversions (a known source of CWE-190 and CWE-195 vulnerabilities), Rust requires explicit casting via `as` or fallible conversion traits (`TryFrom`/`TryInto`). The explicit cast doesn't prevent overflow, but it prevents *silent* coercion surprises.
- The type system supports typestate patterns. Types can encode valid state transitions, preventing use of a resource in an invalid state (e.g., a socket that has not been connected, a mutex that has not been locked). This is a security-adjacent pattern that eliminates whole classes of misuse.

**Corrections needed:**

- **Type system does not prevent injection attacks.** Several council members (apologist most prominently) imply that Rust's type system raises the barrier for injection vulnerabilities. This is only conditionally true. SQL injection via string concatenation is entirely possible in Rust — the type system does not distinguish a trusted string from an attacker-controlled one. Parameterized query APIs (e.g., `sqlx`) mitigate this, but they are opt-in choices, not language-level enforcement. This is the same situation as Java, Python, or Go with appropriate libraries.
- **Serde deserialization does not provide logical safety guarantees.** Serde correctly and safely deserializes attacker-controlled input into valid Rust types — it prevents memory corruption during deserialization, but the resulting well-typed struct can still carry semantically malicious values. Logic vulnerabilities in processing deserialized data are not addressed by the type system. The apologist's characterization of deserialization safety should be scoped to memory safety, not semantic safety.
- **Integer overflow in release mode is not ergonomically prevented.** As noted in Section 7, Rust's release-mode arithmetic wraps silently. The type system provides the tools (`checked_add`, etc.) but does not enforce their use. The council perspectives do not address this in the type system context.

**Additional context:**

- The `#[must_use]` attribute and the compiler warning for unused `Result` values represent a security-relevant ergonomic design: the language makes it harder to silently drop error values. This is underemphasized across all perspectives.
- The absence of implicit coercions means that converting between numeric types requires deliberate decision by the developer — which forces awareness of potential truncation or overflow. Whether they use `as` (potentially truncating), `TryFrom` (fallible), or `saturating_cast` depends on developer choice, but at minimum the choice is visible.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- Ownership and borrowing eliminate use-after-free, double-free, dangling pointers, and data races from safe Rust at compile time. This is the correct characterization of the guarantee.
- Runtime bounds checking on slice indexing (`[]` operator) prevents out-of-bounds reads and writes, catching bugs at runtime rather than silently accessing adjacent memory. This is enabled by default and disabled only via explicit `get_unchecked()` in an `unsafe` block.
- The `unsafe` keyword lexically bounds the regions where manual invariant maintenance is required. Auditors can identify and focus on `unsafe` blocks rather than the entire codebase.
- Miri detects undefined behavior in `unsafe` code via MIR interpretation, providing a testing-time verification layer for operations the type system cannot statically verify.

**Corrections needed:**

- **The "safety is non-local" problem is not adequately addressed by lexical marking.** The `portable-atomic-util` soundness bug (documented in [NOTGULL-UNSAFE]) illustrates a structural limitation: `unsafe` code in one crate made assumptions about invariants that were violated by safe code in a different crate — with no `unsafe` keyword visible at the violation site. The `unsafe` keyword marks where the programmer *claims* responsibility for an invariant; it does not mark where invariants *must be upheld* by callers. This is a fundamental limitation, not a fixable tooling problem. The detractor correctly identifies this; the apologist and historian do not address it. The historian's statement that the `unsafe` boundary "is leaky but not absent" is the closest acknowledgment, but it understates the structural nature of the problem.
- **RUDRA's findings indicate systematic unsoundness, not exceptional cases.** The RUDRA paper's discovery of 264 previously unknown memory safety bugs in 43,000 crates — including bugs in the standard library, in official crates, and in the compiler — indicates that unsoundness in "safe" abstractions is a systematic condition, not an exceptional one [RUDRA-PAPER]. The standard library's 57 soundness issues filed over three years, with increasing discovery rate (28% in 2024 alone) [SANDCELL-ARXIV], further supports this. Council members who characterize the unsafe ecosystem as "bounded and auditable" should acknowledge that current auditing practice is insufficient to find all existing unsoundness.
- **Stacked Borrows / aliasing rules specification gap is a security concern.** Developers writing `unsafe` code cannot fully specify the rules they are required to follow, because those rules have not been formally adopted by the Rust Project. The Tree Borrows model (an evolution of Stacked Borrows) was proposed but as of early 2026, neither model has official status. This creates a meaningful gap for safety-critical and security-critical `unsafe` code: correctness proofs cannot be written against an unstated standard, and the Miri tool implements a heuristic model rather than a guaranteed-complete specification. The detractor addresses this; no other perspective does.

**Additional context:**

- The interaction between panics and `unsafe` code is a documented soundness hazard. Code that calls a panicking function while holding exclusive access to data, with `unsafe` invariants partially established, may leave data in an inconsistent state that is subsequently accessed safely [RUDRA-PAPER, bug category: "panic safety"]. This is one of the three categories RUDRA scans for, and it is a non-obvious interaction between Rust's error handling model and its safety model.
- The Rust 2024 Edition's changes include stricter handling of temporary lifetime extension and new `unsafe` block requirements, improving the soundness surface. But these improvements are edition-opt-in and may not apply to pre-2024 code in the ecosystem.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- `Send` and `Sync` marker traits prevent data races at compile time for safe Rust code. A type that is not `Send` cannot be transferred across thread boundaries; a type that is not `Sync` cannot be referenced from multiple threads simultaneously. These constraints are enforced statically, eliminating the dominant class of concurrency security bugs (data races).
- `Rc<T>` does not implement `Send`, preventing accidental cross-thread sharing of non-atomically-counted references. `Arc<T>` does implement `Send`, requiring atomic operations and thus making the synchronization cost explicit.
- The `Send`/`Sync` model is more secure than `ThreadSanitizer`-based runtime detection: compile-time prevention versus runtime detection of a non-deterministic, timing-dependent bug class.

**Corrections needed:**

- **Manual `Send`/`Sync` implementation silently re-introduces data races.** Implementing `Send` or `Sync` manually requires `unsafe` code [RUSTBOOK-CH16]. A type that incorrectly claims to be `Send` or `Sync` — while actually containing a non-thread-safe interior — will bypass the compiler's data race prevention entirely, without any syntactic indicator at the point of misuse. This is the "non-local safety" problem applied to concurrency: the `unsafe` block is in the `impl Send` definition, but the data race occurs at a call site that sees only safe code. Only the detractor addresses this; it should appear in all perspectives that claim Rust prevents data races.
- **Time-of-check to time-of-use (TOCTOU) races are not prevented.** Rust's ownership model prevents memory data races. It does not prevent TOCTOU races on file system operations, network state, or any external resource where a check and a use are separated by time during which another party can modify the resource. This is a well-known security vulnerability class (CWE-362) that Rust's type system does not address. No council perspective addresses this gap.
- **Deadlock is not prevented.** The `Mutex<T>` pattern prevents data races but does not prevent deadlock. A Rust program can deadlock by acquiring locks in inconsistent order, and the type system provides no protection. In security contexts, deadlock is a denial-of-service vector. Some perspectives imply the concurrency model is more comprehensive than it is; it addresses data races specifically, not concurrency correctness in general.

**Additional context:**

- The async ecosystem's requirement that spawned tasks have `'static` lifetime forces the `Arc<Mutex<T>>` pattern for any shared mutable state across async task boundaries. This pattern is memory-safe and data-race-free, but it concentrates mutable state behind mutex guards where deadlock risks are real. The interaction between async cancellation (dropping a future mid-execution) and mutex guards can cause surprising behavior if guards are held across `await` points — a documented foot-gun that requires developer discipline. The 2024 State of Rust Survey explicitly cites async code as a top pain point [RUSTBLOG-SURVEY-2024].
- `FutureUnordered` and `select!` macro usage can "easily lead to deadlock" according to Niko Matsakis's 2024 analysis [BABYSTEPS-ASYNC-2024]. This is a security-relevant ergonomic concern for async services.

---

### Other Sections (security-relevant issues)

**Ecosystem (Section 6/8 in council documents):**

- **crates.io supply chain risk is equivalent to npm/pip, not superior.** The detractor's characterization is accurate. crates.io has no mandatory code review, no code signing requirement by default, and is subject to typosquatting attacks. The `cargo audit` tool checks against the RustSec advisory database but must be explicitly adopted. RUSTSEC-2025-0028 (the `cve-rs` crate) is a concrete demonstration that adversarial packages can exploit unsound compiler internals [RUSTSEC-2025-0028]. The broader Rust security narrative — sometimes extended to imply supply chain advantages — is not warranted by the crates.io security model.
- **`rustls` and the cryptographic ecosystem deserve acknowledgment.** The practitioner's note that `rustls` (a TLS implementation in pure safe Rust, audited and deployed by Cloudflare and Mozilla) represents a meaningful improvement over OpenSSL for memory safety is correct. The `ring` and `RustCrypto` crate families are generally well-regarded and some are audited. However, "well-regarded and some are audited" is not equivalent to "standardized and mandatorily audited." The absence of cryptographic primitives from `std` means that a Rust application's cryptographic posture depends entirely on which ecosystem crates are selected and correctly configured. For security-sensitive applications, this requires expertise that the language itself does not scaffold.
- **Ferrocene and safety-critical certification gap.** The Rust Blog's January 2026 post "What does it take to ship Rust in safety-critical?" [SAFETY-CRITICAL-2026] documents that async Rust has no qualification story for high-criticality ISO 26262 components and that `no_std` safety-critical work is blocked by the absence of essential math functions in `core`. For security-critical embedded systems, these are real deployment blockers. The historian's perspective on certification lacks this depth.

**Tooling:**

- Miri is the correct tool for detecting undefined behavior in `unsafe` code, but no data exists on its adoption rate in production pipelines. The practitioner recommends it for crates with significant `unsafe`; the community recommendation exists but is not enforced by any default Cargo workflow.

---

## Implications for Language Design

**1. Conditional safety guarantees require explicit, prominent communication.**
Rust's memory safety guarantee is real but conditional: it applies to code in the safe subset, with the condition that all transitively linked `unsafe` code is correctly implemented. This conditionality is not adequately communicated in Rust's public narrative. Language designers should resist the temptation to make unconditional safety claims for systems with necessary escape hatches. The honest characterization — "safe by default, with visible, bounded regions of explicit unsafety" — is both accurate and useful. The unconditional framing creates misaligned expectations that undermine trust when soundness bugs are discovered.

**2. Escape hatches create non-local obligations that lexical marking alone does not resolve.**
The `unsafe` keyword marks where a programmer claims responsibility for invariants; it does not mark where those invariants must be upheld by callers. This creates a structural "non-local safety" problem: safe code can violate invariants established in `unsafe` code without any syntactic indication. A more complete design would include mechanisms for `unsafe` code to communicate its invariant requirements to callers — something closer to dependent types or effect systems than a lexical marker. This is not a criticism of `unsafe` as a concept; it is a recognized limitation of the current design. Future language designers should investigate whether invariant propagation can be made more explicit.

**3. Security ergonomics require examining the path of least resistance, not just the path of maximum safety.**
Rust's default path for memory management is the secure path — the borrow checker enforces safety by default, and unsafety requires explicit opt-in. This is the correct design. But for other security properties, the path of least resistance is not always the secure one: `.unwrap()` is nearly as easy as `?`; `cargo audit` requires explicit setup; choosing correct cryptographic crates requires expertise the language does not scaffold. Language designers should evaluate all security-relevant decisions on the axis of "is the secure default the easy default?" — not just memory management, but error handling ergonomics, supply chain tooling, and cryptographic API design.

**4. Formal specification of unsafe semantics is prerequisite to sound ecosystem audit.**
The absence of formally specified aliasing rules for Rust's `unsafe` code means that soundness proofs for `unsafe`-based abstractions cannot be written against a stable, complete specification. This is a gap for safety-critical and security-critical use cases. Language designers targeting systems programming with unsafe escape hatches should prioritize formal specification of unsafe semantics — not as an academic exercise, but as a prerequisite for rigorous security auditing and safety certification.

**5. Default-safe, opt-in-unsafe is correct architecture; the challenge is minimizing the unsafe surface.**
Rust's architecture — safe by default, explicit `unsafe` for escapes — is demonstrably superior to C's ambient unsafety for auditing purposes. The 19.11% of crates using `unsafe` directly represents a bounded and potentially auditable surface. The challenge is that "audited by the community" is not equivalent to "proven correct" — as RUDRA demonstrated, automated scanning can find soundness bugs at scale that manual review misses. Language designers should not assume that lexical marking alone provides adequate safety assurance; tooling for automated soundness checking (RUDRA-style static analysis, Miri-style interpretation) should be part of the ecosystem's standard security workflow, not an optional add-on.

---

## References

**CVE and Security Data**

- [RUSTFOUNDATION-UNSAFE-WILD] "Unsafe Rust in the Wild: Notes on the Current State of Unsafe Rust." Rust Foundation. May 2024. https://rustfoundation.org/media/unsafe-rust-in-the-wild-notes-on-the-current-state-of-unsafe-rust/
- [RUDRA-PAPER] Bae, Y. et al. "Rudra: Finding Memory Safety Bugs in Rust at the Ecosystem Scale." SOSP 2021 (Distinguished Artifact Award). https://dl.acm.org/doi/10.1145/3477132.3483570
- [SANDCELL-ARXIV] "SandCell: Sandboxing Rust Beyond Unsafe Code." arXiv:2509.24032. https://arxiv.org/html/2509.24032v1
- [RUSTSEC-2025-0028] "RUSTSEC-2025-0028: cve-rs introduces memory vulnerabilities in safe Rust." RustSec Advisory Database. https://rustsec.org/advisories/RUSTSEC-2025-0028.html
- [RUSTSEC-UNSOUND] "Advisories with keyword 'unsound'." RustSec Advisory Database. https://rustsec.org/keywords/unsound.html
- [PENLIGENT-CVE-2025] "CVE-2025-68260: First Rust Vulnerability in the Linux Kernel." Penligent. 2025. https://www.penligent.ai/hackinglabs/rusts-first-breach-cve-2025-68260-marks-the-first-rust-vulnerability-in-the-linux-kernel/
- [RUSTBLOG-CVE-2024-43402] "Security advisory for the standard library (CVE-2024-43402)." Rust Blog. 2024-09-04. https://blog.rust-lang.org/2024/09/04/cve-2024-43402.html
- [CVEDETAILS-RUST] "Rust-lang Rust: Security vulnerabilities, CVEs." CVE Details. https://www.cvedetails.com/vulnerability-list/vendor_id-19029/product_id-48677/Rust-lang-Rust.html
- [RUSTSEC-TOKIO-2023] "RUSTSEC-2023-0005: tokio::io::ReadHalf unsplit is Unsound." https://rustsec.org/advisories/RUSTSEC-2023-0005.html

**Memory Safety Evidence**

- [GOOGLE-SECURITY-BLOG-ANDROID] "Rust in Android: move fast and fix things." Google Online Security Blog. November 2025. https://security.googleblog.com/2025/11/rust-in-android-move-fast-fix-things.html
- [MARS-RESEARCH-RFL-2024] "Rust for Linux: Understanding the Security Impact of Rust in the Linux Kernel." ACSAC 2024. https://mars-research.github.io/doc/2024-acsac-rfl.pdf
- [DARKREADING-RUST-SECURITY] "Rust Code Delivers Security, Streamlines DevOps." Dark Reading. https://www.darkreading.com/application-security/rust-code-delivers-better-security-streamlines-devops
- [MSRC-2019] Miller, M. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019. https://www.microsoft.com/en-us/msrc/blog/2019/07/a-proactive-approach-to-more-secure-code/

**Unsafe and Soundness**

- [NOTGULL-UNSAFE] "The rabbit hole of unsafe Rust bugs." notgull.net. https://notgull.net/cautionary-unsafe-tale/
- [STACKED-BORROWS] Jung, R. et al. "Stacked Borrows: An Aliasing Model for Rust." POPL 2020. https://plv.mpi-sws.org/rustbelt/stacked-borrows/
- [RUSTSEC-OUROBOROS] "RUSTSEC-2023-0042: Ouroboros is Unsound." https://rustsec.org/advisories/RUSTSEC-2023-0042.html
- [RUDRA-BUG-CATEGORIES] Bae, Y. et al. RUDRA paper, section on bug categories (panic safety, higher-order safety invariants, Send/Sync propagation). SOSP 2021.

**Concurrency**

- [RUSTBOOK-CH16] "Fearless Concurrency." The Rust Programming Language. https://doc.rust-lang.org/book/ch16-00-concurrency.html
- [BABYSTEPS-ASYNC-2024] Matsakis, N. "What I'd like to see for Async Rust in 2024." 2024-01-03. https://smallcultfollowing.com/babysteps/blog/2024/01/03/async-rust-2024/

**Ergonomics and Developer Experience**

- [RUSTBLOG-SURVEY-2024] "2024 State of Rust Survey Results." Rust Blog. 2025-02-13. https://blog.rust-lang.org/2025/02/13/2024-State-Of-Rust-Survey-results/
- [RUSTBOOK-CH9] "Error Handling." The Rust Programming Language. https://doc.rust-lang.org/book/ch09-00-error-handling.html
- [CLOUDFLARE-POSTMORTEM-2025] Cloudflare outage postmortem, November 2025 (cited via practitioner perspective). [Source URL not independently verified — practitioner cites as CLOUDFLARE-POSTMORTEM-2025]

**Safety-Critical and Specification**

- [SAFETY-CRITICAL-2026] "What does it take to ship Rust in safety-critical?" Rust Blog. 2026-01-14. https://blog.rust-lang.org/2026/01/14/what-does-it-take-to-ship-rust-in-safety-critical/
- [TWEEDE-SPEC] "Rust needs an official specification." Tweede Golf. https://tweedegolf.nl/en/blog/140/rust-needs-an-official-specification
- [FERROCENE-DEV] Ferrocene (safety-critical Rust toolchain). https://ferrocene.dev/en

**Shared Evidence Repository**

- [evidence/cve-data/rust.md] Rust CVE Pattern Summary. This project. February 2026.
- [evidence/cve-data/c.md] C CVE Pattern Summary. This project. February 2026.
