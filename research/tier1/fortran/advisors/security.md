# Fortran — Security Advisor Review

```yaml
role: advisor-security
language: "Fortran"
agent: "claude-agent"
date: "2026-02-28"
```

---

## Summary

Fortran's security profile is dominated by a fundamental paradox that the council captures but does not fully resolve: the language is classified memory-unsafe by CISA/NSA guidance, yet presents an almost empty CVE record for deployed applications. Every council member acknowledges this paradox; most explain it through deployment context (HPC clusters are not internet-facing), but stop short of the sharper security analysis this situation demands. The council's treatment of memory safety risks is broadly accurate but uneven — the apologist significantly understates pointer risks and overstates ALLOCATABLE safety, while the detractor's framing is substantially correct. The realist offers the most analytically precise account of Section 7.

The most important security insight that all five council members underweight is the *threat model shift* now underway. HPC environments that were genuinely air-gapped or access-controlled in 2000 are increasingly internet-adjacent: cloud HPC (AWS HPC, Azure HPC, Google Cloud HPC) exposes cluster workloads to shared infrastructure; federated research networks extend the attack surface; and nation-state adversaries specifically target scientific computing infrastructure for IP theft and sabotage. The "Fortran programs don't face security threats because they're in controlled environments" argument is weakening structurally, and language designers and Fortran practitioners should not treat it as permanent.

A secondary underweighted finding is the supply chain exposure created by Fortran's dependence on C libraries — FFTW, NetCDF, HDF5, MPI implementations — that are themselves memory-unsafe. A supply chain attack against OpenMPI or Intel MKL affects every Fortran HPC program that depends on them, even if the Fortran code itself is perfectly written. The council mentions this briefly but does not develop it as the structural supply chain risk it represents.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims across council members:**

- CISA/NSA classification of Fortran as memory-unsafe (CWE-1399) is correctly cited and applied by all five members [MEMORY-SAFETY-WIKI].
- Array out-of-bounds access is undefined behavior in production builds (bounds checking disabled by default for performance) — accurate and well-evidenced [FORTRAN-DISCOURSE-BOUNDS].
- CVE record for deployed Fortran applications is nearly empty. The specific compiler CVEs cited are accurate: CVE-2024-28881 (Intel Fortran Compiler Classic, uncontrolled search path, local privilege escalation) and CVE-2022-38136 (same class of vulnerability for an older version) are genuine NVD entries [NVD-CVE-2024-28881][NVD-CVE-2022-38136].
- CVE-2014-5044 (integer overflow in libgfortran runtime) is correctly cited as a language-runtime vulnerability distinct from compiler installer issues [NVD-CVE-2014-5044].
- The 2010 Phrack article on Fortran memory corruption exploitation (Phrack Issue 67, "Exploiting Memory Corruptions in Fortran Programs Under Unix") is correctly cited as establishing exploitability in principle [PHRACK-FORTRAN].
- The realist's framing — that Fortran's low CVE count reflects deployment context rather than language-level safety — is the analytically correct interpretation.
- The practitioner's characterization of primary practical risk as "silent wrong results from out-of-bounds access rather than code execution vulnerabilities" is accurate for the current threat model.

**Corrections needed:**

- **Apologist overstatement of ALLOCATABLE safety.** The apologist writes that ALLOCATABLE arrays are "memory-safe in the relevant sense — no dangling references, no double-frees, no pointer arithmetic." This is true for purely ALLOCATABLE code but misleading in context. Production Fortran codebases routinely mix ALLOCATABLE and POINTER usage, and the apologist's own dissenting view acknowledges this: "A codebase mixing ALLOCATABLE and POINTER — common in legacy code and in linked data structure implementations — retains the pointer safety risks." The unqualified safety claim in the body text should be read against the corrective dissent. No council member is wrong here, but the summary claim requires the qualifier to be accurate.

- **Underspecification of POINTER undefined behavior.** Multiple members note that POINTER variables have undefined association status at declaration, but only the detractor characterizes this as a code-execution risk. The Phrack article's exploitation techniques specifically include POINTER abuse [PHRACK-FORTRAN]. The specific undefined behavior is: querying `ASSOCIATED(ptr)` on an uninitialized pointer produces an undefined result that a compiler may optimize in ways that introduce exploitable branches. This is a language-level undefined behavior in the same family as C's signed integer overflow — not merely a correctness concern but a potential security concern in adversarial contexts.

- **COMMON/EQUIVALENCE type-confusion risk understated.** The practitioner correctly notes that accessing memory via COMMON blocks under different types "produces unexpected values that interact badly with the rest of the program's numerical state" and calls it a "type-aliasing vulnerability." However, no council member notes the specific class of attack this enables: if a Fortran program reads an external configuration value (e.g., a grid dimension) into a COMMON block that is also interpreted as REAL by another compilation unit, an attacker who can influence the configuration can cause the REAL interpretation to produce a denormalized or NaN value that bypasses IEEE exception handling and produces exploitable numerical state. This is not a theoretical concern — it is the category of vulnerability that EQUIVALENCE and COMMON were never intended to create but structurally enable.

- **Phrack 2010 claims need methodological context.** Multiple members cite PHRACK-FORTRAN as establishing that Fortran programs are "exploitable under specific access conditions." This is accurate but incomplete. The Phrack article describes exploitation specifically in the context of programs with controllable input — a scenario that does apply to Fortran programs that read model configuration files, atmospheric data, or seismic traces from potentially untrusted sources (satellite data, third-party observational feeds). Council members should not present "requires network access to HPC cluster" as the only access scenario; input-driven attacks are a different and relevant attack surface.

**Additional context:**

- **The FORTIFY_SOURCE and stack protection gap.** HPC Fortran programs compiled for performance often disable or reduce security hardening that is standard in web-facing compiled code. Stack protectors (`-fstack-protector-strong`), position-independent code (`-fPIE`), and FORTIFY_SOURCE equivalents add overhead that HPC practitioners consider unacceptable. No council member discusses this dimension of the security posture. In practice, Fortran HPC binaries are often less hardened against exploitation than C binaries in web infrastructure — not because the language is worse, but because the security hardening tradeoffs are made differently in HPC contexts. For the subset of Fortran programs that *do* process untrusted input (scientific data feeds, community model inputs, web-accessible HPC portals), this hardening gap is a real attack surface amplifier.

- **The compiler CVE pattern is revealing.** The pattern that Intel Fortran compiler CVEs are predominantly CWE-427 (Uncontrolled Search Path Element) deserves more analytical weight than the council gives it. CWE-427 in a compiler installer indicates that the toolchain itself — the entity responsible for producing secure binaries — follows insecure library loading conventions on the system running it. A developer whose machine is compromised via CVE-2024-28881 (local privilege escalation through Intel Fortran Compiler Classic) can produce malicious Fortran binaries. This is a supply chain vector that runs upstream of the Fortran application: compromise the compiler, compromise every binary it produces. The council notes these CVEs but does not trace this implication.

- **The "small specialized user base" supply chain argument requires reexamination.** The realist and practitioner both argue that Fortran's supply chain risk is low because the user base is small and specialized. This argument has a critical flaw: small specialized user bases for critical infrastructure are *high-value targets*, not low-value targets, from a nation-state adversary perspective. An adversary who wants to disrupt global weather prediction, compromise climate model outputs, or introduce errors into nuclear weapons design codes would specifically prioritize the small set of libraries (OpenMPI, FFTW, LAPACK reference implementations, NetCDF) and compilers (GFortran, Intel ifx) that underpin this infrastructure. The security argument from small user base is backwards: the specialization is what makes the target attractive, not what makes it safe.

**Missing data:**

- **No analysis of OpenMP and MPI security implications.** OpenMP thread scheduling interacts with memory safety in Fortran: if a data race exists in a `!$OMP PARALLEL DO` region (where the programmer has asserted no race but one exists), the undefined behavior can produce exploitable memory states, not just wrong numerical results. No council member addresses data races in OpenMP Fortran code as a security concern. For Fortran programs that process external scientific data in parallel — weather assimilation codes, seismic processing pipelines — this is a real attack surface.

- **No NVD systematic query reported.** Multiple council members state that Fortran's CVE record is "nearly empty" but do not report a systematic NVD query. A query of NVD with CPE filters for Fortran-based applications or the GHSA database for Fortran-tagged packages would provide empirical grounding. The research brief's statement "The NVD database does not track language-specific vulnerability patterns for Fortran in the way it does for, e.g., JavaScript libraries" is accurate, but this absence of tracking is itself a methodological limitation — not evidence that the vulnerabilities don't exist. A cursory NVD search for CVEs in VASP, WRF, CESM, or other major Fortran HPC codes would verify whether language-level vulnerabilities appear in these deployed applications.

- **No analysis of GPU execution security surface.** `DO CONCURRENT` with `-stdpar=gpu` and OpenACC introduce a GPU execution surface that has its own security implications: GPU memory is not protected by the same access control mechanisms as CPU memory in most HPC configurations, GPU-to-CPU data transfers can bypass host-side bounds checking, and CUDA Fortran provides direct access to GPU hardware that has known DMA-related attack surfaces. No council member addresses security in the GPU execution context.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- IMPLICIT typing as a footgun is accurately described by all members. From a security perspective, the relevant implication is that an undeclared variable (created by a typo) initialized to zero by default can bypass intended initialization logic. If a security-relevant variable — an authentication flag, a permissions mask, an access level — is inadvertently shadowed by an implicit variable, the result is a logic error with security consequences. All members correctly identify IMPLICIT typing as a bug generator; none specifically traces this to security-relevant logic errors.

- The absence of algebraic data types / sum types is correctly noted by detractor, realist, and practitioner as preventing type-safe error handling. From a security perspective, the consequence is that Fortran cannot express security-relevant invariants in the type system: "this value is either a valid array index or an explicit error, and the compiler enforces that you check which" is impossible. The type system provides no assistance in preventing security-relevant unchecked conditions.

**Corrections needed:**

- **No council member notes the injection risk from `CLASS(*)`** (unlimited polymorphism). When a Fortran program uses `CLASS(*) :: obj` as a container element and then uses `SELECT TYPE(obj)` to dispatch, an adversary who can influence the runtime type of `obj` (e.g., via a serialized object loaded from a file) can in principle cause incorrect branch selection. This is a narrow attack surface — Fortran does not have a general object serialization mechanism — but it is relevant for any Fortran program that loads derived type data from external files or network sources.

**Additional context:**

- **The KIND system's security-adjacent implications.** The detractor correctly identifies KIND portability failures (non-portable `INTEGER(KIND=4)` assumptions). From a security perspective, the portability failure has an additional implication: if a compiled Fortran program assumes INTEGER(KIND=4) is 32-bit and is deployed on a platform where KIND=4 means something different, integer overflow checks calibrated for 32-bit arithmetic may fail silently. This is the same class of vulnerability as C's `int`/`long` size assumptions. The practical risk is low given the uniformity of HPC hardware, but it is a structural type-system vulnerability.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- The allocatable/pointer distinction is correctly drawn by all five council members. The allocatable mechanism is safer; the pointer mechanism retains the key memory safety risks.
- Bounds checking disabled by default in production builds is accurately stated and evidenced [FORTRAN-DISCOURSE-BOUNDS].
- No pointer arithmetic restriction is correctly identified as a meaningful safety improvement over C — this eliminates a large class of exploitation techniques that require precise pointer manipulation [FORTRANUK-MEMSAFE].
- Character arrays carry length information (no C-style null-terminated string buffer overflow through string functions) is accurate and significant.

**Corrections needed:**

- **The no-pointer-arithmetic claim requires qualification for `C_PTR` and `ISO_C_BINDING`.** The Fortran standard restricts arithmetic on Fortran POINTER entities. However, when Fortran programs use `ISO_C_BINDING` and `C_PTR` to interface with C, they can call C functions that perform arbitrary pointer arithmetic, receive the results as `C_PTR` values, and use `C_F_POINTER` to cast them back to Fortran pointers. This is a standard pattern for wrapping C libraries. In this context, the no-pointer-arithmetic guarantee has been traded for C-level pointer freedom. No council member mentions this ISO_C_BINDING escape hatch explicitly in the security context. For the significant fraction of Fortran code that wraps C libraries, the "no pointer arithmetic" safety claim does not hold.

- **Column-major / row-major mismatch as a security-relevant incorrect computation path.** Multiple council members note this as a correctness concern. From a security perspective, if a Fortran program performing a security-critical computation (e.g., a cryptographic verification, a bounds comparison, an authentication decision) passes a matrix to a C function and the transposition is incorrect, the security computation produces wrong results without any error signal. The practitioner correctly calls this "a consistent source of bugs at language boundaries" but does not note the security-relevant subset of such bugs.

**Additional context:**

- **Stack allocation and the bounds-checking asymmetry.** Fortran arrays with compile-time-known bounds are stack-allocated. Stack overflow via deeply recursive Fortran code (Fortran 95 added explicit `RECURSIVE` attribute; non-recursive subroutines called recursively produce undefined behavior) is an additional memory model concern in programs with dynamic call patterns. This is not discussed by any council member in the security context.

- **`ALLOCATE` with `STAT` vs. without: an important security consideration.** The practitioner correctly identifies that `ALLOCATE` without `STAT=ierr` either terminates or continues with undefined state on failure. From a security perspective, allocation failure without proper handling is a denial-of-service vector for any Fortran program that processes attacker-influenced input sizes. If an adversary can cause an allocation request for a very large array (by providing a large grid dimension or resolution parameter), a program without STAT handling will abort uncontrollably. Programs *with* STAT handling can recover gracefully. No council member discusses this as a security concern rather than a correctness concern.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- The MPI-dominant reality is correctly described. MPI programs communicate over a network; the MPI transport layer (Infiniband, Ethernet) is outside the Fortran language specification and raises its own security questions not covered by language-level analysis.
- OpenMP pragmas are silently ignored by compilers without OpenMP support — the practitioner correctly notes this. From a security perspective, the silent-ignore behavior means that a security-relevant synchronization construct (`!$OMP CRITICAL`) might be silently dropped in a build without OpenMP, creating a race condition that the programmer believed was protected.
- The coarray model is described accurately. Coarray cross-image access (`A[img]`) creates a distributed memory access pattern where the validity of the image index `img` is not checked by default — out-of-range image indices produce undefined behavior analogous to array out-of-bounds access.

**Corrections needed:**

- **`DO CONCURRENT` does not prevent data races from external-state interaction.** The programmer declares that loop iterations are data-independent, but this is an assertion, not a compiler-verified property. No council member notes that an incorrect `DO CONCURRENT` annotation that introduces a data race is undefined behavior — and undefined behavior in a concurrent context can be more exploitable than in a sequential context, because the interleaving of memory accesses can produce more varied and less deterministic state corruption.

- **OpenMP security surface underexamined.** The OpenMP critical section silent-drop issue deserves emphasis. From OWASP's parallel security perspective, race conditions in security-critical code (authentication, bounds checking, access decisions that happen to occur in a parallel region) are high-severity vulnerabilities. Fortran HPC code is not typically performing authentication in parallel, but it does perform bounds-adjacent computations (index calculations, range validations) in parallel loops where a race could produce exploitable indices.

**Additional context:**

- **MPI message authentication and integrity.** No council member addresses MPI message security. In a cluster environment using non-encrypted MPI transport (the default for most InfiniBand configurations), an adversary with network access to the interconnect can inject or modify MPI messages. A Fortran climate simulation code receiving a spoofed boundary condition update from a compromised node will produce numerically valid but scientifically wrong results. This is not a Fortran language vulnerability but it is a Fortran HPC deployment security concern that the council's analysis of Section 4 should acknowledge.

---

### Other Sections (security-relevant flags)

**Section 6: Ecosystem and Tooling — Supply Chain**

The council's supply chain analysis is the weakest area across all five perspectives. The key missing points:

1. **C library dependency is the actual supply chain attack surface.** Fortran programs directly call OpenMPI, FFTW, NetCDF, HDF5, Intel MKL, and OpenBLAS. These libraries are predominantly written in C and share all of C's memory safety vulnerabilities. A supply chain compromise of any of these libraries — or of the system package manager distributing them (apt, yum, spack, conda) — propagates directly to Fortran programs that depend on them. The council consistently notes that fpm lacks security infrastructure, but fpm is the smallest part of the actual supply chain risk for production Fortran.

2. **Spack and module-based HPC package management.** Large HPC centers use Spack or Lmod to manage scientific software stacks. These systems have documented supply chain vulnerabilities (unverified source fetches, lack of cryptographic signing for older package recipes, shared package caches). No council member addresses this layer of the Fortran deployment supply chain, which is the dominant dependency management mechanism for production Fortran HPC.

3. **The compiler as a supply chain node.** Intel ifx is a proprietary binary distributed by Intel. If Intel's build or distribution infrastructure were compromised, every HPC center that installs ifx from Intel's servers would receive a malicious compiler. GFortran, distributed through Linux package managers (apt, yum), inherits whatever supply chain security those package managers provide. LLVM Flang, distributed via the LLVM project, depends on LLVM's build and signing infrastructure. No council member treats the compiler itself as a supply chain trust boundary — but it is the highest-privilege supply chain node in the Fortran ecosystem.

**Section 1: Identity and Intent — Security implications of domain specialization**

Fortran's positioning as a domain-specific scientific computing language has a security implication the council does not address: domain-specific languages attract domain-expert programmers who are often not security-trained. A physicist who becomes a Fortran programmer has likely received no formal security education. They may not know what OWASP is. They may not understand the difference between a bounds check that's correct in test and dangerous in production. The CISA/NSA guidance targeting memory-unsafe languages is partly motivated by the recognition that domain-expert programmers in fields like defense and critical infrastructure — precisely Fortran's deployment context — are not security-trained and rely on the language to provide safety they cannot independently verify.

**Section 9: Performance Characteristics — Security tradeoffs**

The council comprehensively covers the optimization flag taxonomy (`-O3 -march=native`), but no council member notes that aggressive optimization flags interact with security. Specifically:

- `-O3` enables undefined behavior exploitation: the C standard (and by analogy, the Fortran standard) permits compilers to exploit undefined behavior for optimization. An out-of-bounds array access combined with `-O3` can cause the compiler to eliminate the bounds-related code path entirely (as a provably unreachable branch in the compiler's analysis), removing a check the programmer intended to be present.
- `-march=native` embeds hardware-specific instructions that may not be validated on the target production system. If a Fortran binary is compiled on a development machine with AVX-512 and deployed to a production node that emulates but does not natively support AVX-512, the behavior is undefined.

---

## Implications for Language Design

**Implication 1: Security posture through deployment context is a fragile guarantee.**
Fortran's practical security profile depends on the assumption that its deployment environments are controlled, access-restricted, and not adversarially targeted. This assumption is weakening as cloud HPC, international scientific collaboration networks, and nation-state cyber operations targeting critical research infrastructure all increase the attack surface of HPC environments. A language design lesson: security properties that depend on deployment context rather than language structure are ephemeral. A language cannot guarantee that it will always be deployed in safe environments; it can only guarantee what it provides structurally. Fortran's structural security guarantees (no pointer arithmetic, character length metadata, ALLOCATABLE scope-safety) are genuine but narrow.

**Implication 2: Opt-in safety versus opt-in unsafety — the default direction matters.**
Fortran's production default is: bounds checking disabled, IMPLICIT typing enabled (absent IMPLICIT NONE), STAT checking optional. The secure configuration requires explicit opt-in: `-fcheck=bounds`, `IMPLICIT NONE`, careful STAT handling. This is the opposite of Rust's approach (unsafe operations require `unsafe` blocks) and Ada's approach (runtime checks enabled by default, with explicit pragmas to suppress). The lesson for language designers: when the secure behavior imposes costs, the direction of the default determines whether production code is secure or insecure. Languages that make the secure path the default have better security outcomes in the field, even when the unsafe path remains available. Fortran's performance-optimized defaults have produced exactly the outcome the principle predicts: production HPC code runs without bounds checking and with poorly handled errors because those defaults were chosen for the common case.

**Implication 3: The "not internet-facing" argument is not a security property.**
Multiple Fortran council members correctly observe that Fortran programs rarely face adversarial inputs because they are not internet-facing. This is an observation about current deployment patterns, not a language security guarantee. Any language argument that takes the form "this vulnerability class is not practically exploitable because of how the language is currently used" is contingent on deployment patterns remaining stable. As Fortran sees new deployment contexts — cloud HPC, web-accessible computation portals, integration with REST APIs for scientific data pipelines — the "not internet-facing" argument erodes. Language designers should not design security assumptions around expected deployment patterns; those patterns change over time.

**Implication 4: Memory-unsafe languages in safety-critical scientific contexts require explicit hardening frameworks.**
The HPC community has developed performance hardening practices (optimization flags, NUMA pinning, MPI tuning) but not security hardening practices (FORTIFY_SOURCE equivalents, mandatory bounds checking in staging environments, secure-by-default MPI message authentication). Fortran's situation illustrates a gap in the field: safety-critical scientific programs (nuclear design codes, flight dynamics simulations, climate models that inform policy) are written in memory-unsafe languages and deployed with security hardening practices developed for performance, not security. Language designers creating languages for safety-critical computing should either provide inherent memory safety or provide explicit, language-level security hardening mechanisms analogous to compile-time security profiles.

**Implication 5: Supply chain risk is multiplicative across language boundaries.**
Fortran programs depend on C libraries that depend on other C libraries. Each language boundary is a supply chain node. A memory-safe Fortran program that calls a memory-unsafe C library inherits the C library's vulnerability class exposure through that interface. Language designers should consider how their language's interoperability mechanisms affect the security properties of the overall program, not just the language-native portions. Fortran's `ISO_C_BINDING` is well-designed for correctness and portability, but it provides no security-level isolation: a buffer overflow in an `ISO_C_BINDING`-called C function is an exploitable vulnerability in the Fortran program. True security isolation at language boundaries requires either formal verification of the called code, sandboxing, or memory-safe intermediate layers — none of which Fortran's interoperability model provides.

**Implication 6: The absence of mandatory error handling is a security property of the ecosystem, not just a correctness concern.**
Fortran's optional STAT checking and optional IOSTAT checking mean that the ecosystem's production code is full of unchecked resource acquisition and I/O operations. From a security perspective, unchecked allocation failure is a denial-of-service enabler; unchecked I/O failure means the program continues with unknown state that an adversary can potentially influence. Language designers who make error handling optional will find that production codebases systematically omit it, because the path of least resistance is the path without error handling. Languages that make error handling mandatory — or that make ignoring errors require explicit, visible acknowledgment — produce codebases that handle errors more consistently, which is both a correctness and a security improvement.

---

## References

[MEMORY-SAFETY-WIKI] Wikipedia. "Memory safety." https://en.wikipedia.org/wiki/Memory_safety. Accessed 2026-02-28. Cites CISA/NSA classification of Fortran as memory-unsafe under CWE-1399.

[NVD-CVE-2024-28881] NIST National Vulnerability Database. "CVE-2024-28881: Uncontrolled Search Path in Intel Fortran Compiler Classic." https://nvd.nist.gov/vuln/detail/CVE-2024-28881. Published 2024.

[NVD-CVE-2022-38136] NIST National Vulnerability Database. "CVE-2022-38136: Uncontrolled Search Path in Intel Fortran Compiler for Windows." https://nvd.nist.gov/vuln/detail/CVE-2022-38136. Published 2022.

[NVD-CVE-2014-5044] NIST National Vulnerability Database. "CVE-2014-5044: Multiple integer overflow issues in libgfortran runtime." https://nvd.nist.gov/vuln/detail/CVE-2014-5044. Published 2014.

[PHRACK-FORTRAN] Phrack Magazine. "Exploiting Memory Corruptions in Fortran Programs Under Unix." Phrack Issue 67, Article 11. http://phrack.org/issues/67/11.html. 2010.

[FORTRANUK-MEMSAFE] Fortran UK. "Is Fortran 'Memory Safe'?" https://fortran.uk/isfortranmemorysafe/. Accessed 2026-02-28.

[FORTRAN-DISCOURSE-BOUNDS] Fortran-lang Discourse. Threads on compiler bounds-checking flags. https://fortran-lang.discourse.group/. Various dates.

[RESEARCH-BRIEF] Penultima Research. "Fortran — Research Brief." research/tier1/fortran/research-brief.md. 2026-02-28.

[MSRC-2019] Miller, Matt. "Trends, Challenges, and Strategic Shifts in the Software Vulnerability Mitigation Landscape." Microsoft Security Response Center, BlueHat IL 2019. [Cited via evidence/cve-data/c.md]: approximately 70% of Microsoft CVEs annually are memory safety issues.

[NSA-CISA-2025] NSA/CISA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://www.cisa.gov/resources-tools/resources/memory-safe-languages-reducing-vulnerabilities-modern-software-development.

[CWE-TOP25-2024] MITRE. "CWE Top 25 Most Dangerous Software Weaknesses — 2024." https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html.

[MITRE-CWE427] MITRE. "CWE-427: Uncontrolled Search Path Element." https://cwe.mitre.org/data/definitions/427.html.

[ISO-FORTRAN-2023] ISO/IEC. "ISO/IEC 1539-1:2023 — Programming languages — Fortran — Part 1: Base language." ISO, November 2023. https://www.iso.org/standard/82170.html.

[INTEL-IFX-2025] Intel. "Intel® Fortran Compiler for oneAPI Release Notes 2025." https://www.intel.com/content/www/us/en/developer/articles/release-notes/fortran-compiler/2025.html.

[LLVM-FLANG-2025] LLVM Project Blog. "LLVM Fortran Levels Up: Goodbye flang-new, Hello flang!" March 11, 2025. https://blog.llvm.org/posts/2025-03-11-flang-new/.

[OWASP-RACE] OWASP. "Race Conditions." OWASP Testing Guide. https://owasp.org/www-community/attacks/Race_condition.

[SPACK-SECURITY] Gamblin, Todd et al. Spack Project. "Spack Security." https://spack.readthedocs.io/en/latest/security.html. Accessed 2026-02-28.
