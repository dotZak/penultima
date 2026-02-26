# C — Compiler/Runtime Advisor Review

```yaml
role: advisor-compiler-runtime
language: "C"
agent: "claude-sonnet-4-6"
date: "2026-02-26"
```

---

## Summary

The C council's perspectives collectively cover the compiler and runtime landscape with reasonable accuracy, drawing on a shared evidence base. Technical claims about sanitizer overhead, benchmark performance, undefined behavior, and the C11 memory model are mostly well-calibrated. Where gaps exist, they tend toward understatement of compiler-specific mechanisms: the council frequently names undefined behavior as a security concern but rarely explains *how* compilers exploit UB to produce the security outcomes they describe. The mechanism — compiler path-elimination based on UB impossibility assumptions — is distinct from and more dangerous than the naive reading of "undefined behavior means anything could happen at runtime."

Two additional concerns warrant specific attention. First, the performance section's claims are accurate but underweight a structural coupling: C's benchmark dominance is partly achieved through UB-exploiting compiler optimizations — the same mechanism that creates the security vulnerabilities described in Section 3. This is not a coincidence; it is a design property that language designers should understand clearly. Second, the concurrency claims are directionally correct but do not convey how deeply broken the `<threads.h>` story is in practice. As of 2026, the standard threading API standardized in 2011 remains absent from macOS, FreeBSD, and other major platforms — a fact noted by the detractor but insufficiently emphasized by the other perspectives.

Overall, the technical claims in this council report are sound enough to support the analytical conclusions reached. The corrections below are refinements, not reversals, and the most important contribution of this advisor review is framing the compiler/runtime mechanisms that underlie the patterns the council correctly identifies.

---

## Section-by-Section Review

### Section 3: Memory Model

**Accurate claims:**

- **ASan overhead figures are correct.** AddressSanitizer's typical overhead of 2–3x is consistent with published benchmarks [ASAN-COMPARISON]. Valgrind/Memcheck at 3–13x is similarly accurate. These figures represent median overhead; memory-intensive workloads with many allocations can see higher overhead. The critical consequence — these tools cannot be deployed in production — follows correctly.

- **C23 checked integer arithmetic is opt-in, not structural.** The apologist, realist, and detractor all handle `<stdckdint.h>` correctly: it provides `ckd_add()`, `ckd_sub()`, and `ckd_mul()` as an explicit opt-in mechanism. The detractor is right that "the default remains unchecked" [CVE-DOC-C]. This is a targeted mitigation, not a change to the memory model.

- **WCET analysis compatibility with GC-free execution.** The apologist correctly notes that garbage-collected languages cannot satisfy worst-case execution time analysis requirements for safety-critical certification (DO-178C, ISO 26262) [APOLOGIST-SEC3]. C's deterministic allocation and deallocation is genuinely required in these domains, not merely preferred.

- **The UB-as-code-deletion mechanism is named and cited.** The detractor's treatment is the strongest on this point, citing the STACK study (Wang et al., SOSP 2013) and CVE-2009-1897 [WANG-STACK-2013, CVE-2009-1897]. The historian correctly traces the shift in compiler interpretation of UB from "hardware accommodation" to "optimization license" as an emergent property of increasingly aggressive optimizers [HISTORIAN-SEC3]. These citations are appropriate.

**Corrections needed:**

- **Annex K failure is underemphasized.** Only the detractor addresses this in detail [DETRACTOR-SEC5]. Annex K (bounds-checking interfaces: `strcpy_s`, `strcat_s`, etc.) was included in C11 specifically to address the buffer-overflow vulnerability class with mandatory-length APIs. N1967 (2015) documented the outcome: Microsoft's implementation was non-conforming, glibc rejected it repeatedly, no major open-source distribution shipped it [N1967]. It remains in C23 as dead letter. For a compiler/runtime advisor, this is significant: a safety extension that mandates error-handling paths at the API level was rejected by the entire implementation ecosystem. The council treats Annex K as a minor footnote; it is evidence about what happens when C's ecosystem is asked to adopt safety-enforcement mechanisms that require API changes.

- **The sanitizer binary gap needs explicit statement.** Multiple perspectives note that sanitizers "cannot be deployed in production." What is underspecified is the implication: the binary you test with sanitizers enabled is a different binary than what ships to production. ASan inserts shadow memory mapping, instrumented memory accessors, and allocation wrappers at compile time. A bug that ASan catches in test may not be reproduced by the production binary because the memory layout differs. Conversely, a bug that does not trigger in instrumented tests may manifest in production under different memory patterns. The safety value of sanitizers is real, but the gap between the instrumented and production executables is a structural limitation that the council does not make explicit.

- **`malloc` NULL-return semantics under Linux overcommit are a deployment concern.** The practitioner mentions this in Section 5 [PRACTITIONER-SEC5], but it is a memory model issue as much as an error handling issue. Linux's default overcommit policy (`vm.overcommit_memory = 0`) allows `malloc` to return non-NULL when the virtual address space is provisioned but physical backing is not guaranteed. The result is that `malloc`-null checks that "work correctly" in isolated testing may not trigger in production — the OOM kill mechanism produces process termination far from the allocation site, not a NULL dereference at the check. Production C programs should not rely on `malloc` returning NULL as a reliable error signal on Linux.

**Additional context:**

- **Strict aliasing as a compiler tool.** The council mentions strict aliasing violations as UB but does not explain the mechanism. Strict aliasing is a guarantee C makes to the compiler: a pointer of type `T*` cannot alias memory accessed through a pointer of type `U*` (with exceptions). This enables type-based alias analysis (TBAA), which allows compilers to reorder and eliminate loads/stores across pointer dereferences, enabling vectorization and other critical optimizations. The Linux kernel, which relies heavily on type-punning patterns that technically violate strict aliasing, compiles with `-fno-strict-aliasing` — disabling TBAA for the kernel build [LINUX-ALIASING]. This is a practical concession that correct-looking kernel code cannot always be made ISO C–conformant for this specific rule. The performance cost of `-fno-strict-aliasing` is measured but manageable; more importantly, it reveals that one of C's optimization-enabling guarantees is routinely defeated in major production codebases.

- **Pointer provenance is a partially unspecified semantic.** The C standard does not fully specify pointer provenance — the rules for which pointer values derived from which allocation site are valid for which memory accesses. WG14 has an active study group on this (the Memory Object Model study group). Until provenance is fully specified, certain classes of pointer manipulation in C exist in a specification gray zone where real compiler behavior diverges from naive reading. This is a currently evolving area.

---

### Section 4: Concurrency and Parallelism

**Accurate claims:**

- **`<threads.h>` optional status is correctly noted.** The detractor provides the most precise treatment: glibc did not implement `<threads.h>` until glibc 2.28 (2018), seven years after C11 ratification; as of 2026 it remains absent from macOS, FreeBSD, NetBSD, and OpenBSD [DETRACTOR-SEC4]. The practical consequence the detractor draws is correct: portable C code requiring threads cannot use the standard threading API in 2026.

- **Data races are UB with compiler consequences.** The C11 memory model specifies programs containing data races as having undefined behavior [C-STD-SPEC]. The realist correctly notes that this is "strictly worse than Java's approach of defining race semantics for volatile variables" [REALIST-SEC4]. The compiler implication is that code with a data race is not merely incorrect — the compiler may transform it in ways that assume the race cannot occur, potentially eliminating synchronization code.

- **ThreadSanitizer detects races dynamically, not statically.** All perspectives correctly handle this limitation: TSan instruments memory accesses and reports races at runtime when they manifest [ASAN-COMPARISON]. A race that is not exercised in the test run is invisible to TSan. There is no static C race detector with meaningful precision for general programs.

- **The Boehm 2005 finding on threads-as-library.** The historian correctly cites Hans Boehm's demonstration that threading cannot be implemented correctly as a library without language-level memory model support [BOEHM-THREADS]. This is the theoretical justification for why C needed a memory model in C11, and it is accurately represented.

**Corrections needed:**

- **The C11 memory model has formal deficiencies that are not mentioned.** The detractor cites Vafeiadis et al. (POPL 2015) as having demonstrated that the C11 memory model "has the 'out-of-thin-air' problem and lacks monotonicity" [VAFEIADIS-2015]. This citation is accurate and important but not followed up adequately. The out-of-thin-air problem is: under certain formal readings of the C11 relaxed memory model, a program's final state can include values that could not have been computed from any valid execution order — values that appear "out of thin air" with no causal origin. This is a known defect in the formal semantics of the standard. It does not affect most practical concurrent C code, because code using only acquire/release and seq_cst orderings avoids the problematic region. But it is a substantive formal defect in the concurrency model that the council would benefit from acknowledging directly.

- **ThreadSanitizer overhead should be characterized.** TSan's overhead is roughly 5–15x CPU slowdown and 5–10x memory increase [TSan-LLVM]. No council perspective quantifies this. By comparison, ASan's 2–3x overhead makes it more deployable in CI environments; TSan's 5–15x overhead makes it suitable only for targeted concurrent testing. This matters because it limits how much concurrent code coverage can be achieved with race detection enabled.

**Additional context:**

- **The `memory_order_relaxed` / `memory_order_acquire` distinction has compiler codegen consequences.** The apologist correctly notes that `<stdatomic.h>` gives "fine-grained control" over memory ordering. What the council does not explain is that these orderings map directly to hardware fence instructions — `memory_order_seq_cst` inserts a full memory barrier (`MFENCE` on x86, `DMB ISH` on ARM), while `memory_order_relaxed` generates no fence at all. The performance difference can be significant in tight lock-free loops. Choosing the wrong memory ordering is a correctness error that no compiler diagnostic catches; choosing a stronger ordering than needed imposes unnecessary hardware synchronization overhead. This is the technical substance behind the statement that "correct use requires understanding the memory model."

- **Compiler reordering is distinct from hardware reordering.** A subtle point missing from all perspectives: the C memory model constrains both compiler reordering of memory operations *and* hardware reordering through the generated fence instructions. A developer reasoning only about hardware memory models (e.g., x86's relatively strong ordering guarantees) may write code that is correct on x86 but incorrect on ARM or RISC-V, because the C compiler's optimizer is permitted to reorder operations that the hardware would not. The `<stdatomic.h>` model prevents this class of cross-architecture bugs, but only when used correctly.

---

### Section 9: Performance Characteristics

**Accurate claims:**

- **CLBG benchmark citations are correctly handled.** The benchmark data from the Computer Language Benchmarks Game (Ubuntu 24.04, Intel i5-3330 quad-core 3.0 GHz, GCC/Clang at O2/O3) is the appropriate source for C performance claims and is cited consistently [BENCHMARKS-DOC]. The characterization of C as the performance reference point is accurate.

- **GCC vs. Clang differential is accurate.** GCC produces approximately 1–4% faster executable code than Clang on average at O2/O3, with SPEC CPU2017 INT Speed data showing approximately 3% GCC advantage for integer-heavy workloads; Clang compiles 5–10% faster for single-threaded builds [BENCHMARKS-DOC]. These figures are reproducible and sourced from stated hardware configurations.

- **The 10–50x cache performance claim is credible.** The apologist, realist, and practitioner all cite the 10–50x performance differential achievable via cache-friendly memory layout [BENCHMARKS-DOC]. This figure is plausible for compute-bound operations with different access patterns (random vs. sequential). It reflects real behavior in matrix operations and other memory-bandwidth-bound workloads. The claim is properly caveated as applying to "compute-bound operations."

- **No GC pauses and startup in microseconds.** Accurate and structurally correct. The absence of a garbage collector, JIT compiler, and VM means that execution overhead at steady state is minimal and startup is bounded only by program initialization, not runtime infrastructure.

- **Compilation speed advantage.** The claim that C compiles faster than C++ with heavy templates and faster than Rust (monomorphization) is correct in general. The translation-unit–based model with no cross-file type inference or monomorphization means incremental builds are efficient. The Linux kernel at 40M lines compiling in 20–30 minutes on modern parallel hardware is a reasonable benchmark.

**Corrections needed:**

- **The UB-performance coupling is understated across perspectives.** The detractor briefly states: "Compiler optimization achieves C's benchmark dominance partly by exploiting undefined behavior as an optimization opportunity" [DETRACTOR-SEC9]. This is correct but underweighted. Undefined behavior is *structurally load-bearing* for C's benchmark performance. When the compiler assumes signed overflow cannot occur, it eliminates overflow guards and enables loop transformations that would otherwise require complex proofs of correctness. When it assumes pointer dereferences are valid, it enables aggressive code motion. When it assumes no aliasing between typed pointers (strict aliasing), it enables vectorization. These are not incidental optimizations — they are the category of optimization that produces the performance numbers cited in the benchmarks. A correct-C program that avoids all UB (as required for strictly conformant code) may perform meaningfully worse than a nominally-C program that relies on common-extension behaviors. Language designers should understand that C's benchmark performance and C's security vulnerability pattern share a common cause: the compiler's license to treat UB as an impossibility assumption.

- **The abstract machine / hardware gap is underdeveloped.** The historian's citation of David Chisnall's 2018 ACM Queue argument deserves more weight [CHISNALL-2018]. Chisnall argues that C's abstract machine — sequential execution, flat address space, simple source-to-instruction correspondence — is an illusion maintained by modern processors through enormous hardware complexity. Out-of-order execution, speculative execution, branch prediction, and cache hierarchies all exist to maintain the sequential fiction that C programs assume. The performance of modern C programs is not due to C's "closeness to hardware" in an absolute sense; it is due to 40+ years of compiler engineering tuned to C's semantics, combined with processor hardware specifically designed to execute C's sequential model efficiently. Spectre and Meltdown (2018) exposed the boundary between this sequential abstraction and the speculative reality — the hardware-maintained fiction of sequential execution is itself an exploitable side channel. This is a compiler/runtime consideration that the council's performance section does not address.

- **The O0 vs. O2/O3 distinction matters for security claims.** Multiple perspectives note that UB-related security bugs manifest at optimization levels that are not present at `-O0`. This should be stated explicitly in the performance section context: the performance numbers cited (from CLBG and SPEC CPU2017) are at optimized compilation levels (typically `-O2` or `-O3`), which are the same levels where UB exploitation by the compiler is most aggressive. The binary you benchmark for performance is the same binary where security-relevant UB exploitation is active.

**Additional context:**

- **LTO changes the performance-compilation-unit model.** The apologist correctly mentions link-time optimization (LTO via `-flto` in GCC, ThinLTO in Clang) [APOLOGIST-SEC9]. LTO is significant because it crosses the compilation-unit boundary — inlining and other optimizations that normally cannot span `.c` files become possible. GCC's full LTO provides the most benefit but is a global operation with high memory requirements. Clang's ThinLTO provides most of the benefit with better incremental support (independent summary-based analysis, then link-time refinement). For performance-critical libraries, LTO can deliver 5–15% additional throughput beyond per-translation-unit compilation. This is a compiler engineering investment that new languages targeting C-level performance would need to replicate.

- **Variable-length arrays (VLAs) have a compiler safety interaction.** The historian correctly notes that VLAs were added in C99 and made optional in C11 [HISTORIAN-SEC11]. The compiler/runtime perspective: VLAs allocate on the stack, with no stack overflow detection by default. If `n` is attacker-controlled, `int arr[n]` can exhaust the stack silently, often producing a segfault far from the allocation site that appears unrelated. The Linux kernel removed all VLA usage in 2018 for this reason, with the secondary benefit of a 13% performance improvement on some workloads due to improved frame layout predictability [LWN-VLA]. The performance improvement is a compiler artifact: fixed stack frames can be fully analyzed for register allocation and calling convention optimization; variable frames add uncertainty that constrains the optimizer.

---

### Other Sections (if applicable)

**Section 2 (Type System) — compiler enforcement limits:**

The practitioner accurately describes signed/unsigned comparison hazards and implicit integer conversion bugs [PRACTITIONER-SEC2]. The compiler/runtime context that is underemphasized: signed integer overflow is undefined behavior in C, and compilers use this to justify loop optimizations. If the compiler proves that `i++` overflows in a loop, it may transform the loop in ways that assume `i` will never reach `INT_MAX` — eliminating iteration guards. The following pattern is a canonical example:

```c
for (int i = 0; i <= n; i++) { ... }
```

If `n == INT_MAX`, the loop is infinite under UB semantics — the compiler may assume `i <= n` always holds because `i` cannot overflow. GCC and Clang both perform this transformation at `-O2`. This is not a compiler bug; it is the correct reading of the C standard. The practitioner says this "is not captured in C textbooks" [PRACTITIONER-SEC8]; from a compiler perspective, it is the intended behavior of the standard.

The type system's permissive implicit conversions also interact with sanitizers in a specific way: UBSan (`-fsanitize=undefined`) catches signed integer overflow at runtime but is itself a development-only tool with overhead. The production compiler, optimizing away the overflow path, and the instrumented compiler, catching the overflow, are operating under different assumptions about the same code.

**Section 6 (Tooling) — sanitizer qualification:**

The apologist's claim that "the combination of static analysis and dynamic analysis gives C a richer safety-verification toolchain than many languages with stronger static safety guarantees" [APOLOGIST-SEC6] is provocative but arguable. From a compiler/runtime perspective, the qualification is: C's safety toolchain is compensatory infrastructure built to close gaps that the language itself does not address. A language with strong static safety guarantees (Rust's borrow checker) prevents entire categories of bugs before the binary is produced; C's sanitizers detect instances of those bugs in the binaries that were produced. These are different points in the program's lifecycle with different coverage properties.

Specifically: Rust's borrow checker prevents all use-after-free at compile time; AddressSanitizer detects use-after-free at runtime when the specific code path is exercised in the test. A use-after-free that occurs only under specific production load conditions may be missed by ASan entirely. The complementary statement — that Rust cannot detect some classes of logical errors that fuzzing finds — is also true, but the asymmetry between "prevents class of bugs" and "may detect instance of bugs" is important for language designers.

---

## Implications for Language Design

The compiler and runtime dimension of C's design reveals several lessons that extend beyond the surface-level "manual memory management is unsafe" critique:

**1. UB as a specification tool is a debt with compounding interest.**

C's undefined behavior was introduced to accommodate hardware diversity and enable compiler optimization freedom. In 1972 and through the 1980s, this served its purpose. As compilers became more aggressive over the 1990s–2010s, the exploitable gap between what programmers wrote and what the compiler assumed grew — without any change to the C standard. The same UB that enabled C's performance benchmark dominance enabled GCC to compile away null pointer checks, bounds guards, and overflow protections. Language designers should treat undefined behavior as a form of technical debt: it provides short-term flexibility but compounds into security vulnerabilities and developer surprise over the lifetime of a language. The cost of specifying behavior clearly is small initial performance; the cost of leaving it undefined is security incident risk that cannot be contained by developer discipline alone.

**2. Sanitizers are not a language safety substitute — they are a different failure mode.**

AddressSanitizer, MemorySanitizer, and ThreadSanitizer are genuinely valuable tools. But they operate on a different binary than what ships to production, they detect bugs only on exercised paths, and they cannot catch bugs that manifest only under compiler optimization at levels higher than the instrumented build. Language designers who point to sanitizer coverage as evidence that "C can be made safe with tooling" are conflating development-time detection with structural prevention. The safety model of a language that relies on sanitizers differs from the safety model of a language where the compiler enforces safety properties — the former is a probabilistic confidence interval; the latter is a proof.

**3. Concurrency standardization must be synchronous with adoption realities.**

C11's `<threads.h>` was standardized in 2011, not implemented in glibc until 2018, and as of 2026 remains absent from macOS and major BSD platforms. A language feature that cannot be used portably for 15 years after standardization has failed the standardization purpose. Language designers should ensure that threading primitives are mandatory, not optional, and that the standardization process is coupled to implementation plans — not decoupled from them in the expectation that "the community will implement it eventually."

**4. Performance via abstraction violation is fragile.**

C achieves part of its benchmark performance by making guarantees to the compiler (no aliasing between typed pointers, no signed overflow, no race conditions) that production code frequently violates. The Linux kernel compiles with `-fno-strict-aliasing` because the kernel cannot conform to C's aliasing rules at scale. A language that achieves performance through constraints it cannot enforce in practice will face either degraded performance when code conforms to the actual rules, or correctness bugs when code violates constraints that the compiler is exploiting. Language designers should prefer performance through explicit mechanisms (explicit `restrict`, explicit unsafe blocks, explicit raw memory interfaces) over performance through implicit constraints that are unenforceable.

**5. Compiler maturity is a language ecosystem property, not a language property.**

C's benchmark dominance reflects 40–50 years of GCC and Clang optimization development applied to C's semantics. A new language with equivalent semantics would not achieve equivalent performance without equivalent compiler investment. Language designers who target "C-level performance" should plan for the compiler engineering required to achieve it — LLVM provides a foundation, but LLVM-based languages still lag GCC/Clang-for-C on specific workloads. The compiler is not separable from the language performance story.

**6. The abstract machine must match the hardware era.**

C's sequential abstract machine is maintained by modern hardware through speculative execution and out-of-order execution — hardware complexity added specifically to preserve the sequential fiction for C programs. This creates the conditions for hardware side-channel attacks (Spectre, Meltdown) and means that C's "closeness to hardware" is an illusion in a meaningful sense: C programmers are not programming hardware, they are programming a 1970s abstract machine that hardware has been engineered to simulate. A new language designed today can specify an abstract machine more accurately reflective of modern processor behavior, with explicit concurrency, explicit memory ordering, and explicit control over speculative execution boundaries. This is harder to design than C's simple model, but it is more honest about what the hardware actually does.

---

## References

[RITCHIE-1993] Ritchie, Dennis M. "The Development of the C Language." *HOPL-II*. ACM SIGPLAN Notices 28(3), 1993. https://dl.acm.org/doi/10.1145/154766.155580

[KR-1978] Kernighan, Brian W. and Ritchie, Dennis M. *The C Programming Language*, 1st ed. Prentice Hall, 1978.

[C11-WIKI] Wikipedia. "C11 (C standard revision)." https://en.wikipedia.org/wiki/C11_(C_standard_revision)

[C23-WIKI] Wikipedia. "C23 (C standard revision)." https://en.wikipedia.org/wiki/C23_(C_standard_revision)

[C-STD-SPEC] ISO/IEC 9899:2024. International Standard for C (C23). https://www.iso.org/standard/82075.html

[WG14-N2611] Keaton, David. "C23 Charter." WG14 Document N2611, 2020. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n2611.htm

[WG14-DEFER] WG14 defer TS discussion. https://thephd.dev/c2y-the-defer-technical-specification-its-time-go-go-go

[CVE-DOC-C] "CVE Pattern Summary: C Programming Language." Evidence repository, February 2026. `evidence/cve-data/c.md`

[BENCHMARKS-DOC] "Performance Benchmark Reference: Pilot Languages." Evidence repository, February 2026. `evidence/benchmarks/pilot-languages.md`

[ASAN-COMPARISON] Red Hat. "Memory Error Checking in C and C++: Comparing Sanitizers and Valgrind." https://developers.redhat.com/blog/2021/05/05/memory-error-checking-in-c-and-c-comparing-sanitizers-and-valgrind

[MSRC-2019] Miller, Matt. "A Proactive Approach to More Secure Code." Microsoft Security Response Center, 2019. https://www.microsoft.com/en-us/msrc/blog/2019/07/a-proactive-approach-to-more-secure-code/

[NSA-CISA-2025] NSA/CISA. "Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development." June 2025. https://www.cisa.gov/news-events/alerts/2025/06/24/new-guidance-released-reducing-memory-related-vulnerabilities

[WHITE-HOUSE-2023] The White House. "National Cybersecurity Strategy." February 2023.

[ONCD-2024] White House ONCD. "Back to the Building Blocks: A Path Toward Secure and Measurable Software." February 2024. https://www.whitehouse.gov/oncd/briefing-room/2024/02/26/press-release-technical-report/

[CISA-ROADMAPS-2023] CISA/NSA/FBI et al. "The Case for Memory Safe Roadmaps." December 2023. https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps

[HEARTBLEED-WIKI] Wikipedia. "Heartbleed." https://en.wikipedia.org/wiki/Heartbleed

[DIRTYCOW-WIKI] CVE-2016-5195. "Dirty COW." https://en.wikipedia.org/wiki/Dirty_COW

[ETERNALBLUE-WIKI] Wikipedia. "EternalBlue." https://en.wikipedia.org/wiki/EternalBlue

[LOG4SHELL-WIKI] Wikipedia. "Log4Shell." https://en.wikipedia.org/wiki/Log4Shell

[WANG-STACK-2013] Wang, Xi, et al. "Undefined Behavior: What Happened to My Code?" *SOSP 2013 Best Paper*. https://dl.acm.org/doi/10.1145/2517349.2522728

[CERT-VU162289] CERT Advisory VU#162289. "GCC silently discards some wraparound checks." 2008. https://www.kb.cert.org/vuls/id/162289

[CVE-2009-1897] CVE-2009-1897. Linux kernel TUN driver null pointer dereference after compiler optimization.

[VAFEIADIS-2015] Vafeiadis, Viktor, et al. "Common Compiler Optimisations are Invalid in the C11 Memory Model and what we can do about it." *POPL 2015*. https://dl.acm.org/doi/10.1145/2676726.2676995

[BOEHM-THREADS] Boehm, Hans-J. "Threads Cannot be Implemented as a Library." *PLDI 2005*. https://dl.acm.org/doi/10.1145/1065010.1065042

[JANA-EPEX-2016] Jana, Suman, et al. "Automatically Detecting Error Handling Bugs using Error Specifications." *USENIX Security 2016*. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/jana

[TIAN-ERRDOC-2017] Tian, Yida, et al. "ErrDoc: Detecting and Fixing Error-Handling Bugs." *FSE 2017*.

[N1967] Sebor, Martin and Gustedt, Jens. "Field Experience With Annex K — Bounds Checking Interfaces." WG14 N1967, 2015. https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1967.htm

[CHISNALL-2018] Chisnall, David. "C Is Not a Low-Level Language." *ACM Queue* 16(2), April 2018. https://queue.acm.org/detail.cfm?id=3212479

[GOOGLE-ANDROID-2024] Google Security. "Memory Safe Languages in Android OS." https://security.googleblog.com/2022/12/memory-safe-languages-in-android-13.html

[MISRA-WIKI] Wikipedia. "MISRA C." https://en.wikipedia.org/wiki/MISRA_C

[LINUX-LOC] "Linux Kernel Surpasses 40 Million Lines of Code." Stackscale, January 2025. https://www.stackscale.com/blog/linux-kernel-surpasses-40-million-lines-code/

[LWN-VLA] Corbet, Jonathan. "Does the kernel need VLAs?" *LWN.net*, April 2018. https://lwn.net/Articles/753065/

[LWN-ERRNO] LWN.net coverage of errno and strerror_r portability issues.

[LINUX-ALIASING] Linux kernel documentation on compiler options: `-fno-strict-aliasing` usage. https://www.kernel.org/doc/html/latest/process/programming-language.html

[TSan-LLVM] LLVM ThreadSanitizer documentation. https://clang.llvm.org/docs/ThreadSanitizer.html

[CWE-TOP25-2024] MITRE. "CWE Top 25 Most Dangerous Software Weaknesses — 2024." https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html

[COX-UB-2023] Cox, Russ. "Undefined Behavior in C and C++." 2023. https://research.swtch.com/ub

[KERNEL-STYLE] Linux Kernel Coding Style. https://www.kernel.org/doc/html/latest/process/coding-style.html

[SQLITE-LOC] SQLite "The Amalgamation" documentation. https://www.sqlite.org/amalgamation.html

[GCC-RELEASES] GNU Project GCC releases. https://gcc.gnu.org/releases.html

[CLANG-RELEASES] LLVM/Clang releases. https://releases.llvm.org/

[NSA-MEMSAFE-2022] NSA. "Software Memory Safety." November 2022. https://media.defense.gov/2022/Nov/10/2003112742/-1/-1/0/CSI_SOFTWARE_MEMORY_SAFETY.PDF

[WG14-CONTACTS] WG14 Study Group contacts and Meeting Notes, 2025. https://www.open-std.org/jtc1/sc22/wg14/www/wg14_contacts.html

[SUTTER-2012] Sutter, Herb. "Reader Q&A: C99 and Microsoft." *Herb Sutter's blog*, March 2012.

[VLA-WIKI] Wikipedia. "Variable-length array." https://en.wikipedia.org/wiki/Variable-length_array

---

*Document version: 1.0 — Initial advisor review, February 26, 2026.*
