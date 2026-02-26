# Performance Benchmark Reference: Pilot Languages

**Document Purpose:** Comprehensive overview of performance characteristics for four pilot languages (PHP, C, Mojo, COBOL) with current benchmark data and methodological context.

**Last Updated:** February 2026

---

## Executive Summary

This document synthesizes performance benchmarking data across four distinct language categories: systems programming (C), web scripting with JIT optimization (PHP), emerging AI-focused systems language (Mojo), and legacy transaction processing (COBOL). Each represents different optimization targets and hardware ecosystems. The comparison emphasizes that cross-language benchmarking requires understanding both technical metrics and the specific workload contexts where each language excels.

---

## 1. C: Systems Programming Baseline

### Computer Language Benchmarks Game Performance

The Computer Language Benchmarks Game (benchmarksgame-team.pages.debian.net) provides standardized algorithm implementations across multiple languages. Testing occurs on consistent hardware: Ubuntu 24.04 on x86-64 architecture with quad-core 3.0 GHz Intel i5-3330 and 15.8 GiB RAM. Key findings for C:

- C achieves near-identical execution speed to C++, often with lower memory consumption
- C implementations consistently rank in the top tier across algorithmic benchmarks
- Performance advantage reflects minimal runtime overhead and direct hardware access
- Cache-friendly implementations benefit from careful memory layout and access patterns

### Compilation Characteristics

GCC vs. Clang analysis reveals trade-offs:

**Generated Code Quality:**
- GCC produces 1-4% faster executable code on average at optimization levels O2 and O3
- SPEC CPU2017 INT Speed shows GCC maintaining approximately 3% average performance advantage
- Clang outperforms GCC on specific workloads (AI kernels like deepsjeng and leela), exceeding by >3%

**Compilation Speed:**
- Clang traditionally compiles 5-10% faster than GCC for single-threaded builds
- Recent performance varies by project: Clang significantly slower on Linux kernel compilation, marginally faster on LLVM itself
- Optimization level impact: O0 (unoptimized) compiles fastest; O2/O3 require progressively more compiler analysis time

### Known Performance Characteristics

**Cache Efficiency:** C enables explicit control over memory layout and access patterns. Careful register usage and cache-line alignment yield dramatic performance differences (10-50x for compute-bound operations).

**Runtime Overhead:** Negligible. No garbage collection, no runtime type checking, no virtual machine. Direct instruction translation to hardware.

**Hardware Proximity:** Inline assembly, direct pointer manipulation, and memory management make C the de facto baseline for performance claims in other languages.

---

## 2. PHP: Web-Focused Dynamic Language with JIT

### PHP 8.x JIT Performance Improvements

PHP introduced Just-In-Time compilation in PHP 8.0, substantially refined in PHP 8.4. JIT translates hot code paths to native machine code at runtime:

**Synthetic Benchmarks (CPU-Intensive):**
- Up to 3x performance improvement for fractal generation and mathematical computation
- 1.5-2x improvement for long-running applications and batch processing
- Gains correlate with instruction repetition and loop-heavy algorithms

**Real-World Web Applications:**
- WordPress, MediaWiki, and Symfony demonstrate minimal or inconsistent JIT benefit
- Function JIT sometimes shows worse performance than non-JIT execution
- Results vary run-to-run, with smaller deltas than synthetic benchmarks suggest

### TechEmpower Framework Benchmark Results

Latest benchmarking (March 2025, Round 23) on new hardware (Intel Xeon Gold 6330, 56 cores, 64GB RAM, 40Gbps Ethernet):

- PHP-based frameworks (Laravel, Symfony) occupy lower performance tiers
- Rust-based frameworks dominate top positions across nearly all test categories
- Three-fold performance improvement in network-bound tests attributed entirely to hardware upgrade, not framework improvements
- JavaScript Express, Ruby Rails, and Python Django similarly occupy bottom tier positions

### When JIT Provides Value

**High-Value Scenarios:**
- CLI applications with long execution times
- Worker queues processing large batches
- Machine learning and heavy data processing tasks
- Applications performing complex mathematical calculations

**Limited Benefit Scenarios:**
- Traditional request-response web applications (typical <100ms request duration)
- Framework overhead dominates; JIT compilation time not amortized
- Database queries typically represent bottleneck, not PHP computation

### Startup Time and Request Characteristics

- PHP request startup: ~5-50ms (framework dependent)
- Typical web request duration: 10-200ms (database-bound)
- JIT warmup period: 1000+ loop iterations for optimization
- Requests-per-second: TechEmpower measures 5,000-15,000 RPS for PHP frameworks (vs. 500,000+ for optimized Rust)

---

## 3. Mojo: MLIR-Based Systems Language for AI

### Modular's Published Benchmarks

Mojo, built on Multi-Level Intermediate Representation (MLIR) from LLVM ecosystem, presents first-party performance claims:

**Notable Claims:**
- 12x faster than Python without optimization attempts
- Approximately 2x faster than Julia for certain vector operations (7ms vs. 12ms for 10M vector)
- Competitive with CUDA/HIP on memory-bound kernels
- Performance gaps on AMD GPUs for atomic operations and compute-bound fast-math kernels

### The 35,000x Faster Claim: Context and Caveats

Modular's viral benchmark claims Mojo executes Mandelbrot set generation 35,000x faster than interpreted Python. **Critical context:**

- Baseline: unoptimized Python without NumPy (pure Python interpretation)
- Mojo version: optimized with static typing, inlining, and MLIR compilation
- Comparison is not language-to-language but rather optimized Mojo vs. naive Python
- Equivalent optimized Python (using NumPy) shows much smaller gap (~50-300x)
- The claim reflects extremes, not typical performance scenarios

### MLIR Compilation Characteristics

Mojo leverages Multi-Level Intermediate Representation:

**Advantages:**
- Bridges Python's ease-of-use with C++-level performance
- Portable across GPU architectures (NVIDIA, AMD, Intel)
- Hardware-agnostic abstractions enable code reuse
- Compile-time optimization visibility at multiple abstraction levels

**Current State:**
- Young ecosystem with evolving documentation
- Hardware support expanding (NVIDIA Blackwell, AMD MI355X added in 2025)
- GPU programming syntax inspired by CUDA improves accessibility for AI researchers

### Independent Benchmark Reality

Recent academic research (ACL NAACL 2025) presents more nuanced results:
- Mojo competitive with CUDA/HIP for memory-bound kernels
- Performance gaps exist for specific atomic operations
- Fast-math optimization results vary by GPU architecture
- Library maturity and compiler stability still developing

---

## 4. COBOL: Mainframe Transaction Processing

### Mainframe Performance Metrics

COBOL performance cannot be directly compared to general-purpose language benchmarks. Instead, understand COBOL's performance through specialized mainframe metrics:

**MIPS (Million Instructions Per Second):**
- Primary capacity measurement for mainframe hardware/logical partitions (LPARs)
- No direct translation formula from CPU seconds to MIPS (architectural consideration)
- MIPS reflects infrastructure capacity, not algorithm efficiency

**Throughput Metrics:**
- Transaction processing speed measured in TPS (Transactions Per Second)
- Example: AWS-hosted COBOL/CICS implementation achieved 15,200 MIPS equivalent at 1,018 sustained TPS
- CICS processes approximately 1.2 million transactions per second globally (recent measurements)
- Historical scale: 30 billion transactions daily in 2013

### CICS Batch Processing Performance

IBM's Customer Information Control System (CICS), operational since 1969:

- Powers 95% of world ATM transactions
- Engineered for mission-critical reliability and deterministic latency
- Optimized for I/O-bound workloads (database transactions, network calls)
- CPU efficiency secondary to availability and consistency

### Why COBOL Comparisons Differ

COBOL performance discussion targets different metrics than scientific computing benchmarks:

**Different Optimization Targets:**
- COBOL: maximize transaction throughput on specific mainframe hardware
- C: minimize algorithm execution time on generic processors
- Python/PHP: balance development speed with acceptable request latency

**Hardware Specialization:**
- COBOL optimized for IBM mainframe architecture (z-series processors)
- Different instruction set, memory architecture, I/O subsystem
- Ported implementations (AWS, Linux) show different MIPS-to-TPS ratios

**Workload Mismatch:**
- Benchmarks Game algorithms: computational, minimal I/O
- COBOL workloads: I/O-heavy, transaction-focused, batch processing
- Performance "advantage" exists only within matching workload contexts

---

## 5. Benchmark Methodology: Limitations and Context

### Microbenchmarks vs. Real Workloads

**Microbenchmark Characteristics:**
- Isolate specific algorithmic operation (matrix multiply, sort, parsing)
- Repeat operation millions of times to amplify differences
- Minimize I/O and system calls
- Result: extreme sensitivity to compiler optimization and cache behavior

**Real-World Differences:**
- Actual applications are I/O bound (database, network, disk)
- Single operation executes once or small number of times
- CPU cycles may be irrelevant if database query dominates (100-1000ms vs. 10µs computation)
- Framework overhead, memory allocation, and context switching dominate

**Implication:** A language's microbenchmark advantage of 2-3x often yields unmeasurable end-user latency improvement in production workloads.

### Cross-Language Benchmark Dangers

**Fundamental Incomparability:**
1. **Programming Model Differences:** C uses manual memory management; PHP uses automatic; COBOL uses fixed records. These architectural differences make direct comparison inherently misleading.

2. **Optimization Maturity:** Some languages have decades of compiler optimization (C, COBOL); others are emerging (Mojo). "Unfair" comparisons due to toolchain maturity, not language inherent capability.

3. **Algorithmic Expression:** Some algorithms express naturally in specific languages. Mandelbrot set computation (Mojo's benchmark) benefits enormously from static typing and inlining—not representative of string processing or web request handling.

4. **Workload Specialization:** Each language targets different problem domains. Comparing COBOL transaction throughput to C's algorithm speed is like comparing a truck to a sports car—both correct, but measuring different objectives.

### Hardware Dependence

**CPU Architecture Affects Results Dramatically:**
- TechEmpower 2025 Round 23 saw 3x performance improvement purely from new hardware (Intel Xeon Gold 6330 vs. previous generation)
- Cache line size, memory bandwidth, vector instruction availability affect each language differently
- Mojo shows variable performance on AMD vs. NVIDIA GPUs due to architectural differences
- C's advantage partially derives from allowing explicit hardware-specific tuning

**Compilation and Optimization Effects:**

| Factor | Impact |
|--------|--------|
| Compiler version | ±5-10% execution time difference |
| Optimization level (O0 vs. O3) | 2-10x execution time difference |
| Architecture-specific tuning | 1.5-5x difference |
| JIT warmup status (PHP, Mojo) | Not reaching JIT: 50-100x slower |

### Compiler Optimization as Confound Variable

Comparing Mojo's "35,000x faster" claim requires noting the optimization delta:
- Unoptimized Python: interpreted, dynamically typed, no inlining
- Optimized Mojo: statically compiled, inlined, MLIR optimized
- The 35,000x represents optimization techniques (static typing, compilation) more than language design

Similarly, C's benchmark dominance reflects compiler sophistication (40+ years of GCC/Clang development) applied to C's explicit, compiler-friendly semantics.

---

## Practical Recommendations

1. **Use C** for performance-critical system software, embedded systems, and low-level infrastructure where microbenchmarks accurately predict real-world impact.

2. **Use PHP** for web applications where request latency is I/O bound, accepting that JIT provides marginal benefit unless processing large datasets or running long-duration CLI tasks.

3. **Use Mojo** for new AI/ML infrastructure projects where Python usability combined with system-language performance offers genuine advantage over pure C++; exercise caution with production claims from vendor benchmarks.

4. **COBOL** remains optimal for proven mainframe transaction processing systems; migration decisions should be motivated by operational cost, not comparative benchmark performance.

5. **Always measure end-user metrics** (request latency, user experience) rather than relying on algorithmic benchmarks—I/O, network, and database latency typically dominate CPU time.

---

## Sources

- [Computer Language Benchmarks Game](https://benchmarksgame-team.pages.debian.net/benchmarksgame/index.html)
- [GCC 13 vs. Clang 17 Compiler Benchmarks - Phoronix](https://www.phoronix.com/review/gcc-clang-eoy2023)
- [PHP 8.4 JIT Under the Microscope - Medium](https://medium.com/@laurentmn/%EF%B8%8F-php-8-4-jit-under-the-microscope-benchmarking-real-symfony-7-4-applications-part-1-c685e1326f5e)
- [TechEmpower Web Framework Performance Benchmarks](https://www.techempower.com/benchmarks/)
- [Framework Benchmarks Round 23 - TechEmpower Blog](https://www.techempower.com/blog/2025/03/17/framework-benchmarks-round-23/)
- [Mojo: MLIR-Based Performance-Portable HPC Science Kernels - arXiv](https://arxiv.org/abs/2509.21039)
- [MojoBench: Language Modeling and Benchmarks for Mojo - ACL Anthology](https://aclanthology.org/2025.findings-naacl.230/)
- [Break the Myth of MIPS per TPS of CICS - Mainframe2Cloud](https://www.linkedin.com/pulse/break-myth-mips-per-tps-cics-new-approach-mainframe-ming-lu)
- [Performance Benchmarks for PHP environments in 2025 - UMA Technology](https://umatechnology.org/performance-benchmarks-for-php-environments-in-2025/)
- [GCC vs Clang/LLVM: An In-Depth Comparison - Alibaba Tech Medium](https://alibabatech.medium.com/gcc-vs-clang-llvm-an-in-depth-comparison-of-c-c-compilers-899ede2be378)

---

*This document should be reviewed and updated quarterly as new benchmark data emerges and language implementations evolve.*
