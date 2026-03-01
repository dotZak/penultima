# Lua — Detractor Perspective

```yaml
role: detractor
language: "Lua"
agent: "claude-agent"
date: "2026-02-28"
```

---

## 1. Identity and Intent

Lua was designed with crystalline clarity of purpose: a small, embeddable extension language for C applications, born in 1993 to serve petroleum-engineering data-entry tools at PUC-Rio. The design mandate — "keep the language simple and small; keep the implementation simple, small, fast, portable, and free" [HOPL-2007] — was not a slogan but a genuine engineering constraint. This clarity is precisely what makes Lua so interesting to critique: a language can be well-designed for its stated purpose and still fail badly when it is used for purposes it was not designed for. Lua is that language.

The problem is not that Lua's designers made foolish choices. The problem is that Lua is now routinely deployed far outside its design envelope, and its architects have proved unwilling — on principled ideological grounds — to evolve the language to meet that reality.

### The Embedding Mission Does Not Match Actual Use

Lua's needle-through-the-eye metaphor [NEEDLE-2011] describes a language optimized for the C/Lua embedding boundary: every feature must work symmetrically from both sides. This constraint is elegant for embedded use. But the evidence shows that Lua's primary user populations in 2026 are not primarily exploiting embedding: they are writing game logic in Roblox (hundreds of millions of users) [LUAU-WIKI], scripting World of Warcraft addons [WOW-ADDONS], configuring Neovim plugins, and running OpenResty web services [OR-GITHUB]. These are scripting-in-the-large use cases, not the "configuration adapter" role the language was optimized for.

In response to scripting-in-the-large demands, Roblox did not continue to use Lua — they forked it into Luau, adding gradual typing, better performance, and formal sandboxing [LUAU-WIKI]. This is not a minor ecosystem development; it is the largest Lua user base in the world formally declaring that standard Lua is insufficient for their needs. When your biggest adopter forks your language, that is not a testament to success — it is an architectural verdict.

### "Simple and Small" as Ideology, Not Engineering

The unanimity-required decision process [HOPL-2007] — where all three creators must agree before any feature is added — is presented as a strength in the language's historical account. In practice, it has produced three decades of features deferred that are now served by competing forks, external libraries, and dialects. Static typing, optional or not, was researched at PUC-Rio itself (the Typed Lua project, 2014 [TYPED-LUA-2014]) and declined. The generational GC was added in 5.2, removed due to bugs in 5.3, and reintroduced in 5.4 — a 9-year round trip for a feature that modern production systems require. Global variables were acknowledged as a problem for years before optional `global` declarations arrived in 5.5 [PHORONIX-5.5], and even then only as opt-in.

A language that "raised itself rather than was designed" [HOPL-2007] may be charmingly evolutionary, but from the user's perspective, it is a language that fixes known bugs on geological time scales.

---

## 2. Type System

### The Global Default: A Bug Factory

Lua's most immediately costly design decision is not a type system choice — it is a scoping choice with type-system consequences. Variables in Lua are global by default unless explicitly declared `local`. This means that the canonical Lua mistake is:

```lua
function calculate(x)
    result = x * 2    -- silently creates global 'result'
    return result
end
```

Any function in the same program that references `result` without declaring it local will interact with this global. In a large game script with hundreds of functions, this creates a class of bugs that is invisible to the language, undiscoverable without a linter, and resistant to debugging because the problem manifests far from its source.

This is not an exotic edge case. Developers report it consistently [QUORA-GLOBALS]. The lua-users wiki has an entire page documenting workarounds [LUA-WIKI-GLOBALS]. The issue was documented as a "gotcha" in *Programming in Lua* in 2003 [PIL]. After twenty years of community complaints, Lua 5.5 introduced *optional* explicit global declaration via the `global` keyword [PHORONIX-5.5]. Optional. Opt-in. The default remains broken.

For comparison: Python requires no declaration keyword but makes all name-in-scope assignments local by default, requiring explicit `global` to promote to global scope. This is the inverse design, and it is strictly safer. JavaScript's `var` scoping was similarly disastrous, and the response was `let` and `const` which became the dominant practice within years of introduction. Lua's response took thirty years and remained opt-in. This is a governance failure as much as a design failure.

### Dynamic Typing Without Mitigation

Pure dynamic typing is a defensible choice when paired with strong tooling (Python's mypy ecosystem, TypeScript for JavaScript). Lua's dynamic typing is not paired with strong tooling — it is paired with the weakest type-checking ecosystem of any major scripting language currently in use.

The fundamental problems are compounded:

**Nil propagation is silent.** When a Lua function fails to return a value — due to a code path that falls off the end, or a table lookup for a missing key — the caller receives `nil`. There is no error, no warning, no stack trace. The nil propagates silently until something tries to do arithmetic on it or call it, at which point the error message is typically "attempt to perform arithmetic on a nil value" with a stack frame that may be several levels removed from the actual bug site.

**No algebraic data types, no union types, no result types.** The language cannot express "this function returns either a value or an error" at the type level. The `type()` function is Lua's only runtime introspection tool. Callers cannot know from function signatures what they will receive.

**Automatic coercions mask errors.** String-to-number coercion means `"10" + 5 == 15` succeeds silently. This is the kind of implicit conversion that modern language design has moved away from precisely because it hides type errors. PHP received deserved criticism for similar behaviors in the 1990s and spent a decade cleaning them up.

**Metatables are powerful and opaque.** The metatable system is elegant in theory — a single mechanism for operator overloading, OOP, and extensible semantics. In practice, it means that understanding what a piece of Lua code does requires knowing the runtime metatable state of every value involved. A function call `obj:method()` might dispatch through `__index` to a prototype chain, or call a raw function, or invoke `__call` on a non-function value. This is not discoverable from the code; it requires runtime knowledge of the object's metatable. Standard IDEs cannot provide reliable autocomplete for metatable-based objects without type annotations that don't exist in standard Lua.

### OOP Without Convention

Lua deliberately omits built-in classes. The result is not a more elegant system — it is five to ten competing OOP libraries (middleclass, SECS, Penlight OOP, classic, 30log, and others) with incompatible APIs, none of which is canonical, all of which implement slightly different semantics for inheritance, `super`, and method dispatch [LUA-USERS-OOP]. In any codebase that depends on multiple libraries, some of which use library A's OOP and some library B's, object systems become incompatible. This is not a theoretical concern; it is a practical reality in Lua game codebases.

---

## 3. Memory Model

### The C Embedding Problem

Standard Lua's memory model is admirably clean for pure Lua code: automatic GC, no pointer arithmetic, no buffer overflow from Lua-level operations. The brief is correct that "pure Lua is memory-safe by construction" [BRIEF]. But this memory safety guarantee is contingent on the correctness of every C extension in the process.

This conditional guarantee is not an edge case — it is Lua's dominant deployment pattern. OpenResty runs LuaJIT inside nginx with dozens of C extensions for Redis, MySQL, HTTP, and cryptography [OR-GITHUB]. Roblox's Luau runtime embeds a substantial C++ engine. World of Warcraft's addon system runs inside a C++ game client. The attack surface is not the Lua VM; it is the entire C/C++ extension ecosystem.

The evidence shows this attack surface is real: CVE-2022-28805 (heap-based buffer over-read in the Lua parser), CVE-2021-44964 (use-after-free in the GC enabling sandbox escape), CVE-2022-33099 (heap-buffer overflow in `luaG_runerror`), and CVE-2021-43519 (stack overflow in `lua_resume`) all represent vulnerabilities in the Lua implementation itself, not in C extensions [CVEDETAILS-LUA]. The Redis embedded Lua CVE-2024-31449 demonstrates that even mature, production-critical deployments of embedded Lua suffer stack buffer overflows from the Lua/C boundary [CVE-2024-31449].

### The GC Tuning Problem

Lua's incremental GC has three knobs: pause, step multiplier, and step size. These are low-level parameters expressed in opaque ratios with no clear guidance on appropriate values for specific workloads. The [GC-PAPER] (2020) devotes substantial effort to explaining what these parameters actually mean — a necessity because the reference manual's description is insufficient for production GC tuning. Game developers in particular report GC pauses causing frame hitches that require tuning collectgarbage parameters manually [HN-COMPAT].

The generational GC mode, added in 5.4, is not the default. A developer who doesn't read release notes carefully will use the incremental GC, which may be inferior for workloads with many short-lived objects. The 9-year history of the generational GC (added in 5.2, removed in 5.3 due to bugs, reintroduced in corrected form in 5.4 [LWN-5.4]) is not a story of careful iteration — it is a story of a team shipping a buggy feature, silently removing it, and quietly reintroducing it a decade later.

### pcall and C++ Destructors

The C API documentation acknowledges one of the most dangerous aspects of Lua's memory model: `lua_pcall` (and Lua's `pcall`) use `longjmp` to unwind the stack. When Lua code calls C++ code that has instantiated stack objects, a Lua error will `longjmp` past those objects' destructors, leaking every RAII-managed resource. This is not a footnote — it is a fundamental incompatibility between Lua's error model and C++ idioms that causes resource leaks in the common case of embedding Lua in C++ applications [LUA-USERS-CPP-ERR]. The workaround (wrapping C++ entry points in C++ try/catch before calling Lua) is non-obvious and not enforced by the language.

---

## 4. Concurrency and Parallelism

### Coroutines Are Not Concurrency

Lua's concurrency primitive is the coroutine: cooperative, single-threaded, single-core [COROUTINES-PAPER]. At any moment, exactly one coroutine runs. There is no preemption, no parallelism, no multi-core exploitation. The research brief notes this without flinching: "No native threads in standard Lua" [BRIEF].

The problem is not that coroutines are useless — OpenResty's use of LuaJIT coroutines backed by nginx's event loop is a legitimate high-concurrency architecture [OR-DOCS]. The problem is that this architecture is not an intrinsic Lua capability; it is an OpenResty capability that happens to use Lua as its scripting layer. Standard PUC-Lua cannot replicate it without nginx. Any developer who wants async I/O in standard Lua faces choices that are all unsatisfying: use `llthreads2` (which creates multiple Lua states with no shared heap, effectively parallel processes), use `lanes` (which has a separate shared-data model), or block.

For context: Python, which is routinely criticized for its GIL, has asyncio as a first-class standard library module, and the GIL was removed from the default CPython build in Python 3.13 [PY-GIL]. JavaScript, widely mocked for its "callback hell," now has `async`/`await` built into the language specification. Go was designed around goroutines and channels. Lua's response to parallel computing in 2026 is: "use multiple independent Lua states with C-level threading."

Multiple Lua states share no heap. This means data must be marshaled across the boundary via serialization or C-level mechanisms. For a game engine with a physics simulation and a game logic layer, this means no shared Lua tables, no shared Lua objects, no shared closures — everything must be converted at the boundary. This is not a minor inconvenience; it is a fundamental architectural constraint that eliminates entire classes of concurrent programming patterns.

### The OpenResty Trap

OpenResty's concurrency model works well for the specific case of stateless HTTP request handling where I/O dominates. It is a poor model for:
- Stateful services with long-lived objects
- CPU-intensive background processing
- Patterns that require periodic timers not tied to request lifecycles
- WebSocket handling (awkward to implement without blocking)

Developers who discover Lua through OpenResty and then attempt to extend it beyond HTTP request/response often find themselves fighting the event model rather than working with it. The model is powerful within its constraints and brittle at their edges.

---

## 5. Error Handling

### The pcall Tax

Lua's error handling mechanism is `pcall` and `xpcall`. The design is coherent: `pcall` catches errors and returns status/result pairs. The problem is ergonomics and completeness.

**Every potentially-failing call must be wrapped.** Unlike Rust's `?` operator or Go's named return values (which establish a pattern), there is no propagation sugar. A chain of three function calls that each might fail requires three `pcall` invocations or an explicit error re-raise idiom. In practice, developers either wrap excessively (incurring overhead and boilerplate) or skip `pcall` entirely and let errors propagate to a top-level handler — where context about what actually failed has been lost.

**Error objects have no standard structure.** Error values can be strings, tables, or any other Lua value. Convention says "use a string for human display" or "use a table for structured errors," but there is no type to check against, no `.code` or `.message` field that callers can rely on. Each library invents its own error format. This proliferation of error conventions is the same problem that plagued C (return codes? errno? structs? varies by library) and was one of Go's motivations for `error` interfaces — a motivation Lua has not acted on.

**Functions do not declare their error contracts.** In a statically typed language, a function's signature tells you what it can return and whether it can fail. In Lua, there is no convention for signaling "this function can raise." The standard library itself is inconsistent: some functions return `nil, error_message` on failure; others call `error()`; `assert()` can be used to convert the former into the latter. Callers must read documentation or source code to understand error behavior.

**xpcall's handler runs with an unwound stack.** This is the fundamental limitation of `xpcall`: by the time the handler runs, the call stack of the failing code is gone. The handler can capture a traceback via `debug.traceback()`, but the live state — the values of local variables, the contents of tables at the moment of failure — is unrecoverable. Post-mortem debugging of Lua errors is correspondingly difficult.

### Silent Nil: The Hidden Failure Mode

Lua's second error mechanism is not an error at all: it is the nil return. Functions that encounter missing data return `nil`, and the caller either checks or doesn't. The language makes not checking easy:

```lua
local value = config["missing_key"]  -- nil, no error
local result = value.subfield         -- error: "attempt to index a nil value"
-- the error points to the *second* line, not the source of the problem
```

The result is a class of nil-pointer bugs that are structurally identical to null-pointer dereferences in unsafe languages, except Lua does not give them a special name, does not help you find them statically, and reports them with error messages that attribute blame to the symptom site, not the cause site. Luau (Roblox's dialect) addressed this with optional type annotations that can flag potentially-nil values [LUAU-WIKI]; standard Lua continues to leave this entirely to runtime.

---

## 6. Ecosystem and Tooling

### LuaRocks: The Package Manager That Almost Works

LuaRocks is the de facto Lua package manager, and its ~3,000 packages represent the most damning single metric about Lua's ecosystem [LUAROCKS]. For comparison: npm has over 3.5 million packages, PyPI exceeds 550,000, Cargo has over 150,000. LuaRocks' catalog is appropriate for a language from 1994, not for a language whose primary production deployment (Roblox) serves hundreds of millions of users.

The package count understates the quality problem. A meaningful fraction of the 3,000 rocks are unmaintained, do not specify maximum compatible Lua versions, and fail to compile on current systems. The community observation that "there's about a 60% chance of LuaRocks working with any particular package on Windows" [GOODBYE-LUA] — while informal — reflects genuine frustration with the platform's reliability. The LuaRocks security incident of 2019, where the site itself used `math.random` (non-cryptographically-secure) for generating API keys and password reset tokens, revealed that the infrastructure for distributing Lua's ecosystem had basic security failures [LUAROCKS-SECURITY].

Lockfile support was added belatedly in LuaRocks 3.3.0 (2020) via a `--pin` flag. This remains opt-in [LUAROCKS-3.3]. Cargo has enforced lockfiles since 2015. npm has enforced package-lock.json since 2016. The failure to provide reproducible builds by default is not a minor inconvenience — it means that Lua projects are systematically difficult to deploy reproducibly, which is a fundamental requirement for professional software delivery.

A new package manager, Lux, was announced in April 2025 [LUX-2025] — which is both evidence that the community recognizes the problem and evidence that in 2025, Lua is still solving problems that the rest of the ecosystem solved a decade ago.

### The LuaJIT Fragmentation Crisis

The most structurally damaging fact about Lua's ecosystem is the LuaJIT schism, and it cannot be understated.

LuaJIT 2.x implements Lua 5.1 semantics [LUAJIT-COMPAT]. PUC-Lua is at 5.5. That is four major revisions of language changes — integer arithmetic semantics (5.3), RAII patterns (5.4), global declarations (5.5), removed functions (`unpack` → `table.unpack`), changed scoping rules — that LuaJIT users cannot access. Mike Pall, LuaJIT's creator and sole architect, stepped back from the project in 2015 [GOODBYE-LUA-BLOG]. The community-maintained LuaJIT fork continues to receive bug fixes, but no new language features.

The consequence: every Lua library must decide whether to target Lua 5.1/LuaJIT, Lua 5.2, Lua 5.3, Lua 5.4/5.5, or some combination thereof. OpenResty, one of Lua's most prominent production deployments, is built on LuaJIT and therefore frozen at Lua 5.1 semantics for its ecosystem [OR-GITHUB]. A developer who learns Lua 5.4 best practices and then tries to write an OpenResty plugin will discover that half their code is incompatible. A library author who wants to support both platforms must either maintain two codebases or write to the lowest common denominator (Lua 5.1), forgoing a decade of language improvements.

This fragmentation is a direct result of PUC-Rio's governance approach. The three-person team that controls PUC-Lua made breaking changes in every minor version. Those breaking changes made LuaJIT incompatibility permanent. The team has not intervened to mitigate the fragmentation, because LuaJIT is not their project. The result is that Lua's ecosystem is split in half, and the half that gets the best performance (LuaJIT) is also the half that is stuck with a decade-old language version.

### IDE Support: Functional but Lagging

The `lua-language-server` (sumneko) extension for VS Code has 7M+ installs [VSCODE-LUA], which demonstrates genuine adoption. The quality of that support is, however, structurally limited by the dynamic type system. Without type annotations, the language server cannot determine what methods an object has, what a function's return type is, or whether a nil access is an error. The EmmyLua annotation system provides a workaround through specially-formatted comments — but comments are not checked by the language, can silently diverge from actual code, and provide documentation rather than correctness guarantees.

Compare this to TypeScript, where the type system is a first-class language feature that powers IDE support throughout the developer experience. Or to Luau, where gradual typing actually powers static error detection. Standard Lua's IDE story is "we will try to guess what your code does from reading it dynamically, and we will guess wrong about anything that goes through metatables." For a production language used in codebases of hundreds of thousands of lines, this is not good enough.

---

## 7. Security Profile

### The C Extension Attack Surface

The research brief correctly notes that CVE vulnerabilities in Lua itself have declined: 0 CVEs in 2024, 1 in 2023, after a peak of 2021–2022 [CVEDETAILS-LUA]. But the brief understates what the 2021–2022 cluster reveals about the structural security situation.

CVE-2021-44964 (use-after-free in the GC, enabling sandbox escape) and CVE-2022-28805 (heap-based buffer over-read in the parser when compiling untrusted code) both represent fundamental implementation vulnerabilities, not peripheral code. The GC and the parser are core components. Sandbox escape via a crafted Lua script (CVE-2021-44964, CVSS 6.3) is exactly the threat model that game engines, Redis, and other embedders must worry about, because their users can provide arbitrary Lua code.

A broader analysis by game security researchers found that Lua's sandbox escape vulnerabilities have been used in practice against game engines: a pattern of using the Lua interpreter in game save data to achieve code execution has been documented on multiple gaming platforms [PS4-VULN]. The same architectural principle — Lua execution is trusted to be safe within the sandbox — is the shared vulnerability assumption across all Lua embedding contexts.

CVE-2024-31449 in Redis demonstrates that even mature, production-grade embedders make this error: Redis's embedded Lua had a stack buffer overflow exploitable via the authenticated Lua scripting interface [CVE-2024-31449]. Every time Lua is embedded in an application and users can influence Lua execution, the entire C implementation's correctness is in scope.

### The Absent Security Model

Standard Lua has no formal security model. Sandboxing is achieved by convention: don't load libraries you don't want sandbox code to access, replace `load()` with a restricted version, restrict `_ENV` to a controlled subset of globals. None of this is enforced by the language runtime. There is no capability system, no proof-of-correctness for isolation, no formal specification of what a sandbox guarantee actually provides.

The Roblox experience is instructive: when Roblox needed formally correct sandboxing for user-generated game scripts — where security failures could expose children to malicious code — they had to build an entirely new enforcement layer in Luau [LUAU-WIKI]. Standard Lua's sandbox is "remove the functions you don't want," which is security-by-subtraction and fragile against bugs in the implementation.

### Supply Chain Weakness

LuaRocks lacked cryptographic package signing at launch and for years afterward. The 2019 security incident revealed that the package registry's own authentication infrastructure was implemented insecurely [LUAROCKS-SECURITY]. As of 2026, SHA-256 hashes are supported in newer rockspecs, but verification is not mandatory and is not enforced by the toolchain in all configurations. Compare: Cargo verifies packages against checksums stored in `Cargo.lock` by default; RubyGems has supported signed gems since 2011; npm enforces integrity verification via package-lock.json's `integrity` field. Lua's package distribution remains years behind the state of the art on supply chain security.

---

## 8. Developer Experience

### The Global Variable Tax

Every Lua developer who has moved from another language has a story about a bug caused by a missing `local` keyword. The variable is created silently in the global environment, the function works in isolation, and then fails mysteriously when called in a different context because some other function happened to use the same name. This is not a hypothetical scenario — it is the single most documented beginner footgun in Lua [QUORA-GLOBALS, ZEROBRANE-GUIDE].

The correct Lua style is to use `local` for everything, use a linter (LuaCheck) to flag globals, and treat global access as a code smell. This means the safe way to write Lua requires a linter that the language distribution does not include, catching a class of bugs that the language intentionally enables. The 5.5 opt-in `global` declaration addresses this, but only for users who enable the new mode — a breaking change that existing codebases cannot easily adopt.

### 1-Based Indexing: The Impedance Mismatch

One-based array indexing is Lua's most frequently mocked choice, and the mockery is partially deserved. The reason it is mocked is that it causes real bugs. When Lua code interacts with the LuaJIT FFI (C-compatible zero-indexed arrays), when Lua code implements algorithms from C textbooks (zero-indexed), when Lua developers write `for i = 0, n-1 do` expecting to iterate n items (and get n-1 because Lua tables start at 1) — these are not thought experiments, they are daily developer encounters [HN-1BASED].

The lua-users wiki's "Counting From One" page documents the issue and provides workarounds, which is itself evidence that the issue is pervasive enough to warrant community documentation [LUA-USERS-COUNT]. The interaction between Lua's 1-based convention and FFI's 0-based C arrays is a recurring source of off-by-one errors in embedding code. A developer working simultaneously on Lua game logic and C extension code must maintain a mental model of which side of every index is 1-based and which is 0-based — a source of bugs that alternative designs would eliminate.

### The Roblox Effect and Misaligned Learning Paths

The world's largest Lua user base — by a vast margin — is Roblox, which reports hundreds of millions of accounts. But Roblox uses Luau, not Lua [LUAU-WIKI]. This creates a perverse situation: most people who "learn Lua" are actually learning Luau, a superset with gradual typing, different performance characteristics, and formal sandboxing. When those developers try to write standard Lua (for, say, Neovim plugins or a LuaRocks module), they encounter missing features (type annotations don't work), different version semantics (Luau is based on 5.1), and a completely different standard library ecosystem (Roblox's APIs vs. standard Lua's minimal stdlib).

Conversely, developers who learn from the official Lua documentation and PIL produce code that does not run on the platform where most Lua beginners will encounter the language. The ecosystem is fragmented at the learning level, not just the library level.

### Salary Data as Signal

JetBrains' developer ecosystem surveys (2024, 2025) do not track Lua [JETBRAINS-2025]. Stack Overflow's 2024-2025 surveys placed Lua at approximately 6.2% of respondents for "languages worked with," outside the top 15 [SO-2024]. No systematic salary data exists for Lua-specific roles. Standalone Lua developer positions are uncommon in English-language job markets; Lua skills appear as secondary qualifications within game engine programming, OpenResty/nginx engineering, or embedded systems roles.

This is not simply an artifact of Lua's embeddedness. Python is also widely used as an embedded scripting language (in Maya, Blender, various data tools), and it appears at 51% in SO surveys with robust salary data. Lua's invisibility in professional metrics reflects a genuine market reality: Lua does not produce enough standalone economic activity to be tracked. This has implications for the developer population's sustainability.

---

## 9. Performance Characteristics

### The LuaJIT Dependency Problem

Standard Lua's performance situation is uncomfortable. The Computer Language Benchmarks Game categorizes standard PUC-Lua among the five slowest interpreted languages alongside Python, Perl, Ruby, and TypeScript [ARXIV-ENERGY]. On a CPU-intensive loop benchmark, standard Lua 5.4.2 runs in approximately 3.3–3.7 seconds versus C's 0.78–0.81 seconds [BENCH-LANGUAGE] — roughly 4–5× slower than compiled C.

The official answer is: use LuaJIT. LuaJIT achieves near-C performance (0.81 seconds in the same benchmark), competitive with Java and JavaScript V8 [LUAJIT-PERF, EKLAUSMEIER]. But using LuaJIT for performance means accepting Lua 5.1 semantics, an unmaintained JIT core (since Mike Pall's 2015 departure), and a dependency on a project whose future is uncertain.

This creates an impossible choice for performance-critical Lua applications:

1. Use standard PUC-Lua: correct, maintained, but significantly slower than LuaJIT.
2. Use LuaJIT: fast, but frozen at Lua 5.1 with an uncertain maintenance future.
3. Use Luau (Roblox's fork): fast with native code generation for x64/ARM64 [LUAU-WIKI], but a Roblox-developed dialect not intended for general use.

No path provides both current-version semantics and JIT performance without a non-PUC dependency. This is a structural gap that has existed since 2015 and shows no sign of closing.

### Startup Time vs. Runtime Performance

Lua's startup time is genuinely fast — sub-millisecond, appropriate for embedded use [BRIEF]. But this is only relevant if you're loading Lua repeatedly as a scripting extension. In modern deployment patterns — long-running services, game loops, web application servers — startup time is a one-time cost and runtime performance is what matters. On runtime performance, standard Lua's position among the slowest interpreted languages is not mitigated by its fast startup.

### The GC Performance Problem at Scale

The incremental GC's default tuning is conservative, designed to avoid pauses at the cost of throughput. In practice, game developers frequently report needing to manually tune `collectgarbage()` parameters to avoid frame-rate hitches. The generational GC mode (opt-in in 5.4) addresses this for allocation-heavy workloads, but is not the default. The research behind the 5.2 generational GC being removed due to bugs suggests that GC correctness is difficult — and Lua 5.4's 40% performance improvement over 5.3 [PHORONIX-5.4] is partly attributable to finally getting the GC right.

---

## 10. Interoperability

### The C API: Powerful, Error-Prone, Irreplaceable

Lua's C API is the language's greatest technical achievement and its most dangerous interface. The stack-based API — where every operation pushes and pops values on a virtual stack shared between C and Lua — is compact and portable, but it is also completely unchecked by the compiler. Stack index arithmetic is manual. Leaving values on the stack, popping too many, or accessing the wrong stack position all produce undefined behavior or panics at runtime. There are no compile-time checks for stack balance.

The canonical pattern for writing a safe C binding requires calling `lua_checkstack()` before pushing values, using macros to document stack effects, and carefully auditing every code path for stack balance. Libraries like Sol2 and LuaBridge exist specifically to provide C++ wrappers that handle stack management automatically — evidence that manual stack management is too error-prone for production use without abstraction.

The `lua_State *` pointer that every C function receives is not thread-safe. Accessing the same Lua state from multiple threads causes data corruption, with no mutex protection at the API level. Lua relies entirely on the embedder to enforce state isolation — a responsibility that requires understanding Lua internals that are not prominently documented.

### The "Eye of the Needle" as Constraint

The design principle that every feature must work symmetrically from both C and Lua [NEEDLE-2011] is elegant but constraining. It explains why Lua cannot have certain features that would be natural in a pure scripting language: if a feature cannot be represented in the C API, it cannot be added. This constraint prevented Lua from having a more expressive type system (because type annotations would require C-side type system support), first-class exception objects (because C code would need to participate in exception propagation), or structured concurrency (because C code drives the event loop).

The needle-through-the-eye principle was appropriate in 1993 when Lua was primarily an extension language. In 2026, when Lua is used as a standalone scripting language in contexts where C interop is irrelevant (Neovim configuration, simple automation scripts, game mod logic), the constraint still limits the language — for no benefit.

### Version Portability Across Embeddings

A Lua script written for Neovim (LuaJIT, Lua 5.1) does not run in World of Warcraft's addon system (Lua 5.x, with Blizzard-specific library restrictions) without modification. A script written for Redis's embedded Lua (5.1) cannot use Lua 5.4 features. A script for Roblox's Luau can use gradual typing that standard Lua does not parse.

This multi-version fragmentation means that "Lua code" is not a coherent category. It is a family of dialects sharing syntax but with incompatible semantics and APIs. The practical consequence is that Lua has very limited code reuse across embedding contexts, unlike Python (where most pure-Python packages run on any conforming Python 3.x implementation) or JavaScript (where Node.js modules generally run across Node.js versions within well-defined compatibility windows).

---

## 11. Governance and Evolution

### The Three-Person Risk

Lua is governed by Roberto Ierusalimschy, Luiz Henrique de Figueiredo, and Waldemar Celes — the same three people who created it in 1993, all affiliated with PUC-Rio [HOPL-2007]. The decision process requires unanimity, there is no formal succession plan, and there is no legal entity (foundation, corporation, or independent consortium) that would persist beyond the individuals' involvement.

This is the highest bus factor problem of any production language I am aware of at comparable scale. Python has the Python Software Foundation. Ruby has the Ruby Association. Go has Google's institutional backing. Rust has the Rust Foundation with corporate members. JavaScript has ECMA TC39 with representatives from every major browser vendor. Lua has three professors at a Brazilian university.

To be clear: those three professors have maintained remarkable stability and quality for thirty years. The critique is not personal — it is structural. Institutionalized succession is not designed for the previous thirty years; it is designed for the next thirty. There is no evidence that PUC-Rio has a succession plan for Lua's leadership. If Ierusalimschy (the primary author of *Programming in Lua* and the most publicly visible maintainer) retired or became unavailable, it is not clear that Lua development would continue in any organized form.

No RFC process, no governance document, no technical roadmap [LUA-FAQ] — Lua's future is entirely at the discretion of three individuals. For a language embedded in critical infrastructure (Redis, nginx, game engines used by hundreds of millions of people), this is an unacceptable governance risk.

### Breaking Changes Every Minor Version

Lua's backward compatibility policy is, bluntly, not a compatibility policy: it is a documentation of breakages. Each 5.x release has introduced incompatibilities documented in the reference manual as "Incompatibilities with Previous Version" [LUA-MANUAL-5.4]. The research brief lists them: `unpack()` removed in 5.3 (moved to `table.unpack`), integer arithmetic semantics changed in 5.3, module scoping changed in 5.2, `setfenv`/`getfenv` replaced in 5.2, RAII semantics introduced in 5.4 [BRIEF].

Major versions are spaced 4–5 years apart. That means every 4–5 years, Lua adopters must audit their codebase for incompatibilities and potentially update every library they depend on. For organizations that embed Lua for stability (game engines, network appliances, legacy systems), this is a significant maintenance cost. The absence of a long-term support release — there is no "Lua 5.4 LTS" equivalent — means that organizations must either track the latest version or accept security vulnerabilities in an unsupported version.

The contrast with Lua's design philosophy is striking. The creators explicitly resist adding features ("it is much easier to add features later than to remove them" [HOPL-2007]), yet they do not offer the same conservatism toward backward compatibility. Features are added slowly; compatibility is broken repeatedly.

### The LuaJIT Abandonment

The community-maintained LuaJIT fork continues, but it is not receiving new language features. The planned new garbage collector for LuaJIT (documented on the LuaJIT wiki [LUAJIT-NEW-GC]) has not been implemented. LuaJIT remains on Lua 5.1 semantics. PUC-Rio has made no public statement about bridging the LuaJIT/PUC-Lua compatibility gap, providing a JIT-compiled version of PUC-Lua, or endorsing a successor JIT implementation.

The situation is analogous to if Python had a high-performance JIT (PyPy) that stayed at Python 2.7 while the main implementation moved to Python 3. The Python community resolved this tension over a decade through sustained effort, explicit compatibility initiatives, and eventually the deprecation of Python 2. Lua's team has not engaged with the LuaJIT compatibility problem in any public, systematic way.

### Standardization: An Unaddressed Gap

Lua has no ISO, ANSI, or ECMA standard. The PUC-Rio reference manual is the sole normative document. There is no formal conformance test suite (unlike ECMAScript's test262). This means:
- Embedding applications have no guarantee that their Lua implementation is conformant.
- Alternative implementations (LuaJIT, Luau) define "Lua" by reference to PUC-Rio's informal specification, leading to disagreements about correct behavior.
- Legal and procurement processes for enterprise use sometimes require formal standards; Lua's absence from formal standardization bodies limits its enterprise adoption.

For a language in use for over thirty years with hundreds of millions of indirect users, the absence of any standardization process is remarkable.

---

## 12. Synthesis and Assessment

### Greatest Strengths

Credit is due where credit is genuine. Lua's embedding architecture is excellent for its intended use case. The `lua_State` abstraction, the C API's completeness for embedding purposes, and the language's sub-300KB binary size genuinely enable applications that no other scripting language can achieve [LTN001]. Coroutines are first-class and well-designed within their collaborative model. The language's syntax is readable and consistent. The decision to use one mechanism (metatables) for multiple purposes (OOP, operator overloading, RAII, sandboxing) achieves genuine economy of mechanism. LuaJIT, despite its limitations, remains one of the fastest JIT-compiled dynamic language implementations ever built [LUAJIT-PERF].

### Greatest Weaknesses

**Structural — cannot be fixed without breaking changes:**

1. **Global-by-default scoping.** This is the original sin of Lua's design, persisting for thirty years because the team chose to add an opt-in fix rather than change the default. In a language used for large codebases, the default must be safe.

2. **No standard type system or typing story.** The absence of any gradual typing in standard Lua forces every large-scale user (Roblox, OpenResty with TypeScript-like type hints) to solve this themselves. The Typed Lua research project existed in 2014; the language is still untyped in 2026.

3. **LuaJIT/PUC-Lua schism.** The language's performance story requires LuaJIT; LuaJIT requires Lua 5.1 semantics. This contradiction has not been resolved in a decade.

4. **Governance bus factor of 3.** Without institutional succession, Lua's future depends on three individuals' continued involvement.

**Fixable — ecosystem/tooling gaps:**

5. **LuaRocks supply chain security.** The 2019 security incident and ongoing absence of mandatory package verification are fixable given community effort.

6. **No integrated build/test/publish pipeline.** The gap between LuaRocks and Cargo/npm in terms of developer experience is a matter of tooling investment, not language design.

7. **IDE support quality.** The `lua-language-server` is functional; gradual type annotation support (via EmmyLua comments) could be extended significantly with investment.

### Lessons for Language Design

The following lessons are derived from Lua's specific design choices and their documented consequences. They are intended as generic guidance for language designers.

**Lesson 1: Default scope must be local, not global.**
Lua's global-by-default variable scoping has caused decades of production bugs, entire linter ecosystems to detect the problem, and was partially addressed only after thirty years via an opt-in change in 5.5. The correct default is local scope. When a feature's "safe" mode must be opt-in, the default will produce unsafe code in practice. Prove this by noticing that virtually every serious Lua codebase immediately installs LuaCheck and configures it to flag undeclared globals — workarounds for the wrong default.

**Lesson 2: Silent failure modes (nil returns, implicit coercions) accumulate into unreliable systems at scale.**
Lua's nil-propagation model — where any table miss or absent return value produces nil, which silently propagates until it causes a type error at a distant call site — produces bugs that are difficult to find and impossible to prevent statically. Languages should distinguish "this value was intentionally absent" (Option/Maybe) from "this value is missing because of a bug." Lua conflates both into nil. The consequence is that nil-related errors in Lua are harder to debug than null pointer exceptions in Java, because they propagate farther before triggering.

**Lesson 3: Performance tiers must be part of the language design, not outsourced to forks.**
Lua's performance story requires LuaJIT, which implements a different, older version of the language. This forces users to choose between performance and language currency — a choice that no production language should impose. Languages should either design for performance from the start (Rust, Go) or provide an official, maintained, language-version-compatible JIT path (Java's HotSpot, JavaScript's V8). Outsourcing performance to a community fork produces the LuaJIT situation: orphaned at an old language version, with unclear maintenance future.

**Lesson 4: Error handling must have propagation sugar or callers will not handle errors.**
Lua's pcall/xpcall model requires developers to explicitly wrap every potentially-failing call. Without propagation sugar, developers systematically under-wrap, swallowing errors or propagating nil. The empirical evidence from other languages is consistent: Go added `%w` error wrapping because bare error returns were being silently ignored; Rust's `?` operator was designed specifically because Result without propagation sugar produces verbose, error-ignoring code. The boilerplate tax of explicit error handling without propagation sugar correlates with production error-ignoring.

**Lesson 5: Type systems should be gradual, not binary.**
The choice of "dynamic typing only" versus "full static typing" is a false binary that Lua should have escaped in 2014 when Typed Lua was researched. TypeScript demonstrated definitively (by 2017) that gradual typing for a popular dynamic language is feasible, widely adopted, and dramatically improves developer experience and defect detection. Python's mypy, Dart's sound null safety, and Luau all confirm this. Lua declined to add gradual typing to the mainline language; Roblox added it in their fork and found it so valuable they made it the basis of Luau's main selling point. Languages should provide a gradual typing story.

**Lesson 6: Minor version breakage destroys ecosystem momentum.**
Lua breaks backward compatibility at every minor version (5.x). Each breakage — unpack removal, integer arithmetic semantics changes, module system changes — fragments the library ecosystem, creates version targeting problems for library authors, and makes upgrades costly for embedders. Languages can evolve or maintain compatibility, but not both without explicit LTS commitments. Python took this seriously after the Python 2/3 disaster: Python 3.x has maintained strong backward compatibility within the 3.x series. Lua's approach means that moving from OpenResty (LuaJIT/5.1) to current PUC-Lua (5.5) is a non-trivial migration involving breaking changes accumulated across four major revisions.

**Lesson 7: Governance must outlive its founders.**
Lua is one of the most successful embeddable languages ever created, with hundreds of millions of indirect users, running in critical infrastructure worldwide. Its governance is three professors at one university with no succession plan, no legal entity, and no formal community process. This governance structure is adequate for an academic research prototype; it is inadequate for infrastructure software. Languages intending longevity beyond their original creators' active involvement should establish institutional structures — foundations, RFCs, governance documents — before they are needed, not in response to crisis.

**Lesson 8: An absent standard library is not neutral — it is a coordination problem.**
Lua's deliberately minimal standard library (no networking, no JSON, no HTTP, no cryptography, no UUID) is presented as enabling domain-specific extension by host applications. In practice, it means that every standalone Lua program must reinvent or locate third-party solutions for fundamentally common tasks, and the ~3,000-package LuaRocks ecosystem provides an insufficient and unreliable foundation for finding them. The battery-included philosophy of Python produced a more coherent and reliable ecosystem than Lua's "the host provides what you need" philosophy. Languages designed for standalone scripting use should include a standard library that covers common tasks, or commit fully to the embedded model and accept that standalone use will be frustrating.

**Lesson 9: Sandbox security requires formal specification, not convention.**
Lua's sandboxing model ("don't expose the functions you don't want sandbox code to access") is a convention enforced by nothing. CVE-2021-44964 demonstrated that even this convention is insufficient when the implementation has bugs. Robust sandboxing requires a formal capability model, an explicit API for defining sandbox boundaries, and a specified security invariant that the implementation proves. Luau addressed this with formally specified capabilities; standard Lua remains on security-by-subtraction. Languages intended for executing untrusted code must provide a formal security model, not security folklore.

**Lesson 10: The embedding/scripting tension should be resolved, not ignored.**
Lua was designed for embedding and is predominantly used for scripting. These are different requirements. Embedding demands minimal footprint, a clean C API, and deference to the host. Scripting demands a rich standard library, good error messages, IDE support, and a complete story for common tasks (file I/O, networking, testing). Lua has prioritized embedding requirements throughout its evolution, and the scripting use case is served by community workarounds, dialects (Luau), and third-party frameworks (OpenResty). A language that tries to serve both should explicitly acknowledge the tension and make deliberate choices about which requirements take priority in which contexts — rather than defaulting to embedding priorities across all contexts.

### Dissenting Views

**On global-by-default:** One can argue that global-by-default was rational in 1993 given Lua's intended use: configuration scripts where everything should be accessible to the host C application. The decision looks worse retrospectively because of how Lua's use cases evolved. This is not a criticism of the original design — it is a criticism of the failure to update the default as use cases changed.

**On the small standard library:** The minimalist standard library makes Lua genuinely embeddable in contexts (microcontrollers, network appliances) where no other language fits. This is a real and valuable property. The criticism is not that the minimal stdlib is wrong — it is that the minimal stdlib without a rich, reliable, well-maintained package ecosystem leaves standalone Lua developers poorly served.

**On governance:** One can argue that three-person governance is not inherently fragile if those three people are committed and competent, as the Lua creators have demonstrably been for thirty years. The counter is that institutional continuity should not depend on individual longevity. The argument is about design of governance, not about the quality of the specific individuals.

---

## References

[HOPL-2007] Ierusalimschy, R., de Figueiredo, L.H., Celes, W. "The evolution of Lua." *HOPL III*. ACM, 2007. https://www.lua.org/doc/hopl.pdf

[COLA-2025] Ierusalimschy, R., de Figueiredo, L.H., Celes, W. "The evolution of Lua, continued." *Journal of Computer Languages*, 2025. https://www.lua.org/doc/cola.pdf

[NEEDLE-2011] Ierusalimschy, R., de Figueiredo, L.H., Celes, W. "Passing a language through the eye of a needle." *Communications of the ACM*, Vol. 54, No. 7, July 2011. https://cacm.acm.org/practice/passing-a-language-through-the-eye-of-a-needle/

[TYPED-LUA-2014] Maidl, A.M. et al. "Typed Lua: An Optional Type System for Lua." *Workshop on Dynamic Languages and Applications (Dyla)*, 2014. https://dl.acm.org/doi/10.1145/2617548.2617553

[PIL] Ierusalimschy, R. *Programming in Lua*, 4th ed. Lua.org, 2016. https://www.lua.org/pil/

[LUA-MANUAL-5.4] Ierusalimschy, R. et al. "Lua 5.4 Reference Manual." lua.org. https://www.lua.org/manual/5.4/manual.html

[LUA-MANUAL-5.5] Ierusalimschy, R. et al. "Lua 5.5 Reference Manual." lua.org. https://www.lua.org/manual/5.5/manual.html

[LUA-VERSIONS] "Lua: version history." lua.org. https://www.lua.org/versions.html

[LUA-FAQ] "Lua FAQ." lua.org. https://www.lua.org/faq.html

[LTN001] Ierusalimschy, R. "Lua Technical Note 1: Minimal Lua 5.1 Installation." lua.org. https://www.lua.org/notes/ltn001.html

[LUA-LICENSE] "Lua copyright and license." lua.org. https://www.lua.org/license.html

[LWN-5.4] LWN.net. "What's new in Lua 5.4." December 2020. https://lwn.net/Articles/826134/

[PHORONIX-5.4] Larabel, M. "Lua 5.4 released with new garbage collection mode, warning system." Phoronix, June 2020. https://www.phoronix.com/news/Lua-5.4-Released

[PHORONIX-5.5] Larabel, M. "Lua 5.5 released with declarations for global variables, garbage collection improvements." Phoronix, December 2025. https://www.phoronix.com/news/Lua-5.5-Released

[GC-PAPER] "Understanding Lua's Garbage Collection." arXiv:2005.13057, May 2020. https://arxiv.org/pdf/2005.13057

[COROUTINES-PAPER] de Moura, A.L., Ierusalimschy, R. "Revisiting Coroutines." *ACM Transactions on Programming Languages and Systems*, 2009. https://www.inf.puc-rio.br/~roberto/docs/MCC15-04.pdf

[LUA5-IMPL] Ierusalimschy, R., de Figueiredo, L.H., Celes, W. "The implementation of Lua 5.0." *Journal of Universal Computer Science*, 2005. https://www.lua.org/doc/jucs05.pdf

[LUAROCKS] LuaRocks project. https://luarocks.org/

[LUAROCKS-SECURITY] LuaRocks security incident, March 2019. https://luarocks.org/security-incident-march-2019

[LUAROCKS-3.3] LuaRocks 3.3.0 release announcement (--pin flag added). lua-l mailing list, January 2020. http://lua-users.org/lists/lua-l/2020-01/msg00307.html

[LUX-2025] mrcjkb.dev. "Announcing Lux — a luxurious package manager for Lua." April 2025. https://mrcjkb.dev/posts/2025-04-07-lux-announcement.html

[LUAU-WIKI] "Luau (programming language)." Wikipedia. https://en.wikipedia.org/wiki/Luau_(programming_language)

[LUAU-GITHUB] Roblox/luau repository. GitHub. https://github.com/luau-lang/luau

[OR-GITHUB] openresty/lua-nginx-module. GitHub. https://github.com/openresty/lua-nginx-module

[OR-DOCS] OpenResty documentation. https://openresty.org/en/lua-nginx-module.html

[CF-BLOG] Cloudflare blog. "Pushing Nginx to its limit with Lua." https://blog.cloudflare.com/pushing-nginx-to-its-limit-with-lua/

[REDIS-LUA] Redis documentation on Lua scripting. https://redis.io/docs/manual/programmability/eval-intro/

[CVEDETAILS-LUA] CVE Details — LUA security vulnerabilities list. https://www.cvedetails.com/vulnerability-list/vendor_id-13641/LUA.html

[CVE-2024-31449] "CVE-2024-31449 — Redis Lua scripting stack buffer overflow." Redis Security Advisory, October 2024. https://redis.io/blog/security-advisory-cve-2024-31449-cve-2024-31227-cve-2024-31228/

[CVE-2021-44964] Use-after-free in Lua GC/finalizer enabling sandbox escape. CVE-2021-44964. CVSS 6.3. https://www.cvedetails.com/vulnerability-list/vendor_id-13641/LUA.html

[CVE-2022-28805] Heap-based buffer over-read in lparser.c. CVE-2022-28805. CVSS 6.4. https://www.cvedetails.com/vulnerability-list/vendor_id-13641/year-2022/LUA.html

[PS4-VULN] "Vulnerabilities — PS4 Developer wiki." https://www.psdevwiki.com/ps4/Vulnerabilities

[LUAJIT-PERF] LuaJIT performance page. https://luajit.org/performance.html

[LUAJIT-COMPAT] Hacker News discussion: "Isn't LuaJIT stuck on Lua 5.1, and no longer in development?" https://news.ycombinator.com/item?id=15650546

[LUAJIT-NEW-GC] "New Garbage Collector." LuaJIT wiki. http://wiki.luajit.org/New-Garbage-Collector

[BENCH-LANGUAGE] DNS/benchmark-language. GitHub. https://github.com/DNS/benchmark-language

[EKLAUSMEIER] Klausmeier, E. "Performance Comparison C vs. Java vs. Javascript vs. LuaJIT vs. PyPy vs. PHP vs. Python vs. Perl." July 2021. https://eklausmeier.goip.de/blog/2021/07-13-performance-comparison-c-vs-java-vs-javascript-vs-luajit-vs-pypy-vs-php-vs-python-vs-perl

[ARXIV-ENERGY] "It's Not Easy Being Green: On the Energy Efficiency of Programming Languages." arXiv, October 2024. https://arxiv.org/html/2410.05460v1

[SO-2024] Stack Overflow Annual Developer Survey 2024. https://survey.stackoverflow.co/2024/

[SO-2025] Stack Overflow Annual Developer Survey 2025. https://survey.stackoverflow.co/2025/

[JETBRAINS-2025] JetBrains State of Developer Ecosystem 2025. https://devecosystem-2025.jetbrains.com/

[TIOBE-2026] TIOBE Index, February 2026. https://www.tiobe.com/tiobe-index/

[ZEROBRANE] ZeroBrane Studio. https://studio.zerobrane.com/

[ZEROBRANE-GUIDE] Kulchenko, P. "Lua: Good, bad, and ugly parts." ZeroBrane notebook. https://notebook.kulchenko.com/programming/lua-good-different-bad-and-ugly-parts

[VSCODE-LUA] sumneko/lua-language-server extension on VS Code Marketplace. https://marketplace.visualstudio.com/items?itemName=actboy168.lua-debug

[WOW-ADDONS] World of Warcraft addon documentation. Blizzard Entertainment.

[VALVE-DOTA] Dota 2 Workshop tools documentation. Valve.

[HN-COMPAT] Hacker News discussion: "Lua 'minor versions' tend to break compatibility with older code." https://news.ycombinator.com/item?id=23686782

[LUA-WIKI-COMPAT] lua-users wiki. "Lua Version Compatibility." http://lua-users.org/wiki/LuaVersionCompatibility

[LUA-USERS-OOP] lua-users wiki. "Object-Oriented Programming." http://lua-users.org/wiki/ObjectOrientedProgramming

[LUA-USERS-COUNT] lua-users wiki. "Counting From One." http://lua-users.org/wiki/CountingFromOne

[LUA-USERS-CPP-ERR] lua-users wiki. "Error Handling Between Lua And C++." http://lua-users.org/wiki/ErrorHandlingBetweenLuaAndCplusplus

[QUORA-GLOBALS] "Why aren't more people annoyed by default global variables in Lua?" Quora. https://www.quora.com/Why-arent-more-people-annoyed-by-default-global-variables-in-Lua

[LUA-WIKI-GLOBALS] lua-users wiki. Global variable management discussions and patterns. http://lua-users.org/wiki/

[GOODBYE-LUA] "Goodbye, Lua." RealMensch blog, May 2016. https://realmensch.org/2016/05/28/goodbye-lua/

[HN-1BASED] "Ask HN: Can Lua be remade to use 0-based numbering?" Hacker News, 2023. https://news.ycombinator.com/item?id=36258843

[BRIEF] Lua — Research Brief. research/tier1/lua/research-brief.md. 2026-02-28.

[LABLUA] LabLua — Programming Language Research Group, PUC-Rio. http://www.lua.inf.puc-rio.br/

[PY-GIL] Python Enhancement Proposal 703 (PEP 703). "Making the Global Interpreter Lock Optional in CPython." https://peps.python.org/pep-0703/
