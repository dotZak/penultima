# Ruby — Security Advisor Review

```yaml
role: advisor-security
language: "Ruby"
agent: "claude-sonnet-4-6"
date: "2026-02-27"
schema_version: "1.1"
```

---

## Summary

Ruby's security profile is shaped by a fundamental tension embedded in its design philosophy: a language engineered to maximize programmer flexibility and minimize friction will structurally enable attack surface that a more restrictive language would prevent by construction. The council captures this tension to varying degrees, but the apologist perspective in particular understates some genuine risks and contains one factual error (the YAML.safe_load transition). The detractor, by contrast, correctly identifies the structural relationship between Ruby's flexibility-granting features and its security surface, producing the sharpest analysis in the council on this dimension.

The most important gap across all five perspectives is the near-complete omission of Brakeman — the primary static security analysis tool for Rails applications, capable of detecting SQL injection, XSS, command injection, mass assignment vulnerabilities, and dozens of other Rails-specific security issues. Brakeman represents a significant piece of Ruby's ecosystem security story and its absence weakens the council's treatment of Section 6 and Section 7. Similarly, `bundler-audit` (vulnerability scanning of dependency manifests) is not mentioned by any council member. These omissions matter because a key question about Ruby's security is whether the tooling makes secure practices the default path — and the answer is "more than the council credits."

The core runtime's CVE profile is accurately described as modest. The research brief correctly notes that most CVEs concentrate in standard library components (date, uri, openssl, rexml, webrick) rather than the core VM [RUBY-SECURITY; CVEDETAILS-RUBY]. However, the comparison the apologist draws — "compare this to CVE volumes for the C runtime, the Linux kernel, or any JVM implementation" — is the wrong comparison class. Those are systems-level runtimes with enormous attack surfaces. The correct comparison for Ruby is Python (similar deployment profile, similar language properties) and Node.js. That comparison would be more informative and more defensible. The supply chain picture is well-documented but its structural causes — a flat namespace, trust-by-default publishing, historically inadequate automated malware scanning — deserve clearer analysis than the council provides.

---

## Section-by-Section Review

### Section 7: Security Profile

**Accurate claims:**

- The CVE count for the CRuby runtime is genuinely low: 3 in 2024, 6 in the first two months of 2025 per CVEDetails [CVEDETAILS-RUBY]. These figures are sourced. The research brief correctly notes that most historical CVEs concentrate in standard library components (date, uri, openssl, rexml, webrick) rather than the core VM [RUBY-SECURITY].

- ReDoS (Regular Expression Denial of Service) is correctly identified as a cross-language issue arising from NFA-based backtracking regex engines, not a Ruby-specific design flaw. The specific CVEs in the `date` gem and `uri` component are accurately cited [RUBY-CVE-REDOS]. This vulnerability class exists identically in Python's `re` module, Ruby's Regexp, and many other implementations.

- `Kernel#open` shell injection is correctly flagged as a genuine Ruby-specific footgun: calling `open()` with user input beginning with `|` executes an OS command [BISHOPFOX-RUBY]. The council is right that this risk is documented and avoidable. The apologist correctly notes that `File.open` is the safe alternative.

- The removal of `$SAFE` taint tracking in Ruby 3.0 is correctly characterized by the apologist and realist as removing a false guarantee [RUBY-3-0-RELEASE]. The mechanism was deprecated and removed not because safety was irrelevant, but because the implementation did not deliver meaningful protection. Developers who relied on `$SAFE` for sandboxing had a false sense of security — removing it was the more honest and safer outcome. The historian's treatment of this point is particularly sharp: "$SAFE removal demonstrates that honest acknowledgment of a failed security model is possible — but it took 25 years."

- Supply chain incidents are documented with specificity: 700+ malicious gems in February 2020 [THN-TYPOSQUAT-2020]; 60+ malicious packages with 275,000+ cumulative downloads ongoing since 2023 [REVERSINGLABS-GEMS]; fastlane CI/CD credential theft gems in 2025 [SOCKET-MALICIOUS-GEMS]; simultaneous RubyGems/PyPI attack in August 2025 [THN-GEMS-2025]. The data is accurate.

- The `Object#send` vulnerability vector is correctly identified in the research brief [BISHOPFOX-RUBY]: using `Object#send` with attacker-controlled input allows arbitrary method invocation, including methods with sensitive effects. This is analogous in severity to `Kernel#open` misuse. The council largely skips over this in prose (it appears in the research brief but not substantively in any council perspective). It should be noted that this vector is distinct from `Kernel#open` and more subtle: the attack surface includes any code path that dynamically dispatches method names derived from external input, which is a common Rails pattern (e.g., `params[:action].to_sym` passed to `send`).

- Memory safety is correctly characterized: Ruby application code is memory-safe (no use-after-free, buffer overflow, or dangling pointers in pure Ruby code), while C extensions can introduce unsafe operations. The comparison to Python rather than Rust is correct — the relevant baseline for Ruby's security posture is the language tier it occupies (GC'd, interpreted, application-layer), not systems languages.

**Corrections needed:**

- **Factual error in the apologist**: The apologist writes: "Kernel#load requires `permitted_classes:` since Ruby 3.1." This is wrong. The method in question is `YAML.load`, not `Kernel#load`. Specifically, Psych 4.0 (bundled with Ruby 3.1) changed the default behavior of `YAML.load` to disallow arbitrary object deserialization by default; callers must opt in via `permitted_classes:` to restore the previous behavior [RUBY-3-1-RELEASE]. `Kernel#load` is for loading Ruby source files and is unrelated to YAML deserialization. This is a meaningful factual error because `Kernel#load` with user input is itself a serious code injection vulnerability — conflating the two could mislead readers about which vector was addressed.

- **Misleading CVE comparison**: The apologist's comparison of Ruby's CVE count to "C runtime, the Linux kernel, or any JVM implementation" is not a valid comparison. Those are systems software components with fundamentally different attack surfaces, scrutiny levels, and deployed footprints. A comparable analysis would compare Ruby's CVE rate to Python's, controlling for deployment scale and scrutiny level. No such comparison is provided by any council member. Without this context, the "modest CVE count" claim is suggestive but not evidentiary.

- **Omission of runtime C-layer memory safety CVEs**: The council's treatment of Ruby's memory safety focuses on application-level code safety. However, the CRuby runtime itself is implemented in C, and has had genuine memory safety CVEs at the runtime level. The research brief identifies: buffer over-read and double-free CVEs in Ruby's Regexp compiler, exploitable via untrusted user input for regex compilation [RUBY-SECURITY]. These are not C extension vulnerabilities — they are CRuby's own C code. The apologist's claim that "memory safety issues... simply do not exist in Ruby code" is true for application-layer Ruby, but not for the CRuby runtime layer that processes all Ruby programs. A runtime-level buffer overflow reachable through arbitrary regex input is a significant attack surface.

**Additional context:**

- **Brakeman is absent from all council perspectives.** Brakeman is a static analysis tool specifically designed to find security vulnerabilities in Rails applications: SQL injection (including ActiveRecord query misuse), XSS (unescaped output in ERB templates), command injection (shell invocations from user input), mass assignment, CSRF protection gaps, redirect vulnerabilities, and 50+ additional check types. It integrates into CI pipelines and is widely used in mature Rails codebases. The Rails security story is materially different with Brakeman in the picture: the "insecure path is the easy path" critique is partially countered by a static analysis tool that catches many common patterns before deployment. This does not eliminate the underlying risks, but it meaningfully shifts the security ergonomics assessment.

- **bundler-audit** (the Bundler security audit gem) checks a project's `Gemfile.lock` against a database of known-vulnerable gem versions. This provides a dependency scanning layer analogous to `npm audit` or Rust's `cargo audit`. No council member mentions it. For assessing Ruby's supply chain security posture, the absence of integrated dependency auditing in the core toolchain (bundler-audit must be installed separately, unlike Go's `govulncheck` which is available via go toolchain) is relevant context.

- **Rails CVE history and mass assignment**: The research brief cites Rails remote code execution vulnerabilities [RAILS-RCE-CODECLIMATE], specifically the GitHub mass assignment incident (circa 2012, CVE-2012-2661) where an attacker could modify the `github_owner_*` attribute of repos via the default-open mass assignment in Rails 2.x/3.x. This is a Rails-ecosystem vulnerability, not a CRuby language vulnerability, but it illustrates that Ruby's low core CVE count is not the complete picture of what practitioners deploying Ruby web applications are exposed to. The transition to `strong_params` in Rails 4 (2013) fixed this at the framework level — demonstrating the security improvement that secure-by-default API design achieves.

- **Security ergonomics data point**: The academic study of Stack Overflow data found that "Application Quality and Security" was challenging for over 40% of experienced Ruby developers — notably ranking among the more difficult topics even for practitioners, not beginners [ARXIV-RUBY-2025]. This is a security ergonomics signal: even experienced developers find Ruby application security non-trivial. No council member cites this finding in their security section.

- **CVE scope breakdown**: The research brief correctly notes that CVEs concentrate in standard library components rather than the core VM. For security analysis, this distinction matters: standard library vulnerabilities (date, uri, webrick, rexml) are often reachable from web application code through normal usage, making them high-impact despite being outside the core VM. The apologist's framing that the CVE count is low should be understood in this context.

**Missing data:**

- No GHSA (GitHub Security Advisory Database) query is provided. GHSA has a `rubygems` ecosystem namespace that would add context to gem-level vulnerability rates, distinct from the CRuby runtime CVEDetails data.

- No comparison to Python's CVE profile (NVD query: `python` language runtime) is provided, which would be the most defensible peer comparison.

- No analysis of Rails-specific CVE history separate from CRuby CVEs. For practitioners, Rails CVEs are the primary exposure surface.

---

### Section 2: Type System (security implications)

**Accurate claims:**

- The council correctly notes that Ruby's dynamic type system provides no compile-time protection against injection vulnerabilities. Input arrives as strings; there is no type-level distinction between "user-supplied string" and "sanitized string" in base Ruby.

- The apologist's observation that duck typing means object suitability is determined by method availability is accurate. The security implication is that method-level checks (does this object respond to a given method?) cannot substitute for type-level checks that prevent confusion attacks.

- The fragmentation between Sorbet and RBS is accurately characterized as limiting adoption [RUBY-TYPING-2024]. Neither approach has achieved the ecosystem penetration needed to make type-level security guarantees practical at the language level.

**Corrections needed:**

- The council does not discuss whether Sorbet or RBS can be used for taint tracking — encoding "this string has been sanitized" vs. "this string is raw user input" in the type system. This is a realistic capability of gradual type systems in some languages (e.g., Java annotations like `@Untainted`, Haskell's type-level tainting) that Ruby's optional typing could theoretically support via Sorbet signatures. The council should note that even with Sorbet, this level of type-based security enforcement would require significant adoption and library coverage that does not exist today.

**Additional context:**

- `method_missing` as an implicit attack surface: the ability for objects to respond to arbitrary method calls via `method_missing` means that code which appears to call a safe method could inadvertently invoke a proxy that forwards the call somewhere dangerous. In large Rails applications using metaprogramming-heavy libraries (ActiveRecord, Draper, etc.), the call graph is not statically analyzable. This is not uniquely a security vulnerability but it complicates static analysis, making Brakeman's conservative over-approximation of call paths both necessary and imprecise.

- Open classes create a lateral attack surface: any gem can modify built-in class behavior. A malicious gem that redefines `String#to_s` or `Integer#+` could alter program semantics silently. This is not a hypothetical — the supply chain attack surface includes modification of core class behavior. The council mentions this in the context of monkey-patching but does not connect it to the supply chain security section.

---

### Section 3: Memory Model (security implications)

**Accurate claims:**

- Ruby application code (pure Ruby) is genuinely memory-safe. Use-after-free, buffer overflow, and dangling pointer vulnerabilities cannot arise from Ruby application code. This is a meaningful structural protection for application-layer development.

- The claim that C extensions can introduce memory safety vulnerabilities is accurate. Any gem with a C extension (nokogiri, pg, ffi, etc.) operates outside Ruby's memory safety guarantees. Memory corruption vulnerabilities in C extensions are feasible and have been reported.

- The GC is correctly described as automatic and largely transparent to application developers. GC pauses are an availability concern but not a security concern in the traditional sense.

**Corrections needed:**

- As noted above, the runtime-level memory safety CVEs (Regexp buffer over-read, double-free) need acknowledgment. The claim that memory safety issues "simply do not exist in Ruby code" conflates the language level (true) with the runtime level (not true for CRuby's C implementation).

**Additional context:**

- **GVL as an accidental security benefit**: The GVL, criticized widely as a concurrency limitation, provides a structural protection against a class of data-race vulnerabilities in Ruby application code. By serializing Ruby bytecode execution across threads, the GVL prevents time-of-check/time-of-use (TOCTOU) races in pure Ruby code that could otherwise create security vulnerabilities. For example, a session fixation attack that relies on racing a session ID validation against a session invalidation cannot be constructed in pure multithreaded Ruby in the way it could in a truly parallel runtime without explicit synchronization. This benefit is real but limited: C extensions can release the GVL, and I/O-bound code executes with the GVL released. No council member discusses this tradeoff. It should be noted that this "protection" is a byproduct of a concurrency limitation, not a designed security property, and Ractor adoption would change this picture.

- **Frozen strings as a limited immutability guarantee**: The `# frozen_string_literal: true` pragma (enabled by default in Ruby's own standard library) prevents string mutation. In a security context, immutable strings prevent a class of mutation-after-check attacks where a string is validated and then mutated before use. This is a narrow but real protection. The council notes frozen strings only in the performance context; the security implication is absent.

---

### Section 4: Concurrency (security implications)

**Accurate claims:**

- The GVL's I/O-release behavior is correctly described: I/O operations release the GVL, allowing other threads to run. This means race conditions involving I/O-bound state (e.g., database reads followed by writes in a web request) are not protected by the GVL. Security implications: concurrent modification of shared session or authentication state during I/O is possible and must be handled by application-level synchronization.

- Ractors' requirement that shared state be frozen is accurately described [RUBY-3-0-RELEASE]. This constraint, while a usability friction, has a security benefit: it prevents one Ractor from reading shared mutable state that another is modifying, eliminating a class of race conditions between execution contexts.

**Corrections needed:**

- The council does not address data race conditions in C extensions. C extensions that release the GVL (to allow parallelism during computation) can introduce data races on shared Ruby objects if they are not written carefully. This is a known security concern in extension development: a C extension that releases the GVL while accessing Ruby objects can race with Ruby bytecode execution in another thread. Security implications: race conditions in authentication or authorization checks in C-extension-based libraries (e.g., cryptographic token validation in a C extension) could be exploitable.

**Additional context:**

- The fiber scheduler interface (Fiber Scheduler, Ruby 3.0+) and async I/O libraries introduce cooperative concurrency. In the `async` gem's execution model, fiber switching occurs at I/O boundaries. This means that state that appears to be accessed sequentially may be interleaved with other request processing. Rails applications using async I/O patterns must ensure that request-scoped state (e.g., `Current` attributes, thread-local variables used by Rails) is correctly isolated per fiber, not per thread. This is a security-relevant ergonomics concern for applications adopting newer concurrency models.

---

### Other Sections (if applicable)

**Section 6: Ecosystem and Tooling — security-relevant gaps**

All five council perspectives omit Brakeman from their ecosystem discussion. Brakeman (https://brakemanscanner.org/) is the primary static security analysis tool for Rails applications, detecting:

- SQL injection (including ActiveRecord query manipulation via string interpolation)
- Cross-site scripting (unescaped output in ERB, Haml, Slim templates)
- Command injection (shell invocations from controller params)
- Unsafe deserialization
- Redirect vulnerabilities
- Mass assignment issues
- CSRF protection gaps
- And 50+ additional check types

Brakeman runs on the AST of the Rails application, does not require running the code, and integrates into CI pipelines. It is widely used in mature Rails codebases and represents a meaningful security differentiator for the Rails ecosystem. Its absence from the council's ecosystem section is a material gap.

Similarly absent: `bundler-audit`, which scans `Gemfile.lock` against a vulnerability database derived from GHSA. The gem is maintained by the community and provides the basic dependency security scanning that `cargo audit` and `npm audit` provide in other ecosystems.

The combination of Brakeman + bundler-audit + RuboCop (with `rubocop-rails-security` cops) constitutes a reasonable static security posture for Rails applications. Presenting Ruby's ecosystem security story without these tools gives an incomplete picture.

**Section 11: Governance — supply chain security**

The October 2025 RubyGems governance transition (from Ruby Central to the Ruby core team) [RUBY-RUBYGEMS-TRANSITION] has potential security implications beyond the governance narrative the council presents. Package registry security (malware detection, publisher identity verification, signing infrastructure) is influenced by who controls and funds the registry. The transition occurred under pressure and the security investments in the registry — automated malware scanning, publisher verification, signing — are not documented in the council or research brief. The historian correctly notes the structural fragility of infrastructure built outside the language's governance, but doesn't assess the security infrastructure state under the new governance.

---

## Implications for Language Design

The following observations are drawn from Ruby's security profile and are intended as generic lessons applicable to any language design effort.

**1. A language's attack surface is proportional to its flexibility, and this relationship should be explicit in the design.**

Ruby's most persistent security vulnerabilities — `Kernel#open` command injection, `Object#send` method invocation with arbitrary input, YAML deserialization, open classes as supply chain attack vectors — all arise directly from the language's core design philosophy of maximum flexibility. The "minimize programmer frustration" objective, pursued without explicit security modeling, produces a language where the shortest path between two points can be a security vulnerability. Language designers should formally model the security consequences of each flexibility-granting feature: the privilege of `eval` carries a proportional code injection cost; dynamic dispatch with attacker-controlled method names is a privilege escalation vector; open classes are a supply chain attack surface. These are not accidents — they are the predictable consequences of specific design decisions.

**2. Removing a false security guarantee is better than maintaining it; but the correct lesson is not to create the false guarantee.**

Ruby's removal of `$SAFE` taint tracking in Ruby 3.0 [RUBY-3-0-RELEASE] is generally cited as an example of good decision-making: the mechanism provided no meaningful security and created false assurance. That is the right decision given the situation. But the prior question is why a taint-tracking mechanism that didn't work was added in the first place and maintained for approximately 25 years. The lesson is not only "remove security theater when you find it" — it is "when adding security mechanisms, validate that they actually prevent the attacks they claim to prevent before shipping them." Security mechanisms that cannot be proved effective should not be included, because removing them later is costly and the false assurance they provide causes harm in the interim.

**3. Package registry design requires adversarial security modeling as a first-class design constraint, not a retrofit.**

RubyGems's flat namespace and trust-by-default publishing model made the 2020 typosquatting incident (700+ malicious gems, 95,000+ downloads [THN-TYPOSQUAT-2020]) and subsequent campaigns (275,000+ downloads from malicious packages through 2025 [REVERSINGLABS-GEMS]) structurally predictable. A flat namespace where `fast-lane` and `fastlane` are distinct and both can be registered means that any attacker can occupy adjacent namespace slots. A trust-by-default model where any account can publish any gem means that identity is not verified. These are architectural decisions made before the registry became critical infrastructure, and they cannot be corrected without breaking changes to the ecosystem. Language designers building package registries should treat namespace collision, publisher identity, and supply chain integrity as primary design requirements, not features to be added later.

**4. The GVL illustrates that concurrency constraints have security implications worth modeling.**

The GVL's serialization of Ruby bytecode execution provides implicit protection against data-race vulnerabilities in Ruby application code. This is an accidental security benefit of a concurrency limitation — not a designed property. But it illustrates a general principle: a language's concurrency model determines its data-race attack surface. Languages that provide "safe" concurrency by construction (Rust's ownership model, Ractor's freeze requirements) structurally prevent a class of concurrent-access security vulnerabilities. Language designers considering concurrency models should explicitly analyze the security implications of their choice: allowing mutable shared state across threads creates both a concurrency complexity problem and a potential security problem, and both should be in scope.

**5. Type systems can encode sanitization state; dynamic languages cannot enforce this without compiler support.**

A statically typed language can, in principle, encode the difference between `UnsanitizedInput` and `SanitizedString` at the type level — and then reject programs that pass the former to functions expecting the latter. This is the intuition behind taint-tracking type systems. Ruby's dynamic type system cannot provide this guarantee: there is no compiler to reject programs that pass raw user input to SQL query constructors. The ecosystem compensation (Brakeman, parameter sanitization conventions, ActiveRecord parameterized queries) is effective but requires developer discipline and tooling coverage. Language designers who build dynamic type systems are implicitly accepting that injection vulnerability prevention must be handled at the library and tooling layers rather than the language layer. This is a valid choice for certain use cases, but it is a choice with a cost that should be stated explicitly.

**6. Static security analysis tools are a partial substitute for language-level safety guarantees, but require ecosystem commitment.**

Brakeman's existence and adoption in the Ruby/Rails ecosystem demonstrates that a mature dynamic language can achieve reasonable security assurance through static analysis tooling even without language-level type enforcement. However, Brakeman's effectiveness depends on patterns being recognizable to its AST analysis — heavily metaprogrammed code is harder to analyze. The practical lesson: where a language cannot provide security guarantees at the language level, investing in high-quality static analysis tooling is the correct ecosystem response. But tooling cannot substitute fully: it will always have false negatives on complex metaprogramming, and it is not available before the ecosystem matures.

---

## References

[ARXIV-RUBY-2025] "Unveiling Ruby: Insights from Stack Overflow and Developer Survey." arXiv:2503.19238v2. March 2025. https://arxiv.org/html/2503.19238v2

[BISHOPFOX-RUBY] Bishop Fox. "Ruby Vulnerabilities: Exploiting Open, Send, and Deserialization." https://bishopfox.com/blog/ruby-vulnerabilities-exploits

[BRAKEMAN] Brakeman. "A static analysis security tool for Ruby on Rails applications." https://brakemanscanner.org/

[BUNDLER-AUDIT] bundler-audit GitHub repository. "Patch-level verification for Bundler." https://github.com/rubysec/bundler-audit

[CVEDETAILS-RUBY] CVEDetails.com. "Ruby-lang Ruby: Security vulnerabilities, CVEs." https://www.cvedetails.com/product/12215/Ruby-lang-Ruby.html?vendor_id=7252

[RAILS-RCE-CODECLIMATE] Code Climate. "Rails' Remote Code Execution Vulnerability Explained." https://codeclimate.com/blog/rails-remote-code-execution-vulnerability-explained

[RAILS-SURVEY-2024] Planet Argon / railsdeveloper.com. "2024 Ruby on Rails Community Survey Results." https://railsdeveloper.com/survey/2024/

[REVERSINGLABS-GEMS] ReversingLabs. "Mining for malicious Ruby gems." https://www.reversinglabs.com/blog/mining-for-malicious-ruby-gems

[RUBY-3-0-RELEASE] ruby-lang.org. "Ruby 3.0.0 Released." December 25, 2020. https://www.ruby-lang.org/en/news/2020/12/25/ruby-3-0-0-released/

[RUBY-3-1-RELEASE] ruby-lang.org. "Ruby 3.1.0 Released." December 25, 2021. https://www.ruby-lang.org/en/news/2021/12/25/ruby-3-1-0-released/

[RUBY-CVE-REDOS] ruby-lang.org. "Security." Various ReDoS CVEs documented at https://www.ruby-lang.org/en/security/

[RUBY-RUBYGEMS-TRANSITION] ruby-lang.org. "The Transition of RubyGems Repository Ownership." October 17, 2025. https://www.ruby-lang.org/en/news/2025/10/17/rubygems-repository-transition/

[RUBY-SECURITY] ruby-lang.org. "Security." https://www.ruby-lang.org/en/security/

[RUBY-TYPING-2024] Leach, B. "Ruby typing 2024: RBS, Steep, RBS Collections, subjective feelings." brandur.org. https://brandur.org/fragments/ruby-typing-2024

[SOCKET-MALICIOUS-GEMS] Socket.dev. "Malicious Ruby Gems Exfiltrate Telegram Tokens and Messages." https://socket.dev/blog/malicious-ruby-gems-exfiltrate-telegram-tokens-and-messages-following-vietnam-ban

[THN-GEMS-2025] The Hacker News. "RubyGems, PyPI Hit by Malicious Packages Stealing Credentials, Crypto." August 2025. https://thehackernews.com/2025/08/rubygems-pypi-hit-by-malicious-packages.html

[THN-TYPOSQUAT-2020] The Hacker News. "Over 700 Malicious Typosquatted Libraries Found On RubyGems Repository." April 2020. https://thehackernews.com/2020/04/rubygems-malware-packages.html
