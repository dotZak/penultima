# Cross-Language Developer Survey Aggregation
## PHP, C, Mojo, and COBOL Analysis

**Document Date:** February 2026
**Survey Data Coverage:** 2024–2025

---

## Executive Summary

This document aggregates data from major developer surveys to establish baseline statistics for four pilot programming languages: PHP, C, Mojo, and COBOL. The research synthesizes findings from the Stack Overflow Annual Developer Surveys (2024–2025), JetBrains Developer Ecosystem Surveys (2024–2025), State of PHP surveys, and community reports. Notable findings include PHP's mature adoption (74.5% of websites), C's fluctuating rankings despite widespread systems programming use, Mojo's nascent but rapidly growing community (175,000+ developers), and COBOL's paradoxical status as both critically important and severely under-resourced.

---

## Methodology and Limitations

### Survey Sources and Scope

This aggregation draws from three primary sources:

1. **Stack Overflow Annual Developer Survey (2024–2025)**
   - 2024: 65,000+ respondents from global developer community
   - 2025: 49,000+ respondents across 177 countries, 314 technologies
   - Platform: Primarily English-speaking, Stack Overflow user base
   - Methodology: Online questionnaire; self-selection bias inherent

2. **JetBrains State of Developer Ecosystem Survey (2024–2025)**
   - 2024: 23,262 developers after data cleaning
   - 2025: 24,534 developers across 194 countries
   - Platform: Users of JetBrains development tools
   - Methodology: Online survey with stratified sampling attempts

3. **PHP-Specific Surveys**
   - Zend/Perforce PHP Landscape Report 2025: 561 PHP professional respondents
   - JetBrains PHP subset: 2,660 PHP developers (2024), 1,720 (2025)
   - Methodology: Self-reported language identification

4. **Mojo Community Data**
   - Modular/Mojo official communications and GitHub metrics
   - No formal academic survey; community-reported figures
   - Methodology: Aggregated public metrics

### Critical Limitations

**Self-Selection Bias:** Developers who respond to surveys tend to be more engaged, better-compensated, and more likely to work with modern tooling. Enterprise COBOL shops and embedded C developers may be systematically underrepresented.

**Platform Skew:** Stack Overflow's user base skews toward web development, open-source contributors, and English-speaking developers, underrepresenting systems programming, legacy codebases, and non-English-speaking regions.

**Language vs. Primary Language:** Surveys often conflate "languages used" with "primary language." A developer might use C for 5% of their time but spend 95% in Python. Adoption percentages may be misleading without context.

**Sampling Differences:** Different surveys use different sample populations (Stack Overflow users, JetBrains tool users, self-selected PHP professionals), making direct comparison problematic.

**Absence as Silence:** The lack of COBOL or Mojo data in major surveys does not indicate irrelevance but rather reflects survey design choices and audience composition.

---

## PHP: Dominant Web Language in Maturity

### Usage and Adoption Rates

PHP demonstrates unparalleled dominance in web infrastructure despite declining perception among developers:

- **Web Server Dominance:** 74.5–77.5% of all websites with a known server-side programming language use PHP, representing over 33 million live websites
- **Developer Adoption:** 18.2% of all surveyed developers report using PHP (Stack Overflow 2024–2025); among professional developers specifically, 18.7%
- **Primary Language:** 1,720 developers identified PHP as their main programming language in JetBrains 2025; represented 2,660 in 2024

**Interpretation:** PHP's low survey adoption (18%) masks its overwhelming production dominance (74.5% of websites). This discrepancy reflects survey bias: web infrastructure developers and legacy system maintainers are underrepresented in Stack Overflow's audience, while frontend developers and newer engineers are overrepresented.

### Satisfaction and Sentiment

- **Committed User Base:** 58% of PHP developers do not plan to migrate to other languages in the next year, indicating stable satisfaction despite criticism
- **Most Loved/Dreaded Status:** PHP does not appear in Stack Overflow's "most loved" top rankings; classified as "stable but mature" in JetBrains 2025 ("PHP remains a stable, professional, and evolving ecosystem" despite long-term decline classification)
- **Maturity Classification:** JetBrains identifies PHP as in "long-term decline" alongside Ruby and Objective-C, but the categorization reflects adoption trends rather than satisfaction

### Salary Data

- **Average Base Salary (U.S.):** $102,144 per year
- **Range:** $102,302–$134,253 depending on experience level
- **Hourly Rate:** $49 average
- **Annual Range:** $50,000–$120,000+ depending on experience and industry

PHP developer compensation is moderate, lower than Python ($112,504 average) but competitive with web-stack languages.

### Developer Demographics and Experience

- **Experience Distribution:** 88% of PHP developers have more than three years of experience; largest cohort falls in 6–10 year range
- **Team Size:** 56% work in teams of 2–7 people; 12% work independently
- **Age Profile:** PHP developer base skews toward experienced practitioners rather than beginners

### AI Tool Adoption

- **Overall Adoption:** 95% of PHP developers have tried at least one AI tool
- **Regular Use:** 80% regularly use AI assistants or AI-powered editors
- **Tool Preferences:** ChatGPT leads at 49% daily use, followed by GitHub Copilot (29%) and JetBrains AI Assistant (20%)

### Framework Ecosystem

- **Laravel Dominance:** 61% of PHP developers use Laravel regularly (2024 JetBrains)
- **Code Quality Tools:** PHPStan jumped to 36% adoption in 2025, up 9 percentage points from previous year

### Industry and Domain Distribution

PHP remains dominant in web development, content management systems (WordPress powers ~43% of all websites), e-commerce platforms, and rapid application development. Limited presence in systems programming, data science, or AI/ML applications.

### Trends Over Time

**Declining:** Adoption percentage among surveyed developers declining relative to Python, JavaScript, and Go; fewer new developers choosing PHP as first language.

**Stable:** Production dominance unchanged; web infrastructure dependency remains; economic migration away from PHP occurs more slowly than perceived in developer surveys.

---

## C: Systems Foundation in Flux

### Usage and Adoption Rates

C presents a complex picture of continued critical importance alongside perceived decline in developer surveys:

- **Survey Rankings Volatility:**
  - IEEE Spectrum 2024: Fell from 4th to 9th place
  - TIOBE Index February 2026: C strengthens second place with "clear rating increase"
  - Market Context: Python dominates with 26.98% market share (July 2025); C language group (C/C++) remains fundamental to systems programming, operating systems, embedded systems, and high-performance computing

- **Developer Adoption:** Limited specific data in major surveys; not listed separately in Stack Overflow's top languages (JavaScript 62%, Python 51%, TypeScript 38% in 2024)

### Salary Data

- **Average Base Salary (U.S.):** $76,304 per year
- **Compensation Context:** Lowest among the four languages examined, reflecting both the demographics of the C developer population (including lower-cost regions, embedded systems specialists) and the survey bias toward web-based development where C is underrepresented

### Industry and Domain Distribution

C remains essential in:
- Operating systems and kernels (Linux, Windows NT core, macOS)
- Embedded systems and IoT
- Financial systems (alongside COBOL)
- Database engines and system utilities
- Performance-critical applications

**Survey Gap:** These domains are underrepresented in Stack Overflow's typical respondent profile (web developers, full-stack engineers).

### Trends Over Time

**Paradox:** C ranks low in developer preference surveys but maintains or increases in language popularity metrics (TIOBE). Explanation: C is not a choice but a necessity in systems programming; new developers choose Python or JavaScript, but C remains irreplaceable in infrastructure layers.

### Data Absence

Stack Overflow 2024–2025 and JetBrains surveys do not provide specific C language statistics for "most loved," "most dreaded," satisfaction ratings, or demographic breakdowns. This absence reflects audience composition (web developers) rather than C's actual usage in production systems.

---

## Mojo: Emerging AI-Focused Language

### Usage and Adoption Rates

Mojo represents a post-launch phase of rapid community growth without yet achieving mainstream adoption:

- **Community Size:** 175,000+ developers reported by Modular (as of 2025)
- **GitHub Metrics:** 23,000+ GitHub stars; 22,000+ community members
- **Code Volume:** 750,000+ lines of open-source code
- **Survey Representation:** Absent from Stack Overflow 2024–2025 and JetBrains Developer Ecosystem surveys; not established enough for inclusion in major developer population studies

### Developer Motivation and Use Cases

- **Primary Focus:** AI and machine learning development; positioned as a "high-performance Python for AI" language
- **Community Engagement:** Active digital and in-person meetups; user-contributed improvements prominent (e.g., version 24.4 release highlighted community contributions)
- **Project Scale:** Community members building "larger projects" with Mojo but still in exploratory phase

### Demographic Profile

- **Experience Level:** Early adopters include experienced Python developers, AI/ML specialists, and language enthusiasts
- **Geography:** Global community with particular engagement from AI-focused development regions
- **Age/Experience:** No survey data; community composition likely skews toward engineers comfortable with bleeding-edge tools

### Trends and Growth Trajectory

**Growth Phase:** Mojo is in the rapid early-adoption phase. Community grew from near-zero in 2022 to 175,000 developers by 2025, suggesting strong network effects and interest in AI-native language design.

**Challenges:** Limited third-party library ecosystem, smaller community relative to Python, fewer tutorials and Stack Overflow resources compared to established languages.

**Future Positioning:** Mojo lacks sufficient maturity for enterprise adoption data but shows strong signals for continued growth in AI/ML domain.

### Salary and Industry Data

No survey data available. Compensation likely aligned with AI/ML developer salaries ($130,000–$180,000+ in U.S., 2025) given target audience, but this is extrapolation rather than measured data.

---

## COBOL: The Persistent Paradox

### Usage and Adoption Rates

COBOL presents the starkest contrast between critical production importance and minimal developer survey representation:

- **Code Volume:** 775–850 billion lines of COBOL in daily use worldwide (Micro Focus estimate)
- **Business Criticality:** 70% of global financial transactions execute on COBOL systems; 92% of surveyed organizations regard COBOL as strategic technology
- **Survey Representation:** **Absent from Stack Overflow 2024–2025 and JetBrains 2024–2025 surveys**
- **Popularity Rankings:** TIOBE Index: Consistently ranked ~20th most popular language by internet traffic; never left index despite minimal web presence

### Developer Demographics and Supply Crisis

- **Age Profile:** Average age of COBOL programmer estimated at 55 years (2014); no current data available but demographic cohort aging continuously
- **Decline Rate:** Gartner 2004 estimated ~2 million COBOL programmers worldwide with 5% annual decline; no recent global census exists
- **Educational Void:** 70% of universities do not include COBOL in computer science curriculum (2013 survey; current data unavailable)

**Crisis Assessment:** COBOL faces a severe developer shortage. Replacement programmers are not being trained, while systems remain critical. Salary premiums for COBOL expertise exist in market but are not captured in standard surveys.

### Industry and Domain Distribution

COBOL is exclusively enterprise-focused:
- Financial services (banking, insurance, investment)
- Government and public sector (tax systems, social security)
- Utility companies (billing, metering systems)
- Telecommunications

No presence in startups, open-source projects, educational use, or web development.

### Salary Data

**Not available in major surveys.** Anecdotal reports suggest COBOL expertise commands premium compensation (estimated $80,000–$150,000+ for experienced developers in U.S., driven by scarcity and business-critical nature), but this is not quantified in systematic developer surveys.

### Trends Over Time

**Declining:** New COBOL programmer supply is critically low. Systems remain in production indefinitely due to rewrite costs (billions invested in legacy systems remain cheaper than replacement). Modernization efforts (e.g., rewriting in Java, Python) proceed slowly. Net trend: code volume stable; developer population declining by estimated 5% annually or higher; average age increasing.

### Data Absence Interpretation

COBOL's absence from Stack Overflow and JetBrains surveys reflects methodology: these platforms survey engaged developers on modern platforms (web, open-source). Enterprise COBOL shops operate internal systems with limited Stack Overflow participation or external tool dependency. **Absence indicates platform limitation, not irrelevance.**

---

## Cross-Language Comparison Matrix

| Metric | PHP | C | Mojo | COBOL |
|--------|-----|---|------|-------|
| **Survey Representation** | High (18.2%) | Low/Absent | Absent | Absent |
| **Production Dominance** | Very High (74.5% websites) | High (systems infrastructure) | Emerging | Very High (70% financial) |
| **Developer Supply** | Stable | Stable | Growing | Declining |
| **Average Salary (U.S.)** | $102,144 | $76,304 | Unknown | Unknown (estimated premium) |
| **Satisfaction Trend** | Stable/Declining perception | Paradox: low surveys, high importance | High (early adopters) | Not measured |
| **Maturity Stage** | Mature/Stable | Mature/Foundational | Early Adoption | Mature/Legacy |
| **Community Size** | Large (millions) | Large (systems) | 175,000+ | Unknown (thousands) |
| **AI Tool Adoption** | 95% tried, 80% regular use | Not measured | Central feature | Not measured |
| **Primary Use Domain** | Web development | Systems/embedded/infrastructure | AI/ML | Enterprise financial/government |

---

## Key Findings and Interpretations

### 1. Survey Bias Distorts Perception
The four languages occupy radically different ecological niches, but major developer surveys capture only a narrow slice of actual production use. PHP dominates web infrastructure despite low survey salience; COBOL remains critical in finance despite zero survey presence; C remains fundamental despite ranking declines in developer preference surveys.

### 2. "Primary Language" vs. "Languages Used" Distinction
Survey aggregation reveals a critical methodological issue: developers report different things depending on question framing. PHP shows 18.2% adoption among "developers using PHP" but 74.5% dominance among "websites powered by PHP." These measure different phenomena.

### 3. Demographic Skew Favors Web and Open Source
All major surveys overrepresent web developers, open-source contributors, and English-speaking regions. Systems programming (C), enterprise platforms (COBOL), and emerging AI platforms (Mojo) are underrepresented or invisible.

### 4. Economic Incentives and Labor Market Reality
Salary data reveals C developers earn least despite foundational importance, suggesting survey-based compensation data reflects demand in surveyed domains (web) rather than broader labor markets. COBOL likely commands premiums in enterprise markets but is unmeasured.

### 5. Mojo Represents Emerging Paradigm Shift
Mojo's rapid adoption by AI developers signals language preferences shifting toward domain-specific design (high-performance Python for AI) rather than general-purpose tools. First survey appearance will arrive in 2026–2027 surveys.

### 6. COBOL's Persistent Invisibility Is a Measurement Problem
COBOL's absence from surveys is not evidence of irrelevance but of incompatible measurement methodologies. Enterprise systems remain economically critical and increasingly difficult to staff.

---

## Recommendations for Future Survey Design

To improve cross-language aggregation:

1. **Oversampling:** Explicitly sample from enterprise domains (financial services, government, telecommunications) where C and COBOL dominance is absolute
2. **Company-Level Data:** Aggregate language use by examining deployed systems rather than surveying developers alone
3. **Distinction Clarity:** Separate questions for "primary language," "languages used," and "languages known" to eliminate ambiguity
4. **Domain Breakdown:** Report language statistics by industry vertical, not in aggregate
5. **Salary Calibration:** Separate compensation data by domain (web development, systems programming, enterprise finance) to prevent averaging incomparable markets
6. **Emerging Language Tracking:** Include Mojo and other post-2020 languages starting in 2026 surveys to capture adoption while adoptions are trackable

---

## Sources Cited

- [Stack Overflow Annual Developer Survey 2024](https://survey.stackoverflow.co/2024/)
- [Stack Overflow Annual Developer Survey 2025](https://survey.stackoverflow.co/2025/)
- [Stack Overflow Blog: 2024 Survey Results](https://stackoverflow.blog/2025/01/01/developers-want-more-more-more-the-2024-results-from-stack-overflow-s-annual-developer-survey/)
- [JetBrains State of Developer Ecosystem 2024](https://www.jetbrains.com/lp/devecosystem-2024/)
- [JetBrains State of Developer Ecosystem 2025](https://devecosystem-2025.jetbrains.com/)
- [JetBrains Blog: State of Developer Ecosystem 2025](https://blog.jetbrains.com/research/2025/10/state-of-developer-ecosystem-2025/)
- [JetBrains: The State of PHP 2024](https://blog.jetbrains.com/phpstorm/2025/02/state-of-php-2024/)
- [JetBrains: The State of PHP 2025](https://blog.jetbrains.com/phpstorm/2025/10/state-of-php-2025/)
- [Zend PHP Landscape Report 2025](https://www.zend.com/resources/php-landscape-report)
- [Zend PHP Usage Trends 2025](https://www.zend.com/blog/php-usage-trends)
- [Modular Mojo Programming Language](https://www.modular.com/mojo)
- [TIOBE Index February 2026](https://www.tiobe.com/tiobe-index/)
- [IEEE Spectrum Top Programming Languages 2024](https://spectrum.ieee.org/top-programming-languages-2024)
- [The Register: JetBrains 2025 Survey Analysis](https://www.theregister.com/2025/10/21/massive_jetbrains_dev_survey/)
- [HackerRank Blog: The Inevitable Return of COBOL](https://pages.hackerrank.com/blog/the-inevitable-return-of-cobol)
- [VentureBeat: Best-Paid Programming Languages 2025](https://venturebeat.com/programming-development/these-are-the-best-paid-programming-languages-for-2025/)

---

**Document Version:** 1.0
**Prepared:** February 2026
**Data Coverage:** 2024–2025 survey cycles
**Word Count:** ~1,400 words
