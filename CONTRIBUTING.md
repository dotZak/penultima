# Contributing to Penultima

Penultima's deliberation is conducted primarily by AI agents, but human expertise is an invaluable source of evidence, correction, and perspective. This document describes how to participate.

## Ways to Contribute

### Report Feedback (Issues)

If you have expertise in a language and notice that a council report contains factual errors, missing evidence, or significant omissions, open an issue. Use the appropriate issue template:

- **Factual Correction** — A specific claim in a report is wrong or misleading. Include the report section, the claim, and your correction with a source.
- **Missing Evidence** — You have data (CVE patterns, benchmarks, survey results, production case studies) that a report should reference. Include the source, its relevance, and which report section it applies to.
- **Missing Perspective** — A report overlooks something important about a language. Describe what's missing and why it matters for Penultima's design goals.
- **Tier Reclassification** — You believe a language is in the wrong tier. State the language, the proposed tier, and your reasoning.

### Broader Discussion (Discussions)

For conversations that don't fit neatly into a single issue:

- Methodology questions or suggestions
- Language tier assignment debates
- Design philosophy discussions
- Process improvement proposals

### Evidence Contributions (Pull Requests)

If you have data suitable for the shared evidence repository (`evidence/`), submit a pull request with:

- The data in a structured format (CSV, JSON, or markdown)
- A README describing the source, methodology, and limitations
- Date of collection and any known biases

### Wiki

The wiki serves as a community knowledge base for supplementary context that doesn't belong in the formal reports: reading lists, historical context, links to relevant research, and community-contributed explainers.

## Guidelines

- **Evidence over opinion.** This project values empirical grounding. If you make a claim, cite a source. If you disagree with a report's assessment, provide evidence for an alternative view.
- **Good faith.** Every language has strengths and weaknesses. The goal is pragmatic assessment, not advocacy or demolition.
- **Scope.** Contributions should be relevant to Penultima's goal of designing a better-informed programming language. General language war debates belong elsewhere.
- **Respect the schema.** Reports follow a versioned common schema (`schema/common-report-schema.md`). If you think the schema is missing something, open an issue proposing an amendment rather than working around it.

## Code of Conduct

[TBD — to be established before public launch.]
