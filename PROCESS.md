# Penultima Process Guide

**Version:** 1.0
**Status:** Draft

This document maps the seven deliberation phases onto GitHub's collaboration infrastructure. It describes how each phase produces artifacts, where work happens, and how progress is tracked.

For what gets produced, see `schema/common-report-schema.md`. For how documents are structured, see `templates/`. This document covers the mechanics of how work moves through the system.

---

## Labels

The following label taxonomy is used across issues, PRs, and discussions.

### Phase Labels

- `phase:1-schema` — Schema design and council formation
- `phase:2-deliberation` — Internal council reports
- `phase:3-relevance` — Relevance negotiation
- `phase:4-cross-review` — Cross-review documents
- `phase:5-response` — Integrative responses
- `phase:6-synthesis` — Pattern analysis and design principles
- `phase:7-design` — Language specification

### Role Labels

- `role:apologist`
- `role:realist`
- `role:detractor`
- `role:historian`
- `role:practitioner`
- `advisor:compiler-runtime`
- `advisor:security`
- `advisor:pedagogy`
- `advisor:systems-architecture`
- `council:synthesis`

### Type Labels

- `type:report` — A deliverable document
- `type:review` — Advisor or cross-review feedback
- `type:deadlock` — Unresolved council disagreement
- `type:gap` — Missing analysis identified by synthesis
- `type:evidence` — New data for the evidence repository
- `type:schema-amendment` — Proposed change to the report schema
- `type:human-feedback` — Commentary from human contributors

### Language Labels

One label per Tier 1 language (e.g., `lang:rust`, `lang:python`, `lang:c`). Created when language lists are finalized.

### Tier Labels

- `tier:1`
- `tier:2`
- `tier:3`

---

## Milestones

Each phase is a milestone. Progress is tracked by the ratio of closed to open issues and merged to open PRs within each milestone.

- **Phase 1: Schema and Formation**
- **Phase 2: Internal Deliberation**
- **Phase 3: Relevance Negotiation**
- **Phase 4: Cross-Review**
- **Phase 5: Response and Integration**
- **Phase 6: Synthesis**
- **Phase 7: Language Design**

---

## Phase 1: Schema Design and Council Formation

### Where it happens

- **Schema work:** PRs against `schema/common-report-schema.md`
- **Council formation:** Issues tagged `phase:1-schema`
- **Tier assignment discussions:** Discussions category "Language Tiers"

### Artifacts

- Finalized common report schema (merged to `main`)
- Tier 1, 2, and 3 language lists (captured in README and as label sets)
- Agent assignments per council (tracked in an issue or project board)

### Completion criteria

Schema is merged, language lists are finalized, all councils are formed.

---

## Phase 2: Internal Deliberation

### Where it happens

- **Individual agent work:** Each agent writes to their file in `research/tier1/<language>/council/`. Work happens on feature branches.
- **Advisor input:** Advisors write to `research/tier1/<language>/advisors/`. May happen on the same branch or separate branches.
- **Consensus formation:** The council produces `research/tier1/<language>/report.md`.
- **Quality gate:** The complete set of files (individual perspectives + advisor input + consensus report) is submitted as a single PR.

### Pull request process

1. A branch is created: `phase2/<language>` (e.g., `phase2/rust`).
2. Council agents produce their individual files and the consensus report.
3. A PR is opened with labels `phase:2-deliberation`, `type:report`, and the relevant `lang:` label.
4. Cross-cutting advisors review the PR. Each advisor reviews the sections within their domain:
   - **Compiler/runtime:** Sections 3 (Memory), 4 (Concurrency), 9 (Performance)
   - **Security:** Section 7 (Security Profile), plus security-relevant claims in other sections
   - **Pedagogy:** Section 8 (Developer Experience), plus learnability/cognitive load claims elsewhere
   - **Systems architecture:** Section 6 (Ecosystem), Section 10 (Interoperability), Section 11 (Governance)
5. Advisors leave PR review comments. The council revises.
6. When all advisors approve, the PR is merged.

### Anti-bias rotation

After the PR is opened but before advisor review, a randomly assigned council member is tagged on the PR with a request to red-team their own report. Their red-team comments are added as a PR review.

### Deadlocks

If the council cannot reach consensus on a point, the dissenting view is included in the report (per the schema) and a separate issue is opened:
- Labels: `type:deadlock`, `phase:2-deliberation`, relevant `lang:` and `role:` labels
- Body: The two positions, each with supporting evidence
- Assigned to milestone "Phase 6: Synthesis"

### Tier 2 and Tier 3

Tier 2 reports follow the same PR process but with a single analyst and no advisor review gate. Tier 3 entries can be batched into a single PR.

---

## Phase 3: Relevance Negotiation

### Where it happens

- **Discussions**, category "Relevance Negotiation"
- One Discussion thread per Tier 1 language: "Relevance Negotiation: [Language]"

### Process

1. Each council posts a comment in their language's thread containing their relevance statement (using the template in `schema/common-report-schema.md`, Appendix C):
   - Languages they intend to review (outbound)
   - Languages whose review they'd value (inbound requests)
   - Languages they declare low-relevance for
2. Councils check *other* languages' threads for inbound requests directed at them.
3. If a council receives an inbound request it didn't plan for, it responds in-thread: either accepting with rationale or declining with explanation.
4. After one negotiation round, each council updates their relevance statement as a final comment in their thread.
5. The finalized relevance statement is committed as `research/tier1/<language>/relevance.md`.

### Why Discussions, not Issues

The relevance negotiation is a conversation, not a task to be closed. The thread history — who wanted what, who declined, who was surprised — is itself valuable data for the synthesis phase. Discussions preserve this naturally.

---

## Phase 4: Cross-Review

### Where it happens

- **PRs** to `research/tier1/<target-language>/cross-reviews/`
- Branch naming: `phase4/<reviewer>-reviews-<target>` (e.g., `phase4/rust-reviews-cpp`)

### Process

1. Each council creates cross-review documents for the languages identified in Phase 3.
2. Each cross-review is filed as `research/tier1/<target-language>/cross-reviews/from-<reviewer>.md`.
3. PRs are opened with labels `phase:4-cross-review`, both `lang:` labels (reviewer and target), and `type:review`.
4. Cross-cutting advisors do a lighter review than Phase 2 — checking for evidence standards compliance and flagging claims that lack citations. They are not gatekeepers on opinion, only on rigor.
5. Merged when evidence standards are met.

### Volume management

With up to 600 cross-reviews, PRs should be batched where practical. A council reviewing multiple languages can submit a batch PR covering all its outbound reviews, or group them by affinity.

---

## Phase 5: Response and Integration

### Where it happens

- **PRs** to `research/tier1/<language>/response.md`
- Branch naming: `phase5/<language>` (e.g., `phase5/rust`)

### Process

1. Each council reads all cross-reviews in `research/tier1/<language>/cross-reviews/`.
2. The council produces `research/tier1/<language>/response.md` using the integrative response template.
3. A PR is opened with labels `phase:5-response`, `type:report`, and the relevant `lang:` label.
4. Advisor review is optional at this stage — the primary quality control is internal to the council.
5. Merged when complete.

---

## Phase 6: Synthesis

### Where it happens

- **PRs** to `research/synthesis/`
- **Issues** for gap identification and follow-up requests
- Branch naming: `phase6/synthesis`

### Process

1. The Synthesis Council (cross-cutting advisors + generalist agents) reads:
   - All merged Tier 1 internal reports
   - All merged cross-reviews
   - All merged integrative responses
   - All open `type:deadlock` issues
   - Tier 2 and Tier 3 reports
   - Relevance negotiation threads
   - Human feedback (issues tagged `type:human-feedback`)
2. The Synthesis Council produces:
   - `research/synthesis/mission-statement.md`
   - `research/synthesis/design-principles.md`
   - Pattern analysis documents in `research/synthesis/pattern-analysis/`
3. These are submitted as a PR with labels `phase:6-synthesis`, `council:synthesis`.

### Gap identification

If the Synthesis Council identifies gaps — areas no council adequately addressed — it opens issues:
- Labels: `type:gap`, `phase:6-synthesis`, relevant `lang:` labels
- Body: The gap, why it matters, and which council(s) should address it
- These are assigned back to the relevant councils for targeted follow-up, which are submitted as additional PRs

### Deadlock resolution

The Synthesis Council reviews all open `type:deadlock` issues and posts its adjudication as a comment. The issue is then closed with a resolution label (`resolved:position-a`, `resolved:position-b`, `resolved:compromise`, or `resolved:deferred`).

---

## Phase 7: Language Design

### Where it happens

- New directory structure (TBD — likely `spec/`, `reference/`, `tooling/`)
- **Issues** for design decisions
- **PRs** for specification work
- **Discussions** category "Language Design" for open-ended design conversations

### Process

This phase is governed by the Steering Council, Technical Design Authority, and RFC process described in the whitepaper. Detailed process to be specified before Phase 7 begins.

---

## Cross-Phase Processes

### Human Feedback

Human contributors can participate at any phase. Their input enters the system through:

- **Issues** tagged `type:human-feedback` and the relevant phase/language labels
- **PR reviews** on any open PR (human review comments are treated as additional evidence)
- **Discussion threads** in any active Discussion

The Synthesis Council is required to review all `type:human-feedback` issues as part of Phase 6.

### Schema Amendments

At any point during the deliberation, a council or advisor may propose a schema amendment:

1. Open an issue with label `type:schema-amendment`.
2. The cross-cutting advisors review the proposal.
3. If accepted, a PR is opened against `schema/common-report-schema.md` with the version incremented.
4. Existing reports are assessed for compliance. If updates are needed, new issues are opened and assigned to the relevant councils.

### Evidence Repository Updates

New evidence (CVE data, survey results, benchmarks) can be added at any time via PRs to `evidence/`. Each PR must include:
- The data in a structured format
- A README or frontmatter describing source, methodology, and limitations
- Date of collection

The wiki provides human-readable context for interpreting evidence.

---

## Project Board

A GitHub Project board provides a high-level view of progress:

- **Columns:** One per phase (Phase 1 through Phase 7)
- **Cards:** One per language (Tier 1), grouped by current phase
- **Automation:** Cards move columns when associated milestone issues are closed or PRs are merged

This gives a glanceable answer to "where is each language in the process?"

---

## Branch Strategy

- `main` — Merged, reviewed documents only. Represents the current state of the deliberation.
- `phase2/<language>` — Internal deliberation work for a specific language.
- `phase4/<reviewer>-reviews-<target>` — Cross-review work.
- `phase5/<language>` — Integrative response work.
- `phase6/synthesis` — Synthesis work.

Feature branches are deleted after merge. The full history is preserved in the git log and PR history.
