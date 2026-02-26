# Agent Orchestration Guide

This document describes how to run the language council agents using Claude Code.

## Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed and authenticated
- This repository cloned locally
- Evidence repository seeded for the target language (see `evidence/`)

## Architecture

Each language council's Phase 2 analysis runs in four stages:

```
Stage 0.5: Researcher (sequential, runs first)
  └── researcher → research-brief.md

Stage 1: Council Members (parallel, after Stage 0.5)
  ├── apologist
  ├── realist
  ├── detractor
  ├── historian
  └── practitioner

Stage 2: Advisors (parallel, after Stage 1)
  ├── compiler-runtime
  ├── security
  ├── pedagogy
  └── systems-architecture

Stage 3: Consensus (after Stage 2)
  └── consensus agent → report.md
```

**Stage 0.5** produces a factual research brief — a shared baseline of facts, data, and citations with no interpretation. This prevents the five council members from redundantly researching the same facts and ensures they all work from the same evidence.

**Stage 1** runs five council members in parallel. Each reads the research brief and the evidence files, then writes their perspective. They do not read each other's output.

**Stage 2** runs four advisors in parallel. Each reads all five council member perspectives plus the research brief, and produces a specialist review focusing on their domain.

**Stage 3** runs the consensus agent, which reads all nine inputs (5 council + 4 advisors) and synthesizes them into the final report.

## Running a Council

### Quick Start

```bash
./run-council.sh PHP php
```

The script handles all four stages, progress reporting, output verification, and retry on failure.

### Pilot Languages

| Language | Command |
|----------|---------|
| PHP      | `./run-council.sh PHP php` |
| C        | `./run-council.sh C c` |
| Mojo     | `./run-council.sh Mojo mojo` |
| COBOL    | `./run-council.sh COBOL cobol` |

### Running All Pilots

Sequentially:
```bash
for pair in "PHP php" "C c" "Mojo mojo" "COBOL cobol"; do
  set -- $pair
  ./run-council.sh "$1" "$2"
done
```

In parallel (resource-intensive — up to 20+ concurrent Claude agents):
```bash
./run-council.sh PHP php &
./run-council.sh C c &
./run-council.sh Mojo mojo &
./run-council.sh COBOL cobol &
wait
echo "All pilot language councils complete"
```

## Script Features

### Progress Reporting

The script displays colored progress output with stage headers, per-agent start/completion status, elapsed time per stage and total, and a final output verification with word counts.

### Token Limit Recovery

If an agent hits the context window limit, the script automatically retries with a continuation prompt that instructs the agent to read its partial output and complete the remaining sections. Each agent gets up to 3 attempts (1 initial + 2 retries).

### Research Brief Caching

Stage 0.5 checks whether a research brief already exists. If it does, the stage is skipped. Delete the file to force regeneration:

```bash
rm research/tier1/php/research-brief.md
```

### Logging

All agent output is captured in `logs/<language>/`:

```
logs/php/
├── researcher.log
├── apologist.log
├── realist.log
├── detractor.log
├── historian.log
├── practitioner.log
├── compiler-runtime.log
├── security.log
├── pedagogy.log
├── systems-architecture.log
└── consensus.log
```

## Expected Output

After a successful run:

```
research/tier1/<lang>/
├── research-brief.md          ← Stage 0.5
├── council/
│   ├── apologist.md           ← Stage 1
│   ├── realist.md             ← Stage 1
│   ├── detractor.md           ← Stage 1
│   ├── historian.md           ← Stage 1
│   └── practitioner.md        ← Stage 1
├── advisors/
│   ├── compiler-runtime.md    ← Stage 2
│   ├── security.md            ← Stage 2
│   ├── pedagogy.md            ← Stage 2
│   └── systems-architecture.md ← Stage 2
└── report.md                  ← Stage 3
```

## Agent Files

| File | Stage | Role |
|------|-------|------|
| `agents/researcher.md` | 0.5 | Produces factual research brief with no interpretation |
| `agents/council/apologist.md` | 1 | Best possible case for the language |
| `agents/council/realist.md` | 1 | Balanced, dispassionate assessment |
| `agents/council/detractor.md` | 1 | Rigorous critique of weaknesses |
| `agents/council/historian.md` | 1 | Historical context for design decisions |
| `agents/council/practitioner.md` | 1 | Production experience perspective |
| `agents/advisors/compiler-runtime.md` | 2 | Verifies compiler/runtime claims |
| `agents/advisors/security.md` | 2 | Verifies security claims against CVE data |
| `agents/advisors/pedagogy.md` | 2 | Evaluates learnability and cognitive load |
| `agents/advisors/systems-architecture.md` | 2 | Assesses scalability and production concerns |
| `agents/consensus.md` | 3 | Synthesizes all inputs into final report |
| `agents/base-context.md` | — | Shared context read by all agents |

## Troubleshooting

**Agent doesn't write to the correct path:** Check that `LANG_SLUG` matches the directory name and that directories were created (the script handles this automatically).

**Agent produces thin or generic content:** Check that the evidence files exist in `evidence/` and that the research brief was generated successfully — council members depend on it.

**Agent hits token limit:** The script retries automatically. If it still fails, check whether the research brief is unusually long or whether the language has very extensive evidence files.

**Stage 2 agents can't find Stage 1 output:** The script waits for all Stage 1 processes before starting Stage 2. If running manually, ensure the `wait` command is used.

**Research brief already exists but is outdated:** Delete it to regenerate: `rm research/tier1/<lang>/research-brief.md`

## Cost Estimation

Each researcher agent uses approximately 20,000–40,000 output tokens. Each council member uses 10,000–30,000. Each advisor uses 5,000–15,000. The consensus agent uses 15,000–40,000. For one language, expect roughly 120,000–300,000 total output tokens across all 11 agents.

For four pilot languages, budget approximately 500,000–1,200,000 output tokens.
