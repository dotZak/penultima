# Penultima

**A living programming language informed by collective intelligence.**

Every programming language is an artifact of its moment — shaped by the hardware constraints, theoretical understanding, and practical needs of the era in which it was conceived. More critically, every language is shaped by the limitations of its creators: brilliant individuals who cannot hold the entire state of the art in their heads simultaneously. The result is a landscape of languages that each embody genuine insights alongside blind spots, elegant solutions adjacent to regrettable compromises.

Penultima is an attempt to change the process by which languages are designed. Rather than relying on a small team's intuitions, Penultima is informed by a structured deliberation conducted by specialized AI agents — each an expert advocate, realist, or critic for a specific programming language — synthesizing decades of evidence from CVE databases, developer surveys, type system research, and production postmortems into a coherent set of design principles.

The name reflects the philosophy: *penultima*, the second to last. There will always be a next language, a next insight, a next generation of evidence. Penultima's contribution is not to be the final word, but to be the first language designed with all the words that came before it.

## How It Works

The project proceeds in seven phases:

1. **Schema Design** — Define the common report structure that all analysis documents follow ([schema/](schema/))
2. **Internal Deliberation** — Each language council (five AI agents per language) produces a consensus report
3. **Relevance Negotiation** — Councils identify which cross-reviews will produce the most signal
4. **Cross-Review** — Each council reviews other languages from its own perspective
5. **Response and Integration** — Each council responds to cross-reviews of its language
6. **Synthesis** — A dedicated council distills patterns across all reports into design principles
7. **Language Design** — Penultima is specified, informed by the full deliberation corpus

For the full rationale, process description, and governance structure, see the [whitepaper](docs/penultima-whitepaper.docx).

## Repository Structure

```
penultima/
├── docs/                           # Project documents
│   └── penultima-whitepaper.docx   # Founding whitepaper
│
├── schema/                         # Report schema and versioning
│   └── common-report-schema.md     # v1.0 — the template all reports follow
│
├── research/
│   ├── tier1/                      # Full council treatment (25 languages)
│   │   └── <language>/
│   │       ├── council/            # Individual agent perspectives
│   │       │   ├── apologist.md
│   │       │   ├── realist.md
│   │       │   ├── detractor.md
│   │       │   ├── historian.md
│   │       │   └── practitioner.md
│   │       ├── advisors/           # Cross-cutting advisor input
│   │       │   ├── compiler-runtime.md
│   │       │   ├── security.md
│   │       │   ├── pedagogy.md
│   │       │   └── systems-architecture.md
│   │       ├── report.md           # Consensus internal report (Phase 2)
│   │       ├── relevance.md        # Relevance statement (Phase 3)
│   │       ├── cross-reviews/      # Reviews BY other councils (Phase 4)
│   │       │   └── from-<language>.md
│   │       └── response.md         # Integrative response (Phase 5)
│   │
│   ├── tier2/                      # Condensed single-analyst reports
│   │   └── <language>.md
│   │
│   ├── tier3/                      # Honorable mentions
│   │   └── <language>.md
│   │
│   └── synthesis/                  # Phase 6 outputs
│       ├── mission-statement.md
│       ├── design-principles.md
│       └── pattern-analysis/
│
├── evidence/                       # Shared evidence repository
│   ├── cve-data/                   # Vulnerability pattern data
│   ├── surveys/                    # Developer survey aggregations
│   └── benchmarks/                 # Performance benchmark collections
│
├── governance/                     # Governance charters and processes
│
└── templates/                      # Document templates
    ├── tier1/
    │   ├── internal-report.md      # Template for Phase 2 consensus reports
    │   ├── cross-review.md         # Template for Phase 4 cross-reviews
    │   └── response.md             # Template for Phase 5 responses
    ├── tier2/
    │   └── condensed-report.md     # Template for Tier 2 analyses
    └── tier3/
        └── honorable-mention.md    # Template for Tier 3 entries
```

## Language Tiers

**Tier 1** — Full five-agent council, cross-review participation, and integrative response. Languages with large production footprints or genuinely distinct design philosophies. *List to be finalized.*

**Tier 2** — Single-analyst condensed report. Languages that contributed important ideas or are historically significant. *List to be finalized.*

**Tier 3** — Brief honorable mention. Esoteric, academic, or hobby languages offering at least one notable insight. *List to be finalized.*

## Contributing

This project is conducted primarily by AI agents, but human commentary is welcomed and valued. If you have expertise in a particular language and want to contribute perspective, evidence, or corrections:

- **Issues** — Use issue templates to provide feedback on specific language reports, suggest evidence sources, or flag inaccuracies
- **Discussions** — Broader conversations about methodology, language tier assignments, or design philosophy
- **Wiki** — Community knowledge base for supplementary resources, reading lists, and context

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Status

🔧 **Phase 0: Infrastructure** — Establishing the repository structure, report schema, and process documentation. Language councils have not yet been formed.

## License

[TBD]
