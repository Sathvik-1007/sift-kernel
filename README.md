# SIFT Kernel

**Forensic Evidence Operating System** — An MCP server that makes evidence spoliation architecturally impossible, hallucinations structurally unregisterable, and forensic methodology computationally enforced.

Built for the [FIND EVIL! Hackathon](https://findevil.devpost.com/) by SANS Institute.

---

## Results

| Metric | Value |
|--------|-------|
| Forensic operations | **129** across 14 categories (+ 21 reporting/kernel tools) |
| Reasoning engine (FARE) | **DSmT/PCR5 evidence fusion + Active Inference (EFE) tool selection + Rough-set confidence tiers** |
| Knowledge base | **90 evidence-to-hypothesis rules** across 7 artifact categories, 12 attack scenarios |
| Auto-correlation | **Temporal proximity + MITRE kill-chain sequencing + shared entity detection** |
| Formal security properties | **6** (property-tested, 10,000 scenarios each) |
| Context overload solved | **32 tools** exposed (14 category dispatchers + 18 kernel) — not 128 flat |
| Hallucination rate | **0%** by construction (findings require evidence links + deterministic verification) |
| Methodology enforcement | Signal-driven reactive FSM (7 states) + capability DAG |
| Self-correction | External-feedback architecture (arXiv:2601.00828) — FARE conflict detection, entropy tracking, bias monitoring |
| Inference constraint | Level 3-4 per Hilgert et al. 2025 (arXiv:2506.00274) — server handles parsing + anomaly detection |
| Report formats | Markdown, JSON, **interactive HTML** (entropy curve SVG, dark/light toggle, correlation timeline) |
| Transports | stdio + HTTP/SSE (fail-closed bearer auth) |
| Tested against | Real 16GB SRL-2018 E01 disk image (APT compromise) |

---

## SUBMISSION COMPLIANCE

> **Judges:** Every turn-in requirement maps to a specific file. Nothing is hidden.

| # | Requirement | Location | Status |
|---|-------------|----------|--------|
| 1 | Code repository (public, open source) | This repository | Done |
| 2 | Open source license (MIT or Apache 2.0) | [LICENSE](./LICENSE) | Done (MIT) |
| 3 | README with setup instructions | [README.md](./README.md) — see "Quick Start" below | Done |
| 4 | Live deployment URL or local run instructions | [README.md](./README.md) — see "Quick Start" below | Done (local) |
| 5 | Text description of features/functionality | [README.md](./README.md) — see "What It Does" + "How It Works" below | Done |
| 6 | Demo video (< 5 min, live terminal, audio, self-correction) | [docs/DEMO.md](./docs/DEMO.md) — script + link | Pending |
| 7 | Architecture diagram | [docs/architecture.md](./docs/architecture.md) | Done |
| 8 | Evidence dataset documentation | [docs/DATASET.md](./docs/DATASET.md) | Done |
| 9 | Accuracy report | [docs/ACCURACY-REPORT.md](./docs/ACCURACY-REPORT.md) | Done |
| 10 | Agent execution logs | [docs/EXECUTION-LOGS.md](./docs/EXECUTION-LOGS.md) + `sift-output/ledger.db` | Done |

### Additional Documentation

| Document | Description |
|----------|-------------|
| [CLAUDE.md](./CLAUDE.md) | Agent skill file — teaches any LLM the investigation loop |
| [docs/ZERO-TRUST-ALIGNMENT.md](./docs/ZERO-TRUST-ALIGNMENT.md) | How architecture maps to Anthropic's Zero Trust for AI Agents (2026) |
| [docs/USER-GUIDE.md](./docs/USER-GUIDE.md) | Practitioner guide for forensic analysts |
| [docs/DESIGN-DECISIONS.md](./docs/DESIGN-DECISIONS.md) | Architectural choices and rationale |
| [docs/BYPASS-TESTING.md](./docs/BYPASS-TESTING.md) | Security bypass attempts and why they fail |

---

## What It Does

SIFT Kernel sits between any AI agent (Claude, GPT, Llama, etc.) and the SANS SIFT Workstation's 200+ forensic tools. It provides:

- **129 forensic operations** across 14 categories + 21 reporting tools, exposed via the Model Context Protocol (MCP)
- **Category dispatcher architecture** — agent sees 32 tools (14 forensic categories + 18 kernel), each category groups related operations
- **Capability-based security** — no shell access exists, read-only evidence mounts
- **Hash-chained evidence ledger** — every tool call cryptographically recorded
- **Confidence scoring** — findings require evidence links (hallucinations structurally blocked)
- **FARE reasoning engine** — Dempster-Shafer evidence fusion (PCR5), Active Inference (EFE) tool selection, Rough-set confidence tiers, convergence detection, cognitive bias monitoring
- **Auto-correlation** — deterministic attack chain detection via temporal proximity + MITRE kill-chain sequencing + shared entity linking
- **Self-correction architecture** — coverage gap detection, FARE conflict interrupts (K>0.3), entropy-plateau falsification injection, evidence provenance verification
- **Forensic knowledge enrichment** — every tool response includes expert caveats, corroboration suggestions, and interpretation guidance at the response level (not system prompt)
- **Determinism tracking** — measures how closely the agent follows server methodology recommendations (0.0-1.0 score)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  ANY MCP CLIENT (Claude Code, Cursor, Zed, etc.)            │
└────────────────────────────┬────────────────────────────────┘
                             │ MCP Protocol (stdio)
┌────────────────────────────▼────────────────────────────────┐
│  SIFT KERNEL                                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Category Dispatchers (14 forensic + 18 kernel = 32)   │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Meta-Cognitive Toolkit (self-correction engine)         │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Evidence Ledger (hash-chained, append-only)            │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Output Intelligence (anomaly detection)                │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Capability Kernel (DAG prerequisites, ro mounts)       │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Tool Executors (binary allowlist, shell:false)         │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────────┬────────────────────────────────┘
                             │ subprocess (shell:false)
┌────────────────────────────▼────────────────────────────────┐
│  SIFT WORKSTATION (200+ forensic binaries)                   │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Node.js 18+
- SIFT Workstation (for actual forensic tool execution)

### Install

```bash
git clone https://github.com/YOUR_USERNAME/sift-kernel.git
cd sift-kernel
npm install
```

### Run

```bash
# As MCP server (stdio transport — for Claude Code, OpenCode, etc.)
npx tsx src/index.ts --output ./investigation

# With evidence pre-loaded (optional — can also load dynamically via mount_evidence tool)
npx tsx src/index.ts --evidence /path/to/image.E01 --output ./investigation

# HTTP transport with bearer auth (for remote/multi-client access)
npx tsx src/index.ts --transport http --port 3000 --token YOUR_SECRET

# Fresh investigation (wipes prior state)
npx tsx src/index.ts --fresh --output ./investigation
```

### Connect from MCP Client

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "sift-kernel": {
      "command": "npx",
      "args": ["tsx", "/path/to/sift-kernel/src/index.ts", "--output", "/tmp/sift-output", "--fresh"],
      "env": {}
    }
  }
}
```

## How It Works

### The "Even Dumb LLMs Work" Loop

```
while (not done):
    result = call("suggest_next_action")
    call(result.tool_name, result.params)
```

Any model that can parse JSON and call a function produces a valid, methodology-correct, auditable forensic investigation. The intelligence is in the server.

### Progressive Disclosure

At session start, the agent sees **32 tools** (14 category dispatchers + 18 kernel). Each category groups related operations:

```
filesystem(operation="list_directory", path="/Users")
registry(operation="get_persistence_keys")
event_logs(operation="parse_event_log", path="/Windows/System32/winevt/Logs/Security.evtx")
```

The capability kernel still blocks out-of-order calls — methodology is enforced regardless of what the agent tries.

### FARE: Forensic Abductive Reasoning Engine

The server doesn't just run tools — it **reasons** about the investigation state using published mathematical frameworks:

| Component | Theory | What it does |
|-----------|--------|--------------|
| DSmT/PCR5 Fusion | Dezert-Smarandache (2006) | Combines contradictory tool outputs without Zadeh's paradox |
| Active Inference (EFE) | Friston (2015) | Selects the tool that maximally reduces hypothesis uncertainty |
| Rough-Set Confidence | Pawlak (1982) | Maps findings to CONFIRMED/SUPPORTED/INFERRED tiers with mathematical grounding |
| Convergence Detection | Shannon (1948) | Tracks investigation entropy; detects learning, plateau, and divergence |
| Cognitive Bias Monitoring | Kahneman & Tversky (1974) | Detects confirmation bias, anchoring, and tunnel vision in the investigation |
| Auto-Correlation | Carrier (2006) + ATT&CK | Temporal + kill-chain + entity linking across findings |

Every tool response includes the FARE state: entropy, dominant hypothesis, active signals, conflict coefficient, and bias warnings.

### Rich Investigation Directives

`suggest_next_action` returns a full forensic cognitive frame — not just "run this tool":

```json
{
  "tool": "registry",
  "operation": "get_persistence_keys",
  "directive": {
    "whatEvilLooksLike": "Entries pointing to temp dirs, random names, encoded PowerShell",
    "whatNormalLooksLike": "Chrome Update, Windows Defender, Office updaters",
    "hypothesisTested": "Has the attacker established registry-based persistence?",
    "confirmationCriteria": "Run key value points to a path containing suspicious executables",
    "ifConfirmed": "Register T1547.001 finding, advance to scheduled tasks",
    "ifAbsent": "Persistence is NOT via registry — check scheduled tasks"
  },
  "efe_score": 0.34,
  "information_gain": "EFE=0.34 (risk=0.20, ambiguity=0.14)"
}
```

The methodology engine drives the investigation — any MCP-capable LLM follows the structured directives without needing forensic domain knowledge.

### Confidence Scoring

| Level | Criteria |
|-------|----------|
| HYPOTHESIZED | 0 evidence links — investigation marker only |
| INFERRED | 1 evidence source |
| SUPPORTED | 2+ sources, same category |
| CONFIRMED | 2+ sources, different categories |

Findings cannot appear in the final report without evidence links. Hallucinations are structurally impossible.

### Evidence Ledger

Every tool call produces a hash-chained ledger entry:
- Tool name + parameters
- Output hash (SHA-256)
- Previous entry hash (tamper detection)
- Capabilities held at time of execution
- Duration

Run `verify_chain` to cryptographically validate the entire audit trail.

## Workflows (15)

| # | Workflow | Tools | Description |
|---|----------|-------|-------------|
| 1 | Acquisition | 5 | Mount, verify, partition discovery |
| 2 | Filesystem | 9 | Directory listing, file extraction, deleted recovery |
| 3 | Timeline | 6 | Super timeline, filtering, anomaly detection |
| 4 | Registry | 9 | Hives, persistence, user activity, USB |
| 5 | Event Logs | 8 | EVTX, logon correlation, PowerShell |
| 6 | Execution | 7 | Prefetch, Amcache, ShimCache, SRUM |
| 7 | Persistence | 9 | YARA, scheduled tasks, WMI, BITS |
| 8 | Memory | 11 | Processes, injection, rootkits, network |
| 9 | Network | 8 | PCAP, beaconing, DNS, HTTP |
| 10 | Browser | 6 | History, downloads, cache, extensions |
| 11 | User Activity | 8 | LNK, jumplists, shellbags, recycle bin |
| 12 | Anti-Forensics | 7 | Timestomping, log clearing, wiping |
| 13 | Correlation | 7 | Attack narrative, lateral movement, MITRE |
| 14 | Linux | 8 | Auth, syslog, bash, cron, systemd |
| 15 | Reporting | 21 | Coverage, confidence, provenance, export |

## Academic Foundations & Novel Contributions

This project implements the **first computational realization** of several theoretical frameworks for DFIR:

| Framework | Citation | Our novel application |
|-----------|----------|---------------------|
| Hypothesis-based forensic investigation | Carrier 2006 (Purdue/CERIAS PhD) | First computational implementation — his model was purely theoretical |
| DSmT/PCR5 evidence fusion | Smarandache & Dezert 2006 | Applied to forensic tool outputs (prior: only VBIED/radar) |
| Active Inference for action selection | Friston 2015 (Free Energy Principle) | First application to DFIR tool orchestration |
| Rough-set decision approximations | Pawlak 1982 | Maps to forensic confidence tiers + stop criterion |
| External self-correction | Huang et al. 2025 (arXiv:2601.00828) | Server provides external correction signals (not LLM self-correcting) |
| MCP inference constraint levels | Hilgert et al. 2025 (arXiv:2506.00274) | Implemented Level 3-4 constraint with metadata reporting |
| Nondeterminism mitigation | Gruber & Hilgert 2026 (arXiv:2604.05589) | Determinism score quantifying methodology adherence |
| Knowledge-execution gap | DFIR-Metric 2025 (arXiv:2505.19973) | Rich directives bridge the 70% knowledge → 20% execution gap |
| Multi-agent forensic specialisation | CyberSleuth 2025 (arXiv:2508.20643) | Category dispatchers = lightweight specialist decomposition |

## Security Properties

Formally verified via property-based tests (`npm test`):

- **P1:** No shell execution capability exists (no code path)
- **P2:** No finding without evidence links enters the report
- **P3:** Capability graph is a valid DAG (no cycles)
- **P4:** Hash chain valid for any operation sequence
- **P5:** Every tool call produces exactly one ledger entry
- **P6:** All file access contained within evidence mount prefix

## Development

```bash
# Type check
npx tsc --noEmit

# Run tests
npx vitest run

# Watch mode
npx vitest
```

## Tech Stack

| Package | Purpose |
|---------|---------|\
| @modelcontextprotocol/sdk | MCP server (stdio + HTTP/SSE transport) |
| zod | Runtime validation + branded types |
| better-sqlite3 | Evidence ledger (WAL mode, hash-chained) |
| neverthrow | Type-safe Result<T, E> — no exceptions in domain layer |
| nanoid | Unique IDs for ledger entries + findings |
| exponential-backoff | Retry transient I/O failures with jitter |
| vitest + fast-check | Testing + property-based formal verification |

## License

MIT
