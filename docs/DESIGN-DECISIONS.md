# Design Decisions

## Why a Capability Kernel (Not Just Tool Wrappers)

**Problem:** Protocol SIFT gives the agent shell access + instructions. Nothing prevents the agent from:
- Running `rm -rf /mnt/evidence` (evidence destruction)
- Skipping integrity verification (invalid chain of custody)
- Claiming findings it never verified (hallucination)

**Decision:** A DAG-based capability system where tool execution requires prior capabilities to be held. `execute_shell` doesn't exist as a tool — there is nothing to bypass.

**Alternative considered:** Prompt-based constraints ("never write to evidence"). Rejected because prompt injection can bypass any text-based rule.

## Why Progressive Disclosure (Not Flat Tool List)

**Problem:** 129 tools in a flat list is ~80-100KB of JSON in the LLM's context window. This causes:
- Decision paralysis (which of 127 should I call?)
- Context budget wasted on tool schemas instead of forensic data
- Weak models hallucinate tool names

**Decision:** 32 tools always visible: 18 kernel tools + 14 category dispatchers. Each category accepts an operation parameter to access all operations within it. No notification-based dynamic tool lists — works on all MCP clients.

**Alternative considered:** Category prefixes (`fs_list_directory`, `reg_parse_key`). Rejected because it still puts all 127 definitions in context even if names are clearer.

## Why Hash-Chained Ledger (Not Just Logs)

**Problem:** Unstructured logs can be edited after the fact. A forensic report needs reproducible, tamper-evident provenance.

**Decision:** SQLite append-only table where each entry includes `prev_hash = SHA-256(previous_entry)`. Tampering breaks the chain, detectable via `verify_chain()`.

**Alternative considered:** Git-based audit trail. Rejected because git add/commit is slow for high-frequency tool calls and requires filesystem overhead.

## Why TypeScript (Not Python)

**Problem:** The MCP SDK is native TypeScript. The DFIR community prefers Python.

**Decision:** TypeScript for:
- Native MCP SDK with full type safety
- `exactOptionalPropertyTypes` + `noUncheckedIndexedAccess` catch bugs at compile time
- Better structured concurrency (async/await) for future HTTP transport
- `better-sqlite3` is synchronous (no async overhead for append-only writes)

**Trade-off acknowledged:** DFIR practitioners may find Python more approachable. Mitigated by clear documentation and `npx` one-line install.

## Why Confidence Scoring (Not Just Pass/Fail)

**Problem:** LLMs treat all information as equally certain. "The malware was planted on March 3" and "a file existed" carry different weight.

**Decision:** Deterministic confidence levels based on evidence graph topology:
- INFERRED: 1 evidence source
- SUPPORTED: 2+ from same category
- CONFIRMED: 2+ from different categories (cross-domain corroboration)

The final report can be filtered by confidence threshold. Court-facing reports use CONFIRMED only.

## Why In-Process Handlers (Not All Binary)

**Problem:** Not all forensic analysis requires an external binary. Anti-forensics detection, correlation, and report generation are computation on already-collected data.

**Decision:** Three tool execution tiers:
1. **Binary-backed** (50 tools): Spawn real SIFT tools
2. **In-process** (57 tools): TypeScript logic on cached data (intelligence detectors, correlators, parsers)
3. **Meta-cognitive** (23 tools): Pure state queries

This means 80 tools work on ANY machine without SIFT installed. Only binary-backed tools need the forensic toolkit.

## Why neverthrow (Not Exceptions)

**Problem:** Thrown exceptions are invisible in TypeScript's type system. A function that can fail looks identical to one that can't.

**Decision:** `Result<T, E>` from neverthrow. Domain code never throws. Errors are typed, explicit, and handled at every boundary.

**Benefit:** The compiler forces handling of every error case. No silent failures, no `try/catch` forgotten.

## Why Zod (Not io-ts or Manual Validation)

**Problem:** MCP tool inputs come as `unknown`. Need runtime validation with good error messages.

**Decision:** Zod for input schema validation. It's the MCP SDK's native validation library — zero impedance mismatch.

## Why SQLite (Not PostgreSQL or Files)

**Problem:** Need persistent, queryable storage for the evidence ledger.

**Decision:** better-sqlite3:
- Zero-config (no database server to install)
- Synchronous API (no async overhead for simple append-only writes)
- WAL mode (concurrent readers don't block writers)
- Single-file (easy to backup, portable)
- Production-grade (used by many forensic tools themselves)

## Why `shell: false` (Not Default Spawn)

**Problem:** `child_process.spawn()` with default options uses the shell on some platforms, enabling command injection.

**Decision:** Explicit `shell: false` + binary allowlist. Even if an attacker controls a parameter value, it becomes a literal argv string — no interpretation, no injection.

## Why Enriched Responses (Not Raw JSON)

**Problem:** Tool output alone doesn't tell the agent what to do next. Especially weak models need guidance.

**Decision:** Every response includes:
- `_meta.suggested_next_actions[]` — what to call next and why
- `_meta.anomalies_detected[]` — pre-flagged suspicious items
- `_meta.investigation_progress` — overall completion percentage

A model that can only do "call the next suggested tool" still produces a valid investigation.

## Why FARE Reasoning Engine (Not Just Rule-Based)

**Decision:** Implement a formal mathematical reasoning engine (DSmT + Active Inference + Rough Sets) instead of simple heuristics.

**Rationale:** The Self-Correction Paradox (Huang et al. 2025, arXiv:2601.00828) proves that LLMs cannot reliably self-correct without external feedback. Simple rule-based anomaly detection finds WHAT is suspicious but cannot answer "what should I investigate NEXT to reduce uncertainty most?" — that requires information-theoretic scoring.

Active Inference's Expected Free Energy (EFE) provides exactly this: for each candidate tool, compute how much running it would reduce the gap between what we believe and what we need to know. This transforms "suggest next action" from a checklist into an optimal experiment design problem (Lindley 1956).

DSmT/PCR5 was chosen over classical Dempster-Shafer because forensic evidence is inherently contradictory (anti-forensics creates paradoxical states where timestamps disagree, logs are absent, etc.). Classical DS normalizes conflict away; PCR5 redistributes it proportionally, preserving the conflict coefficient K as a self-correction signal.

## Why Category Dispatchers (Not Progressive Disclosure Via Notifications)

**Decision:** Expose 14 category tools + 18 kernel tools statically, instead of dynamically showing/hiding tools via `notifications/tools/list_changed`.

**Rationale:** Most MCP clients (OpenCode, Cursor, Gemini CLI, many VS Code extensions) do NOT re-fetch the tool list after receiving notifications. This makes dynamic tool disclosure unreliable. Category dispatchers guarantee all capabilities are accessible from any client, while the capability kernel still enforces methodology ordering via prerequisite checks.

## Why Auto-Correlation (Not LLM-Driven Correlation)

**Decision:** The server deterministically correlates registered findings via temporal proximity (±30 min window), MITRE kill-chain sequencing, and shared entity detection — rather than asking the LLM to connect dots.

**Rationale:** CyberSleuth (arXiv:2508.20643) demonstrates that multi-hop correlation is where LLMs fail most frequently. By making correlation deterministic and server-side, we ensure two different LLMs investigating the same evidence produce identical correlation graphs. The attack chain construction is reproducible and auditable — critical for the three-claim trace judges perform.

## Why Determinism Tracking (Not Trust-The-Agent)

**Decision:** Track how closely the agent follows server methodology recommendations (determinism_score 0.0-1.0).

**Rationale:** Gruber & Hilgert (arXiv:2604.05589) prove that "agent-mediated execution introduces nondeterminism in trace generation." By measuring adherence explicitly, the system can: (1) report investigation quality to the user, (2) detect when an agent is ignoring methodology guidance, and (3) provide evidence for audit that the investigation followed a defensible process.
