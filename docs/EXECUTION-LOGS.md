# Agent Execution Logs

## Overview

SIFT Kernel produces structured, tamper-evident execution logs automatically. Every tool call the agent makes is recorded in a hash-chained evidence ledger — not as an afterthought but as the core data structure of the system.

## Where Logs Live

```
sift-output/
├── ledger.db          # SQLite database (evidence ledger)
├── raw/               # Raw tool output (one JSON file per execution)
│   ├── {entry-id}.json
│   └── ...
└── reports/           # Generated investigation reports
```

## Ledger Schema

Each entry in `ledger.db` contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique entry ID (nanoid) |
| `tool` | string | Tool name executed |
| `params` | JSON | Input parameters |
| `outputHash` | string | SHA-256 of raw output |
| `rawOutputPath` | string | Path to raw output file |
| `timestamp` | ISO 8601 | When executed |
| `prevHash` | string | SHA-256 of previous entry (chain link) |
| `capabilitiesHeld` | string[] | Capabilities active at execution time |
| `success` | boolean | Whether tool succeeded |
| `errorMessage` | string? | Error details if failed |
| `durationMs` | number | Execution time |
| `findingsProduced` | string[] | Finding IDs generated from this output |

## Querying the Ledger

### Via MCP Tools (During Investigation)

```
# Validate entire chain integrity
verify_chain()
→ { valid: true, entryCount: 47, firstEntry: "...", lastEntry: "..." }

# Get full investigation summary
get_investigation_state()
→ { phase, capabilities, findings, hypotheses, activeWorkflows }

# Export complete audit log
export_audit_log(format="json")
→ All ledger entries as structured JSON
```

### Via SQLite (Post-Investigation)

```bash
# Open the ledger
sqlite3 sift-output/ledger.db

# Count entries
SELECT COUNT(*) FROM ledger;

# View last 10 tool calls
SELECT tool, params, success, timestamp FROM ledger ORDER BY timestamp DESC LIMIT 10;

# Trace a finding's provenance
SELECT * FROM ledger WHERE id IN (
  SELECT json_each.value FROM findings, json_each(findings.evidence_ids) WHERE findings.id = 'finding-xyz'
);

# Verify hash chain manually
SELECT id, prevHash FROM ledger ORDER BY timestamp;
```

## Provenance Tracing

Every finding links back to specific ledger entries. Given a finding ID:

```
Finding: "Lateral movement via RDP from WS01 to DC01"
  ├── Evidence #1: ledger entry abc123 (parse_event_log → 4624 logon)
  ├── Evidence #2: ledger entry def456 (get_network_connections → RDP traffic)
  └── Evidence #3: ledger entry ghi789 (parse_registry_key → RDP cache)
```

This chain is **complete and automatic**. The agent provides evidence IDs when calling `register_finding` — the server validates they exist in the ledger.

## Hash Chain Verification

Each ledger entry includes `prevHash = SHA-256(serialize(previousEntry))`. This creates a tamper-evident chain:

```
Entry 1: prevHash = "000...000" (genesis)
Entry 2: prevHash = SHA-256(Entry 1)
Entry 3: prevHash = SHA-256(Entry 2)
...
Entry N: prevHash = SHA-256(Entry N-1)
```

`verify_chain()` walks the entire chain and confirms every hash matches. If ANY entry was modified, inserted, or deleted, the chain breaks.

## Example Execution Log (Annotated)

```json
{
  "id": "kj4m2n9x",
  "tool": "list_directory",
  "params": {"evidence_path": "/Users/Admin/AppData/Local/Temp/", "partition_index": 0},
  "outputHash": "a3b2c1d0e9f8...",
  "timestamp": "2026-06-09T14:30:00.000Z",
  "prevHash": "f1e2d3c4b5a6...",
  "capabilitiesHeld": ["evidence_mounted", "integrity_verified", "filesystem_accessible"],
  "success": true,
  "durationMs": 1200,
  "findingsProduced": ["finding-suspicious-exe"]
}
```

## Log Format Compliance

The structured execution log satisfies the hackathon requirement for "structured agent execution logs" because:

1. **Structured** — SQLite database with typed columns, not free-text
2. **Complete** — every tool call recorded, no exceptions (Property P5 guarantees this)
3. **Traceable** — any finding traces back to exact tool calls via evidence links
4. **Tamper-evident** — hash chain catches modifications
5. **Queryable** — SQL for post-hoc analysis, MCP tools for live queries
6. **Exportable** — `export_audit_log(format="json"|"csv")` for offline analysis

## Three-Claim Trace (Judge Verification)

Judges verify submissions by picking 3 findings from the report and tracing each back to the specific tool execution that produced it. Here's how that works with SIFT Kernel:

**Step 1:** Judge picks a finding from the HTML/markdown report (e.g., "Malware toolkit perfmon-k in ProgramData")

**Step 2:** The finding object includes `evidence` — an array of ledger entry IDs

**Step 3:** Each ledger entry ID maps to:
- The exact tool that ran (`filesystem.list_directory`)
- The exact parameters (`{ path: "/ProgramData" }`)
- The SHA-256 hash of the raw output
- The raw output file (stored in `sift-output/raw/{entry_id}.json`)
- The timestamp and duration of execution

**Step 4:** Judge opens the raw output file and verifies the claimed artifact actually appears in the tool's output

This chain is **automatic** — not something the agent or operator needs to construct manually. Every `register_finding` call stores the provenance snippets (the specific lines from evidence that prove the finding) alongside the finding object.

### Verify Chain Integrity

```bash
# Via MCP tool
sift-kernel_verify_chain

# Returns: { valid: true, entries_checked: N }
# If tampered: { valid: false, break_at_entry: "..." }
```

### Export for Offline Review

```bash
# JSON export of all ledger entries
sift-kernel_reporting(operation="export_audit_log", format="json")

# CSV for spreadsheet analysis
sift-kernel_reporting(operation="export_audit_log", format="csv")
```

## Real Investigation Samples

### Sample: rocba-cdrive.e01 — First Two Ledger Entries

From `sift-output/ledger.db` (39 total entries in full run):

```
Entry 1:
  id: cqsvScn5hq8YZow353XP9
  tool: mount_evidence
  params: {"image_path":"/path/to/rocba-cdrive.e01","format":"e01"}
  outputHash: 925efa79f512a6fe4acb3f4f6973f2ac8687c90aa5322a58289e8ded21d25398
  timestamp: 2026-06-16T03:29:12.278Z
  prevHash: 901131d838b17aac0f7885b81e03cbdc9f5157a00343d30ab22083685ed1416a
  capabilities_granted: [evidence_mounted]
  success: true

Entry 2:
  id: 2gGzIVD0Bocr6OsKAu__-
  tool: verify_integrity
  params: {"algorithm":"sha256"}
  outputHash: d184c4eebb17d8333b7e36475f78a45c858756d869933c6f9ee79238883a402c
  timestamp: 2026-06-16T03:30:01.336Z
  prevHash: 70ab635faa498b3d4ba65c11fbf60bbe463e4f6eb1247085ba363e50627c882c
  capabilities_granted: [evidence_mounted, integrity_verified]
  success: true
  durationMs: 45022
```

### Sample: base-wkstn-01-c-drive.E01 — Full Run Stats

| Metric | Value |
|--------|-------|
| Total ledger entries | 57 |
| Successful tool calls | 49 |
| Failed tool calls | 8 (environment — missing binaries) |
| Findings registered | 4 |
| Hypotheses registered | 2 |
| Chain integrity | VALID |
| Total execution time | ~12 minutes |
| Report format | Interactive HTML (HMAC-sealed) |
