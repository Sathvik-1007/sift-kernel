# User Guide

## What is SIFT Kernel?

SIFT Kernel is a Model Context Protocol (MCP) server that makes AI-driven forensic investigations **provably correct**. It sits between an AI agent (Claude Code, OpenCode, etc.) and the SIFT Workstation forensic tools, enforcing:

- **Forensic methodology** — you can't skip steps
- **Evidence integrity** — no write access to evidence
- **Finding provenance** — every claim traces to tool output
- **Hallucination prevention** — findings without evidence are rejected

## Prerequisites

- Node.js 18+
- SIFT Workstation tools (optional for meta-cognitive features; required for live analysis)
- An MCP-compatible client (Claude Code, OpenCode, Cursor, etc.)

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/sift-kernel.git
cd sift-kernel
npm install
```

## Running

### As MCP Server (recommended)

Add to your MCP client configuration:

**Claude Code (`.claude/mcp.json`):**
```json
{
  "mcpServers": {
    "sift-kernel": {
      "command": "npx",
      "args": ["tsx", "src/index.ts", "--fresh", "--output", "./sift-output"]
    }
  }
}
```

**OpenCode (`~/.config/opencode/opencode.jsonc`):**
```jsonc
{
  "mcp": {
    "sift-kernel": {
      "type": "local",
      "command": "npx",
      "args": ["tsx", "/path/to/sift-kernel/src/index.ts"]
    }
  }
}
```

### CLI Options

```bash
npx tsx src/index.ts [options]

Options:
  --output <path>     Path for investigation output (default: /tmp/sift-output)
  --evidence <path>   Optional: pre-load evidence path (can also use mount_evidence dynamically)
  --memory <path>     Path to memory dump (optional)
  --fresh             Start a fresh investigation (clears prior state)
  --transport <type>  "stdio" (default) or "http"
  --port <number>     HTTP port (default: 3000, requires --transport http)
  --token <string>    Bearer token for HTTP auth (requires --transport http)
```

## Investigation Workflow

### 1. Mount Evidence

```
Agent: mount_evidence(image_path="/cases/case001/disk.E01")
```

The server detects the format (E01, raw, VMDK) and performs a read-only mount.

### 2. Verify Integrity

```
Agent: verify_integrity(algorithm="sha256")
```

Creates a cryptographic baseline. All analysis tools are now unlocked.

### 3. Follow the Server's Guidance

```
Agent: suggest_next_action()
→ { "tool": "list_directory", "reason": "Begin filesystem triage", "priority": "HIGH" }
```

The methodology engine always knows what to do next.

### 4. Activate Workflows as Needed

```
Agent: activate_workflow("registry")
Agent: activate_workflow("event_logs")
```

Tools appear and disappear dynamically. The agent never sees all 128 at once.

### 5. Register Findings

```
Agent: register_finding(
  type="persistence",
  description="Scheduled task 'WindowsUpdate' executing C:\\temp\\payload.exe",
  evidence=["ledger-entry-id-1", "ledger-entry-id-2"],
  mitre_technique="T1053.005"
)
```

Server validates evidence exists, computes confidence, and records in the hash-chained ledger.

### 6. Self-Correct

```
Agent: get_coverage_gaps()
→ { "gaps": [{"category": "anti_forensics", "priority": "CRITICAL", ...}] }
```

Fill gaps before finalizing.

### 7. Generate Report

```
Agent: generate_report(min_confidence="INFERRED", format="narrative")
```

## Key Concepts

### Progressive Disclosure
- 32 tools always visible (18 kernel + 14 category dispatchers)
- Activate workflows to reveal forensic tools (6-11 per workflow)
- Maximum ~35 visible at once
- Deactivate when done to reduce context

### Confidence Levels
| Level | Meaning | Evidence Requirement |
|-------|---------|---------------------|
| HYPOTHESIZED | Investigation marker | None (cannot appear in report) |
| INFERRED | Single source suggests | 1 evidence link |
| SUPPORTED | Multiple sources agree | 2+ from same category |
| CONFIRMED | Cross-domain corroboration | 2+ from different categories |
| CONFLICTED | Contradicting evidence | Needs resolution |

### Evidence Ledger
Every tool call produces an append-only, hash-chained entry. The chain is:
- **Tamper-evident** — verify with `verify_chain()`
- **Queryable** — `export_audit_log()` exports as JSON or CSV
- **Reproducible** — another examiner can replay the investigation

### Capability Kernel
Tools have prerequisites. You must:
1. `mount_evidence` → produces `evidence_mounted`
2. `verify_integrity` → produces `integrity_verified`
3. Only THEN can you run analysis tools

This prevents accidental evidence handling without integrity verification.

## Troubleshooting

### "CAPABILITY_BLOCKED" response
The tool requires capabilities you haven't acquired yet. Check `get_investigation_state()` to see what's missing, then acquire the prerequisite.

### "Binary not found"
The forensic tool isn't installed. Install SIFT Workstation tools: `sudo cast install teamdfir/sift`

### Stale investigation state
Call `reset_investigation()` or restart with `--fresh`.

## For Practitioners

### Chain of Custody
The evidence ledger is court-admissible quality:
- SHA-256 hash-chained (each entry references the previous)
- Append-only (entries cannot be deleted or modified)
- Timestamped with ISO-8601
- Every finding links to specific ledger entries

### Formal Guarantees
Property-tested (fast-check, 10,000 scenarios):
- P1: No tool call can write to evidence mount path
- P2: No finding in final report without evidence links
- P3: Capability graph is a valid DAG (no cycles)
- P4: Hash chain integrity holds for any operation sequence
- P5: Every tool call produces exactly one ledger entry
- P6: All file access is contained within evidence mount prefix
