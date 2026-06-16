# Forensic Investigation Methodology — Reactive State Machine

## Design Philosophy

The SIFT Kernel methodology engine models how a **senior DFIR analyst** actually investigates: not a fixed checklist, but a **signal-driven graph** where findings determine the next investigative path.

This is the "teach the AI to think like a senior analyst" requirement from the hackathon: *"How they sequence their approach. How they recognize when something doesn't add up. How they adjust."*

## Architecture: Reactive FSM (not linear)

```
┌──────────────┐
│  COLLECTION  │ Mount + verify evidence
└──────┬───────┘
       │ evidence_mounted + integrity_verified
┌──────▼───────┐
│    TRIAGE    │ Scan filesystem — detect initial signals
└──────┬───────┘
       │ Signals emitted from tool output patterns
┌──────▼───────┐
│   CLASSIFY   │ What type of incident? Activate investigation paths
└──────┬───────┘
        │ One or MORE paths activated based on signals (for PRIORITY, not gating)
┌──────▼───────┐
│ INVESTIGATE  │ Attempt the COMPREHENSIVE baseline (execution, persistence,
│              │ accounts, registry, anti-forensics, user activity) on EVERY
│              │ case. Signals re-order priority + add depth — never skip a
│              │ category. New signals mid-investigation add MORE depth.
└──────┬───────┘
       │ ALL baseline + active-path tools attempted (executed/failed/unreachable)
┌──────▼───────┐
│   TIMELINE   │ Correlate all findings temporally
└──────┬───────┘
       │ timeline generated, attempted, or unreachable
┌──────▼───────┐
│  CORRELATE   │ Build attack narrative + MITRE ATT&CK mapping
└──────┬───────┘
       │ narrative built, attempted, or no findings to correlate
┌──────▼───────┐
│    REPORT    │ Generate final forensic report with HMAC seal
└──────────────┘
```

## The Coverage Guarantee (why two runs converge)

A senior analyst does **not** stop checking persistence just because they found
insider-threat documents. They run a complete baseline on every case, then go
**deep** wherever the evidence points. The FSM enforces exactly this:

- **Baseline (mandatory, deterministic):** the INVESTIGATE phase will not reach
  TIMELINE until it has *attempted* every tool in the baseline matrix —
  program execution (prefetch/amcache/shimcache), persistence
  (run keys/tasks/services/startup), malware scan (YARA), accounts
  (logon correlation/account manipulation), system & registry context, anti-forensics
  (log clearing/timestomping/secure deletion), and user activity (LNK/recycle bin).
  This is independent of which signals fired, so **any LLM, on any run, covers the
  same categories.**
- **Signals add priority + depth, never gating:** a detected signal (e.g.
  `MALWARE_INDICATORS`) moves its category to the front of the queue and unlocks
  *additional* depth tools (e.g. `check_wmi_persistence`, `hash_and_lookup`). It
  does **not** cause other baseline categories to be skipped.
- **Attempted ≠ covered:** a tool that fails (missing binary, broken backend) is
  recorded as *attempted* so the FSM progresses, but it does **not** count as
  analytical coverage — the accuracy report surfaces it as an environment
  limitation. A tool-poor environment therefore yields *honest low coverage*, not
  a fast shallow "done".

> This is the fix for the divergence where one run reported malware + insider
> threat and another reported only anti-forensics on the same image. Both runs now
> attempt the full baseline and converge on the same comprehensive finding set.

## Signals Drive Priority & Depth (not selection)

Unlike a linear state machine (phase 1 → 2 → 3 → ...), the FSM uses **investigation
signals** emitted by tool outputs to decide what to prioritise and how deep to go —
on top of the always-on baseline.

### Signals

| Signal | Triggered By | Investigation Path Activated |
|--------|-------------|------------------------------|
| `MALWARE_INDICATORS` | Suspicious EXEs, known-bad paths, Quarantine dir, YARA hits | Malware & Persistence Analysis |
| `INSIDER_INDICATORS` | OSINT tools, sensitive docs in personal folders, competitive intel | Insider Threat & Data Collection |
| `LATERAL_MOVEMENT` | Remote logons (type 3/10), net use, PsExec, WinRM | Lateral Movement & Credential Analysis |
| `PERSISTENCE_FOUND` | Registry run keys, scheduled tasks, services | Malware & Persistence Analysis |
| `ANTI_FORENSICS_DETECTED` | SDelete, log clearing, timestomping | Anti-Forensics & Evidence Destruction |
| `DATA_STAGING` | Archives in unusual dirs, compression tools, cloud sync | Insider Threat & Data Collection |
| `CREDENTIAL_ACCESS` | Mimikatz, lsass dump, SAM/NTDS access | Lateral Movement & Credential Analysis |
| `NETWORK_ANOMALY` | C2 beaconing, unusual connections, DNS tunneling | Network Forensics |

### How Signal Detection Works

After every tool execution, the server scans the raw output for patterns:
```
Tool output: "d/d 12345-144-6: Windows/Temp/suspicious-toolkit"
Pattern match: executable in Temp directory → MALWARE_INDICATORS signal emitted
Result: "Malware & Persistence Analysis" path activated
```

This happens **automatically** — the LLM doesn't need to decide what to investigate. The FSM detects the signal and activates the appropriate path. `suggest_next_action` then recommends tools from the activated path.

## Investigation Paths

When signals are detected, **investigation paths** are activated. Multiple paths can be active simultaneously (an APT case might have malware + lateral movement + anti-forensics all active).

### Path 1: Malware & Persistence Analysis (Priority 1)
**Triggered by:** MALWARE_INDICATORS, PERSISTENCE_FOUND
- get_persistence_keys (CRITICAL)
- check_scheduled_tasks (CRITICAL)
- check_services (CRITICAL)
- check_startup_locations (CRITICAL)
- scan_yara (CRITICAL)
- hash_and_lookup
- parse_prefetch
- parse_amcache
- check_wmi_persistence

### Path 2: Lateral Movement & Credential Analysis (Priority 2)
**Triggered by:** LATERAL_MOVEMENT, CREDENTIAL_ACCESS
- correlate_logon_events (CRITICAL)
- parse_event_log (CRITICAL)
- detect_account_manipulation (CRITICAL)
- parse_powershell_logs
- search_events
- detect_beaconing
- extract_connections

### Path 3: Insider Threat & Data Collection (Priority 3)
**Triggered by:** INSIDER_INDICATORS, DATA_STAGING
- parse_browser_history (CRITICAL)
- parse_browser_downloads (CRITICAL)
- parse_lnk_files (CRITICAL)
- get_usb_history (CRITICAL)
- parse_jumplists
- parse_shellbags
- parse_recycle_bin
- parse_mru_lists

### Path 4: Anti-Forensics & Evidence Destruction (Priority 4)
**Triggered by:** ANTI_FORENSICS_DETECTED
- detect_timestomping (CRITICAL)
- detect_log_clearing (CRITICAL)
- detect_secure_deletion (CRITICAL)
- detect_hidden_data
- detect_wiping_tools
- detect_anti_analysis

### Path 5: Execution Artifact Analysis (Priority 5)
**Triggered by:** EXECUTION_EVIDENCE
- parse_prefetch (CRITICAL)
- parse_amcache (CRITICAL)
- parse_shimcache
- parse_srum
- parse_bam
- parse_userassist

### Path 6: Network Forensics (Priority 6)
**Triggered by:** NETWORK_ANOMALY
- parse_pcap_summary (CRITICAL)
- detect_beaconing (CRITICAL)
- extract_dns_queries
- extract_http_traffic
- extract_connections

## Self-Correction Mechanism

The FSM enables self-correction through:

1. **Signal-driven pivoting** — If anti-forensics signals appear mid-investigation, the anti-forensics path activates automatically. The agent didn't plan for it; the evidence demanded it.

2. **Coverage gap awareness** — `get_coverage_gaps` shows what active investigation paths have uncompleted tools, sorted by forensic significance.

3. **Default paths on clean triage** — If no signals are detected during triage (unusual but possible), the FSM activates `malware_analysis` + `anti_forensics_investigation` as defaults. A senior analyst always checks these even when nothing is obviously wrong.

## For LLM Agents

The interaction pattern is simple:
```
1. Call suggest_next_action()
2. Response includes: tool, reason, call_as, fsm_state, active_investigation_paths, observed_signals
3. Call the suggested tool via category dispatcher
4. Tool output is automatically scanned for signals
5. If new signals detected → new paths activate → next suggestion comes from new path
6. Repeat until suggest_next_action returns null (investigation complete)
```

Even a model with no forensic knowledge produces a valid investigation by following `suggest_next_action`. The methodology is encoded in the server, not the prompt.

## Forensic Knowledge Enrichment

Every tool response includes a `forensic_context` field with tool-specific guidance:

- **Caveat** — What could go wrong, what the evidence means and doesn't mean, common attacker evasion techniques relevant to this artifact
- **Corroboration** — Which other tools should be used to confirm or refute the finding

Example for `get_file_metadata`:
```json
{
  "forensic_context": {
    "guidance": "$STANDARD_INFORMATION timestamps are easily modified. Compare with $FILE_NAME timestamps — if $SI.Created < $FN.Created, timestomping likely occurred.",
    "corroboration": "detect_timestomping for systematic analysis, parse_usnjrnl for change journal evidence"
  }
}
```

When anomalies are detected, the caveat is prefixed with ⚠️ to draw attention.

This is delivered at the **response level** (not in the system prompt) so context arrives exactly when the LLM processes that specific tool's output — preventing the "drift" problem where LLMs forget system-prompt guidance during long sessions.
