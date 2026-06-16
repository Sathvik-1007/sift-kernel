/**
 * In-Process Tool Handlers
 * 
 * These tools execute TypeScript logic directly — no external binary needed.
 * They operate on:
 * - Cached data from prior tool calls (ledger entries, raw outputs)
 * - Intelligence detectors (timestomping, beaconing, wiping, etc.)
 * - Data correlation across findings
 * - Text parsing of extracted files
 * 
 * Each handler returns { success: true, output: string } or { success: false, error: string }
 */

import { detectTimestomping, type TimestampPair } from "../intelligence/timestomping.js";
import { detectBeaconing, type NetworkCallback } from "../intelligence/beaconing.js";
import { detectKnownBadPaths, type FileEntry } from "../intelligence/known-bad-paths.js";
import { detectWipingTools } from "../intelligence/wiping-tools.js";
import { detectLogGaps, type EventRecord } from "../intelligence/log-gap.js";
import type { Finding, Hypothesis, LedgerEntry } from "../domain/types.js";

// ─── Handler Result Type ─────────────────────────────────────────────────────

export interface HandlerResult {
  success: boolean;
  output: string;
  error?: string;
}

type HandlerFn = (params: Record<string, unknown>, context: HandlerContext) => HandlerResult;

export interface HandlerContext {
  findings: ReadonlyMap<string, Finding>;
  hypotheses: ReadonlyMap<string, Hypothesis>;
  ledgerEntries: readonly LedgerEntry[];
  rawOutputs: ReadonlyMap<string, string>;
  evidencePath: string;
}

// ─── Anti-Forensics Handlers ─────────────────────────────────────────────────

function handleDetectTimestomping(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  // Find prior fls/istat outputs that contain timestamp data
  const istatEntries = ctx.ledgerEntries.filter(e => e.tool === "get_file_metadata" || e.tool === "list_directory");
  if (istatEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_data", message: "No filesystem metadata available yet. Run list_directory or get_file_metadata first to collect timestamp data for analysis.", suggestion: { tool: "list_directory", reason: "Collect filesystem timestamps for stomping detection" } }) };
  }

  // Extract timestamp pairs from raw istat outputs
  const pairs: TimestampPair[] = [];
  for (const entry of istatEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    // Parse SI vs FN timestamps from istat output
    const siCreated = extractTimestamp(raw, "STANDARD_INFORMATION", "Created");
    const fnCreated = extractTimestamp(raw, "FILE_NAME", "Created");
    const siModified = extractTimestamp(raw, "STANDARD_INFORMATION", "Modified");
    const fnModified = extractTimestamp(raw, "FILE_NAME", "Modified");
    if (siCreated && fnCreated) {
      pairs.push({ siCreated, fnCreated, siModified: siModified ?? siCreated, fnModified: fnModified ?? fnCreated, filename: entry.tool, inode: entry.id as string });
    }
  }

  const anomalies = detectTimestomping(pairs);
  return { success: true, output: JSON.stringify({ result: anomalies.length > 0 ? "timestomping_detected" : "clean", anomalies_found: anomalies.length, details: anomalies, analyzed_entries: istatEntries.length }) };
}

function handleDetectLogClearing(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const evtxEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_event_log" || e.tool === "search_events");
  if (evtxEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_data", message: "No event log data available. Parse event logs first.", suggestion: { tool: "parse_event_log", reason: "Collect event log data for gap analysis" } }) };
  }

  // Parse event records from raw outputs
  const records: EventRecord[] = [];
  for (const entry of evtxEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    const parsed = parseEventRecords(raw);
    records.push(...parsed);
  }

  const gaps = detectLogGaps(records);
  return { success: true, output: JSON.stringify({ result: gaps.length > 0 ? "log_clearing_detected" : "clean", gaps_found: gaps.length, details: gaps, analyzed_records: records.length }) };
}

function handleDetectSecureDeletion(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const flsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory" || e.tool === "recover_deleted");
  if (flsEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_data", message: "No filesystem listing data. Run list_directory with show_deleted=true first.", suggestion: { tool: "list_directory", params: { path: "/", show_deleted: true }, reason: "Collect deleted file data" } }) };
  }

  // Analyze deleted file patterns from fls output
  const deletedFiles: string[] = [];
  for (const entry of flsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    const lines = raw.split("\n");
    for (const line of lines) {
      if (line.includes("*") || line.match(/^[rd]\/-/)) {
        deletedFiles.push(line.trim());
      }
    }
  }

  // Detect patterns indicating secure deletion
  const indicators: Array<{ type: string; evidence: string; confidence: string }> = [];
  const orphanCount = deletedFiles.filter(f => f.includes("OrphanFile")).length;
  if (orphanCount > 10) {
    indicators.push({ type: "mass_orphan_files", evidence: `${orphanCount} orphan MFT entries found`, confidence: "SUPPORTED" });
  }
  const zeroByteDeleted = deletedFiles.filter(f => f.match(/\s+0\s+/)).length;
  if (zeroByteDeleted > 5) {
    indicators.push({ type: "zero_byte_deleted", evidence: `${zeroByteDeleted} deleted files with zero-byte content (data wiped)`, confidence: "INFERRED" });
  }

  return { success: true, output: JSON.stringify({ result: indicators.length > 0 ? "secure_deletion_detected" : "clean", indicators, deleted_file_count: deletedFiles.length, analyzed_entries: flsEntries.length }) };
}

function handleDetectHiddenData(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory" || e.tool === "list_partitions");
  if (fsEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_data", message: "No filesystem data available.", suggestion: { tool: "list_directory", reason: "Collect filesystem data for hidden data detection" } }) };
  }

  const indicators: Array<{ type: string; evidence: string; location: string }> = [];
  for (const entry of fsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    // Check for Alternate Data Streams (ADS)
    if (raw.includes(":$DATA") || raw.match(/:\w+:\$DATA/)) {
      indicators.push({ type: "alternate_data_stream", evidence: "ADS detected in file listing", location: "filesystem" });
    }
    // Check for hidden partitions (unallocated gaps in mmls)
    if (entry.tool === "list_partitions" && raw.includes("Unallocated")) {
      const gaps = raw.split("\n").filter(l => l.includes("Unallocated"));
      for (const gap of gaps) {
        const sizeMatch = gap.match(/(\d+)\s*$/);
        if (sizeMatch && parseInt(sizeMatch[1]!) > 2048) { // > 1MB
          indicators.push({ type: "hidden_partition", evidence: `Unallocated space: ${gap.trim()}`, location: "partition_table" });
        }
      }
    }
  }

  return { success: true, output: JSON.stringify({ result: indicators.length > 0 ? "hidden_data_detected" : "clean", indicators, analyzed_entries: fsEntries.length }) };
}

function handleDetectWipingTools(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory" || e.tool === "search_filename");
  if (fsEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_data", message: "No filesystem data. Run list_directory first.", suggestion: { tool: "list_directory", params: { path: "/", recursive: true }, reason: "Scan for wiping tool artifacts" } }) };
  }

  const filePaths: string[] = [];
  for (const entry of fsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    filePaths.push(...raw.split("\n").filter(l => l.trim()));
  }

  const anomalies = detectWipingTools(filePaths);
  return { success: true, output: JSON.stringify({ result: anomalies.length > 0 ? "wiping_tools_detected" : "clean", tools_found: anomalies.length, details: anomalies, files_scanned: filePaths.length }) };
}

function handleDetectAntiAnalysis(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const regEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_registry_key" || e.tool === "get_system_config");
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory");
  if (regEntries.length === 0 && fsEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_data", message: "Need registry or filesystem data first.", suggestion: { tool: "parse_registry_key", reason: "Check registry for anti-analysis artifacts" } }) };
  }

  const indicators: Array<{ type: string; evidence: string; confidence: string }> = [];
  // Check for VM/sandbox evasion artifacts in raw outputs
  const vmIndicators = ["VBoxGuest", "vmtools", "VMwareService", "VirtualBox", "VBOX", "vmware", "qemu", "Sandboxie", "SbieDll"];
  for (const entry of [...regEntries, ...fsEntries]) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    for (const vm of vmIndicators) {
      if (raw.toLowerCase().includes(vm.toLowerCase())) {
        indicators.push({ type: "vm_detection_artifact", evidence: `Found "${vm}" in ${entry.tool} output`, confidence: "INFERRED" });
      }
    }
  }

  return { success: true, output: JSON.stringify({ result: indicators.length > 0 ? "anti_analysis_detected" : "clean", indicators, analyzed_entries: regEntries.length + fsEntries.length }) };
}

function handleGetAntiForensicsSummary(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  // Aggregate results from all anti-forensics tools already run
  const afEntries = ctx.ledgerEntries.filter(e =>
    e.tool === "detect_timestomping" || e.tool === "detect_log_clearing" ||
    e.tool === "detect_secure_deletion" || e.tool === "detect_hidden_data" ||
    e.tool === "detect_wiping_tools" || e.tool === "detect_anti_analysis"
  );

  if (afEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_analysis_yet", message: "No anti-forensics analysis has been performed yet. Run individual detection tools first.", tools_to_run: ["detect_timestomping", "detect_log_clearing", "detect_secure_deletion", "detect_hidden_data", "detect_wiping_tools", "detect_anti_analysis"] }) };
  }

  const results: Record<string, unknown> = {};
  for (const entry of afEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "{}";
    try { results[entry.tool] = JSON.parse(raw); } catch { results[entry.tool] = { raw }; }
  }

  return { success: true, output: JSON.stringify({ summary: results, tools_executed: afEntries.length, total_tools: 6 }) };
}

// ─── Correlation Handlers ────────────────────────────────────────────────────

function handleCorrelateTimelineEvents(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const timelineEntries = ctx.ledgerEntries.filter(e => e.tool === "filter_timeline" || e.tool === "generate_timeline");
  if (timelineEntries.length === 0 || ctx.findings.size === 0) {
    return { success: true, output: JSON.stringify({ result: "insufficient_data", message: "Need both timeline data and registered findings for correlation." }) };
  }

  // Cross-reference findings with timeline
  const correlations: Array<{ finding_id: string; finding_desc: string; timeline_overlap: string }> = [];
  for (const [id, finding] of ctx.findings) {
    if (finding.temporalRange) {
      correlations.push({ finding_id: id, finding_desc: finding.description, timeline_overlap: `${finding.temporalRange.start} - ${finding.temporalRange.end}` });
    }
  }

  return { success: true, output: JSON.stringify({ correlations, findings_with_temporal: correlations.length, total_findings: ctx.findings.size }) };
}

function handleBuildAttackNarrative(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  if (ctx.findings.size === 0) {
    return { success: true, output: JSON.stringify({ result: "no_findings", message: "Register findings before building narrative." }) };
  }

  // Order findings by temporal range
  const ordered = [...ctx.findings.values()]
    .filter(f => f.temporalRange)
    .sort((a, b) => (a.temporalRange?.start ?? "").localeCompare(b.temporalRange?.start ?? ""));

  const narrative = ordered.map((f, i) => ({
    step: i + 1,
    time: f.temporalRange?.start ?? "unknown",
    type: f.type,
    description: f.description,
    confidence: f.confidence,
    mitre: f.mitreTechnique ?? null,
  }));

  return { success: true, output: JSON.stringify({ narrative, total_steps: narrative.length, unordered_findings: ctx.findings.size - ordered.length }) };
}

function handleDetectLateralMovement(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  // Look for lateral movement indicators in findings and event log data
  const lateralFindings = [...ctx.findings.values()].filter(f => f.type === "lateral_movement");
  const logonEntries = ctx.ledgerEntries.filter(e => e.tool === "correlate_logon_events" || e.tool === "search_events");

  const indicators: Array<{ type: string; evidence: string; source: string }> = [];
  for (const entry of logonEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    if (raw.includes("Type 3") || raw.includes("type: 3") || raw.includes("logon_type: 3")) {
      indicators.push({ type: "network_logon", evidence: "Type 3 (Network) logon detected", source: entry.id as string });
    }
    if (raw.includes("Type 10") || raw.includes("type: 10") || raw.includes("logon_type: 10")) {
      indicators.push({ type: "rdp_logon", evidence: "Type 10 (RemoteInteractive/RDP) logon detected", source: entry.id as string });
    }
  }

  return { success: true, output: JSON.stringify({ lateral_movement_indicators: indicators, existing_findings: lateralFindings.length, logon_entries_analyzed: logonEntries.length }) };
}

function handleMapMitreTechniques(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  if (ctx.findings.size === 0) {
    return { success: true, output: JSON.stringify({ result: "no_findings", message: "Register findings first." }) };
  }

  // Map finding types to MITRE ATT&CK
  const MITRE_MAP: Record<string, { tactic: string; technique: string; id: string }> = {
    initial_access: { tactic: "Initial Access", technique: "Various", id: "TA0001" },
    execution: { tactic: "Execution", technique: "Various", id: "TA0002" },
    persistence: { tactic: "Persistence", technique: "Various", id: "TA0003" },
    privilege_escalation: { tactic: "Privilege Escalation", technique: "Various", id: "TA0004" },
    defense_evasion: { tactic: "Defense Evasion", technique: "Various", id: "TA0005" },
    credential_access: { tactic: "Credential Access", technique: "Various", id: "TA0006" },
    lateral_movement: { tactic: "Lateral Movement", technique: "Various", id: "TA0008" },
    collection: { tactic: "Collection", technique: "Various", id: "TA0009" },
    command_and_control: { tactic: "Command and Control", technique: "Various", id: "TA0011" },
    exfiltration: { tactic: "Exfiltration", technique: "Various", id: "TA0010" },
    impact: { tactic: "Impact", technique: "Various", id: "TA0040" },
  };

  const mapped = [...ctx.findings.values()].map(f => ({
    finding_id: f.id,
    finding_type: f.type,
    description: f.description,
    mitre: f.mitreTechnique ?? MITRE_MAP[f.type]?.id ?? "unmapped",
    tactic: MITRE_MAP[f.type]?.tactic ?? "Unknown",
  }));

  const tactics = new Set(mapped.map(m => m.tactic));
  return { success: true, output: JSON.stringify({ mapped_findings: mapped, tactics_covered: [...tactics], coverage: `${tactics.size}/14 tactics` }) };
}

function handleGetInvestigationSummary(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const byType: Record<string, number> = {};
  const byConfidence: Record<string, number> = {};
  for (const f of ctx.findings.values()) {
    byType[f.type] = (byType[f.type] ?? 0) + 1;
    byConfidence[f.confidence] = (byConfidence[f.confidence] ?? 0) + 1;
  }

  return { success: true, output: JSON.stringify({
    total_findings: ctx.findings.size,
    total_hypotheses: ctx.hypotheses.size,
    findings_by_type: byType,
    findings_by_confidence: byConfidence,
    tool_calls_total: ctx.ledgerEntries.length,
    open_hypotheses: [...ctx.hypotheses.values()].filter(h => h.status === "OPEN").length,
  }) };
}

function handleExportTimelineOfCompromise(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const ordered = [...ctx.findings.values()]
    .filter(f => f.temporalRange && f.confidence !== "CONFLICTED")
    .sort((a, b) => (a.temporalRange?.start ?? "").localeCompare(b.temporalRange?.start ?? ""));

  if (ordered.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_temporal_findings", message: "No findings with temporal data. Add temporal_range when registering findings." }) };
  }

  const timeline = ordered.map(f => ({
    time: f.temporalRange?.start,
    end: f.temporalRange?.end,
    action: f.description,
    type: f.type,
    confidence: f.confidence,
    mitre: f.mitreTechnique ?? null,
  }));

  return { success: true, output: JSON.stringify({ timeline_of_compromise: timeline, total_events: timeline.length }) };
}

function handleGetIocSummary(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const allIocs: Array<{ type: string; value: string; finding_id: string }> = [];
  for (const [id, f] of ctx.findings) {
    if (f.iocs) {
      for (const ioc of f.iocs) {
        allIocs.push({ type: ioc.type, value: ioc.value, finding_id: id });
      }
    }
  }

  const byType: Record<string, string[]> = {};
  for (const ioc of allIocs) {
    if (!byType[ioc.type]) byType[ioc.type] = [];
    byType[ioc.type]!.push(ioc.value);
  }

  return { success: true, output: JSON.stringify({ total_iocs: allIocs.length, by_type: byType, all_iocs: allIocs }) };
}

// ─── Event Log In-Process Handlers ───────────────────────────────────────────

function handleListEventLogs(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  // Search ALL cached fls output (any list_directory or search_filename call) for .evtx files
  const allEntries = ctx.ledgerEntries.filter(e =>
    e.tool === "list_directory" || e.tool === "search_filename" || e.tool === "get_filesystem_info"
  );

  const evtxFiles: string[] = [];
  for (const entry of allEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    const lines = raw.split("\n");
    for (const line of lines) {
      if (line.toLowerCase().includes(".evtx")) {
        evtxFiles.push(line.trim());
      }
    }
  }

  if (evtxFiles.length === 0) {
    // No evtx found in any cached output — tell agent to run list_directory on the Logs dir
    return { success: true, output: JSON.stringify({ evtx_files_found: 0, result: "no_evtx_in_cache", message: "No .evtx files found in cached filesystem listings. Call filesystem(operation='list_directory', path='/Windows/System32/winevt/Logs') first, then call this tool again.", suggestion: { tool: "filesystem", params: { operation: "list_directory", path: "/Windows/System32/winevt/Logs" } } }) };
  }

  return { success: true, output: JSON.stringify({ evtx_files_found: evtxFiles.length, files: evtxFiles.slice(0, 50), note: evtxFiles.length > 50 ? `Showing first 50 of ${evtxFiles.length}` : undefined }) };
}

function handleDetectLogGaps(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  return handleDetectLogClearing(_params, ctx); // Same logic
}

function handleCorrelateLogonEvents(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const evtxEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_event_log" || e.tool === "search_events");
  if (evtxEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_event_data", message: "Parse event logs first.", suggestion: { tool: "parse_event_log" } }) };
  }

  // Extract logon/logoff pairs (4624/4634)
  const sessions: Array<{ logon_id: string; logon_type: string; user: string; source: string }> = [];
  for (const entry of evtxEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    if (raw.includes("4624") || raw.includes("4634")) {
      // Basic extraction
      const userMatch = raw.match(/Account Name:\s*(\S+)/i) ?? raw.match(/user[_\s]*name.*?:\s*(\S+)/i);
      sessions.push({ logon_id: entry.id as string, logon_type: raw.includes("Type 3") ? "Network" : raw.includes("Type 10") ? "RDP" : "Interactive", user: userMatch?.[1] ?? "unknown", source: "event_log" });
    }
  }

  return { success: true, output: JSON.stringify({ sessions_reconstructed: sessions.length, sessions: sessions.slice(0, 20) }) };
}

function handleDetectAccountManipulation(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const evtxEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_event_log" || e.tool === "search_events");
  if (evtxEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_event_data", message: "Parse Security event log first.", suggestion: { tool: "search_events", params: { event_ids: [4720, 4722, 4724, 4732] } } }) };
  }

  const manipulations: Array<{ event_id: string; description: string; evidence: string }> = [];
  const targetEids = ["4720", "4722", "4724", "4732", "4728", "4756"];
  for (const entry of evtxEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    for (const eid of targetEids) {
      if (raw.includes(eid)) {
        manipulations.push({ event_id: eid, description: getEidDescription(eid), evidence: entry.id as string });
      }
    }
  }

  return { success: true, output: JSON.stringify({ manipulations_detected: manipulations.length, details: manipulations }) };
}

function handleGetSecuritySummary(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const evtxEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_event_log" || e.tool === "search_events");
  const eidCounts: Record<string, number> = {};
  for (const entry of evtxEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    const eidMatches = raw.matchAll(/Event\s*(?:ID|identifier):\s*(\d+)/gi);
    for (const m of eidMatches) {
      eidCounts[m[1]!] = (eidCounts[m[1]!] ?? 0) + 1;
    }
  }

  return { success: true, output: JSON.stringify({ event_id_distribution: eidCounts, total_entries_analyzed: evtxEntries.length, notable: getNotableEids(eidCounts) }) };
}

// ─── Browser Handlers (SQLite-based) ─────────────────────────────────────────

function handleBrowserTool(toolName: string, _params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  // Browser tools need extracted SQLite DB files from the image
  const extractedEntries = ctx.ledgerEntries.filter(e => e.tool === "extract_file");
  const browserPaths = [
    "AppData/Local/Google/Chrome/User Data/Default/History",
    "AppData/Local/Microsoft/Edge/User Data/Default/History",
    "AppData/Roaming/Mozilla/Firefox/Profiles",
  ];

  // Check if browser databases have been extracted
  const hasExtracted = extractedEntries.some(e => {
    const raw = ctx.rawOutputs.get(e.id as string) ?? "";
    return browserPaths.some(p => raw.toLowerCase().includes(p.toLowerCase()));
  });

  if (!hasExtracted) {
    return { success: true, output: JSON.stringify({
      result: "databases_not_extracted",
      message: `Browser analysis requires extracting browser SQLite databases first. Use extract_file on the browser profile database.`,
      browser_paths: { chrome: "Users/*/AppData/Local/Google/Chrome/User Data/Default/History", edge: "Users/*/AppData/Local/Microsoft/Edge/User Data/Default/History", firefox: "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite" },
      suggestion: { tool: "search_filename", params: { pattern: "(History|places\\.sqlite)$" }, reason: "Locate browser databases for extraction" },
    }) };
  }

  return { success: false, output: JSON.stringify({ result: "requires_extraction", tool: toolName, message: "Browser databases must be extracted first. Use extract_file to get the SQLite DB, then re-run this tool." }) };
}

// ─── Linux Analysis Handlers ─────────────────────────────────────────────────

function handleLinuxTool(toolName: string, _params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  // Linux tools parse text files extracted from the image via icat
  const extractedEntries = ctx.ledgerEntries.filter(e => e.tool === "extract_file");
  const linuxPaths: Record<string, string> = {
    parse_auth_log: "/var/log/auth.log",
    parse_syslog: "/var/log/syslog",
    parse_bash_history: "/.bash_history",
    parse_cron_jobs: "/etc/crontab",
    parse_systemd_journal: "/var/log/journal",
    parse_ssh_artifacts: "/.ssh/authorized_keys",
    check_linux_persistence: "/etc/systemd/system",
    parse_audit_log: "/var/log/audit/audit.log",
  };

  const targetPath = linuxPaths[toolName] ?? "";
  const hasExtracted = extractedEntries.some(e => {
    const raw = ctx.rawOutputs.get(e.id as string) ?? "";
    return raw.includes(targetPath);
  });

  if (!hasExtracted) {
    return { success: true, output: JSON.stringify({
      result: "file_not_extracted",
      message: `Linux analysis requires extracting ${targetPath} from the image first.`,
      suggestion: { tool: "search_filename", params: { pattern: targetPath.split("/").pop() }, reason: `Locate ${targetPath} for extraction` },
      workflow: "1. search_filename to find the inode → 2. extract_file by inode → 3. re-run this tool",
    }) };
  }

  // If file was extracted, parse it from raw output
  for (const entry of extractedEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    if (raw.includes(targetPath) || raw.length > 0) {
      const parsed = parseLinuxLog(toolName, raw);
      return { success: true, output: JSON.stringify({ result: "parsed", tool: toolName, data: parsed }) };
    }
  }

  return { success: true, output: JSON.stringify({ result: "parse_failed", message: "File extracted but parsing produced no results." }) };
}

// ─── Persistence/User-Activity In-Process Handlers ───────────────────────────

function handleCheckScheduledTasks(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory" || e.tool === "extract_file");
  if (fsEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_data", message: "Need filesystem data. Search for task XML files first.", suggestion: { tool: "search_filename", params: { pattern: "\\.xml$" }, reason: "Find scheduled task definitions in Windows/System32/Tasks/" } }) };
  }

  // Look for task-related content in extracted data
  const tasks: Array<{ name: string; action: string; trigger: string }> = [];
  for (const entry of fsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    // Parse XML task definitions
    const execMatches = raw.matchAll(/<Exec>.*?<Command>(.*?)<\/Command>.*?<\/Exec>/gs);
    for (const m of execMatches) {
      tasks.push({ name: "task", action: m[1] ?? "", trigger: "scheduled" });
    }
    // Also check for task files in directory listings
    if (raw.includes("Tasks/") || raw.includes("Tasks\\")) {
      const taskFiles = raw.split("\n").filter(l => l.includes("Tasks"));
      for (const f of taskFiles.slice(0, 10)) {
        tasks.push({ name: f.trim(), action: "unknown (extract to view)", trigger: "needs_extraction" });
      }
    }
  }

  return { success: true, output: JSON.stringify({ tasks_found: tasks.length, tasks, suggestion: tasks.length === 0 ? { tool: "search_filename", params: { pattern: "Tasks" } } : undefined }) };
}

function handleCheckServices(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const regEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_registry_key" || e.tool === "get_system_config");
  if (regEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_data", message: "Parse SYSTEM registry hive first.", suggestion: { tool: "parse_registry_key", params: { hive_path: "Windows/System32/config/SYSTEM", plugin: "services" } } }) };
  }

  const services: Array<{ name: string; path: string; start_type: string; suspicious: boolean }> = [];
  for (const entry of regEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    const serviceMatches = raw.matchAll(/(?:ServiceName|ImagePath|Service).*?[=:]\s*(.+)/gi);
    for (const m of serviceMatches) {
      const path = m[1]?.trim() ?? "";
      services.push({ name: path.split("\\").pop() ?? path, path, start_type: "auto", suspicious: isSuspiciousServicePath(path) });
    }
  }

  return { success: true, output: JSON.stringify({ services_found: services.length, suspicious: services.filter(s => s.suspicious), all_services: services.slice(0, 30) }) };
}

function handleLoadNetworkCapture(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  // Verify pcap exists — just a gate for capability production
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory" || e.tool === "search_filename");
  const hasPcap = fsEntries.some(e => {
    const raw = ctx.rawOutputs.get(e.id as string) ?? "";
    return raw.match(/\.(pcap|pcapng|cap)/i) !== null;
  });

  if (hasPcap) {
    return { success: true, output: JSON.stringify({ result: "capture_located", message: "Network capture file found in evidence.", suggestion: { tool: "parse_pcap_summary", reason: "Get high-level network statistics" } }) };
  }

  return { success: true, output: JSON.stringify({ result: "no_capture", message: "No PCAP files found in evidence. Search for network captures.", suggestion: { tool: "search_filename", params: { pattern: "\\.(pcap|pcapng|cap)$" } } }) };
}

function handleDetectBeaconing(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const netEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_pcap_summary" || e.tool === "extract_connections");
  if (netEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_network_data", message: "Parse network capture first.", suggestion: { tool: "parse_pcap_summary" } }) };
  }

  // Extract connection data for beaconing analysis
  const events: NetworkCallback[] = [];
  for (const entry of netEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    const lines = raw.split("\n");
    for (const line of lines) {
      const parts = line.split(/\s+/);
      if (parts.length >= 4) {
        const ts = Date.parse(parts[0]!);
        if (!isNaN(ts)) {
          events.push({ timestamp: ts, dstAddr: parts[2] ?? "", dstPort: parseInt(parts[3] ?? "0"), bytes: parseInt(parts[4] ?? "0") });
        }
      }
    }
  }

  if (events.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_parseable_connections", message: "Connection data not in expected format. Need tshark conversation output.", analyzed_entries: netEntries.length }) };
  }

  const anomalies = detectBeaconing(events);
  return { success: true, output: JSON.stringify({ result: anomalies.length > 0 ? "beaconing_detected" : "clean", beacons: anomalies, connections_analyzed: events.length }) };
}

// ─── Misc In-Process Handlers ────────────────────────────────────────────────

function handleCompareTimelines(params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const timelineEntries = ctx.ledgerEntries.filter(e => e.tool === "filter_timeline" || e.tool === "generate_timeline");
  if (timelineEntries.length < 2) {
    return { success: true, output: JSON.stringify({ result: "insufficient_timelines", message: "Need at least 2 timeline filter results to compare. Run filter_timeline with different time ranges." }) };
  }

  return { success: false, output: JSON.stringify({ result: "requires_data", ranges: params, timeline_entries: timelineEntries.length, message: "Timeline comparison requires generated timeline data from both ranges." }) };
}

function handleDetectTimelineAnomalies(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const timelineEntries = ctx.ledgerEntries.filter(e => e.tool === "filter_timeline" || e.tool === "generate_timeline");
  if (timelineEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_timeline", message: "Generate timeline first.", suggestion: { tool: "generate_timeline" } }) };
  }

  return { success: false, output: JSON.stringify({ result: "requires_data", message: "Timeline anomaly detection requires Plaso super timeline output. Run generate_timeline first.", analyzed_entries: timelineEntries.length }) };
}

function handleGetTimelineStatistics(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const timelineEntries = ctx.ledgerEntries.filter(e => e.tool === "filter_timeline" || e.tool === "generate_timeline");
  if (timelineEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_timeline", suggestion: { tool: "generate_timeline" } }) };
  }
  return { success: false, output: JSON.stringify({ result: "requires_data", timeline_entries: timelineEntries.length, message: "Statistics require generated timeline data." }) };
}

// ─── Registry Hive Discovery ─────────────────────────────────────────────────

function handleListRegistryHives(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const flsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory");
  if (flsEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_filesystem_data", message: "Run list_directory first to discover registry hive files.", suggestion: { tool: "list_directory", params: { path: "/Windows/System32/config/" } } }) };
  }
  const knownHives = ["SAM", "SYSTEM", "SOFTWARE", "SECURITY", "DEFAULT", "NTUSER.DAT", "UsrClass.dat"];
  const found: string[] = [];
  for (const entry of flsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    for (const hive of knownHives) {
      if (raw.toLowerCase().includes(hive.toLowerCase())) found.push(hive);
    }
  }
  return { success: true, output: JSON.stringify({ result: "hives_found", hives: [...new Set(found)], known_locations: { SAM: "Windows/System32/config/SAM", SYSTEM: "Windows/System32/config/SYSTEM", SOFTWARE: "Windows/System32/config/SOFTWARE", NTUSER: "Users/<user>/NTUSER.DAT" }, next_step: "Extract hive via extract_file then use parse_registry_key" }) };
}

// ─── Persistence checks (in-process logic on cached data) ────────────────────

function handleCheckStartupLocations(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const regEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_registry_key" || e.tool === "get_persistence_keys");
  const PERSISTENCE_LOCATIONS = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved",
    "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
  ];
  if (regEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_registry_data", message: "No registry data available. Run get_persistence_keys first.", persistence_locations_to_check: PERSISTENCE_LOCATIONS, suggestion: { tool: "get_persistence_keys", reason: "Check all known persistence registry locations" } }) };
  }
  const foundPersistence: string[] = [];
  for (const entry of regEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    for (const loc of PERSISTENCE_LOCATIONS) {
      if (raw.toLowerCase().includes(loc.split("\\").pop()!.toLowerCase())) foundPersistence.push(loc);
    }
  }
  return { success: true, output: JSON.stringify({ result: "startup_check_complete", locations_checked: PERSISTENCE_LOCATIONS.length, findings: foundPersistence, checked_from_registry_entries: regEntries.length }) };
}

function handleCheckWmiPersistence(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory" || e.tool === "search_filename");
  const wmiPaths = ["OBJECTS.DATA", "MAPPING*.MAP", "INDEX.BTR", ".mof"];
  const found: string[] = [];
  for (const entry of fsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    for (const p of wmiPaths) {
      if (raw.includes(p.replace("*", ""))) found.push(p);
    }
  }
  return { success: true, output: JSON.stringify({ result: found.length > 0 ? "wmi_artifacts_found" : "no_wmi_artifacts", wmi_repository_files: found, wmi_paths: ["Windows/System32/wbem/Repository/"], check_for: ["EventFilter", "EventConsumer", "FilterToConsumerBinding"], suggestion: found.length === 0 ? { tool: "list_directory", params: { path: "/Windows/System32/wbem/Repository/" } } : { tool: "extract_file", reason: "Extract OBJECTS.DATA for WMI persistence analysis" } }) };
}

function handleCheckBitsJobs(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory" || e.tool === "search_filename");
  const bitsFiles = ["qmgr0.dat", "qmgr1.dat"];
  const found: string[] = [];
  for (const entry of fsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    for (const f of bitsFiles) { if (raw.includes(f)) found.push(f); }
  }
  return { success: true, output: JSON.stringify({ result: found.length > 0 ? "bits_queue_found" : "no_bits_queue", bits_files: found, default_path: "ProgramData/Microsoft/Network/Downloader/", analysis: "BITS transfer jobs can be used for data exfiltration or C2 download persistence", suggestion: found.length === 0 ? { tool: "list_directory", params: { path: "/ProgramData/Microsoft/Network/Downloader/" } } : { tool: "extract_file", reason: "Extract BITS queue file for analysis" } }) };
}

function handleCheckComHijacking(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const regEntries = ctx.ledgerEntries.filter(e => e.tool === "parse_registry_key");
  if (regEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_registry_data", message: "Need registry data to check COM hijacking.", suggestion: { tool: "parse_registry_key", params: { plugin: "clsid" }, reason: "Check CLSID InProcServer32 for hijacked COM objects" } }) };
  }
  const suspiciousClsids: string[] = [];
  for (const entry of regEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    const lines = raw.split("\n");
    for (const line of lines) {
      if (line.includes("InProcServer32") && (line.includes("\\Temp\\") || line.includes("\\AppData\\") || line.includes(".tmp"))) {
        suspiciousClsids.push(line.trim());
      }
    }
  }
  return { success: true, output: JSON.stringify({ result: suspiciousClsids.length > 0 ? "suspicious_com_objects" : "no_hijacking_detected", suspicious_entries: suspiciousClsids, check_locations: ["HKCR\\CLSID", "HKCU\\Software\\Classes\\CLSID"], indicators: ["InProcServer32 pointing to temp dirs", "DLL in user-writable locations", "Missing original Microsoft DLL"] }) };
}

function handleCheckDllSearchOrder(_params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory");
  const knownDllHijackTargets = ["version.dll", "cryptbase.dll", "dwmapi.dll", "uxtheme.dll", "propsys.dll", "ntmarta.dll", "secur32.dll", "profapi.dll"];
  const suspicious: string[] = [];
  for (const entry of fsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    for (const dll of knownDllHijackTargets) {
      if (raw.toLowerCase().includes(dll) && (raw.includes("Temp") || raw.includes("AppData") || raw.includes("Desktop"))) {
        suspicious.push(dll);
      }
    }
  }
  return { success: true, output: JSON.stringify({ result: suspicious.length > 0 ? "dll_hijack_candidates" : "no_hijacking_detected", suspicious_dlls: suspicious, known_targets: knownDllHijackTargets, technique: "T1574.001 - DLL Search Order Hijacking", analysis: "Known DLLs in unexpected locations (user dirs, temp) indicate potential hijacking" }) };
}

// ─── User Activity (in-process on cached filesystem data) ────────────────────

function handleUserActivityTool(tool: string, params: Record<string, unknown>, ctx: HandlerContext): HandlerResult {
  const fsEntries = ctx.ledgerEntries.filter(e => e.tool === "list_directory" || e.tool === "extract_file");
  const toolGuidance: Record<string, { paths: string[]; binary: string; description: string }> = {
    parse_lnk_files: { paths: ["Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/"], binary: "LECmd.dll", description: "Windows shortcut analysis: target paths, timestamps, volume serial numbers" },
    parse_jumplists: { paths: ["Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/", "Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/"], binary: "JLECmd.dll", description: "Jump list analysis: recent/frequent file access per application" },
    parse_shellbags: { paths: ["Users/<user>/NTUSER.DAT", "Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat"], binary: "SBECmd.dll", description: "Shell bag analysis: folder navigation history proving directory access" },
    parse_recycle_bin: { paths: ["$Recycle.Bin/"], binary: "RBCmd.dll", description: "Recycle bin analysis: deleted file recovery with original paths and timestamps" },
    parse_recent_docs: { paths: ["Users/<user>/NTUSER.DAT (RecentDocs key)"], binary: "rip.pl -p recentdocs", description: "Recent documents accessed via Office or Explorer" },
    parse_mru_lists: { paths: ["Users/<user>/NTUSER.DAT (TypedURLs, RunMRU, etc.)"], binary: "rip.pl -p typedurls", description: "Most Recently Used lists across all applications" },
    parse_rdp_cache: { paths: ["Users/<user>/AppData/Local/Microsoft/Terminal Server Client/Cache/"], binary: "bmc-tools.py", description: "RDP bitmap cache: screenshots of remote sessions" },
    parse_clipboard_history: { paths: ["Users/<user>/AppData/Local/Microsoft/Windows/Clipboard/"], binary: "N/A (SQLite DB)", description: "Windows clipboard history (Win10 1809+)" },
  };
  const guidance = toolGuidance[tool];
  if (!guidance) return { success: false, error: `Unknown user activity tool: ${tool}`, output: "" };

  if (fsEntries.length === 0) {
    return { success: true, output: JSON.stringify({ result: "no_filesystem_data", tool, description: guidance.description, required_paths: guidance.paths, binary_needed: guidance.binary, suggestion: { tool: "list_directory", params: { path: guidance.paths[0] }, reason: `Locate ${tool.replace("parse_", "")} artifacts` } }) };
  }

  // Check if relevant files are in cached filesystem data
  const relevantFiles: string[] = [];
  for (const entry of fsEntries) {
    const raw = ctx.rawOutputs.get(entry.id as string) ?? "";
    for (const p of guidance.paths) {
      const searchTerm = p.split("/").pop()?.replace("*", "") ?? "";
      if (searchTerm && raw.includes(searchTerm)) relevantFiles.push(searchTerm);
    }
  }

  if (relevantFiles.length > 0) {
    return { success: true, output: JSON.stringify({ result: "artifacts_located", tool, description: guidance.description, files_found: relevantFiles, next_step: `Extract with extract_file then parse. On SIFT: dotnet /opt/zimmermantools/${guidance.binary}`, binary_needed: guidance.binary }) };
  }

  return { success: true, output: JSON.stringify({ result: "artifacts_not_found", tool, description: guidance.description, expected_paths: guidance.paths, suggestion: { tool: "list_directory", params: { path: guidance.paths[0] }, reason: `Search for ${tool.replace("parse_", "")} artifacts` } }) };
}

// ─── Handler Registry ────────────────────────────────────────────────────────

const IN_PROCESS_HANDLERS: ReadonlyMap<string, HandlerFn> = new Map([
  // Anti-forensics (6 tools)
  ["detect_timestomping", handleDetectTimestomping],
  ["detect_log_clearing", handleDetectLogClearing],
  ["detect_secure_deletion", handleDetectSecureDeletion],
  ["detect_hidden_data", handleDetectHiddenData],
  ["detect_wiping_tools", handleDetectWipingTools],
  ["detect_anti_analysis", handleDetectAntiAnalysis],
  ["get_anti_forensics_summary", handleGetAntiForensicsSummary],

  // Correlation (7 tools)
  ["correlate_timeline_events", handleCorrelateTimelineEvents],
  ["build_attack_narrative", handleBuildAttackNarrative],
  ["detect_lateral_movement", handleDetectLateralMovement],
  ["map_mitre_techniques", handleMapMitreTechniques],
  ["get_investigation_summary", handleGetInvestigationSummary],
  ["export_timeline_of_compromise", handleExportTimelineOfCompromise],
  ["get_ioc_summary", handleGetIocSummary],

  // Event log in-process (5 tools)
  ["list_event_logs", handleListEventLogs],
  ["detect_log_gaps", handleDetectLogGaps],
  ["correlate_logon_events", handleCorrelateLogonEvents],
  ["detect_account_manipulation", handleDetectAccountManipulation],
  ["get_security_summary", handleGetSecuritySummary],

  // Browser (6 tools)
  ["parse_browser_history", (p, c) => handleBrowserTool("parse_browser_history", p, c)],
  ["parse_browser_downloads", (p, c) => handleBrowserTool("parse_browser_downloads", p, c)],
  ["parse_browser_cache", (p, c) => handleBrowserTool("parse_browser_cache", p, c)],
  ["parse_browser_cookies", (p, c) => handleBrowserTool("parse_browser_cookies", p, c)],
  ["parse_browser_extensions", (p, c) => handleBrowserTool("parse_browser_extensions", p, c)],
  ["parse_browser_saved_passwords", (p, c) => handleBrowserTool("parse_browser_saved_passwords", p, c)],

  // Linux (8 tools)
  ["parse_auth_log", (p, c) => handleLinuxTool("parse_auth_log", p, c)],
  ["parse_syslog", (p, c) => handleLinuxTool("parse_syslog", p, c)],
  ["parse_bash_history", (p, c) => handleLinuxTool("parse_bash_history", p, c)],
  ["parse_cron_jobs", (p, c) => handleLinuxTool("parse_cron_jobs", p, c)],
  ["parse_systemd_journal", (p, c) => handleLinuxTool("parse_systemd_journal", p, c)],
  ["parse_ssh_artifacts", (p, c) => handleLinuxTool("parse_ssh_artifacts", p, c)],
  ["check_linux_persistence", (p, c) => handleLinuxTool("check_linux_persistence", p, c)],
  ["parse_audit_log", (p, c) => handleLinuxTool("parse_audit_log", p, c)],

  // Persistence / User Activity (selected in-process)
  ["check_scheduled_tasks", handleCheckScheduledTasks],
  ["check_services", handleCheckServices],
  ["load_network_capture", handleLoadNetworkCapture],
  ["detect_beaconing", handleDetectBeaconing],
  // identify_memory_profile: handled by binary mapping (vol windows.info.Info)
  ["compare_timelines", handleCompareTimelines],
  ["detect_timeline_anomalies", handleDetectTimelineAnomalies],
  ["get_timeline_statistics", handleGetTimelineStatistics],

  // Registry hive discovery
  ["list_registry_hives", handleListRegistryHives],

  // parse_prefetch + parse_amcache: handled by binary mappings (PECmd, AmcacheParser)

  // Persistence checks (in-process logic)
  ["check_startup_locations", handleCheckStartupLocations],
  ["check_wmi_persistence", handleCheckWmiPersistence],
  ["check_bits_jobs", handleCheckBitsJobs],
  ["check_com_hijacking", handleCheckComHijacking],
  ["check_dll_search_order", handleCheckDllSearchOrder],

  // User Activity (all 8 tools)
  ["parse_lnk_files", (p, c) => handleUserActivityTool("parse_lnk_files", p, c)],
  ["parse_jumplists", (p, c) => handleUserActivityTool("parse_jumplists", p, c)],
  ["parse_shellbags", (p, c) => handleUserActivityTool("parse_shellbags", p, c)],
  ["parse_recycle_bin", (p, c) => handleUserActivityTool("parse_recycle_bin", p, c)],
  ["parse_recent_docs", (p, c) => handleUserActivityTool("parse_recent_docs", p, c)],
  ["parse_mru_lists", (p, c) => handleUserActivityTool("parse_mru_lists", p, c)],
  ["parse_rdp_cache", (p, c) => handleUserActivityTool("parse_rdp_cache", p, c)],
  ["parse_clipboard_history", (p, c) => handleUserActivityTool("parse_clipboard_history", p, c)],
]);

/** Check if a tool has an in-process handler */
export function hasInProcessHandler(tool: string): boolean {
  return IN_PROCESS_HANDLERS.has(tool);
}

/** Execute an in-process handler */
export function executeInProcess(tool: string, params: Record<string, unknown>, context: HandlerContext): HandlerResult | null {
  const handler = IN_PROCESS_HANDLERS.get(tool);
  if (!handler) return null;
  return handler(params, context);
}

// ─── Utility Functions ───────────────────────────────────────────────────────

function extractTimestamp(raw: string, section: string, field: string): number | null {
  // Match istat timestamp format: "2021-01-01 12:00:00 (UTC)" or ISO "2021-01-01T12:00:00Z"
  const sectionRegex = new RegExp(`\\$${section}[\\s\\S]*?${field}[:\\s]+([\\d\\-T:.Z+\\s]+?)(?:\\s*\\(|\\n|$)`, "i");
  const match = raw.match(sectionRegex);
  if (match?.[1]) {
    const cleaned = match[1].trim().replace(/\s*\(.*\)$/, "");
    const ts = Date.parse(cleaned);
    return isNaN(ts) ? null : ts;
  }
  return null;
}

function parseEventRecords(raw: string): EventRecord[] {
  const records: EventRecord[] = [];
  const lines = raw.split("\n");
  let eventId = 0;
  let recordId = 0;
  let timestamp = "";
  let channel = "";

  for (const line of lines) {
    const eidMatch = line.match(/Event\s*(?:ID|identifier):\s*(\d+)/i);
    if (eidMatch) eventId = parseInt(eidMatch[1]!);

    const ridMatch = line.match(/Record\s*(?:number|ID):\s*(\d+)/i);
    if (ridMatch) recordId = parseInt(ridMatch[1]!);

    const tsMatch = line.match(/(?:Date|Written|Time).*?:\s*(.+)/i);
    if (tsMatch) timestamp = tsMatch[1]!.trim();

    const chanMatch = line.match(/(?:Source|Channel).*?:\s*(.+)/i);
    if (chanMatch) channel = chanMatch[1]!.trim();

    // Record boundary
    if (line.trim() === "" && eventId) {
      if (recordId && timestamp && channel) {
        records.push({ eventId, recordId, timestamp, channel });
      }
      eventId = 0; recordId = 0; timestamp = ""; channel = "";
    }
  }

  // Don't forget last record
  if (eventId && recordId && timestamp && channel) {
    records.push({ eventId, recordId, timestamp, channel });
  }

  return records;
}

function parseLinuxLog(tool: string, raw: string): unknown {
  const lines = raw.split("\n").filter(l => l.trim());
  switch (tool) {
    case "parse_auth_log":
      return { entries: lines.slice(0, 100).map(l => ({ raw: l, has_sudo: l.includes("sudo"), has_ssh: l.includes("sshd"), has_failed: l.includes("Failed") })), total_lines: lines.length };
    case "parse_bash_history":
      return { commands: lines.slice(0, 200), total: lines.length };
    case "parse_cron_jobs":
      return { entries: lines.filter(l => !l.startsWith("#")).map(l => ({ raw: l })), total: lines.length };
    default:
      return { lines: lines.slice(0, 100), total: lines.length };
  }
}

function getEidDescription(eid: string): string {
  const map: Record<string, string> = {
    "4720": "User account created",
    "4722": "User account enabled",
    "4724": "Password reset attempt",
    "4732": "User added to security group",
    "4728": "User added to global group",
    "4756": "User added to universal group",
  };
  return map[eid] ?? `Event ID ${eid}`;
}

function getNotableEids(counts: Record<string, number>): Array<{ eid: string; count: number; significance: string }> {
  const notable: Array<{ eid: string; count: number; significance: string }> = [];
  const significanceMap: Record<string, string> = {
    "1102": "Audit log cleared",
    "4624": "Successful logon",
    "4625": "Failed logon",
    "4688": "Process creation",
    "4720": "Account created",
    "7045": "Service installed",
    "4697": "Service installed (legacy)",
  };
  for (const [eid, count] of Object.entries(counts)) {
    if (significanceMap[eid]) {
      notable.push({ eid, count, significance: significanceMap[eid]! });
    }
  }
  return notable.sort((a, b) => b.count - a.count);
}

function isSuspiciousServicePath(path: string): boolean {
  const suspicious = [/\\temp\\/i, /\\tmp\\/i, /\\appdata\\/i, /\\users\\.*\\desktop/i, /\\downloads\\/i, /cmd\.exe/i, /powershell/i, /mshta/i, /rundll32/i, /regsvr32/i];
  return suspicious.some(r => r.test(path));
}
