import crypto from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { CapabilityGraph, TOOL_SPECS, KERNEL_TOOLS } from "./domain/capability-graph.js";
import { FORENSIC_CATEGORIES, KERNEL_TOOL_NAMES, getCategoryDescription, getCategoryInputSchema, getCategoryOperations, resolveDispatch } from "./dispatcher.js";
import { ProgressiveDisclosure } from "./domain/progressive-disclosure.js";
import { MethodologyTracker } from "./domain/methodology.js";
import { createLedgerEntry, hashData, hashEntry, getGenesisHash } from "./domain/ledger.js";
import { createFinding, reassessFinding, findingsConflict, type RegisterFindingInput } from "./domain/finding.js";
import { createHypothesis, updateHypothesis } from "./domain/hypothesis.js";
import { SqliteLedgerStore } from "./adapters/sqlite-ledger.js";
import { ProcessExecutor } from "./adapters/process-executor.js";
import { FileRawOutputStore } from "./adapters/file-raw-output.js";
import { FsEvidenceStore } from "./adapters/fs-evidence.js";
import { ForensicReasoningEngine, computeCorrelationGraph } from "./reasoning/index.js";
import type { FindingForCorrelation } from "./reasoning/index.js";
import type { LedgerEntryId, Finding, Hypothesis, ArtifactCategory, Capability } from "./domain/types.js";
import { join } from "node:path";
import { mkdirSync, writeFileSync } from "node:fs";
import { parseToolOutput as parseToolRaw } from "./parsers/index.js";
import type { AnomalyFlag } from "./parsers/index.js";
import { hasInProcessHandler, executeInProcess, type HandlerContext } from "./handlers/in-process.js";

// HTML entity escaping for evidence-derived content (H4 fix — prevents XSS from attacker-controlled filenames)
function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ─── Configuration ───────────────────────────────────────────────────────────

export interface ServerConfig {
  readonly evidencePath: string;
  readonly memoryPath?: string | undefined;
  readonly outputPath: string;
  readonly dbPath: string;
  readonly sudo?: boolean | undefined;
  readonly allTools?: boolean | undefined;
}

// ─── Tool Input Schemas ──────────────────────────────────────────────────────

function getToolInputSchema(tool: string): Record<string, unknown> {
  const schemas: Record<string, Record<string, unknown>> = {
    mount_evidence: { type: "object", properties: { image_path: { type: "string", description: "Path to forensic image (E01/raw/dd/VMDK/AFF4)" }, partition_index: { type: "number", description: "Partition index to mount (from list_partitions)" } }, required: ["image_path"] },
    verify_integrity: { type: "object", properties: { algorithm: { type: "string", enum: ["sha256", "md5", "sha1"], description: "Hash algorithm" } }, required: [] },
    get_image_metadata: { type: "object", properties: {}, required: [] },
    list_partitions: { type: "object", properties: {}, required: [] },
    get_filesystem_info: { type: "object", properties: { partition_index: { type: "number" } }, required: [] },
    list_directory: { type: "object", properties: { path: { type: "string", description: "Directory path within image" }, recursive: { type: "boolean" }, show_deleted: { type: "boolean" } }, required: ["path"] },
    extract_file: { type: "object", properties: { inode: { type: "number" }, output_name: { type: "string" } }, required: ["inode"] },
    search_filename: { type: "object", properties: { pattern: { type: "string", description: "Regex pattern to match" }, path: { type: "string", description: "Subtree path to search within (e.g. /Windows/Prefetch). Omit for full image." }, case_sensitive: { type: "boolean" } }, required: ["pattern"] },
    get_file_metadata: { type: "object", properties: { inode: { type: "number" } }, required: ["inode"] },
    recover_deleted: { type: "object", properties: { output_dir: { type: "string" } }, required: [] },
    carve_files: { type: "object", properties: { file_types: { type: "array", items: { type: "string" } } }, required: [] },
    analyze_unallocated: { type: "object", properties: { output_dir: { type: "string" } }, required: [] },
    extract_strings: { type: "object", properties: { path: { type: "string" }, min_length: { type: "number" }, encoding: { type: "string", enum: ["ascii", "unicode", "both"] } }, required: ["path"] },
    parse_usnjrnl: { type: "object", properties: { time_range: { type: "object", properties: { start: { type: "string" }, end: { type: "string" } } } }, required: [] },
    generate_timeline: { type: "object", properties: { parsers: { type: "array", items: { type: "string" } }, time_range: { type: "object", properties: { start: { type: "string" }, end: { type: "string" } } } }, required: [] },
    filter_timeline: { type: "object", properties: { start: { type: "string" }, end: { type: "string" }, source_type: { type: "string" }, keyword: { type: "string" }, limit: { type: "number" } }, required: [] },
    detect_timeline_anomalies: { type: "object", properties: {}, required: [] },
    get_timeline_context: { type: "object", properties: { timestamp: { type: "string" }, window_minutes: { type: "number" } }, required: ["timestamp"] },
    compare_timelines: { type: "object", properties: { range_a: { type: "object", properties: { start: { type: "string" }, end: { type: "string" } } }, range_b: { type: "object", properties: { start: { type: "string" }, end: { type: "string" } } } }, required: ["range_a", "range_b"] },
    get_timeline_statistics: { type: "object", properties: {}, required: [] },
    activate_workflow: { type: "object", properties: { workflow: { type: "string", description: "Workflow ID to activate (use list_workflows to see options)" } }, required: ["workflow"] },
    deactivate_workflow: { type: "object", properties: { workflow: { type: "string", description: "Workflow ID to deactivate" } }, required: ["workflow"] },
    list_workflows: { type: "object", properties: {}, required: [] },
    suggest_next_action: { type: "object", properties: {}, required: [] },
    get_investigation_state: { type: "object", properties: {}, required: [] },
    get_coverage_gaps: { type: "object", properties: { limit: { type: "number", description: "Max gaps to return" } }, required: [] },
    get_methodology_coverage: { type: "object", properties: {}, required: [] },
    register_finding: { type: "object", properties: { type: { type: "string", enum: ["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "lateral_movement", "collection", "command_and_control", "exfiltration", "impact", "anti_forensics", "anomaly", "ioc"] }, description: { type: "string" }, evidence: { type: "array", items: { type: "string" }, minItems: 1, description: "Ledger entry IDs that support this finding (at least one required)" }, temporal_range: { type: "object", properties: { start: { type: "string" }, end: { type: "string" } } }, mitre_technique: { type: "string" }, mitre_tactic: { type: "string" }, affected_hosts: { type: "array", items: { type: "string" } }, iocs: { type: "array", items: { type: "object", properties: { type: { type: "string" }, value: { type: "string" } } } }, supports_hypotheses: { type: "array", items: { type: "string" } }, contradicts_hypotheses: { type: "array", items: { type: "string" } } }, required: ["type", "description", "evidence"] },
    register_hypothesis: { type: "object", properties: { description: { type: "string" } }, required: ["description"] },
    generate_report: { type: "object", properties: { min_confidence: { type: "string", enum: ["HYPOTHESIZED", "INFERRED", "SUPPORTED", "CONFIRMED"] }, format: { type: "string", enum: ["markdown", "json", "html"], description: "Output format: markdown (.md file), json (.json file), or html (interactive standalone .html file with PDF export button). All formats save to the output directory." } }, required: [] },
    verify_chain: { type: "object", properties: {}, required: [] },
    get_investigation_health: { type: "object", properties: {}, required: [] },
    get_confidence_summary: { type: "object", properties: {}, required: [] },
    get_unsupported_findings: { type: "object", properties: {}, required: [] },
    get_contradictions: { type: "object", properties: {}, required: [] },
    get_hypothesis_status: { type: "object", properties: {}, required: [] },
    reassess_finding: { type: "object", properties: { finding_id: { type: "string" }, additional_evidence: { type: "array", items: { type: "string" } } }, required: ["finding_id", "additional_evidence"] },
    trace_provenance: { type: "object", properties: { finding_id: { type: "string" } }, required: ["finding_id"] },
    get_questions_to_investigate: { type: "object", properties: {}, required: [] },
    corroborate_finding: { type: "object", properties: { finding_id: { type: "string" } }, required: ["finding_id"] },
    challenge_finding: { type: "object", properties: { finding_id: { type: "string" } }, required: ["finding_id"] },
    export_audit_log: { type: "object", properties: { format: { type: "string", enum: ["json", "csv"] } }, required: [] },
    reset_investigation: { type: "object", properties: {}, required: [] },
    get_job_status: { type: "object", properties: { job_id: { type: "string", description: "Job ID to check status for. Omit to list all jobs." } }, required: [] },
    get_investigation_protocol: { type: "object", properties: {}, required: [] },
  };

  return schemas[tool] ?? { type: "object", properties: { path: { type: "string" } }, required: [] };
}

// ─── Output Schema (MCP 2025 spec feature) ───────────────────────────────────

function getToolOutputSchema(tool: string): { type: "object"; properties: Record<string, unknown>; required?: string[] } {
  // All forensic tools return a standard enriched response envelope
  const forensicOutput = {
    type: "object" as const,
    properties: {
      result: { type: "object", description: "Structured analysis data (tool-specific)" },
      anomalies_detected: { type: "array", items: { type: "object", properties: { type: { type: "string" }, severity: { type: "string" }, description: { type: "string" }, evidence: { type: "array", items: { type: "string" } } } } },
      suggested_next_actions: { type: "array", items: { type: "object", properties: { tool: { type: "string" }, reason: { type: "string" }, priority: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] } } } },
      progress: { type: "object", properties: { phase: { type: "string" }, overall_coverage: { type: "number" }, category_coverage: { type: "object" } } },
      ledger_entry_id: { type: "string", description: "Hash-chained evidence ledger entry ID for audit trail" },
    },
    required: ["result", "ledger_entry_id"],
  };

  // Meta-cognitive tools have their own schemas
  const metaSchemas: Record<string, { type: "object"; properties: Record<string, unknown>; required?: string[] }> = {
    suggest_next_action: { type: "object", properties: { suggestion: { type: "object", properties: { tool: { type: "string" }, reason: { type: "string" }, priority: { type: "string" } } }, methodology_phase: { type: "object", properties: { id: { type: "string" }, name: { type: "string" }, description: { type: "string" }, order: { type: "string" } } }, phase_progress: { type: "array" }, top_gaps: { type: "array" }, overall_coverage: { type: "number" } }, required: ["suggestion"] },
    get_investigation_state: { type: "object", properties: { phase: { type: "string" }, capabilities_held: { type: "array", items: { type: "string" } }, active_workflows: { type: "array" }, tool_count: { type: "number" } }, required: ["phase"] },
    get_coverage_gaps: { type: "object", properties: { gaps: { type: "array", items: { type: "object", properties: { category: { type: "string" }, priority: { type: "string" }, significance: { type: "string" } } } } }, required: ["gaps"] },
    get_confidence_summary: { type: "object", properties: { confirmed: { type: "number" }, supported: { type: "number" }, inferred: { type: "number" }, hypothesized: { type: "number" }, total: { type: "number" } }, required: ["total"] },
    get_investigation_health: { type: "object", properties: { health: { type: "string", enum: ["POOR", "FAIR", "GOOD", "EXCELLENT"] }, coverage_pct: { type: "number" }, recommendations: { type: "array", items: { type: "string" } } }, required: ["health"] },
    get_methodology_coverage: { type: "object", properties: { categories: { type: "array", items: { type: "object", properties: { category: { type: "string" }, coverage_pct: { type: "number" }, tools_used: { type: "number" }, tools_total: { type: "number" } } } } }, required: ["categories"] },
    register_finding: { type: "object", properties: { success: { type: "boolean" }, finding_id: { type: "string" }, confidence: { type: "string", enum: ["HYPOTHESIZED", "INFERRED", "SUPPORTED", "CONFIRMED"] } }, required: ["success", "finding_id", "confidence"] },
    register_hypothesis: { type: "object", properties: { hypothesis_id: { type: "string" }, description: { type: "string" } }, required: ["hypothesis_id"] },
    generate_report: { type: "object", properties: { report: { type: "object" } }, required: ["report"] },
    verify_chain: { type: "object", properties: { valid: { type: "boolean" }, entry_count: { type: "number" } }, required: ["valid"] },
    activate_workflow: { type: "object", properties: { activated: { type: "string" }, new_tools: { type: "array", items: { type: "string" } }, total_visible: { type: "number" } } },
    deactivate_workflow: { type: "object", properties: { deactivated: { type: "string" }, removed_tools: { type: "array", items: { type: "string" } }, total_visible: { type: "number" } } },
    list_workflows: { type: "object", properties: { workflows: { type: "array" }, active_count: { type: "number" }, visible_tool_count: { type: "number" } } },
  };

  return metaSchemas[tool] ?? forensicOutput;
}

// ─── Parser Dispatch ─────────────────────────────────────────────────────────

function parseToolOutput(tool: string, raw: string): { parsed: unknown; anomalies: AnomalyFlag[] } {
  const result = parseToolRaw(tool, raw);
  if (result.isOk()) {
    return { parsed: result.value.data, anomalies: [...result.value.anomalies] };
  }
  // Parser failed or no parser exists — return raw
  return { parsed: { raw_output: raw }, anomalies: [] };
}

// ─── Tool-to-Binary Mapping ──────────────────────────────────────────────────

interface BinaryMapping {
  binary: string;
  buildArgs: (params: Record<string, unknown>, evidencePath: string, offset: number, outputPath: string) => string[];
}

function getToolBinaryMapping(tool: string, partitionOffset: number): BinaryMapping | null {
  // Binary names verified against SIFT Workstation (Protocol SIFT skills + apt packages)
  const mappings: Record<string, BinaryMapping> = {
    // ── Sleuth Kit (apt: sleuthkit) ──
    // All TSK tools use: <tool> -o <offset> <image> [inode]
    // offset comes from investigationState.partitionOffset (detected by mmls or default 0)
    list_directory: { binary: "fls", buildArgs: (p, ev, off) => [...(p["recursive"] ? ["-r"] : []), "-l", "-p", ...(p["show_deleted"] ? ["-d"] : []), "-o", String(off), ev, ...(p["inode"] ? [String(p["inode"])] : [])] },
    list_partitions: { binary: "mmls", buildArgs: (_, ev) => [ev] },
    get_file_metadata: { binary: "istat", buildArgs: (p, ev, off) => ["-o", String(off), ev, String(p["inode"])] },
    extract_file: { binary: "icat", buildArgs: (p, ev, off) => ["-o", String(off), ev, String(p["inode"])] },
    search_filename: { binary: "fls", buildArgs: (p, ev, off) => {
      const args = ["-r", "-l", "-p", "-o", String(off), ev];
      const startInode = (p["start_inode"] ?? p["inode"]) as string | undefined;
      if (startInode) args.push(startInode);
      return args;
    } },
    recover_deleted: { binary: "tsk_recover", buildArgs: (p, ev, off, out) => ["-o", String(off), "-e", ev, `${out}/recovered/`] },
    get_filesystem_info: { binary: "fsstat", buildArgs: (_, ev, off) => ["-o", String(off), ev] },
    get_image_metadata: { binary: "img_stat", buildArgs: (_, ev) => [ev] },

    // ── Carving (apt: foremost, scalpel, bulk-extractor) ──
    carve_files: { binary: "foremost", buildArgs: (p, ev, _off, out) => ["-o", `${out}/carved/`, ...(p["file_types"] ? ["-t", (p["file_types"] as string[]).join(",")] : []), "-i", ev] },
    analyze_unallocated: { binary: "bulk_extractor", buildArgs: (_, ev, _off, out) => ["-o", `${out}/be_out/`, ev] },
    extract_strings: { binary: "strings", buildArgs: (p, _, _o3, out) => ["-a", ...(p["encoding"] === "unicode" ? ["-el"] : p["encoding"] === "both" ? ["-el", "-a"] : []), ...(p["min_length"] ? ["-n", String(p["min_length"])] : []), String(p["path"] ?? "")] },

    // ── Plaso (pip: plaso, binaries: log2timeline, psort) ──
    generate_timeline: { binary: "log2timeline", buildArgs: (p, ev, _off, out) => [...(p["parsers"] ? ["--parsers", (p["parsers"] as string[]).join(",")] : []), "--status_view", "none", "--storage_file", `${out}/timeline.plaso`, ev] },
    filter_timeline: { binary: "psort", buildArgs: (p, _, _o4, out) => ["-o", "l2tcsv", ...(p["start"] ? ["--slice", `${p["start"]}`] : []), "--storage_file", `${out}/timeline.plaso`] },
    get_timeline_context: { binary: "psort", buildArgs: (p, _, _o5, out) => ["-o", "l2tcsv", "--slice", String(p["timestamp"] ?? ""), "--slice_size", String(p["window_minutes"] ?? 5), "--storage_file", `${out}/timeline.plaso`] },

    // ── Event Logs (evtx_dump from cargo, or evtxexport from libevtx-utils) ──
    parse_event_log: { binary: "evtx_dump", buildArgs: (p, _) => ["-o", "jsonl", String(p["path"] ?? "")] },
    search_events: { binary: "evtx_dump", buildArgs: (p, _) => ["-o", "jsonl", String(p["path"] ?? "")] },
    parse_powershell_logs: { binary: "evtx_dump", buildArgs: (p, _) => ["-o", "jsonl", String(p["path"] ?? "")] },

    // ── YARA (apt: yara) ──
    scan_yara: { binary: "yara", buildArgs: (p, ev) => ["-r", "-p", "4", String(p["rules"] ?? "/usr/share/yara/rules"), ev] },

    // ── Network (apt: wireshark-common provides tshark) ──
    parse_pcap_summary: { binary: "tshark", buildArgs: (p, _) => ["-r", String(p["path"] ?? ""), "-q", "-z", "conv,tcp"] },
    extract_connections: { binary: "tshark", buildArgs: (p, _) => ["-r", String(p["path"] ?? ""), "-q", "-z", "conv,ip"] },
    search_pcap: { binary: "tshark", buildArgs: (p, _) => ["-r", String(p["path"] ?? ""), "-Y", String(p["filter"] ?? ""), "-T", "json", "-l"] },
    extract_files_from_pcap: { binary: "tshark", buildArgs: (p, ev) => ["-r", String(p["path"] ?? ""), "--export-objects", `http,${ev || "/tmp"}/pcap_export/`] },
    extract_dns_queries: { binary: "tshark", buildArgs: (p, _) => ["-r", String(p["path"] ?? ""), "-q", "-z", "dns,tree"] },
    extract_http_traffic: { binary: "tshark", buildArgs: (p, _) => ["-r", String(p["path"] ?? ""), "-Y", "http", "-T", "fields", "-e", "http.request.method", "-e", "http.request.uri", "-e", "http.host"] },

    // ── Hashing (apt: hashdeep, md5deep, ssdeep) ──
    verify_integrity: { binary: "ewfverify", buildArgs: (p, ev) => [ev] },
    hash_and_lookup: { binary: "hashdeep", buildArgs: (p, _) => ["-r", "-csha256", String(p["path"] ?? "")] },

    // ── Volatility 3 (binary: vol) ──
    identify_memory_profile: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.info.Info"] },
    list_processes: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.pslist.PsList"] },
    detect_process_injection: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.malfind.Malfind"] },
    list_network_connections: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.netscan.NetScan"] },
    detect_rootkit: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.ssdt.SSDT"] },
    dump_process: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "windows.dumpfiles.DumpFiles", "--pid", String(p["pid"] ?? 0)] },
    get_command_history: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.cmdline.CmdLine"] },
    scan_memory_yara: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "yarascan.YaraScan", "--yara-file", String(p["rules"] ?? "")] },
    list_handles: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.handles.Handles", ...(p["pid"] ? ["--pid", String(p["pid"])] : [])] },
    analyze_privileges: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.privileges.Privs"] },
    list_kernel_drivers: { binary: "vol", buildArgs: (p, ev) => ["-f", String(p["memory_path"] ?? ev), "--output", "json", "windows.driverscan.DriverScan"] },

    // ── Registry (regipy-plugins-run from pip, or rip.pl from regripper) ──
    // Plugin names verified against regipy 6.2.1 plugin registry. `path` is the
    // extracted host-path hive (auto-extracted from the image before execution).
    parse_registry_key: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", String(p["plugin"] ?? ""), String(p["path"] ?? "")] },
    get_user_activity: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "user_assist,recentdocs,typed_paths,typed_urls,runmru,word_wheel_query", String(p["path"] ?? "")] },
    get_system_config: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "computer_name,timezone_data,host_domain_name,shutdown,active_control_set", String(p["path"] ?? "")] },
    get_persistence_keys: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "ntuser_persistence,image_file_execution_options,appinit_dlls,appcert_dlls,services", String(p["path"] ?? "")] },
    get_installed_software: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "installed_programs_ntuser,installed_programs_software", String(p["path"] ?? "")] },
    get_usb_history: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "usbstor_plugin,usb_devices,mounted_devices", String(p["path"] ?? "")] },
    get_network_config: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "network_data,networklist,routes,network_drives_plugin", String(p["path"] ?? "")] },
    parse_sam: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "samparse,local_sid,domain_sid,last_logon_plugin", String(p["path"] ?? "")] },
    // shimcache: handled by AppCompatCacheParser (Zimmerman) below
    parse_bam: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "background_activity_moderator", String(p["path"] ?? "")] },
    parse_muicache: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "muicache", String(p["path"] ?? "")] },
    parse_userassist: { binary: "regipy-plugins-run", buildArgs: (p, _, _o, out) => ["-o", `${out}/regipy_out.json`, "-p", "user_assist", String(p["path"] ?? "")] },

    // ── ESE Database tools (apt: libesedb-utils) — for SRUM ──
    parse_srum: { binary: "esedbexport", buildArgs: (p, _, _o2, out) => ["-t", `${out}/srum_export/`, String(p["path"] ?? "")] },

    // ── USN Journal ──
     parse_usnjrnl: { binary: "MFTECmd", buildArgs: (p, _, _o, out) => ["-f", String(p["path"] ?? ""), "--csv", out] },

     // ── Zimmerman .NET Tools (execution artifacts, user activity) ──
     parse_prefetch: { binary: "PECmd", buildArgs: (p, _, _o, out) => ["-d", String(p["path"] ?? "/Windows/Prefetch"), "--csv", out, "-q"] },
     parse_amcache: { binary: "AmcacheParser", buildArgs: (p, _, _o, out) => ["-f", String(p["path"] ?? ""), "--csv", out] },
     parse_shimcache: { binary: "AppCompatCacheParser", buildArgs: (p, _, _o, out) => ["-f", String(p["path"] ?? ""), "--csv", out] },
     parse_lnk_files: { binary: "LECmd", buildArgs: (p, _, _o, out) => ["-d", String(p["path"] ?? ""), "--csv", out, "-q"] },
     parse_jumplists: { binary: "JLECmd", buildArgs: (p, _, _o, out) => ["-d", String(p["path"] ?? ""), "--csv", out, "-q"] },
     parse_shellbags: { binary: "SBECmd", buildArgs: (p, _, _o, out) => ["-d", String(p["path"] ?? ""), "--csv", out] },
     parse_recycle_bin: { binary: "RBCmd", buildArgs: (p, _, _o, out) => ["-d", String(p["path"] ?? ""), "--csv", out, "-q"] },
   };
   return mappings[tool] ?? null;
}

// ─── Create Server ───────────────────────────────────────────────────────────

export function createSiftKernelServer(config: ServerConfig) {
  const server = new Server(
    { name: "sift-kernel", version: "1.0.0" },
    { capabilities: { tools: { listChanged: true }, resources: {}, prompts: {} } },
  );

  // ── Forensic Knowledge Enrichment ──
  // Tool-specific caveats, corroboration suggestions, and interpretation guidance
  // Delivered at response level (like Valhuntir's FK package) so context arrives when the LLM needs it
  const FORENSIC_GUIDANCE: Record<string, { caveat: string; corroborate_with: string }> = {
    list_directory: { caveat: "Timestamps in directory listings reflect MFT metadata. Attackers commonly timestomp $STANDARD_INFORMATION — always cross-check with $FILE_NAME timestamps via get_file_metadata.", corroborate_with: "get_file_metadata for timestamp validation, search_filename for hidden/alternate data streams" },
    search_filename: { caveat: "Filename search covers allocated MFT entries. Deleted files may not appear unless show_deleted is set. Attackers rename tools to blend in (svchost.exe in wrong dir, etc).", corroborate_with: "get_file_metadata to check timestamps and size, scan_yara for content-based detection" },
    get_file_metadata: { caveat: "$STANDARD_INFORMATION timestamps are easily modified. Compare with $FILE_NAME timestamps — if $SI.Created < $FN.Created, timestomping likely occurred.", corroborate_with: "detect_timestomping for systematic analysis, parse_usnjrnl for change journal evidence" },
    parse_prefetch: { caveat: "Prefetch shows execution evidence but can be deleted/disabled by attackers. Absence of prefetch does NOT mean non-execution. Check amcache/shimcache as corroboration.", corroborate_with: "parse_amcache (hash-based execution evidence), parse_shimcache (registry-based)" },
    parse_amcache: { caveat: "Amcache records SHA1 hashes at install time. Hash may differ from current file if modified post-install. Cross-reference with shimcache for execution timeline.", corroborate_with: "parse_prefetch (execution count/timing), hash_and_lookup (current file hash vs known malware)" },
    parse_shimcache: { caveat: "ShimCache proves a file EXISTED — not that it executed (entry created on file metadata access). Verify with prefetch or Sysmon EID 1.", corroborate_with: "parse_prefetch (proves execution), parse_event_log (Sysmon process creation)" },
    get_persistence_keys: { caveat: "Registry persistence is one vector. Also check scheduled tasks, services, WMI subscriptions, startup folders, COM hijacks, and DLL search order.", corroborate_with: "check_scheduled_tasks, check_services, check_wmi_persistence, check_startup_locations" },
    parse_event_log: { caveat: "Event logs can be cleared (EID 1102 in Security). Check for time gaps. Sysmon is more tamper-resistant. Correlation across multiple log sources increases confidence.", corroborate_with: "detect_log_gaps (identifies clearing), correlate_logon_events (session reconstruction)" },
    detect_timestomping: { caveat: "SI/FN timestamp mismatch is strong indicator but not proof. Some legitimate operations (file copy, defrag) can cause discrepancies. Look for patterns across multiple files.", corroborate_with: "parse_usnjrnl (change journal shows true modification times), get_file_metadata" },
    detect_log_clearing: { caveat: "Missing event log ranges could indicate clearing OR simply log rotation. Check Security log for EID 1102/1100. Compare expected event density with actual.", corroborate_with: "parse_event_log (look for EID 1102), detect_timestomping (cleared + timestomped = deliberate)" },
    scan_yara: { caveat: "YARA signatures detect KNOWN patterns. Novel/custom malware may not match any rule. Combine with behavioral analysis (persistence, network callbacks).", corroborate_with: "check_startup_locations (behavioral persistence), detect_beaconing (C2 callbacks)" },
    list_processes: { caveat: "Process listing shows point-in-time state at acquisition. Processes can be hidden via DKOM. Check for process injection and orphaned threads.", corroborate_with: "detect_process_injection (malfind), detect_rootkit (SSDT/IDT hooks)" },
    detect_beaconing: { caveat: "Regular intervals suggest C2, but could also be legitimate polling (updates, telemetry). Check destination reputation and payload content.", corroborate_with: "extract_dns_queries (domain reputation), extract_http_traffic (payload inspection)" },
    generate_timeline: { caveat: "Super timeline is synthesis tool — it combines evidence from multiple sources. Most powerful AFTER individual artifact analysis to connect findings chronologically.", corroborate_with: "filter_timeline with specific time windows around known events" },
    build_attack_narrative: { caveat: "Narrative should follow evidence chain. Every claim must trace to a registered finding with evidence links. Avoid speculation without corroboration.", corroborate_with: "verify_chain (ensure all findings are grounded), get_confidence_summary" },
  };

  function getForensicContext(toolName: string, hasAnomalies: boolean): { guidance: string; corroboration: string } | undefined {
    const guidance = FORENSIC_GUIDANCE[toolName];
    if (!guidance) return undefined;
    return {
      guidance: hasAnomalies
        ? `⚠️ ANOMALIES DETECTED — ${guidance.caveat}`
        : guidance.caveat,
      corroboration: guidance.corroborate_with,
    };
  }

  // ── Infrastructure ──
  mkdirSync(config.outputPath, { recursive: true });
  const ledgerStore = new SqliteLedgerStore(config.dbPath);
  const executor = new ProcessExecutor(config.outputPath, config.sudo ?? false);
  const rawStore = new FileRawOutputStore(join(config.outputPath, "raw"));
  const evidenceStore = new FsEvidenceStore(config.outputPath);

  // ── Domain State ──
  const capabilityGraph = new CapabilityGraph();
  const methodology = new MethodologyTracker();
  const disclosure = new ProgressiveDisclosure();
  const reasoningEngine = new ForensicReasoningEngine();
  const findings: Map<string, Finding> = new Map();
  const hypotheses: Map<string, Hypothesis> = new Map();

  // ── Shared Investigation State ──
  // Written by mount_evidence, read by all forensic tools.
  // Single source of truth for evidence access.
  const investigationState = {
    imagePath: config.evidencePath || "",
    partitionOffset: 0,               // From mmls; 0 for single-partition images
    accessMode: "raw" as "raw" | "mounted",
    mountPoint: "",
    imageFormat: "",
    // Evidence type detection — drives which methodology baseline applies
    evidenceType: "unknown" as "disk-windows" | "disk-linux" | "disk-macos" | "memory" | "pcap" | "unknown",
    filesystemType: "" as string,  // NTFS, ext4, APFS, etc.
  };

  // Session-stable HMAC key (H3 fix) — env var for production, session-persistent fallback for dev
  const sessionHmacKey = process.env["SIFT_KERNEL_HMAC_SECRET"]
    || crypto.randomBytes(32).toString("hex");

  // Determinism tracker (Gruber & Hilgert 2026, arXiv:2604.05589)
  // Measures how closely the LLM follows server recommendations vs deviating
  const determinismTracker = {
    lastRecommendedTool: null as string | null,
    totalRecommendations: 0,
    followed: 0,
    deviated: 0,
    getScore(): number { return this.totalRecommendations === 0 ? 1.0 : this.followed / this.totalRecommendations; },
  };

  // Async job store for long-running tools (timeline, carving, bulk analysis)
  const asyncJobs = new Map<string, { status: "running" | "completed" | "failed"; tool: string; startedAt: string; result?: string; error?: string; outputPath?: string }>();

  // Tools that genuinely take minutes — run async, return job_id for polling
  const ASYNC_TOOLS = new Set(["generate_timeline", "carve_files", "analyze_unallocated", "recover_deleted"]);

  // Wire progressive disclosure notifications
  disclosure.setOnToolsChanged(() => {
    server.notification({ method: "notifications/tools/list_changed" });
  });

  // ─── Tool Definitions (Progressive Disclosure) ─────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools: Array<Record<string, unknown>> = [];

    // ── Kernel tools (always visible, direct call) ──
    for (const toolName of KERNEL_TOOL_NAMES) {
      const spec = TOOL_SPECS.find(s => s.tool === toolName);
      if (!spec && toolName !== "get_investigation_protocol" && toolName !== "activate_workflow" && toolName !== "deactivate_workflow" && toolName !== "list_workflows") continue;
      const description = spec?.description ?? toolName;
      tools.push({
        name: toolName,
        description,
        inputSchema: getToolInputSchema(toolName),
        annotations: {
          readOnlyHint: toolName !== "mount_evidence" && toolName !== "reset_investigation",
          destructiveHint: toolName === "reset_investigation",
        },
      });
    }

    // ── Category dispatcher tools (one per forensic workflow) ──
    for (const category of FORENSIC_CATEGORIES) {
      tools.push({
        name: category,
        description: getCategoryDescription(category),
        inputSchema: getCategoryInputSchema(category),
        annotations: { readOnlyHint: true, destructiveHint: false },
      });
    }

    return { tools };
  });

  // ─── Tool Call Handler ─────────────────────────────────────────────────────

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    let { name, arguments: params } = request.params;
    let toolParams = (params ?? {}) as Record<string, unknown>;

    // ── Category Dispatcher: route category(operation, ...) → internal tool ──
    if ((FORENSIC_CATEGORIES as readonly string[]).includes(name)) {
      const operation = toolParams["operation"] as string | undefined;
      if (!operation) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "MISSING_OPERATION", message: `Category '${name}' requires an 'operation' parameter. Available: ${getCategoryOperations(name as ArtifactCategory).join(", ")}` }) }], isError: true };
      }
      const internalTool = resolveDispatch(name, operation);
      if (!internalTool) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "INVALID_OPERATION", message: `Operation '${operation}' not found in category '${name}'. Available: ${getCategoryOperations(name as ArtifactCategory).join(", ")}` }) }], isError: true };
      }
      // Rewrite the call to the internal tool name, passing remaining params
      name = internalTool;
      const { operation: _op, ...rest } = toolParams;
      toolParams = rest;
    }

    // ── Workflow Management (always available) ──
    if (name === "activate_workflow") {
      const result = disclosure.activate(toolParams["workflow"] as string);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }

    if (name === "deactivate_workflow") {
      const result = disclosure.deactivate(toolParams["workflow"] as string);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }

    if (name === "list_workflows") {
      const workflows = disclosure.listWorkflows(capabilityGraph.getHeld());
      return { content: [{ type: "text" as const, text: JSON.stringify({ hint: "Each workflow is a callable category tool. Call category(operation='...') to use any operation within it.", workflows, total_tools: TOOL_SPECS.length }) }] };
    }

    // ── Investigation Protocol (the "skill" — CALL THIS FIRST) ──
    if (name === "get_investigation_protocol") {
      return { content: [{ type: "text" as const, text: `# SIFT Kernel Investigation Protocol

## How to use this MCP server

This server exposes forensic analysis through CATEGORY tools. Each category groups related operations.

**To call a forensic operation:**
  category_name(operation="operation_name", ...params)

Example: filesystem(operation="list_directory", path="/Windows/Prefetch")
Example: registry(operation="get_persistence_keys")
Example: anti_forensics(operation="detect_timestomping", path="/Windows")

**Kernel tools** (mount_evidence, verify_integrity, suggest_next_action, register_finding, etc.) are called directly by name.

## The Investigation Loop

1. mount_evidence(image_path) — Load the disk image
2. verify_integrity() — Verify image hash (unlocks analysis)
3. suggest_next_action() — Server tells you EXACTLY what to call next (includes category + operation)
4. Call the suggested operation via its category dispatcher
5. register_finding(type, description, evidence=[ledger_entry_ids]) when you find something
6. get_coverage_gaps() every 3-5 calls to check what's missed
7. generate_report(format="html") ONLY when suggest_next_action returns investigation_status="READY_FOR_REPORT". The methodology FSM determines readiness, not an arbitrary threshold.

## Categories

| Category | Operations |
|----------|-----------|
| acquisition | get_image_metadata, list_partitions, get_filesystem_info |
| filesystem | list_directory, extract_file, search_filename, get_file_metadata, recover_deleted, carve_files, analyze_unallocated, extract_strings, parse_usnjrnl |
| timeline | generate_timeline, filter_timeline, detect_timeline_anomalies, get_timeline_context |
| registry | list_registry_hives, parse_registry_key, get_user_activity, get_system_config, get_persistence_keys, get_installed_software, get_usb_history, get_network_config, parse_sam |
| event_logs | list_event_logs, parse_event_log, search_events, detect_log_gaps, correlate_logon_events, parse_powershell_logs, detect_account_manipulation |
| execution_artifacts | parse_prefetch, parse_amcache, parse_shimcache, parse_srum, parse_bam, parse_muicache, parse_userassist |
| persistence | scan_yara, check_scheduled_tasks, check_services, check_startup_locations, check_wmi_persistence, check_bits_jobs, check_com_hijacking, check_dll_search_order, hash_and_lookup |
| memory | identify_memory_profile, list_processes, detect_process_injection, list_network_connections, dump_process, get_command_history, scan_memory_yara, detect_rootkit |
| network | load_network_capture, parse_pcap_summary, extract_connections, search_pcap, detect_beaconing, extract_dns_queries, extract_http_traffic |
| browser | parse_browser_history, parse_browser_downloads, parse_browser_cache, parse_browser_cookies, parse_browser_extensions |
| user_activity | parse_lnk_files, parse_jumplists, parse_shellbags, parse_recycle_bin, parse_recent_docs, parse_mru_lists |
| anti_forensics | detect_timestomping, detect_log_clearing, detect_secure_deletion, detect_hidden_data, detect_wiping_tools, detect_anti_analysis |
| correlation | correlate_timeline_events, build_attack_narrative, detect_lateral_movement, map_mitre_techniques, get_investigation_summary |
| linux | parse_auth_log, parse_syslog, parse_bash_history, parse_cron_jobs, parse_systemd_journal, parse_ssh_artifacts |

## Key Rules

- suggest_next_action() tells you the category + operation to call — just follow it
- Keep calling suggest_next_action() → execute → repeat IN A LOOP until investigation_status says READY_FOR_REPORT
- Each tool response includes a ledger_entry_id — collect these as evidence for register_finding
- If a tool returns CAPABILITY_BLOCKED, it tells you the prerequisite to call first
- If a tool fails, call suggest_next_action() again — it will skip that tool and suggest the next
- The methodology engine drives SANS FOR508 phases automatically — trust it
- A thorough investigation typically requires 30-50+ tool calls across all baseline categories
` }] };
    }

    // ── Reset Investigation (always available) ──
    if (name === "reset_investigation") {
      const prevFindings = findings.size;
      const prevHypotheses = hypotheses.size;
      const prevEntries = ledgerStore.getAllEntries().length;
      capabilityGraph.reset();
      methodology.reset();
      disclosure.reset();
      reasoningEngine.reset();
      findings.clear();
      hypotheses.clear();
      ledgerStore.clear();
      return { content: [{ type: "text" as const, text: JSON.stringify({
        status: "RESET_COMPLETE",
        cleared: { findings: prevFindings, hypotheses: prevHypotheses, ledger_entries: prevEntries },
        message: "Investigation state reset. All findings, hypotheses, and ledger entries cleared. Ready for a new case.",
      }) }] };
    }

    // ── Meta-Cognitive Tools (always available) ──
    if (name === "get_job_status") {
      const jobId = toolParams["job_id"] as string | undefined;
      if (jobId) {
        const job = asyncJobs.get(jobId);
        if (!job) return { content: [{ type: "text" as const, text: JSON.stringify({ error: "Job not found", job_id: jobId }) }], isError: true };
        return { content: [{ type: "text" as const, text: JSON.stringify(job) }] };
      }
      // List all jobs
      const jobs = Array.from(asyncJobs.entries()).map(([id, j]) => ({ job_id: id, ...j }));
      return { content: [{ type: "text" as const, text: JSON.stringify({ jobs }) }] };
    }

    if (name === "suggest_next_action") {
      const suggestion = methodology.suggestNextAction(capabilityGraph.getHeld());
      const gaps = methodology.getCoverageGaps(capabilityGraph.getHeld()).slice(0, 3);
      const phases = methodology.getPhases();

      // Auto-activate workflows needed for the current state
      const autoActivated: string[] = [];
      for (const wfId of methodology.getWorkflowsToActivate()) {
        if (!disclosure.getActiveWorkflows().includes(wfId)) {
          const result = disclosure.activate(wfId);
          if (result.success) autoActivated.push(wfId);
        }
      }

      // Also activate the workflow of the suggested tool
      if (suggestion) {
        const spec = capabilityGraph.getSpec(suggestion.tool);
        if (spec && !disclosure.isToolVisible(suggestion.tool)) {
          const result = disclosure.activate(spec.category);
          if (result.success) autoActivated.push(spec.category);
        }
      }

      // FARE: Use EFE to score candidates — EFE OVERRIDES FSM when it finds a significantly better tool
      const candidates = gaps.map(g => g.tool);
      if (suggestion) candidates.push(suggestion.tool);
      const efeSelection = candidates.length > 0 ? reasoningEngine.selectNextTool(candidates) : null;

      // EFE overrides FSM suggestion when: (1) EFE chose a different tool, (2) EFE winner is decisively better than its own runner-up by >0.1, (3) the EFE tool is executable
      const fsmTool = suggestion?.tool;
      const efeTool = efeSelection?.tool;
      const efeOverrides = efeTool && fsmTool && efeTool !== fsmTool
        && efeSelection.efeScore.total < (efeSelection.alternatives?.[0]?.total ?? Infinity) - 0.1
        && capabilityGraph.canExecute(efeTool);
      const selectedTool = efeOverrides ? efeTool : fsmTool;
      const selectedSuggestion = efeOverrides && selectedTool
        ? { tool: selectedTool, reason: `EFE override: ${efeSelection.efeScore.explanation}`, priority: "HIGH" as const }
        : suggestion;

      return { content: [{ type: "text" as const, text: JSON.stringify({
        suggestion: selectedSuggestion ? {
          ...selectedSuggestion,
          call_as: KERNEL_TOOL_NAMES.includes(selectedSuggestion.tool)
            ? { tool: selectedSuggestion.tool, params: {} }
            : { tool: capabilityGraph.getSpec(selectedSuggestion.tool)?.category ?? "unknown", params: { operation: selectedSuggestion.tool } },
          efe_score: efeSelection?.efeScore.total,
          efe_overrode_fsm: efeOverrides,
          information_gain: efeSelection ? `EFE=${efeSelection.efeScore.total.toFixed(3)} (risk=${efeSelection.efeScore.risk.toFixed(3)}, ambiguity=${efeSelection.efeScore.ambiguity.toFixed(3)})` : undefined,
        } : null,
        fsm_state: methodology.getState(),
        active_investigation_paths: methodology.getActivePaths().map(p => ({ id: p.id, name: p.name, triggered_by: p.triggeredBy })),
        observed_signals: methodology.getSignals(),
        phase_progress: phases.map(p => ({ id: p.id, name: p.name, status: p.status })),
        auto_activated_workflows: autoActivated.length > 0 ? autoActivated : undefined,
        top_gaps: gaps,
        overall_coverage: methodology.getOverallCoverage(),
        investigation_status: methodology.isReadyForReport()
          ? "READY_FOR_REPORT"
          : "CONTINUE_INVESTIGATING — the methodology FSM has not completed all phases. Follow the suggestion above and keep calling suggest_next_action.",
        remaining_steps: methodology.getRemainingSteps(),
        reasoning: {
          entropy: reasoningEngine.getEntropy(),
          convergence: reasoningEngine.getReasoningReport().convergenceState,
          dominant_hypothesis: reasoningEngine.getDominantHypothesis(),
          learning_rate: reasoningEngine.getLearningRate(),
          bias_warnings: reasoningEngine.getReasoningReport().biasWarnings,
        },
      }) }] };
    }

    if (name === "get_investigation_state") {
      return { content: [{ type: "text" as const, text: JSON.stringify({
        phase: capabilityGraph.getPhase(),
        held_capabilities: capabilityGraph.getHeld(),
        active_workflows: disclosure.getActiveWorkflows(),
        visible_tools: disclosure.getVisibleToolCount(),
        total_tools: TOOL_SPECS.length,
        findings_count: findings.size,
        hypotheses_count: hypotheses.size,
        coverage: methodology.getOverallCoverage(),
      }) }] };
    }

    if (name === "get_coverage_gaps") {
      const limit = (toolParams["limit"] as number) ?? 10;
      const gaps = methodology.getCoverageGaps(capabilityGraph.getHeld()).slice(0, limit);
      return { content: [{ type: "text" as const, text: JSON.stringify({ gaps, overall_coverage: methodology.getOverallCoverage() }) }] };
    }

    if (name === "get_methodology_coverage") {
      const coverage = methodology.getCoverage();
      return { content: [{ type: "text" as const, text: JSON.stringify({ coverage, overall: methodology.getOverallCoverage() }) }] };
    }

    if (name === "get_investigation_health") {
      const unsupported = [...findings.values()].filter((f) => f.confidence === "INFERRED");
      const conflicts = findConflicts();
      const coverage = methodology.getOverallCoverage();
      const health = coverage >= 70 && unsupported.length === 0 && conflicts.length === 0 ? "EXCELLENT"
        : coverage >= 50 && unsupported.length <= 2 ? "GOOD"
        : coverage >= 30 ? "FAIR" : "POOR";

      return { content: [{ type: "text" as const, text: JSON.stringify({
        health,
        coverage_pct: coverage,
        total_findings: findings.size,
        unsupported_findings: unsupported.length,
        contradictions: conflicts.length,
        hypotheses_open: [...hypotheses.values()].filter((h) => h.status === "OPEN").length,
        recommendations: getHealthRecommendations(coverage, unsupported.length, conflicts.length),
        determinism_score: determinismTracker.getScore(),
        reasoning_state: { entropy: reasoningEngine.getReasoningReport().entropyCurve.slice(-1)[0] ?? 0, convergence: reasoningEngine.getReasoningReport().convergenceState },
      }) }] };
    }

    if (name === "get_confidence_summary") {
      const summary = { HYPOTHESIZED: 0, INFERRED: 0, SUPPORTED: 0, CONFIRMED: 0, CONFLICTED: 0 };
      for (const f of findings.values()) summary[f.confidence]++;
      return { content: [{ type: "text" as const, text: JSON.stringify(summary) }] };
    }

    if (name === "get_unsupported_findings") {
      const unsupported = [...findings.values()].filter((f) => f.confidence === "INFERRED" || f.confidence === "HYPOTHESIZED");
      return { content: [{ type: "text" as const, text: JSON.stringify(unsupported.map((f) => ({ id: f.id, type: f.type, description: f.description, confidence: f.confidence, evidence_count: f.evidence.length }))) }] };
    }

    if (name === "get_contradictions") {
      return { content: [{ type: "text" as const, text: JSON.stringify(findConflicts()) }] };
    }

    if (name === "get_hypothesis_status") {
      return { content: [{ type: "text" as const, text: JSON.stringify([...hypotheses.values()].map((h) => ({ id: h.id, description: h.description, status: h.status, supporting: h.supportingFindings.length, contradicting: h.contradictingFindings.length }))) }] };
    }

    if (name === "get_questions_to_investigate") {
      const questions = generateInvestigationQuestions();
      return { content: [{ type: "text" as const, text: JSON.stringify(questions) }] };
    }

    if (name === "trace_provenance") {
      const findingId = toolParams["finding_id"] as string;
      const finding = findings.get(findingId);
      if (!finding) return { content: [{ type: "text" as const, text: JSON.stringify({ error: `Finding ${findingId} not found` }) }] };
      const allEntries = ledgerStore.getAllEntries();
      const evidenceIds = new Set(finding.evidence.map((e) => e as string));
      const chain = allEntries.filter((e) => evidenceIds.has(e.id as string));
      return { content: [{ type: "text" as const, text: JSON.stringify({ finding: { id: finding.id, description: finding.description, confidence: finding.confidence }, provenance_chain: chain }) }] };
    }

    if (name === "corroborate_finding") {
      const findingId = toolParams["finding_id"] as string;
      const finding = findings.get(findingId);
      if (!finding) return { content: [{ type: "text" as const, text: JSON.stringify({ error: `Finding ${findingId} not found` }) }] };
      const suggestions = suggestCorroboration(finding);
      return { content: [{ type: "text" as const, text: JSON.stringify({ finding_id: findingId, current_confidence: finding.confidence, suggested_tools: suggestions }) }] };
    }

    if (name === "challenge_finding") {
      const findingId = toolParams["finding_id"] as string;
      const finding = findings.get(findingId);
      if (!finding) return { content: [{ type: "text" as const, text: JSON.stringify({ error: `Finding ${findingId} not found` }) }] };
      const challenges = suggestChallenge(finding);
      return { content: [{ type: "text" as const, text: JSON.stringify({ finding_id: findingId, challenge_strategies: challenges }) }] };
    }

    if (name === "export_audit_log") {
      const entries = ledgerStore.getAllEntries();
      const format = toolParams["format"] as string ?? "json";
      if (format === "csv") {
        const header = "id,tool,timestamp,success,duration_ms,output_hash";
        const rows = entries.map(e => `${e.id},${e.tool},${e.timestamp},${e.success},${e.durationMs},${e.outputHash}`);
        return { content: [{ type: "text" as const, text: JSON.stringify({ format: "csv", entry_count: entries.length, csv: [header, ...rows].join("\n") }) }] };
      }
      return { content: [{ type: "text" as const, text: JSON.stringify({ format, entry_count: entries.length, entries }) }] };
    }

    // ── Finding Registration ──
    if (name === "register_finding") {
      if (!toolParams["type"] || !toolParams["description"] || !Array.isArray(toolParams["evidence"])) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "Missing required parameters", required: ["type", "description", "evidence"], guidance: "Provide type (finding category), description (what was found), and evidence (array of ledger entry IDs that support this finding)" }) }], isError: true };
      }
      const input = {
        type: toolParams["type"] as Finding["type"],
        description: toolParams["description"] as string,
        evidence: (toolParams["evidence"] as string[]).map((id) => id as unknown as LedgerEntryId),
      } as RegisterFindingInput;

      // Build mutable object then cast — exactOptionalPropertyTypes requires this pattern
      const mutableInput: Record<string, unknown> = { ...input };
      if (toolParams["temporal_range"]) mutableInput["temporalRange"] = toolParams["temporal_range"];
      if (toolParams["mitre_technique"]) mutableInput["mitreTechnique"] = toolParams["mitre_technique"];
      if (toolParams["mitre_tactic"]) mutableInput["mitreTactic"] = toolParams["mitre_tactic"];
      if (toolParams["affected_hosts"]) mutableInput["affectedHosts"] = toolParams["affected_hosts"];
      if (toolParams["iocs"]) mutableInput["iocs"] = toolParams["iocs"];
      if (toolParams["supports_hypotheses"]) mutableInput["supportsHypotheses"] = (toolParams["supports_hypotheses"] as string[]).map((id) => id as unknown as Finding["supportsHypotheses"][number]);
      if (toolParams["contradicts_hypotheses"]) mutableInput["contradictsHypotheses"] = (toolParams["contradicts_hypotheses"] as string[]).map((id) => id as unknown as Finding["contradictsHypotheses"][number]);

      const finalInput = mutableInput as unknown as RegisterFindingInput;
      const existingIds = ledgerStore.getAllIds();
      const getCat = (id: LedgerEntryId) => {
        const allEntries = ledgerStore.getAllEntries();
        const entry = allEntries.find((e) => e.id === id);
        return entry ? capabilityGraph.getCategory(entry.tool) : undefined;
      };

      const result = createFinding(finalInput, existingIds, getCat);
      if (result.isErr()) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: result.error.message, guidance: result.error.guidance }) }], isError: true };
      }

      const finding = result.value;
      findings.set(finding.id as string, finding);
      capabilityGraph.produce("register_finding");

      // ─── Deterministic Verification (Brian Carrier method) ───────────────────
      // Check if key terms from the description actually appear in the cited evidence.
      // This catches the case where an LLM fabricates a finding about an artifact
      // that doesn't actually exist in the tool output it cited as evidence.
      let verificationStatus: "VERIFIED" | "UNVERIFIED" | "PARTIAL" = "UNVERIFIED";
      const description = (toolParams["description"] as string).toLowerCase();
      const evidenceIds = toolParams["evidence"] as string[];
      let matchCount = 0;
      for (const eid of evidenceIds) {
        const rawResult = rawStore.retrieve(eid as unknown as LedgerEntryId);
        if (rawResult.isOk()) {
          const rawText = rawResult.value.toLowerCase();
          // Extract significant terms from description (>3 chars, not common words)
          const terms = description.split(/[\s,./\\()\[\]]+/).filter(t => t.length > 3 && !["the", "was", "were", "that", "this", "from", "with", "found", "file", "evidence"].includes(t));
          const matched = terms.filter(t => rawText.includes(t));
          if (matched.length > 0) matchCount++;
        }
      }
      if (matchCount === evidenceIds.length) verificationStatus = "VERIFIED";
      else if (matchCount > 0) verificationStatus = "PARTIAL";

      // Evidence provenance snippets (CyberSleuth arXiv:2508.20643 — complete evidence chains)
      // Extract the SPECIFIC text from cited evidence that grounds this finding
      const provenanceSnippets: Array<{ evidence_id: string; snippet: string; tool: string }> = [];
      for (const eid of evidenceIds) {
        const rawResult = rawStore.retrieve(eid as unknown as LedgerEntryId);
        const ledgerEntry = ledgerStore.getAllEntries().find(e => e.id === eid);
        if (rawResult.isOk() && ledgerEntry) {
          const rawText = rawResult.value;
          const terms = description.split(/[\s,./\\()\[\]]+/).filter(t => t.length > 3);
          // Find the line containing the most matching terms
          const lines = rawText.split("\n");
          let bestLine = "";
          let bestScore = 0;
          for (const line of lines) {
            const lowerLine = line.toLowerCase();
            const score = terms.filter(t => lowerLine.includes(t)).length;
            if (score > bestScore) { bestScore = score; bestLine = line.trim(); }
          }
          if (bestLine) {
            provenanceSnippets.push({ evidence_id: eid, snippet: bestLine.slice(0, 200), tool: ledgerEntry.tool });
          }
        }
      }

      // Wire hypothesis updates (C3 fix) — update hypotheses when a finding supports/contradicts them
      const supportsHyps = (toolParams["supports_hypotheses"] as string[] | undefined) ?? [];
      const contradictsHyps = (toolParams["contradicts_hypotheses"] as string[] | undefined) ?? [];
      for (const hid of supportsHyps) {
        const h = hypotheses.get(hid);
        if (h) {
          hypotheses.set(hid, updateHypothesis(h, { type: "support", findingId: finding.id }));
        }
      }
      for (const hid of contradictsHyps) {
         const h = hypotheses.get(hid);
         if (h) {
           hypotheses.set(hid, updateHypothesis(h, { type: "contradict", findingId: finding.id }));
         }
       }

       // Update methodology's view of open hypotheses for CORRELATE→REPORT gating
       methodology.setOpenHypothesesCount([...hypotheses.values()].filter(h => h.status === "OPEN").length);

       return { content: [{ type: "text" as const, text: JSON.stringify({ success: true, finding_id: finding.id, confidence: finding.confidence, verification: verificationStatus, provenance_snippets: provenanceSnippets, message: `Finding registered with confidence: ${finding.confidence}. Evidence verification: ${verificationStatus}` }) }] };
    }

    if (name === "register_hypothesis") {
      const hyp = createHypothesis({ description: toolParams["description"] as string });
      hypotheses.set(hyp.id as string, hyp);
      methodology.setOpenHypothesesCount([...hypotheses.values()].filter(h => h.status === "OPEN").length);
      return { content: [{ type: "text" as const, text: JSON.stringify({ success: true, hypothesis_id: hyp.id }) }] };
    }

    if (name === "reassess_finding") {
      const findingId = toolParams["finding_id"] as string;
      const finding = findings.get(findingId);
      if (!finding) return { content: [{ type: "text" as const, text: JSON.stringify({ error: "Finding not found" }) }], isError: true };

      const additionalEvidence = (toolParams["additional_evidence"] as string[]).map((id) => id as unknown as LedgerEntryId);
      const existingIds = ledgerStore.getAllIds();
      const getCat = (id: LedgerEntryId) => {
        const allEntries = ledgerStore.getAllEntries();
        const entry = allEntries.find((e) => e.id === id);
        return entry ? capabilityGraph.getCategory(entry.tool) : undefined;
      };

      const result = reassessFinding(finding, additionalEvidence, existingIds, getCat);
      if (result.isErr()) return { content: [{ type: "text" as const, text: JSON.stringify({ error: result.error.message }) }], isError: true };

      findings.set(findingId, result.value);
      return { content: [{ type: "text" as const, text: JSON.stringify({ finding_id: findingId, old_confidence: finding.confidence, new_confidence: result.value.confidence }) }] };
    }

     if (name === "generate_report") {
      // ENFORCEMENT: Block premature report generation — the methodology FSM must reach REPORT state
      if (!methodology.isReadyForReport()) {
        const remaining = methodology.getRemainingSteps();
        const openHypotheses = [...hypotheses.values()].filter(h => h.status === "OPEN");
        return { content: [{ type: "text" as const, text: JSON.stringify({
          error: "INVESTIGATION_INCOMPLETE",
          message: `Cannot generate report — methodology FSM is at "${methodology.getState()}", not "REPORT". ${remaining.count} baseline tools remain unattempted. Call suggest_next_action() and continue investigating.`,
          fsm_state: methodology.getState(),
          remaining_tools: remaining.tools.slice(0, 10),
          remaining_count: remaining.count,
          open_hypotheses: openHypotheses.length,
          coverage: methodology.getOverallCoverage(),
          action_required: "Call suggest_next_action() to get the next tool to execute. Do NOT attempt generate_report until investigation_status returns READY_FOR_REPORT.",
        }) }] };
      }
      const minConfidence = toolParams["min_confidence"] as string ?? "INFERRED";
      const rawFormat = toolParams["format"] as string ?? "markdown";
      const format = rawFormat === "narrative" ? "markdown" : rawFormat; // backward compat
      const levels = ["HYPOTHESIZED", "INFERRED", "SUPPORTED", "CONFIRMED"];
      const minIdx = levels.indexOf(minConfidence);
      const reportFindings = [...findings.values()].filter((f) => levels.indexOf(f.confidence) >= minIdx && f.confidence !== "CONFLICTED");
      const chainResult = ledgerStore.verifyChain();
      const chainValid = chainResult.isOk() ? chainResult.value.valid : false;
      const now = new Date().toISOString();
      const totalCalls = ledgerStore.count();
      const coverage = methodology.getOverallCoverage();

       if (format === "markdown") {
        // Generate structured investigative narrative (not raw JSON)
        const lines: string[] = [];
        lines.push("# Forensic Investigation Report");
        lines.push("");
        // Completeness assessment
        const fsmState = methodology.getState();
        if (fsmState !== "REPORT") {
          lines.push(`> **⚠️ INVESTIGATION INCOMPLETE** — FSM at \`${fsmState}\`, not \`REPORT\`. Coverage: ${coverage}%. The methodology baseline has unattempted tools.`);
          const remainingGaps = methodology.getCoverageGaps(capabilityGraph.getHeld());
          if (remainingGaps.length > 0) {
            lines.push(`> Unattempted (${remainingGaps.length}): ${remainingGaps.slice(0, 5).map(g => g.tool).join(", ")}${remainingGaps.length > 5 ? "..." : ""}`);
          }
          lines.push("");
        }
        lines.push(`**Generated:** ${now}`);
        lines.push(`**Phase:** ${capabilityGraph.getPhase()}`);
        lines.push(`**FSM State:** ${fsmState}`);
        lines.push(`**Coverage:** ${coverage}%`);
        lines.push(`**Total Tool Executions:** ${totalCalls}`);
        lines.push(`**Chain Integrity:** ${chainValid ? "VALID" : "BROKEN"}`);
        lines.push("");
        lines.push("## Executive Summary");
        lines.push("");
        const confirmedCount = reportFindings.filter(f => f.confidence === "CONFIRMED").length;
        const supportedCount = reportFindings.filter(f => f.confidence === "SUPPORTED").length;
        const inferredCount = reportFindings.filter(f => f.confidence === "INFERRED").length;
        lines.push(`Investigation produced ${reportFindings.length} findings: ${confirmedCount} CONFIRMED, ${supportedCount} SUPPORTED, ${inferredCount} INFERRED.`);
        lines.push("");

        if (reportFindings.length > 0) {
          lines.push("## Findings (by confidence)");
          lines.push("");
          for (const f of reportFindings.sort((a, b) => levels.indexOf(b.confidence) - levels.indexOf(a.confidence))) {
            lines.push(`### [${f.confidence}] ${f.type.toUpperCase()}: ${f.description}`);
            lines.push("");
            if (f.mitreTactic) lines.push(`- **MITRE Tactic:** ${f.mitreTactic}`);
            if (f.mitreTechnique) lines.push(`- **MITRE Technique:** ${f.mitreTechnique}`);
            lines.push(`- **Evidence sources:** ${f.evidence.length} ledger entries`);
            lines.push(`- **Evidence IDs:** ${f.evidence.join(", ")}`);
            lines.push("");
          }
        }

        if (hypotheses.size > 0) {
          lines.push("## Hypotheses");
          lines.push("");
          for (const [, h] of hypotheses) {
            const supporting = reportFindings.filter(f => f.type === h.id || f.description.toLowerCase().includes(h.description.toLowerCase().split(" ")[0] ?? "")).length;
            lines.push(`- **${h.description}** — ${h.status} (${supporting} supporting findings)`);
          }
          lines.push("");
        }

        lines.push("## Audit Trail");
        lines.push("");
        lines.push(`- Ledger entries: ${totalCalls}`);
        lines.push(`- Hash chain: ${chainValid ? "Verified (tamper-free)" : "INVALID — investigation integrity compromised"}`);
        lines.push(`- All findings trace to tool executions via evidence IDs`);
        lines.push("");

        // HMAC seal
        const crypto = await import("node:crypto");
        const reportText = lines.join("\n");
        const hmacKey = sessionHmacKey;
        const hmac = crypto.createHmac("sha256", hmacKey).update(reportText).digest("hex");
        lines.push("## Report Seal");
        lines.push("");
        lines.push(`HMAC-SHA256: \`${hmac}\``);
        lines.push(`Sealed at: ${now}`);
        lines.push(`Verify: Recompute HMAC-SHA256 over report text above this section using the server's secret key (SIFT_KERNEL_HMAC_SECRET env var).`);

        const reportText2 = lines.join("\n");
        const fs2 = await import("node:fs");
        const path2 = await import("node:path");
        const outputDir2 = config.outputPath;
        if (!fs2.existsSync(outputDir2)) fs2.mkdirSync(outputDir2, { recursive: true });
        const evidenceName2 = investigationState.imagePath
          ? path2.basename(investigationState.imagePath).replace(/\.[^.]+$/, "").replace(/[^a-zA-Z0-9_-]/g, "_")
          : "unknown";
        const reportPath2 = path2.join(outputDir2, `${evidenceName2}-${now.replace(/[:.]/g, "-")}.md`);
        fs2.writeFileSync(reportPath2, reportText2);

        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "report_generated", format: "markdown", path: reportPath2, findings_count: reportFindings.length, coverage, chain_valid: chainValid, hmac_seal: hmac }) }] };
      }

      if (format === "html") {
        const crypto = await import("node:crypto");
        const fs = await import("node:fs");
        const path = await import("node:path");
        const confirmedCount = reportFindings.filter(f => f.confidence === "CONFIRMED").length;
        const supportedCount = reportFindings.filter(f => f.confidence === "SUPPORTED").length;
        const inferredCount = reportFindings.filter(f => f.confidence === "INFERRED").length;
        const mitreTactics = [...new Set(reportFindings.map(f => f.mitreTactic).filter(Boolean))];
        const mitreCount = [...new Set(reportFindings.map(f => f.mitreTechnique).filter(Boolean))].length;
        const hmacKey = sessionHmacKey;
        const hmacValue = crypto.createHmac("sha256", hmacKey).update(JSON.stringify({ findings: reportFindings, coverage, chainValid, totalCalls, timestamp: now })).digest("hex");
        const htmlContent = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SIFT Kernel — Forensic Investigation Report</title>
<style>
  :root {
    --bg: #0f1419;
    --surface: #1a1f2e;
    --surface-elevated: #232a3b;
    --border: #2d3748;
    --text: #e2e8f0;
    --text-secondary: #a0aec0;
    --muted: #718096;
    --accent: #63b3ed;
    --accent-dim: rgba(99, 179, 237, 0.1);
    --green: #48bb78;
    --green-dim: rgba(72, 187, 120, 0.15);
    --yellow: #ecc94b;
    --yellow-dim: rgba(236, 201, 75, 0.15);
    --red: #fc8181;
    --red-dim: rgba(252, 129, 129, 0.15);
    --purple: #b794f4;
    --radius: 12px;
    --shadow: 0 4px 6px -1px rgba(0,0,0,0.3), 0 2px 4px -1px rgba(0,0,0,0.2);
  }
  [data-theme="light"] {
    --bg: #f7fafc;
    --surface: #ffffff;
    --surface-elevated: #ffffff;
    --border: #e2e8f0;
    --text: #1a202c;
    --text-secondary: #4a5568;
    --muted: #718096;
    --accent: #3182ce;
    --accent-dim: rgba(49, 130, 206, 0.08);
    --green: #38a169;
    --green-dim: rgba(56, 161, 105, 0.1);
    --yellow: #d69e2e;
    --yellow-dim: rgba(214, 158, 46, 0.1);
    --red: #e53e3e;
    --red-dim: rgba(229, 62, 62, 0.08);
    --purple: #805ad5;
    --shadow: 0 4px 6px -1px rgba(0,0,0,0.07), 0 2px 4px -1px rgba(0,0,0,0.04);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.7;
    padding: 2.5rem;
    max-width: 1100px;
    margin: 0 auto;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2.5rem;
    padding-bottom: 1.5rem;
    border-bottom: 2px solid var(--border);
  }
  .header-left h1 {
    font-size: 1.75rem;
    font-weight: 700;
    letter-spacing: -0.02em;
  }
  .header-left p {
    font-size: 0.85rem;
    color: var(--muted);
    margin-top: 0.25rem;
  }
  .theme-toggle {
    cursor: pointer;
    background: var(--surface-elevated);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.5rem 1rem;
    color: var(--text);
    font-size: 0.8rem;
    transition: all 0.2s;
  }
  .theme-toggle:hover { border-color: var(--accent); }
  .header-actions { display: flex; gap: 0.5rem; }
  .export-btn {
    cursor: pointer;
    background: var(--accent);
    border: none;
    border-radius: 8px;
    padding: 0.5rem 1rem;
    color: #fff;
    font-size: 0.8rem;
    font-weight: 600;
    transition: all 0.2s;
  }
  .export-btn:hover { opacity: 0.85; }
  @media print {
    .header-actions, .theme-toggle, .export-btn { display: none !important; }
    body { padding: 1rem; max-width: 100%; }
    .summary-grid { grid-template-columns: repeat(3, 1fr); }
  }

  /* Executive Summary Grid */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
  }
  @media (max-width: 768px) { .summary-grid { grid-template-columns: 1fr; } }
  .summary-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.5rem;
    box-shadow: var(--shadow);
    transition: transform 0.15s;
  }
  .summary-card:hover { transform: translateY(-2px); }
  .summary-card .value {
    font-size: 2.5rem;
    font-weight: 800;
    color: var(--accent);
    line-height: 1;
    margin-bottom: 0.25rem;
  }
  .summary-card .label {
    font-size: 0.75rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }
  .summary-card.valid .value { color: var(--green); }
  .summary-card.warn .value { color: var(--yellow); }

  /* Confidence Section */
  .confidence-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.5rem;
    margin-bottom: 2rem;
    box-shadow: var(--shadow);
  }
  .confidence-section h2 {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin-bottom: 1rem;
  }
  .confidence-bar {
    display: flex;
    height: 12px;
    border-radius: 6px;
    overflow: hidden;
    background: var(--border);
    margin-bottom: 1rem;
  }
  .confidence-bar .seg-confirmed { background: var(--green); }
  .confidence-bar .seg-supported { background: var(--accent); }
  .confidence-bar .seg-inferred { background: var(--yellow); }
  .confidence-legend {
    display: flex;
    gap: 1.5rem;
    flex-wrap: wrap;
  }
  .legend-item {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  .legend-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
  }
  .legend-dot.confirmed { background: var(--green); }
  .legend-dot.supported { background: var(--accent); }
  .legend-dot.inferred { background: var(--yellow); }

  /* Section Cards */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 2rem;
    margin-bottom: 1.5rem;
    box-shadow: var(--shadow);
  }
  .card h2 {
    font-size: 1.1rem;
    font-weight: 700;
    margin-bottom: 1.25rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .card h2 .icon { font-size: 1.2rem; }

  /* Findings */
  .finding {
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
    background: var(--bg);
    border-left: 4px solid var(--accent);
    transition: border-color 0.2s;
  }
  .finding.CONFIRMED { border-left-color: var(--green); background: var(--green-dim); }
  .finding.SUPPORTED { border-left-color: var(--accent); background: var(--accent-dim); }
  .finding.INFERRED { border-left-color: var(--yellow); background: var(--yellow-dim); }
  .finding-header {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  .finding-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .finding-badge.confirmed { background: var(--green); color: #fff; }
  .finding-badge.supported { background: var(--accent); color: #fff; }
  .finding-badge.inferred { background: var(--yellow); color: #000; }
  .finding-title {
    font-size: 0.9rem;
    font-weight: 600;
    line-height: 1.4;
  }
  .finding-type {
    display: inline-block;
    font-size: 0.7rem;
    font-weight: 700;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-right: 0.4rem;
  }
  .finding-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    margin-top: 0.5rem;
    font-size: 0.78rem;
    color: var(--muted);
  }
  .finding-meta span { display: flex; align-items: center; gap: 0.3rem; }

  /* MITRE ATT&CK */
  .mitre-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 0.75rem;
  }
  .mitre-item {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .mitre-item .technique {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--accent);
  }
  .mitre-item .tactic {
    font-size: 0.72rem;
    color: var(--muted);
    text-transform: capitalize;
  }

  /* Hypotheses Table */
  table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 0.85rem;
  }
  th {
    text-align: left;
    padding: 0.75rem 1rem;
    color: var(--muted);
    font-weight: 600;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-bottom: 2px solid var(--border);
  }
  td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--border);
    color: var(--text-secondary);
  }
  tr:last-child td { border-bottom: none; }
  .status-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    background: var(--accent-dim);
    color: var(--accent);
  }

  /* Audit & Seal */
  .audit-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
  }
  @media (max-width: 600px) { .audit-grid { grid-template-columns: 1fr; } }
  .audit-item {
    background: var(--bg);
    border-radius: 8px;
    padding: 1rem;
    border: 1px solid var(--border);
  }
  .audit-item .label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; margin-bottom: 0.25rem; }
  .audit-item .value { font-size: 1rem; font-weight: 600; }
  .seal-block {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 0.75rem;
    line-height: 1.8;
    color: var(--text-secondary);
    word-break: break-all;
  }
  .seal-block .label { color: var(--muted); }
  .seal-block .value { color: var(--green); font-weight: 600; }

  /* Footer */
  footer {
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    text-align: center;
    font-size: 0.75rem;
    color: var(--muted);
  }
</style>
</head>
<body>
<header>
  <div class="header-left">
    <h1>Forensic Investigation Report</h1>
    <p>Generated by SIFT Kernel | ${now}</p>
  </div>
  <div class="header-actions">
    <button class="theme-toggle" onclick="document.documentElement.dataset.theme=document.documentElement.dataset.theme==='dark'?'light':'dark'">Switch Theme</button>
    <button class="export-btn" onclick="window.print()">Export PDF</button>
  </div>
</header>

<div class="summary-grid">
  <div class="summary-card"><div class="value">${reportFindings.length}</div><div class="label">Findings</div></div>
  <div class="summary-card"><div class="value">${mitreCount}</div><div class="label">ATT&CK Techniques</div></div>
  <div class="summary-card"><div class="value">${totalCalls}</div><div class="label">Tool Executions</div></div>
  <div class="summary-card ${chainValid ? "valid" : "warn"}"><div class="value">${chainValid ? "Valid" : "Broken"}</div><div class="label">Chain Integrity</div></div>
  <div class="summary-card"><div class="value">${coverage}%</div><div class="label">Methodology Coverage</div></div>
  <div class="summary-card"><div class="value">${methodology.getState()}</div><div class="label">FSM State</div></div>
  <div class="summary-card"><div class="value">${capabilityGraph.getPhase()}</div><div class="label">Investigation Phase</div></div>
</div>

${methodology.getState() !== "REPORT" ? `<div style="background:var(--warn-bg,#fff3cd);border:1px solid var(--warn-border,#ffc107);border-radius:8px;padding:16px;margin:24px 0;color:var(--warn-text,#856404);">
  <strong>⚠️ Investigation Incomplete</strong> — FSM state: <code>${methodology.getState()}</code> (not REPORT). 
  The methodology baseline has unattempted tools. Coverage: ${coverage}%.
  ${(() => { const g = methodology.getCoverageGaps(capabilityGraph.getHeld()); return g.length > 0 ? `<br>Unattempted: ${g.slice(0, 6).map(x => x.tool).join(", ")}${g.length > 6 ? "..." : ""}` : ""; })()}
</div>` : ""}

<div class="confidence-section">
  <h2>Evidence Confidence Distribution</h2>
  <div class="confidence-bar">
    <div class="seg-confirmed" style="width:${reportFindings.length ? (confirmedCount / reportFindings.length * 100) : 0}%"></div>
    <div class="seg-supported" style="width:${reportFindings.length ? (supportedCount / reportFindings.length * 100) : 0}%"></div>
    <div class="seg-inferred" style="width:${reportFindings.length ? (inferredCount / reportFindings.length * 100) : 0}%"></div>
  </div>
  <div class="confidence-legend">
    <div class="legend-item"><span class="legend-dot confirmed"></span>${confirmedCount} Confirmed (multi-source corroboration)</div>
    <div class="legend-item"><span class="legend-dot supported"></span>${supportedCount} Supported (2+ sources, same domain)</div>
    <div class="legend-item"><span class="legend-dot inferred"></span>${inferredCount} Inferred (single source)</div>
  </div>
</div>

${reportFindings.length > 0 ? `<div class="card">
  <h2><span class="icon">&#128270;</span> Findings</h2>
  ${reportFindings.sort((a, b) => levels.indexOf(b.confidence) - levels.indexOf(a.confidence)).map(f => `
  <div class="finding ${f.confidence}">
    <div class="finding-header">
      <span class="finding-badge ${f.confidence.toLowerCase()}">${f.confidence}</span>
      <div class="finding-title"><span class="finding-type">${escapeHtml(f.type.replace(/_/g, " "))}</span>${escapeHtml(f.description)}</div>
    </div>
    <div class="finding-meta">
      ${f.mitreTactic ? `<span>Tactic: <strong>${escapeHtml(f.mitreTactic)}</strong></span>` : ""}
      ${f.mitreTechnique ? `<span>Technique: <strong>${escapeHtml(f.mitreTechnique)}</strong></span>` : ""}
      <span>Evidence: <strong>${f.evidence.length} sources</strong></span>
    </div>
  </div>`).join("")}
</div>` : ""}

${mitreTactics.length > 0 ? `<div class="card">
  <h2><span class="icon">&#9760;</span> MITRE ATT&CK Mapping</h2>
  <div class="mitre-grid">
    ${reportFindings.filter(f => f.mitreTechnique).map(f => `
    <div class="mitre-item">
      <span class="technique">${escapeHtml(f.mitreTechnique ?? "")}</span>
      <span class="tactic">${escapeHtml(f.mitreTactic || "Unknown")}</span>
    </div>`).join("")}
  </div>
</div>` : ""}

${hypotheses.size > 0 ? `<div class="card">
  <h2><span class="icon">&#128161;</span> Investigation Hypotheses</h2>
  <table>
    <thead><tr><th>Hypothesis</th><th>Status</th><th>Supporting</th><th>Contradicting</th></tr></thead>
    <tbody>
      ${[...hypotheses.values()].map(h => `<tr>
        <td>${escapeHtml(h.description)}</td>
        <td><span class="status-badge">${h.status}</span></td>
        <td>${h.supportingFindings?.length || 0}</td>
        <td>${h.contradictingFindings?.length || 0}</td>
      </tr>`).join("")}
    </tbody>
  </table>
</div>` : ""}

<div class="card">
  <h2><span class="icon">&#129504;</span> Forensic Reasoning Analysis (FARE)</h2>
  <div style="text-align:center;margin:1rem 0">
    ${reasoningEngine.getEntropySVG(500, 140)}
  </div>
  <div class="summary-grid">
    <div class="summary-item"><div class="label">Convergence</div><div class="value">${reasoningEngine.getReasoningReport().convergenceState}</div></div>
    <div class="summary-item"><div class="label">Dominant Hypothesis</div><div class="value">${reasoningEngine.getDominantHypothesis()?.id ?? "None (insufficient evidence)"}</div></div>
    <div class="summary-item"><div class="label">Belief Interval</div><div class="value">${reasoningEngine.getDominantHypothesis() ? `[${reasoningEngine.getDominantHypothesis()!.belief.toFixed(2)}, ${reasoningEngine.getDominantHypothesis()!.plausibility.toFixed(2)}]` : "N/A"}</div></div>
    <div class="summary-item"><div class="label">Rules Triggered</div><div class="value">${reasoningEngine.getReasoningReport().rulesTriggered.length}</div></div>
    <div class="summary-item"><div class="label">Comebacks</div><div class="value">${reasoningEngine.getReasoningReport().comebacksTriggered}</div></div>
    <div class="summary-item"><div class="label">Quality</div><div class="value">${reasoningEngine.getReasoningReport().investigationQuality}</div></div>
  </div>
  ${reasoningEngine.getReasoningReport().biasWarnings.length > 0 ? `<div style="margin-top:0.5rem;padding:0.5rem;background:rgba(255,152,0,0.1);border-radius:4px;border-left:3px solid #ff9800"><strong>Bias Warnings:</strong> ${reasoningEngine.getReasoningReport().biasWarnings.map(w => w.description).join("; ")}</div>` : ""}
  <p style="font-size:0.75rem;color:var(--muted);margin-top:0.5rem">Powered by DSmT/PCR5 evidence fusion + Active Inference Expected Free Energy. Entropy curve shows investigation learning rate. Belief intervals from Dempster-Shafer theory (not point estimates). Citations: Carrier 2006, Smarandache & Dezert 2006, Friston 2015.</p>
</div>

${(() => {
  const correlationFindings: FindingForCorrelation[] = reportFindings.map(f => ({
    id: f.id as string,
    description: f.description,
    mitreTechnique: f.mitreTechnique,
    mitreTactic: f.mitreTactic,
    temporalStart: f.temporalRange?.start,
    temporalEnd: f.temporalRange?.end,
    registeredAt: Date.now(),
  }));
  const graph = computeCorrelationGraph(correlationFindings);
  if (graph.edges.length === 0 && graph.chains.length === 0) return "";
  return `<div class="card">
  <h2><span class="icon">&#128268;</span> Auto-Correlation Graph</h2>
  <p style="font-size:0.8rem;color:var(--muted);margin-bottom:1rem">Deterministic correlation: temporal proximity (±30min), MITRE kill-chain sequencing, shared entities. No LLM inference — reproducible.</p>
  ${graph.chains.length > 0 ? `<div style="margin-bottom:1rem"><h3 style="font-size:0.9rem;margin-bottom:0.5rem">Attack Chains Detected</h3>
  ${graph.chains.map(c => `<div style="padding:0.75rem;background:rgba(244,67,54,0.05);border-left:3px solid var(--red);border-radius:4px;margin-bottom:0.5rem">
    <strong>Chain: ${c.killChainPhases.map(p => escapeHtml(p)).join(" → ")}</strong> (confidence: ${(c.confidence * 100).toFixed(0)}%)<br/>
    <span style="font-size:0.8rem">${escapeHtml(c.narrative)}</span>
  </div>`).join("")}</div>` : ""}
  ${graph.timeline.length > 0 ? `<div><h3 style="font-size:0.9rem;margin-bottom:0.5rem">Event Timeline</h3>
  <div style="border-left:2px solid var(--border);padding-left:1rem;margin-left:0.5rem">
  ${graph.timeline.map(t => `<div style="margin-bottom:0.5rem;position:relative">
    <div style="position:absolute;left:-1.35rem;top:0.3rem;width:8px;height:8px;border-radius:50%;background:var(--accent)"></div>
    <span style="font-size:0.75rem;color:var(--muted)">${escapeHtml(t.phase)}</span><br/>
    <span style="font-size:0.85rem">${escapeHtml(t.description)}</span>
  </div>`).join("")}
  </div></div>` : ""}
  <p style="font-size:0.7rem;color:var(--muted);margin-top:0.75rem">${graph.edges.length} correlation edges detected (${graph.edges.filter(e => e.edgeType === "KILL_CHAIN_SEQUENCE").length} kill-chain, ${graph.edges.filter(e => e.edgeType === "TEMPORAL_PROXIMITY").length} temporal, ${graph.edges.filter(e => e.edgeType === "SHARED_ENTITY").length} shared-entity)</p>
</div>`;
})()}

<div class="card">
  <h2><span class="icon">&#128279;</span> Audit Trail &amp; Chain of Custody</h2>
  <div class="audit-grid">
    <div class="audit-item"><div class="label">Ledger Entries</div><div class="value">${totalCalls}</div></div>
    <div class="audit-item"><div class="label">Hash Chain</div><div class="value" style="color:${chainValid ? "var(--green)" : "var(--red)"}">${chainValid ? "Verified (Tamper-Free)" : "INTEGRITY VIOLATION"}</div></div>
    <div class="audit-item"><div class="label">Evidence Model</div><div class="value">Append-Only SHA-256</div></div>
    <div class="audit-item"><div class="label">Methodology</div><div class="value">SANS IR (DAG-Enforced)</div></div>
  </div>
  <p style="font-size:0.8rem;color:var(--muted);margin-top:0.5rem">Every finding is traceable to specific tool executions via evidence IDs. The hash-chained ledger is self-authenticating. Run <code>verify_chain()</code> to independently validate.</p>
</div>

<div class="card">
  <h2><span class="icon">&#128274;</span> Report Seal</h2>
  <div class="seal-block">
    <span class="label">Generated:</span> <span class="value">${now}</span><br>
    <span class="label">HMAC-SHA256:</span> <span class="value">${hmacValue}</span><br>
    <span class="label">Key Derivation:</span> SIFT_KERNEL_HMAC_SECRET (server-held, not embedded)<br>
    <span class="label">Payload:</span> {findings:${reportFindings.length}, coverage:${coverage}%, chain:${chainValid}, calls:${totalCalls}}
  </div>
</div>

${(() => {
  // Ground-truth comparison — load if available
  try {
    const gtDir = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "ground-truth");
    const gtFiles = fs.readdirSync(gtDir).filter((f: string) => f.endsWith(".json"));
    if (gtFiles.length === 0) return "";
    const imageName = investigationState.imagePath ? path.basename(investigationState.imagePath).replace(/\.[^.]+$/, "") : "";
    const norm = (s: string) => s.toLowerCase().replace(/[-_\s]/g, "");
    const gtFile = gtFiles.find((f: string) => norm(imageName).includes(norm(f.replace(".json", "")))) ?? gtFiles[0];
    const gt = JSON.parse(fs.readFileSync(path.join(gtDir, gtFile!), "utf-8"));
    const gtIocs: { type: string; value: string; description: string; mitre?: string }[] = gt.iocs ?? [];
    const gtTtps: string[] = gt.mitre_ttps ?? [];
    const foundMitres = new Set(reportFindings.map(f => f.mitreTechnique).filter((t): t is string => !!t));
    const allFindingText = reportFindings.map((f) =>
      f.description.toLowerCase() + " " + (f.iocs ?? []).map((i: {type:string;value:string}) => i.value.toLowerCase()).join(" ")
    ).join(" ");
    const detectedIocs = gtIocs.filter(ioc => {
      const val = ioc.value.toLowerCase().replace(/[\\/]/g, "/");
      const parts = val.split("/").filter(Boolean);
      const lastPart = parts[parts.length - 1] ?? "";
      if (allFindingText.includes(val)) return true;
      if (lastPart.length > 3 && allFindingText.includes(lastPart)) return true;
      if (ioc.mitre && foundMitres.has(ioc.mitre)) return true;
      return false;
    });
    const detectedTtps = gtTtps.filter(t => foundMitres.has(t));
    const iocRate = gtIocs.length > 0 ? Math.round((detectedIocs.length / gtIocs.length) * 100) : 0;
    const ttpRate = gtTtps.length > 0 ? Math.round((detectedTtps.length / gtTtps.length) * 100) : 0;
    return `<div class="card">
  <h2><span class="icon">&#127919;</span> Ground Truth Accuracy</h2>
  <p style="font-size:0.85rem;color:var(--muted)">Compared against: <code>${escapeHtml(gtFile!)}</code> (${gt.case_id ?? "unknown case"})</p>
  <div class="audit-grid">
    <div class="audit-item"><div class="label">IOC Detection</div><div class="value">${detectedIocs.length}/${gtIocs.length} (${iocRate}%)</div></div>
    <div class="audit-item"><div class="label">TTP Coverage</div><div class="value">${detectedTtps.length}/${gtTtps.length} (${ttpRate}%)</div></div>
    <div class="audit-item"><div class="label">False Positives</div><div class="value">${reportFindings.length - detectedIocs.length > 0 ? reportFindings.length - detectedIocs.length + " (unconfirmed)" : "0"}</div></div>
    <div class="audit-item"><div class="label">Expected Verdict</div><div class="value">${escapeHtml(gt.expected_verdict ?? "N/A")}</div></div>
  </div>
  <details style="margin-top:1rem"><summary style="cursor:pointer;font-weight:600">IOC Breakdown</summary>
  <table style="width:100%;font-size:0.8rem;margin-top:0.5rem;border-collapse:collapse">
    <tr><th style="text-align:left;border-bottom:1px solid var(--border)">IOC</th><th>MITRE</th><th>Detected</th></tr>
    ${gtIocs.map(ioc => {
      const val = ioc.value.toLowerCase().replace(/[\\/]/g, "/");
      const parts = val.split("/").filter(Boolean);
      const lastPart = parts[parts.length - 1] ?? "";
      const detected = allFindingText.includes(val) || (lastPart.length > 3 && allFindingText.includes(lastPart)) || (ioc.mitre != null && foundMitres.has(ioc.mitre));
      return `<tr><td style="border-bottom:1px solid var(--border)">${escapeHtml(ioc.value)}</td><td>${escapeHtml(ioc.mitre ?? "")}</td><td style="color:${detected ? "var(--green)" : "var(--red)"}">${detected ? "YES" : "NO"}</td></tr>`;
    }).join("")}
  </table>
  </details>
  <details style="margin-top:0.5rem"><summary style="cursor:pointer;font-weight:600">TTP Breakdown</summary>
  <table style="width:100%;font-size:0.8rem;margin-top:0.5rem;border-collapse:collapse">
    <tr><th style="text-align:left;border-bottom:1px solid var(--border)">Technique</th><th>Detected</th></tr>
    ${gtTtps.map(t => `<tr><td style="border-bottom:1px solid var(--border)">${escapeHtml(t)}</td><td style="color:${foundMitres.has(t) ? "var(--green)" : "var(--red)"}">${foundMitres.has(t) ? "YES" : "NO"}</td></tr>`).join("")}
  </table>
  </details>
</div>`;
  } catch { return ""; }
})()}

<footer>
  SIFT Kernel — Forensic Evidence Operating System | Zero Trust Architecture | Hash-Chained Provenance
</footer>
</body>
</html>`;

        // Save to output directory
        const outputDir = config.outputPath;
        const evidenceName = investigationState.imagePath
          ? path.basename(investigationState.imagePath).replace(/\.[^.]+$/, "").replace(/[^a-zA-Z0-9_-]/g, "_")
          : "unknown";
        const reportPath = path.join(outputDir, `${evidenceName}-${now.replace(/[:.]/g, "-")}.html`);
        try { fs.mkdirSync(outputDir, { recursive: true }); } catch { /* best-effort: writeFileSync below will surface real permission errors */ }
        fs.writeFileSync(reportPath, htmlContent);

        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "report_generated", format: "html", path: reportPath, findings_count: reportFindings.length, coverage, chain_valid: ledgerStore.verifyChain().isOk(), hmac_seal: hmacValue }) }] };
      }

      // JSON format — save to file
      const jsonReport = {
        report: {
          generated_at: now,
          phase: capabilityGraph.getPhase(),
          coverage,
          findings: reportFindings,
          hypotheses: [...hypotheses.values()],
          chain_valid: chainValid,
          total_tool_calls: totalCalls,
        },
      };
      const fs3 = await import("node:fs");
      const path3 = await import("node:path");
      const outputDir3 = config.outputPath;
      if (!fs3.existsSync(outputDir3)) fs3.mkdirSync(outputDir3, { recursive: true });
      const evidenceName3 = investigationState.imagePath
        ? path3.basename(investigationState.imagePath).replace(/\.[^.]+$/, "").replace(/[^a-zA-Z0-9_-]/g, "_")
        : "unknown";
      const reportPath3 = path3.join(outputDir3, `${evidenceName3}-${now.replace(/[:.]/g, "-")}.json`);
      fs3.writeFileSync(reportPath3, JSON.stringify(jsonReport, null, 2));
      return { content: [{ type: "text" as const, text: JSON.stringify({ status: "report_generated", format: "json", path: reportPath3, findings_count: reportFindings.length, coverage, chain_valid: chainValid }) }] };
    }

    if (name === "verify_chain") {
      const chainResult = ledgerStore.verifyChain();
      if (chainResult.isErr()) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ valid: false, error: chainResult.error.message }) }] };
      }
      const { valid, entryCount, message } = chainResult.value;
      return { content: [{ type: "text" as const, text: JSON.stringify({ valid, entries_checked: entryCount, message }) }] };
    }

    // ── mount_evidence: Special handler (multi-step, format-aware) ──
    // E01 images require: ewfmount → creates /mnt/ewf/ewf1 → mount -o ro,loop → filesystem
    // Raw/dd images: mount -o ro,loop,noexec directly
    // VMDK images: qemu-nbd or mount via loop
    // This is documented in SIFT Workstation usage guides.
    if (name === "mount_evidence") {
      const imagePath = toolParams["image_path"] as string;
      if (!imagePath) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "image_path is required" }) }], isError: true };
      }

      // Detect format from extension (verified approach from SIFT docs)
      const ext = imagePath.toLowerCase().split(".").pop() ?? "";
      const mountSteps: string[] = [];
      let mountCommand: { binary: string; args: string[] };

      // ── MEMORY IMAGE DETECTION ──
      const MEMORY_EXTENSIONS = new Set(["raw", "img", "dmp", "mem", "vmem", "lime", "core"]);
      const PCAP_EXTENSIONS = new Set(["pcap", "pcapng", "cap"]);

      if (MEMORY_EXTENSIONS.has(ext) && !imagePath.includes("drive") && !imagePath.includes("disk")) {
        // Check if this is actually a memory dump (vol can identify it)
        const volCheck = await executor.execute("vol", ["-f", imagePath, "windows.info.Info"]);
        if (volCheck.isOk() && (volCheck.value.exitCode === 0 || volCheck.value.stdout.includes("Kernel"))) {
          investigationState.imagePath = imagePath;
          investigationState.evidenceType = "memory";
          investigationState.imageFormat = ext;
          investigationState.accessMode = "raw";
          capabilityGraph.produce("mount_evidence");
          capabilityGraph.grant("memory_profiled" as Capability);
          methodology.recordExecution("mount_evidence");
          // Record in ledger
          const outputHash = hashData(volCheck.value.stdout);
          const lastEntry = ledgerStore.getLastEntry();
          const prevHash = lastEntry ? hashEntry(lastEntry) : getGenesisHash();
          const entry = createLedgerEntry({ tool: "mount_evidence", toolParams: { image_path: imagePath, format: "memory" }, outputHash, rawOutputPath: "", prevHash, capabilitiesHeld: capabilityGraph.getHeld(), findingsProduced: [], anomaliesFlagged: [], durationMs: 0, success: true });
          const storeResult = rawStore.store(entry.id, volCheck.value.stdout);
          ledgerStore.append({ ...entry, rawOutputPath: storeResult.isOk() ? storeResult.value : "" });
          const autoActivated = disclosure.onCapabilityGained(["evidence_mounted", "memory_profiled"] as readonly Capability[]);
          return { content: [{ type: "text" as const, text: JSON.stringify({ result: { status: "mounted", image_path: imagePath, format: "MEMORY", evidence_type: "memory", note: "Memory image detected. Volatility3 workflows unlocked." }, suggested_next_actions: [{ tool: "verify_integrity", reason: "Verify memory dump integrity", priority: "CRITICAL" }], progress: { phase: capabilityGraph.getPhase(), workflows_newly_activated: autoActivated }, ledger_entry_id: entry.id }) }] };
        }
      }

      if (PCAP_EXTENSIONS.has(ext)) {
        // Network capture — no disk mount needed
        investigationState.imagePath = imagePath;
        investigationState.evidenceType = "pcap";
        investigationState.imageFormat = ext;
        investigationState.accessMode = "raw";
        capabilityGraph.produce("mount_evidence");
        capabilityGraph.grant("network_capture_loaded" as Capability);
        methodology.recordExecution("mount_evidence");
        const pcapHash = hashData(`PCAP: ${imagePath}`);
        const pcapLastEntry = ledgerStore.getLastEntry();
        const pcapPrevHash = pcapLastEntry ? hashEntry(pcapLastEntry) : getGenesisHash();
        const pcapEntry = createLedgerEntry({ tool: "mount_evidence", toolParams: { image_path: imagePath, format: "pcap" }, outputHash: pcapHash, rawOutputPath: "", prevHash: pcapPrevHash, capabilitiesHeld: capabilityGraph.getHeld(), findingsProduced: [], anomaliesFlagged: [], durationMs: 0, success: true });
        rawStore.store(pcapEntry.id, `PCAP loaded: ${imagePath}`);
        ledgerStore.append({ ...pcapEntry, rawOutputPath: "" });
        const pcapAutoActivated = disclosure.onCapabilityGained(["evidence_mounted", "network_capture_loaded"] as readonly Capability[]);
        return { content: [{ type: "text" as const, text: JSON.stringify({ result: { status: "mounted", image_path: imagePath, format: "PCAP", evidence_type: "pcap", note: "Network capture detected. Network forensics workflow unlocked." }, suggested_next_actions: [{ tool: "verify_integrity", reason: "Verify capture integrity", priority: "CRITICAL" }], progress: { phase: capabilityGraph.getPhase(), workflows_newly_activated: pcapAutoActivated }, ledger_entry_id: pcapEntry.id }) }] };
      }

      if (ext === "e01" || ext === "s01" || ext === "ex01") {
        // Expert Witness Format: requires ewfmount first (verified from Protocol SIFT + SIFT docs)
        mountSteps.push(
          `1. ewfmount "${imagePath}" /mnt/ewf/ → creates /mnt/ewf/ewf1`,
          `2. mount -o ro,loop,noexec,noatime /mnt/ewf/ewf1 /mnt/evidence/`
        );
        mountCommand = { binary: "ewfmount", args: [imagePath, "/mnt/ewf/"] };
      } else if (ext === "vmdk") {
        mountSteps.push(
          `1. qemu-nbd -r -c /dev/nbd0 "${imagePath}"`,
          `2. mount -o ro,noexec,noatime /dev/nbd0p1 /mnt/evidence/`
        );
        mountCommand = { binary: "qemu-nbd", args: ["-r", "-c", "/dev/nbd0", imagePath] };
      } else if (ext === "aff4") {
        mountSteps.push(
          `1. affuse "${imagePath}" /mnt/aff/ → creates raw image`,
          `2. mount -o ro,loop,noexec,noatime /mnt/aff/*.raw /mnt/evidence/`
        );
        mountCommand = { binary: "affuse", args: [imagePath, "/mnt/aff/"] };
      } else {
        // Raw/dd — direct mount
        mountSteps.push(`mount -o ro,loop,noexec,noatime "${imagePath}" /mnt/evidence/`);
        mountCommand = { binary: "mount", args: ["-o", "ro,loop,noexec,noatime", imagePath, "/mnt/evidence/"] };
      }

      // Execute first step of mount
      const execResult = await executor.execute(mountCommand.binary, mountCommand.args);
      let success = execResult.isOk() && execResult.value.exitCode === 0;
      let rawOutput = execResult.isOk() ? execResult.value.stdout + execResult.value.stderr : execResult.isErr() ? execResult.error.message : "";

      // FALLBACK: If mount fails, check if the image is directly accessible by sleuthkit
      // This handles ewfmounted images (/mnt/ewf/ewf1) and raw images that don't need mounting
      if (!success) {
        const flsCheck = await executor.execute("fls", ["-o", "0", imagePath]);
        if (flsCheck.isOk() && flsCheck.value.exitCode === 0 && flsCheck.value.stdout.length > 0) {
          success = true;
          rawOutput = `Image accessible directly via Sleuth Kit (no filesystem mount needed).\nRoot entries:\n${flsCheck.value.stdout.slice(0, 2000)}`;
          // Try to detect partition offset via mmls
          const mmlsResult = await executor.execute("mmls", [imagePath]);
          if (mmlsResult.isOk() && mmlsResult.value.exitCode === 0 && mmlsResult.value.stdout.length > 0) {
            // Parse mmls output: find the largest NTFS partition
            const lines = mmlsResult.value.stdout.split("\n");
            for (const line of lines) {
              if (/NTFS|Win95|FAT/i.test(line)) {
                const match = line.match(/\d+:\s+\d+\s+(\d+)\s+\d+\s+(\d+)/);
                if (match?.[1]) {
                  investigationState.partitionOffset = parseInt(match[1], 10);
                  break;
                }
              }
            }
          }
          // If mmls found nothing (single partition), offset stays 0
          investigationState.imagePath = imagePath;
          investigationState.accessMode = "raw";
          investigationState.imageFormat = ext || "raw";

          // Detect filesystem type and evidence type via fsstat
          const fsResult = await executor.execute("fsstat", ["-o", String(investigationState.partitionOffset), imagePath]);
          if (fsResult.isOk() && fsResult.value.exitCode === 0) {
            const fsOutput = fsResult.value.stdout;
            if (/NTFS|FAT/i.test(fsOutput)) {
              investigationState.evidenceType = "disk-windows";
              investigationState.filesystemType = /NTFS/i.test(fsOutput) ? "NTFS" : "FAT";
            } else if (/ext[234]|xfs|btrfs/i.test(fsOutput)) {
              investigationState.evidenceType = "disk-linux";
              investigationState.filesystemType = fsOutput.match(/ext[234]|xfs|btrfs/i)?.[0] ?? "ext4";
              capabilityGraph.grant("linux_accessible" as Capability);
            } else if (/HFS|APFS/i.test(fsOutput)) {
              investigationState.evidenceType = "disk-macos";
              investigationState.filesystemType = /APFS/i.test(fsOutput) ? "APFS" : "HFS+";
            } else {
              investigationState.evidenceType = "disk-windows"; // default assumption for unknown disk FS
              investigationState.filesystemType = "unknown";
            }
          }
        }
      }

      // Record in ledger regardless of outcome
      const outputHash = hashData(rawOutput);
      const lastEntry = ledgerStore.getLastEntry();
      const prevHash = lastEntry ? hashEntry(lastEntry) : getGenesisHash();
      const entry = createLedgerEntry({
        tool: "mount_evidence",
        toolParams: { image_path: imagePath, format: ext },
        outputHash,
        rawOutputPath: "",
        prevHash,
        capabilitiesHeld: capabilityGraph.getHeld(),
        findingsProduced: [],
        anomaliesFlagged: [],
        durationMs: 0,
        success,
        ...(success ? {} : { errorMessage: rawOutput }),
      });
      const storeResult = rawStore.store(entry.id, rawOutput);
      ledgerStore.append({ ...entry, rawOutputPath: storeResult.isOk() ? storeResult.value : "" });

      // Produce capabilities on success
      if (success) {
        // Update investigation state — tools will read from here
        if (!investigationState.imagePath) {
          investigationState.imagePath = imagePath;
          investigationState.imageFormat = ext || "raw";
        }
        capabilityGraph.produce("mount_evidence");
        methodology.recordExecution("mount_evidence");
        methodology.setEvidenceType(investigationState.evidenceType);
        const autoActivated = disclosure.onCapabilityGained(["evidence_mounted"]);

        return { content: [{ type: "text" as const, text: JSON.stringify({
          result: {
            status: "mounted",
            image_path: imagePath,
            format: ext.toUpperCase(),
            evidence_type: investigationState.evidenceType,
            filesystem_type: investigationState.filesystemType,
            mount_point: "/mnt/evidence/",
            read_only: true,
            mount_steps: mountSteps,
            note: ext === "e01" ? "E01 mounted via ewfmount (two-step process per SIFT documentation)" : "Direct read-only mount",
          },
          suggested_next_actions: [{ tool: "verify_integrity", reason: "Always verify evidence integrity before analysis", priority: "CRITICAL" }],
          progress: { phase: capabilityGraph.getPhase(), overall_coverage: methodology.getOverallCoverage(), workflows_newly_activated: autoActivated },
          ledger_entry_id: entry.id,
        }) }] };
      }

      return { content: [{ type: "text" as const, text: JSON.stringify({
        error: "MOUNT_FAILED",
        image_path: imagePath,
        format: ext,
        mount_steps: mountSteps,
        raw_error: rawOutput,
        guidance: `Ensure image exists at ${imagePath} and required tool (${mountCommand.binary}) is installed. On SIFT: all tools pre-installed.`,
      }) }], isError: true };
    }

    // ── Capability Check ──
    const canExec = capabilityGraph.canExecute(name);
    if (canExec.isErr()) {
      const error = canExec.error;
      return { content: [{ type: "text" as const, text: JSON.stringify({
        error: "CAPABILITY_BLOCKED",
        tool: name,
        missing_capabilities: error.missing,
        held_capabilities: error.held,
        guidance: error.guidance,
        suggestion: methodology.suggestNextAction(capabilityGraph.getHeld()),
      }) }], isError: true };
    }

    // ── Execute Forensic Tool ──
    const startTime = Date.now();
    const mapping = getToolBinaryMapping(name, investigationState.partitionOffset);

    let rawOutput: string;
    let success: boolean;
    let errorMsg: string | undefined;

    // Async tools (minutes-long) return job_id immediately and run in background
    if (ASYNC_TOOLS.has(name) && mapping) {
      const jobId = `job-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const evidencePath = investigationState.imagePath || config.evidencePath;
      const args = mapping.buildArgs(toolParams, evidencePath, investigationState.partitionOffset, config.outputPath);
      asyncJobs.set(jobId, { status: "running", tool: name, startedAt: new Date().toISOString() });
      // Fire and forget — runs in background
      executor.execute(mapping.binary, args, { timeoutMs: 300_000 }).then((result) => {
        if (result.isOk()) {
          const output = result.value.stdout;
          // Write async output to a file in the output directory
          const outputPath = `${config.outputPath}/async-${jobId}.txt`;
          try { writeFileSync(outputPath, output); } catch { /* best-effort */ }
          asyncJobs.set(jobId, { status: "completed", tool: name, startedAt: asyncJobs.get(jobId)!.startedAt, result: output.slice(0, 2000), outputPath });
        } else {
          asyncJobs.set(jobId, { status: "failed", tool: name, startedAt: asyncJobs.get(jobId)!.startedAt, error: result.error.message });
        }
      });
      // Record in ledger
      const lastEntry = ledgerStore.getLastEntry();
      const prevHash = lastEntry ? hashEntry(lastEntry) : getGenesisHash();
      const entry = createLedgerEntry({ tool: name, toolParams, outputHash: "", rawOutputPath: "", prevHash, capabilitiesHeld: capabilityGraph.getHeld(), findingsProduced: [], anomaliesFlagged: [], durationMs: 0, success: true });
      ledgerStore.append(entry);
      // Mark launched so the methodology FSM advances (the job is dispatched —
      // the agent must NOT be told to launch it again; it polls get_job_status).
      methodology.recordExecution(name);
      return { content: [{ type: "text" as const, text: JSON.stringify({
        status: "ASYNC_JOB_STARTED",
        job_id: jobId,
        tool: name,
        message: `${name} is a long-running operation. It has been started in the background. Call get_job_status with job_id="${jobId}" to check progress.`,
        suggested_next_actions: [{ tool: "get_job_status", params: { job_id: jobId }, reason: "Check if the background job has completed" }],
      }) }] };
    }

    // Long-running tools get progress notifications
    const LONG_RUNNING_TOOLS = new Set(["generate_timeline", "filter_timeline", "scan_yara", "scan_memory_yara", "list_processes", "detect_process_injection", "carve_files", "analyze_unallocated", "detect_rootkit"]);
    const isLongRunning = LONG_RUNNING_TOOLS.has(name);

    if (isLongRunning) {
      server.notification({ method: "notifications/progress", params: { progressToken: name, progress: 0, total: 100, message: `Starting ${name}...` } });
    }

    if (mapping) {
      const evidencePath = investigationState.imagePath || config.evidencePath;
      // Tools that need a HOST PATH to an extracted file (not an evidence-relative path).
      // Event-log parsers take a `path`; registry parsers default to a canonical hive
      // when no path is given so they work autonomously. Large artifacts (262MB evtx,
      // multi-MB hives) are streamed to disk via extractToFile (no in-memory size cap).
      const REGISTRY_DEFAULT_HIVE: Record<string, string> = {
        get_system_config: "/Windows/System32/config/SYSTEM",
        get_persistence_keys: "/Windows/System32/config/SOFTWARE",
        get_installed_software: "/Windows/System32/config/SOFTWARE",
        get_usb_history: "/Windows/System32/config/SYSTEM",
        get_network_config: "/Windows/System32/config/SYSTEM",
        parse_sam: "/Windows/System32/config/SAM",
        parse_shimcache: "/Windows/System32/config/SYSTEM",
        parse_bam: "/Windows/System32/config/SYSTEM",
      };
      const toolsNeedingExtractedFile = new Set([
        "parse_event_log", "search_events", "parse_powershell_logs",
        "parse_registry_key", "get_user_activity", "get_system_config",
        "get_persistence_keys", "get_installed_software", "get_usb_history",
        "get_network_config", "parse_sam", "parse_shimcache", "parse_bam",
        "parse_muicache", "parse_userassist",
      ]);
      // Default canonical hive for registry tools when the agent gave no path
      if (REGISTRY_DEFAULT_HIVE[name] && !toolParams["path"]) {
        toolParams["path"] = REGISTRY_DEFAULT_HIVE[name];
      }
      if (toolsNeedingExtractedFile.has(name) && toolParams["path"] && evidencePath) {
        const pathStr = String(toolParams["path"]).replace(/^\//, "").replace(/\/$/, "");
        // Only resolve+extract if this is an evidence-relative path (not an already-extracted host path)
        if (pathStr && !String(toolParams["path"]).startsWith(config.outputPath)) {
          const segments = pathStr.split("/").filter(Boolean);
          let currentInode: string | null = null;
          for (const seg of segments) {
            const flsArgs = ["-o", String(investigationState.partitionOffset), evidencePath, ...(currentInode ? [currentInode] : [])];
            const segResult = await executor.execute("fls", flsArgs);
            if (segResult.isErr()) break;
            const lines = segResult.value.stdout.split("\n");
            const match = lines.find(l => {
              const parts = l.split("\t");
              const n = parts[1];
              return parts.length >= 2 && n !== undefined && n.toLowerCase() === seg.toLowerCase();
            });
            if (match) {
              const inodeMatch = match.match(/\s(\d+)(?:-\d+)*(?:-\d+)*:/);
              if (inodeMatch && inodeMatch[1]) { currentInode = inodeMatch[1]; } else break;
            } else break;
          }
          if (currentInode) {
            // Stream-extract via icat to a host file (no size cap — handles 262MB evtx)
            const safeName = (segments[segments.length - 1] ?? "file").replace(/[^A-Za-z0-9._-]/g, "_");
            const extractedPath = `${config.outputPath}/extracted_${currentInode}_${safeName}`;
            const exResult = await executor.extractToFile(
              "icat",
              ["-o", String(investigationState.partitionOffset), evidencePath, currentInode],
              extractedPath,
            );
            if (exResult.isOk()) {
              toolParams["path"] = extractedPath;
            }
          }
        }
      }

      const tskToolsNeedingInode = new Set(["list_directory", "search_filename"]);
      if (tskToolsNeedingInode.has(name) && toolParams["path"] && !toolParams["inode"] && evidencePath) {
        const pathStr = String(toolParams["path"]).replace(/^\//, "").replace(/\/$/, "");
        if (pathStr) {
          const segments = pathStr.split("/").filter(Boolean);
          let currentInode: string | null = null;
          for (const seg of segments) {
            const flsArgs = ["-o", String(investigationState.partitionOffset), evidencePath, ...(currentInode ? [currentInode] : [])];
            const segResult = await executor.execute("fls", flsArgs);
            if (segResult.isErr()) break;
            const lines = segResult.value.stdout.split("\n");
            const match = lines.find(l => {
              const parts = l.split("\t");
              const name2 = parts[1];
              return parts.length >= 2 && name2 !== undefined && name2.toLowerCase() === seg.toLowerCase();
            });
            if (match) {
              const inodeMatch = match.match(/\s(\d+)(?:-\d+)*(?:-\d+)*:/);
              if (inodeMatch && inodeMatch[1]) { currentInode = inodeMatch[1]; } else break;
            } else break;
          }
          if (currentInode) {
            toolParams["inode"] = currentInode;
            delete toolParams["path"];
          }
        }
      }
      const args = mapping.buildArgs(toolParams, evidencePath, investigationState.partitionOffset, config.outputPath);
      if (isLongRunning) {
        server.notification({ method: "notifications/progress", params: { progressToken: name, progress: 10, total: 100, message: `Executing ${mapping.binary}...` } });
      }
      // Per-tool executor options: searches and recursive ops get shorter timeout + line limit
      const execOpts: import("./ports/tool-executor.port.js").ExecutorOptions = {};
      if (name === "search_filename") {
        Object.assign(execOpts, { timeoutMs: 30_000, maxLines: 50_000 });
      } else if (name === "list_directory" && toolParams["recursive"]) {
        Object.assign(execOpts, { timeoutMs: 30_000, maxLines: 20_000 });
      } else if (name === "parse_event_log" || name === "search_events" || name === "parse_powershell_logs") {
        // evtx_dump on a 262MB log emits millions of JSONL events; bound output to a
        // representative sample (≈3000 events) — enough to detect clearing (EID 1102),
        // logons (4624/4625), process creation (4688) — without flooding LLM context.
        Object.assign(execOpts, { timeoutMs: 35_000, maxLines: 3_000 });
      }
      const execResult = await executor.execute(mapping.binary, args, execOpts);
      if (execResult.isErr()) {
        rawOutput = "";
        success = false;
        errorMsg = execResult.error.message;
      } else {
        rawOutput = execResult.value.stdout;
        // exitCode -1 = killed due to line limit (partial output is valid for searches)
        success = execResult.value.exitCode === 0 || (execResult.value.exitCode === -1 && rawOutput.length > 0);
        errorMsg = success ? undefined : execResult.value.stderr;
        // regipy-plugins-run writes JSON to its -o file; stdout is only progress noise
        // ("Loaded N plugins / Finished X/N"). Always read the JSON file, not stdout.
        if (success && mapping.binary === "regipy-plugins-run") {
          try {
            const { readFileSync, unlinkSync } = await import("node:fs");
            try {
              const json = readFileSync(`${config.outputPath}/regipy_out.json`, "utf8");
              if (json.trim().length > 0) rawOutput = json;
              try { unlinkSync(`${config.outputPath}/regipy_out.json`); } catch { /* ignore */ }
            } catch { /* file missing — tool produced no output */ }
          } catch { /* import failure — leave stdout */ }
        }
      }
      // Post-execution filtering: search_filename filters fls output by regex pattern
      if (name === "search_filename" && success && rawOutput) {
        const pattern = toolParams["pattern"] as string | undefined;
        if (pattern) {
          try {
            const re = new RegExp(pattern, toolParams["case_sensitive"] ? "" : "i");
            rawOutput = rawOutput.split("\n").filter(line => re.test(line)).join("\n");
          } catch { /* invalid regex — return unfiltered */ }
        }
      }
      if (isLongRunning) {
        server.notification({ method: "notifications/progress", params: { progressToken: name, progress: 90, total: 100, message: `Parsing output...` } });
      }
    } else {
      // Try in-process handler (intelligence detectors, correlation, text parsing)
      const entries = ledgerStore.getAllEntries();
      const rawOutputMap = new Map<string, string>();
      for (const e of entries) {
        const r = rawStore.retrieve(e.id);
        if (r.isOk()) rawOutputMap.set(e.id as string, r.value);
      }
      const context: HandlerContext = {
        findings,
        hypotheses,
        ledgerEntries: entries,
        rawOutputs: rawOutputMap,
        evidencePath: investigationState.imagePath || config.evidencePath,
      };
      const inProcessResult = executeInProcess(name, toolParams, context);
      if (inProcessResult) {
        rawOutput = inProcessResult.output;
        success = inProcessResult.success;
        errorMsg = inProcessResult.success ? undefined : inProcessResult.error;
      } else {
        // No binary mapping AND no in-process handler — HONEST failure
        rawOutput = "";
        success = false;
        errorMsg = `Tool "${name}" requires SIFT Workstation forensic binary that is not available on this system. Install SIFT: sudo cast install teamdfir/sift`;
      }
    }

    const durationMs = Date.now() - startTime;

    // Determinism tracking — did the LLM follow our recommendation?
    if (determinismTracker.lastRecommendedTool) {
      determinismTracker.totalRecommendations++;
      if (name === determinismTracker.lastRecommendedTool) { determinismTracker.followed++; }
      else { determinismTracker.deviated++; }
    }

    // Parse output + detect anomalies
    const { parsed, anomalies } = rawOutput ? parseToolOutput(name, rawOutput) : { parsed: success ? { status: "completed", tool: name } : { error: errorMsg ?? "Tool execution failed" }, anomalies: [] as AnomalyFlag[] };

    // Create ledger entry first (need the ID for raw store)
    const outputHash = hashData(JSON.stringify(parsed));
    const lastEntry = ledgerStore.getLastEntry();
    const prevHash = lastEntry ? hashEntry(lastEntry) : getGenesisHash();
    const entry = createLedgerEntry({
      tool: name,
      toolParams,
      outputHash,
      rawOutputPath: "",
      prevHash,
      capabilitiesHeld: capabilityGraph.getHeld(),
      findingsProduced: [],
      anomaliesFlagged: [],
      durationMs,
      success,
      ...(errorMsg ? { errorMessage: errorMsg } : {}),
    });

    // Store raw output using the entry ID
    const storeResult = rawStore.store(entry.id, rawOutput);
    const rawPath = storeResult.isOk() ? storeResult.value : "";

    // Update entry with raw path and append to ledger
    const finalEntry = { ...entry, rawOutputPath: rawPath };
    ledgerStore.append(finalEntry);

    // Update capabilities + methodology — capabilities ONLY produced on success
    let produced: readonly Capability[] = [];
     if (success) {
       produced = capabilityGraph.produce(name) as readonly Capability[];
       methodology.recordExecution(name);
       // Detect investigation signals from tool output (drives FSM transitions)
       if (rawOutput) {
         methodology.detectSignals(rawOutput);
       }
     } else {
       methodology.recordFailure(name);
     }

     // FARE: Process tool output through reasoning engine (DSmT/PCR5 + EFE + convergence)
     const toolCategory = capabilityGraph.getSpec(name)?.category ?? "filesystem";
     const reasoningUpdate = reasoningEngine.processToolOutput(name, rawOutput, success, toolCategory);

     // Auto-activate workflows for newly gained capabilities
    const autoActivated = disclosure.onCapabilityGained(produced);

    // Build enriched response — result MUST be an object (outputSchema requires type:\"object\")
    const suggestion = methodology.suggestNextAction(capabilityGraph.getHeld());
    // Record what we recommend for determinism scoring on next call
    determinismTracker.lastRecommendedTool = suggestion?.tool ?? null;
    const resultObj = (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed))
      ? parsed as Record<string, unknown>
      : { data: parsed };

    // Forensic Knowledge enrichment — tool-specific caveats and corroboration guidance
    const forensicContext = getForensicContext(name, anomalies.length > 0);

    const response = {
      result: resultObj,
      anomalies: anomalies.map((a) => ({ type: a.type, severity: a.severity, description: a.description, affected_items: a.affectedItems })),
      forensic_context: forensicContext,
      suggested_next_actions: suggestion ? [{
        tool: suggestion.tool,
        reason: suggestion.reason,
        priority: suggestion.priority,
        call_as: KERNEL_TOOL_NAMES.includes(suggestion.tool)
          ? { tool: suggestion.tool, params: {} }
          : { tool: capabilityGraph.getSpec(suggestion.tool)?.category ?? "unknown", params: { operation: suggestion.tool } },
        investigation_context: suggestion.activePathNames.length > 0 ? `Active paths: ${suggestion.activePathNames.join(", ")}` : undefined,
      }] : [],
      progress: {
        phase: capabilityGraph.getPhase(),
        overall_coverage: methodology.getOverallCoverage(),
        active_workflows: disclosure.getActiveWorkflows(),
        workflows_newly_activated: autoActivated,
      },
      reasoning: {
        entropy: reasoningUpdate.entropy,
        convergence: reasoningUpdate.convergenceState,
        conflict: reasoningUpdate.conflict,
        dominant_hypothesis: reasoningUpdate.dominantHypothesis,
        rules_fired: reasoningUpdate.triggeredRules,
        bias_warnings: reasoningUpdate.biasWarnings,
        comeback_triggered: reasoningUpdate.comebackTriggered,
        // Self-correction signal (arXiv:2601.00828 — external feedback > intrinsic self-correction)
        // Provides SPECIFIC contradicting evidence, not just "conflict detected"
        self_correction_trigger: reasoningUpdate.conflict > 0.3
          ? { type: "CONFLICT", conflict_k: reasoningUpdate.conflict, message: `Evidence conflict K=${reasoningUpdate.conflict.toFixed(2)} detected. Prior hypothesis may need revision.`, contradicting_evidence: reasoningUpdate.triggeredRules.slice(-2).join("; "), action: "Re-examine with contradicting evidence. The most recent signals conflict with the dominant hypothesis — investigate the alternative." }
          : reasoningUpdate.convergenceState === "STUCK"
            ? { type: "STUCK", entropy: reasoningUpdate.entropy, message: "Entropy plateau detected — investigation not learning.", action: "Try FALSIFYING the leading hypothesis instead of confirming it. Look for evidence that would DISPROVE your current theory." }
            : reasoningUpdate.convergenceState === "DIVERGING"
              ? { type: "DIVERGING", entropy: reasoningUpdate.entropy, message: "Entropy increasing — new contradictory evidence found.", action: "A new signal contradicts prior conclusions. Register a new hypothesis to account for the divergent evidence." }
              : reasoningUpdate.biasWarnings.length > 0
                ? { type: "BIAS", bias_type: reasoningUpdate.biasWarnings[0]?.type ?? "unknown", message: `${reasoningUpdate.biasWarnings[0]?.type ?? "unknown"} bias detected.`, action: "Consider alternative explanations. You may be confirming what you expect rather than testing what you don't." }
                : null,
      },
      // Inference constraint metadata (Hilgert et al. 2025, arXiv:2506.00274)
      inference_constraint: {
        level: anomalies.length > 0 ? 4 : (parsed && typeof parsed === "object" ? 3 : 2),
        description: anomalies.length > 0
          ? "L4: Full abstraction — server performed parsing + anomaly detection, returning pre-interpreted data"
          : "L3: Structured output — server parsed raw tool output into typed JSON",
      },
      // Determinism tracking (Gruber & Hilgert 2026, arXiv:2604.05589)
      determinism: {
        tool_recommended: suggestion?.tool ?? null,
        recommendation_followed: determinismTracker.lastRecommendedTool === name,
        score: determinismTracker.getScore(),
        stats: { total: determinismTracker.totalRecommendations, followed: determinismTracker.followed, deviated: determinismTracker.deviated },
      },
      ledger_entry_id: entry.id,
      duration_ms: durationMs,
    };

    if (!success && errorMsg) {
      if (isLongRunning) {
        server.notification({ method: "notifications/progress", params: { progressToken: name, progress: 100, total: 100, message: `Failed: ${errorMsg.slice(0, 50)}` } });
      }
      const errorResponse = { ...response, error: errorMsg };
      return { content: [{ type: "text" as const, text: JSON.stringify(errorResponse) }], structuredContent: errorResponse, isError: true };
    }

    if (isLongRunning) {
      server.notification({ method: "notifications/progress", params: { progressToken: name, progress: 100, total: 100, message: `Complete (${durationMs}ms)` } });
    }

    return { content: [{ type: "text" as const, text: JSON.stringify(response) }], structuredContent: response };
  });

  // ─── Resources ─────────────────────────────────────────────────────────────

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: [
      { uri: "forensic://methodology/windows-ir", name: "Windows IR Methodology", description: "Complete Windows incident response methodology", mimeType: "text/markdown" },
      { uri: "forensic://methodology/memory-analysis", name: "Memory Analysis Guide", description: "Memory forensics analysis playbook", mimeType: "text/markdown" },
      { uri: "forensic://artifact-types", name: "Artifact Types Reference", description: "All forensic artifact types and their significance", mimeType: "application/json" },
      { uri: "forensic://investigation/state", name: "Current Investigation State", description: "Live investigation state and progress", mimeType: "application/json" },
    ],
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    if (uri === "forensic://methodology/windows-ir") {
      return { contents: [{ uri, mimeType: "text/markdown", text: WINDOWS_IR_METHODOLOGY }] };
    }
    if (uri === "forensic://methodology/memory-analysis") {
      return { contents: [{ uri, mimeType: "text/markdown", text: MEMORY_ANALYSIS_GUIDE }] };
    }
    if (uri === "forensic://artifact-types") {
      return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(ARTIFACT_TYPES) }] };
    }
    if (uri === "forensic://investigation/state") {
      return { contents: [{ uri, mimeType: "application/json", text: JSON.stringify({ phase: capabilityGraph.getPhase(), capabilities: capabilityGraph.getHeld(), coverage: methodology.getOverallCoverage(), findings: findings.size }) }] };
    }
    return { contents: [] };
  });

  // ─── Prompts ───────────────────────────────────────────────────────────────

  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: [
      { name: "start_investigation", description: "Begin a full forensic investigation from image mount to final report" },
      { name: "quick_triage", description: "Fast triage for initial assessment of evidence" },
      { name: "deep_analysis", description: "Focused deep analysis on specific artifact category" },
    ],
  }));

  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name: promptName } = request.params;
    if (promptName === "start_investigation") {
      return { messages: [{ role: "user" as const, content: { type: "text" as const, text: INVESTIGATION_PROMPT } }] };
    }
    if (promptName === "quick_triage") {
      return { messages: [{ role: "user" as const, content: { type: "text" as const, text: TRIAGE_PROMPT } }] };
    }
    if (promptName === "deep_analysis") {
      return { messages: [{ role: "user" as const, content: { type: "text" as const, text: DEEP_ANALYSIS_PROMPT } }] };
    }
    return { messages: [] };
  });

  // ─── Helper Functions ──────────────────────────────────────────────────────

  function findConflicts(): Array<{ finding_a: string; finding_b: string; reason: string }> {
    const conflicts: Array<{ finding_a: string; finding_b: string; reason: string }> = [];
    const findingList = [...findings.values()];
    for (let i = 0; i < findingList.length; i++) {
      for (let j = i + 1; j < findingList.length; j++) {
        if (findingsConflict(findingList[i]!, findingList[j]!)) {
          conflicts.push({ finding_a: findingList[i]!.id as string, finding_b: findingList[j]!.id as string, reason: "Contradicting evidence on same technique/hypothesis" });
        }
      }
    }
    return conflicts;
  }

  function generateInvestigationQuestions(): string[] {
    const questions: string[] = [];
    const phase = capabilityGraph.getPhase();
    if (phase === "UNINITIALIZED") questions.push("What forensic image should be examined?");
    if (phase === "MOUNTED") questions.push("Has the evidence integrity been verified?");
    if (findings.size === 0 && phase !== "UNINITIALIZED") questions.push("What artifacts suggest initial access?", "Are there signs of persistence?");
    const gaps = methodology.getCoverageGaps(capabilityGraph.getHeld());
    for (const gap of gaps.slice(0, 3)) {
      questions.push(`Have ${gap.category} artifacts been examined? (${gap.tool}: ${gap.description})`);
    }
    if (findings.size > 0) {
      const inferred = [...findings.values()].filter((f) => f.confidence === "INFERRED");
      for (const f of inferred.slice(0, 2)) {
        questions.push(`Can finding "${f.description}" be corroborated with additional evidence?`);
      }
    }
    return questions;
  }

  function suggestCorroboration(finding: Finding): Array<{ tool: string; reason: string }> {
    const suggestions: Array<{ tool: string; reason: string }> = [];
    const existingCategories = new Set<string>();
    const allEntries = ledgerStore.getAllEntries();
    for (const evId of finding.evidence) {
      const entry = allEntries.find((e) => e.id === evId);
      if (entry) existingCategories.add(capabilityGraph.getCategory(entry.tool) ?? "");
    }
    // Suggest tools from categories NOT already used as evidence
    const allCategories: ArtifactCategory[] = ["filesystem", "timeline", "registry", "event_logs", "execution_artifacts", "persistence", "memory", "network"];
    for (const cat of allCategories) {
      if (!existingCategories.has(cat)) {
        const tools = capabilityGraph.getToolsByCategory(cat);
        if (tools.length > 0) {
          suggestions.push({ tool: tools[0]!.tool, reason: `Cross-reference with ${cat} evidence (would upgrade to CONFIRMED)` });
        }
      }
    }
    return suggestions.slice(0, 3);
  }

  function suggestChallenge(finding: Finding): Array<{ strategy: string; tool: string; reason: string }> {
    return [
      { strategy: "temporal_verification", tool: "get_timeline_context", reason: "Verify the timing claims match the super timeline" },
      { strategy: "alternative_explanation", tool: "detect_anti_forensics_summary", reason: "Check if anti-forensics could explain the evidence differently" },
      { strategy: "scope_check", tool: "search_events", reason: "Search for events that would be expected IF this finding were false" },
    ];
  }

  function getHealthRecommendations(coverage: number, unsupported: number, conflicts: number): string[] {
    const recs: string[] = [];
    if (coverage < 50) recs.push("Coverage is low. Use get_coverage_gaps to identify unexamined artifact categories.");
    if (unsupported > 0) recs.push(`${unsupported} findings have only single-source evidence. Use corroborate_finding to strengthen them.`);
    if (conflicts > 0) recs.push(`${conflicts} contradictions detected. Resolve them before generating the final report.`);
    if (recs.length === 0) recs.push("Investigation health is excellent. Consider generating the final report.");
    return recs;
  }

  return server;
}

// ─── MCP Resources Content ───────────────────────────────────────────────────

const WINDOWS_IR_METHODOLOGY = `# Windows Incident Response Methodology

## Phase 1: Evidence Acquisition
1. Mount evidence image read-only
2. Verify integrity (hash comparison)
3. Identify partitions and filesystem type

## Phase 2: Triage
1. List filesystem structure — look for obvious IOCs
2. Check execution artifacts (Prefetch, Amcache) — what ran?
3. Parse event logs — authentication, process creation
4. Check persistence mechanisms — what survives reboot?

## Phase 3: Deep Analysis
1. Generate and filter super timeline
2. Parse registry hives — user activity, system config
3. Analyze browser history — download sources
4. Check anti-forensics indicators — timestomping, log clearing

## Phase 4: Correlation
1. Map findings to MITRE ATT&CK
2. Build attack narrative timeline
3. Identify lateral movement paths
4. Extract IOCs (hashes, IPs, domains)

## Phase 5: Reporting
1. Verify all findings have evidence
2. Corroborate single-source findings
3. Resolve contradictions
4. Generate confidence-graded report
`;

const MEMORY_ANALYSIS_GUIDE = `# Memory Forensics Analysis Guide

## Step 1: Profile Detection
- Identify OS version and architecture
- Determine correct Volatility profile

## Step 2: Process Analysis
- List all processes (pslist/pstree)
- Identify suspicious: unusual parents, misspelled names, wrong paths
- Check for injection (malfind)
- Examine command lines

## Step 3: Network Analysis
- Active connections (netscan)
- Look for C2: unusual ports, known-bad IPs
- Check for DNS tunneling indicators

## Step 4: Code Analysis
- Dump suspicious processes
- YARA scan memory for malware signatures
- Check for rootkits (SSDT/IDT hooks)

## Step 5: Correlation
- Cross-reference with disk artifacts
- Match process timestamps with timeline
- Validate registry persistence with memory state
`;

const ARTIFACT_TYPES = {
  categories: [
    { id: "acquisition", significance: "CRITICAL", description: "Image metadata, partition tables, filesystem information" },
    { id: "filesystem", significance: "HIGH", description: "File system metadata, deleted files, alternate data streams" },
    { id: "timeline", significance: "CRITICAL", description: "Super timeline from all sources — the backbone of any investigation" },
    { id: "registry", significance: "HIGH", description: "System configuration, user activity, persistence mechanisms" },
    { id: "event_logs", significance: "CRITICAL", description: "Authentication, process creation, service installs, PowerShell" },
    { id: "execution_artifacts", significance: "HIGH", description: "Evidence of program execution: Prefetch, Amcache, ShimCache" },
    { id: "persistence", significance: "CRITICAL", description: "How attacker maintains access: services, tasks, WMI, COM" },
    { id: "memory", significance: "HIGH", description: "Live process state, injected code, network connections, rootkits" },
    { id: "network", significance: "MEDIUM", description: "Packet captures, C2 communication, lateral movement traffic" },
    { id: "browser", significance: "MEDIUM", description: "Download sources, browsing history, cached credentials" },
    { id: "user_activity", significance: "MEDIUM", description: "User actions: file access, folder navigation, program usage" },
    { id: "anti_forensics", significance: "CRITICAL", description: "Evidence of evidence destruction: timestomping, log clearing" },
    { id: "correlation", significance: "HIGH", description: "Attack narrative, lateral movement detection, MITRE mapping" },
    { id: "linux", significance: "HIGH", description: "Auth logs, command history, cron persistence, SSH artifacts" },
  ],
};

// ─── MCP Prompts Content ─────────────────────────────────────────────────────

const INVESTIGATION_PROMPT = `You are conducting a forensic investigation using the SIFT Kernel MCP server.

WORKFLOW:
1. Call suggest_next_action() to get your first step
2. Follow the suggestion — call the recommended tool with the recommended params
3. Review the response: check anomalies, read suggested_next_actions
4. Register findings when you discover evidence of attacker activity
5. Call suggest_next_action() again to continue — it returns investigation_status telling you whether to keep going
6. Repeat until investigation_status says READY_FOR_REPORT (the methodology FSM has completed all phases)
7. Call generate_report(format="html") ONLY when investigation_status = READY_FOR_REPORT

CRITICAL — DO NOT STOP EARLY:
- generate_report() will REJECT your call if the FSM has not reached REPORT state
- If a tool fails, call suggest_next_action() — it skips failed tools and suggests the next one
- Tool failures are EXPECTED (dirty hives, missing binaries) — they do NOT mean "stop investigating"
- The FSM tracks what succeeded AND what failed — it only advances when ALL tools are attempted
- You must keep calling suggest_next_action() until investigation_status = "READY_FOR_REPORT"
- There is no shortcut. The loop IS the investigation.

RULES:
- Every finding MUST link to ledger_entry_ids from prior tool calls
- Use register_hypothesis() to propose investigation directions
- Use corroborate_finding() to strengthen weak findings
- Use get_contradictions() to identify conflicts before reporting
- NEVER claim something without tool evidence backing it
- When suggest_next_action tells you to call get_hypothesis_status, DO IT — unresolved hypotheses block report generation

The server guides your methodology. Trust suggest_next_action(). It knows what you've checked and what's missing.`;

const TRIAGE_PROMPT = `Quick triage: identify the most critical indicators in minimum time.

1. mount_evidence → verify_integrity
2. list_directory (check Users/, Windows/Temp/, ProgramData/)
3. parse_prefetch (what executed recently?)
4. list_event_logs → search_events (EID 4688 process creation)
5. get_persistence_keys (what survives reboot?)

Register findings immediately. Don't go deep — flag and move on. The goal is a 5-minute assessment of compromise severity.`;

const DEEP_ANALYSIS_PROMPT = `Deep analysis mode: thoroughly examine one artifact category.

1. Call get_coverage_gaps() to identify the weakest area
2. Activate that workflow
3. Execute EVERY tool in the workflow systematically
4. Cross-reference findings with other categories
5. Corroborate all single-source findings
6. Challenge findings that seem too convenient

The goal is DEPTH, not breadth. Exhaust one category before moving to the next.`;
