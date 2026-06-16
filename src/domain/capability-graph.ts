import type { Capability, ToolCapabilitySpec, ArtifactCategory } from "./types.js";
import { capabilityError, type CapabilityError } from "./errors.js";
import { ok, err, type Result } from "neverthrow";

// ─── Tool Capability Specifications ──────────────────────────────────────────
// Static definition of ALL tools. Each tool has:
// - requires: capabilities that must be held before execution
// - produces: capabilities gained after successful execution
// - category: which workflow this belongs to
// - description: human-readable purpose

export const TOOL_SPECS: readonly ToolCapabilitySpec[] = [
  // ── Acquisition ──
  { tool: "mount_evidence", requires: [], produces: ["evidence_mounted"], category: "acquisition", description: "Mount forensic image read-only (E01/raw/VMDK/AFF4)" },
  { tool: "verify_integrity", requires: ["evidence_mounted"], produces: ["integrity_verified"], category: "acquisition", description: "Verify image hash integrity and create baseline" },
  { tool: "get_image_metadata", requires: ["evidence_mounted"], produces: [], category: "acquisition", description: "Get image format, size, hash, acquisition info" },
  { tool: "list_partitions", requires: ["evidence_mounted"], produces: ["partitions_listed"], category: "acquisition", description: "List partition table via mmls" },
  { tool: "get_filesystem_info", requires: ["partitions_listed"], produces: [], category: "acquisition", description: "Get filesystem details per partition via fsstat" },

  // ── Filesystem ──
  { tool: "list_directory", requires: ["evidence_mounted", "integrity_verified"], produces: ["filesystem_accessible"], category: "filesystem", description: "List directory contents with deleted file detection" },
  { tool: "extract_file", requires: ["filesystem_accessible"], produces: [], category: "filesystem", description: "Extract file by inode to output directory" },
  { tool: "search_filename", requires: ["filesystem_accessible"], produces: [], category: "filesystem", description: "Search filenames by regex across image" },
  { tool: "get_file_metadata", requires: ["filesystem_accessible"], produces: [], category: "filesystem", description: "Get full inode metadata via istat" },
  { tool: "recover_deleted", requires: ["filesystem_accessible"], produces: [], category: "filesystem", description: "Bulk recovery of deleted files" },
  { tool: "carve_files", requires: ["evidence_mounted", "integrity_verified"], produces: [], category: "filesystem", description: "Signature-based file carving (foremost/scalpel)" },
  { tool: "analyze_unallocated", requires: ["filesystem_accessible"], produces: [], category: "filesystem", description: "Run bulk_extractor on unallocated space" },
  { tool: "extract_strings", requires: ["filesystem_accessible"], produces: [], category: "filesystem", description: "Extract strings from raw regions or files" },
  { tool: "parse_usnjrnl", requires: ["filesystem_accessible"], produces: [], category: "filesystem", description: "Parse $UsnJrnl change journal entries" },

  // ── Timeline ──
  { tool: "generate_timeline", requires: ["evidence_mounted", "integrity_verified"], produces: ["timeline_generated"], category: "timeline", description: "Generate super timeline via log2timeline (Plaso)" },
  { tool: "filter_timeline", requires: ["timeline_generated"], produces: [], category: "timeline", description: "Filter timeline by date/source/keyword via psort" },
  { tool: "detect_timeline_anomalies", requires: ["timeline_generated"], produces: [], category: "timeline", description: "Detect statistical anomalies (bursts, gaps)" },
  { tool: "get_timeline_context", requires: ["timeline_generated"], produces: [], category: "timeline", description: "Get N-minute context window around timestamp" },
  { tool: "compare_timelines", requires: ["timeline_generated"], produces: [], category: "timeline", description: "Diff two timeline ranges" },
  { tool: "get_timeline_statistics", requires: ["timeline_generated"], produces: [], category: "timeline", description: "Activity distribution summary" },

  // ── Registry ──
  { tool: "list_registry_hives", requires: ["filesystem_accessible"], produces: ["registry_accessible"], category: "registry", description: "Locate all registry hive files in image" },
  { tool: "parse_registry_key", requires: ["registry_accessible"], produces: [], category: "registry", description: "Parse specific registry key via regripper" },
  { tool: "get_user_activity", requires: ["registry_accessible"], produces: [], category: "registry", description: "NTUSER.DAT: typed paths, recent docs, UserAssist" },
  { tool: "get_system_config", requires: ["registry_accessible"], produces: [], category: "registry", description: "SYSTEM: hostname, timezone, network, shutdown time" },
  { tool: "get_persistence_keys", requires: ["registry_accessible"], produces: [], category: "registry", description: "Check ALL known persistence registry locations (50+)" },
  { tool: "get_installed_software", requires: ["registry_accessible"], produces: [], category: "registry", description: "SOFTWARE: uninstall entries, app paths, install dates" },
  { tool: "get_usb_history", requires: ["registry_accessible"], produces: [], category: "registry", description: "USBSTOR + mountpoints + setupapi correlation" },
  { tool: "get_network_config", requires: ["registry_accessible"], produces: [], category: "registry", description: "Network interfaces, DNS, firewall rules" },
  { tool: "parse_sam", requires: ["registry_accessible"], produces: [], category: "registry", description: "SAM: user accounts, last login, password policy" },

  // ── Event Logs ──
  { tool: "list_event_logs", requires: ["filesystem_accessible"], produces: ["eventlogs_accessible"], category: "event_logs", description: "Find all .evtx files in image" },
  { tool: "parse_event_log", requires: ["eventlogs_accessible"], produces: [], category: "event_logs", description: "Parse specific event log to structured events" },
  { tool: "search_events", requires: ["eventlogs_accessible"], produces: [], category: "event_logs", description: "Filter events by EID/time/user/computer" },
  { tool: "detect_log_gaps", requires: ["eventlogs_accessible"], produces: [], category: "event_logs", description: "Sequential Event ID gap analysis" },
  { tool: "correlate_logon_events", requires: ["eventlogs_accessible"], produces: [], category: "event_logs", description: "Session reconstruction from logon/logoff pairs" },
  { tool: "parse_powershell_logs", requires: ["eventlogs_accessible"], produces: [], category: "event_logs", description: "ScriptBlock Logging + PSReadline history" },
  { tool: "detect_account_manipulation", requires: ["eventlogs_accessible"], produces: [], category: "event_logs", description: "EID 4720/4722/4724/4732 account change correlation" },
  { tool: "get_security_summary", requires: ["eventlogs_accessible"], produces: [], category: "event_logs", description: "Aggregate security event statistics" },

  // ── Execution Artifacts ──
  { tool: "parse_prefetch", requires: ["filesystem_accessible"], produces: ["execution_artifacts_parsed"], category: "execution_artifacts", description: "Prefetch files: execution count, last run, DLLs loaded" },
  { tool: "parse_amcache", requires: ["filesystem_accessible"], produces: ["execution_artifacts_parsed"], category: "execution_artifacts", description: "Amcache: SHA1 hashes, paths, install timestamps" },
  { tool: "parse_shimcache", requires: ["registry_accessible"], produces: ["execution_artifacts_parsed"], category: "execution_artifacts", description: "AppCompatCache: execution evidence in registry" },
  { tool: "parse_srum", requires: ["filesystem_accessible"], produces: ["execution_artifacts_parsed"], category: "execution_artifacts", description: "SRUM database: network/app resource usage" },
  { tool: "parse_bam", requires: ["registry_accessible"], produces: ["execution_artifacts_parsed"], category: "execution_artifacts", description: "Background Activity Moderator execution times" },
  { tool: "parse_muicache", requires: ["registry_accessible"], produces: ["execution_artifacts_parsed"], category: "execution_artifacts", description: "MUICache: GUI program execution evidence" },
  { tool: "parse_userassist", requires: ["registry_accessible"], produces: ["execution_artifacts_parsed"], category: "execution_artifacts", description: "UserAssist: ROT-13 decoded run counts + focus time" },

  // ── Persistence & Malware ──
  { tool: "scan_yara", requires: ["filesystem_accessible"], produces: ["persistence_checked"], category: "persistence", description: "YARA rule scanning against files/regions" },
  { tool: "check_scheduled_tasks", requires: ["filesystem_accessible"], produces: ["persistence_checked"], category: "persistence", description: "Scheduled task XML file parsing" },
  { tool: "check_services", requires: ["registry_accessible"], produces: ["persistence_checked"], category: "persistence", description: "Registry service enumeration + anomaly detection" },
  { tool: "check_startup_locations", requires: ["registry_accessible", "filesystem_accessible"], produces: ["persistence_checked"], category: "persistence", description: "ALL 50+ persistence vectors enumerated" },
  { tool: "check_wmi_persistence", requires: ["filesystem_accessible"], produces: ["persistence_checked"], category: "persistence", description: "WMI MOF files + event subscription persistence" },
  { tool: "check_bits_jobs", requires: ["filesystem_accessible"], produces: ["persistence_checked"], category: "persistence", description: "BITS transfer jobs (C2/exfiltration)" },
  { tool: "check_com_hijacking", requires: ["registry_accessible"], produces: ["persistence_checked"], category: "persistence", description: "COM object registry hijack detection" },
  { tool: "check_dll_search_order", requires: ["filesystem_accessible", "registry_accessible"], produces: ["persistence_checked"], category: "persistence", description: "Known DLL search order exploits" },
  { tool: "hash_and_lookup", requires: ["filesystem_accessible"], produces: [], category: "persistence", description: "Hash files and compare to known-malware databases" },

  // ── Memory Forensics ──
  { tool: "identify_memory_profile", requires: ["evidence_mounted"], produces: ["memory_profiled"], category: "memory", description: "Auto-detect OS profile for memory image" },
  { tool: "list_processes", requires: ["memory_profiled"], produces: ["memory_accessible"], category: "memory", description: "Process listing via vol3 pslist/pstree" },
  { tool: "detect_process_injection", requires: ["memory_accessible"], produces: [], category: "memory", description: "Detect injected code via malfind" },
  { tool: "list_network_connections", requires: ["memory_accessible"], produces: [], category: "memory", description: "Network connections via netscan" },
  { tool: "dump_process", requires: ["memory_accessible"], produces: [], category: "memory", description: "Dump process memory to file" },
  { tool: "get_command_history", requires: ["memory_accessible"], produces: [], category: "memory", description: "Command line args + console history" },
  { tool: "scan_memory_yara", requires: ["memory_accessible"], produces: [], category: "memory", description: "YARA scanning on memory dump" },
  { tool: "detect_rootkit", requires: ["memory_accessible"], produces: [], category: "memory", description: "SSDT/IDT/IRP hook detection" },
  { tool: "list_handles", requires: ["memory_accessible"], produces: [], category: "memory", description: "Open file/registry handles per process" },
  { tool: "analyze_privileges", requires: ["memory_accessible"], produces: [], category: "memory", description: "Token and privilege escalation analysis" },
  { tool: "list_kernel_drivers", requires: ["memory_accessible"], produces: [], category: "memory", description: "Loaded drivers + unsigned detection" },

  // ── Network Forensics ──
  { tool: "load_network_capture", requires: ["evidence_mounted"], produces: ["network_capture_loaded"], category: "network", description: "Load PCAP/PCAPNG for analysis" },
  { tool: "parse_pcap_summary", requires: ["network_capture_loaded"], produces: [], category: "network", description: "Conversation statistics via tshark" },
  { tool: "extract_connections", requires: ["network_capture_loaded"], produces: [], category: "network", description: "Flow list with bytes and timing" },
  { tool: "search_pcap", requires: ["network_capture_loaded"], produces: [], category: "network", description: "Display filter search on capture" },
  { tool: "extract_files_from_pcap", requires: ["network_capture_loaded"], produces: [], category: "network", description: "Carve files from TCP streams" },
  { tool: "detect_beaconing", requires: ["network_capture_loaded"], produces: [], category: "network", description: "C2 periodic callback detection (jitter analysis)" },
  { tool: "extract_dns_queries", requires: ["network_capture_loaded"], produces: [], category: "network", description: "DNS request/response extraction" },
  { tool: "extract_http_traffic", requires: ["network_capture_loaded"], produces: [], category: "network", description: "HTTP requests + responses + bodies" },

  // ── Browser Forensics ──
  { tool: "parse_browser_history", requires: ["filesystem_accessible"], produces: ["browser_accessible"], category: "browser", description: "Chrome/Firefox/Edge URL history + timestamps" },
  { tool: "parse_browser_downloads", requires: ["browser_accessible"], produces: [], category: "browser", description: "Download records with source URLs" },
  { tool: "parse_browser_cache", requires: ["browser_accessible"], produces: [], category: "browser", description: "Cached web resources" },
  { tool: "parse_browser_cookies", requires: ["browser_accessible"], produces: [], category: "browser", description: "Session and persistent cookies" },
  { tool: "parse_browser_extensions", requires: ["browser_accessible"], produces: [], category: "browser", description: "Installed extensions + permissions" },
  { tool: "parse_browser_saved_passwords", requires: ["browser_accessible"], produces: [], category: "browser", description: "Saved credential extraction" },

  // ── User Activity ──
  { tool: "parse_lnk_files", requires: ["filesystem_accessible"], produces: ["user_activity_parsed"], category: "user_activity", description: "Windows shortcuts: target, timestamps, volume info" },
  { tool: "parse_jumplists", requires: ["filesystem_accessible"], produces: ["user_activity_parsed"], category: "user_activity", description: "Recent/frequent file access per application" },
  { tool: "parse_shellbags", requires: ["registry_accessible"], produces: ["user_activity_parsed"], category: "user_activity", description: "Folder navigation history" },
  { tool: "parse_recycle_bin", requires: ["filesystem_accessible"], produces: ["user_activity_parsed"], category: "user_activity", description: "$I/$R file recovery with original paths" },
  { tool: "parse_recent_docs", requires: ["registry_accessible"], produces: ["user_activity_parsed"], category: "user_activity", description: "Office recent documents" },
  { tool: "parse_mru_lists", requires: ["registry_accessible"], produces: ["user_activity_parsed"], category: "user_activity", description: "Most Recently Used across applications" },
  { tool: "parse_rdp_cache", requires: ["filesystem_accessible"], produces: ["user_activity_parsed"], category: "user_activity", description: "RDP bitmap cache images" },
  { tool: "parse_clipboard_history", requires: ["filesystem_accessible"], produces: ["user_activity_parsed"], category: "user_activity", description: "Clipboard artifact recovery" },

  // ── Anti-Forensics Detection ──
  { tool: "detect_timestomping", requires: ["filesystem_accessible"], produces: ["anti_forensics_checked"], category: "anti_forensics", description: "Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps" },
  { tool: "detect_log_clearing", requires: ["eventlogs_accessible"], produces: ["anti_forensics_checked"], category: "anti_forensics", description: "Gap analysis + Security EID 1102/1100 detection" },
  { tool: "detect_secure_deletion", requires: ["filesystem_accessible"], produces: ["anti_forensics_checked"], category: "anti_forensics", description: "MFT orphan entries + unallocated patterns" },
  { tool: "detect_hidden_data", requires: ["filesystem_accessible"], produces: ["anti_forensics_checked"], category: "anti_forensics", description: "ADS, slack space, hidden partitions" },
  { tool: "detect_wiping_tools", requires: ["filesystem_accessible"], produces: ["anti_forensics_checked"], category: "anti_forensics", description: "CCleaner/SDelete/timestomp.exe artifact signatures" },
  { tool: "detect_anti_analysis", requires: ["filesystem_accessible", "registry_accessible"], produces: ["anti_forensics_checked"], category: "anti_forensics", description: "VM/sandbox evasion artifact detection" },
  { tool: "get_anti_forensics_summary", requires: ["anti_forensics_checked"], produces: [], category: "anti_forensics", description: "Aggregated anti-forensics assessment" },

  // ── Correlation ──
  { tool: "correlate_timeline_events", requires: ["timeline_generated", "findings_registered"], produces: ["correlation_complete"], category: "correlation", description: "Cross-source event correlation" },
  { tool: "build_attack_narrative", requires: ["findings_registered"], produces: ["correlation_complete"], category: "correlation", description: "High-level attack timeline construction" },
  { tool: "detect_lateral_movement", requires: ["eventlogs_accessible", "findings_registered"], produces: ["correlation_complete"], category: "correlation", description: "Cross-machine movement detection" },
  { tool: "map_mitre_techniques", requires: ["findings_registered"], produces: [], category: "correlation", description: "Auto-map findings to ATT&CK framework" },
  { tool: "get_investigation_summary", requires: ["findings_registered"], produces: [], category: "correlation", description: "Executive summary of all findings" },
  { tool: "export_timeline_of_compromise", requires: ["findings_registered"], produces: [], category: "correlation", description: "Structured attack timeline for reporting" },
  { tool: "get_ioc_summary", requires: ["findings_registered"], produces: [], category: "correlation", description: "All IOCs extracted across investigation" },

  // ── Linux Analysis ──
  { tool: "parse_auth_log", requires: ["linux_accessible"], produces: [], category: "linux", description: "SSH logins, sudo, su, failed attempts" },
  { tool: "parse_syslog", requires: ["linux_accessible"], produces: [], category: "linux", description: "System events from syslog" },
  { tool: "parse_bash_history", requires: ["linux_accessible"], produces: [], category: "linux", description: "Command history with timestamps" },
  { tool: "parse_cron_jobs", requires: ["linux_accessible"], produces: [], category: "linux", description: "Crontab scheduled persistence" },
  { tool: "parse_systemd_journal", requires: ["linux_accessible"], produces: [], category: "linux", description: "Journalctl structured log events" },
  { tool: "parse_ssh_artifacts", requires: ["linux_accessible"], produces: [], category: "linux", description: "authorized_keys, known_hosts, key files" },
  { tool: "check_linux_persistence", requires: ["linux_accessible"], produces: [], category: "linux", description: "systemd, init.d, bashrc, crontab, LD_PRELOAD" },
  { tool: "parse_audit_log", requires: ["linux_accessible"], produces: [], category: "linux", description: "Auditd structured event parsing" },

  // ── Reporting / Meta-Cognitive ──
  { tool: "register_finding", requires: ["evidence_mounted"], produces: ["findings_registered"], category: "reporting", description: "Register finding with REQUIRED evidence links" },
  { tool: "register_hypothesis", requires: ["evidence_mounted"], produces: [], category: "reporting", description: "Propose investigation hypothesis" },
  { tool: "generate_report", requires: ["findings_registered"], produces: ["report_ready"], category: "reporting", description: "Final report filtered by confidence threshold" },
  { tool: "verify_chain", requires: [], produces: [], category: "reporting", description: "Validate evidence ledger hash chain integrity" },
  { tool: "get_investigation_state", requires: [], produces: [], category: "reporting", description: "Current capabilities, phase, and active workflows" },
  { tool: "get_methodology_coverage", requires: [], produces: [], category: "reporting", description: "Coverage percentage per artifact category" },
  { tool: "get_coverage_gaps", requires: [], produces: [], category: "reporting", description: "Unchecked artifacts prioritized by significance" },
  { tool: "get_unsupported_findings", requires: [], produces: [], category: "reporting", description: "Findings needing additional corroboration" },
  { tool: "get_contradictions", requires: [], produces: [], category: "reporting", description: "Conflicting findings requiring resolution" },
  { tool: "suggest_next_action", requires: [], produces: [], category: "reporting", description: "Methodology-driven recommendation for next step" },
  { tool: "get_hypothesis_status", requires: [], produces: [], category: "reporting", description: "Evidence for/against each hypothesis" },
  { tool: "reassess_finding", requires: ["findings_registered"], produces: [], category: "reporting", description: "Re-evaluate finding confidence with new evidence" },
  { tool: "get_confidence_summary", requires: [], produces: [], category: "reporting", description: "Confidence level breakdown across all findings" },
  { tool: "trace_provenance", requires: [], produces: [], category: "reporting", description: "Full evidence chain for any finding" },
  { tool: "get_questions_to_investigate", requires: [], produces: [], category: "reporting", description: "Server-generated investigation questions" },
  { tool: "get_investigation_health", requires: [], produces: [], category: "reporting", description: "Overall investigation quality score" },
  { tool: "corroborate_finding", requires: ["findings_registered"], produces: [], category: "reporting", description: "Suggest additional evidence sources for finding" },
  { tool: "challenge_finding", requires: ["findings_registered"], produces: [], category: "reporting", description: "Seek contradicting evidence for finding" },
  { tool: "export_audit_log", requires: [], produces: [], category: "reporting", description: "Export full hash-chained investigation record" },
  { tool: "reset_investigation", requires: [], produces: [], category: "reporting", description: "Clear all state and start a fresh investigation" },
  { tool: "get_job_status", requires: [], produces: [], category: "reporting", description: "Check status of a background job (long-running tools)" },
] as const;

// ─── Workflow Definitions (Progressive Disclosure) ────────────────────────────

export interface WorkflowDefinition {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly category: ArtifactCategory;
  readonly toolCount: number;
  readonly prerequisites: readonly Capability[];
  readonly autoActivateOn: readonly Capability[];
}

export const WORKFLOW_DEFINITIONS: readonly WorkflowDefinition[] = [
  { id: "acquisition", name: "Evidence Acquisition", description: "Mount, verify integrity, partition discovery", category: "acquisition", toolCount: 5, prerequisites: [], autoActivateOn: ["evidence_mounted"] },
  { id: "filesystem", name: "Filesystem Analysis", description: "Directory listing, file extraction, deleted recovery, string search, USN journal", category: "filesystem", toolCount: 9, prerequisites: ["integrity_verified"], autoActivateOn: ["integrity_verified"] },
  { id: "timeline", name: "Timeline Analysis", description: "Super timeline generation, filtering, anomaly detection, context windows", category: "timeline", toolCount: 6, prerequisites: ["integrity_verified"], autoActivateOn: ["integrity_verified"] },
  { id: "registry", name: "Windows Registry", description: "Hive parsing, persistence keys, user activity, USB history, SAM", category: "registry", toolCount: 9, prerequisites: ["filesystem_accessible"], autoActivateOn: ["filesystem_accessible"] },
  { id: "event_logs", name: "Windows Event Logs", description: "EVTX parsing, logon correlation, PowerShell, account manipulation", category: "event_logs", toolCount: 8, prerequisites: ["filesystem_accessible"], autoActivateOn: ["filesystem_accessible"] },
  { id: "execution_artifacts", name: "Execution Artifacts", description: "Prefetch, Amcache, ShimCache, SRUM, BAM, MUICache, UserAssist", category: "execution_artifacts", toolCount: 7, prerequisites: ["filesystem_accessible"], autoActivateOn: ["filesystem_accessible"] },
  { id: "persistence", name: "Persistence & Malware", description: "YARA scanning, scheduled tasks, services, WMI, BITS, COM hijack", category: "persistence", toolCount: 9, prerequisites: ["filesystem_accessible"], autoActivateOn: ["filesystem_accessible"] },
  { id: "memory", name: "Memory Forensics", description: "Process listing, injection detection, rootkits, network, drivers", category: "memory", toolCount: 11, prerequisites: ["evidence_mounted"], autoActivateOn: ["memory_profiled"] },
  { id: "network", name: "Network Forensics", description: "PCAP analysis, connections, beaconing, DNS, HTTP, lateral movement", category: "network", toolCount: 8, prerequisites: ["evidence_mounted"], autoActivateOn: ["network_capture_loaded"] },
  { id: "browser", name: "Browser Forensics", description: "History, downloads, cache, cookies, extensions, saved passwords", category: "browser", toolCount: 6, prerequisites: ["filesystem_accessible"], autoActivateOn: ["browser_accessible"] },
  { id: "user_activity", name: "User Activity", description: "LNK files, jumplists, shellbags, recycle bin, MRU, RDP cache", category: "user_activity", toolCount: 8, prerequisites: ["filesystem_accessible"], autoActivateOn: ["user_activity_parsed"] },
  { id: "anti_forensics", name: "Anti-Forensics Detection", description: "Timestomping, log clearing, secure deletion, hidden data, wiping tools", category: "anti_forensics", toolCount: 7, prerequisites: ["filesystem_accessible"], autoActivateOn: [] },
  { id: "correlation", name: "Correlation & Narrative", description: "Cross-source correlation, attack narrative, lateral movement, MITRE mapping", category: "correlation", toolCount: 7, prerequisites: ["findings_registered"], autoActivateOn: ["findings_registered"] },
  { id: "linux", name: "Linux Analysis", description: "Auth logs, syslog, bash history, cron, systemd, SSH artifacts, audit", category: "linux", toolCount: 8, prerequisites: ["linux_accessible"], autoActivateOn: ["linux_accessible"] },
  { id: "reporting", name: "Reporting & Validation", description: "Coverage analysis, confidence summary, provenance tracing, audit export", category: "reporting", toolCount: 21, prerequisites: [], autoActivateOn: [] },
];

// ─── Kernel Tools (Always Visible) ───────────────────────────────────────────

export const KERNEL_TOOLS: readonly string[] = [
  "mount_evidence",
  "verify_integrity",
  "suggest_next_action",
  "get_investigation_state",
  "get_coverage_gaps",
  "get_methodology_coverage",
  "register_finding",
  "register_hypothesis",
  "generate_report",
  "verify_chain",
  "get_investigation_health",
  "get_confidence_summary",
  "reset_investigation",
];

// ─── Capability Graph State ──────────────────────────────────────────────────

export class CapabilityGraph {
  private readonly specs: ReadonlyMap<string, ToolCapabilitySpec>;
  private readonly held: Set<Capability>;

  constructor() {
    this.specs = new Map(TOOL_SPECS.map((s) => [s.tool, s]));
    this.held = new Set();
  }

  /** Check if a tool can execute given current capabilities */
  canExecute(tool: string): Result<true, CapabilityError> {
    const spec = this.specs.get(tool);
    if (!spec) {
      return err({
        kind: "CAPABILITY_ERROR",
        tool,
        missing: [],
        held: [...this.held],
        message: `Unknown tool "${tool}"`,
        guidance: `Tool "${tool}" is not registered in the capability graph.`,
      });
    }

    const missing = spec.requires.filter((cap) => !this.held.has(cap));
    if (missing.length > 0) {
      return err(capabilityError(tool, missing, [...this.held]));
    }

    return ok(true);
  }

  /** Produce capabilities after successful tool execution */
  produce(tool: string): readonly Capability[] {
    const spec = this.specs.get(tool);
    const produced: Capability[] = [];
    if (spec) {
      for (const cap of spec.produces) {
        if (!this.held.has(cap)) {
          this.held.add(cap);
          produced.push(cap);
        }
      }
    }
    return produced;
  }

  /** Grant a capability directly (for evidence-type-specific capabilities like linux_accessible, memory_profiled) */
  grant(capability: Capability): boolean {
    if (this.held.has(capability)) return false;
    this.held.add(capability);
    return true;
  }

  /** Get current held capabilities */
  getHeld(): readonly Capability[] {
    return [...this.held];
  }

  /** Check if a specific capability is held */
  has(cap: Capability): boolean {
    return this.held.has(cap);
  }

  /** Get all registered tool names */
  getAllTools(): readonly string[] {
    return [...this.specs.keys()];
  }

  /** Get current investigation phase based on held capabilities */
  getPhase(): string {
    if (this.held.has("report_ready")) return "REPORTING";
    if (this.held.has("correlation_complete")) return "CORRELATING";
    if (this.held.has("findings_registered")) return "ANALYZING";
    if (this.held.has("integrity_verified")) return "TRIAGING";
    if (this.held.has("evidence_mounted")) return "MOUNTED";
    return "UNINITIALIZED";
  }

  /** Get tools that are currently executable */
  getExecutableTools(): readonly string[] {
    return [...this.specs.entries()]
      .filter(([_, spec]) => spec.requires.every((cap) => this.held.has(cap)))
      .map(([name]) => name);
  }

  /** Get tools that are NOT yet executable (and what they're missing) */
  getBlockedTools(): ReadonlyArray<{ tool: string; missing: readonly Capability[] }> {
    return [...this.specs.entries()]
      .filter(([_, spec]) => !spec.requires.every((cap) => this.held.has(cap)))
      .map(([name, spec]) => ({
        tool: name,
        missing: spec.requires.filter((cap) => !this.held.has(cap)),
      }));
  }

  /** Get the category for a tool */
  getCategory(tool: string): ArtifactCategory | undefined {
    return this.specs.get(tool)?.category;
  }

  /** Get tool spec */
  getSpec(tool: string): ToolCapabilitySpec | undefined {
    return this.specs.get(tool);
  }

  /** Get tools in a specific category */
  getToolsByCategory(category: ArtifactCategory): readonly ToolCapabilitySpec[] {
    return TOOL_SPECS.filter((s) => s.category === category);
  }

  /** Reset state (for testing) */
  reset(): void {
    this.held.clear();
  }
}
