/**
 * Category Dispatcher — routes category(operation, params) → internal tool handler.
 * Exposes 14 category tools + 18 kernel tools = 32 total (no bloat, no notifications needed).
 */
import { TOOL_SPECS } from "./domain/capability-graph.js";
import type { ArtifactCategory } from "./domain/types.js";

// Categories that become dispatcher tools (non-reporting categories)
export const FORENSIC_CATEGORIES: readonly ArtifactCategory[] = [
  "acquisition", "filesystem", "timeline", "registry", "event_logs",
  "execution_artifacts", "persistence", "memory", "network",
  "browser", "user_activity", "anti_forensics", "correlation", "linux",
] as const;

// Kernel tools (direct, always visible — the meta/reporting/self-verification tools)
export const KERNEL_TOOL_NAMES: readonly string[] = [
  "get_investigation_protocol",
  "mount_evidence",
  "verify_integrity",
  "suggest_next_action",
  "get_investigation_state",
  "get_coverage_gaps",
  "get_investigation_health",
  "get_confidence_summary",
  "get_methodology_coverage",
  "register_finding",
  "register_hypothesis",
  "generate_report",
  "verify_chain",
  "reset_investigation",
  "get_job_status",
  "list_workflows",
  "activate_workflow",
  "deactivate_workflow",
  // Self-verification / adversarial phase tools (C2 fix)
  "get_contradictions",
  "challenge_finding",
  "corroborate_finding",
  "get_unsupported_findings",
  "reassess_finding",
  "trace_provenance",
  "get_hypothesis_status",
  "get_questions_to_investigate",
  "export_audit_log",
] as const;

// Build the operations enum for each category
export function getCategoryOperations(category: ArtifactCategory): string[] {
  return TOOL_SPECS
    .filter(s => s.category === category && !KERNEL_TOOL_NAMES.includes(s.tool))
    .map(s => s.tool);
}

// Build the description for a category tool (includes operation list)
export function getCategoryDescription(category: ArtifactCategory): string {
  const ops = TOOL_SPECS.filter(s => s.category === category && !KERNEL_TOOL_NAMES.includes(s.tool));
  const opList = ops.map(o => `${o.tool}: ${o.description}`).join("\n  ");
  const categoryNames: Record<string, string> = {
    acquisition: "Evidence Acquisition & Verification",
    filesystem: "Filesystem Analysis",
    timeline: "Timeline Analysis (Plaso)",
    registry: "Windows Registry Analysis",
    event_logs: "Windows Event Log Analysis",
    execution_artifacts: "Execution Artifact Analysis",
    persistence: "Persistence & Malware Detection",
    memory: "Memory Forensics (Volatility3)",
    network: "Network Forensics (tshark/PCAP)",
    browser: "Browser Forensics",
    user_activity: "User Activity Analysis",
    anti_forensics: "Anti-Forensics Detection",
    correlation: "Cross-Source Correlation",
    linux: "Linux Analysis",
  };
  return `${categoryNames[category] ?? category}\n\nAvailable operations:\n  ${opList}`;
}

// Build the input schema for a category dispatcher
export function getCategoryInputSchema(category: ArtifactCategory): Record<string, unknown> {
  const ops = getCategoryOperations(category);
  // Collect all unique params across ops in this category
  const allParams = new Set<string>();
  for (const op of ops) {
    const spec = TOOL_SPECS.find(s => s.tool === op);
    if (spec) {
      // Get params from the internal tool schema
      const params = getInternalToolParams(op);
      for (const p of Object.keys(params)) allParams.add(p);
    }
  }

  const properties: Record<string, unknown> = {
    operation: {
      type: "string",
      enum: ops,
      description: "Which operation to perform. See tool description for details.",
    },
  };

  // Add common forensic params (flat — simpler for LLMs)
  const commonParams: Record<string, { type: string; description: string }> = {
    path: { type: "string", description: "Filesystem path within the evidence image" },
    inode: { type: "string", description: "MFT inode number for direct access" },
    pattern: { type: "string", description: "Regex pattern for searching" },
    start_inode: { type: "string", description: "Starting inode for scoped search" },
    show_deleted: { type: "string", description: "Include deleted entries (true/false)" },
    evidence_path: { type: "string", description: "Path to file within evidence" },
    algorithm: { type: "string", description: "Hash algorithm (sha256/md5)" },
    yara_rules: { type: "string", description: "Path to YARA rules file" },
    filter: { type: "string", description: "Display filter (for network tools)" },
    event_id: { type: "string", description: "Event ID to filter by" },
    time_start: { type: "string", description: "Start of time range (ISO 8601)" },
    time_end: { type: "string", description: "End of time range (ISO 8601)" },
    pid: { type: "string", description: "Process ID (for memory tools)" },
    parsers: { type: "string", description: "Comma-separated parser list (for timeline)" },
  };

  for (const [key, val] of Object.entries(commonParams)) {
    if (allParams.has(key)) {
      properties[key] = val;
    }
  }

  // Always include path and pattern for most categories
  if (!properties["path"] && ["filesystem", "registry", "event_logs", "execution_artifacts", "persistence", "browser", "user_activity", "linux", "anti_forensics"].includes(category)) {
    properties["path"] = commonParams["path"];
  }

  return {
    type: "object",
    properties,
    required: ["operation"],
  };
}

// Get the internal param names for a tool (used to build category schema)
function getInternalToolParams(tool: string): Record<string, boolean> {
  // Map of tool → params it accepts
  const toolParams: Record<string, string[]> = {
    list_directory: ["path", "inode", "show_deleted"],
    extract_file: ["inode", "path"],
    search_filename: ["pattern", "path", "start_inode"],
    get_file_metadata: ["inode", "path"],
    recover_deleted: ["path"],
    carve_files: ["path"],
    analyze_unallocated: ["path"],
    extract_strings: ["path", "inode"],
    parse_usnjrnl: ["path"],
    generate_timeline: ["parsers"],
    filter_timeline: ["filter", "time_start", "time_end"],
    detect_timeline_anomalies: [],
    get_timeline_context: ["time_start"],
    compare_timelines: ["time_start", "time_end"],
    get_timeline_statistics: [],
    list_registry_hives: [],
    parse_registry_key: ["path"],
    get_user_activity: ["path"],
    get_system_config: [],
    get_persistence_keys: [],
    get_installed_software: [],
    get_usb_history: [],
    get_network_config: [],
    parse_sam: [],
    list_event_logs: [],
    parse_event_log: ["path"],
    search_events: ["event_id", "time_start", "time_end", "filter"],
    detect_log_gaps: ["path"],
    correlate_logon_events: [],
    parse_powershell_logs: [],
    detect_account_manipulation: [],
    get_security_summary: [],
    parse_prefetch: ["path"],
    parse_amcache: ["path"],
    parse_shimcache: [],
    parse_srum: ["path"],
    parse_bam: [],
    parse_muicache: [],
    parse_userassist: [],
    scan_yara: ["yara_rules", "path"],
    check_scheduled_tasks: [],
    check_services: [],
    check_startup_locations: [],
    check_wmi_persistence: [],
    check_bits_jobs: [],
    check_com_hijacking: [],
    check_dll_search_order: [],
    hash_and_lookup: ["path"],
    identify_memory_profile: [],
    list_processes: [],
    detect_process_injection: ["pid"],
    list_network_connections: [],
    dump_process: ["pid"],
    get_command_history: [],
    scan_memory_yara: ["yara_rules"],
    detect_rootkit: [],
    list_handles: ["pid"],
    analyze_privileges: [],
    list_kernel_drivers: [],
    load_network_capture: ["path"],
    parse_pcap_summary: [],
    extract_connections: [],
    search_pcap: ["filter"],
    extract_files_from_pcap: [],
    detect_beaconing: [],
    extract_dns_queries: [],
    extract_http_traffic: [],
    parse_browser_history: ["path"],
    parse_browser_downloads: [],
    parse_browser_cache: [],
    parse_browser_cookies: [],
    parse_browser_extensions: [],
    parse_browser_saved_passwords: [],
    parse_lnk_files: ["path"],
    parse_jumplists: ["path"],
    parse_shellbags: [],
    parse_recycle_bin: ["path"],
    parse_recent_docs: [],
    parse_mru_lists: [],
    parse_rdp_cache: [],
    parse_clipboard_history: [],
    detect_timestomping: ["path"],
    detect_log_clearing: ["path"],
    detect_secure_deletion: [],
    detect_hidden_data: [],
    detect_wiping_tools: [],
    detect_anti_analysis: [],
    get_anti_forensics_summary: [],
    correlate_timeline_events: [],
    build_attack_narrative: [],
    detect_lateral_movement: [],
    map_mitre_techniques: [],
    get_investigation_summary: [],
    export_timeline_of_compromise: [],
    get_ioc_summary: [],
    parse_auth_log: ["path"],
    parse_syslog: ["path"],
    parse_bash_history: ["path"],
    parse_cron_jobs: [],
    parse_systemd_journal: [],
    parse_ssh_artifacts: [],
    check_linux_persistence: [],
    parse_audit_log: ["path"],
    get_image_metadata: [],
    list_partitions: [],
    get_filesystem_info: [],
  };
  const params = toolParams[tool] ?? [];
  const result: Record<string, boolean> = {};
  for (const p of params) result[p] = true;
  return result;
}

/**
 * Resolve a dispatcher call to an internal tool name.
 * Returns the internal tool name that the server's existing handlers understand.
 */
export function resolveDispatch(category: string, operation: string): string | null {
  const ops = getCategoryOperations(category as ArtifactCategory);
  if (ops.includes(operation)) return operation;
  return null;
}
