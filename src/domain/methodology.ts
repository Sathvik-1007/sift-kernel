import type { ArtifactCategory, SuggestedAction, ToolCapabilitySpec, Capability } from "./types.js";
import { TOOL_SPECS } from "./capability-graph.js";
import { INVESTIGATION_ONTOLOGY, type InvestigationNode } from "../reasoning/ontology.js";

// ─── Reactive Forensic Investigation State Machine ────────────────────────────
// Models how a senior DFIR analyst investigates: not a fixed sequence, but a
// SIGNAL-DRIVEN graph where findings determine the next investigative path.
//
// Based on: NIST SP 800-86, SANS FOR508, and the "follow the evidence" principle.
//
// Key difference from a linear state machine: after initial triage, the FSM
// BRANCHES based on what was found. Malware indicators lead to persistence +
// execution analysis. Insider indicators lead to user activity + data staging.
// Both can be active simultaneously.

// ─── Investigation Signals ────────────────────────────────────────────────────
// Signals are emitted by tool outputs and drive state transitions.

export type InvestigationSignal =
  | "MALWARE_INDICATORS"       // Suspicious EXEs, known-bad paths, AV quarantine, YARA hits
  | "INSIDER_INDICATORS"       // OSINT tools, sensitive docs in personal folders, data staging
  | "LATERAL_MOVEMENT"         // Remote logons (type 3/10), net use, PsExec, RDP
  | "PERSISTENCE_FOUND"        // Registry run keys, scheduled tasks, services, startup items
  | "ANTI_FORENSICS_DETECTED"  // Timestomping, log clearing, SDelete, wiping tools
  | "DATA_STAGING"             // Archives, compression tools in unusual locations
  | "CREDENTIAL_ACCESS"        // Mimikatz, lsass dump, SAM access, credential files
  | "EXECUTION_EVIDENCE"       // Prefetch confirms execution, amcache confirms install
  | "NETWORK_ANOMALY"          // C2 beaconing, unusual connections, DNS tunneling
  | "CLEAN_PHASE";             // No anomalies in current analysis — move on

// ─── Investigation Paths ──────────────────────────────────────────────────────
// After triage, the FSM activates one or more PATHS based on observed signals.
// Each path has its own tool sequence. Paths execute in priority order.

export interface InvestigationPath {
  readonly id: string;
  readonly name: string;
  readonly triggeredBy: readonly InvestigationSignal[];
  readonly description: string;
  readonly priority: number; // Lower = higher priority
  readonly tools: readonly { tool: string; reason: string; critical: boolean }[];
  readonly categories: readonly ArtifactCategory[];
}

const INVESTIGATION_PATHS: readonly InvestigationPath[] = [
  {
    id: "malware_analysis",
    name: "Malware & Persistence Analysis",
    triggeredBy: ["MALWARE_INDICATORS", "PERSISTENCE_FOUND"],
    description: "Suspicious executables or persistence mechanisms detected. Investigate what was installed, how it persists, and what it does.",
    priority: 1,
    categories: ["persistence", "execution_artifacts"],
    tools: [
      { tool: "get_persistence_keys", reason: "Check all registry persistence locations (Run, RunOnce, etc.)", critical: true },
      { tool: "check_scheduled_tasks", reason: "Scheduled tasks are a top APT persistence vector", critical: true },
      { tool: "check_services", reason: "Malicious services for persistence", critical: true },
      { tool: "check_startup_locations", reason: "All 50+ startup vectors", critical: true },
      { tool: "scan_yara", reason: "Signature-based malware detection", critical: true },
      { tool: "hash_and_lookup", reason: "Hash suspicious files against threat intel", critical: false },
      { tool: "parse_prefetch", reason: "Confirm execution + identify loaded DLLs", critical: false },
      { tool: "parse_amcache", reason: "SHA1 hash + install timestamp", critical: false },
      { tool: "check_wmi_persistence", reason: "WMI event subscriptions (stealthy persistence)", critical: false },
    ],
  },
  {
    id: "lateral_movement",
    name: "Lateral Movement & Credential Analysis",
    triggeredBy: ["LATERAL_MOVEMENT", "CREDENTIAL_ACCESS"],
    description: "Remote access or credential theft indicators. Investigate authentication events, remote sessions, and network connections.",
    priority: 2,
    categories: ["event_logs", "network"],
    tools: [
      { tool: "correlate_logon_events", reason: "Reconstruct logon sessions (4624/4634 pairs)", critical: true },
      { tool: "parse_event_log", reason: "Security event log for auth events", critical: true },
      { tool: "detect_account_manipulation", reason: "Account creation/modification (4720/4722/4724)", critical: true },
      { tool: "parse_powershell_logs", reason: "PowerShell remoting + encoded commands", critical: false },
      { tool: "search_events", reason: "Filter for specific lateral movement EIDs", critical: false },
      { tool: "detect_beaconing", reason: "C2 callback patterns in network data", critical: false },
      { tool: "extract_connections", reason: "Network flow analysis", critical: false },
    ],
  },
  {
    id: "insider_threat",
    name: "Insider Threat & Data Collection",
    triggeredBy: ["INSIDER_INDICATORS", "DATA_STAGING"],
    description: "User activity suggests data collection, staging, or exfiltration preparation. Investigate user files, browser history, USB usage.",
    priority: 3,
    categories: ["user_activity", "browser"],
    tools: [
      { tool: "parse_browser_history", reason: "What sites/tools were accessed", critical: true },
      { tool: "parse_browser_downloads", reason: "What was downloaded (OSINT tools, archives)", critical: true },
      { tool: "parse_lnk_files", reason: "Recent file access — what was opened/moved", critical: true },
      { tool: "get_usb_history", reason: "USB devices — potential exfil medium", critical: true },
      { tool: "parse_jumplists", reason: "Per-application recent access", critical: false },
      { tool: "parse_shellbags", reason: "Folder navigation history — where user browsed", critical: false },
      { tool: "parse_recycle_bin", reason: "Deleted evidence of staging/cleanup", critical: false },
      { tool: "parse_mru_lists", reason: "Most recently used files across apps", critical: false },
    ],
  },
  {
    id: "anti_forensics_investigation",
    name: "Anti-Forensics & Evidence Destruction",
    triggeredBy: ["ANTI_FORENSICS_DETECTED"],
    description: "Evidence of cleanup detected. Earlier phases may have missed artifacts. Deep-dive into what was hidden or destroyed.",
    priority: 4,
    categories: ["anti_forensics"],
    tools: [
      { tool: "detect_timestomping", reason: "Compare $SI vs $FN timestamps — detect backdating", critical: true },
      { tool: "detect_log_clearing", reason: "Event log gap analysis + Security EID 1102", critical: true },
      { tool: "detect_secure_deletion", reason: "MFT orphans + unallocated patterns", critical: true },
      { tool: "detect_hidden_data", reason: "Alternate data streams, slack space, hidden partitions", critical: false },
      { tool: "detect_wiping_tools", reason: "SDelete, CCleaner, Eraser artifacts", critical: false },
      { tool: "detect_anti_analysis", reason: "VM/sandbox evasion indicators", critical: false },
    ],
  },
  {
    id: "execution_deep_dive",
    name: "Execution Artifact Analysis",
    triggeredBy: ["EXECUTION_EVIDENCE"],
    description: "Confirmed execution of suspicious programs. Deep-dive into what ran, when, how often, and what resources it consumed.",
    priority: 5,
    categories: ["execution_artifacts"],
    tools: [
      { tool: "parse_prefetch", reason: "Execution count + last run + DLLs loaded", critical: true },
      { tool: "parse_amcache", reason: "SHA1 + path + install timestamp", critical: true },
      { tool: "parse_shimcache", reason: "Execution order evidence", critical: false },
      { tool: "parse_srum", reason: "Network/app resource usage per process", critical: false },
      { tool: "parse_bam", reason: "Background Activity Moderator timestamps", critical: false },
      { tool: "parse_userassist", reason: "GUI program execution counts", critical: false },
    ],
  },
  {
    id: "network_investigation",
    name: "Network Forensics",
    triggeredBy: ["NETWORK_ANOMALY"],
    description: "Network anomalies detected. Analyze traffic patterns, DNS queries, and potential C2 channels.",
    priority: 6,
    categories: ["network"],
    tools: [
      { tool: "parse_pcap_summary", reason: "Traffic overview and conversation stats", critical: true },
      { tool: "detect_beaconing", reason: "Periodic C2 callback detection", critical: true },
      { tool: "extract_dns_queries", reason: "DNS requests — potential tunneling/C2", critical: false },
      { tool: "extract_http_traffic", reason: "HTTP requests + responses", critical: false },
      { tool: "extract_connections", reason: "Full flow list with bytes/timing", critical: false },
    ],
  },
];

// ─── Baseline Investigation Matrix ────────────────────────────────────────────
// The non-negotiable checklist a senior analyst covers on ANY Windows disk image,
// regardless of what triage surfaces first. Signals (above) re-order and DEEPEN
// this baseline — they never let the agent SKIP a category. This is what makes
// coverage deterministic: every investigation, driven by any LLM, attempts the
// full baseline before it is allowed to conclude.
//
// Ordered by SANS FOR508 Day-1 priority: execution → persistence → accounts →
// system/registry context → anti-forensics → user activity → malware scan.

export interface BaselineItem {
  readonly tool: string;
  readonly category: ArtifactCategory;
  readonly reason: string;
}

export const BASELINE_INVESTIGATION: readonly BaselineItem[] = [
  // Program execution — what ran on the system
  { tool: "parse_prefetch", category: "execution_artifacts", reason: "Execution evidence: what ran, when, how often, DLLs loaded" },
  { tool: "parse_amcache", category: "execution_artifacts", reason: "Installed/executed binaries with SHA1 + first-seen timestamps" },
  { tool: "parse_shimcache", category: "execution_artifacts", reason: "AppCompatCache — execution evidence even for deleted binaries" },
  // Persistence — how an intruder survives reboot
  { tool: "get_persistence_keys", category: "persistence", reason: "Registry autorun keys (Run/RunOnce/Winlogon) — top persistence vector" },
  { tool: "check_scheduled_tasks", category: "persistence", reason: "Scheduled tasks — the persistence the deleted TaskScheduler log would hide" },
  { tool: "check_services", category: "persistence", reason: "Malicious / unsigned services configured to auto-start" },
  { tool: "check_startup_locations", category: "persistence", reason: "All 50+ startup vectors (startup folders, registry, GPO)" },
  { tool: "scan_yara", category: "persistence", reason: "Signature-based malware detection across the image" },
  // Accounts & authentication — who logged in, what was created
  { tool: "correlate_logon_events", category: "event_logs", reason: "Reconstruct logon sessions (4624/4634) — detect lateral movement / missing logs" },
  { tool: "detect_account_manipulation", category: "event_logs", reason: "Account creation/modification (4720/4722/4724) — rogue accounts" },
  // System & registry context
  { tool: "get_system_config", category: "registry", reason: "Hostname, timezone, network config, last-shutdown — anchors the timeline" },
  { tool: "get_user_activity", category: "registry", reason: "NTUSER: typed paths, recent docs, UserAssist — what the user did" },
  { tool: "get_usb_history", category: "registry", reason: "USB device history — primary exfiltration medium" },
  // Anti-forensics — ALWAYS check for cleanup, even when nothing else looks wrong
  { tool: "detect_log_clearing", category: "anti_forensics", reason: "Event-log gaps + Security EID 1102 — detect evidence destruction" },
  { tool: "detect_timestomping", category: "anti_forensics", reason: "$SI vs $FN timestamp mismatch — detect backdated malware" },
  { tool: "detect_secure_deletion", category: "anti_forensics", reason: "MFT orphans + wiped clusters — detect securely-deleted evidence" },
  // User activity & data handling
  { tool: "parse_lnk_files", category: "user_activity", reason: "Recent file access — what was opened, from where (incl. removable media)" },
  { tool: "parse_recycle_bin", category: "user_activity", reason: "Deleted files with original paths — staging / cleanup evidence" },
];

// Linux-specific baseline (used when evidence_type = disk-linux)
export const BASELINE_LINUX: readonly BaselineItem[] = [
  { tool: "parse_auth_log", category: "linux", reason: "SSH logins, sudo, su, failed attempts — authentication timeline" },
  { tool: "parse_bash_history", category: "linux", reason: "Command history — what the attacker/user ran" },
  { tool: "parse_cron_jobs", category: "linux", reason: "Crontab persistence — scheduled backdoors" },
  { tool: "check_linux_persistence", category: "linux", reason: "systemd, init.d, bashrc, LD_PRELOAD, cron — all persistence vectors" },
  { tool: "parse_ssh_artifacts", category: "linux", reason: "authorized_keys, known_hosts — lateral movement evidence" },
  { tool: "parse_syslog", category: "linux", reason: "System events — service starts, kernel messages, network changes" },
  { tool: "scan_yara", category: "persistence", reason: "Signature-based malware detection" },
  { tool: "detect_timestomping", category: "anti_forensics", reason: "Timestamp manipulation detection" },
];

// Memory-specific baseline (used when evidence_type = memory)
export const BASELINE_MEMORY: readonly BaselineItem[] = [
  { tool: "list_processes", category: "memory", reason: "Process listing — identify suspicious/hidden processes" },
  { tool: "detect_process_injection", category: "memory", reason: "Malfind — detect injected code in process memory" },
  { tool: "list_network_connections", category: "memory", reason: "Network connections at time of capture — active C2" },
  { tool: "get_command_history", category: "memory", reason: "Command-line arguments reveal attacker actions" },
  { tool: "detect_rootkit", category: "memory", reason: "SSDT/IDT hooks — kernel-level persistence" },
  { tool: "list_kernel_drivers", category: "memory", reason: "Loaded drivers — unsigned/suspicious kernel modules" },
  { tool: "scan_memory_yara", category: "memory", reason: "In-memory YARA scanning — detect packed/encrypted malware" },
];

// Network-specific baseline (used when evidence_type = pcap)
export const BASELINE_NETWORK: readonly BaselineItem[] = [
  { tool: "parse_pcap_summary", category: "network", reason: "Traffic overview — protocols, endpoints, volumes" },
  { tool: "extract_connections", category: "network", reason: "Connection flows — identify suspicious endpoints" },
  { tool: "detect_beaconing", category: "network", reason: "C2 callback detection via interval/jitter analysis" },
  { tool: "extract_dns_queries", category: "network", reason: "DNS queries — domain reputation, tunneling detection" },
  { tool: "extract_http_traffic", category: "network", reason: "HTTP requests — data exfiltration, malware downloads" },
  { tool: "search_pcap", category: "network", reason: "Deep packet search for IOCs" },
];

// ─── FSM States ───────────────────────────────────────────────────────────────

export type FSMState =
  | "COLLECTION"     // Mount + verify evidence
  | "TRIAGE"         // Initial filesystem scan — detect signals
  | "CLASSIFY"       // Decide investigation paths based on signals
  | "INVESTIGATE"    // Execute active investigation paths
  | "TIMELINE"       // Correlate findings temporally
  | "CORRELATE"      // Build attack narrative + MITRE mapping
  | "REPORT";        // Generate final report

// ─── Signal Detection Patterns ────────────────────────────────────────────────
// These patterns are checked against tool output to auto-detect signals.

export interface SignalPattern {
  readonly signal: InvestigationSignal;
  readonly patterns: readonly string[];
  readonly description: string;
}

export const SIGNAL_PATTERNS: readonly SignalPattern[] = [
  {
    signal: "MALWARE_INDICATORS",
    patterns: [
      "Quarantine", ".exe in ProgramData", ".exe in Temp", ".exe in AppData",
      "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin",
      "svchost", "lsass", "csrss", "dllhost", "taskhost",
    ],
    description: "Executables in suspicious locations, LOLBins, or AV quarantine presence",
  },
  {
    signal: "INSIDER_INDICATORS",
    patterns: [
      "OSINT", "Confidential", "CONFIDENTIAL", "SECRET", "RESTRICTED",
      "exfil", "staging", "7z", "rar", "archive",
      "personal", "private", "encrypted",
    ],
    description: "OSINT tools, sensitive documents in personal folders, data staging patterns",
  },
  {
    signal: "LATERAL_MOVEMENT",
    patterns: [
      "PsExec", "psexec", "net use", "net1.exe", "wmic",
      "Enter-PSSession", "Invoke-Command", "WinRM",
      "Type 3", "Type 10", "LogonType.*3", "LogonType.*10",
    ],
    description: "Remote access tools, network logon types, remote execution frameworks",
  },
  {
    signal: "PERSISTENCE_FOUND",
    patterns: [
      "Run\\\\", "RunOnce", "Startup", "schtasks",
      "CurrentVersion\\\\Run", "services", "WMI", "BITS",
    ],
    description: "Registry autorun keys, scheduled tasks, service installations",
  },
  {
    signal: "ANTI_FORENSICS_DETECTED",
    patterns: [
      "SDelete", "sdelete", "CCleaner", "Eraser", "BleachBit",
      "timestomp", "ClearEventLog", "wevtutil cl",
      "Event ID: 1102", "Event ID: 1100",
    ],
    description: "Evidence destruction tools, log clearing events, timestomping indicators",
  },
  {
    signal: "DATA_STAGING",
    patterns: [
      "7za.exe", "7z.exe", "rar.exe", "WinRAR",
      "staging", "exfil", "upload", "transfer",
      "rclone", "megasync", "dropbox",
    ],
    description: "Compression utilities in unusual locations, staging directories, cloud sync tools",
  },
  {
    signal: "CREDENTIAL_ACCESS",
    patterns: [
      "mimikatz", "lsass", "procdump", "sekurlsa",
      "SAM", "NTDS", "credential", "password",
      "lazagne", "hashcat", "dump",
    ],
    description: "Credential theft tools, memory dumping of authentication processes",
  },
  {
    signal: "NETWORK_ANOMALY",
    patterns: [
      "beacon", "callback", "C2", "command and control",
      "port 4444", "port 8080", "reverse shell",
      "dns tunnel", "exfiltration",
    ],
    description: "C2 communication patterns, unusual network connections, tunneling",
  },
  // Linux-specific signals
  {
    signal: "PERSISTENCE_FOUND",
    patterns: [
      "cron", "crontab", "@reboot", "systemd", "init.d",
      ".bashrc", ".profile", "LD_PRELOAD", "authorized_keys",
    ],
    description: "Linux persistence mechanisms: cron, systemd, shell profiles, SSH keys",
  },
  {
    signal: "CREDENTIAL_ACCESS",
    patterns: [
      "/etc/shadow", "/etc/passwd", ".ssh/id_rsa", "id_ed25519",
      "known_hosts", "history", "bash_history",
    ],
    description: "Linux credential/key access indicators",
  },
];

// ─── Forensic significance per tool ──────────────────────────────────────────

const FORENSIC_SIGNIFICANCE: ReadonlyMap<string, "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"> = new Map([
  ["mount_evidence", "CRITICAL"],
  ["verify_integrity", "CRITICAL"],
  ["list_directory", "CRITICAL"],
  ["search_filename", "CRITICAL"],
  ["parse_prefetch", "CRITICAL"],
  ["get_persistence_keys", "CRITICAL"],
  ["check_scheduled_tasks", "CRITICAL"],
  ["check_startup_locations", "CRITICAL"],
  ["scan_yara", "CRITICAL"],
  ["detect_timestomping", "CRITICAL"],
  ["detect_log_clearing", "CRITICAL"],
  ["generate_timeline", "CRITICAL"],
  ["correlate_logon_events", "HIGH"],
  ["parse_event_log", "HIGH"],
  ["list_processes", "HIGH"],
  ["detect_process_injection", "HIGH"],
  ["parse_amcache", "HIGH"],
  ["parse_shimcache", "HIGH"],
  ["get_user_activity", "HIGH"],
  ["list_network_connections", "HIGH"],
  ["detect_beaconing", "HIGH"],
  ["check_services", "HIGH"],
  ["detect_lateral_movement", "HIGH"],
  ["build_attack_narrative", "HIGH"],
  ["map_mitre_techniques", "HIGH"],
  ["parse_srum", "MEDIUM"],
  ["parse_bam", "MEDIUM"],
  ["parse_userassist", "MEDIUM"],
  ["detect_secure_deletion", "MEDIUM"],
  ["detect_hidden_data", "MEDIUM"],
  ["get_command_history", "MEDIUM"],
  ["detect_rootkit", "MEDIUM"],
  ["parse_powershell_logs", "MEDIUM"],
  ["carve_files", "LOW"],
  ["recover_deleted", "LOW"],
  ["extract_strings", "LOW"],
]);

// ─── Types ────────────────────────────────────────────────────────────────────

interface CategoryCoverage {
  readonly category: ArtifactCategory;
  readonly totalTools: number;
  readonly executedTools: readonly string[];
  readonly percentage: number;
}

interface CoverageGap {
  readonly category: ArtifactCategory;
  readonly tool: string;
  readonly description: string;
  readonly forensicSignificance: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  readonly missingCapabilities: readonly Capability[];
}

// ─── The Reactive State Machine ───────────────────────────────────────────────

export class MethodologyTracker {
  private readonly executedTools: Set<string> = new Set();
  private readonly failedTools: Set<string> = new Set();
  private readonly observedSignals: Set<InvestigationSignal> = new Set();
  private readonly activePaths: Set<string> = new Set();
  private currentState: FSMState = "COLLECTION";
  private readonly specsByCategory: ReadonlyMap<ArtifactCategory, readonly ToolCapabilitySpec[]>;
  private evidenceType: "disk-windows" | "disk-linux" | "disk-macos" | "memory" | "pcap" | "unknown" = "unknown";
  private openHypothesesCount = 0;

  /** Update the count of unresolved hypotheses — called by server after each finding registration */
  setOpenHypothesesCount(count: number): void { this.openHypothesesCount = count; }

  constructor() {
    const map = new Map<ArtifactCategory, ToolCapabilitySpec[]>();
    for (const spec of TOOL_SPECS) {
      const existing = map.get(spec.category) ?? [];
      existing.push(spec);
      map.set(spec.category, existing);
    }
    this.specsByCategory = map;
  }

  /** Set evidence type — drives which baseline applies */
  setEvidenceType(type: "disk-windows" | "disk-linux" | "disk-macos" | "memory" | "pcap" | "unknown"): void {
    this.evidenceType = type;
  }

  /** Get the appropriate baseline for the current evidence type */
  private getBaseline(): readonly BaselineItem[] {
    switch (this.evidenceType) {
      case "disk-linux": return BASELINE_LINUX;
      case "memory": return BASELINE_MEMORY;
      case "pcap": return BASELINE_NETWORK;
      default: return BASELINE_INVESTIGATION; // Windows + macOS + unknown
    }
  }

  /** Emit a signal (from tool output analysis). Activates investigation paths. */
  emitSignal(signal: InvestigationSignal): void {
    this.observedSignals.add(signal);
    // Activate matching investigation paths
    for (const path of INVESTIGATION_PATHS) {
      if (path.triggeredBy.includes(signal)) {
        this.activePaths.add(path.id);
      }
    }
  }

  /** Check tool output for signal patterns and auto-emit matching signals */
  detectSignals(toolOutput: string): readonly InvestigationSignal[] {
    const detected: InvestigationSignal[] = [];
    const lower = toolOutput.toLowerCase();
    for (const sp of SIGNAL_PATTERNS) {
      if (sp.patterns.some(p => lower.includes(p.toLowerCase()))) {
        if (!this.observedSignals.has(sp.signal)) {
          this.emitSignal(sp.signal);
          detected.push(sp.signal);
        }
      }
    }
    return detected;
  }

  /** Record successful tool execution */
  recordExecution(tool: string): void {
    this.executedTools.add(tool);
    this.failedTools.delete(tool);
  }

  /** Record failed tool execution */
  recordFailure(tool: string): void {
    this.failedTools.add(tool);
  }

  /** Get current FSM state */
  getState(): FSMState { return this.currentState; }

  /** Get observed signals */
  getSignals(): readonly InvestigationSignal[] { return [...this.observedSignals]; }

  /** Get active investigation paths */
  getActivePaths(): readonly InvestigationPath[] {
    return INVESTIGATION_PATHS.filter(p => this.activePaths.has(p.id));
  }

  /** Advance state based on conditions */
  private advanceState(heldCapabilities: readonly Capability[]): void {
    const heldSet = new Set(heldCapabilities);

    switch (this.currentState) {
      case "COLLECTION":
        if (heldSet.has("evidence_mounted") && heldSet.has("integrity_verified")) {
          this.currentState = "TRIAGE";
        }
        break;
      case "TRIAGE":
        // For memory/pcap, skip straight to CLASSIFY (no filesystem to list)
        if (this.evidenceType === "memory" || this.evidenceType === "pcap") {
          this.currentState = "CLASSIFY";
        } else if (this.executedTools.has("list_directory") && (this.executedTools.has("search_filename") || this.failedTools.has("search_filename"))) {
          this.currentState = "CLASSIFY";
        }
        break;
      case "CLASSIFY":
        // Triage complete → begin deep investigation. Coverage is driven by the
        // comprehensive baseline (not by signals), so we always proceed.
        if (this.observedSignals.size > 0 || this.executedTools.has("list_directory") || this.executedTools.has("search_filename")) {
          this.currentState = "INVESTIGATE";
        }
        break;
      case "INVESTIGATE":
        // Advance ONLY when every baseline + signal-driven tool has been attempted
        // (executed, failed, or genuinely unreachable). No early 50% bail-out.
        if (this.nextInvestigateTool(heldSet) === null) {
          this.currentState = "TIMELINE";
        }
        break;
      case "TIMELINE":
        if (this.executedTools.has("generate_timeline") || this.failedTools.has("generate_timeline") ||
            !this.capsHeld("generate_timeline", heldSet)) {
          this.currentState = "CORRELATE";
        }
        break;
      case "CORRELATE": {
        const corrTools = ["build_attack_narrative", "map_mitre_techniques"];
        const anyActionablePending = corrTools.some(t =>
          !this.executedTools.has(t) && !this.failedTools.has(t) && this.capsHeld(t, heldSet));
        // Gate: don't advance to REPORT if hypotheses remain unresolved AND
        // corroboration tools haven't been attempted. This encourages the agent
        // to call get_hypothesis_status / corroborate_finding before wrapping up.
        const hypothesesBlocking = this.openHypothesesCount > 0 &&
          !this.executedTools.has("get_hypothesis_status") && !this.failedTools.has("get_hypothesis_status");
        if (!anyActionablePending && !hypothesesBlocking) {
          this.currentState = "REPORT";
        }
        break;
      }
      case "REPORT":
        break; // Terminal
    }
  }

  /** Suggest next action based on reactive FSM state */
  suggestNextAction(heldCapabilities: readonly Capability[]): SuggestedAction & {
    phase: string;
    phaseDescription: string;
    state: FSMState;
    activePathNames: readonly string[];
    signals: readonly InvestigationSignal[];
    transition?: string;
  } | null {
    this.advanceState(heldCapabilities);
    const heldSet = new Set(heldCapabilities);

    switch (this.currentState) {
       case "COLLECTION": {
         if (!this.executedTools.has("mount_evidence")) {
           return this.mkSuggestion("mount_evidence", "Mount the evidence image (E01/raw/dd/VMDK)", "CRITICAL", "Evidence Collection");
         }
         if (!this.executedTools.has("verify_integrity") && !this.failedTools.has("verify_integrity")) {
           return this.mkSuggestion("verify_integrity", "Cryptographic verification — establishes evidentiary foundation", "CRITICAL", "Evidence Collection");
         }
         if (!this.executedTools.has("list_partitions") && !this.failedTools.has("list_partitions")) {
           return this.mkSuggestion("list_partitions", "Identify partition layout before filesystem access", "HIGH", "Evidence Collection");
         }
         // All collection tools attempted — advance
         this.currentState = "TRIAGE";
         return this.suggestNextAction(heldCapabilities);
       }

      case "TRIAGE": {
        // For memory-only evidence, skip filesystem triage
        if (this.evidenceType === "memory") {
          this.currentState = "CLASSIFY";
          return this.suggestNextAction(heldCapabilities);
        }
        // For PCAP-only, skip filesystem triage
        if (this.evidenceType === "pcap") {
          this.currentState = "CLASSIFY";
          return this.suggestNextAction(heldCapabilities);
        }
        if (!this.executedTools.has("list_directory")) {
          return this.mkSuggestion("list_directory", "Scan root filesystem — identify users, programs, suspicious directories", "CRITICAL", "Filesystem Triage");
        }
        if (!this.executedTools.has("search_filename") && !this.failedTools.has("search_filename")) {
          return this.mkSuggestion("search_filename", "Search for suspicious files (executables in unusual locations, known-bad names)", "CRITICAL", "Filesystem Triage");
        }
        // Triage done — advance
        this.currentState = "CLASSIFY";
        return this.suggestNextAction(heldCapabilities);
      }

      case "CLASSIFY": {
        // Classification is implicit: signals observed during triage have already
        // activated their paths. Coverage is guaranteed by the baseline regardless,
        // so move straight into deep investigation.
        this.currentState = "INVESTIGATE";
        return this.suggestNextAction(heldCapabilities);
      }

      case "INVESTIGATE": {
        const next = this.nextInvestigateTool(heldSet);
        if (next) {
          return this.mkSuggestion(
            next.tool,
            next.reason,
            next.critical ? "CRITICAL" : "HIGH",
            "Deep Investigation",
          );
        }
        // Every baseline + signal-driven tool attempted — advance to timeline
        this.currentState = "TIMELINE";
        return this.suggestNextAction(heldCapabilities);
      }

      case "TIMELINE": {
        const tl = "generate_timeline";
        if (!this.executedTools.has(tl) && !this.failedTools.has(tl) && this.capsHeld(tl, heldSet)) {
          return this.mkSuggestion(tl, "Super timeline — correlate all events chronologically to reveal attack sequence", "HIGH", "Timeline Synthesis");
        }
        this.currentState = "CORRELATE";
        return this.suggestNextAction(heldCapabilities);
      }

      case "CORRELATE": {
        // Correlation tools synthesise registered findings. If none are actionable
        // (e.g. no findings were registered), skip to report rather than loop.
        for (const tool of ["build_attack_narrative", "map_mitre_techniques"]) {
          if (this.executedTools.has(tool) || this.failedTools.has(tool)) continue;
          if (!this.capsHeld(tool, heldSet)) continue; // unreachable — no mechanical unlocker
          const reason = tool === "build_attack_narrative"
            ? "Synthesize registered findings into a coherent attack narrative"
            : "Map findings to MITRE ATT&CK framework";
          return this.mkSuggestion(tool, reason, tool === "build_attack_narrative" ? "HIGH" : "MEDIUM", "Correlation & Synthesis");
        }
        // Hypothesis resolution gate: if hypotheses remain OPEN, suggest reviewing them
        if (this.openHypothesesCount > 0 && !this.executedTools.has("get_hypothesis_status") && !this.failedTools.has("get_hypothesis_status")) {
          return this.mkSuggestion("get_hypothesis_status", `${this.openHypothesesCount} hypotheses remain unresolved — review their evidence status before reporting`, "HIGH", "Hypothesis Resolution");
        }
        this.currentState = "REPORT";
        return this.suggestNextAction(heldCapabilities);
      }

      case "REPORT": {
        if (!this.executedTools.has("generate_report")) {
          if (!this.capsHeld("generate_report", heldSet)) {
            return this.mkSuggestion("register_finding", "Register at least one finding before generating the report", "HIGH", "Report Generation");
          }
          return this.mkSuggestion("generate_report", "Generate final forensic report with confidence levels and HMAC seal. Use format='html' for visual report with entropy curve, correlation graph, and Export PDF button.", "HIGH", "Report Generation");
        }
        return null; // Investigation complete
      }
    }
  }

  // ─── INVESTIGATE-phase coverage engine ──────────────────────────────────────
  // The senior-analyst guarantee: a comprehensive baseline is attempted on EVERY
  // investigation, then signal-driven paths add DEPTH on whatever was found.
  // Signals re-order and deepen — they never gate which categories get covered.

  /** All tools the INVESTIGATE phase must consider: baseline (always) + active-path depth. */
  private investigateCandidates(): readonly { tool: string; reason: string; critical: boolean }[] {
    const out: { tool: string; reason: string; critical: boolean }[] = [];
    const seen = new Set<string>();
    // 1. Comprehensive baseline — evidence-type-aware, every investigation.
    for (const b of this.getBaseline()) {
      out.push({ tool: b.tool, reason: `[Baseline · ${b.category}] ${b.reason}`, critical: true });
      seen.add(b.tool);
    }
    // 2. Signal-driven depth — extra tools from paths the evidence activated.
    for (const path of [...this.getActivePaths()].sort((a, b) => a.priority - b.priority)) {
      for (const t of path.tools) {
        if (seen.has(t.tool)) continue;
        out.push({ tool: t.tool, reason: `[${path.name}] ${t.reason}`, critical: t.critical });
        seen.add(t.tool);
      }
    }
    return out;
  }

  /**
   * The next actionable INVESTIGATE tool, or null when the full baseline + active
   * paths have all been attempted or proven unreachable. Active-path categories are
   * prioritised first (signal-driven ordering); within that, critical before optional.
   * Capability prerequisites are resolved by suggesting their unlocker tool.
   */
  private nextInvestigateTool(heldSet: Set<Capability>): { tool: string; reason: string; critical: boolean } | null {
    const activeCats = new Set(this.getActivePaths().flatMap(p => [...p.categories]));
    const ordered = [...this.investigateCandidates()].sort((a, b) => {
      const sa = TOOL_SPECS.find(s => s.tool === a.tool);
      const sb = TOOL_SPECS.find(s => s.tool === b.tool);
      const aActive = sa && activeCats.has(sa.category) ? 0 : 1;
      const bActive = sb && activeCats.has(sb.category) ? 0 : 1;
      if (aActive !== bActive) return aActive - bActive;          // signal-driven priority
      if (a.critical !== b.critical) return a.critical ? -1 : 1;  // critical before optional
      return 0;
    });

    for (const c of ordered) {
      if (this.executedTools.has(c.tool) || this.failedTools.has(c.tool)) continue; // attempted
      const spec = TOOL_SPECS.find(s => s.tool === c.tool);
      if (!spec) continue;
      const missing = spec.requires.filter(cap => !heldSet.has(cap));
      if (missing.length === 0) {
        return { tool: c.tool, reason: c.reason, critical: c.critical };
      }
      // Prerequisite missing — suggest an unlocker that hasn't been attempted yet.
      const unlocker = TOOL_SPECS.find(s =>
        s.produces.some(p => missing.includes(p)) &&
        !this.executedTools.has(s.tool) && !this.failedTools.has(s.tool)
      );
      if (unlocker) {
        return { tool: unlocker.tool, reason: `Prerequisite for "${c.tool}": unlocks ${unlocker.produces.join(", ")}`, critical: c.critical };
      }
      // No attemptable unlocker → tool is unreachable in this environment; skip it.
    }
    return null;
  }

  /** True if every capability a tool requires is currently held. */
  private capsHeld(tool: string, heldSet: Set<Capability>): boolean {
    const spec = TOOL_SPECS.find(s => s.tool === tool);
    if (!spec) return false;
    return spec.requires.every(cap => heldSet.has(cap));
  }

  private mkSuggestion(tool: string, reason: string, priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", phaseName: string): SuggestedAction & {
    phase: string; phaseDescription: string; state: FSMState; activePathNames: readonly string[]; signals: readonly InvestigationSignal[]; transition?: string;
    directive?: { whatEvilLooksLike: string; whatNormalLooksLike: string; hypothesisTested: string; confirmationCriteria: string; ifConfirmed: string; ifAbsent: string; params?: Record<string, string> };
  } {
    // Find the matching ontology node for this tool to provide full cognitive frame
    const node = INVESTIGATION_ONTOLOGY.find(n => n.tool === tool || n.operation === tool) as InvestigationNode | undefined;
    return {
      tool,
      reason,
      priority,
      phase: phaseName,
      phaseDescription: phaseName,
      state: this.currentState,
      activePathNames: this.getActivePaths().map(p => p.name),
      signals: [...this.observedSignals],
      ...(node ? { directive: {
        whatEvilLooksLike: node.whatEvilLooksLike,
        whatNormalLooksLike: node.whatNormalLooksLike,
        hypothesisTested: node.hypothesisTested,
        confirmationCriteria: node.confirmationCriteria,
        ifConfirmed: node.ifConfirmed,
        ifAbsent: node.ifAbsent,
        ...(node.params ? { params: node.params } : {}),
      }} : {}),
    };
  }

  /** Get phases for display — maps FSM states to a structured view */
  getPhases(): readonly { id: string; name: string; status: "pending" | "active" | "complete" | "skipped"; order: number }[] {
    const states: { id: FSMState; name: string; order: number }[] = [
      { id: "COLLECTION", name: "Evidence Collection & Verification", order: 0 },
      { id: "TRIAGE", name: "Filesystem Triage", order: 1 },
      { id: "CLASSIFY", name: "Incident Classification", order: 2 },
      { id: "INVESTIGATE", name: "Deep Investigation (signal-driven)", order: 3 },
      { id: "TIMELINE", name: "Timeline Synthesis", order: 4 },
      { id: "CORRELATE", name: "Correlation & ATT&CK Mapping", order: 5 },
      { id: "REPORT", name: "Report Generation", order: 6 },
    ];
    const currentOrder = states.find(s => s.id === this.currentState)?.order ?? 0;
    return states.map(s => ({
      id: s.id,
      name: s.name,
      order: s.order,
      status: s.id === this.currentState ? "active" as const :
              s.order < currentOrder ? "complete" as const : "pending" as const,
    }));
  }

  /** Whether the FSM has reached the REPORT state (all baseline tools attempted) */
  isReadyForReport(): boolean {
    return this.currentState === "REPORT";
  }

  /** Force FSM to REPORT when remaining tools are environmentally blocked (not actionable). */
  forceAdvanceToReport(): void {
    this.currentState = "REPORT";
  }

  /** Alternative stop criterion using Rough Set boundary (H1 wire-in) */
  /** Get count and names of baseline tools not yet attempted */
  getRemainingSteps(): { count: number; tools: readonly string[] } {
    const baseline = this.getBaseline();
    const remaining = baseline.filter(b =>
      !this.executedTools.has(b.tool) && !this.failedTools.has(b.tool)
    );
    return { count: remaining.length, tools: remaining.map(b => b.tool) };
  }

  getOverallCoverage(): number {
    let analysisCategories: ArtifactCategory[];
    switch (this.evidenceType) {
      case "disk-linux":
        analysisCategories = ["filesystem", "linux", "anti_forensics", "persistence", "timeline"];
        break;
      case "memory":
        analysisCategories = ["memory"];
        break;
      case "pcap":
        analysisCategories = ["network"];
        break;
      default: // disk-windows, disk-macos, unknown
        // Disk-derivable categories only. Memory and network forensics require
        // their own evidence sources (a memory dump / packet capture); counting
        // them against a pure disk image would understate true coverage.
        analysisCategories = [
          "filesystem", "timeline", "registry", "event_logs",
          "execution_artifacts", "persistence", "anti_forensics",
          "user_activity", "browser", "correlation",
        ];
    }
    let total = 0;
    let executed = 0;
    let unavailable = 0;
    for (const cat of analysisCategories) {
      const specs = this.specsByCategory.get(cat) ?? [];
      total += specs.length;
      executed += specs.filter(s => this.executedTools.has(s.tool)).length;
      // Tools that failed (binary unavailable in this environment) are excluded
      // from the denominator — they're environmental limits, not investigation gaps.
      unavailable += specs.filter(s => this.failedTools.has(s.tool) && !this.executedTools.has(s.tool)).length;
    }
    const achievable = total - unavailable;
    return achievable > 0 ? Math.round((executed / achievable) * 100) : 0;
  }

  /** Get coverage per category */
  getCoverage(): readonly CategoryCoverage[] {
    const result: CategoryCoverage[] = [];
    for (const [category, specs] of this.specsByCategory) {
      const executed = specs.filter(s => this.executedTools.has(s.tool)).map(s => s.tool);
      result.push({
        category,
        totalTools: specs.length,
        executedTools: executed,
        percentage: specs.length > 0 ? Math.round((executed.length / specs.length) * 100) : 0,
      });
    }
    return result.sort((a, b) => a.percentage - b.percentage);
  }

  /** Get coverage gaps, prioritized by active investigation paths */
  getCoverageGaps(heldCapabilities: readonly Capability[]): readonly CoverageGap[] {
    const gaps: CoverageGap[] = [];
    const heldSet = new Set(heldCapabilities);
    // Baseline categories are evidence-type-aware; active-path categories add depth.
    const baselineCategories = new Set(this.getBaseline().map(b => b.category));
    const activeCategories = new Set([
      ...baselineCategories,
      ...this.getActivePaths().flatMap(p => [...p.categories]),
    ]);

    for (const spec of TOOL_SPECS) {
      if (this.executedTools.has(spec.tool)) continue;
      if (spec.category === "reporting" || spec.category === "acquisition") continue;

      const missingCaps = spec.requires.filter(cap => !heldSet.has(cap));
      const significance = FORENSIC_SIGNIFICANCE.get(spec.tool) ?? "LOW";

      gaps.push({
        category: spec.category,
        tool: spec.tool,
        description: spec.description,
        forensicSignificance: significance,
        missingCapabilities: missingCaps,
      });
    }

    const sigOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return gaps.sort((a, b) => {
      // Active path categories first
      const aActive = activeCategories.has(a.category) ? 0 : 1;
      const bActive = activeCategories.has(b.category) ? 0 : 1;
      if (aActive !== bActive) return aActive - bActive;
      // Executable first
      if (a.missingCapabilities.length === 0 && b.missingCapabilities.length > 0) return -1;
      if (a.missingCapabilities.length > 0 && b.missingCapabilities.length === 0) return 1;
      return sigOrder[a.forensicSignificance] - sigOrder[b.forensicSignificance];
    });
  }

  /** Get workflows to activate based on current state + evidence type + active paths */
  getWorkflowsToActivate(): readonly string[] {
    switch (this.currentState) {
      case "COLLECTION": return ["acquisition"];
      case "TRIAGE":
        if (this.evidenceType === "memory") return ["memory"];
        if (this.evidenceType === "pcap") return ["network"];
        return ["filesystem"];
      case "CLASSIFY":
        if (this.evidenceType === "memory") return ["memory"];
        if (this.evidenceType === "pcap") return ["network"];
        return ["filesystem"];
      case "INVESTIGATE": return [...new Set([
        ...this.getBaseline().map(b => b.category),
        ...this.getActivePaths().flatMap(p => [...p.categories]),
      ])];
      case "TIMELINE": return ["timeline"];
      case "CORRELATE": return ["correlation"];
      case "REPORT": return [];
    }
  }

  /** Reset */
  reset(): void {
    this.executedTools.clear();
    this.failedTools.clear();
    this.observedSignals.clear();
    this.activePaths.clear();
    this.currentState = "COLLECTION";
  }
}
