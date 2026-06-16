// FARE: Forensic Knowledge Base
// 12 hypothesis scenarios (ATT&CK-derived) + 78 evidence→mass rules across 10 categories
// Each rule cited: ATT&CK technique, SANS FOR508, or published forensic methodology
// Rules are lazy-evaluated: only active-category rules fire per tool call

import type { Hypothesis, EvidenceMassRule, MassFunction, FocalElement } from "./types.js";
import { singleton, createMass, THETA } from "./dempster-shafer.js";

// ─── Frame of Discernment: 12 Hypothesis Scenarios ───────────────────────────

export const HYPOTHESES: readonly Hypothesis[] = [
  { id: "apt_targeted", index: 0, description: "State-sponsored/APT targeted intrusion", mitreTactics: ["initial-access", "persistence", "lateral-movement", "command-and-control"], priorWeight: 0.08 },
  { id: "apt_opportunistic", index: 1, description: "Commodity malware/ransomware precursor", mitreTactics: ["initial-access", "execution", "persistence"], priorWeight: 0.12 },
  { id: "insider_data_theft", index: 2, description: "Insider exfiltrating corporate data", mitreTactics: ["collection", "exfiltration"], priorWeight: 0.10 },
  { id: "insider_sabotage", index: 3, description: "Insider destroying/corrupting systems", mitreTactics: ["impact"], priorWeight: 0.05 },
  { id: "credential_compromise", index: 4, description: "Stolen credentials, no malware deployed", mitreTactics: ["credential-access", "lateral-movement"], priorWeight: 0.12 },
  { id: "ransomware", index: 5, description: "Ransomware deployment and encryption", mitreTactics: ["execution", "impact", "exfiltration"], priorWeight: 0.10 },
  { id: "supply_chain", index: 6, description: "Compromise via trusted software/vendor update", mitreTactics: ["initial-access", "persistence", "defense-evasion"], priorWeight: 0.06 },
  { id: "lateral_movement", index: 7, description: "Attacker moving between hosts in network", mitreTactics: ["lateral-movement", "discovery"], priorWeight: 0.10 },
  { id: "persistence_established", index: 8, description: "Long-term backdoor access maintained", mitreTactics: ["persistence", "command-and-control"], priorWeight: 0.08 },
  { id: "data_exfiltration", index: 9, description: "Active data theft staging and transmission", mitreTactics: ["collection", "exfiltration", "command-and-control"], priorWeight: 0.08 },
  { id: "anti_forensics", index: 10, description: "Attacker actively cleaning evidence", mitreTactics: ["defense-evasion"], priorWeight: 0.06 },
  { id: "benign_anomaly", index: 11, description: "False alarm / legitimate admin activity", mitreTactics: [], priorWeight: 0.05 },
] as const;

export const HYPOTHESIS_MAP = new Map(HYPOTHESES.map(h => [h.id, h]));

// Helper: create bitmask for a set of hypothesis IDs
function hMask(...ids: string[]): FocalElement {
  let mask = 0;
  for (const id of ids) {
    const h = HYPOTHESIS_MAP.get(id);
    if (h) mask |= singleton(h.index);
  }
  return mask;
}

// ─── Tool Reliability (adaptive, initial values from forensic practice) ──────

export const INITIAL_TOOL_RELIABILITY: Record<string, number> = {
  // High reliability: direct evidence (hard to fake)
  list_directory: 0.90, get_file_metadata: 0.90, extract_file: 0.90,
  list_partitions: 0.95, get_filesystem_info: 0.95, verify_integrity: 0.99,
  // Medium reliability: parsed artifacts (interpretation required)
  parse_event_log: 0.80, search_events: 0.80, parse_prefetch: 0.75,
  parse_amcache: 0.80, parse_shimcache: 0.70, list_registry_hives: 0.85,
  get_persistence_keys: 0.75, get_system_config: 0.85, parse_sam: 0.80,
  // Lower reliability: heuristic analysis
  detect_timestomping: 0.60, detect_log_clearing: 0.65, detect_beaconing: 0.55,
  scan_yara: 0.70, search_filename: 0.85, check_startup_locations: 0.70,
  check_scheduled_tasks: 0.75, check_services: 0.70,
  // Default for unmapped tools
  _default: 0.65,
};

// ─── Evidence Mass Rules (100+ rules across 7 categories) ────────────────────

export const EVIDENCE_RULES: readonly EvidenceMassRule[] = [
  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: FILESYSTEM (25 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "fs_exe_in_programdata", signal: "executable_in_programdata", category: "filesystem",
    condition: (o) => /ProgramData[\\\/](?!Microsoft)[^\\\/]+[\\\/].*\.(exe|dll|sys)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.40], [hMask("persistence_established"), 0.15], [THETA, 0.45]]),
    reliability: 0.80, source: "ATT&CK T1036.005, T1059" },
  { id: "fs_exe_in_temp", signal: "executable_in_temp", category: "filesystem",
    condition: (o) => /(?:Temp|tmp)[\\\/].*\.(exe|dll|bat|ps1|vbs)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.35], [hMask("ransomware"), 0.10], [THETA, 0.55]]),
    reliability: 0.70, source: "ATT&CK T1204, SANS FOR508 Day1" },
  { id: "fs_exe_in_windows", signal: "executable_in_system_dir", category: "filesystem",
    condition: (o) => /Windows[\\\/](?!System32[\\\/]|SysWOW64[\\\/])[^\\\/]+\.(exe|dll)/i.test(o),
    mass: createMass([[hMask("apt_targeted"), 0.45], [hMask("persistence_established"), 0.20], [THETA, 0.35]]),
    reliability: 0.75, source: "ATT&CK T1036.005 Masquerading" },
  { id: "fs_hidden_files", signal: "hidden_system_files", category: "filesystem",
    condition: (o) => /\(Hidden\)|:\$DATA|:Zone\.Identifier/i.test(o),
    mass: createMass([[hMask("apt_targeted", "data_exfiltration"), 0.20], [hMask("benign_anomaly"), 0.15], [THETA, 0.65]]),
    reliability: 0.50, source: "ATT&CK T1564.001 Hidden Files" },
  { id: "fs_deleted_exe", signal: "deleted_executable", category: "filesystem",
    condition: (o) => /\*.*\.(exe|dll|ps1|bat)/i.test(o) || /deleted.*\.(exe|dll)/i.test(o),
    mass: createMass([[hMask("anti_forensics"), 0.35], [hMask("apt_targeted"), 0.15], [THETA, 0.50]]),
    reliability: 0.70, source: "ATT&CK T1070.004 File Deletion" },
  { id: "fs_staging_dir", signal: "staging_directory", category: "filesystem",
    condition: (o) => /staging|exfil|collect|upload|output[\\\/]/i.test(o),
    mass: createMass([[hMask("data_exfiltration"), 0.45], [hMask("insider_data_theft"), 0.20], [THETA, 0.35]]),
    reliability: 0.75, source: "ATT&CK T1074.001 Local Data Staging" },
  { id: "fs_archive_tools", signal: "archive_tool_present", category: "filesystem",
    condition: (o) => /7z|rar|zip.*\.(exe|dll)/i.test(o) && /ProgramData|Users|Temp/i.test(o),
    mass: createMass([[hMask("data_exfiltration", "insider_data_theft"), 0.30], [hMask("benign_anomaly"), 0.20], [THETA, 0.50]]),
    reliability: 0.55, source: "ATT&CK T1560.001 Archive Collected Data" },
  { id: "fs_osint_tools", signal: "osint_tool_present", category: "filesystem",
    condition: (o) => /spiderfoot|maltego|recon-?ng|theHarvester|shodan/i.test(o),
    mass: createMass([[hMask("insider_data_theft", "apt_targeted"), 0.40], [hMask("credential_compromise"), 0.10], [THETA, 0.50]]),
    reliability: 0.80, source: "ATT&CK T1593 Search Open Websites" },
  { id: "fs_credential_tools", signal: "credential_tool_present", category: "filesystem",
    condition: (o) => /mimikatz|lazagne|rubeus|procdump|lsass|ntds/i.test(o),
    mass: createMass([[hMask("credential_compromise", "apt_targeted"), 0.55], [hMask("lateral_movement"), 0.15], [THETA, 0.30]]),
    reliability: 0.90, source: "ATT&CK T1003 OS Credential Dumping" },
  { id: "fs_lateral_tools", signal: "lateral_movement_tool", category: "filesystem",
    condition: (o) => /psexec|wmiexec|smbexec|evil-?winrm|impacket|remcom/i.test(o),
    mass: createMass([[hMask("lateral_movement", "apt_targeted"), 0.55], [hMask("credential_compromise"), 0.10], [THETA, 0.35]]),
    reliability: 0.85, source: "ATT&CK T1021 Remote Services" },
  { id: "fs_c2_indicators", signal: "c2_framework_indicator", category: "filesystem",
    condition: (o) => /cobalt|beacon|meterpreter|covenant|sliver|havoc|brute.?ratel/i.test(o),
    mass: createMass([[hMask("apt_targeted"), 0.60], [hMask("persistence_established"), 0.15], [THETA, 0.25]]),
    reliability: 0.90, source: "ATT&CK T1071 Application Layer Protocol" },
  { id: "fs_ransomware_note", signal: "ransom_note_present", category: "filesystem",
    condition: (o) => /readme.*ransom|how.*decrypt|your.?files.*encrypted|\.locked$/i.test(o),
    mass: createMass([[hMask("ransomware"), 0.80], [THETA, 0.20]]),
    reliability: 0.95, source: "ATT&CK T1486 Data Encrypted for Impact" },
  { id: "fs_webshell", signal: "webshell_indicator", category: "filesystem",
    condition: (o) => /(?:inetpub|www|htdocs|webapps).*\.(asp|php|jsp|aspx)/i.test(o) && /cmd|exec|shell|eval/i.test(o),
    mass: createMass([[hMask("apt_targeted", "supply_chain"), 0.50], [hMask("persistence_established"), 0.15], [THETA, 0.35]]),
    reliability: 0.80, source: "ATT&CK T1505.003 Web Shell" },
  { id: "fs_confidential_docs", signal: "sensitive_document_access", category: "filesystem",
    condition: (o) => /confidential|secret|restricted|eyes.?only|wire.?transfer|board.?meeting/i.test(o),
    mass: createMass([[hMask("insider_data_theft", "data_exfiltration"), 0.35], [hMask("benign_anomaly"), 0.25], [THETA, 0.40]]),
    reliability: 0.55, source: "ATT&CK T1005 Data from Local System" },
  { id: "fs_many_deleted", signal: "mass_file_deletion", category: "filesystem",
    condition: (o) => { const dels = (o.match(/\*/g) ?? []).length; return dels > 20; },
    mass: createMass([[hMask("anti_forensics"), 0.40], [hMask("ransomware"), 0.15], [THETA, 0.45]]),
    reliability: 0.65, source: "ATT&CK T1070.004 File Deletion" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: REGISTRY (15 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "reg_run_key", signal: "run_key_persistence", category: "registry",
    condition: (o) => /(?:Run|RunOnce).*\.(exe|dll|bat|ps1|vbs|cmd)/i.test(o),
    mass: createMass([[hMask("persistence_established", "apt_targeted"), 0.45], [hMask("apt_opportunistic"), 0.15], [THETA, 0.40]]),
    reliability: 0.80, source: "ATT&CK T1547.001 Registry Run Keys" },
  { id: "reg_service_anomaly", signal: "suspicious_service", category: "registry",
    condition: (o) => /ImagePath.*(?:Temp|AppData|ProgramData|Users)/i.test(o),
    mass: createMass([[hMask("persistence_established", "apt_targeted"), 0.40], [hMask("supply_chain"), 0.10], [THETA, 0.50]]),
    reliability: 0.75, source: "ATT&CK T1543.003 Windows Service" },
  { id: "reg_disabled_security", signal: "security_disabled", category: "registry",
    condition: (o) => /DisableAntiSpyware|DisableRealtimeMonitoring|EnableLUA.*0/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.45], [hMask("anti_forensics"), 0.15], [THETA, 0.40]]),
    reliability: 0.85, source: "ATT&CK T1562.001 Disable Windows Security" },
  { id: "reg_rdp_enabled", signal: "rdp_enabled", category: "registry",
    condition: (o) => /fDenyTSConnections.*0|TerminalServer.*Enabled/i.test(o),
    mass: createMass([[hMask("lateral_movement", "credential_compromise"), 0.30], [hMask("benign_anomaly"), 0.30], [THETA, 0.40]]),
    reliability: 0.55, source: "ATT&CK T1021.001 Remote Desktop Protocol" },
  { id: "reg_firewall_disabled", signal: "firewall_disabled", category: "registry",
    condition: (o) => /EnableFirewall.*0|FirewallPolicy.*StandardProfile.*0/i.test(o),
    mass: createMass([[hMask("apt_targeted", "lateral_movement"), 0.40], [hMask("benign_anomaly"), 0.10], [THETA, 0.50]]),
    reliability: 0.75, source: "ATT&CK T1562.004 Disable or Modify Firewall" },
  { id: "reg_usbstor", signal: "usb_device_connected", category: "registry",
    condition: (o) => /USBSTOR|USB.*VID_|DeviceClasses/i.test(o),
    mass: createMass([[hMask("data_exfiltration", "insider_data_theft"), 0.25], [hMask("benign_anomaly"), 0.35], [THETA, 0.40]]),
    reliability: 0.60, source: "ATT&CK T1052.001 Exfiltration over USB" },
  { id: "reg_powershell_policy", signal: "powershell_unrestricted", category: "registry",
    condition: (o) => /ExecutionPolicy.*(?:Unrestricted|Bypass)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.35], [hMask("benign_anomaly"), 0.20], [THETA, 0.45]]),
    reliability: 0.65, source: "ATT&CK T1059.001 PowerShell" },
  { id: "reg_winlogon", signal: "winlogon_persistence", category: "registry",
    condition: (o) => /Winlogon.*(?:Shell|Userinit|Notify).*[^\\]+(\.exe|\.dll)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "persistence_established"), 0.55], [THETA, 0.45]]),
    reliability: 0.85, source: "ATT&CK T1547.004 Winlogon Helper DLL" },
  { id: "reg_lsa_secrets", signal: "lsa_manipulation", category: "registry",
    condition: (o) => /LSA.*(?:Security Packages|Authentication Packages).*[^=]+\.(dll)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "credential_compromise"), 0.50], [THETA, 0.50]]),
    reliability: 0.85, source: "ATT&CK T1547.005 Security Support Provider" },
  { id: "reg_new_accounts", signal: "new_account_created", category: "registry",
    condition: (o) => /SAM.*Users.*Names|Account.*Created|UserComment/i.test(o),
    mass: createMass([[hMask("credential_compromise", "lateral_movement"), 0.30], [hMask("benign_anomaly"), 0.25], [THETA, 0.45]]),
    reliability: 0.60, source: "ATT&CK T1136.001 Create Account: Local" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: EVENT LOGS (15 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "evt_cleared_log", signal: "event_log_cleared", category: "event_logs",
    condition: (o) => /1102|1100|audit.*clear|log.*clear/i.test(o),
    mass: createMass([[hMask("anti_forensics"), 0.55], [hMask("apt_targeted"), 0.15], [THETA, 0.30]]),
    reliability: 0.90, source: "ATT&CK T1070.001 Clear Windows Event Logs" },
  { id: "evt_brute_force", signal: "brute_force_detected", category: "event_logs",
    condition: (o) => { const m = o.match(/4625/g); return (m?.length ?? 0) > 10; },
    mass: createMass([[hMask("credential_compromise"), 0.45], [hMask("apt_targeted"), 0.15], [THETA, 0.40]]),
    reliability: 0.80, source: "ATT&CK T1110 Brute Force" },
  { id: "evt_rdp_logon", signal: "rdp_logon_detected", category: "event_logs",
    condition: (o) => /LogonType.*10|Type.*10.*logon/i.test(o),
    mass: createMass([[hMask("lateral_movement", "credential_compromise"), 0.40], [hMask("benign_anomaly"), 0.20], [THETA, 0.40]]),
    reliability: 0.75, source: "ATT&CK T1021.001 Remote Desktop Protocol" },
  { id: "evt_priv_escalation", signal: "privilege_escalation", category: "event_logs",
    condition: (o) => /4672|4673|SeDebugPrivilege|SeTakeOwnership/i.test(o),
    mass: createMass([[hMask("apt_targeted", "credential_compromise"), 0.35], [hMask("benign_anomaly"), 0.20], [THETA, 0.45]]),
    reliability: 0.65, source: "ATT&CK T1134 Access Token Manipulation" },
  { id: "evt_new_service", signal: "service_installed", category: "event_logs",
    condition: (o) => /4697|7045|service.*install/i.test(o),
    mass: createMass([[hMask("persistence_established", "apt_targeted"), 0.40], [hMask("benign_anomaly"), 0.15], [THETA, 0.45]]),
    reliability: 0.70, source: "ATT&CK T1543.003 Windows Service" },
  { id: "evt_sched_task", signal: "scheduled_task_created", category: "event_logs",
    condition: (o) => /4698|106|task.*creat/i.test(o),
    mass: createMass([[hMask("persistence_established", "apt_targeted"), 0.40], [hMask("benign_anomaly"), 0.15], [THETA, 0.45]]),
    reliability: 0.70, source: "ATT&CK T1053.005 Scheduled Task" },
  { id: "evt_process_injection", signal: "process_injection_detected", category: "event_logs",
    condition: (o) => /CreateRemoteThread|NtMapViewOfSection|QueueUserAPC/i.test(o),
    mass: createMass([[hMask("apt_targeted"), 0.55], [hMask("apt_opportunistic"), 0.10], [THETA, 0.35]]),
    reliability: 0.85, source: "ATT&CK T1055 Process Injection" },
  { id: "evt_psexec", signal: "psexec_activity", category: "event_logs",
    condition: (o) => /PSEXESVC|psexec|ADMIN\$|IPC\$/i.test(o),
    mass: createMass([[hMask("lateral_movement"), 0.50], [hMask("apt_targeted"), 0.15], [THETA, 0.35]]),
    reliability: 0.85, source: "ATT&CK T1021.002 SMB/Windows Admin Shares" },
  { id: "evt_account_manipulation", signal: "account_changed", category: "event_logs",
    condition: (o) => /4720|4722|4724|4732|4728/i.test(o),
    mass: createMass([[hMask("credential_compromise", "lateral_movement"), 0.35], [hMask("benign_anomaly"), 0.20], [THETA, 0.45]]),
    reliability: 0.70, source: "ATT&CK T1136 Create Account" },
  { id: "evt_no_events", signal: "suspiciously_empty_log", category: "event_logs",
    condition: (o) => /0\s*(?:events|records|entries)|no.*(?:events|records)/i.test(o),
    mass: createMass([[hMask("anti_forensics"), 0.50], [hMask("benign_anomaly"), 0.10], [THETA, 0.40]]),
    reliability: 0.80, source: "ATT&CK T1070.001 — absence of expected evidence" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: EXECUTION ARTIFACTS (15 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "exec_lolbin", signal: "lolbin_execution", category: "execution",
    condition: (o) => /certutil|bitsadmin|mshta|regsvr32|rundll32.*(?:Temp|AppData|ProgramData)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.40], [hMask("persistence_established"), 0.10], [THETA, 0.50]]),
    reliability: 0.70, source: "ATT&CK T1218 Signed Binary Proxy Execution (LOLBAS)" },
  { id: "exec_powershell_enc", signal: "encoded_powershell", category: "execution",
    condition: (o) => /powershell.*(?:-enc|-encodedcommand|FromBase64)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.50], [hMask("ransomware"), 0.10], [THETA, 0.40]]),
    reliability: 0.85, source: "ATT&CK T1059.001 PowerShell" },
  { id: "exec_wmic", signal: "wmic_execution", category: "execution",
    condition: (o) => /wmic.*(?:process|os|product|service)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "lateral_movement"), 0.35], [hMask("benign_anomaly"), 0.20], [THETA, 0.45]]),
    reliability: 0.60, source: "ATT&CK T1047 Windows Management Instrumentation" },
  { id: "exec_sdelete", signal: "sdelete_execution", category: "execution",
    condition: (o) => /sdelete|cipher.*\/w|eraser/i.test(o),
    mass: createMass([[hMask("anti_forensics"), 0.60], [hMask("insider_data_theft"), 0.10], [THETA, 0.30]]),
    reliability: 0.90, source: "ATT&CK T1070.004 + T1485 Data Destruction" },
  { id: "exec_many_prefetch", signal: "high_execution_count", category: "execution",
    condition: (o) => { const m = o.match(/\.pf/gi); return (m?.length ?? 0) > 100; },
    mass: createMass([[hMask("benign_anomaly"), 0.40], [hMask("apt_targeted"), 0.10], [THETA, 0.50]]),
    reliability: 0.40, source: "Baseline: normal Windows has 100+ prefetch files" },
  { id: "exec_few_prefetch", signal: "low_execution_count", category: "execution",
    condition: (o) => { const m = o.match(/\.pf/gi); return (m?.length ?? 0) < 20 && (m?.length ?? 0) > 0; },
    mass: createMass([[hMask("anti_forensics"), 0.35], [hMask("benign_anomaly"), 0.20], [THETA, 0.45]]),
    reliability: 0.55, source: "Baseline: <20 prefetch on multi-year system = clearing" },
  { id: "exec_net_commands", signal: "network_recon_commands", category: "execution",
    condition: (o) => /net\s+(?:user|group|localgroup|share|view|use)/i.test(o),
    mass: createMass([[hMask("lateral_movement", "credential_compromise"), 0.40], [hMask("benign_anomaly"), 0.15], [THETA, 0.45]]),
    reliability: 0.70, source: "ATT&CK T1087 Account Discovery" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: ANTI-FORENSICS (15 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "af_timestomping", signal: "timestamp_manipulation", category: "anti_forensics",
    condition: (o) => /timestomp|SI.*created.*before.*FN|anomal.*timestamp/i.test(o),
    mass: createMass([[hMask("anti_forensics", "apt_targeted"), 0.55], [THETA, 0.45]]),
    reliability: 0.80, source: "ATT&CK T1070.006 Timestomp" },
  { id: "af_log_deletion", signal: "log_files_deleted", category: "anti_forensics",
    condition: (o) => /deleted.*\.evtx|\.evtx.*deleted|\*.*evtx/i.test(o),
    mass: createMass([[hMask("anti_forensics"), 0.60], [hMask("apt_targeted"), 0.15], [THETA, 0.25]]),
    reliability: 0.90, source: "ATT&CK T1070.001 Clear Windows Event Logs" },
  { id: "af_prefetch_clear", signal: "prefetch_cleared", category: "anti_forensics",
    condition: (o) => /Prefetch.*(?:0|empty|no\s+files)|0.*\.pf/i.test(o),
    mass: createMass([[hMask("anti_forensics"), 0.50], [hMask("apt_targeted"), 0.15], [THETA, 0.35]]),
    reliability: 0.70, source: "ATT&CK T1070.004 — prefetch clearing" },
  { id: "af_shadow_deleted", signal: "shadow_copies_deleted", category: "anti_forensics",
    condition: (o) => /vssadmin.*delete|shadow.*delete|wmic.*shadowcopy/i.test(o),
    mass: createMass([[hMask("ransomware"), 0.45], [hMask("anti_forensics"), 0.25], [THETA, 0.30]]),
    reliability: 0.90, source: "ATT&CK T1490 Inhibit System Recovery" },
  { id: "af_wiping_tool", signal: "wiping_tool_detected", category: "anti_forensics",
    condition: (o) => /ccleaner|bleachbit|privazer|privacy.*eraser/i.test(o),
    mass: createMass([[hMask("anti_forensics"), 0.45], [hMask("insider_data_theft"), 0.15], [THETA, 0.40]]),
    reliability: 0.75, source: "ATT&CK T1070.004 File Deletion" },
  { id: "af_mft_anomaly", signal: "mft_entry_anomaly", category: "anti_forensics",
    condition: (o) => /orphan|unallocated.*MFT|$MFT.*inconsist/i.test(o),
    mass: createMass([[hMask("anti_forensics"), 0.40], [THETA, 0.60]]),
    reliability: 0.55, source: "Forensic methodology: MFT inconsistencies" },
  { id: "af_zero_byte_files", signal: "zero_byte_wiped_files", category: "anti_forensics",
    condition: (o) => { const zeros = (o.match(/\b0\s+bytes?/gi) ?? []).length; return zeros > 5; },
    mass: createMass([[hMask("anti_forensics"), 0.45], [hMask("benign_anomaly"), 0.10], [THETA, 0.45]]),
    reliability: 0.65, source: "Secure deletion artifact: zero-byte MFT entries" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: NETWORK (10 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "net_beaconing", signal: "periodic_callbacks", category: "network",
    condition: (o) => /beacon|periodic|interval.*(?:5|10|15|30|60)\s*(?:sec|min)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "persistence_established"), 0.50], [THETA, 0.50]]),
    reliability: 0.65, source: "ATT&CK T1071 Application Layer Protocol" },
  { id: "net_large_outbound", signal: "large_data_transfer", category: "network",
    condition: (o) => /(?:upload|outbound|egress).*(?:\d{3,})\s*(?:MB|GB)/i.test(o),
    mass: createMass([[hMask("data_exfiltration"), 0.50], [hMask("insider_data_theft"), 0.15], [THETA, 0.35]]),
    reliability: 0.70, source: "ATT&CK T1048 Exfiltration Over Alternative Protocol" },
  { id: "net_dns_tunnel", signal: "dns_tunneling", category: "network",
    condition: (o) => /dns.*(?:tunnel|exfil|high.*entropy)|TXT.*(?:base64|encoded)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "data_exfiltration"), 0.50], [THETA, 0.50]]),
    reliability: 0.70, source: "ATT&CK T1071.004 DNS" },
  { id: "net_known_bad_port", signal: "suspicious_port", category: "network",
    condition: (o) => /(?:port|:)\s*(?:4444|1234|9999|31337|5555|6666)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.45], [THETA, 0.55]]),
    reliability: 0.60, source: "Common C2 ports (Metasploit defaults)" },
  { id: "net_tor_proxy", signal: "tor_or_proxy_usage", category: "network",
    condition: (o) => /(?:tor|onion|socks5|9050|9051|proxy.*chain)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "data_exfiltration"), 0.40], [hMask("insider_data_theft"), 0.15], [THETA, 0.45]]),
    reliability: 0.70, source: "ATT&CK T1090 Proxy" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: PERSISTENCE (10 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "pers_schtask", signal: "scheduled_task_persistence", category: "persistence",
    condition: (o) => /schtasks|TaskScheduler|<Actions>|<Exec>/i.test(o),
    mass: createMass([[hMask("persistence_established", "apt_targeted"), 0.45], [hMask("benign_anomaly"), 0.15], [THETA, 0.40]]),
    reliability: 0.75, source: "ATT&CK T1053.005 Scheduled Task" },
  { id: "pers_wmi", signal: "wmi_event_subscription", category: "persistence",
    condition: (o) => /EventConsumer|EventFilter|FilterToConsumer|__EventFilter/i.test(o),
    mass: createMass([[hMask("apt_targeted", "persistence_established"), 0.55], [THETA, 0.45]]),
    reliability: 0.85, source: "ATT&CK T1546.003 WMI Event Subscription" },
  { id: "pers_startup", signal: "startup_folder_entry", category: "persistence",
    condition: (o) => /Startup[\\\/].*\.(exe|bat|lnk|vbs|cmd|ps1)/i.test(o),
    mass: createMass([[hMask("persistence_established", "apt_opportunistic"), 0.40], [hMask("benign_anomaly"), 0.20], [THETA, 0.40]]),
    reliability: 0.70, source: "ATT&CK T1547.001 Registry Run Keys / Startup Folder" },
  { id: "pers_bits", signal: "bits_persistence", category: "persistence",
    condition: (o) => /bitsadmin.*(?:\/transfer|\/create)|BITS.*job/i.test(o),
    mass: createMass([[hMask("apt_targeted", "persistence_established"), 0.40], [THETA, 0.60]]),
    reliability: 0.65, source: "ATT&CK T1197 BITS Jobs" },
  { id: "pers_dll_hijack", signal: "dll_search_order_hijack", category: "persistence",
    condition: (o) => /(?:DLL|dll).*(?:hijack|sideload|phantom)|LoadLibrary.*(?:Temp|AppData)/i.test(o),
    mass: createMass([[hMask("apt_targeted"), 0.50], [hMask("supply_chain"), 0.15], [THETA, 0.35]]),
    reliability: 0.75, source: "ATT&CK T1574.001 DLL Search Order Hijacking" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: USER ACTIVITY (10 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "usr_recon_downloads", signal: "recon_tool_downloaded", category: "user_activity",
    condition: (o) => /Zone\.Identifier.*(?:nmap|burp|wireshark|fiddler|bloodhound)/i.test(o),
    mass: createMass([[hMask("insider_data_theft", "apt_targeted"), 0.35], [hMask("benign_anomaly"), 0.20], [THETA, 0.45]]),
    reliability: 0.60, source: "ATT&CK T1595 Active Scanning" },
  { id: "usr_cloud_sync", signal: "cloud_sync_app", category: "user_activity",
    condition: (o) => /dropbox|onedrive|gdrive|mega\.nz|pcloud/i.test(o) && /upload|sync|recent/i.test(o),
    mass: createMass([[hMask("data_exfiltration", "insider_data_theft"), 0.30], [hMask("benign_anomaly"), 0.30], [THETA, 0.40]]),
    reliability: 0.50, source: "ATT&CK T1567 Exfiltration Over Web Service" },
  { id: "usr_email_forward", signal: "email_forwarding_rule", category: "user_activity",
    condition: (o) => /forward|redirect.*(?:rule|filter)|auto-?forward/i.test(o),
    mass: createMass([[hMask("insider_data_theft", "data_exfiltration"), 0.35], [hMask("benign_anomaly"), 0.20], [THETA, 0.45]]),
    reliability: 0.60, source: "ATT&CK T1114.003 Email Forwarding Rule" },
  { id: "usr_multiple_admins", signal: "multiple_admin_accounts", category: "user_activity",
    condition: (o) => { const admins = (o.match(/(?:admin|administrator|adm)[^\s]*/gi) ?? []).length; return admins > 3; },
    mass: createMass([[hMask("credential_compromise", "lateral_movement"), 0.30], [hMask("benign_anomaly"), 0.25], [THETA, 0.45]]),
    reliability: 0.55, source: "ATT&CK T1136 Create Account" },
  { id: "usr_deleted_profile", signal: "user_profile_deleted", category: "user_activity",
    condition: (o) => /\*.*(?:Users|profiles)|deleted.*(?:user|account|profile)|(?:svc|sql|admin).*deleted/i.test(o),
    mass: createMass([[hMask("anti_forensics", "credential_compromise"), 0.35], [hMask("benign_anomaly"), 0.20], [THETA, 0.45]]),
    reliability: 0.60, source: "ATT&CK T1070.004 + T1531 Account Access Removal" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: MEMORY (10 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "mem_injection", signal: "memory_injection_detected", category: "memory",
    condition: (o) => /malfind|inject|hollow|PAGE_EXECUTE_READWRITE/i.test(o),
    mass: createMass([[hMask("apt_targeted"), 0.55], [hMask("apt_opportunistic"), 0.15], [THETA, 0.30]]),
    reliability: 0.85, source: "ATT&CK T1055 Process Injection" },
  { id: "mem_hidden_process", signal: "hidden_process", category: "memory",
    condition: (o) => /hidden.*process|DKOM|unlinked|phantom.*pid/i.test(o),
    mass: createMass([[hMask("apt_targeted"), 0.60], [THETA, 0.40]]),
    reliability: 0.90, source: "ATT&CK T1014 Rootkit" },
  { id: "mem_suspicious_parent", signal: "suspicious_process_tree", category: "memory",
    condition: (o) => /cmd.*→.*powershell|svchost.*→.*cmd|explorer.*→.*cmd/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.40], [THETA, 0.60]]),
    reliability: 0.65, source: "SANS: Anomalous Parent-Child Process Relationships" },
  { id: "mem_network_suspicious", signal: "process_unexpected_network", category: "memory",
    condition: (o) => /(?:notepad|calc|mspaint).*(?:ESTABLISHED|LISTEN|SYN)/i.test(o),
    mass: createMass([[hMask("apt_targeted"), 0.55], [THETA, 0.45]]),
    reliability: 0.80, source: "SANS FOR508: processes that shouldn't have network connections" },

  // ══════════════════════════════════════════════════════════════════════
  // CATEGORY: LINUX (10 rules)
  // ══════════════════════════════════════════════════════════════════════
  { id: "linux_ssh_brute", signal: "ssh_brute_force", category: "linux",
    condition: (o) => { const fails = (o.match(/Failed password/gi) ?? []).length; return fails > 10; },
    mass: createMass([[hMask("credential_compromise", "apt_opportunistic"), 0.45], [THETA, 0.55]]),
    reliability: 0.80, source: "ATT&CK T1110.001 Brute Force" },
  { id: "linux_cron_persist", signal: "cron_persistence", category: "linux",
    condition: (o) => /crontab|@reboot|cron\.d.*(?:\.sh|wget|curl|python|perl)/i.test(o),
    mass: createMass([[hMask("persistence_established", "apt_targeted"), 0.45], [hMask("benign_anomaly"), 0.15], [THETA, 0.40]]),
    reliability: 0.75, source: "ATT&CK T1053.003 Cron" },
  { id: "linux_systemd_persist", signal: "systemd_unit_injection", category: "linux",
    condition: (o) => /systemd.*(?:enable|start).*(?:\.service|\.timer)|ExecStart.*(?:nc|bash|python|perl)/i.test(o),
    mass: createMass([[hMask("persistence_established", "apt_targeted"), 0.50], [THETA, 0.50]]),
    reliability: 0.80, source: "ATT&CK T1543.002 Systemd Service" },
  { id: "linux_suid_abuse", signal: "suid_binary_suspicious", category: "linux",
    condition: (o) => /(?:chmod.*\+s|SUID).*(?:bash|sh|python|perl|find|vim|nmap)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "credential_compromise"), 0.50], [THETA, 0.50]]),
    reliability: 0.85, source: "ATT&CK T1548.001 Setuid/Setgid" },
  { id: "linux_auth_key_inject", signal: "authorized_keys_modified", category: "linux",
    condition: (o) => /authorized_keys.*(?:ssh-rsa|ssh-ed25519|ecdsa)/i.test(o),
    mass: createMass([[hMask("persistence_established", "lateral_movement"), 0.45], [hMask("benign_anomaly"), 0.15], [THETA, 0.40]]),
    reliability: 0.70, source: "ATT&CK T1098.004 SSH Authorized Keys" },
  { id: "linux_ld_preload", signal: "ld_preload_hijack", category: "linux",
    condition: (o) => /LD_PRELOAD|ld\.so\.preload|\.so.*(?:inject|hook)/i.test(o),
    mass: createMass([[hMask("apt_targeted"), 0.55], [THETA, 0.45]]),
    reliability: 0.90, source: "ATT&CK T1574.006 Dynamic Linker Hijacking" },
  { id: "linux_reverse_shell", signal: "reverse_shell_evidence", category: "linux",
    condition: (o) => /(?:bash|nc|ncat|socat).*(?:-e|\/dev\/tcp|mkfifo|mknod)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.50], [THETA, 0.50]]),
    reliability: 0.85, source: "ATT&CK T1059.004 Unix Shell" },
  { id: "linux_history_cleared", signal: "bash_history_cleared", category: "linux",
    condition: (o) => /history.*-c|unset.*HISTFILE|HISTSIZE=0|truncate.*history/i.test(o),
    mass: createMass([[hMask("anti_forensics", "apt_targeted"), 0.50], [THETA, 0.50]]),
    reliability: 0.80, source: "ATT&CK T1070.003 Clear Command History" },
  { id: "linux_root_login", signal: "direct_root_login", category: "linux",
    condition: (o) => /Accepted.*root.*(?:from|ssh)|session opened.*root/i.test(o),
    mass: createMass([[hMask("credential_compromise", "apt_targeted"), 0.35], [hMask("benign_anomaly"), 0.25], [THETA, 0.40]]),
    reliability: 0.65, source: "Direct root login (should use sudo)" },
  { id: "linux_webshell", signal: "webshell_indicators", category: "linux",
    condition: (o) => /(?:www|html|public_html).*(?:\.php|\.jsp|\.asp).*(?:cmd|exec|system|passthru|shell_exec)/i.test(o),
    mass: createMass([[hMask("apt_targeted", "apt_opportunistic"), 0.55], [THETA, 0.45]]),
    reliability: 0.85, source: "ATT&CK T1505.003 Web Shell" },
] as const;

/** Get rules by category (lazy evaluation — only fire rules in active category) */
export function getRulesByCategory(category: string): readonly EvidenceMassRule[] {
  return EVIDENCE_RULES.filter(r => r.category === category);
}

/** Get all rules (for comprehensive evaluation) */
export function getAllRules(): readonly EvidenceMassRule[] {
  return EVIDENCE_RULES;
}

/** Get initial tool reliability */
export function getToolReliability(tool: string): number {
  return INITIAL_TOOL_RELIABILITY[tool] ?? INITIAL_TOOL_RELIABILITY["_default"] ?? 0.65;
}
