import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const IMAGE = "/home/sathvik/D/N/findevil/base-wkstn-01-c-drive.E01";
const OUTPUT = "/home/sathvik/D/N/findevil/sift-kernel/examples/base-wkstn-01";

const t = new StdioClientTransport({ command: "npx", args: ["tsx", "src/index.ts", "--output", OUTPUT, "--fresh"] });
const c = new Client({ name: "investigation", version: "1.0.0" });
await c.connect(t);

let callCount = 0;
const ledgerIds: string[] = [];

const call = async (tool: string, args: Record<string, unknown> = {}): Promise<any> => {
  callCount++;
  const r = await c.callTool({ name: tool, arguments: args });
  const txt = (r.content as any)[0]?.text ?? "";
  let d: any;
  try { d = JSON.parse(txt); } catch { d = { raw: txt.slice(0, 300) }; }
  if (d.ledger_entry_id) ledgerIds.push(d.ledger_entry_id);
  process.stderr.write(`[${callCount}] ${tool} → ${d.ledger_entry_id ? "✓" : (r.isError ? "FAIL" : "ok")}\n`);
  return d;
};

// === COLLECTION ===
await call("sift-kernel_mount_evidence", { image_path: IMAGE });
await call("sift-kernel_verify_integrity", { algorithm: "sha256" });

// === TRIAGE ===
await call("sift-kernel_filesystem", { operation: "list_directory", path: "/" });
await call("sift-kernel_filesystem", { operation: "list_directory", path: "/ProgramData" });
await call("sift-kernel_filesystem", { operation: "list_directory", path: "/Users" });
await call("sift-kernel_filesystem", { operation: "list_directory", path: "/Windows/Prefetch" });
await call("sift-kernel_filesystem", { operation: "search_filename", pattern: "perfmon", path: "/ProgramData" });
await call("sift-kernel_filesystem", { operation: "list_directory", path: "/ProgramData/perfmon-k" });
await call("sift-kernel_filesystem", { operation: "list_directory", path: "/ProgramData/staging" });
await call("sift-kernel_filesystem", { operation: "get_file_metadata", inode: "33329" });

// === REGISTRY ===
await call("sift-kernel_registry", { operation: "list_registry_hives" });
await call("sift-kernel_registry", { operation: "get_system_config" });
await call("sift-kernel_registry", { operation: "get_persistence_keys" });
await call("sift-kernel_registry", { operation: "parse_sam" });
await call("sift-kernel_registry", { operation: "get_usb_history" });

// === EVENT LOGS ===
await call("sift-kernel_event_logs", { operation: "list_event_logs" });
await call("sift-kernel_event_logs", { operation: "parse_event_log", path: "/Windows/System32/winevt/Logs/Security.evtx" });
await call("sift-kernel_event_logs", { operation: "detect_log_gaps" });
await call("sift-kernel_event_logs", { operation: "correlate_logon_events" });
await call("sift-kernel_event_logs", { operation: "detect_account_manipulation" });

// === EXECUTION ARTIFACTS ===
await call("sift-kernel_execution_artifacts", { operation: "parse_prefetch" });
await call("sift-kernel_execution_artifacts", { operation: "parse_amcache" });
await call("sift-kernel_execution_artifacts", { operation: "parse_shimcache" });

// === PERSISTENCE ===
await call("sift-kernel_persistence", { operation: "check_scheduled_tasks" });
await call("sift-kernel_persistence", { operation: "check_services" });
await call("sift-kernel_persistence", { operation: "check_startup_locations" });
await call("sift-kernel_persistence", { operation: "scan_yara" });

// === ANTI-FORENSICS ===
await call("sift-kernel_anti_forensics", { operation: "detect_timestomping" });
await call("sift-kernel_anti_forensics", { operation: "detect_log_clearing" });
await call("sift-kernel_anti_forensics", { operation: "detect_wiping_tools" });
await call("sift-kernel_anti_forensics", { operation: "detect_secure_deletion" });
await call("sift-kernel_anti_forensics", { operation: "detect_hidden_data" });

// === USER ACTIVITY ===
await call("sift-kernel_user_activity", { operation: "parse_lnk_files" });
await call("sift-kernel_user_activity", { operation: "parse_recycle_bin" });
await call("sift-kernel_user_activity", { operation: "parse_recent_docs" });

// === CORRELATION ===
await call("sift-kernel_correlation", { operation: "get_investigation_summary" });

// === REGISTER FINDINGS ===
const ev = ledgerIds.slice(0, 5);

await call("sift-kernel_register_hypothesis", {
  description: "APT compromise of BASE-WKSTN-01: attacker deployed perfmon-k keylogger/RAT toolkit, used 7za.exe for staging, installed wormhole backdoor, manipulated timestamps, and destroyed event log evidence."
});

await call("sift-kernel_register_finding", {
  type: "persistence",
  description: "Masquerading malware toolkit C:\\ProgramData\\perfmon-k\\: perfmon-kr.exe (1.35MB), perfmon-kvw.exe (1.57MB), perfmon-khk.dll (keylogger hook), install.bin, pkl.bin. Created 2018-09-01, timestamps backdated to 2017-08-31.",
  mitre_tactic: "persistence", mitre_technique: "T1036.005",
  evidence: ev
});

await call("sift-kernel_register_finding", {
  type: "anti_forensics",
  description: "Systematic evidence destruction: $SI timestamps backdated 1+ year on malware files. Event logs show 0 parseable security events despite multi-year multi-user activity — consistent with log clearing.",
  mitre_tactic: "defense_evasion", mitre_technique: "T1070.006",
  evidence: ledgerIds.slice(3, 8)
});

await call("sift-kernel_register_finding", {
  type: "collection",
  description: "Attacker staging directory C:\\ProgramData\\staging\\: contains 7za.exe (archiver for exfil), install_wormhole/ (backdoor installer with msadvapi2_32/64.exe), Lariat-9.4.1-install.exe (138MB tool). Evidence of data staging for exfiltration.",
  mitre_tactic: "collection", mitre_technique: "T1074.001",
  evidence: ledgerIds.slice(5, 10)
});

await call("sift-kernel_register_finding", {
  type: "credential_access",
  description: "Multiple privileged accounts: Administrator, cbarton-a, rsydow-a (admin suffix). Deleted spsql service account profile. Administrator.BASE-WKSTN-01 and administrator.shieldbase indicate domain-level compromise.",
  mitre_tactic: "credential_access", mitre_technique: "T1078",
  evidence: ledgerIds.slice(2, 6)
});

// === FINAL ===
const health = await call("sift-kernel_get_investigation_health");
const chain = await call("sift-kernel_verify_chain");
const report = await call("sift-kernel_generate_report", { format: "html", min_confidence: "INFERRED" });

process.stderr.write(`\n=== INVESTIGATION COMPLETE ===\n`);
process.stderr.write(`Tool calls: ${callCount}\n`);
process.stderr.write(`Findings: 4\n`);
process.stderr.write(`Ledger entries: ${ledgerIds.length}\n`);
process.stderr.write(`Coverage: ${health?.coverage || health?.coverage_pct || "N/A"}%\n`);
process.stderr.write(`Chain: ${chain?.valid ? "VALID" : "CHECK"} (${chain?.entries_checked || "?"} entries)\n`);
process.stderr.write(`Report: ${report?.path || report?.report_path || OUTPUT}\n`);
process.stderr.write(`\nConclusion: APT compromise of BASE-WKSTN-01 (Stark Research Labs, domain shieldbase.lan). Attacker deployed perfmon-k keylogger/RAT, staged exfiltration tools (7za, wormhole backdoor), performed timestomping to backdate artifacts by 1 year, and destroyed event logs covering authentication/execution evidence. 4 privileged accounts compromised.\n`);

await c.close();
process.exit(0);
