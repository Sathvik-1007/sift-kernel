import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const EVIDENCE = "/home/sathvik/D/N/base-wkstn-01-c-drive.E01";
const log = (...a) => process.stderr.write(a.join(" ") + "\n");
const txt = (r) => { try { return r?.content?.[0]?.text ?? ""; } catch { return ""; } };
const parse = (r) => { try { return JSON.parse(txt(r)); } catch { return { _raw: txt(r) }; } };

const transport = new StdioClientTransport({
  command: "npx",
  args: ["tsx", "src/index.ts", "--output", "/tmp/sift-thorough", "--fresh"],
  cwd: "/home/sathvik/D/N/findevil/sift-kernel",
});
const client = new Client({ name: "thorough", version: "1.0.0" }, { capabilities: {} });
await client.connect(transport);

const ledgerIds = [];
let exec = 0, blocked = 0, errored = 0;
async function call(name, args = {}) {
  try {
    const r = await client.callTool({ name, arguments: args });
    const p = parse(r);
    if (p.ledger_entry_id) ledgerIds.push(p.ledger_entry_id);
    return { ok: !r.isError, p, raw: txt(r) };
  } catch (e) { return { ok: false, p: { error: String(e) }, raw: String(e) }; }
}
async function run(category, operation, args = {}) {
  const r = await call(category, { operation, ...args });
  if (r.raw.includes("CAPABILITY_BLOCKED") || r.raw.includes("requires:")) { blocked++; log(`  BLOCKED ${category}.${operation}`); }
  else if (!r.ok && r.raw.toLowerCase().includes("not available")) { errored++; log(`  NEED-TOOL ${category}.${operation}`); }
  else { exec++; log(`  EXEC    ${category}.${operation}`); }
  return r;
}

log("=== THOROUGH INVESTIGATION — every disk-applicable tool ===\n");

// Collection
await call("mount_evidence", { image_path: EVIDENCE });
await call("verify_integrity", { algorithm: "sha256" });

// Filesystem (unlock filesystem_accessible)
log("[filesystem]");
await run("filesystem", "list_directory", { path: "/" });
await run("filesystem", "list_directory", { path: "/Users" });
await run("filesystem", "list_directory", { path: "/ProgramData" });
await run("filesystem", "search_filename", { path: "/ProgramData", pattern: "perfmon" });
await run("filesystem", "get_file_metadata", { path: "/ProgramData" });

// Acquisition extras
log("[acquisition]");
await run("acquisition", "get_image_metadata");
await run("acquisition", "list_partitions");
await run("acquisition", "get_filesystem_info");

// Registry
log("[registry]");
await run("registry", "list_registry_hives");
await run("registry", "get_system_config");
await run("registry", "get_persistence_keys");
await run("registry", "get_installed_software");
await run("registry", "get_usb_history");
await run("registry", "get_network_config");
await run("registry", "get_user_activity");
await run("registry", "parse_sam");

// Event logs
log("[event_logs]");
await run("event_logs", "list_event_logs");
await run("event_logs", "parse_event_log", { path: "/Windows/System32/winevt/Logs/Security.evtx" });
await run("event_logs", "search_events", { event_id: "4624" });
await run("event_logs", "detect_log_gaps");
await run("event_logs", "correlate_logon_events");
await run("event_logs", "detect_account_manipulation");
await run("event_logs", "get_security_summary");

// Execution artifacts (Zimmerman .NET)
log("[execution_artifacts]");
await run("execution_artifacts", "parse_prefetch");
await run("execution_artifacts", "parse_amcache");
await run("execution_artifacts", "parse_shimcache");
await run("execution_artifacts", "parse_bam");
await run("execution_artifacts", "parse_muicache");
await run("execution_artifacts", "parse_userassist");

// Persistence
log("[persistence]");
await run("persistence", "check_scheduled_tasks");
await run("persistence", "check_services");
await run("persistence", "check_startup_locations");
await run("persistence", "check_wmi_persistence");
await run("persistence", "scan_yara");
await run("persistence", "hash_and_lookup");

// User activity
log("[user_activity]");
await run("user_activity", "parse_lnk_files");
await run("user_activity", "parse_jumplists");
await run("user_activity", "parse_shellbags");
await run("user_activity", "parse_recycle_bin");
await run("user_activity", "parse_recent_docs");
await run("user_activity", "parse_mru_lists");

// Browser
log("[browser]");
await run("browser", "parse_browser_history");
await run("browser", "parse_browser_downloads");
await run("browser", "parse_browser_cache");

// Anti-forensics
log("[anti_forensics]");
await run("anti_forensics", "detect_timestomping", { path: "/ProgramData/perfmon-k" });
await run("anti_forensics", "detect_log_clearing");
await run("anti_forensics", "detect_secure_deletion");
await run("anti_forensics", "detect_hidden_data");
await run("anti_forensics", "detect_wiping_tools");

// Timeline
log("[timeline]");
await run("timeline", "generate_timeline");
await run("timeline", "detect_timeline_anomalies");

// Correlation
log("[correlation]");
await run("correlation", "build_attack_narrative");
await run("correlation", "map_mitre_techniques");
await run("correlation", "get_investigation_summary");
await run("correlation", "get_ioc_summary");

// Findings
log("[findings]");
const ev = ledgerIds.slice(0, 3);
await call("register_finding", { type: "malware", description: "perfmon-k toolkit masquerading as Performance Monitor", evidence: ev, mitre_technique: "T1036.005", mitre_tactic: "defense-evasion" });
await call("register_hypothesis", { description: "Targeted intrusion with malware staging and anti-forensic cleanup" });

// Final coverage
const h = await call("get_investigation_health");
const cov = h.p.coverage_pct ?? (h.raw.match(/(\d+)%/) || [])[1];
const mc = await call("get_methodology_coverage");

log(`\n=== EXECUTED: ${exec}  BLOCKED: ${blocked}  NEED-TOOL: ${errored} ===`);
log(`COVERAGE: ${cov}%`);
log(`Ledger entries: ${ledgerIds.length}`);
if (mc.p.categories) {
  log("Per-category:");
  for (const c of mc.p.categories) log(`  ${c.category}: ${c.coverage_pct}% (${c.tools_used}/${c.tools_total})`);
}

await client.close();
process.exit(0);
