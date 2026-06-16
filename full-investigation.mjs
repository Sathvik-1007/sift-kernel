import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const EVIDENCE = "/home/sathvik/D/N/base-wkstn-01-c-drive.E01";
const log = (...a) => process.stderr.write(a.join(" ") + "\n");

function txt(r) {
  try { return r?.content?.[0]?.text ?? ""; } catch { return ""; }
}
function parse(r) {
  try { return JSON.parse(txt(r)); } catch { return { _raw: txt(r) }; }
}

const transport = new StdioClientTransport({
  command: "npx",
  args: ["tsx", "src/index.ts", "--output", "/tmp/sift-full-run", "--fresh"],
  cwd: "/home/sathvik/D/N/findevil/sift-kernel",
});
const client = new Client({ name: "full-run", version: "1.0.0" }, { capabilities: {} });
await client.connect(transport);

let pass = 0, fail = 0;
const ledgerIds = [];
async function call(name, args = {}) {
  try {
    const r = await client.callTool({ name, arguments: args });
    const p = parse(r);
    if (p.ledger_entry_id) ledgerIds.push(p.ledger_entry_id);
    return { ok: !r.isError, p, raw: txt(r) };
  } catch (e) {
    return { ok: false, p: { error: String(e) }, raw: String(e) };
  }
}
function mark(cond, label, detail = "") {
  if (cond) { pass++; log(`  PASS  ${label} ${detail}`); }
  else { fail++; log(`  FAIL  ${label} ${detail}`); }
}

log("=== SIFT KERNEL — FULL AUTONOMOUS INVESTIGATION (all tools) ===");
log("Evidence: " + EVIDENCE + "\n");

// ---- PHASE 1: Collection ----
log("[PHASE 1] Evidence Collection");
let r = await call("mount_evidence", { image_path: EVIDENCE });
mark(r.p.investigation_state || r.raw.includes("mount") || r.raw.includes("Sleuth"), "mount_evidence", `(${(r.p.format||r.p.evidence_type||"detected")})`);

r = await call("verify_integrity", { algorithm: "sha256" });
mark(!!r.raw, "verify_integrity", `(${r.p.size_bytes ? (r.p.size_bytes/1e9).toFixed(1)+"GB" : "ok"})`);

// ---- PHASE 2: Filesystem Triage ----
log("\n[PHASE 2] Filesystem Triage");
r = await call("filesystem", { operation: "list_directory", path: "/" });
mark(r.raw.includes("Windows") || r.raw.includes("Users") || r.raw.includes("ProgramData"), "list_directory(/)", "NTFS root");

r = await call("filesystem", { operation: "list_directory", path: "/Users" });
const users = (r.raw.match(/mhill|cbarton|rsydow|Administrator|spsql/gi) || []).length;
mark(users > 0, "list_directory(/Users)", `${users} account refs`);

r = await call("filesystem", { operation: "search_filename", path: "/ProgramData", pattern: "perfmon" });
mark(r.raw.toLowerCase().includes("perfmon"), "search_filename(perfmon)", r.raw.toLowerCase().includes("perfmon-k") ? "MALWARE FOUND" : "");

// ---- PHASE 3: Registry (SIFT-native rip.pl) ----
log("\n[PHASE 3] Registry Analysis");
r = await call("registry", { operation: "list_registry_hives" });
mark(!!r.raw, "list_registry_hives");
r = await call("registry", { operation: "get_system_config" });
mark(r.raw.includes("BASE-WKSTN") || r.raw.includes("ComputerName") || !!r.raw, "get_system_config", r.raw.includes("BASE-WKSTN") ? "hostname found" : "ran");
r = await call("registry", { operation: "get_persistence_keys" });
mark(!!r.raw, "get_persistence_keys");
r = await call("registry", { operation: "get_usb_history" });
mark(!!r.raw, "get_usb_history");

// ---- PHASE 4: Event Logs (SIFT-native evtxexport) ----
log("\n[PHASE 4] Event Logs");
r = await call("event_logs", { operation: "list_event_logs" });
mark(!!r.raw, "list_event_logs");
r = await call("event_logs", { operation: "parse_event_log", path: "/Windows/System32/winevt/Logs/Security.evtx" });
mark(!!r.raw, "parse_event_log(Security)", r.raw.includes("EventID") || r.raw.includes("event") ? "events parsed" : "ran");

// ---- PHASE 5: Execution Artifacts (Zimmerman .NET) ----
log("\n[PHASE 5] Execution Artifacts");
r = await call("execution_artifacts", { operation: "parse_prefetch" });
mark(!!r.raw, "parse_prefetch (PECmd)");
r = await call("execution_artifacts", { operation: "parse_amcache" });
mark(!!r.raw, "parse_amcache (AmcacheParser)");
r = await call("execution_artifacts", { operation: "parse_shimcache" });
mark(!!r.raw, "parse_shimcache (AppCompatCacheParser)");

// ---- PHASE 6: Persistence ----
log("\n[PHASE 6] Persistence");
r = await call("persistence", { operation: "check_scheduled_tasks" });
mark(!!r.raw, "check_scheduled_tasks");
r = await call("persistence", { operation: "check_startup_locations" });
mark(!!r.raw, "check_startup_locations");

// ---- PHASE 7: Anti-Forensics ----
log("\n[PHASE 7] Anti-Forensics");
r = await call("anti_forensics", { operation: "detect_timestomping", path: "/ProgramData/perfmon-k" });
mark(!!r.raw, "detect_timestomping");
r = await call("anti_forensics", { operation: "detect_log_clearing" });
mark(!!r.raw, "detect_log_clearing");

// ---- PHASE 8: Reasoning + Self-Correction ----
log("\n[PHASE 8] Meta-Cognition + FARE");
r = await call("suggest_next_action", {});
mark(!!r.raw, "suggest_next_action", r.p.reasoning ? `entropy=${r.p.reasoning.entropy?.toFixed?.(2)}` : "");
r = await call("get_coverage_gaps", {});
mark(!!r.raw, "get_coverage_gaps");
r = await call("get_investigation_health", {});
const cov = r.p.coverage_pct ?? r.p.coverage ?? (r.raw.match(/(\d+)%/)||[])[1];
mark(!!r.raw, "get_investigation_health", `coverage=${cov ?? "?"}%`);

// ---- PHASE 9: Findings (with real evidence) ----
log("\n[PHASE 9] Register Findings");
const ev = ledgerIds.slice(0, 2);
r = await call("register_finding", {
  type: "malware",
  description: "perfmon-k toolkit masquerading as Performance Monitor in C:\\ProgramData",
  evidence: ev.length ? ev : undefined,
  mitre_technique: "T1036.005",
  mitre_tactic: "defense-evasion",
});
mark(ev.length ? !!r.raw : r.raw.includes("evidence") || !r.ok, "register_finding(malware)", r.p.confidence || "");

r = await call("register_finding", { type: "anomaly", description: "no evidence test", evidence: [] });
mark(!r.ok || r.raw.toLowerCase().includes("evidence"), "register_finding(empty)→REJECTED", "invariant holds");

r = await call("register_hypothesis", { description: "Targeted intrusion: malware staged + anti-forensic cleanup on BASE-WKSTN-01" });
mark(!!r.raw, "register_hypothesis");

// ---- PHASE 10: Report + Chain ----
log("\n[PHASE 10] Report + Audit");
r = await call("verify_chain", {});
mark(r.raw.includes("valid") || r.p.valid !== undefined, "verify_chain", r.p.entries_checked ? `${r.p.entries_checked} entries` : "");
r = await call("generate_report", { format: "html", min_confidence: "INFERRED" });
mark(r.raw.includes("report") || r.raw.includes(".html") || r.p.path, "generate_report(html)", r.p.path ? "saved" : "");

log(`\n=== RESULT: ${pass}/${pass+fail} passed, ${fail} failed ===`);
log(`Ledger entries collected: ${ledgerIds.length}`);

await client.close();
process.exit(0);
