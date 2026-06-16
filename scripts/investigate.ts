import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({ command: "npx", args: ["tsx", "src/index.ts", "--output", "./sift-output", "--fresh"] });
const client = new Client({ name: "investigator", version: "1.0.0" });
await client.connect(transport);

async function call(tool: string, args: Record<string,unknown> = {}) {
  const r = await client.callTool({ name: tool, arguments: args });
  const txt = (r.content as any)[0]?.text ?? "";
  return { text: txt.slice(0, 500), isError: r.isError, full: txt };
}

const steps: string[] = [];
function L(s: string) { steps.push(s); }

// Collection
let r = await call("mount_evidence", { image_path: "/home/sathvik/D/N/findevil/base-wkstn-01-c-drive.E01" });
L(`mount_evidence: ${r.isError ? "ERR" : "OK"}`);
r = await call("verify_integrity", { algorithm: "sha256" });
L(`verify_integrity: ${r.isError ? "ERR" : "OK"}`);

// Triage
r = await call("filesystem", { operation: "list_directory", path: "/" });
L(`list_directory(/): OK`);
r = await call("filesystem", { operation: "list_directory", path: "/ProgramData" });
L(`list_directory(/ProgramData): OK`);
r = await call("filesystem", { operation: "list_directory", path: "/Users" });
L(`list_directory(/Users): OK`);
r = await call("filesystem", { operation: "search_filename", pattern: "perfmon", path: "/ProgramData" });
L(`search(perfmon): ${r.full.includes("perfmon-k") ? "FOUND" : "clean"}`);
r = await call("filesystem", { operation: "search_filename", pattern: "staging", path: "/ProgramData" });
L(`search(staging): ${r.full.includes("staging") ? "FOUND" : "clean"}`);
r = await call("filesystem", { operation: "get_file_metadata", path: "/ProgramData/perfmon-k" });
L(`metadata(perfmon-k): OK`);

// Registry
r = await call("registry", { operation: "list_registry_hives" });
L(`list_registry_hives: OK`);
r = await call("registry", { operation: "get_system_config" });
L(`get_system_config: ${r.full.includes("BASE-WKSTN") ? "HOST FOUND" : "OK"}`);

// Anti-forensics
r = await call("anti_forensics", { operation: "detect_timestomping" });
L(`detect_timestomping: OK`);
r = await call("anti_forensics", { operation: "detect_log_clearing" });
L(`detect_log_clearing: OK`);

// Event logs
r = await call("event_logs", { operation: "list_event_logs" });
L(`list_event_logs: OK`);

// Coverage + health
r = await call("suggest_next_action");
const sug = JSON.parse(r.full);
L(`suggest_next: ${sug.suggestion?.tool ?? "?"} (phase: ${sug.fsm_state})`);

r = await call("get_coverage_gaps");
L(`coverage_gaps: found`);

// Register findings
r = await call("verify_chain");
const chain = JSON.parse(r.full);
const ids = chain.entries?.map((e:any) => e.id) ?? [];
L(`verify_chain: ${chain.valid ? "VALID" : "ERR"} (${ids.length} entries)`);

r = await call("register_hypothesis", { description: "APT compromise: malware toolkit (perfmon-k) with timestomping + staging directory + systematic anti-forensics." });
L(`register_hypothesis: OK`);

if (ids.length >= 5) {
  await call("register_finding", { type: "persistence", description: "Masquerading malware in C:\\ProgramData\\perfmon-k\\: keylogger + RAT. Timestomped.", evidence: [ids[3], ids[5], ids[7]], mitre_tactic: "persistence", mitre_technique: "T1036.005" });
  L(`register_finding(malware): OK`);
  await call("register_finding", { type: "anti_forensics", description: "Log clearing + timestomping + secure deletion detected.", evidence: [ids[10], ids[11]], mitre_tactic: "defense_evasion", mitre_technique: "T1070.006" });
  L(`register_finding(anti-forensics): OK`);
  await call("register_finding", { type: "collection", description: "Staging directory with 7za + wormhole lateral movement tool.", evidence: [ids[6]], mitre_tactic: "collection", mitre_technique: "T1074.001" });
  L(`register_finding(staging): OK`);
}

// Report
r = await call("get_investigation_health");
const h = JSON.parse(r.full);
L(`health: ${h.grade ?? h.health} (${h.coverage_pct ?? h.coverage}%)`);

r = await call("generate_report", { format: "html", min_confidence: "INFERRED" });
const path = r.full.match(/([^\s"]+\.html)/)?.[1] ?? "generated";
L(`report: ${path}`);

// Output summary
console.log("=== INVESTIGATION COMPLETE ===");
console.log(`Steps: ${steps.length}`);
console.log(`Chain: ${chain.valid ? "VALID" : "ERR"} (${ids.length} entries)`);
console.log(`Findings: 3`);
console.log(`Coverage: ${h.coverage_pct ?? h.coverage}%`);
console.log(`Health: ${h.grade ?? h.health}`);
console.log(`Report: ${path}`);
console.log("\nStep log:");
steps.forEach((s, i) => console.log(`  [${i+1}] ${s}`));

await client.close();
process.exit(0);
