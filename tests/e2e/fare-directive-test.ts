import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const t = new StdioClientTransport({ command: "npx", args: ["tsx", "src/index.ts", "--output", "/tmp/sift-fare-test", "--fresh"] });
const c = new Client({ name: "test", version: "1.0.0" });
await c.connect(t);

const results: string[] = [];
const check = (name: string, cond: boolean) => { results.push(`${cond ? "✓" : "✗"} ${name}`); };

// Mount + verify
await c.callTool({ name: "mount_evidence", arguments: { image_path: process.env["E01_PATH"] || "/home/sathvik/D/N/base-wkstn-01-c-drive.E01" } });
await c.callTool({ name: "verify_integrity", arguments: { algorithm: "sha256" } });

// suggest_next_action — should have rich directive
const r1 = await c.callTool({ name: "suggest_next_action", arguments: {} });
const d1 = JSON.parse((r1.content as Array<{text:string}>)[0].text);
check("has suggestion", !!d1.suggestion);
check("has directive", !!d1.suggestion?.directive);
check("directive.whatEvilLooksLike present", !!d1.suggestion?.directive?.whatEvilLooksLike);
check("directive.hypothesisTested present", !!d1.suggestion?.directive?.hypothesisTested);
check("directive.confirmationCriteria present", !!d1.suggestion?.directive?.confirmationCriteria);
check("directive.ifConfirmed present", !!d1.suggestion?.directive?.ifConfirmed);
check("directive.ifAbsent present", !!d1.suggestion?.directive?.ifAbsent);
check("has efe_score", typeof d1.suggestion?.efe_score === "number");
check("has reasoning (entropy)", typeof d1.reasoning?.entropy === "number");

// Call filesystem to advance FSM and check directive changes
await c.callTool({ name: "filesystem", arguments: { operation: "list_directory", path: "/" } });
const r2 = await c.callTool({ name: "suggest_next_action", arguments: {} });
const d2 = JSON.parse((r2.content as Array<{text:string}>)[0].text);
check("second suggestion different tool", d1.suggestion?.tool !== d2.suggestion?.tool || d1.suggestion?.operation !== d2.suggestion?.operation);
check("second has directive OR is a non-ontology tool", d2.suggestion?.directive !== undefined || d2.suggestion?.tool !== undefined);

// Verify register_finding deterministic verification
const ledgerIds = [d1.ledger_entry_id, (JSON.parse((r1.content as Array<{text:string}>)[0].text)).ledger_entry_id].filter(Boolean);
// Use any real ledger entry from the mount step
const stateR = await c.callTool({ name: "get_investigation_state", arguments: {} });
const state = JSON.parse((stateR.content as Array<{text:string}>)[0].text);
check("investigation phase advanced past COLLECTION", state.phase !== "COLLECTION");

// Register a finding with real evidence — check verification field
const chainR = await c.callTool({ name: "verify_chain", arguments: {} });
const chain = JSON.parse((chainR.content as Array<{text:string}>)[0].text);
if (chain.entry_count > 0) {
  // Get a real entry ID from the ledger to use as evidence
  const mountEntry = chain.latest_entry_id;
  if (mountEntry) {
    const findR = await c.callTool({ name: "register_finding", arguments: {
      type: "anomaly",
      description: "Suspicious directory perfmon-k found in ProgramData containing executables",
      evidence: [mountEntry],
      mitre_tactic: "Defense Evasion",
      mitre_technique: "T1036.005"
    }});
    const find = JSON.parse((findR.content as Array<{text:string}>)[0].text);
    check("finding has verification field", "verification" in find);
    check("verification is VERIFIED or PARTIAL or UNVERIFIED", ["VERIFIED", "PARTIAL", "UNVERIFIED"].includes(find.verification));
  }
}

await c.close();

const passed = results.filter(r => r.startsWith("✓")).length;
const failed = results.filter(r => r.startsWith("✗")).length;
process.stderr.write(`\n=== FARE DIRECTIVE TEST ===\n${results.join("\n")}\n\nResult: ${passed}/${passed+failed} passed\n`);
process.exit(failed > 0 ? 1 : 0);
