/**
 * Real Evidence Integration Test
 * 
 * Tests the MCP server end-to-end against a REAL forensic disk image.
 * Validates: mount → verify → triage → deep analysis → findings → report
 * 
 * Requires: SIFT_EVIDENCE_PATH env var pointing to an E01/raw disk image
 * Skips gracefully if image not present.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { strict as assert } from "node:assert";

const PROJECT_ROOT = new URL("../../", import.meta.url).pathname.replace(/\/$/, "");
const E01_PATH = process.env["SIFT_EVIDENCE_PATH"] || "";
const NIST_PATH = process.env["SIFT_NIST_PATH"] || "";

async function createClient(): Promise<Client> {
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["tsx", "src/index.ts", "--output", "/tmp/sift-test-evidence", "--fresh"],
    cwd: PROJECT_ROOT,
  });
  const client = new Client({ name: "real-evidence-test", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  return client;
}

async function call(client: Client, tool: string, args: Record<string, unknown> = {}): Promise<any> {
  const r = await client.callTool({ name: tool, arguments: args });
  const text = (r.content as any[])?.[0]?.text ?? "";
  try { return { ...r, data: JSON.parse(text) }; } catch { return { ...r, data: text }; }
}

async function main() {
  // Check if evidence exists
  const fs = await import("node:fs");
  const hasE01 = fs.existsSync(E01_PATH);
  const hasNIST = fs.existsSync(NIST_PATH);

  if (!hasE01 && !hasNIST) {
    console.log("SKIP: No evidence images found. Tests require real forensic data.");
    process.exit(0);
  }

  const imagePath = hasE01 ? E01_PATH : NIST_PATH;
  console.log(`\n=== REAL EVIDENCE INTEGRATION TEST ===`);
  console.log(`Image: ${imagePath}`);
  console.log(`Size: ${(fs.statSync(imagePath).size / (1024*1024*1024)).toFixed(2)} GB\n`);

  const client = await createClient();
  const results: { name: string; pass: boolean; detail: string }[] = [];

  function check(name: string, pass: boolean, detail: string) {
    results.push({ name, pass, detail });
    console.log(`${pass ? "✅" : "❌"} ${name}${detail ? " — " + detail : ""}`);
  }

  try {
    // === Phase 1: Mount & Verify ===
    console.log("\n--- Phase 1: Mount & Verify ---");

    const mount = await call(client, "mount_evidence", { image_path: imagePath });
    check("mount_evidence", !mount.isError, mount.data?.status ?? mount.data?.message ?? "mounted");

    const verify = await call(client, "verify_integrity", { algorithm: "sha256" });
    check("verify_integrity", !verify.isError, verify.data?.format ?? "verified");

    const state = await call(client, "get_investigation_state");
    check("state_after_mount", state.data?.phase === "TRIAGING", `phase=${state.data?.phase}`);

    // === Phase 2: Filesystem Triage ===
    console.log("\n--- Phase 2: Filesystem Triage ---");

    const rootDir = await call(client, "list_directory", { path: "/" });
    check("list_directory(root)", !rootDir.isError, `entries in response`);

    // Parse the root listing to find known directories
    const rootText = typeof rootDir.data === "string" ? rootDir.data : JSON.stringify(rootDir.data);
    const hasUsers = rootText.includes("Users") || rootText.includes("Documents and Settings");
    check("filesystem_has_users", hasUsers, hasUsers ? "Users dir found" : "No Users dir");

    // === Phase 3: Deep Analysis ===
    console.log("\n--- Phase 3: Deep Analysis ---");

    const suggest = await call(client, "suggest_next_action");
    check("suggest_next_action", !suggest.isError && suggest.data?.suggestion, 
      suggest.data?.suggestion?.tool ?? "provides recommendation");

    const gaps = await call(client, "get_coverage_gaps");
    check("get_coverage_gaps", !gaps.isError, 
      `${gaps.data?.gaps?.length ?? 0} gaps identified`);

    const health = await call(client, "get_investigation_health");
    check("investigation_health", !health.isError && health.data?.health, 
      `health=${health.data?.health}`);

    // === Phase 4: Register Findings ===
    console.log("\n--- Phase 4: Register Findings ---");

    // First register a hypothesis
    const hyp = await call(client, "register_hypothesis", { 
      description: "Workstation compromised via lateral movement — attacker tools staged in ProgramData" 
    });
    check("register_hypothesis", !hyp.isError, hyp.data?.hypothesis_id ?? "registered");

    // Try to register a finding with empty evidence (MUST fail)
    const badFinding = await call(client, "register_finding", {
      type: "execution",
      description: "Test finding",
      evidence: []
    });
    check("reject_empty_evidence (critical invariant)", badFinding.isError === true, 
      "Empty evidence correctly rejected");

    // === Phase 5: Methodology Enforcement ===
    console.log("\n--- Phase 5: Methodology Enforcement ---");

    const coverage = await call(client, "get_methodology_coverage");
    check("methodology_coverage", !coverage.isError, "coverage data returned");

    const confidence = await call(client, "get_confidence_summary");
    check("confidence_summary", !confidence.isError, "confidence breakdown returned");

    // === Phase 6: Report & Audit ===
    console.log("\n--- Phase 6: Report & Audit ---");

    const chain = await call(client, "verify_chain");
    check("verify_chain", !chain.isError && chain.data?.valid !== false, 
      `entries=${chain.data?.entry_count ?? 0}, valid=${chain.data?.valid}`);

    const report = await call(client, "generate_report", { min_confidence: "INFERRED" });
    check("generate_report", !report.isError, 
      report.data?.hmac_seal ? "HMAC-sealed narrative" : "report generated");

    // === Phase 7: Progressive Disclosure ===
    console.log("\n--- Phase 7: Progressive Disclosure ---");

    const workflows = await call(client, "list_workflows");
    const wfData = workflows.data;
    const activeCount = typeof wfData === "object" && wfData?.workflows 
      ? wfData.workflows.filter((w: any) => w.active).length : 0;
    check("list_workflows", !workflows.isError, `${activeCount} active workflows`);

    // Activate memory workflow
    const activateMem = await call(client, "activate_workflow", { workflow: "memory" });
    check("activate_workflow(memory)", !activateMem.isError, "memory tools now visible");

    // Deactivate it
    const deactivateMem = await call(client, "deactivate_workflow", { workflow: "memory" });
    check("deactivate_workflow(memory)", !deactivateMem.isError, "memory tools hidden");

    // === Phase 8: Reset ===
    console.log("\n--- Phase 8: Reset ---");

    const reset = await call(client, "reset_investigation");
    check("reset_investigation", !reset.isError, "clean slate");

    const stateAfterReset = await call(client, "get_investigation_state");
    check("state_after_reset", stateAfterReset.data?.phase === "UNINITIALIZED", 
      `phase=${stateAfterReset.data?.phase}`);

  } finally {
    await client.close();
  }

  // === Summary ===
  console.log(`\n=== RESULTS ===`);
  const passed = results.filter(r => r.pass).length;
  const total = results.length;
  console.log(`${passed}/${total} passed`);
  
  const failures = results.filter(r => !r.pass);
  if (failures.length > 0) {
    console.log("\nFAILURES:");
    failures.forEach(f => console.log(`  ❌ ${f.name}: ${f.detail}`));
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
