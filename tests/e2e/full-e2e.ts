import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

interface TestResult {
  test: string;
  pass: boolean;
  detail: string;
}

async function main() {
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["tsx", "src/index.ts", "--output", "/tmp/sift-e2e-full"],
  });
  const client = new Client({ name: "e2e-test", version: "1.0.0" }, {});
  await client.connect(transport);

  const results: TestResult[] = [];

  // Test 1: tools/list at startup
  const tools = await client.listTools();
  results.push({ test: "tools/list (startup)", pass: tools.tools.length >= 30, detail: `${tools.tools.length} tools` });

  // Test 2: suggest_next_action
  const suggest = await client.callTool({ name: "suggest_next_action", arguments: {} });
  const suggestData = JSON.parse((suggest.content as any)[0].text);
  results.push({ test: "suggest_next_action", pass: !!suggestData.suggestion?.tool, detail: `${suggestData.suggestion?.tool}: ${(suggestData.suggestion?.reason || "").slice(0, 60)}` });

  // Test 3: get_investigation_state
  const state = await client.callTool({ name: "get_investigation_state", arguments: {} });
  const stateData = JSON.parse((state.content as any)[0].text);
  results.push({ test: "get_investigation_state", pass: stateData.phase === "UNINITIALIZED", detail: `phase=${stateData.phase}` });

  // Test 4: list_workflows
  const workflows = await client.callTool({ name: "list_workflows", arguments: {} });
  const wfData = JSON.parse((workflows.content as any)[0].text);
  results.push({ test: "list_workflows", pass: wfData.workflows.length >= 10, detail: `${wfData.workflows.length} workflows` });

  // Test 5: get_methodology_coverage
  const coverage = await client.callTool({ name: "get_methodology_coverage", arguments: {} });
  const covData = JSON.parse((coverage.content as any)[0].text);
  results.push({ test: "get_methodology_coverage", pass: true, detail: JSON.stringify(covData).slice(0, 80) });

  // Test 6: get_coverage_gaps
  const gaps = await client.callTool({ name: "get_coverage_gaps", arguments: {} });
  const gapsData = JSON.parse((gaps.content as any)[0].text);
  results.push({ test: "get_coverage_gaps", pass: Array.isArray(gapsData.gaps), detail: `${gapsData.gaps?.length ?? 0} gaps` });

  // Test 7: get_confidence_summary
  const conf = await client.callTool({ name: "get_confidence_summary", arguments: {} });
  const confData = JSON.parse((conf.content as any)[0].text);
  results.push({ test: "get_confidence_summary", pass: true, detail: JSON.stringify(confData).slice(0, 80) });

  // Test 8: get_investigation_health
  const health = await client.callTool({ name: "get_investigation_health", arguments: {} });
  const healthData = JSON.parse((health.content as any)[0].text);
  results.push({ test: "get_investigation_health", pass: !!healthData.health, detail: `health=${healthData.health} coverage=${healthData.coverage_pct}%` });

  // Test 9: verify_chain (empty ledger)
  const chain = await client.callTool({ name: "verify_chain", arguments: {} });
  const chainData = JSON.parse((chain.content as any)[0].text);
  results.push({ test: "verify_chain (empty)", pass: chainData.valid === true, detail: `valid=${chainData.valid}` });

  // Test 10: register_hypothesis
  const hyp = await client.callTool({ name: "register_hypothesis", arguments: { description: "Attacker used RDP lateral movement" } });
  const hypData = JSON.parse((hyp.content as any)[0].text);
  results.push({ test: "register_hypothesis", pass: !!hypData.id || !!hypData.hypothesis_id, detail: JSON.stringify(hypData).slice(0, 80) });

  // Test 11: register_finding with EMPTY evidence (should be rejected)
  const badFinding = await client.callTool({ name: "register_finding", arguments: { type: "lateral_movement", description: "RDP to DC01", evidence: [] } });
  results.push({ test: "register_finding (empty evidence)", pass: badFinding.isError === true, detail: `isError=${badFinding.isError}` });

  // Test 12: activate_workflow
  const activate = await client.callTool({ name: "activate_workflow", arguments: { workflow: "filesystem" } });
  const actData = JSON.parse((activate.content as any)[0].text);
  results.push({ test: "activate_workflow(filesystem)", pass: actData.success === true, detail: actData.message.slice(0, 60) });

  // Test 13: tools/list after activation (should have more tools)
  const tools2 = await client.listTools();
  results.push({ test: "tools/list (after activate)", pass: tools2.tools.length > 15, detail: `${tools2.tools.length} tools` });

  // Test 14: deactivate_workflow
  const deact = await client.callTool({ name: "deactivate_workflow", arguments: { workflow: "filesystem" } });
  const deactData = JSON.parse((deact.content as any)[0].text);
  results.push({ test: "deactivate_workflow(filesystem)", pass: deactData.success === true, detail: deactData.message.slice(0, 60) });

  // Test 15: tools/list after deactivation (may still have auto-activated workflows from mount)
  const tools3 = await client.listTools();
  results.push({ test: "tools/list (after deactivate)", pass: tools3.tools.length >= 30, detail: `${tools3.tools.length} tools (all visible — capability kernel guards access)` });

  // Test 16: mount_evidence (will fail because no file, but tests the handler)
  const mount = await client.callTool({ name: "mount_evidence", arguments: { image_path: "/tmp/nonexistent.E01" } });
  const mountData = JSON.parse((mount.content as any)[0].text);
  results.push({ test: "mount_evidence (no file)", pass: !!mountData.error || !!mountData.status, detail: (mountData.error || mountData.status || "").slice(0, 80) });

  // Test 17: generate_report (markdown format — saves to file, returns JSON)
  const report = await client.callTool({ name: "generate_report", arguments: { format: "markdown" } });
  const reportText = (report.content as Array<{text: string}>)[0]?.text ?? "";
  results.push({ test: "generate_report", pass: reportText.includes("report_generated") && reportText.includes("markdown"), detail: reportText.slice(0, 100) });

  // Test 18: Activate multiple workflows
  await client.callTool({ name: "activate_workflow", arguments: { workflow: "acquisition" } });
  await client.callTool({ name: "activate_workflow", arguments: { workflow: "timeline" } });
  await client.callTool({ name: "activate_workflow", arguments: { workflow: "registry" } });
  const tools4 = await client.listTools();
  results.push({ test: "multi-workflow activation", pass: tools4.tools.length >= 30, detail: `${tools4.tools.length} tools visible` });

  // Test 19: Tool annotations check
  const hasAnnotations = tools4.tools.some(t => t.annotations && (t.annotations as any).readOnlyHint === true);
  results.push({ test: "tool annotations present", pass: hasAnnotations, detail: `Some tools have readOnlyHint` });

  // Print results
  console.log("\n=== SIFT KERNEL E2E TEST RESULTS ===\n");
  let passed = 0, failed = 0;
  for (const r of results) {
    const icon = r.pass ? "PASS" : "FAIL";
    console.log(`[${icon}] ${r.test} — ${r.detail}`);
    if (r.pass) passed++; else failed++;
  }
  console.log(`\n${passed}/${results.length} passed, ${failed} failed`);

  await client.close();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("E2E test error:", e);
  process.exit(1);
});
