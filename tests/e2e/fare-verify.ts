import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({ command: "npx", args: ["tsx", "src/index.ts", "--output", "/tmp/fare-out", "--fresh"] });
const client = new Client({ name: "t", version: "1.0.0" });
await client.connect(transport);

async function call(tool: string, args: Record<string, unknown> = {}) {
  const r = await client.callTool({ name: tool, arguments: args });
  const text = (r.content as any)[0]?.text ?? "";
  return text;
}

const results: string[] = [];

// Mount + verify
await call("mount_evidence", { image_path: "/home/sathvik/D/N/base-wkstn-01-c-drive.E01" });
await call("verify_integrity", { algorithm: "sha256" });
results.push("1. mount+verify: OK");

// List root — check for FARE reasoning in response
const ls = await call("filesystem", { operation: "list_directory", path: "/" });
const lsJ = JSON.parse(ls);
const hasReasoning = !!lsJ.reasoning;
const entropy = lsJ.reasoning?.entropy ?? "none";
results.push(`2. list_directory reasoning: ${hasReasoning}, entropy: ${entropy}`);

// Search perfmon — should trigger MALWARE signal
const sr = await call("filesystem", { operation: "search_filename", pattern: "perfmon", path: "/ProgramData" });
const srJ = JSON.parse(sr);
const srEntropy = srJ.reasoning?.entropy ?? "none";
const srConv = srJ.reasoning?.convergence ?? "none";
results.push(`3. search_perfmon reasoning: entropy=${srEntropy}, convergence=${srConv}`);

// suggest_next_action — check EFE score
const sug = await call("suggest_next_action");
const sugJ = JSON.parse(sug);
results.push(`4. suggest: efe=${sugJ.efe_score ?? "none"}, gain=${sugJ.information_gain ?? "none"}`);
results.push(`   reasoning_state: ${JSON.stringify(sugJ.reasoning_state ?? {}).slice(0,200)}`);

// coverage
const cov = await call("get_coverage_gaps");
const covJ = JSON.parse(cov);
results.push(`5. coverage: ${covJ.overall_coverage}`);

// health
const h = await call("get_investigation_health");
const hJ = JSON.parse(h);
results.push(`6. health: ${hJ.grade}`);

for (const r of results) console.error(r);

await client.close();
process.exit(0);
