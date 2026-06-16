/**
 * Integration test: HTTP Transport with Bearer Authentication
 * Validates Zero Trust fail-closed authentication + full MCP protocol over HTTP.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { strict as assert } from "node:assert";

const PORT = 3099;
const TOKEN = "test-integration-secret-2026";
let server: ChildProcess;

async function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

async function mcpRequest(method: string, params: Record<string, unknown> = {}, token?: string): Promise<Response> {
  return fetch(`http://localhost:${PORT}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      ...(token ? { "Authorization": `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

async function run(): Promise<void> {
  const results: { name: string; pass: boolean; detail?: string }[] = [];

  // Start HTTP server
  server = spawn("npx", ["tsx", "src/index.ts", "--transport", "http", "--port", String(PORT), "--token", TOKEN, "--fresh", "--output", "/tmp/sift-http-integration"], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
  });
  await sleep(3000);

  // Test 1: No auth → 401
  try {
    const res = await mcpRequest("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "1" } });
    results.push({ name: "No auth → 401", pass: res.status === 401 });
  } catch (e) { results.push({ name: "No auth → 401", pass: false, detail: String(e) }); }

  // Test 2: Wrong token → 401
  try {
    const res = await mcpRequest("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "1" } }, "wrong-token");
    results.push({ name: "Wrong token → 401", pass: res.status === 401 });
  } catch (e) { results.push({ name: "Wrong token → 401", pass: false, detail: String(e) }); }

  // Test 3: Correct token → 200 (SSE response)
  try {
    const res = await mcpRequest("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "t", version: "1" } }, TOKEN);
    results.push({ name: "Correct token → 200/202", pass: res.status === 200 || res.status === 202 });
  } catch (e) { results.push({ name: "Correct token → 200/202", pass: false, detail: String(e) }); }

  // Test 4: Wrong endpoint → 404
  try {
    const res = await fetch(`http://localhost:${PORT}/wrong`, { method: "POST", headers: { "Authorization": `Bearer ${TOKEN}` } });
    results.push({ name: "Wrong endpoint → 404", pass: res.status === 404 });
  } catch (e) { results.push({ name: "Wrong endpoint → 404", pass: false, detail: String(e) }); }

  // Test 5: OPTIONS (CORS preflight) → 204
  try {
    const res = await fetch(`http://localhost:${PORT}/mcp`, { method: "OPTIONS" });
    results.push({ name: "CORS preflight → 204", pass: res.status === 204 });
  } catch (e) { results.push({ name: "CORS preflight → 204", pass: false, detail: String(e) }); }

  // Print results
  let passed = 0;
  for (const r of results) {
    const status = r.pass ? "[PASS]" : "[FAIL]";
    console.log(`${status} ${r.name}${r.detail ? " — " + r.detail : ""}`);
    if (r.pass) passed++;
  }
  console.log(`\n${passed}/${results.length} passed`);

  // Cleanup
  server.kill();
  process.exit(passed === results.length ? 0 : 1);
}

run().catch(e => { console.error(e); server?.kill(); process.exit(1); });
