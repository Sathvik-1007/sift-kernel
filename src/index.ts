#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createSiftKernelServer } from "./server.js";
import { join } from "node:path";
import { mkdirSync, rmSync, existsSync } from "node:fs";

// ─── CLI Argument Parsing ────────────────────────────────────────────────────

function parseArgs(): { evidencePath: string | undefined; memoryPath: string | undefined; outputPath: string; verbose: boolean; fresh: boolean; sudo: boolean; allTools: boolean; transport: "stdio" | "http"; port: number; token: string } {
  const args = process.argv.slice(2);
  let evidencePath: string | undefined;
  let memoryPath: string | undefined;
  let outputPath = join(process.cwd(), "sift-output");
  let verbose = false;
  let fresh = false;
  let sudo = false;
  let allTools = false;
  let transport: "stdio" | "http" = "stdio";
  let port = 3000;
  let token = "";

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--evidence":
        evidencePath = args[++i];
        break;
      case "--memory":
        memoryPath = args[++i];
        break;
      case "--output":
        outputPath = args[++i] ?? outputPath;
        break;
      case "--verbose":
        verbose = true;
        break;
      case "--fresh":
        fresh = true;
        break;
      case "--sudo":
        sudo = true;
        break;
      case "--all-tools":
        allTools = true;
        break;
      case "--transport":
        transport = args[++i] as "stdio" | "http";
        break;
      case "--port":
        port = parseInt(args[++i] ?? "3000", 10);
        break;
      case "--token":
        token = args[++i] ?? "";
        break;
      case "--version":
        console.log("sift-kernel 0.1.0");
        process.exit(0);
        break;
      case "--help":
        printHelp();
        process.exit(0);
        break;
    }
  }

  return { evidencePath, memoryPath, outputPath, verbose, fresh, sudo, allTools, transport, port, token };
}

function printHelp(): void {
  console.log(`
sift-kernel — Forensic Evidence Operating System (MCP Server)

Usage: sift-kernel [options]

Options:
  --evidence <path>   Path to forensic disk image (E01/raw/dd/VMDK/AFF4)
  --memory <path>     Path to memory dump (optional)
  --output <path>     Output directory (default: ./sift-output)
  --fresh             Start a clean investigation (wipes prior state)
  --transport <type>  Transport: stdio (default) or http
  --port <number>     HTTP port (default: 3000, requires --transport http)
  --token <secret>    Bearer token for HTTP auth (required with --transport http)
  --sudo              Use sudo for forensic tool execution
  --verbose           Enable verbose logging
  --version           Show version
  --help              Show this help

Example:
  npx sift-kernel --evidence /cases/001/disk.E01 --memory /cases/001/memory.raw
  npx sift-kernel --fresh --evidence /evidence/image.dd --output /tmp/investigation
  npx sift-kernel --transport http --port 3000 --token my-secret-token
`);
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { evidencePath, memoryPath, outputPath, verbose, fresh, sudo, allTools, transport, port, token } = parseArgs();

  // Fresh start: wipe prior investigation state
  if (fresh && existsSync(outputPath)) {
    rmSync(outputPath, { recursive: true, force: true });
    if (verbose) console.error("[sift-kernel] Fresh start: cleared prior state");
  }

  mkdirSync(outputPath, { recursive: true });
  const dbPath = join(outputPath, "ledger.db");

  const config = {
    evidencePath: evidencePath ?? "",
    memoryPath,
    outputPath,
    dbPath,
    sudo,
    allTools,
  };

  if (transport === "http") {
    if (!token) {
      console.error("[sift-kernel] ERROR: --token is required with --transport http (Zero Trust: fail-closed auth)");
      process.exit(1);
    }
    const { startHttpServer } = await import("./http-transport.js");
    startHttpServer({ port, token, config });
  } else {
    const server = createSiftKernelServer(config);
    const stdioTransport = new StdioServerTransport();
    await server.connect(stdioTransport);
  }

  if (verbose) {
    console.error(`[sift-kernel] Server started (${transport})`);
    console.error(`[sift-kernel] Output directory: ${outputPath}`);
    console.error(`[sift-kernel] Ledger database: ${dbPath}`);
    if (evidencePath) console.error(`[sift-kernel] Evidence: ${evidencePath}`);
    if (memoryPath) console.error(`[sift-kernel] Memory: ${memoryPath}`);
  }
}

main().catch((error) => {
  console.error("[sift-kernel] Fatal error:", error);
  process.exit(1);
});
