/**
 * HTTP Transport for SIFT Kernel MCP Server
 * Implements StreamableHTTP with bearer token authentication.
 * Zero Trust: fail-closed authentication (reject if no valid token).
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createSiftKernelServer, type ServerConfig } from "./server.js";

export interface HttpTransportOptions {
  port: number;
  token: string;
  config: ServerConfig;
}

export function startHttpServer(options: HttpTransportOptions): void {
  const { port, token, config } = options;

  const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // CORS headers for browser-based MCP clients
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id");
    res.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Zero Trust: fail-closed bearer token authentication
    const authHeader = req.headers["authorization"];
    if (!authHeader || authHeader !== `Bearer ${token}`) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized", message: "Valid Bearer token required" }));
      return;
    }

    // Only handle /mcp endpoint
    if (req.url !== "/mcp") {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not Found", message: "Use POST /mcp" }));
      return;
    }

    // Create transport and server for each session
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => crypto.randomUUID() });
    const server = createSiftKernelServer(config);

    await server.connect(transport as unknown as import("@modelcontextprotocol/sdk/shared/transport.js").Transport);
    await transport.handleRequest(req, res);
  });

  httpServer.listen(port, () => {
    process.stderr.write(`[sift-kernel] HTTP server listening on http://localhost:${port}/mcp\n`);
    process.stderr.write(`[sift-kernel] Authentication: Bearer token required\n`);
  });
}
