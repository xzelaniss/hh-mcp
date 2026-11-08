import http from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { HttpAuth } from "./auth.js";
import { createServer, TOOL_COUNT } from "./server.js";
import { VERSION } from "./version.js";

// --- HTTP body reader (stateless transport needs the parsed body) ---

const MAX_BODY = 4 * 1024 * 1024;

function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("Request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

export function createHttpServer(auth: HttpAuth, env: NodeJS.ProcessEnv = process.env, port = 3000) {
  // DNS-rebinding protection (off by default in the SDK, CVE-2025-66414):
  // only accept requests whose Host header is in this allow-list.
  const allowedHosts = (
    env.HH_ALLOWED_HOSTS ||
    `127.0.0.1:${port},localhost:${port}`
  )
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const allowedOrigins = env.HH_ALLOWED_ORIGINS
    ? env.HH_ALLOWED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean)
    : undefined;

  const httpServer = http.createServer(async (req, res) => {
    // Do not construct discovery URLs from untrusted Host/Forwarded headers.
    let url: URL;
    try {
      const target = req.url || "/";
      if (!target.startsWith("/") || target.startsWith("//")) throw new Error();
      url = new URL(target, "http://localhost");
    } catch {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Invalid request target");
      return;
    }

    if (req.method === "GET" && url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", tools: TOOL_COUNT, version: VERSION }));
      return;
    }

    if (auth.metadata && (url.pathname === auth.metadataPath || url.pathname === "/.well-known/oauth-protected-resource")) {
      if (req.method !== "GET" && req.method !== "HEAD") {
        res.writeHead(405, { Allow: "GET, HEAD" });
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" });
      res.end(req.method === "HEAD" ? undefined : JSON.stringify(auth.metadata));
      return;
    }

    if (await auth.handleRoute?.(req, res, url)) return;

    if (url.pathname === "/mcp") {
      // Authenticate every method before reading the body, creating an MCP
      // server/transport, or returning protocol-specific responses.
      if (!(await auth.authorize(req, res))) return;
      if (req.method !== "POST") {
        res.writeHead(405, { "Content-Type": "application/json", Allow: "POST" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32000, message: "Method not allowed. Use POST /mcp." },
            id: null,
          }),
        );
        return;
      }
      // Stateless: a fresh server + transport per request avoids the
      // single-shared-transport concurrency bug. Torn down on response close.
      const server = createServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableDnsRebindingProtection: true,
        allowedHosts,
        ...(allowedOrigins ? { allowedOrigins } : {}),
      });
      res.on("close", () => {
        transport.close();
        server.close();
      });
      try {
        await server.connect(transport);
        const body = await readJsonBody(req);
        await transport.handleRequest(req, res, body);
      } catch {
        // Parser/SDK errors may contain attacker-controlled body fragments.
        console.error("[hh-mcp] request failed");
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              error: { code: -32603, message: "Internal server error" },
              id: null,
            }),
          );
        }
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found. Use POST /mcp for the MCP protocol or GET /health for a health check.");
  });

  return httpServer;
}
