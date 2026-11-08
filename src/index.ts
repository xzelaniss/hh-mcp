#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createHttpAuth } from "./auth.js";
import { createHttpServer } from "./http.js";
import { createServer, TOOL_COUNT } from "./server.js";
export { createServer, TOOL_COUNT } from "./server.js";

// --- Start ---

async function main() {
  const args = process.argv.slice(2);
  const httpMode = args.includes("--http") || !!process.env.HTTP_PORT;
  const port = Number(process.env.HTTP_PORT || process.env.PORT || 3000);

  if (httpMode) {
    const auth = await createHttpAuth(process.env);
    const host = process.env.HOST || "127.0.0.1";
    const httpServer = createHttpServer(auth, process.env, port);

    httpServer.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        console.error(`[hh-mcp] Port ${port} is already in use. Set HTTP_PORT/PORT to a free port.`);
      } else {
        console.error("[hh-mcp] HTTP server error:", err);
      }
      process.exit(1);
    });

    httpServer.listen(port, host, () => {
      console.error(
        `[hh-mcp] HTTP mode on ${host}:${port} (${TOOL_COUNT} tools). Endpoint: POST /mcp, health: GET /health`,
      );
    });

    const shutdown = () => httpServer.close(() => {
      void Promise.resolve(auth.close?.()).finally(() => process.exit(0));
    });
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } else {
    const server = createServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(
      `[hh-mcp] Server started (stdio). ${TOOL_COUNT} tools. Auth: ${process.env.HH_ACCESS_TOKEN ? "token set" : "no token (public endpoints only)"}`,
    );
  }
}

main().catch(() => {
  console.error("[hh-mcp] Startup failed. Check authentication configuration and database connectivity.");
  process.exit(1);
});
