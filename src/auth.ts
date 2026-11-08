import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createOAuthServer } from "./oauth/server.js";
import { bearerToken, oauthConfig } from "./oauth/security.js";
import { postgresDatabase } from "./oauth/store.js";

export interface HttpAuth {
  metadata?: { resource: string; authorization_servers: string[]; scopes_supported: string[]; bearer_methods_supported: string[] };
  metadataPath?: string;
  handleRoute?(req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean>;
  close?(): Promise<void>;
  authorize(req: IncomingMessage, res: ServerResponse): Promise<boolean>;
}
export async function createHttpAuth(env: NodeJS.ProcessEnv): Promise<HttpAuth> {
  const mode = env.MCP_AUTH_MODE || "bearer";
  if (mode === "oauth") {
    oauthConfig(env); // Validate before opening database connections.
    const db = postgresDatabase(env.MCP_OAUTH_DATABASE_URL || "");
    try { return await createOAuthServer(env, db); }
    catch (error) { await db.close(); throw error; }
  }
  if (mode !== "bearer") throw new Error("MCP_AUTH_MODE must be bearer or oauth.");
  const secret = env.MCP_SECRET_TOKEN;
  if (!secret || !/^[A-Za-z0-9\-._~+/]+=*$/.test(secret)) throw new Error("Set MCP_SECRET_TOKEN to a non-empty Bearer token before starting HTTP mode.");
  const digest = createHash("sha256").update(secret).digest();
  return { async authorize(req, res) {
    const token = bearerToken(req);
    if (token !== undefined && timingSafeEqual(createHash("sha256").update(token).digest(), digest)) return true;
    res.writeHead(401, { "Content-Type": "application/json", "WWW-Authenticate": 'Bearer realm="hh-mcp"', "Cache-Control": "no-store" });
    res.end(JSON.stringify({ error: "Unauthorized" })); return false;
  } };
}
