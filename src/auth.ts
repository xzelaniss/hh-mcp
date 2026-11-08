import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createRemoteJWKSet, jwtVerify } from "jose";

const SCOPE = "mcp:tools";
const REQUESTED_SCOPES = [SCOPE, "offline_access"];
const TOKEN_PATTERN = /^[A-Za-z0-9\-._~+/]+=*$/;

export interface HttpAuth {
  metadata?: { resource: string; authorization_servers: string[]; scopes_supported: string[]; bearer_methods_supported: string[] };
  metadataPath?: string;
  authorize(req: IncomingMessage, res: ServerResponse): Promise<boolean>;
}

function bearerToken(req: IncomingMessage): string | undefined {
  const count = req.rawHeaders.filter(
    (value, index) => index % 2 === 0 && value.toLowerCase() === "authorization",
  ).length;
  if (count !== 1) return undefined;
  return /^Bearer +([A-Za-z0-9\-._~+/]+=*)$/i.exec(req.headers.authorization || "")?.[1];
}

function deny(res: ServerResponse, challenge: string, status = 401): false {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "WWW-Authenticate": challenge,
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify({ error: status === 401 ? "Unauthorized" : "Forbidden" }));
  return false;
}

function httpsOrigin(env: NodeJS.ProcessEnv, name: string): URL {
  // Configuration errors must not include supplied values (which may be secrets).
  try {
    const url = new URL(env[name] || "");
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      throw new Error();
    }
    return url;
  } catch {
    throw new Error(`Set ${name} to an HTTPS origin without a path, credentials, query or fragment.`);
  }
}

export function createHttpAuth(env: NodeJS.ProcessEnv): HttpAuth {
  const mode = env.MCP_AUTH_MODE || "bearer";
  if (mode === "bearer") {
    const secret = env.MCP_SECRET_TOKEN;
    if (!secret || !TOKEN_PATTERN.test(secret)) {
      throw new Error("Set MCP_SECRET_TOKEN to a non-empty Bearer token before starting HTTP mode.");
    }
    const digest = createHash("sha256").update(secret).digest();
    return {
      async authorize(req, res) {
        const token = bearerToken(req);
        return (token !== undefined && timingSafeEqual(createHash("sha256").update(token).digest(), digest)) ||
          deny(res, 'Bearer realm="hh-mcp"');
      },
    };
  }
  if (mode !== "oauth") throw new Error("MCP_AUTH_MODE must be bearer or oauth.");

  const publicOrigin = httpsOrigin(env, "MCP_PUBLIC_URL").origin;
  const issuer = httpsOrigin(env, "MCP_OAUTH_ISSUER").href;
  // Auth0's issuer includes the trailing slash. Require the exact value rather
  // than silently fixing an issuer mismatch with discovery or token claims.
  if (env.MCP_OAUTH_ISSUER !== issuer) throw new Error("MCP_OAUTH_ISSUER must be the exact canonical issuer, including its trailing slash.");
  const clientId = env.MCP_OAUTH_CLIENT_ID?.trim();
  const subjects = new Set(env.MCP_OAUTH_ALLOWED_SUBJECTS?.split(",").map((s) => s.trim()).filter(Boolean));
  if (!clientId || !subjects.size) throw new Error("Set MCP_OAUTH_CLIENT_ID and MCP_OAUTH_ALLOWED_SUBJECTS before starting OAuth mode.");

  const resource = `${publicOrigin}/mcp`;
  const metadataPath = "/.well-known/oauth-protected-resource/mcp";
  const challenge = `Bearer resource_metadata="${publicOrigin}${metadataPath}", scope="${REQUESTED_SCOPES.join(" ")}"`;
  // Trust only this configured Auth0 tenant. Never use jku/x5u or issuer URLs
  // from an unverified JWT. jose bounds fetch time, caches keys, and rate-limits
  // refreshes for unknown kids. It does not follow JWKS redirects.
  const keys = createRemoteJWKSet(new URL(".well-known/jwks.json", issuer), {
    timeoutDuration: 5000, cooldownDuration: 30000, cacheMaxAge: 600000,
  });
  return {
    metadata: { resource, authorization_servers: [issuer], scopes_supported: REQUESTED_SCOPES, bearer_methods_supported: ["header"] },
    metadataPath,
    async authorize(req, res) {
      const token = bearerToken(req);
      if (!token) return deny(res, challenge);
      try {
        const { payload } = await jwtVerify(token, keys, {
          algorithms: ["RS256"], issuer, audience: resource,
          requiredClaims: ["exp", "iat", "sub", "iss", "aud"],
          maxTokenAge: 3600, clockTolerance: 5,
        });
        if (payload.exp! - payload.iat! > 3600) return deny(res, challenge);
        // Bind access both to the manually registered ChatGPT OAuth client and
        // the owner's exact Auth0 user ID. Signup alone must never grant access.
        if ((payload.azp ?? payload.client_id) !== clientId || !subjects.has(payload.sub!)) {
          return deny(res, challenge, 403);
        }
        if (typeof payload.scope !== "string" || !payload.scope.split(" ").includes(SCOPE)) {
          return deny(res, `${challenge}, error="insufficient_scope"`, 403);
        }
        return true;
      } catch {
        // JWTs, upstream errors and claim values must not reach logs/responses.
        // A key retrieval failure fails closed; there is no static-token fallback.
        return deny(res, challenge);
      }
    },
  };
}
