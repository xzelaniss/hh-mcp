import type { IncomingMessage } from "node:http";
import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";

export const randomSecret = () => randomBytes(32).toString("hex");
export const hash = (value: string) => createHash("sha256").update(value).digest("hex");
export const equal = (a: string, b: string) => timingSafeEqual(Buffer.from(hash(a), "hex"), Buffer.from(hash(b), "hex"));
export const challengeFor = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");
export const passwordHashPattern = /^scrypt\$[a-f0-9]{32}\$[a-f0-9]{128}$/;
export function derivePassword(password: string, salt: string): Promise<Buffer> {
  return new Promise((resolve, reject) => scrypt(password, Buffer.from(salt, "hex"), 64,
    { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
    (error, result) => error ? reject(error) : resolve(result)));
}
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  if (password.length < 32 || password.length > 256) return false;
  const [, salt, digest] = stored.split("$");
  return timingSafeEqual(await derivePassword(password, salt), Buffer.from(digest, "hex"));
}

export interface OAuthConfig {
  origin: string; issuer: string; resource: string; clientId: string; clientSecret: string;
  redirects: string[]; passwordHash: string; version: string;
}
export function oauthConfig(env: NodeJS.ProcessEnv): OAuthConfig {
  let origin: string;
  try {
    const url = new URL(env.MCP_PUBLIC_URL || "");
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error();
    origin = url.origin;
  } catch { throw new Error("Set MCP_PUBLIC_URL to an HTTPS origin without credentials or a path."); }
  const clientId = env.MCP_OAUTH_CLIENT_ID || "";
  const clientSecret = env.MCP_OAUTH_CLIENT_SECRET || "";
  const passwordHash = env.MCP_ADMIN_PASSWORD_HASH || "";
  if (!/^[A-Za-z0-9._-]{8,128}$/.test(clientId) || !/^[a-f0-9]{64}$/.test(clientSecret) || !passwordHashPattern.test(passwordHash)) {
    throw new Error("Set OAuth client credentials and MCP_ADMIN_PASSWORD_HASH using npm run oauth:secrets.");
  }
  const redirects = (env.MCP_OAUTH_REDIRECT_URIS || "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!redirects.length || redirects.some((raw) => {
    try { const url = new URL(raw); return url.protocol !== "https:" || !!url.username || !!url.password || !!url.hash || url.href !== raw; }
    catch { return true; }
  })) throw new Error("Set MCP_OAUTH_REDIRECT_URIS to exact HTTPS callback URLs without fragments or wildcards.");
  if (redirects.some((s) => s.includes("*"))) throw new Error("OAuth redirect wildcards are forbidden.");
  // Rotating the password/client secret or changing resource/callbacks revokes
  // all old flows and grants across all server processes, without RAM state.
  const version = hash(JSON.stringify([origin, clientId, clientSecret, passwordHash, [...redirects].sort()]));
  return { origin, issuer: origin, resource: origin + "/mcp", clientId, clientSecret, redirects, passwordHash, version };
}

export function bearerToken(req: IncomingMessage): string | undefined {
  const count = req.rawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === "authorization").length;
  return count === 1 ? /^Bearer +([A-Za-z0-9\-._~+/]+=*)$/i.exec(req.headers.authorization || "")?.[1] : undefined;
}
