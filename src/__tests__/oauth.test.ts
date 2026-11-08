import http from "node:http";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { auth, type OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { createOAuthServer } from "../oauth/server.js";
import { createHttpServer } from "../http.js";
import { challengeFor, derivePassword, oauthConfig, randomSecret } from "../oauth/security.js";
import { OAuthStore, postgresDatabase, postgresOptions, type Database } from "../oauth/store.js";
import { createHttpAuth } from "../auth.js";

function adapter(pg: PGlite, close = false): Database {
  return {
    query: (sql, values) => pg.query(sql, values),
    transaction: (fn) => pg.transaction((tx) => fn({ query: (sql, values) => tx.query(sql, values) })),
    close: async () => { if (close) await pg.close(); },
  };
}
const password = randomSecret(), secret = randomSecret();
const callback = "https://chatgpt.com/connector_platform_oauth_redirect";
const env: NodeJS.ProcessEnv = {
  MCP_AUTH_MODE: "oauth", MCP_PUBLIC_URL: "https://hh.example", MCP_OAUTH_CLIENT_ID: "chatgpt-headhunter",
  MCP_OAUTH_CLIENT_SECRET: secret, MCP_OAUTH_REDIRECT_URIS: callback,
};
let pg: PGlite;
let db: Database;
let server: http.Server;
let base: string;
async function freePort() {
  const server = http.createServer(); server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((resolve) => server.close(() => resolve())); return port;
}
async function start(database: Database = db, config = env) {
  const port = await freePort();
  const instance = createHttpServer(await createOAuthServer(config, database), { HH_ALLOWED_HOSTS: `127.0.0.1:${port}` }, port);
  instance.listen(port, "127.0.0.1"); await once(instance, "listening");
  return { instance, url: `http://127.0.0.1:${port}` };
}
async function stop(instance: http.Server) {
  instance.closeAllConnections(); await new Promise<void>((resolve) => instance.close(() => resolve()));
}
beforeAll(async () => {
  const salt = randomSecret().slice(0, 32);
  env.MCP_ADMIN_PASSWORD_HASH = `scrypt$${salt}$${(await derivePassword(password, salt)).toString("hex")}`;
  pg = new PGlite(); db = adapter(pg);
  const started = await start(); server = started.instance; base = started.url;
}, 30000);
beforeEach(async () => { await pg.exec("TRUNCATE hh_oauth_grants,hh_oauth_families,hh_oauth_flows,hh_oauth_limits CASCADE"); });
afterAll(async () => { await stop(server); await pg.close(); });
const post = (path: string, values: Record<string, string>, headers: Record<string, string> = {}, target = base) => fetch(target + path, {
  method: "POST", redirect: "manual", headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams(values),
});
async function flow(overrides: Record<string, string> = {}, target = base) {
  const verifier = randomSecret();
  const params = new URLSearchParams({ client_id: env.MCP_OAUTH_CLIENT_ID!, redirect_uri: callback,
    response_type: "code", resource: "https://hh.example/mcp", scope: "mcp:tools offline_access", state: randomSecret(),
    code_challenge_method: "S256", code_challenge: challengeFor(verifier), ...overrides });
  const response = await fetch(target + "/oauth/authorize?" + params, { redirect: "manual" });
  const html = await response.text();
  return { response, html, params, verifier, id: html.match(/name="flow" value="([^"]+)"/)?.[1] || "",
    csrf: html.match(/name="csrf" value="([^"]+)"/)?.[1] || "", cookie: response.headers.get("set-cookie")?.split(";")[0] || "" };
}
async function approve(f: Awaited<ReturnType<typeof flow>>, changes: Record<string, string> = {}, headers: Record<string, string> = {}, target = base) {
  return post("/oauth/authorize", { flow: f.id, csrf: f.csrf, password, ...changes }, { Origin: "https://hh.example", Cookie: f.cookie, ...headers }, target);
}
async function code(target = base) {
  const f = await flow({}, target); expect(f.response.status).toBe(200);
  const response = await approve(f, {}, {}, target); expect(response.status).toBe(303);
  const redirect = new URL(response.headers.get("location")!);
  expect(redirect.searchParams.get("state")).toBe(f.params.get("state"));
  expect(redirect.searchParams.get("iss")).toBe("https://hh.example");
  return { ...f, code: redirect.searchParams.get("code")! };
}
function exchange(c: Awaited<ReturnType<typeof code>>, overrides: Record<string, string> = {}, target = base) {
  return post("/oauth/token", { grant_type: "authorization_code", client_id: env.MCP_OAUTH_CLIENT_ID!, client_secret: secret,
    resource: "https://hh.example/mcp", redirect_uri: callback, code: c.code, code_verifier: c.verifier, ...overrides }, {}, target);
}
function refresh(token: string, overrides: Record<string, string> = {}, target = base) {
  return post("/oauth/token", { grant_type: "refresh_token", client_id: env.MCP_OAUTH_CLIENT_ID!, client_secret: secret,
    resource: "https://hh.example/mcp", refresh_token: token, ...overrides }, {}, target);
}
function mcp(token?: string, method = "tools/list", target = base) {
  return fetch(target + "/mcp", { method: "POST", headers: { Accept: "application/json, text/event-stream", "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: {} }) });
}
async function rpcBody(response: Response) {
  expect(response.status).toBe(200); const text = await response.text();
  return JSON.parse(text.startsWith("event:") ? text.match(/^data: (.+)$/m)![1] : text);
}

describe("Self-hosted OAuth HTTP security", () => {
  it("publishes discovery with S256, issuer identification and no open client registration", async () => {
    const resource = await (await fetch(base + "/.well-known/oauth-protected-resource/mcp")).json();
    expect(resource.resource).toBe("https://hh.example/mcp");
    const metadata = await (await fetch(base + "/.well-known/oauth-authorization-server")).json();
    expect(metadata).toMatchObject({ issuer: "https://hh.example", code_challenge_methods_supported: ["S256"],
      authorization_response_iss_parameter_supported: true, token_endpoint_auth_methods_supported: ["client_secret_post"] });
    expect(metadata.registration_endpoint).toBeUndefined();
    expect((await fetch(base + "/oauth/register", { method: "POST" })).status).toBe(404);
    expect((await mcp()).status).toBe(401);
    expect((await (await fetch(base + "/health")).json()).tools).toBe(19);
  });
  it("completes owner consent, code exchange, 19 tools, refresh rotation and revocation", async () => {
    const c = await code(); const response = await exchange(c); expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const tokens = await response.json(); expect(tokens.expires_in).toBe(900);
    expect((await rpcBody(await mcp(tokens.access_token))).result.tools).toHaveLength(19);
    const rotated = await refresh(tokens.refresh_token); expect(rotated.status).toBe(200);
    const next = await rotated.json(); expect(next.refresh_token).not.toBe(tokens.refresh_token);
    const revoked = await post("/oauth/revoke", { client_id: env.MCP_OAUTH_CLIENT_ID!, client_secret: secret, token: next.refresh_token });
    expect(revoked.status).toBe(200); expect((await mcp(next.access_token)).status).toBe(401);
    expect((await mcp(tokens.access_token)).status).toBe(401);
  });
  it.each([false, true])("keeps MCP OAuth separate from HH vacancy access (HH token configured: %s)", async (configured) => {
    const previousToken = process.env.HH_ACCESS_TOKEN;
    if (configured) process.env.HH_ACCESS_TOKEN = "hh-application-test-token";
    else delete process.env.HH_ACCESS_TOKEN;
    const realFetch = globalThis.fetch;
    let upstreamCalls = 0;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, options) => {
      if (String(input).startsWith("https://api.hh.ru/vacancies?")) {
        upstreamCalls++;
        const headers = options!.headers as Record<string, string>;
        expect(headers.Authorization).toBe(configured ? "Bearer hh-application-test-token" : undefined);
        expect(headers["HH-User-Agent"]).toBeTruthy();
        return configured
          ? Response.json({ items: [], found: 0, page: 0, pages: 0, per_page: 1 })
          : Response.json({ errors: [{ type: "forbidden" }], request_id: "1794177364056354d42f87d2c9641008" }, { status: 403 });
      }
      return realFetch(input, options);
    });
    try {
      expect((await mcp()).status).toBe(401); expect(upstreamCalls).toBe(0);
      const tokens = await (await exchange(await code())).json();
      const response = await fetch(base + "/mcp", { method: "POST", headers: {
        Accept: "application/json, text/event-stream", "Content-Type": "application/json", Authorization: `Bearer ${tokens.access_token}`,
      }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
        name: "search_vacancies", arguments: { text: "python", per_page: 1, page: 0 },
      } }) });
      const result = await rpcBody(response); expect(upstreamCalls).toBe(1);
      if (configured) expect(result.result.isError).not.toBe(true);
      else {
        expect(result.result.isError).toBe(true);
        expect(result.result.structuredContent.error).toMatchObject({ source: "hh_api", http_status: 403, reason: "forbidden", authorization: "anonymous" });
        expect(result.result.content[0].text).not.toContain("lacks required scope");
      }
    } finally {
      fetchSpy.mockRestore();
      if (previousToken === undefined) delete process.env.HH_ACCESS_TOKEN; else process.env.HH_ACCESS_TOKEN = previousToken;
    }
  });
  it("binds login to a Secure HttpOnly SameSite cookie and sets browser defenses", async () => {
    const f = await flow();
    expect(f.response.headers.get("set-cookie")).toMatch(/__Host-hh_oauth=.*; Secure; HttpOnly; SameSite=Lax; Path=\//);
    expect(f.response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(f.response.headers.get("content-security-policy")).toContain("form-action 'self' https://chatgpt.com");
    expect(f.response.headers.get("referrer-policy")).toBe("same-origin");
    expect(f.html).not.toContain(password); expect(f.html).not.toContain(secret);
  });
  it.each(["https://attacker.example/cb", callback + "/extra", callback + "?extra=1", "http://chatgpt.com/connector_platform_oauth_redirect"])("rejects non-exact redirect %s", async (uri) => {
    const f = await flow({ redirect_uri: uri }); expect(f.response.status).toBe(400); expect(f.response.headers.get("location")).toBeNull();
  });
  it.each([{ client_id: "attacker" }, { state: "" }])("rejects bad client/state (%#)", async (overrides) => {
    expect((await flow(overrides)).response.status).toBe(400);
  });
  it.each([{ code_challenge_method: "plain" }, { code_challenge: "" }, { resource: "https://another.example/mcp" }, { response_type: "token" }, { scope: "openid admin" }])("rejects invalid OAuth parameters using only a validated callback (%#)", async (overrides) => {
    const f = await flow(overrides); expect(f.response.status).toBe(303);
    const redirect = new URL(f.response.headers.get("location")!);
    expect(redirect.origin + redirect.pathname).toBe(callback); expect(redirect.searchParams.get("error")).toBeTruthy();
    expect(redirect.searchParams.get("state")).toBe(f.params.get("state")); expect(redirect.searchParams.get("iss")).toBe("https://hh.example");
  });
  it.each([
    [{ csrf: "bad" }, {}], [{}, { Origin: "https://attacker.example" }], [{}, { Origin: "" }], [{}, { Cookie: "" }], [{}, { Cookie: "__Host-hh_oauth=bad" }],
  ])("rejects CSRF, missing origin and foreign browser cookies (%#)", async (values, headers) => {
    expect((await approve(await flow(), values, headers)).status).toBe(400);
  });
  it("denies the wrong admin password and persists the password attempt limit", async () => {
    const f = await flow();
    for (let i = 0; i < 5; i++) expect((await approve(f, { password: randomSecret() })).status).toBe(401);
    const second = await start();
    try { expect((await approve(f, {}, {}, second.url)).status).toBe(429); } finally { await stop(second.instance); }
  });
  it("consumes browser authorization only once, including simultaneous submits", async () => {
    const f = await flow(); const responses = await Promise.all([approve(f), approve(f)]);
    expect(responses.map((r) => r.status).sort()).toEqual([303, 400]);
  });
  it.each([{ redirect_uri: callback + "?changed" }, { code_verifier: randomSecret() }, { resource: "https://other.example" }, { client_secret: "invalid" }, { client_id: "other" }])("binds the code to redirect, verifier, resource and client (%#)", async (overrides) => {
    const c = await code(); expect((await exchange(c, overrides)).status).toBeGreaterThanOrEqual(400);
    expect((await exchange(c)).status).toBe(200);
  });
  it("atomically consumes a code and revokes its tokens after valid replay", async () => {
    const c = await code(); const responses = await Promise.all([exchange(c), exchange(c)]);
    expect(responses.map((r) => r.status).sort()).toEqual([200, 400]);
    const tokens = await responses.find((r) => r.status === 200)!.json();
    expect((await mcp(tokens.access_token)).status).toBe(401);
  });
  it("rejects expired login, code, access and refresh credentials", async () => {
    const f = await flow(); await pg.query("UPDATE hh_oauth_flows SET expires_at=CURRENT_TIMESTAMP - interval '1 second'");
    expect((await approve(f)).status).toBe(400);
    const c = await code(); await pg.query("UPDATE hh_oauth_grants SET expires_at=CURRENT_TIMESTAMP - interval '1 second' WHERE kind='code'");
    expect((await exchange(c)).status).toBe(400);
    const tokens = await (await exchange(await code())).json();
    await pg.query("UPDATE hh_oauth_grants SET expires_at=CURRENT_TIMESTAMP - interval '1 second' WHERE kind IN ('access','refresh')");
    expect((await mcp(tokens.access_token)).status).toBe(401); expect((await refresh(tokens.refresh_token)).status).toBe(400);
  });
  it("allows refresh scope narrowing while preserving the original refresh grant ceiling", async () => {
    const tokens = await (await exchange(await code())).json();
    const narrowed = await (await refresh(tokens.refresh_token, { scope: "mcp:tools" })).json();
    expect(narrowed.scope).toBe("mcp:tools"); expect(narrowed.refresh_token).toBeTruthy();
    expect((await mcp(narrowed.access_token)).status).toBe(200);
    const restored = await (await refresh(narrowed.refresh_token)).json();
    expect(restored.scope).toBe("mcp:tools offline_access");
  });
  it("detects refresh reuse and revokes the entire family", async () => {
    const tokens = await (await exchange(await code())).json();
    const next = await (await refresh(tokens.refresh_token)).json();
    expect((await refresh(tokens.refresh_token)).status).toBe(400);
    expect((await mcp(next.access_token)).status).toBe(401); expect((await refresh(next.refresh_token)).status).toBe(400);
  });
  it("does not escalate scopes or accept tokens through URLs/static secrets", async () => {
    const tokens = await (await exchange(await code())).json();
    expect((await refresh(tokens.refresh_token, { scope: "mcp:tools offline_access admin" })).status).toBe(400);
    expect((await fetch(base + "/mcp?access_token=" + tokens.access_token, { method: "POST" })).status).toBe(401);
    expect((await mcp(secret)).status).toBe(401);
    const c = await code(); const duplicate = new URLSearchParams({ grant_type: "authorization_code", client_id: env.MCP_OAUTH_CLIENT_ID!, client_secret: secret });
    duplicate.append("client_id", "attacker");
    expect((await fetch(base + "/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: duplicate })).status).toBe(400);
    expect((await exchange(c)).status).toBe(200);
  });
  it("stores only hashes of codes, bearer tokens, cookies and CSRF secrets", async () => {
    const c = await code(); const tokens = await (await exchange(c)).json();
    const dump = JSON.stringify(await pg.query("SELECT * FROM hh_oauth_grants"));
    for (const value of [c.code, tokens.access_token, tokens.refresh_token, password, secret, c.csrf, c.cookie.split("=")[1]]) expect(dump).not.toContain(value);
  });
  it("fails closed on database outage and configuration rotation", async () => {
    const tokens = await (await exchange(await code())).json();
    const rotated = await start(db, { ...env, MCP_OAUTH_CLIENT_SECRET: randomSecret() });
    try { expect((await mcp(tokens.access_token, "tools/list", rotated.url)).status).toBe(401); } finally { await stop(rotated.instance); }
    const failing: Database = { ...db, query: vi.fn(async () => { throw new Error("private database error"); }) };
    const config = oauthConfig(env), store = new OAuthStore(failing, config.version);
    await expect(store.access(tokens.access_token, config.resource)).rejects.toThrow();
    // Existing server's store shares this adapter: no new startup/in-memory fallback.
    const original = db.query; db.query = failing.query;
    try { const response = await mcp(tokens.access_token); expect(response.status).toBe(503); expect(await response.text()).not.toContain("private"); }
    finally { db.query = original; }
  });
  it("does not leak credentials or request bodies to logs", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await mcp(randomSecret()); const f = await flow(); await approve(f, { password: randomSecret() });
      expect(spy).not.toHaveBeenCalled();
    } finally { spy.mockRestore(); }
  });
});

it("survives actual on-disk database close/reopen without replay or lost refresh state", async () => {
  const dir = await mkdtemp(join(tmpdir(), "hh-oauth-db-"));
  let disk = new PGlite(join(dir, "pg")); let running = await start(adapter(disk));
  try {
    const c = await code(running.url);
    await stop(running.instance); await disk.close();
    disk = new PGlite(join(dir, "pg")); running = await start(adapter(disk));
    const tokens = await (await exchange(c, {}, running.url)).json();
    expect((await mcp(tokens.access_token, "tools/list", running.url)).status).toBe(200);
    await stop(running.instance); await disk.close();
    disk = new PGlite(join(dir, "pg")); running = await start(adapter(disk));
    const next = await (await refresh(tokens.refresh_token, {}, running.url)).json();
    expect(next.access_token).toBeTruthy();
    expect((await exchange(c, {}, running.url)).status).toBe(400);
    expect((await mcp(next.access_token, "tools/list", running.url)).status).toBe(401);
  } finally { await stop(running.instance); await disk.close(); await rm(dir, { recursive: true, force: true }); }
}, 30000);

it("interoperates with the MCP SDK OAuth client using real discovery, PKCE and a client-side state check", async () => {
  let verifier = "", redirect: URL | undefined, saved: any;
  const state = randomSecret();
  const provider: OAuthClientProvider = {
    redirectUrl: callback, clientMetadata: { redirect_uris: [callback], token_endpoint_auth_method: "client_secret_post", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] },
    clientInformation: () => ({ client_id: env.MCP_OAUTH_CLIENT_ID!, client_secret: secret, issuer: env.MCP_PUBLIC_URL }),
    tokens: () => saved, saveTokens: (value) => { saved = value; },
    redirectToAuthorization: (url) => { redirect = url; }, saveCodeVerifier: (value) => { verifier = value; }, codeVerifier: () => verifier, state: () => state,
  };
  const fetchFn: typeof fetch = (input, options) => fetch(base + new URL(String(input)).pathname, options);
  const options = { serverUrl: "https://hh.example/mcp", resourceMetadataUrl: new URL("https://hh.example/.well-known/oauth-protected-resource/mcp"), fetchFn };
  expect(await auth(provider, options)).toBe("REDIRECT");
  expect(redirect!.searchParams.get("code_challenge_method")).toBe("S256");
  const f = await flow(Object.fromEntries(redirect!.searchParams));
  const approved = await approve(f); const returned = new URL(approved.headers.get("location")!);
  const complete = async (url: URL) => {
    if (url.searchParams.get("state") !== state || url.searchParams.get("iss") !== "https://hh.example") throw new Error("OAuth callback mismatch");
    return auth(provider, { ...options, authorizationCode: url.searchParams.get("code")! });
  };
  const forged = new URL(returned); forged.searchParams.set("state", "attacker");
  await expect(complete(forged)).rejects.toThrow("OAuth callback mismatch");
  expect(await complete(returned)).toBe("AUTHORIZED");
  expect((await mcp(saved.access_token)).status).toBe(200);
  const oldRefresh = saved.refresh_token;
  expect(await auth(provider, options)).toBe("AUTHORIZED");
  expect(saved.refresh_token).not.toBe(oldRefresh);
  expect((await mcp(saved.access_token)).status).toBe(200);
});

describe("configuration", () => {
  it.each([
    { MCP_PUBLIC_URL: "http://hh.example" }, { MCP_PUBLIC_URL: "https://hh.example/mcp" },
    { MCP_OAUTH_REDIRECT_URIS: "https://*.example/cb" }, { MCP_OAUTH_REDIRECT_URIS: "https://example/cb#token" },
    { MCP_OAUTH_REDIRECT_URIS: "http://example/cb" }, { MCP_ADMIN_PASSWORD_HASH: "password" },
    { MCP_OAUTH_CLIENT_SECRET: "short" }, { MCP_OAUTH_CLIENT_ID: "" },
  ])("rejects unsafe settings (%#)", (overrides) => expect(() => oauthConfig({ ...env, ...overrides })).toThrow());
  it("cannot disable TLS or replace DB credentials with URL query options", () => {
    const options = postgresOptions("postgresql://user:private@db.example/database?ssl=0&sslmode=disable&host=attacker.example&password=override");
    expect(options.ssl).toEqual({ rejectUnauthorized: true });
    expect(options.host).toBe("db.example"); expect(options.password).toBe("private");
    expect(options.connectionString).toBeUndefined();
  });
  it("requires a durable PostgreSQL connection and never starts anonymous OAuth", async () => {
    expect(() => postgresDatabase("")).toThrow();
    await expect(createHttpAuth({ ...env, MCP_OAUTH_DATABASE_URL: "" })).rejects.toThrow();
  });
});
