import type { IncomingMessage, ServerResponse } from "node:http";
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createHttpAuth } from "../auth.js";

const issuer = "https://tenant.auth0.com/";
const resource = "https://hh.example/mcp";
const env = {
  MCP_AUTH_MODE: "oauth", MCP_PUBLIC_URL: "https://hh.example", MCP_OAUTH_ISSUER: issuer,
  MCP_OAUTH_CLIENT_ID: "chatgpt-client", MCP_OAUTH_ALLOWED_SUBJECTS: "auth0|owner",
};
let pair: Awaited<ReturnType<typeof generateKeyPair>>;
let otherPair: Awaited<ReturnType<typeof generateKeyPair>>;
let jwks: object;
const fetchMock = vi.fn();
beforeAll(async () => {
  pair = await generateKeyPair("RS256");
  otherPair = await generateKeyPair("RS256");
  jwks = { keys: [{ ...await exportJWK(pair.publicKey), kid: "trusted", alg: "RS256", use: "sig" }] };
});
beforeEach(() => {
  fetchMock.mockReset().mockImplementation(async () => new Response(JSON.stringify(jwks), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

async function sign(overrides: JWTPayload = {}, options: { otherKey?: boolean; alg?: string; kid?: string } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: issuer, aud: resource, iat: now, exp: now + 3600, sub: "auth0|owner", azp: "chatgpt-client",
    scope: "openid email mcp:tools", ...overrides,
  };
  return new SignJWT(claims).setProtectedHeader({ alg: options.alg || "RS256", kid: options.kid || "trusted" })
    .sign(options.otherKey ? otherPair.privateKey : pair.privateKey);
}

async function authorize(token?: string, auth = createHttpAuth(env), duplicate = false) {
  const headers = token === undefined ? [] : ["Authorization", `Bearer ${token}`];
  const req = {
    rawHeaders: duplicate ? [...headers, ...headers] : headers,
    headers: { authorization: token === undefined ? undefined : `Bearer ${token}` },
  } as IncomingMessage;
  let status: number | undefined;
  let responseHeaders: Record<string, string> = {};
  let body = "";
  const res = {
    writeHead(code: number, values: Record<string, string>) { status = code; responseHeaders = values; },
    end(value: string) { body = value; },
  } as unknown as ServerResponse;
  const allowed = await auth.authorize(req, res);
  return { allowed, status, responseHeaders, body };
}

describe("OAuth resource server security", () => {
  it("accepts an owner access token and caches the pinned tenant's JWKS", async () => {
    const auth = createHttpAuth(env);
    const token = await sign();
    expect((await authorize(token, auth)).allowed).toBe(true);
    expect((await authorize(token, auth)).allowed).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(issuer + ".well-known/jwks.json");
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: "manual" });
  });

  it.each([
    ["wrong issuer", { iss: "https://attacker.example/" }],
    ["wrong audience", { aud: "another-api" }],
    ["an ID token", { aud: "chatgpt-client" }],
    ["expired token", { exp: Math.floor(Date.now() / 1000) - 60 }],
    ["missing expiration", { exp: undefined }],
    ["missing issued-at", { iat: undefined }],
    ["future issued-at", { iat: Math.floor(Date.now() / 1000) + 60 }],
    ["future not-before", { nbf: Math.floor(Date.now() / 1000) + 60 }],
    ["overlong lifetime", { exp: Math.floor(Date.now() / 1000) + 7200 }],
    ["missing subject", { sub: undefined }],
  ])("rejects %s", async (_name, claims) => {
    expect(await authorize(await sign(claims))).toMatchObject({ allowed: false, status: 401 });
  });

  it.each([
    ["another user", { sub: "auth0|stranger" }],
    ["another client", { azp: "other-client" }],
    ["no client binding", { azp: undefined }],
    ["machine identity", { sub: "chatgpt-client@clients" }],
  ])("denies %s even with a valid signature", async (_name, claims) => {
    expect(await authorize(await sign(claims))).toMatchObject({ allowed: false, status: 403 });
  });

  it.each([undefined, "openid email", "mcp:tools:other"])("requires the exact scope (%#)", async (scope) => {
    const result = await authorize(await sign({ scope }));
    expect(result).toMatchObject({ allowed: false, status: 403 });
    expect(result.responseHeaders["WWW-Authenticate"]).toContain('error="insufficient_scope"');
  });

  it("rejects wrong signatures, unknown keys, unsigned and symmetric tokens", async () => {
    for (const token of [
      await sign({}, { otherKey: true }), await sign({}, { kid: "unknown" }),
      Buffer.from('{"alg":"none"}').toString("base64url") + "." + Buffer.from("{}").toString("base64url") + ".",
      await new SignJWT({}).setProtectedHeader({ alg: "HS256" }).sign(new Uint8Array(32)),
    ]) expect(await authorize(token)).toMatchObject({ allowed: false, status: 401 });
  });

  it("never follows attacker-selected JWKS URLs in a token", async () => {
    const token = await new SignJWT({}).setProtectedHeader({ alg: "RS256", kid: "trusted", jku: "https://attacker.example/keys" }).sign(otherPair.privateKey);
    expect((await authorize(token)).status).toBe(401);
    expect(fetchMock.mock.calls.every(([url]) => url === issuer + ".well-known/jwks.json")).toBe(true);
  });

  it("fails closed when JWKS is unavailable or redirects", async () => {
    const token = await sign();
    fetchMock.mockRejectedValueOnce(new Error("private upstream details"));
    expect(await authorize(token)).toMatchObject({ allowed: false, status: 401, body: '{"error":"Unauthorized"}' });
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 302, headers: { Location: "https://attacker.example/keys" } }));
    expect((await authorize(token)).status).toBe(401);
  });

  it("rejects duplicate headers and static secrets in OAuth mode", async () => {
    expect((await authorize(await sign(), createHttpAuth(env), true)).status).toBe(401);
    expect((await authorize("static-secret", createHttpAuth({ ...env, MCP_SECRET_TOKEN: "static-secret" }))).status).toBe(401);
  });

  it("gives a discovery challenge without disclosing credentials or claims", async () => {
    const result = await authorize();
    expect(result).toMatchObject({ allowed: false, status: 401, body: '{"error":"Unauthorized"}' });
    expect(result.responseHeaders["WWW-Authenticate"]).toBe('Bearer resource_metadata="https://hh.example/.well-known/oauth-protected-resource/mcp", scope="mcp:tools offline_access"');
  });
});

describe("OAuth configuration fails closed", () => {
  it.each([
    { MCP_AUTH_MODE: "none" }, { MCP_OAUTH_ALLOWED_SUBJECTS: "" }, { MCP_OAUTH_CLIENT_ID: "" },
    { MCP_PUBLIC_URL: "http://hh.example" }, { MCP_PUBLIC_URL: "https://hh.example/mcp" },
    { MCP_PUBLIC_URL: "https://user:secret@hh.example" }, { MCP_PUBLIC_URL: "https://hh.example/?query=secret" },
    { MCP_OAUTH_ISSUER: "http://tenant.auth0.com/" }, { MCP_OAUTH_ISSUER: "https://tenant.auth0.com" },
  ])("rejects unsafe/incomplete configuration (%#)", (overrides) => {
    expect(() => createHttpAuth({ ...env, ...overrides })).toThrow();
  });
});
