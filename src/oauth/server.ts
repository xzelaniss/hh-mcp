import type { IncomingMessage, ServerResponse } from "node:http";
import type { HttpAuth } from "../auth.js";
import { bearerToken, challengeFor, equal, hash, oauthConfig, randomSecret, verifyPassword, type OAuthConfig } from "./security.js";
import { OAuthStore, type Authorization, type Database } from "./store.js";

const cookieName = "__Host-hh_oauth";
class RequestError extends Error {
  constructor(readonly code = "invalid_request", readonly status = 400) { super(code); }
}
function one(params: URLSearchParams, name: string, required = true): string {
  const values = params.getAll(name);
  if (values.length > 1 || (required && (!values.length || !values[0]))) throw new RequestError();
  return values[0] || "";
}
function secureHeaders(res: ServerResponse, config: OAuthConfig) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  // no-referrer causes Chromium to send Origin:null on native form POSTs.
  // same-origin preserves the Origin check while suppressing cross-site referrers.
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Content-Type-Options", "nosniff");
  // Chromium applies form-action to the 303 callback as well as the POST.
  // Permit only trusted configured callback origins, never a request parameter.
  const callbackOrigins = [...new Set(config.redirects.map((uri) => new URL(uri).origin))].join(" ");
  res.setHeader("Content-Security-Policy", `default-src 'none'; form-action 'self' ${callbackOrigins}; frame-ancestors 'none'; base-uri 'none'`);
  res.setHeader("X-Frame-Options", "DENY");
}
function json(res: ServerResponse, status: number, value: unknown) {
  res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(value));
}
async function formBody(req: IncomingMessage): Promise<URLSearchParams> {
  if ((req.headers["content-type"] || "").split(";")[0].trim().toLowerCase() !== "application/x-www-form-urlencoded") throw new RequestError();
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 16384) throw new RequestError("invalid_request", 413);
    chunks.push(chunk);
  }
  const params = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
  for (const key of params.keys()) if (params.getAll(key).length !== 1) throw new RequestError();
  return params;
}
function cookie(req: IncomingMessage): string {
  const values = (req.headers.cookie || "").split(";").map((s) => s.trim()).filter((s) => s.startsWith(cookieName + "="));
  return values.length === 1 ? values[0].slice(cookieName.length + 1) : "";
}
function escape(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
}
function login(res: ServerResponse, config: OAuthConfig, id: string, csrf: string, error = false) {
  res.writeHead(error ? 401 : 200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Вход в HeadHunter MCP</title><body>
<h1>Разрешить доступ к HeadHunter MCP</h1><p>Сервис: ${escape(config.origin)}. Клиент: ${escape(config.clientId)}.</p>
<p>Доступ ко всем 19 инструментам, в том числе данным, доступным через настроенный токен hh.ru. Срок подключения — до 7 дней.</p>
${error ? "<p>Неверный пароль. Повторите вход.</p>" : ""}
<form method="post" action="/oauth/authorize"><input type="hidden" name="flow" value="${escape(id)}"><input type="hidden" name="csrf" value="${escape(csrf)}">
<label>Пароль владельца <input type="password" name="password" autocomplete="current-password" required maxlength="256"></label>
<button type="submit">Войти и разрешить доступ</button></form><p>Если вы не начинали подключение в ChatGPT, закройте эту страницу.</p></body></html>`);
}
function callback(res: ServerResponse, config: OAuthConfig, redirect: string, state: string, values: Record<string, string>) {
  const url = new URL(redirect);
  for (const [name, value] of Object.entries({ ...values, state, iss: config.issuer })) url.searchParams.set(name, value);
  res.writeHead(303, { Location: url.href }); res.end();
}
function authorizeParams(query: URLSearchParams, config: OAuthConfig): Authorization {
  if (one(query, "response_type") !== "code") throw new RequestError("unsupported_response_type");
  if (one(query, "resource") !== config.resource) throw new RequestError("invalid_target");
  if (one(query, "code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(one(query, "code_challenge"))) throw new RequestError();
  const scope = one(query, "scope", false) || "mcp:tools";
  const scopes = scope.split(" ");
  if (!scopes.includes("mcp:tools") || scopes.some((s) => !["mcp:tools", "offline_access"].includes(s))) throw new RequestError("invalid_scope");
  return { redirect: one(query, "redirect_uri"), state: one(query, "state"),
    challenge: one(query, "code_challenge"), resource: config.resource, scope: [...new Set(scopes)].sort().join(" ") };
}

export async function createOAuthServer(env: NodeJS.ProcessEnv, db: Database): Promise<HttpAuth> {
  const config = oauthConfig(env), store = new OAuthStore(db, config.version);
  await store.init();
  const metadataPath = "/.well-known/oauth-protected-resource/mcp";
  const challenge = `Bearer resource_metadata="${config.origin}${metadataPath}", scope="mcp:tools offline_access"`;
  return {
    metadataPath,
    metadata: { resource: config.resource, authorization_servers: [config.issuer], scopes_supported: ["mcp:tools", "offline_access"], bearer_methods_supported: ["header"] },
    close: () => store.close(),
    async authorize(req, res) {
      secureHeaders(res, config);
      const token = bearerToken(req);
      if (token && /^[a-f0-9]{64}$/.test(token)) {
        try { if (await store.access(token, config.resource)) return true; }
        catch { json(res, 503, { error: "temporarily_unavailable" }); return false; }
      }
      res.setHeader("WWW-Authenticate", challenge);
      json(res, 401, { error: "Unauthorized" }); return false;
    },
    async handleRoute(req, res, url) {
      const path = url.pathname;
      if (!["/.well-known/oauth-authorization-server", "/oauth/authorize", "/oauth/token", "/oauth/revoke"].includes(path)) return false;
      secureHeaders(res, config);
      try {
        if (path === "/.well-known/oauth-authorization-server") {
          if (req.method !== "GET") throw new RequestError("invalid_request", 405);
          json(res, 200, {
            issuer: config.issuer, authorization_endpoint: config.origin + "/oauth/authorize", token_endpoint: config.origin + "/oauth/token",
            revocation_endpoint: config.origin + "/oauth/revoke", response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token"], token_endpoint_auth_methods_supported: ["client_secret_post"],
            revocation_endpoint_auth_methods_supported: ["client_secret_post"], code_challenge_methods_supported: ["S256"],
            scopes_supported: ["mcp:tools", "offline_access"], authorization_response_iss_parameter_supported: true,
          }); return true;
        }
        if (path === "/oauth/authorize" && req.method === "GET") {
          const query = url.searchParams;
          // Validate client and exact redirect BEFORE issuing any redirect/error.
          if (one(query, "client_id") !== config.clientId || !config.redirects.includes(one(query, "redirect_uri"))) throw new RequestError();
          const state = one(query, "state");
          if (state.length > 1024 || req.url!.length > 8192) throw new RequestError();
          let params: Authorization;
          try { params = authorizeParams(query, config); }
          catch (error) {
            if (!(error instanceof RequestError)) throw error;
            callback(res, config, one(query, "redirect_uri"), state, { error: error.code }); return true;
          }
          if (!(await store.limit("authorization", 30, 3600))) throw new RequestError("rate_limited", 429);
          await store.cleanup();
          const id = randomSecret(), csrf = randomSecret(), browser = randomSecret();
          await store.createFlow(id, browser, csrf, params);
          res.setHeader("Set-Cookie", `${cookieName}=${browser}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`);
          login(res, config, id, csrf); return true;
        }
        if (path === "/oauth/authorize" && req.method === "POST") {
          // OAuth state belongs to ChatGPT. This independent Origin/cookie/CSRF
          // binding protects the owner's login/consent POST against login CSRF.
          if (req.headers.origin !== config.origin) throw new RequestError();
          const body = await formBody(req), id = one(body, "flow"), csrf = one(body, "csrf"), browser = cookie(req);
          const flow = await store.flow(id);
          if (!flow || !equal(hash(browser), flow.cookie_hash) || !equal(hash(csrf), flow.csrf_hash)) throw new RequestError();
          if (!(await store.limit("password", 5, 900))) throw new RequestError("rate_limited", 429);
          if (!(await verifyPassword(one(body, "password"), config.passwordHash))) { login(res, config, id, csrf, true); return true; }
          const approved = await store.approve(id, browser, csrf);
          if (!approved) throw new RequestError();
          res.setHeader("Set-Cookie", `${cookieName}=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
          callback(res, config, approved.params.redirect, approved.params.state, { code: approved.code }); return true;
        }
        if ((path === "/oauth/token" || path === "/oauth/revoke") && req.method === "POST") {
          const body = await formBody(req);
          // Only a pre-registered confidential client. No DCR/CIMD, implicit,
          // password grant or unauthenticated client_credentials flow exists.
          if (req.headers.authorization || one(body, "client_id", false) !== config.clientId ||
            !equal(one(body, "client_secret", false), config.clientSecret)) throw new RequestError("invalid_client", 401);
          if (!(await store.limit("token", 60, 60))) throw new RequestError("rate_limited", 429);
          if (path === "/oauth/revoke") {
            await store.revoke(one(body, "token")); json(res, 200, {}); return true;
          }
          const grant = one(body, "grant_type"), resource = one(body, "resource");
          if (resource !== config.resource) throw new RequestError("invalid_target");
          let tokens;
          if (grant === "authorization_code") {
            const verifier = one(body, "code_verifier");
            if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) throw new RequestError("invalid_grant");
            tokens = await store.exchange("code", one(body, "code"), {
              resource, redirect: one(body, "redirect_uri"), challenge: challengeFor(verifier),
            });
          } else if (grant === "refresh_token") {
            const scope = one(body, "scope", false);
            tokens = await store.exchange("refresh", one(body, "refresh_token"), {
              resource, ...(scope ? { scope: [...new Set(scope.split(" "))].sort().join(" ") } : {}),
            });
          } else throw new RequestError("unsupported_grant_type");
          if (!tokens) throw new RequestError("invalid_grant");
          json(res, 200, tokens); return true;
        }
        throw new RequestError("invalid_request", 405);
      } catch (error) {
        if (error instanceof RequestError) json(res, error.status, { error: error.code });
        else json(res, 503, { error: "temporarily_unavailable" });
        return true;
      }
    },
  };
}
