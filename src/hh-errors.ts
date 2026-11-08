// Only allow-listed API codes are exposed. Never forward arbitrary upstream
// bodies, URLs (captcha state), descriptions, query strings or credentials.
const TYPES = new Set(["forbidden", "captcha_required", "bad_user_agent", "oauth", "api_access_payment", "bad_argument", "not_found", "service_unavailable", "resumes", "vacancies"]);
const VALUES = new Set(["captcha_required", "bad_authorization", "token_expired", "token_revoked", "application_not_found", "user_auth_expected", "unset", "blacklisted", "action_must_be_payed", "quota_exceeded", "no_available_service", "cant_view_contacts"]);
export function hhErrorDetails(body?: string) {
  const errors: { type: string; value?: string }[] = [];
  let requestId: string | undefined;
  try {
    const json = JSON.parse(body || "{}");
    if (Array.isArray(json.errors)) for (const error of json.errors.slice(0, 8)) {
      if (error && TYPES.has(error.type)) errors.push({ type: error.type, ...(VALUES.has(error.value) ? { value: error.value } : {}) });
    }
    if (typeof json.request_id === "string" && /^[A-Za-z0-9._-]{8,128}$/.test(json.request_id)) {
      const secrets = Object.entries(process.env).filter(([name, value]) => value && (/TOKEN|SECRET|PASSWORD|DATABASE_URL/.test(name))).map(([, value]) => value!.trim());
      if (!secrets.some((secret) => secret.length >= 4 && json.request_id.includes(secret))) requestId = json.request_id;
    }
  } catch { /* HTML/non-JSON errors carry no safe API details. */ }
  return { errors, ...(requestId ? { request_id: requestId } : {}) };
}
export function hhDiagnostic(status: number, body?: string, endpoint = "unknown", authenticated = !!process.env.HH_ACCESS_TOKEN?.trim()) {
  const details = hhErrorDetails(body);
  const has = (code: string) => details.errors.some((e) => e.type === code || e.value === code);
  let reason = "http_error", action = "Check hh.ru API status and request parameters.";
  if (has("captcha_required")) {
    reason = "captcha_required";
    action = "hh.ru requires captcha. Anonymous vacancy search is not reliable for a server. Configure a legitimate HH application access token; do not retry or bypass captcha automatically.";
  } else if (has("bad_user_agent")) {
    reason = "bad_user_agent";
    action = "Set HH_USER_AGENT to your real application name/version and contact email. HH-User-Agent takes precedence over User-Agent.";
  } else if (has("user_auth_expected")) {
    reason = "user_auth_expected";
    action = "This hh.ru method requires a user token. An application token can serve vacancy search but does not identify a user via /me.";
  } else if (details.errors.some((e) => e.type === "oauth" && ["bad_authorization", "token_expired", "token_revoked", "application_not_found"].includes(e.value || ""))) {
    reason = "invalid_hh_token";
    action = "HH reports an invalid, expired or revoked token/application. Fix HH_ACCESS_TOKEN, not the MCP OAuth login.";
  } else if (has("api_access_payment") || has("no_available_service") || has("cant_view_contacts")) {
    reason = "hh_permission_required";
    action = "Check the hh.ru user role and purchased access required by this endpoint; an MCP OAuth token does not grant hh.ru permissions.";
  } else if ((status === 401 || status === 403) && endpoint.split("?")[0].startsWith("/resumes")) {
    reason = "hh_permission_required";
    action = "Resume access requires an HH employer user token and the required paid resume-database access; an application token is not sufficient.";
  } else if (status === 401 || status === 403) {
    reason = "forbidden";
    action = authenticated
      ? "hh.ru denied this request with an HH token; a generic forbidden response does not prove a scope problem. Check the application's API access, account/service restrictions and contact HH support with request_id."
      : "hh.ru denied an anonymous request. Vacancy search may require captcha after the first anonymous call. For server-side search configure HH_ACCESS_TOKEN with a legitimate application token from dev.hh.ru/admin. This is separate from MCP OAuth.";
  }
  return { source: "hh_api" as const, http_status: status, reason, endpoint: endpoint.split("?")[0],
    authorization: authenticated ? "hh_token" : "anonymous", ...details, action };
}
