import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { hhGet, HhApiError } from "../client.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function ok(data: unknown) {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
    headers: { get: () => null },
  };
}

function fail(status: number, statusText = "Error", headers: Record<string, string> = {}) {
  return {
    ok: false,
    status,
    statusText,
    json: () => Promise.resolve({ error: statusText }),
    text: () => Promise.resolve(statusText),
    headers: { get: (k: string) => headers[k] ?? headers[k.toLowerCase()] ?? null },
  };
}

// Fake timers keep retry/backoff delays and the module-global rate limiter
// deterministic and fast. The advancing clock clears the limiter's 1s window
// between tests so prior calls don't inject spurious waits.
let clock = 1_700_000_000_000;

beforeEach(() => {
  vi.useFakeTimers();
  clock += 10_000;
  vi.setSystemTime(clock);
  mockFetch.mockReset();
  delete process.env.HH_ACCESS_TOKEN;
});

afterEach(() => {
  vi.useRealTimers();
  delete process.env.HH_ACCESS_TOKEN;
});

function headersOf(callIndex = 0): Record<string, string> {
  return mockFetch.mock.calls[callIndex]![1]!.headers as Record<string, string>;
}

describe("auth + required headers", () => {
  it("sends HH-User-Agent and User-Agent, omits Authorization without a token", async () => {
    mockFetch.mockResolvedValueOnce(ok({ a: 1 }));
    const p = hhGet("/areas");
    await vi.runAllTimersAsync();
    expect(await p).toEqual({ a: 1 });
    const h = headersOf();
    expect(h["HH-User-Agent"]).toMatch(/hh-mcp\//);
    expect(h["User-Agent"]).toBeTruthy();
    expect(h["Authorization"]).toBeUndefined();
  });

  it("adds a Bearer Authorization header when HH_ACCESS_TOKEN is set", async () => {
    process.env.HH_ACCESS_TOKEN = "tok123";
    mockFetch.mockResolvedValueOnce(ok({}));
    const p = hhGet("/me");
    await vi.runAllTimersAsync();
    await p;
    expect(headersOf()["Authorization"]).toBe("Bearer tok123");
  });

  it("honors HH_USER_AGENT override is reflected by a non-empty UA", async () => {
    mockFetch.mockResolvedValueOnce(ok({}));
    const p = hhGet("/x");
    await vi.runAllTimersAsync();
    await p;
    expect(headersOf()["HH-User-Agent"]).toBeTruthy();
  });
});

describe("error handling", () => {
  it("fails fast on 401 without retrying", async () => {
    mockFetch.mockResolvedValueOnce(fail(401, "Unauthorized"));
    await expect(hhGet("/resumes")).rejects.toBeInstanceOf(HhApiError);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("fails fast on 403 without retrying", async () => {
    mockFetch.mockResolvedValueOnce(fail(403, "Forbidden"));
    await expect(hhGet("/resumes")).rejects.toMatchObject({ status: 403 });
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("retries 5xx then throws HhApiError after MAX_RETRIES", async () => {
    mockFetch.mockResolvedValue(fail(500, "Server Error"));
    const p = hhGet("/vacancies");
    const assertion = expect(p).rejects.toMatchObject({ status: 500 });
    await vi.runAllTimersAsync();
    await assertion;
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });
});

describe("rate limit + retries", () => {
  it("honors Retry-After on 429 and then succeeds", async () => {
    mockFetch
      .mockResolvedValueOnce(fail(429, "Too Many Requests", { "Retry-After": "0" }))
      .mockResolvedValueOnce(ok({ ok: true }));
    const p = hhGet("/vacancies");
    await vi.runAllTimersAsync();
    expect(await p).toEqual({ ok: true });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("retries once on an aborted/timed-out request then succeeds", async () => {
    const abortErr = Object.assign(new Error("The operation was aborted"), {
      name: "AbortError",
    });
    mockFetch.mockRejectedValueOnce(abortErr).mockResolvedValueOnce(ok({ done: true }));
    const p = hhGet("/vacancies");
    await vi.runAllTimersAsync();
    expect(await p).toEqual({ done: true });
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("lets a burst of calls through (serializing extras past the 5 req/s window)", async () => {
    mockFetch.mockResolvedValue(ok({}));
    const ps = Array.from({ length: 7 }, () => hhGet("/x"));
    await vi.runAllTimersAsync();
    await Promise.all(ps);
    expect(mockFetch).toHaveBeenCalledTimes(7);
  });
});

describe("vacancy 403 regression and safe HH diagnostics", () => {
  afterEach(() => { delete process.env.HH_USER_AGENT; delete process.env.MCP_SECRET_TOKEN; });
  const response = (body: unknown, status = 403) => ({ ...fail(status), text: async () => JSON.stringify(body) });
  it("does not classify the observed anonymous forbidden as a token-scope problem", async () => {
    mockFetch.mockResolvedValueOnce(response({ errors: [{ type: "forbidden" }], request_id: "1794177364056354d42f87d2c9641008" }));
    const error = await hhGet("/vacancies?text=private-query&per_page=1").catch((e) => e as HhApiError);
    expect(error.diagnostic).toMatchObject({ source: "hh_api", http_status: 403, reason: "forbidden", authorization: "anonymous", endpoint: "/vacancies", request_id: "1794177364056354d42f87d2c9641008" });
    expect(error.message).not.toContain("lacks required scope");
    expect(JSON.stringify(error)).not.toContain("private-query");
    expect(headersOf().Authorization).toBeUndefined(); expect(mockFetch).toHaveBeenCalledTimes(1);
  });
  it.each([
    [{ type: "captcha_required", value: "captcha_required" }, "captcha_required"],
    [{ type: "bad_user_agent", value: "blacklisted" }, "bad_user_agent"],
    [{ type: "oauth", value: "token_expired" }, "invalid_hh_token"],
    [{ type: "oauth", value: "user_auth_expected" }, "user_auth_expected"],
    [{ type: "api_access_payment", value: "action_must_be_payed" }, "hh_permission_required"],
  ])("classifies HH errors from documented codes (%#)", async (entry, reason) => {
    mockFetch.mockResolvedValueOnce(response({ errors: [entry] }));
    await expect(hhGet("/vacancies")).rejects.toMatchObject({ diagnostic: { reason } });
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
  it("supports anonymous success but sends only the configured HH application token when present", async () => {
    mockFetch.mockResolvedValue(ok({ items: [], found: 0 }));
    expect(await hhGet("/vacancies?per_page=1")).toMatchObject({ items: [] });
    expect(headersOf().Authorization).toBeUndefined();
    process.env.HH_ACCESS_TOKEN = "  hh-application-token  ";
    process.env.MCP_SECRET_TOKEN = "unrelated-mcp-secret";
    process.env.HH_USER_AGENT = "my-hh-mcp/1.0 (owner@example.com)";
    await hhGet("/vacancies?per_page=1");
    expect(headersOf(1).Authorization).toBe("Bearer hh-application-token");
    expect(headersOf(1)["HH-User-Agent"]).toBe(process.env.HH_USER_AGENT);
    expect(headersOf(1)["User-Agent"]).toBe(process.env.HH_USER_AGENT);
    expect(mockFetch.mock.calls[1][1].redirect).toBe("error");
  });
  it("does not expose upstream HTML, descriptions, captcha state or reflected credentials", async () => {
    process.env.HH_ACCESS_TOKEN = "private-hh-token";
    mockFetch.mockResolvedValueOnce(response({ errors: [{ type: "captcha_required", value: "captcha_required", captcha_url: "https://hh.ru/account/captcha?state=private-state", description: "private-hh-token" }], request_id: "private-hh-token", html: "private-body" }));
    const error = await hhGet("/vacancies").catch((e) => e as HhApiError);
    const exposed = error.message + JSON.stringify(error);
    for (const secret of ["private-hh-token", "private-state", "private-body", "captcha_url"]) expect(exposed).not.toContain(secret);
    expect(error.diagnostic.reason).toBe("captcha_required");
  });
  it("does not infer scope failure for non-JSON upstream 403", async () => {
    mockFetch.mockResolvedValueOnce(fail(403, "<html>private-upstream-body</html>"));
    const error = await hhGet("/vacancies").catch((e) => e as HhApiError);
    expect(error.diagnostic.reason).toBe("forbidden");
    expect(JSON.stringify(error)).not.toContain("private-upstream-body");
  });
  it("rejects malformed HH header configuration without exposing its value", async () => {
    process.env.HH_ACCESS_TOKEN = "Bearer secret-value";
    await expect(hhGet("/vacancies")).rejects.toThrow("raw HH token");
    expect(mockFetch).not.toHaveBeenCalled();
    delete process.env.HH_ACCESS_TOKEN;
    process.env.HH_USER_AGENT = "invalid\r\nInjected: secret";
    await expect(hhGet("/vacancies")).rejects.toThrow("single ASCII");
    expect(mockFetch).not.toHaveBeenCalled();
  });
});
