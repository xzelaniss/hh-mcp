import { VERSION } from "./version.js";
import { hhDiagnostic } from "./hh-errors.js";

const BASE_URL = "https://api.hh.ru";
const TIMEOUT = 10_000;
const MAX_RETRIES = 3;

// hh.ru accepts User-Agent or HH-User-Agent; if both are supplied, it uses
// HH-User-Agent. Operators should set a real app name/version and contact email.
// The fallback identifies this repository rather than pretending to be a browser.
const DEFAULT_USER_AGENT = `hh-mcp/${VERSION} (+https://github.com/xzelaniss/hh-mcp)`;

// Rate limiter: 5 requests per second
const RATE_LIMIT = 5;
const RATE_WINDOW = 1000;
const timestamps: number[] = [];

async function waitForRateLimit(): Promise<void> {
  const now = Date.now();
  // Remove timestamps outside the window
  while (timestamps.length > 0 && timestamps[0]! <= now - RATE_WINDOW) {
    timestamps.shift();
  }
  if (timestamps.length >= RATE_LIMIT) {
    const oldest = timestamps[0]!;
    const waitMs = oldest + RATE_WINDOW - now;
    if (waitMs > 0) {
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
  timestamps.push(Date.now());
}

export class HhApiError extends Error {
  readonly diagnostic: ReturnType<typeof hhDiagnostic>;
  readonly body: string;
  constructor(public status: number, public statusText: string, body?: string, endpoint = "unknown", authenticated = !!process.env.HH_ACCESS_TOKEN?.trim()) {
    const diagnostic = hhDiagnostic(status, body, endpoint, authenticated);
    super(`hh.ru API HTTP ${status} [${diagnostic.reason}]: ${diagnostic.action}`);
    this.name = "HhApiError";
    this.diagnostic = diagnostic;
    this.body = JSON.stringify({ errors: diagnostic.errors, ...(diagnostic.request_id ? { request_id: diagnostic.request_id } : {}) });
    // statusText supplied by a remote server is not a trusted error message.
    this.statusText = `HTTP ${status}`;
  }
}

export async function hhGet(path: string): Promise<unknown> {
  const token = process.env.HH_ACCESS_TOKEN?.trim();
  const userAgent = process.env.HH_USER_AGENT?.trim() || DEFAULT_USER_AGENT;
  if (token && !/^[A-Za-z0-9\-._~+/]+=*$/.test(token)) throw new Error("HH_ACCESS_TOKEN must contain only the raw HH token, without the Bearer prefix or line breaks.");
  if (!/^[\x20-\x7E]+$/.test(userAgent)) throw new Error("HH_USER_AGENT must be a single ASCII header value.");
  await waitForRateLimit();

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT);

    const headers: Record<string, string> = {
      // hh.ru reads the custom `HH-User-Agent`; we also send the standard
      // `User-Agent` for proxies/CDNs that key on it.
      "HH-User-Agent": userAgent,
      "User-Agent": userAgent,
      Accept: "application/json",
    };

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(`${BASE_URL}${path}`, {
        headers,
        signal: controller.signal,
        redirect: "error",
      });
      clearTimeout(timer);

      if (response.ok) return response.json();

      const body = await response.text().catch(() => "");

      // A 403 can mean anonymous access restriction, captcha, invalid HH auth,
      // paid permissions or a generic denial. Do not invent a scope diagnosis.
      if (response.status === 401 || response.status === 403) {
        throw new HhApiError(response.status, response.statusText, body, path, !!token);
      }

      // Rate limit — use Retry-After header if available
      if (response.status === 429) {
        const retryAfter = response.headers.get("Retry-After");
        const delay = retryAfter
          ? parseInt(retryAfter, 10) * 1000
          : Math.min(1000 * 2 ** (attempt - 1), 8000);
        if (attempt < MAX_RETRIES) {
          console.error(
            `[hh-mcp] 429 rate limited, retry in ${delay}ms (${attempt}/${MAX_RETRIES})`,
          );
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
        throw new HhApiError(429, "Rate limited — all retries exhausted", body, path, !!token);
      }

      // Server errors — retry
      if (response.status >= 500 && attempt < MAX_RETRIES) {
        const delay = Math.min(1000 * 2 ** (attempt - 1), 8000);
        console.error(
          `[hh-mcp] ${response.status}, retry in ${delay}ms (${attempt}/${MAX_RETRIES})`,
        );
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }

      throw new HhApiError(response.status, response.statusText, body, path, !!token);
    } catch (error) {
      clearTimeout(timer);
      // Abort fires as a DOMException in Node 18+, but be tolerant of runtimes
      // that surface a plain Error named "AbortError".
      const isAbort =
        error instanceof Error && error.name === "AbortError";
      if (isAbort && attempt < MAX_RETRIES) {
        console.error(
          `[hh-mcp] Timeout, retry (${attempt}/${MAX_RETRIES})`,
        );
        continue;
      }
      throw error;
    }
  }
  throw new Error("hh.ru: all retries exhausted");
}
