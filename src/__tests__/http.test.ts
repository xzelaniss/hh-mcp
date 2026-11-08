import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import http from "node:http";
import { once } from "node:events";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Ephemeral test credentials, never production secrets or fixed credentials.
const token = randomBytes(32).toString("hex");
const hhToken = randomBytes(32).toString("hex");
const children: ChildProcess[] = [];
let base: string;
let logs = "";

async function launch(secret: string | undefined, args = ["--http"], authEnv: NodeJS.ProcessEnv = {}) {
  const reservation = http.createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const address = reservation.address();
  if (!address || typeof address === "string") throw new Error("No test port");
  await new Promise<void>((resolve) => reservation.close(() => resolve()));
  const env = { ...process.env, HOST: "127.0.0.1", PORT: String(address.port) };
  // Do not inherit production configuration or credentials.
  for (const key of ["HTTP_PORT", "MCP_SECRET_TOKEN", "HH_ACCESS_TOKEN", "HH_ALLOWED_HOSTS", "HH_ALLOWED_ORIGINS", ...Object.keys(process.env).filter((key) => key.startsWith("MCP_"))]) {
    delete env[key as keyof typeof env];
  }
  Object.assign(env, { HH_ACCESS_TOKEN: hhToken });
  if (secret !== undefined) Object.assign(env, { MCP_SECRET_TOKEN: secret });
  Object.assign(env, authEnv);
  const child = spawn(process.execPath, ["node_modules/tsx/dist/cli.mjs", "src/index.ts", ...args], {
    env, stdio: ["pipe", "pipe", "pipe"],
  });
  children.push(child);
  let output = "";
  const ready = new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Server startup timed out")), 8000);
    child.stderr!.on("data", (data) => {
      output += data.toString();
      logs += data.toString();
      if (output.includes("HTTP mode on") || output.includes("Server started (stdio)")) {
        clearTimeout(timeout);
        resolve();
      }
    });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("exit", () => { clearTimeout(timeout); resolve(); });
  });
  await ready;
  return { child, output, url: `http://127.0.0.1:${address.port}` };
}

beforeAll(async () => { base = (await launch(token)).url; });
afterAll(async () => {
  await Promise.all(children.map(async (child) => {
    if (child.exitCode !== null) return;
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    const timeout = setTimeout(() => child.kill("SIGKILL"), 2000);
    await exited;
    clearTimeout(timeout);
  }));
  expect(logs).not.toContain(token);
  expect(logs).not.toContain(hhToken);
});

function request(path = "/mcp", authorization?: string, method = "POST", body = "{", target = base) {
  return fetch(target + path, {
    method,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(authorization === undefined ? {} : { Authorization: authorization }),
    },
    ...(method === "POST" ? { body } : {}),
  });
}

async function rpc(method: string, params: object, target = base, credential = token) {
  const response = await request("/mcp", `Bearer ${credential}`, "POST", JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), target);
  expect(response.status).toBe(200);
  const text = await response.text();
  return JSON.parse(text.startsWith("event:") ? text.match(/^data: (.+)$/m)![1] : text);
}

describe("HTTP authentication", () => {
  it.each([undefined, "", "Basic invalid", "Bearer wrong", `Bearer ${hhToken}`, `Bearer ${token}suffix`, `Bearer ${token}, Bearer ${token}`])(
    "rejects missing, malformed or incorrect credentials before parsing JSON (%#)", async (authorization) => {
      const response = await request("/mcp", authorization);
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toBe('Bearer realm="hh-mcp"');
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(await response.json()).toEqual({ error: "Unauthorized" });
    },
  );

  it.each(["GET", "DELETE", "OPTIONS", "PUT", "HEAD"])("authenticates %s before method dispatch", async (method) => {
    expect((await request("/mcp", undefined, method)).status).toBe(401);
    expect((await request("/mcp", `Bearer ${token}`, method)).status).toBe(405);
  });

  it("does not accept credentials from the URL", async () => {
    expect((await request(`/mcp?token=${token}&access_token=${token}`)).status).toBe(401);
  });

  it("rejects duplicate Authorization headers", async () => {
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = http.request(base + "/mcp", {
        method: "POST", headers: { Authorization: [`Bearer ${token}`, `Bearer ${token}`] },
      }, (res) => { res.resume(); resolve(res.statusCode); });
      req.on("error", reject);
      req.end("{");
    });
    expect(status).toBe(401);
  });

  it("rejects malformed request targets without crashing", async () => {
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = http.request(base, { path: "//[", method: "GET" }, (res) => {
        res.resume(); resolve(res.statusCode);
      });
      req.on("error", reject); req.end();
    });
    expect(status).toBe(400);
    expect((await fetch(base + "/health")).status).toBe(200);
  });

  it("leaves health public with all 19 tools", async () => {
    const response = await fetch(base + "/health");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: "ok", tools: 19 });
  });

  it("initializes and lists the unchanged 19 tools with valid credentials", async () => {
    expect((await rpc("initialize", {
      protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "auth-test", version: "1" },
    })).result.serverInfo.name).toBe("hh-mcp");
    const result = await rpc("tools/list", {});
    expect(result.result.tools.map((tool: { name: string }) => tool.name).sort()).toEqual([
      "search_vacancies", "get_vacancy", "get_similar_vacancies", "search_resumes", "get_resume",
      "search_employers", "get_employer", "get_employer_vacancies", "get_areas", "get_areas_subtree",
      "get_professional_roles", "get_industries", "get_metro", "get_dictionaries", "validate_token",
      "suggest_positions", "suggest_companies", "suggest_areas", "get_salary_statistics",
    ].sort());
  });

  it("retains the tool call and error response path", async () => {
    // Schema rejection exercises MCP without any external hh.ru request.
    const result = await rpc("tools/call", { name: "get_vacancy", arguments: {} });
    expect(result.result.isError).toBe(true);
    expect(result.result.content[0].text).toContain("vacancy_id");
  });

  it("retains DNS-rebinding protection after successful authentication", async () => {
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = http.request(base + "/mcp", {
        method: "POST", headers: {
          Authorization: `Bearer ${token}`, Host: "untrusted.example",
          Accept: "application/json, text/event-stream", "Content-Type": "application/json",
        },
      }, (res) => { res.resume(); resolve(res.statusCode); });
      req.on("error", reject);
      req.end("{}");
    });
    expect(status).toBe(403);
  });

  it("does not log parser errors containing the secret", async () => {
    const response = await request("/mcp", `Bearer ${token}`, "POST", `{"secret":"${token}", invalid}`);
    expect(response.status).toBe(500);
    await response.text();
    expect(logs).not.toContain(token);
  });

  it.each([undefined, "", "bad secret"])("fails closed at HTTP startup without a usable secret (%#)", async (secret) => {
    const { child, output } = await launch(secret);
    expect(child.exitCode).toBe(1);
    expect(output).toContain("Startup failed");
  });

  it("does not require an MCP secret in stdio mode", async () => {
    const { child, output } = await launch(undefined, []);
    expect(child.exitCode).toBeNull();
    expect(output).toContain("Server started (stdio). 19 tools.");
  });
});
