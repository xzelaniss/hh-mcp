import { randomBytes } from "node:crypto";
import { auth, type OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { expect, it } from "vitest";
import { createHttpAuth } from "../auth.js";

it("interoperates with the standard MCP OAuth client using static credentials, resource and PKCE S256", async () => {
  const issuer = "https://tenant.auth0.com/";
  const serverUrl = "https://hh.example/mcp";
  const metadataUrl = new URL("https://hh.example/.well-known/oauth-protected-resource/mcp");
  const secret = randomBytes(32).toString("hex");
  const metadata = createHttpAuth({
    MCP_AUTH_MODE: "oauth", MCP_PUBLIC_URL: "https://hh.example", MCP_OAUTH_ISSUER: issuer,
    MCP_OAUTH_CLIENT_ID: "test-client", MCP_OAUTH_ALLOWED_SUBJECTS: "auth0|owner",
  }).metadata;
  let verifier = "";
  let redirect: URL | undefined;
  let savedToken: string | undefined;
  let exchanges = 0;
  const provider: OAuthClientProvider = {
    redirectUrl: "https://chatgpt.com/connector_platform_oauth_redirect",
    clientMetadata: {
      redirect_uris: ["https://chatgpt.com/connector_platform_oauth_redirect"],
      token_endpoint_auth_method: "client_secret_post", grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    },
    clientInformation: () => ({ client_id: "test-client", client_secret: secret, issuer, token_endpoint_auth_method: "client_secret_post" }),
    tokens: () => undefined,
    saveTokens: (tokens) => { savedToken = tokens.access_token; },
    redirectToAuthorization: (url) => { redirect = url; },
    saveCodeVerifier: (value) => { verifier = value; },
    codeVerifier: () => verifier,
    state: () => "test-state",
  };
  // Simulate Auth0 discovery/code exchange only: this is not a live Auth0 test.
  const fetchFn: typeof fetch = async (input, options) => {
    const url = String(input);
    if (url === metadataUrl.href) return Response.json(metadata);
    if (url === issuer + ".well-known/oauth-authorization-server" || url === issuer + ".well-known/openid-configuration") {
      return Response.json({
        issuer, authorization_endpoint: issuer + "authorize", token_endpoint: issuer + "oauth/token",
        response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["client_secret_post"],
      });
    }
    if (url === issuer + "oauth/token") {
      const params = new URLSearchParams(options?.body as URLSearchParams);
      expect(params.get("grant_type")).toBe("authorization_code");
      expect(params.get("client_id")).toBe("test-client");
      expect(params.get("client_secret")).toBe(secret);
      expect(params.get("code_verifier")).toBe(verifier);
      expect(params.get("resource")).toBe(serverUrl);
      exchanges++;
      return Response.json({ access_token: "simulated-access-token", token_type: "Bearer", expires_in: 3600 });
    }
    throw new Error("Unexpected discovery URL");
  };
  const options = { serverUrl, resourceMetadataUrl: metadataUrl, fetchFn };
  expect(await auth(provider, options)).toBe("REDIRECT");
  expect(redirect?.origin + redirect!.pathname).toBe(issuer + "authorize");
  expect(redirect?.searchParams.get("resource")).toBe(serverUrl);
  expect(redirect?.searchParams.get("code_challenge_method")).toBe("S256");
  expect(redirect?.searchParams.get("code_challenge")).toBeTruthy();
  expect(redirect?.searchParams.get("scope")?.split(" ")).toEqual(expect.arrayContaining(["mcp:tools", "offline_access"]));
  expect(verifier.length).toBeGreaterThanOrEqual(43);
  expect(await auth(provider, { ...options, authorizationCode: "simulated-code" })).toBe("AUTHORIZED");
  expect(exchanges).toBe(1);
  expect(savedToken).toBe("simulated-access-token");
});
