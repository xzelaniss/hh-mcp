// Run privately on your own machine. Output contains NEW secrets: never paste
// it into chat, GitHub, a build log or a Render Build/Start Command.
import { randomBytes, scryptSync } from "node:crypto";
if (!process.stdout.isTTY && !process.argv.includes("--allow-private-output")) {
  console.error("Run in a private interactive terminal (not CI/build logs). For a private redirected file use --allow-private-output and restrict its permissions.");
  process.exit(1);
}
const password = randomBytes(32).toString("hex");
const salt = randomBytes(16);
const digest = scryptSync(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
console.log("OWNER PASSWORD (save in your password manager; do not put this plaintext password in Render):\n" + password);
console.log("\nRENDER ENV:");
console.log("MCP_ADMIN_PASSWORD_HASH=scrypt$" + salt.toString("hex") + "$" + digest.toString("hex"));
console.log("MCP_OAUTH_CLIENT_ID=chatgpt-headhunter");
console.log("MCP_OAUTH_CLIENT_SECRET=" + randomBytes(32).toString("hex"));
