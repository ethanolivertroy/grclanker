import { fileURLToPath } from "node:url";
import { selectTools } from "./tools.mjs";

/**
 * @param {string[]} toolNames
 * @param {string} apiKey
 * @returns {import("@openai/codex-sdk").CodexOptions}
 */
export function buildCodexOptions(toolNames, apiKey) {
  const selectedNames = selectTools(toolNames).map((tool) => tool.name);
  return {
    apiKey,
    config: {
      mcp_servers: {
        grclanker: {
          command: process.execPath,
          args: [fileURLToPath(new URL("./mcp-server.mjs", import.meta.url)), ...selectedNames],
          // Add the names required by another integration when selecting its tools.
          env_vars: ["GITHUB_ORG", "GITHUB_TOKEN", "GH_TOKEN"],
          required: true,
          startup_timeout_sec: 30,
          tool_timeout_sec: 300,
        },
      },
    },
  };
}

/** @type {import("@openai/codex-sdk").ThreadOptions} */
export const threadOptions = {
  workingDirectory: fileURLToPath(new URL("./", import.meta.url)),
  sandboxMode: "read-only",
  approvalPolicy: "never",
};
