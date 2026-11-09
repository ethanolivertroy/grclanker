// Replace only the launch entry point, while exercising Pi's real import-time
// binary cache path. Earlier eager imports of Pi keep their real module graph.
const TOOLS_MANAGER_URL = new URL("../../node_modules/@earendil-works/pi-coding-agent/dist/utils/tools-manager.js", import.meta.url).href;
const MOCK_URL = "grclanker-pi-binary-cache-mock:main";
const MOCK_SOURCE = `
  import { writeFileSync } from "node:fs";
  import { getToolPath } from ${JSON.stringify(TOOLS_MANAGER_URL)};
  export async function main() {
    writeFileSync(process.env.GRCLANKER_TEST_PI_LAUNCH_RECORD, JSON.stringify({
      fd: getToolPath("fd"),
      agentDir: process.env.GRCLANKER_CODING_AGENT_DIR,
    }));
  }
`;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === "@earendil-works/pi-coding-agent" && context.parentURL?.endsWith("/dist/pi/launch.js")) {
    return { url: MOCK_URL, shortCircuit: true };
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (url !== MOCK_URL) return nextLoad(url, context);
  return { format: "module", shortCircuit: true, source: MOCK_SOURCE };
}
