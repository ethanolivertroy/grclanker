import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { runComputeDoctor } from "./pi/doctor.js";
import { runComputeExec, runComputeList, runComputeSmokeTest } from "./pi/env.js";
import { launchCli, runCliSetup } from "./pi/launch.js";
import { routeCliInvocation } from "./pi/cli-routing.js";
import { GrclankerUserError } from "./pi/setup.js";
import type { ComputeBackendKind } from "./pi/compute.js";
import {
  findRegisteredTool,
  formatToolCatalogText,
  formatToolDetailText,
  getRegisteredToolSummaries,
} from "./pi/tool-catalog.js";

process.title = "grclanker";

function resolveAppRoot(currentDir: string): string {
  if (existsSync(resolve(currentDir, "package.json"))) {
    return currentDir;
  }

  const parentDir = resolve(currentDir, "..");
  if (existsSync(resolve(parentDir, "package.json"))) {
    return parentDir;
  }

  return currentDir;
}

const appRoot = resolveAppRoot(import.meta.dirname);

const commands: Record<string, (compute?: ComputeBackendKind, prompt?: string) => Promise<void>> = {
  setup: (compute) => runCliSetup(appRoot, compute),
  investigate: (compute, prompt) => launchCli(appRoot, "investigate", compute, prompt),
  audit: (compute, prompt) => launchCli(appRoot, "audit", compute, prompt),
  assess: (compute, prompt) => launchCli(appRoot, "assess", compute, prompt),
  validate: (compute, prompt) => launchCli(appRoot, "validate", compute, prompt),
};

function printHelp() {
  console.log(`
grclanker

Usage:
  grclanker                     Interactive GRC CLI
  grclanker setup               Configure local-first or hosted model access
  grclanker setup --compute <k> Save <kind> as the preferred compute backend
  grclanker env list            List every compute backend, bucket, and readiness
  grclanker env doctor          Check compute backend availability
  grclanker env smoke-test      Validate the selected backend end-to-end
  grclanker env exec -- <cmd>   Run a shell command on the selected backend
  grclanker tools               List bundled GRC and compute tools
  grclanker flue run -m <text>  Run the same GRC agent under the Flue Framework runtime
  grclanker investigate         Trace crypto status, KEVs, and exploitability
  grclanker audit               Map evidence against a requested framework
  grclanker assess              Produce a posture readout and remediation order
  grclanker validate            Answer a narrow FIPS validation question
  ... --compute <kind>          Run investigate/audit/assess/validate on a specific backend
                                (interactive mode uses the backend saved by setup --compute)

Install:
  curl -fsSL https://grclanker.com/install | bash
  powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install.ps1 | iex"

Recommended next step after install:
  grclanker setup

Options:
  --help, -h                    Show this help
`);
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const subcommand = args[1];

  if (command === "--help" || command === "-h") {
    printHelp();
    return;
  }

  if (command === "env" && subcommand === "doctor") {
    await runComputeDoctor();
    return;
  }

  if (command === "env" && subcommand === "list") {
    await runComputeList(args.slice(2));
    return;
  }

  if (command === "env" && subcommand === "smoke-test") {
    await runComputeSmokeTest(args.slice(2));
    return;
  }

  if (command === "env" && subcommand === "exec") {
    await runComputeExec(args.slice(2));
    return;
  }

  if (command === "flue") {
    // Loaded lazily so the Pi-based CLI path never pays for the Flue runtime.
    const { runFlueCommand } = await import("./flue/cli.js");
    const exitCode = await runFlueCommand(args.slice(1));
    if (exitCode !== 0) process.exit(exitCode);
    return;
  }

  if (command === "tools") {
    const tools = getRegisteredToolSummaries();
    const toolArgs = args.slice(1);
    const asJson = toolArgs.includes("--json");
    const toolName = toolArgs.find((arg) => arg !== "--json");

    if (toolName) {
      const tool = findRegisteredTool(tools, toolName);
      if (!tool) {
        console.error(`Unknown tool: ${toolName}`);
        console.error("Run 'grclanker tools' to list bundled tools.");
        process.exit(1);
      }
      console.log(asJson ? JSON.stringify(tool, null, 2) : formatToolDetailText(tool));
    } else if (asJson) {
      console.log(JSON.stringify(tools, null, 2));
    } else {
      console.log(formatToolCatalogText(tools));
    }
    return;
  }

  const invocation = routeCliInvocation(args, Object.keys(commands));
  if (invocation.kind === "unknown-option") {
    console.error(`Unknown command: ${invocation.command}`);
    console.error("Run 'grclanker --help' for usage.");
    process.exit(1);
  }

  if (invocation.kind === "command") {
    await commands[invocation.command]!(invocation.compute, invocation.prompt);
    return;
  }

  await launchCli(appRoot, undefined, invocation.compute, invocation.prompt);
}

main().catch((error) => {
  if (error instanceof GrclankerUserError) {
    console.error(error.message);
    process.exit(1);
  }
  console.error(error);
  process.exit(1);
});
