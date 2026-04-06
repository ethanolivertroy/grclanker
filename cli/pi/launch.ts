import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { syncBundledAssets } from "../bootstrap/sync.js";
import {
  ensureGrclankerHome,
  getGrclankerAgentDir,
  getGrclankerSettingsPath,
} from "../config/paths.js";
import { assertEmbeddedPiBranding } from "./branding.js";
import {
  type GrclankerSettings,
  normalizeGrclankerSettings,
  readGrclankerSettings,
  resolveSkillDiscoveryMode,
} from "./settings.js";
import { resolveComputeBackend } from "./compute.js";
import { ensureCliConfigured, runSetupWizard } from "./setup.js";

function resolveExtensionEntrypoint(appRoot: string): string {
  const compiledPath = resolve(appRoot, "dist", "extensions", "grc-tools.js");
  if (existsSync(compiledPath)) {
    return compiledPath;
  }

  return resolve(appRoot, "extensions", "grc-tools.ts");
}

export function prepareCliRuntime(appRoot: string): {
  agentDir: string;
  settingsPath: string;
} {
  assertEmbeddedPiBranding(appRoot);
  ensureGrclankerHome();

  const agentDir = getGrclankerAgentDir();
  syncBundledAssets(appRoot, agentDir);
  const settingsPath = getGrclankerSettingsPath();
  normalizeGrclankerSettings(settingsPath, resolve(appRoot, ".grclanker", "settings.json"));

  return { agentDir, settingsPath };
}

export async function runCliSetup(appRoot: string): Promise<void> {
  prepareCliRuntime(appRoot);
  await runSetupWizard(true);
}

export function buildCliLaunchArgs(
  appRoot: string,
  agentDir: string,
  settings: GrclankerSettings,
  workflow?: string,
): string[] {
  const args: string[] = [];
  if (
    settings.modelMode === "local" &&
    typeof settings.defaultProvider === "string" &&
    typeof settings.defaultModel === "string"
  ) {
    args.push("--model", `${settings.defaultProvider}/${settings.defaultModel}`);
  }
  if (resolveSkillDiscoveryMode(settings) === "bundled-only") {
    args.push("--no-skills");
    args.push("--skill", resolve(agentDir, "skills"));
  }
  args.push("--extension", resolveExtensionEntrypoint(appRoot));
  args.push("--prompt-template", resolve(appRoot, "prompts"));
  args.push("--system-prompt", readFileSync(resolve(appRoot, ".grclanker", "SYSTEM.md"), "utf8"));

  if (workflow) {
    const promptPath = join(appRoot, "prompts", `${workflow}.md`);
    if (!existsSync(promptPath)) {
      console.error(`Workflow prompt not found: ${promptPath}`);
      process.exit(1);
    }
    args.push(readFileSync(promptPath, "utf8"));
  }

  return args;
}

export async function launchCli(
  appRoot: string,
  workflow?: string,
): Promise<void> {
  const workingDir = process.cwd();
  const { agentDir, settingsPath } = prepareCliRuntime(appRoot);
  await ensureCliConfigured();
  const settings = readGrclankerSettings(settingsPath);
  const args = buildCliLaunchArgs(appRoot, agentDir, settings, workflow);

  process.env.GRCLANKER_CODING_AGENT_DIR = agentDir;
  process.env.GRCLANKER_COMPUTE_BACKEND = resolveComputeBackend(settings);
  process.env.PI_SKIP_VERSION_CHECK ??= "1";
  process.chdir(workingDir);

  const { main } = await import("@mariozechner/pi-coding-agent");
  await main(args);
}
