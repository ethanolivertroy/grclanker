import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

const GRCLANKER_CONFIG_DIR = ".grclanker";
const PI_CONFIG_DIR = ".pi";

export function assertIsolatedGrclankerHomePath(path: string): string {
  const segments = resolve(path).split(/[\\/]+/).filter(Boolean);
  if (segments.includes(PI_CONFIG_DIR)) {
    throw new Error(
      "grclanker refuses to use a config home under `.pi`. Unset `GRCLANKER_HOME` or point it at a separate location.",
    );
  }

  return resolve(path);
}

export function getGrclankerHome(): string {
  const configuredBase = resolve(process.env.GRCLANKER_HOME ?? homedir());
  const home = configuredBase.endsWith(GRCLANKER_CONFIG_DIR)
    ? configuredBase
    : resolve(configuredBase, GRCLANKER_CONFIG_DIR);
  return assertIsolatedGrclankerHomePath(home);
}

export function getGrclankerAgentDir(home = getGrclankerHome()): string {
  return resolve(home, "agent");
}

export function getGrclankerSettingsPath(home = getGrclankerHome()): string {
  return resolve(getGrclankerAgentDir(home), "settings.json");
}

export function getGrclankerSandboxConfigPath(home = getGrclankerHome()): string {
  return resolve(home, "sandbox.json");
}

export function getGrclankerModelsPath(home = getGrclankerHome()): string {
  return resolve(getGrclankerAgentDir(home), "models.json");
}

export function getGrclankerStateDir(home = getGrclankerHome()): string {
  return resolve(home, ".state");
}

export function getBootstrapStatePath(home = getGrclankerHome()): string {
  return resolve(getGrclankerStateDir(home), "bootstrap.json");
}

export function ensureGrclankerHome(home = getGrclankerHome()): void {
  for (const dir of [home, getGrclankerAgentDir(home), getGrclankerStateDir(home)]) {
    mkdirSync(dir, { recursive: true });
  }
}
