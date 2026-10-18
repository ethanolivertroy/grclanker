import { existsSync, lstatSync, mkdirSync, readlinkSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, resolve } from "node:path";

const GRCLANKER_CONFIG_DIR = ".grclanker";
const PI_CONFIG_DIR = ".pi";

function pathSegments(path: string): string[] {
  return path.split(/[\\/]+/).filter(Boolean);
}

// Resolve through symlinks, including ones that sit above a directory that does
// not exist yet, so a `~/.grclanker` link into `~/.pi` is visible before mkdir.
function canonicalPath(path: string, seen = new Set<string>()): string {
  const resolved = resolve(path);
  if (seen.has(resolved)) return resolved;
  seen.add(resolved);

  try {
    return realpathSync(resolved);
  } catch {
    // Missing path or a broken symlink. Walk the parents below.
  }

  const missing: string[] = [];
  let current = resolved;
  while (true) {
    let isLink = false;
    try {
      isLink = lstatSync(current).isSymbolicLink();
    } catch {
      isLink = false;
    }
    if (isLink) {
      const target = canonicalPath(resolve(dirname(current), readlinkSync(current)), seen);
      let canonical = target;
      for (const segment of missing.reverse()) canonical = resolve(canonical, segment);
      return canonical;
    }
    if (existsSync(current)) {
      let canonical: string;
      try {
        canonical = realpathSync(current);
      } catch {
        canonical = current;
      }
      for (const segment of missing.reverse()) canonical = resolve(canonical, segment);
      return canonical;
    }
    const parent = dirname(current);
    if (parent === current) return resolved;
    missing.push(basename(current));
    current = parent;
  }
}

function isUnderPiConfig(path: string): boolean {
  return pathSegments(path).includes(PI_CONFIG_DIR);
}

export function assertIsolatedGrclankerHomePath(path: string): string {
  const resolved = resolve(path);
  if (isUnderPiConfig(resolved) || isUnderPiConfig(canonicalPath(resolved))) {
    throw new Error(
      "grclanker refuses to use a config home under `.pi`. Unset `GRCLANKER_HOME` or point it at a separate location.",
    );
  }

  return resolved;
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
