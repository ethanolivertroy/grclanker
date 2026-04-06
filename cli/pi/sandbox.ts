import { constants, existsSync, readFileSync, realpathSync } from "node:fs";
import {
  access,
  mkdir,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { minimatch } from "minimatch";
import {
  SandboxManager,
  type SandboxRuntimeConfig,
} from "@anthropic-ai/sandbox-runtime";
import { getGrclankerSandboxConfigPath } from "../config/paths.js";

export type GrclankerSandboxConfig = SandboxRuntimeConfig & {
  enabled?: boolean;
};

const DEFAULT_CONFIG: GrclankerSandboxConfig = {
  enabled: true,
  network: {
    allowedDomains: [
      "github.com",
      "*.github.com",
      "api.github.com",
      "raw.githubusercontent.com",
      "npmjs.org",
      "*.npmjs.org",
      "registry.npmjs.org",
      "registry.yarnpkg.com",
      "pypi.org",
      "*.pypi.org",
    ],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: ["~/.ssh", "~/.aws", "~/.gnupg"],
    allowWrite: [".", "/tmp"],
    denyWrite: [".env", ".env.*", "*.pem", "*.key"],
  },
};

let initializedForCwd: string | undefined;
let initializationPromise: Promise<void> | undefined;

function deepMergeConfig(
  base: GrclankerSandboxConfig,
  overrides: Partial<GrclankerSandboxConfig>,
): GrclankerSandboxConfig {
  return {
    ...base,
    ...overrides,
    network: {
      ...base.network,
      ...overrides.network,
    },
    filesystem: {
      ...base.filesystem,
      ...overrides.filesystem,
    },
  };
}

function readConfigFile(path: string): Partial<GrclankerSandboxConfig> {
  if (!existsSync(path)) return {};
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Partial<GrclankerSandboxConfig>;
  } catch {
    return {};
  }
}

export function getProjectSandboxConfigPath(cwd: string): string {
  return resolve(cwd, ".grclanker", "sandbox.json");
}

export function loadSandboxConfig(cwd: string): GrclankerSandboxConfig {
  return deepMergeConfig(
    deepMergeConfig(DEFAULT_CONFIG, readConfigFile(getGrclankerSandboxConfigPath())),
    readConfigFile(getProjectSandboxConfigPath(cwd)),
  );
}

function expandHome(value: string): string {
  if (value === "~") return homedir();
  if (value.startsWith("~/")) return resolve(homedir(), value.slice(2));
  return value;
}

function hasGlob(value: string): boolean {
  return /[*?[{]/.test(value);
}

function isWithin(basePath: string, absolutePath: string): boolean {
  return absolutePath === basePath || absolutePath.startsWith(`${basePath}${sep}`);
}

function canonicalizePath(targetPath: string): string {
  const absolutePath = resolve(targetPath);

  if (existsSync(absolutePath)) {
    return realpathSync(absolutePath);
  }

  let existingParent = dirname(absolutePath);
  while (!existsSync(existingParent)) {
    const nextParent = dirname(existingParent);
    if (nextParent === existingParent) {
      return absolutePath;
    }
    existingParent = nextParent;
  }

  const canonicalParent = realpathSync(existingParent);
  const suffix = relative(existingParent, absolutePath);
  return suffix.length > 0 ? resolve(canonicalParent, suffix) : canonicalParent;
}

function matchesRule(absolutePath: string, rule: string, cwd: string): boolean {
  const normalizedPath = canonicalizePath(absolutePath);
  const normalizedCwd = canonicalizePath(cwd);
  const expandedRule = expandHome(rule);

  if (expandedRule === ".") {
    return isWithin(normalizedCwd, normalizedPath);
  }

  if (expandedRule.startsWith("/")) {
    const absoluteRule = canonicalizePath(expandedRule);
    return hasGlob(expandedRule)
      ? minimatch(normalizedPath, absoluteRule, { dot: true, matchBase: true })
      : isWithin(absoluteRule, normalizedPath);
  }

  if (!hasGlob(expandedRule)) {
    return isWithin(canonicalizePath(resolve(normalizedCwd, expandedRule)), normalizedPath);
  }

  const relativePath = relative(normalizedCwd, normalizedPath).split(sep).join("/");
  return minimatch(relativePath, expandedRule, { dot: true, matchBase: true });
}

function assertReadAllowed(
  absolutePath: string,
  cwd: string,
  config: GrclankerSandboxConfig,
): void {
  for (const denied of config.filesystem.denyRead) {
    if (matchesRule(absolutePath, denied, cwd)) {
      throw new Error(`Sandbox denied read access to ${basename(absolutePath)}.`);
    }
  }
}

function assertWriteAllowed(
  absolutePath: string,
  cwd: string,
  config: GrclankerSandboxConfig,
): void {
  const allowed = config.filesystem.allowWrite.some((allowedRule) =>
    matchesRule(absolutePath, allowedRule, cwd),
  );
  if (!allowed) {
    throw new Error(`Sandbox denied write access to ${absolutePath}.`);
  }

  for (const denied of config.filesystem.denyWrite) {
    if (matchesRule(absolutePath, denied, cwd)) {
      throw new Error(`Sandbox denied write access to ${basename(absolutePath)}.`);
    }
  }
}

export async function ensureSandboxReady(cwd: string): Promise<GrclankerSandboxConfig> {
  const config = loadSandboxConfig(cwd);
  if (!config.enabled) {
    return config;
  }

  if (initializedForCwd === cwd) {
    if (initializationPromise) await initializationPromise;
    return config;
  }

  initializationPromise = SandboxManager.initialize(config)
    .then(() => {
      initializedForCwd = cwd;
    });
  await initializationPromise;
  return config;
}

export async function resetSandboxRuntime(): Promise<void> {
  if (!initializationPromise && !initializedForCwd) return;
  try {
    await SandboxManager.reset();
  } finally {
    initializationPromise = undefined;
    initializedForCwd = undefined;
  }
}

export async function wrapCommandWithSandbox(command: string, cwd: string): Promise<string> {
  const config = await ensureSandboxReady(cwd);
  if (!config.enabled) return command;
  return SandboxManager.wrapWithSandbox(command);
}

export function createSandboxReadOperations(cwd: string) {
  const config = loadSandboxConfig(cwd);
  return {
    readFile: async (absolutePath: string) => {
      assertReadAllowed(absolutePath, cwd, config);
      return readFile(absolutePath);
    },
    access: async (absolutePath: string) => {
      assertReadAllowed(absolutePath, cwd, config);
      await access(absolutePath, constants.R_OK);
    },
    detectImageMimeType: async (_absolutePath: string) => null,
  };
}

export function createSandboxWriteOperations(cwd: string) {
  const config = loadSandboxConfig(cwd);
  return {
    writeFile: async (absolutePath: string, content: string) => {
      assertWriteAllowed(absolutePath, cwd, config);
      await writeFile(absolutePath, content, "utf8");
    },
    mkdir: async (dir: string) => {
      assertWriteAllowed(dir, cwd, config);
      await mkdir(dir, { recursive: true });
    },
  };
}

export function createSandboxEditOperations(cwd: string) {
  const readOps = createSandboxReadOperations(cwd);
  const writeOps = createSandboxWriteOperations(cwd);
  return {
    readFile: readOps.readFile,
    writeFile: writeOps.writeFile,
    access: async (absolutePath: string) => {
      await readOps.access(absolutePath);
      assertWriteAllowed(absolutePath, cwd, loadSandboxConfig(cwd));
      await access(absolutePath, constants.W_OK);
    },
  };
}

export function createSandboxLsOperations(cwd: string) {
  const config = loadSandboxConfig(cwd);
  return {
    exists: async (absolutePath: string) => {
      try {
        assertReadAllowed(absolutePath, cwd, config);
        await access(absolutePath, constants.F_OK);
        return true;
      } catch {
        return false;
      }
    },
    stat: async (absolutePath: string) => {
      assertReadAllowed(absolutePath, cwd, config);
      return stat(absolutePath);
    },
    readdir: async (absolutePath: string) => {
      assertReadAllowed(absolutePath, cwd, config);
      return readdir(absolutePath);
    },
  };
}
