import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { basename, resolve } from "node:path";
import {
  getParallelsTemplateInfo,
  getParallelsVmInfo,
  resolveParallelsAutoStart,
  resolveParallelsBaseVmName,
  resolveParallelsClonePrefix,
  resolveParallelsSourceKind,
  resolveParallelsTemplateName,
  resolveParallelsWorkspacePath,
} from "./compute.js";
import { quoteForBash } from "./shell.js";
import type { GrclankerSettings } from "./settings.js";

export type ParallelsSandboxSession = {
  key: string;
  localRoot: string;
  sourceKind: "template" | "base-vm";
  sourceName: string;
  cloneName: string;
  shareName: string;
  workspacePath: string;
};

type PrlctlResult = {
  status: number | null;
  stdout: string;
  stderr: string;
};

const WORKSPACE_CANDIDATES = [
  (shareName: string) => `/media/psf/${shareName}`,
  (shareName: string) => `/mnt/psf/${shareName}`,
  (shareName: string) => `/Volumes/${shareName}`,
  (shareName: string) => `/Volumes/psf/${shareName}`,
] as const;

const sandboxPromises = new Map<string, Promise<ParallelsSandboxSession>>();
const activeSandboxes = new Map<string, ParallelsSandboxSession>();

let cleanupHooksInstalled = false;

function sleepSync(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function runPrlctl(args: string[]): PrlctlResult {
  const result = spawnSync("prlctl", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

  return {
    status: result.status,
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
  };
}

function formatCommandFailure(action: string, result: PrlctlResult): Error {
  const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  return new Error(`${action}. ${detail || "Check Parallels Desktop and the guest configuration."}`);
}

function sanitizeToken(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "sandbox";
}

function uniqueName(prefix: string, seed: string): string {
  const randomSuffix = randomBytes(3).toString("hex");
  return `${sanitizeToken(prefix)}-${sanitizeToken(seed)}-${Date.now()}-${randomSuffix}`;
}

function buildSessionKey(localRoot: string, settings: GrclankerSettings): string {
  return JSON.stringify({
    localRoot: resolve(localRoot),
    sourceKind: resolveParallelsSourceKind(settings),
    templateName: resolveParallelsTemplateName(settings) ?? "",
    baseVmName: resolveParallelsBaseVmName(settings) ?? "",
    clonePrefix: resolveParallelsClonePrefix(settings),
    workspacePath: resolveParallelsWorkspacePath(settings) ?? "",
  });
}

function ensureCleanupHooksInstalled(): void {
  if (cleanupHooksInstalled) return;
  cleanupHooksInstalled = true;

  const cleanup = () => {
    cleanupAllParallelsSandboxesSync();
  };

  process.once("exit", cleanup);
  process.once("SIGINT", () => {
    cleanup();
    process.exit(130);
  });
  process.once("SIGTERM", () => {
    cleanup();
    process.exit(143);
  });
}

function removeSandboxFromCache(session: ParallelsSandboxSession): void {
  activeSandboxes.delete(session.key);
  sandboxPromises.delete(session.key);
}

function cleanupSandboxSync(session: ParallelsSandboxSession): void {
  const info = getParallelsVmInfo(session.cloneName);
  if (info && info.status !== "stopped") {
    runPrlctl(["stop", session.cloneName, "--kill"]);
  }

  if (getParallelsVmInfo(session.cloneName)) {
    runPrlctl(["delete", session.cloneName]);
  }

  removeSandboxFromCache(session);
}

function cleanupAllParallelsSandboxesSync(): void {
  for (const session of [...activeSandboxes.values()]) {
    cleanupSandboxSync(session);
  }
}

function assertBaseVmIsSafe(baseVmName: string, settings: GrclankerSettings): void {
  const baseVm = getParallelsVmInfo(baseVmName);
  if (!baseVm) {
    throw new Error(`Configured Parallels base VM "${baseVmName}" was not found in \`prlctl list -a\`.`);
  }

  if (baseVm.status !== "stopped") {
    throw new Error(
      `Configured Parallels base VM "${baseVmName}" is ${baseVm.status}. Use a stopped base image or template so grclanker can clone it safely.`,
    );
  }

  if (!resolveParallelsAutoStart(settings)) {
    throw new Error(
      "Disposable Parallels sandboxes require `parallelsAutoStart=true` so grclanker can boot the fresh clone it just created.",
    );
  }
}

function assertTemplateIsUsable(templateName: string, settings: GrclankerSettings): void {
  const template = getParallelsTemplateInfo(templateName);
  if (!template) {
    throw new Error(`Configured Parallels template "${templateName}" was not found in \`prlctl list -a -t\`.`);
  }

  if (!resolveParallelsAutoStart(settings)) {
    throw new Error(
      "Disposable Parallels sandboxes require `parallelsAutoStart=true` so grclanker can boot the fresh sandbox it just created.",
    );
  }
}

function configureCloneSharing(
  cloneName: string,
  shareName: string,
  localRoot: string,
): void {
  const sharedFoldersResult = runPrlctl([
    "set",
    cloneName,
    "--shf-host",
    "on",
    "--shf-host-defined",
    "off",
    "--shf-host-automount",
    "on",
  ]);
  if (sharedFoldersResult.status !== 0) {
    throw formatCommandFailure(
      `Could not configure host folder sharing for Parallels clone "${cloneName}"`,
      sharedFoldersResult,
    );
  }

  const addShareResult = runPrlctl([
    "set",
    cloneName,
    "--shf-host-add",
    shareName,
    "--path",
    localRoot,
    "--mode",
    "rw",
  ]);
  if (addShareResult.status !== 0) {
    throw formatCommandFailure(
      `Could not attach repo share "${shareName}" to Parallels clone "${cloneName}"`,
      addShareResult,
    );
  }

  runPrlctl(["set", cloneName, "--smart-mount", "off"]);
  runPrlctl(["set", cloneName, "--shared-clipboard", "off", "--shared-cloud", "off"]);
}

function execInClone(cloneName: string, command: string): PrlctlResult {
  return runPrlctl([
    "exec",
    cloneName,
    "--current-user",
    "bash",
    "-lc",
    command,
  ]);
}

function resolveWorkspaceCandidates(
  shareName: string,
  configuredPath: string | undefined,
): string[] {
  const candidates = [
    configuredPath,
    ...WORKSPACE_CANDIDATES.map((candidate) => candidate(shareName)),
  ];

  return [...new Set(candidates.filter((candidate): candidate is string => Boolean(candidate)))];
}

function waitForWorkspaceMount(
  cloneName: string,
  candidates: string[],
): string {
  const deadline = Date.now() + 45_000;
  let lastError: string | undefined;

  while (Date.now() < deadline) {
    for (const candidate of candidates) {
      const check = execInClone(
        cloneName,
        `if test -d ${quoteForBash(candidate)}; then printf ok; else printf missing; fi`,
      );

      if (check.status === 0 && check.stdout.trim() === "ok") {
        return candidate;
      }

      if (check.status !== 0) {
        lastError = [check.stdout, check.stderr].filter(Boolean).join("\n").trim() || lastError;
      }
    }

    sleepSync(1_500);
  }

  const candidateSummary = candidates.map((candidate) => `  - ${candidate}`).join("\n");
  const detail = lastError ? `\n\nLast guest execution error:\n${lastError}` : "";
  throw new Error(
    [
      `Could not locate the repo inside disposable Parallels clone "${cloneName}".`,
      "grclanker attached the host repo as a shared folder, but none of the expected guest mount paths became available:",
      candidateSummary,
      "",
      "Set `parallelsWorkspacePath` if your guest mounts host shares somewhere else, and make sure Parallels Tools plus guest shell execution are working in the base image.",
      detail,
    ].join("\n"),
  );
}

function createParallelsSandbox(
  localRoot: string,
  settings: GrclankerSettings,
): ParallelsSandboxSession {
  const sourceKind = resolveParallelsSourceKind(settings);
  const sourceName = sourceKind === "template"
    ? resolveParallelsTemplateName(settings)
    : resolveParallelsBaseVmName(settings);
  if (!sourceName) {
    throw new Error(
      sourceKind === "template"
        ? "Parallels sandboxing requires `parallelsTemplateName` so grclanker knows which template to deploy sandboxes from."
        : "Parallels sandboxing requires `parallelsBaseVmName` so grclanker knows which stopped base VM to clone.",
    );
  }

  if (sourceKind === "template") {
    assertTemplateIsUsable(sourceName, settings);
  } else {
    assertBaseVmIsSafe(sourceName, settings);
  }

  const normalizedRoot = resolve(localRoot);
  const repoToken = sanitizeToken(basename(normalizedRoot));
  const cloneName = uniqueName(resolveParallelsClonePrefix(settings), repoToken);
  const shareName = sanitizeToken(`grclanker-workspace-${repoToken}`);
  const sessionKey = buildSessionKey(localRoot, settings);

  let createdClone = false;
  try {
    const cloneResult = sourceKind === "template"
      ? runPrlctl(["create", cloneName, "--ostemplate", sourceName])
      : runPrlctl(["clone", sourceName, "--name", cloneName]);
    if (cloneResult.status !== 0) {
      throw formatCommandFailure(
        sourceKind === "template"
          ? `Could not create disposable Parallels sandbox "${cloneName}" from template "${sourceName}"`
          : `Could not clone Parallels base VM "${sourceName}" into disposable sandbox "${cloneName}"`,
        cloneResult,
      );
    }
    createdClone = true;

    configureCloneSharing(cloneName, shareName, normalizedRoot);

    const startResult = runPrlctl(["start", cloneName]);
    if (startResult.status !== 0) {
      throw formatCommandFailure(
        `Could not start disposable Parallels sandbox "${cloneName}"`,
        startResult,
      );
    }

    const workspacePath = waitForWorkspaceMount(
      cloneName,
      resolveWorkspaceCandidates(shareName, resolveParallelsWorkspacePath(settings)),
    );

    const session: ParallelsSandboxSession = {
      key: sessionKey,
      localRoot: normalizedRoot,
      sourceKind,
      sourceName,
      cloneName,
      shareName,
      workspacePath,
    };
    activeSandboxes.set(sessionKey, session);
    return session;
  } catch (error) {
    if (createdClone) {
      cleanupSandboxSync({
        key: sessionKey,
        localRoot: normalizedRoot,
        sourceKind,
        sourceName,
        cloneName,
        shareName,
        workspacePath: resolveParallelsWorkspacePath(settings) ?? "",
      });
    }
    throw error;
  }
}

export async function ensureParallelsSandbox(
  localRoot: string,
  settings: GrclankerSettings,
): Promise<ParallelsSandboxSession> {
  ensureCleanupHooksInstalled();
  const key = buildSessionKey(localRoot, settings);
  const existing = sandboxPromises.get(key);
  if (existing) return existing;

  const created = Promise.resolve().then(() => createParallelsSandbox(localRoot, settings));
  sandboxPromises.set(key, created);

  try {
    return await created;
  } catch (error) {
    sandboxPromises.delete(key);
    throw error;
  }
}

export async function cleanupParallelsSandboxes(): Promise<void> {
  cleanupAllParallelsSandboxesSync();
}
