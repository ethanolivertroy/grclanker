import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { getBootstrapStatePath } from "../config/paths.js";
import { commitFileTransactionSync, recoverFileTransactionSync, type FileReplacement, type FileTransactionOptions } from "../core/atomic-files.js";

type BootstrapRecord = {
  lastAppliedSourceHash: string;
  lastAppliedTargetHash: string;
};

type BootstrapState = {
  version: 1;
  files: Record<string, BootstrapRecord>;
};

export type BootstrapSyncResult = {
  copied: string[];
  updated: string[];
  skipped: string[];
};

function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function readBootstrapState(path: string): BootstrapState {
  if (!existsSync(path)) {
    return { version: 1, files: {} };
  }

  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as BootstrapState;
    return {
      version: 1,
      files: parsed.files && typeof parsed.files === "object" ? parsed.files : {},
    };
  } catch {
    return { version: 1, files: {} };
  }
}

function listFiles(root: string): string[] {
  if (!existsSync(root)) return [];

  const files: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = resolve(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(path));
      continue;
    }
    if (entry.isFile()) {
      files.push(path);
    }
  }
  return files.sort();
}

function removeEmptyParentDirectories(path: string, stopAt: string): void {
  let current = dirname(path);
  while (current.startsWith(stopAt) && current !== stopAt) {
    if (!existsSync(current)) {
      current = dirname(current);
      continue;
    }
    if (readdirSync(current).length > 0) {
      return;
    }
    rmSync(current, { recursive: true, force: true });
    current = dirname(current);
  }
}

function syncManagedFiles(
  sourceRoot: string,
  targetRoot: string,
  scope: string,
  state: BootstrapState,
  result: BootstrapSyncResult,
  replacements: FileReplacement[],
): void {
  const sourcePaths = new Set(listFiles(sourceRoot).map((sourcePath) => relative(sourceRoot, sourcePath)));

  for (const targetPath of listFiles(targetRoot)) {
    const key = relative(targetRoot, targetPath);
    if (sourcePaths.has(key)) continue;

    const scopedKey = `${scope}:${key}`;
    const previous = state.files[scopedKey] ?? state.files[key];
    if (!previous) continue;

    const currentTargetData = readFileSync(targetPath);
    if (sha256(currentTargetData) !== previous.lastAppliedTargetHash) {
      result.skipped.push(key);
      continue;
    }

    replacements.push({ path: targetPath, data: null });
    delete state.files[scopedKey];
    delete state.files[key];
  }

  for (const sourcePath of listFiles(sourceRoot)) {
    const key = relative(sourceRoot, sourcePath);
    const targetPath = resolve(targetRoot, key);
    const sourceData = readFileSync(sourcePath);
    const sourceHash = sha256(sourceData);
    const scopedKey = `${scope}:${key}`;
    const previous = state.files[scopedKey] ?? state.files[key];

    if (!existsSync(targetPath)) {
      replacements.push({ path: targetPath, data: sourceData });
      state.files[scopedKey] = {
        lastAppliedSourceHash: sourceHash,
        lastAppliedTargetHash: sourceHash,
      };
      delete state.files[key];
      result.copied.push(key);
      continue;
    }

    const currentTargetData = readFileSync(targetPath);
    const currentTargetHash = sha256(currentTargetData);

    if (currentTargetHash === sourceHash) {
      state.files[scopedKey] = {
        lastAppliedSourceHash: sourceHash,
        lastAppliedTargetHash: currentTargetHash,
      };
      delete state.files[key];
      continue;
    }

    if (!previous || currentTargetHash !== previous.lastAppliedTargetHash) {
      result.skipped.push(key);
      continue;
    }

    replacements.push({ path: targetPath, data: sourceData });
    state.files[scopedKey] = {
      lastAppliedSourceHash: sourceHash,
      lastAppliedTargetHash: sourceHash,
    };
    delete state.files[key];
    result.updated.push(key);
  }
}

export function syncBundledAssets(
  appRoot: string,
  agentDir: string,
  persistence: Pick<FileTransactionOptions, "beforeCommit"> = {},
): BootstrapSyncResult {
  const statePath = getBootstrapStatePath();
  const journalPath = `${statePath}.transaction.json`;
  recoverFileTransactionSync(journalPath);
  const state = readBootstrapState(statePath);
  const result: BootstrapSyncResult = { copied: [], updated: [], skipped: [] };
  const replacements: FileReplacement[] = [];

  syncManagedFiles(resolve(appRoot, ".grclanker", "themes"), resolve(agentDir, "themes"), "themes", state, result, replacements);
  syncManagedFiles(resolve(appRoot, ".grclanker", "agents"), resolve(agentDir, "agents"), "agents", state, result, replacements);
  syncManagedFiles(resolve(appRoot, "skills"), resolve(agentDir, "skills"), "skills", state, result, replacements);

  const serialized = JSON.stringify(state, null, 2) + "\n";
  if (!existsSync(statePath) || readFileSync(statePath, "utf8") !== serialized) {
    replacements.push({ path: statePath, data: serialized, mode: 0o600 });
  }
  if (replacements.length > 0) commitFileTransactionSync(replacements, { journalPath, ...persistence });
  for (const replacement of replacements) {
    if (replacement.data === null) removeEmptyParentDirectories(replacement.path, agentDir);
  }
  return result;
}
