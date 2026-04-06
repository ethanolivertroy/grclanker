import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { getBootstrapStatePath } from "../config/paths.js";

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

function writeBootstrapState(path: string, state: BootstrapState): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(state, null, 2) + "\n", "utf8");
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

    rmSync(targetPath, { force: true });
    removeEmptyParentDirectories(targetPath, targetRoot);
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

    mkdirSync(dirname(targetPath), { recursive: true });

    if (!existsSync(targetPath)) {
      writeFileSync(targetPath, sourceData);
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

    writeFileSync(targetPath, sourceData);
    state.files[scopedKey] = {
      lastAppliedSourceHash: sourceHash,
      lastAppliedTargetHash: sourceHash,
    };
    delete state.files[key];
    result.updated.push(key);
  }
}

export function syncBundledAssets(appRoot: string, agentDir: string): BootstrapSyncResult {
  const statePath = getBootstrapStatePath();
  const state = readBootstrapState(statePath);
  const result: BootstrapSyncResult = { copied: [], updated: [], skipped: [] };

  syncManagedFiles(resolve(appRoot, ".grclanker", "themes"), resolve(agentDir, "themes"), "themes", state, result);
  syncManagedFiles(resolve(appRoot, ".grclanker", "agents"), resolve(agentDir, "agents"), "agents", state, result);
  syncManagedFiles(resolve(appRoot, "skills"), resolve(agentDir, "skills"), "skills", state, result);

  writeBootstrapState(statePath, state);
  return result;
}
