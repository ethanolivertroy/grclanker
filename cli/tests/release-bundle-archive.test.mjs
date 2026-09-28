import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createArchive,
  findPythonCommand,
  resolveSourceDateEpoch,
} from "../scripts/build-native-bundle.mjs";

const EPOCH = 1_700_000_000;
const gnuTar = /GNU tar/.test(spawnSync("tar", ["--version"], { encoding: "utf8" }).stdout ?? "");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function stageBundle(root, mtime) {
  const bundle = join(root, "bundle");
  mkdirSync(join(bundle, "app", "bin"), { recursive: true });
  mkdirSync(join(bundle, "node", "bin"), { recursive: true });
  writeFileSync(join(bundle, "node", "bin", "node"), "#!/bin/sh\n");
  chmodSync(join(bundle, "node", "bin", "node"), 0o755);
  writeFileSync(join(bundle, "app", "bin", "grclanker.js"), "console.log('hi');\n");
  writeFileSync(join(bundle, "grclanker"), "#!/usr/bin/env bash\n");
  chmodSync(join(bundle, "grclanker"), 0o755);
  if (process.platform !== "win32") {
    symlinkSync("node", join(bundle, "node", "bin", "nodejs"));
  }
  for (const path of [join(bundle, "grclanker"), join(bundle, "app", "bin", "grclanker.js"), join(bundle, "app")]) {
    utimesSync(path, mtime, mtime);
  }
  return bundle;
}

function buildTwice(archiveExt, options) {
  const workspace = mkdtempSync(join(tmpdir(), "grclanker-archive-test-"));
  try {
    const first = join(workspace, `first.${archiveExt}`);
    const second = join(workspace, `second.${archiveExt}`);
    createArchive(stageBundle(join(workspace, "a"), new Date("2020-01-01T00:00:00Z")), first, archiveExt, options);
    createArchive(stageBundle(join(workspace, "b"), new Date("2024-06-15T12:34:56Z")), second, archiveExt, options);
    return { first: sha256(first), second: sha256(second), listing: listArchive(first, archiveExt) };
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

function listArchive(path, archiveExt) {
  if (archiveExt === "zip") {
    return "";
  }
  return spawnSync("tar", ["-tvzf", path], { encoding: "utf8" }).stdout;
}

test("tar.gz bundles are byte-identical regardless of staging mtimes", { skip: !gnuTar && "requires GNU tar" }, () => {
  const { first, second, listing } = buildTwice("tar.gz", { epoch: EPOCH });
  assert.equal(first, second);
  assert.match(listing, /\s0\/0\s/);
  assert.doesNotMatch(listing, /\b2020-01-01\b|\b2024-06-15\b/);
  assert.match(listing, /-rwxr-xr-x .*\.\/grclanker\n/);
});

test("zip bundles are byte-identical regardless of staging mtimes", (t) => {
  let pythonCommand;
  try {
    pythonCommand = findPythonCommand();
  } catch {
    t.skip("requires python for zip creation");
    return;
  }
  const { first, second } = buildTwice("zip", { epoch: EPOCH, pythonCommand });
  assert.equal(first, second);
});

test("resolveSourceDateEpoch honors SOURCE_DATE_EPOCH and clamps to the zip minimum", () => {
  assert.equal(resolveSourceDateEpoch({ env: { SOURCE_DATE_EPOCH: "1700000000" } }), 1_700_000_000);
  assert.equal(resolveSourceDateEpoch({ env: { SOURCE_DATE_EPOCH: "0" } }), 315_532_800);
  assert.throws(() => resolveSourceDateEpoch({ env: { SOURCE_DATE_EPOCH: "yesterday" } }), /whole number/);
});

test("resolveSourceDateEpoch falls back to the last commit time", () => {
  const epoch = resolveSourceDateEpoch({ env: {} });
  const commitTime = Number(spawnSync("git", ["log", "-1", "--format=%ct"], { encoding: "utf8" }).stdout.trim());
  assert.equal(epoch, commitTime);
});
