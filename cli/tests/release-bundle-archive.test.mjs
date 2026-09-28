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
  normalizeStagedTree,
  resolveSourceDateEpoch,
} from "../scripts/build-native-bundle.mjs";

const EPOCH = 1_700_000_000;
const gnuTar = /GNU tar/.test(spawnSync("tar", ["--version"], { encoding: "utf8" }).stdout ?? "");

// Each variant mimics a different builder umask or checkout: 022, 077, and 002.
const STAGING_VARIANTS = [
  { mtime: new Date("2020-01-01T00:00:00Z"), dir: 0o755, file: 0o644, exec: 0o755 },
  { mtime: new Date("2024-06-15T12:34:56Z"), dir: 0o700, file: 0o600, exec: 0o700 },
  { mtime: new Date("2025-03-03T03:03:03Z"), dir: 0o775, file: 0o664, exec: 0o775 },
];

const EXPECTED_MODES = {
  "app/": 0o755,
  "app/bin/": 0o755,
  "app/bin/grclanker.js": 0o644,
  "app/package.json": 0o644,
  "grclanker": 0o755,
  "node/": 0o755,
  "node/bin/": 0o755,
  "node/bin/node": 0o755,
};

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function stageBundle(root, variant) {
  const bundle = join(root, "bundle");
  const files = [
    ["app/bin/grclanker.js", "console.log('hi');\n", variant.file],
    ["app/package.json", "{}\n", variant.file],
    ["grclanker", "#!/usr/bin/env bash\n", variant.exec],
    ["node/bin/node", "#!/bin/sh\n", variant.exec],
  ];
  for (const [relative, contents, mode] of files) {
    const path = join(bundle, relative);
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, contents);
    chmodSync(path, mode);
    utimesSync(path, variant.mtime, variant.mtime);
  }
  if (process.platform !== "win32") {
    symlinkSync("node", join(bundle, "node", "bin", "nodejs"));
  }
  for (const dir of ["app/bin", "app", "node/bin", "node", "."]) {
    chmodSync(join(bundle, dir), variant.dir);
    utimesSync(join(bundle, dir), variant.mtime, variant.mtime);
  }
  return bundle;
}

function buildVariants(archiveExt, options) {
  const workspace = mkdtempSync(join(tmpdir(), "grclanker-archive-test-"));
  try {
    const archives = STAGING_VARIANTS.map((variant, index) => {
      const archive = join(workspace, `variant-${index}.${archiveExt}`);
      createArchive(stageBundle(join(workspace, `stage-${index}`), variant), archive, archiveExt, options);
      return archive;
    });
    return {
      hashes: archives.map(sha256),
      modes: archiveExt === "zip" ? zipModes(archives[0], options.pythonCommand) : tarModes(archives[0]),
      listing: archiveExt === "zip" ? "" : spawnSync("tar", ["-tvzf", archives[0]], { encoding: "utf8" }).stdout,
    };
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
}

function tarModes(archive) {
  const listing = spawnSync("tar", ["-tvzf", archive], { encoding: "utf8" }).stdout;
  const modes = {};
  for (const line of listing.trim().split("\n")) {
    const [permissions] = line.split(/\s+/);
    const name = line.slice(line.indexOf("./") + 2).replace(/ -> .*$/, "");
    if (!name || permissions.startsWith("l")) {
      continue;
    }
    modes[name] = permissionsToMode(permissions);
  }
  return modes;
}

function permissionsToMode(permissions) {
  return [...permissions.slice(1)].reduce((mode, flag) => (mode << 1) | (flag === "-" ? 0 : 1), 0);
}

function zipModes(archive, pythonCommand) {
  const script = [
    "import json, sys, zipfile",
    "entries = zipfile.ZipFile(sys.argv[1]).infolist()",
    "print(json.dumps({info.filename: (info.external_attr >> 16) & 0o777 for info in entries}))",
  ].join("\n");
  const result = spawnSync(pythonCommand.command, [...pythonCommand.args.slice(0, -1), "-c", script, archive], {
    encoding: "utf8",
  });
  const modes = JSON.parse(result.stdout);
  delete modes["node/bin/nodejs"];
  return modes;
}

function formatModes(modes) {
  return Object.fromEntries(Object.entries(modes).sort().map(([name, mode]) => [name, mode.toString(8)]));
}

test("tar.gz bundles are byte-identical regardless of staging mtimes and modes", { skip: !gnuTar && "requires GNU tar" }, () => {
  const { hashes, modes, listing } = buildVariants("tar.gz", { epoch: EPOCH });
  assert.equal(new Set(hashes).size, 1, `expected one hash, got ${hashes.join(", ")}`);
  assert.deepEqual(formatModes(modes), formatModes(EXPECTED_MODES));
  assert.match(listing, /\s0\/0\s/);
  assert.doesNotMatch(listing, /\b2020-01-01\b|\b2024-06-15\b|\b2025-03-03\b/);
});

test("zip bundles are byte-identical regardless of staging mtimes and modes", (t) => {
  let pythonCommand;
  try {
    pythonCommand = findPythonCommand();
  } catch {
    t.skip("requires python for zip creation");
    return;
  }
  const { hashes, modes } = buildVariants("zip", { epoch: EPOCH, pythonCommand });
  assert.equal(new Set(hashes).size, 1, `expected one hash, got ${hashes.join(", ")}`);
  assert.deepEqual(formatModes(modes), formatModes(EXPECTED_MODES));
});

test("normalizeStagedTree rejects special files", { skip: process.platform === "win32" && "requires mkfifo" }, () => {
  const root = mkdtempSync(join(tmpdir(), "grclanker-archive-fifo-"));
  try {
    const fifo = spawnSync("mkfifo", [join(root, "pipe")]);
    assert.equal(fifo.status, 0);
    assert.throws(() => normalizeStagedTree(root, EPOCH), /Unsupported file type in release bundle/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
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
