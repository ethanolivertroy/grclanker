import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  createSandboxReadOperations,
  createSandboxWriteOperations,
} from "../dist/pi/sandbox.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

test("sandbox read rules follow symlinks before policy checks", async () => {
  const base = createTempBase("grclanker-sandbox-read-");
  const cwd = resolve(base, "project");
  const secretPath = resolve(base, "secret.txt");
  const symlinkPath = resolve(cwd, "linked-secret.txt");

  mkdirSync(resolve(cwd, ".grclanker"), { recursive: true });
  writeFileSync(
    resolve(cwd, ".grclanker", "sandbox.json"),
    JSON.stringify({
      filesystem: {
        denyRead: [secretPath],
        allowWrite: ["."],
        denyWrite: [],
      },
    }, null, 2),
  );
  writeFileSync(secretPath, "super-secret\n", "utf8");
  symlinkSync(secretPath, symlinkPath);

  const readOps = createSandboxReadOperations(cwd);
  await assert.rejects(
    () => readOps.readFile(symlinkPath),
    /Sandbox denied read access/,
  );
});

test("sandbox write rules reject paths that escape through symlinked directories", async () => {
  const base = createTempBase("grclanker-sandbox-write-");
  const cwd = resolve(base, "project");
  const outsideDir = resolve(base, "outside");
  const symlinkDir = resolve(cwd, "linked-outside");
  const escapedPath = resolve(symlinkDir, "new.txt");

  mkdirSync(resolve(cwd, ".grclanker"), { recursive: true });
  mkdirSync(outsideDir, { recursive: true });
  writeFileSync(
    resolve(cwd, ".grclanker", "sandbox.json"),
    JSON.stringify({
      filesystem: {
        denyRead: [],
        allowWrite: ["."],
        denyWrite: [],
      },
    }, null, 2),
  );
  symlinkSync(outsideDir, symlinkDir);

  const writeOps = createSandboxWriteOperations(cwd);
  await assert.rejects(
    () => writeOps.writeFile(escapedPath, "escaped\n"),
    /Sandbox denied write access/,
  );
});
