import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { syncBundledAssets } from "../dist/bootstrap/sync.js";

function withEnv(name, value, fn) {
  const previous = process.env[name];
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }

  try {
    return fn();
  } finally {
    if (previous === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = previous;
    }
  }
}

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

test("syncBundledAssets preserves binary files without utf8 corruption", () => {
  const appRoot = createTempBase("grclanker-bootstrap-app-");
  const homeRoot = createTempBase("grclanker-bootstrap-home-");
  const agentDir = resolve(homeRoot, ".grclanker", "agent");
  const themeDir = resolve(appRoot, ".grclanker", "themes");
  const agentThemePath = resolve(agentDir, "themes", "binary-theme.bin");
  const binaryPayload = Buffer.from([0x00, 0xff, 0x10, 0x80, 0x42, 0x7f]);

  mkdirSync(themeDir, { recursive: true });
  mkdirSync(resolve(appRoot, ".grclanker", "agents"), { recursive: true });
  mkdirSync(resolve(appRoot, "skills"), { recursive: true });
  writeFileSync(resolve(themeDir, "binary-theme.bin"), binaryPayload);

  withEnv("GRCLANKER_HOME", homeRoot, () => {
    syncBundledAssets(appRoot, agentDir);
  });

  assert.deepEqual(readFileSync(agentThemePath), binaryPayload);
});
