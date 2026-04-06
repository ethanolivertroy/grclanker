import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { getGrclankerHome } from "../dist/config/paths.js";
import { prepareCliRuntime } from "../dist/pi/launch.js";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

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

test("prepareCliRuntime writes only under .grclanker and leaves an existing .pi config untouched", () => {
  const base = createTempBase("grclanker-isolation-existing-pi-");
  const piSettingsPath = join(base, ".pi", "agent", "settings.json");
  mkdirSync(dirname(piSettingsPath), { recursive: true });
  writeFileSync(piSettingsPath, '{ "sentinel": true }\n', "utf8");

  withEnv("GRCLANKER_HOME", base, () => {
    const runtime = prepareCliRuntime(appRoot);
    assert.equal(runtime.agentDir, join(base, ".grclanker", "agent"));
    assert.equal(runtime.settingsPath, join(base, ".grclanker", "agent", "settings.json"));
  });

  assert.equal(readFileSync(piSettingsPath, "utf8"), '{ "sentinel": true }\n');
  assert.ok(existsSync(join(base, ".grclanker", "agent", "settings.json")));
});

test("prepareCliRuntime does not create a .pi directory when none exists", () => {
  const base = createTempBase("grclanker-isolation-no-pi-");

  withEnv("GRCLANKER_HOME", base, () => {
    prepareCliRuntime(appRoot);
  });

  assert.equal(existsSync(join(base, ".pi")), false);
  assert.ok(existsSync(join(base, ".grclanker", "agent", "settings.json")));
});

test("getGrclankerHome rejects config homes nested under .pi", () => {
  const base = createTempBase("grclanker-isolation-guard-");

  assert.throws(
    () =>
      withEnv("GRCLANKER_HOME", join(base, ".pi"), () => getGrclankerHome()),
    /refuses to use a config home under `.pi`/,
  );

  assert.throws(
    () =>
      withEnv("GRCLANKER_HOME", join(base, ".pi", "nested-home"), () => getGrclankerHome()),
    /refuses to use a config home under `.pi`/,
  );
});
