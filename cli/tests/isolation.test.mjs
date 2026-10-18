import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { getGrclankerHome } from "../dist/config/paths.js";
import { prepareCliRuntime } from "../dist/pi/launch.js";
import { readModelsConfig } from "../dist/pi/settings.js";

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

test("getGrclankerHome rejects a symlink that lands inside .pi", () => {
  const base = createTempBase("grclanker-isolation-symlink-");
  const pi = join(base, ".pi");
  mkdirSync(pi, { recursive: true });
  const home = join(base, "home");
  mkdirSync(home);
  symlinkSync(pi, join(home, ".grclanker"));

  assert.throws(
    () => withEnv("GRCLANKER_HOME", home, () => getGrclankerHome()),
    /refuses to use a config home under `.pi`/,
  );
  assert.equal(existsSync(join(pi, "agent")), false);

  const alias = join(base, "alias");
  symlinkSync(pi, alias);
  assert.throws(
    () => withEnv("GRCLANKER_HOME", alias, () => getGrclankerHome()),
    /refuses to use a config home under `.pi`/,
  );

  const brokenHome = join(base, "broken-home");
  mkdirSync(brokenHome);
  symlinkSync(join(base, ".pi", "absent"), join(brokenHome, ".grclanker"));
  assert.throws(
    () => withEnv("GRCLANKER_HOME", brokenHome, () => getGrclankerHome()),
    /refuses to use a config home under `.pi`/,
  );
});

test("prepareCliRuntime leaves a malformed settings file unchanged and does not quote it", () => {
  const base = createTempBase("grclanker-isolation-bad-settings-");
  const settingsPath = join(base, ".grclanker", "agent", "settings.json");
  mkdirSync(dirname(settingsPath), { recursive: true });
  const body = '{ "apiKey": "CANARYSECRETVALUE12345" \n';
  writeFileSync(settingsPath, body, "utf8");

  assert.throws(
    () => withEnv("GRCLANKER_HOME", base, () => prepareCliRuntime(appRoot)),
    (error) => {
      assert.match(error.message, /Unable to parse config file: invalid JSON/);
      assert.equal(error.message.includes("CANARYSECRETVALUE12345"), false);
      return true;
    },
  );
  assert.equal(readFileSync(settingsPath, "utf8"), body);
});

test("prepareCliRuntime does not rewrite settings that are JSON but not an object", () => {
  const base = createTempBase("grclanker-isolation-settings-string-");
  const settingsPath = join(base, ".grclanker", "agent", "settings.json");
  mkdirSync(dirname(settingsPath), { recursive: true });
  const body = '"CANARYSTRINGSECRET12345"\n';
  writeFileSync(settingsPath, body, "utf8");

  assert.throws(
    () => withEnv("GRCLANKER_HOME", base, () => prepareCliRuntime(appRoot)),
    (error) => {
      assert.match(error.message, /Unable to parse config file: invalid JSON/);
      assert.equal(error.message.includes("CANARYSTRINGSECRET12345"), false);
      return true;
    },
  );
  assert.equal(readFileSync(settingsPath, "utf8"), body);
});

test("readModelsConfig refuses a malformed models file without quoting or replacing it", () => {
  const base = createTempBase("grclanker-isolation-bad-models-");
  const modelsPath = join(base, "models.json");
  const body = '{ "providers": { "ollama": { "apiKey": "CANARYMODELKEY123456" } }\n';
  writeFileSync(modelsPath, body, "utf8");

  assert.throws(
    () => readModelsConfig(modelsPath),
    (error) => {
      assert.match(error.message, /Unable to parse config file: invalid JSON/);
      assert.equal(error.message.includes("CANARYMODELKEY123456"), false);
      return true;
    },
  );
  assert.equal(readFileSync(modelsPath, "utf8"), body);
});
