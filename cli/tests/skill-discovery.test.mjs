import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildCliLaunchArgs } from "../dist/pi/launch.js";
import {
  normalizeGrclankerSettings,
  readGrclankerSettings,
} from "../dist/pi/settings.js";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

test("bundled-only skill mode disables default discovery and re-adds grclanker bundled skills explicitly", () => {
  const args = buildCliLaunchArgs(appRoot, "/tmp/grclanker-home/agent", {
    modelMode: "local",
    defaultProvider: "ollama",
    defaultModel: "gemma4",
    skillDiscoveryMode: "bundled-only",
  });

  assert.deepEqual(args.slice(0, 4), [
    "--model",
    "ollama/gemma4",
    "--no-skills",
    "--skill",
  ]);
  assert.equal(args[4], "/tmp/grclanker-home/agent/skills");
});

test("bundled-and-project skill mode leaves Pi skill discovery enabled", () => {
  const args = buildCliLaunchArgs(appRoot, "/tmp/grclanker-home/agent", {
    skillDiscoveryMode: "bundled-and-project",
  });

  assert.equal(args.includes("--no-skills"), false);
  assert.equal(args.includes("--skill"), false);
});

test("settings normalization defaults skill discovery to bundled-only", () => {
  const base = createTempBase("grclanker-skill-discovery-default-");
  const settingsPath = join(base, "agent", "settings.json");
  const bundledSettingsPath = join(base, "bundled-settings.json");
  mkdirSync(dirname(settingsPath), { recursive: true });
  writeFileSync(bundledSettingsPath, "{}\n", "utf8");

  normalizeGrclankerSettings(settingsPath, bundledSettingsPath);
  const settings = readGrclankerSettings(settingsPath);

  assert.equal(settings.skillDiscoveryMode, "bundled-only");
});
