import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";

const REPO_ROOT = resolve(import.meta.dirname, "../..");

function readWorkflow(name) {
  return parseYaml(readFileSync(resolve(REPO_ROOT, ".github", "workflows", name), "utf8"));
}

test("the Windows bundle smoke runs when the bundle, installer, or CLI entry changes", () => {
  const triggers = readWorkflow("windows-bundle.yml").on;
  const paths = triggers.pull_request.paths;
  assert.deepEqual(triggers.push.paths, paths);
  for (const required of [
    ".github/workflows/windows-bundle.yml",
    "cli/bin/**",
    "cli/index.ts",
    "cli/scripts/build-native-bundle.mjs",
    "public/install.ps1",
  ]) {
    assert.ok(paths.includes(required), `${required} must trigger the Windows bundle smoke`);
  }
  for (const path of paths) {
    assert.ok(existsSync(resolve(REPO_ROOT, path.replace(/\/\*\*$/, ""))), `${path} no longer exists`);
  }
});
