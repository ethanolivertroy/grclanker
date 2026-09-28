import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "../..");

test("installers use the same source fallback and direct first run to setup", () => {
  const sourceInstallCommands = [
    "npm --prefix cli ci",
    "npm --prefix cli run build",
    "node cli/bin/grclanker.js",
  ];
  const surfaces = [
    resolve(REPO_ROOT, "public", "install"),
    resolve(REPO_ROOT, "public", "install.ps1"),
  ];

  for (const surface of surfaces) {
    const contents = readFileSync(surface, "utf8");
    assert.doesNotMatch(contents, /(?:npm|bun) install -g @grclanker\/cli/);

    let previousIndex = -1;
    for (const command of sourceInstallCommands) {
      const commandIndex = contents.indexOf(command);
      assert.ok(commandIndex > previousIndex, `${surface} must include ${command} in order`);
      previousIndex = commandIndex;
    }

    assert.match(contents, /Ready\..*grclanker setup.*to start\./);
  }
});
