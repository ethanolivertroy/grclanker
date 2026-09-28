import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const cliRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(cliRoot, "..");

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

test("every package.json declares Apache-2.0", () => {
  for (const path of ["package.json", "cli/package.json", "cli/agent-sdk/package.json"]) {
    assert.equal(readJson(join(repoRoot, path)).license, "Apache-2.0", path);
  }
});

test("cli LICENSE and NOTICE match the repository root copies", () => {
  for (const name of ["LICENSE", "NOTICE"]) {
    assert.equal(
      readFileSync(join(cliRoot, name), "utf8"),
      readFileSync(join(repoRoot, name), "utf8"),
      `cli/${name} drifted from ${name}`,
    );
  }
  assert.match(readFileSync(join(repoRoot, "LICENSE"), "utf8"), /Apache License\s+Version 2\.0, January 2004/);
  assert.match(readFileSync(join(repoRoot, "NOTICE"), "utf8"), /Copyright 2026 Ethan Troy/);
});

test("npm package ships LICENSE and NOTICE", () => {
  const output = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: cliRoot,
    encoding: "utf8",
  });
  const packed = new Set(JSON.parse(output)[0].files.map((file) => file.path));
  assert.ok(packed.has("LICENSE"), "LICENSE missing from npm pack");
  assert.ok(packed.has("NOTICE"), "NOTICE missing from npm pack");
});
