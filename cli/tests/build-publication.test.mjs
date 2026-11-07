import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCli } from "../scripts/build.mjs";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "grclanker-build-"));
  mkdirSync(join(root, "node_modules/typescript"), { recursive: true });
  writeFileSync(join(root, "package.json"), '{}');
  writeFileSync(join(root, "node_modules/typescript/package.json"), JSON.stringify({ name: "typescript", bin: { tsc: "bin/tsc" } }));
  mkdirSync(join(root, "dist"));
  writeFileSync(join(root, "dist/index.js"), "old runnable build");
  writeFileSync(join(root, "dist/stale.js"), "old generated file");
  return root;
}

for (const project of ["tsconfig.json", "tsconfig.cursor-sync.json"]) {
  test(`a compiler failure after writing partial output preserves every old build file (${project})`, async () => {
    const root = fixture();
    try {
      await assert.rejects(buildCli({ root, project, runCommand: async (_command, args) => {
        if (!args.includes("--outDir")) return;
        assert.equal(args[args.indexOf("--project") + 1], join(root, project));
        const staging = args[args.indexOf("--outDir") + 1];
        writeFileSync(join(staging, "index.js"), "partial output");
        assert.equal(readFileSync(join(root, "dist/index.js"), "utf8"), "old runnable build");
        throw new Error("synthetic compiler error");
      } }), /synthetic compiler error/);
      assert.equal(readFileSync(join(root, "dist/index.js"), "utf8"), "old runnable build");
      assert.equal(readFileSync(join(root, "dist/stale.js"), "utf8"), "old generated file");
      assert.deepEqual(readdirSync(root).filter((name) => name.startsWith(".dist")), [".dist.snapshot-transaction.json.lock.sqlite"]);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
}

test("a successful compiler publishes its complete tree and removes obsolete build output", async () => {
  const root = fixture();
  try {
    await buildCli({ root, project: "tsconfig.cursor-sync.json", runCommand: async (_command, args) => {
      if (!args.includes("--outDir")) return;
      assert.equal(args[args.indexOf("--project") + 1], join(root, "tsconfig.cursor-sync.json"));
      const staging = args[args.indexOf("--outDir") + 1];
      assert.equal(readFileSync(join(root, "dist/index.js"), "utf8"), "old runnable build");
      for (const entry of ["index.js", "core/registry.js", "extensions/grc-tools.js"]) {
        mkdirSync(join(staging, entry, ".."), { recursive: true });
        writeFileSync(join(staging, entry), "new complete build");
      }
    } });
    assert.equal(readFileSync(join(root, "dist/index.js"), "utf8"), "new complete build");
    assert.equal(existsSync(join(root, "dist/stale.js")), false);
    assert.deepEqual(readdirSync(root).filter((name) => name.startsWith(".dist")), [".dist.snapshot-transaction.json.lock.sqlite"]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("a compiler that emits no runnable output cannot replace the last good build", async () => {
  const root = fixture();
  try {
    await assert.rejects(buildCli({ root, runCommand: async () => {} }), /ENOENT/);
    assert.equal(readFileSync(join(root, "dist/index.js"), "utf8"), "old runnable build");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
