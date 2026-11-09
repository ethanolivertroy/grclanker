import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Hono } from "hono";
import { serveStatic } from "@hono/node-server/serve-static";
import { resolveModelScopeFromModels } from "../node_modules/@earendil-works/pi-coding-agent/dist/core/model-resolver.js";
import { createZipArchive } from "../dist/extensions/grc-tools/zip-archive.js";
import { readZipEntries } from "./helpers/bundle-contents.mjs";

test("Pi model globs retain provider boundaries, case-insensitive matching, and thinking suffixes", () => {
  const models = [
    { provider: "anthropic", id: "claude-sonnet-4-6", name: "Claude Sonnet 4.6" },
    { provider: "anthropic", id: "claude-opus-4-6", name: "Claude Opus 4.6" },
    { provider: "other", id: "claude-sonnet-4-6", name: "Another Sonnet" },
  ];
  const result = resolveModelScopeFromModels(["ANTHROPIC/*SONNET*:high"], models);
  assert.deepEqual(result.scopedModels, [{ model: models[0], thinkingLevel: "high" }]);
  assert.deepEqual(result.diagnostics, []);
  const all = resolveModelScopeFromModels(["*sonnet*"], models);
  assert.deepEqual(all.scopedModels.map(({ model }) => `${model.provider}/${model.id}`), [
    "anthropic/claude-sonnet-4-6", "other/claude-sonnet-4-6",
  ]);
});

test("the CommonJS glob consumer and evidence archives preserve nested, hidden, and space-containing paths", async (t) => {
  // readdir-glob loads minimatch through require, while Pi uses ESM imports.
  const require = createRequire(import.meta.url);
  const { Minimatch } = require("minimatch");
  const glob = new Minimatch("**/*.{json,md}", { dot: true });
  for (const path of ["root.json", "evidence files/users.json", ".meta/source.md"]) {
    assert.equal(glob.match(path), true, path);
  }
  assert.equal(glob.match("evidence files/users.csv"), false);

  const root = mkdtempSync(join(tmpdir(), "grclanker-dependency-archive-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const source = join(root, "source");
  const entries = {
    "root.json": "{}\n",
    "evidence files/users.json": "[]\n",
    ".meta/source.md": "# Source\n",
  };
  for (const [name, body] of Object.entries(entries)) {
    const path = join(source, name);
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, body);
  }
  const zip = join(root, "bundle.zip");
  await createZipArchive(source, zip);
  assert.deepEqual(Object.fromEntries(readZipEntries(zip)), entries);
});

test("static serving keeps public files available and rejects an additional percent-decoding pass", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "grclanker-dependency-static-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "private"));
  writeFileSync(join(root, "public.txt"), "public");
  writeFileSync(join(root, "public%.txt"), "encoded filename");
  writeFileSync(join(root, "private", "secret.txt"), "private data");
  const app = new Hono();
  app.use("/private/*", (c) => c.text("Denied", 401));
  app.use("*", serveStatic({ root }));
  const publicFile = await app.request("/public.txt");
  assert.equal(publicFile.status, 200);
  assert.equal(await publicFile.text(), "public");
  assert.equal((await app.request("/private/secret.txt")).status, 401);
  assert.equal((await app.request("/public%25.txt")).status, 404);
  assert.equal((await app.request("/%2570rivate/secret.txt")).status, 404);
});
