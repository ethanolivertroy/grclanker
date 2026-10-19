import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { ToolCallAbortedError } from "../dist/extensions/grc-tools/abort.js";
import { createZipArchive } from "../dist/extensions/grc-tools/zip-archive.js";
import { readZipEntries } from "./helpers/bundle-contents.mjs";

function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-zip-archive-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function waitUntil(predicate, ms) {
  const deadline = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() >= deadline) return false;
    await sleep(1);
  }
  return true;
}

/** The paths this process holds open, or undefined where /proc does not list them. */
function openPaths() {
  if (process.platform !== "linux") return undefined;
  return readdirSync("/proc/self/fd").flatMap((fd) => {
    try {
      return [readlinkSync(`/proc/self/fd/${fd}`)];
    } catch {
      return [];
    }
  });
}

test("createZipArchive stores a directory's files by relative path, or the listed files by name, readable by the owner only", async (t) => {
  const root = tempDir(t);
  const source = join(root, "bundle");
  mkdirSync(join(source, "evidence"), { recursive: true });
  writeFileSync(join(source, "summary.md"), "# Summary\n");
  writeFileSync(join(source, "evidence", "users.json"), "[]\n");

  const directoryZip = join(root, "bundle.zip");
  await createZipArchive(source, directoryZip);
  assert.deepEqual(Object.fromEntries(readZipEntries(directoryZip)), {
    "evidence/users.json": "[]\n",
    "summary.md": "# Summary\n",
  });
  if (process.platform !== "win32") assert.equal(statSync(directoryZip).mode & 0o777, 0o600);

  const listedZip = join(root, "listed.zip");
  await createZipArchive([{ path: join(source, "summary.md"), name: "README.md" }], listedZip);
  assert.deepEqual(Object.fromEntries(readZipEntries(listedZip)), { "README.md": "# Summary\n" });
});

test("createZipArchive never replaces an existing file, and refuses an aborted call before it creates the archive", async (t) => {
  const root = tempDir(t);
  const source = join(root, "bundle");
  mkdirSync(source);
  writeFileSync(join(source, "summary.md"), "# Summary\n");

  const existing = join(root, "existing.zip");
  writeFileSync(existing, "existing");
  await assert.rejects(createZipArchive(source, existing), { code: "EEXIST" });
  assert.equal(readFileSync(existing, "utf8"), "existing");

  const refused = join(root, "refused.zip");
  await assert.rejects(createZipArchive(source, refused, AbortSignal.abort()), ToolCallAbortedError);
  assert.equal(existsSync(refused), false);
});

test("an abort mid-archive stops createZipArchive at once: it starts no further file, rejects with the abort once the archive is closed, and leaves no file open", async (t) => {
  const root = tempDir(t);
  const source = join(root, "bundle");
  mkdirSync(source);
  const names = Array.from({ length: 20 }, (_, index) => `file-${String(index).padStart(2, "0")}.bin`);
  // Random bytes do not compress, so each entry keeps the archive busy.
  for (const name of names) writeFileSync(join(source, name), randomBytes(512 * 1024));
  const zipPath = join(root, "bundle.zip");
  const controller = new AbortController();

  let outcome;
  createZipArchive(source, zipPath, controller.signal).then(
    () => (outcome = { description: "resolved", settledAt: Date.now() }),
    (error) => (outcome = { error, description: `rejected with ${error}`, settledAt: Date.now() }),
  );
  assert.ok(await waitUntil(() => outcome || (existsSync(zipPath) && statSync(zipPath).size > 0), 5000), "the archive started");
  assert.equal(outcome, undefined, "the archive was still running when the abort came");
  const abortedAt = Date.now();
  controller.abort(new Error("the test stopped the archive"));

  assert.ok(await waitUntil(() => outcome, 1000), "the call settled within a second of the abort");
  assert.ok(outcome.error instanceof ToolCallAbortedError, outcome.description);
  assert.ok(outcome.settledAt - abortedAt < 500, `settled ${outcome.settledAt - abortedAt} ms after the abort`);
  const partial = readFileSync(zipPath);
  const started = names.filter((name) => partial.includes(name));
  assert.ok(started.length < names.length, `started ${started.length} of ${names.length} files`);

  const open = openPaths();
  if (open) {
    assert.equal(open.includes(zipPath), false, "the archive is closed when the call rejects");
    // The file in progress drains into nothing, then closes too.
    await waitUntil(() => !openPaths().some((path) => path.startsWith(source)), 2000);
    assert.deepEqual(openPaths().filter((path) => path.startsWith(source)), [], "no source file stays open");
  }
});
