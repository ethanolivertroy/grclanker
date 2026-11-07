import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { commitFileTransactionSync, recoverDirectorySnapshot, recoverFileTransactionSync, replaceDirectoryAtomically, writeFileAtomicallySync } from "../core/atomic-files.ts";

function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-atomic-"));
  return Promise.resolve().then(() => run(root)).finally(() => rmSync(root, { recursive: true, force: true }));
}

test("file replacement keeps the previous complete value until rename and preserves its mode", () => fixture((root) => {
  const path = join(root, "settings.json");
  writeFileSync(path, "old", { mode: 0o600 });
  writeFileAtomicallySync(path, "new");
  assert.equal(readFileSync(path, "utf8"), "new");
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(root), ["settings.json"]);
}));

test("a multi-file publication failure restores originals and removes newly created files", () => fixture((root) => {
  const first = join(root, "models.json");
  const second = join(root, "settings.json");
  const created = join(root, "new.json");
  const journalPath = join(root, "transaction.json");
  writeFileSync(first, "old models");
  writeFileSync(second, "old settings");
  assert.throws(() => commitFileTransactionSync([
    { path: first, data: "new models" },
    { path: created, data: "new file" },
    { path: second, data: "new settings" },
  ], { journalPath, beforeCommit(index) { if (index === 2) throw new Error("publication failure"); } }), /publication failure/);
  assert.equal(readFileSync(first, "utf8"), "old models");
  assert.equal(readFileSync(second, "utf8"), "old settings");
  assert.deepEqual(readdirSync(root).sort(), [".transaction.json.lock.sqlite", "models.json", "settings.json"]);
}));

test("a transaction commits replacements and deletions as one recoverable file set", () => fixture((root) => {
  const deleted = join(root, "stale.md");
  const added = join(root, "new.md");
  writeFileSync(deleted, "stale");
  commitFileTransactionSync([{ path: deleted, data: null }, { path: added, data: "published" }], { journalPath: join(root, "transaction.json") });
  assert.deepEqual(readdirSync(root).sort(), [".transaction.json.lock.sqlite", "new.md"]);
  assert.equal(readFileSync(added, "utf8"), "published");
}));

test("a crashed writer leaves a journal that restores every previous file before the next read", () => fixture((root) => {
  const first = join(root, "models.json");
  const second = join(root, "settings.json");
  const journalPath = join(root, "transaction.json");
  writeFileSync(first, "old models");
  writeFileSync(second, "old settings");
  const moduleUrl = new URL("../core/atomic-files.ts", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { commitFileTransactionSync } from ${JSON.stringify(moduleUrl)};
    commitFileTransactionSync(${JSON.stringify([{ path: first, data: "new models" }, { path: second, data: "new settings" }])}, {
      journalPath: ${JSON.stringify(journalPath)},
      beforeCommit(index) { if (index === 1) process.exit(73); }
    });
  `], { encoding: "utf8" });
  assert.equal(child.status, 73, child.stderr);
  assert.equal(readFileSync(first, "utf8"), "new models");
  recoverFileTransactionSync(journalPath);
  assert.equal(readFileSync(first, "utf8"), "old models");
  assert.equal(readFileSync(second, "utf8"), "old settings");
  assert.deepEqual(readdirSync(root).sort(), [".transaction.json.lock.sqlite", "models.json", "settings.json"]);
}));

test("a failed snapshot build leaves the existing directory and removes staging files", () => fixture(async (root) => {
  const target = join(root, "docs");
  mkdirSync(target);
  writeFileSync(join(target, "old.md"), "old content");
  await assert.rejects(replaceDirectoryAtomically(target, async (stage) => {
    writeFileSync(join(stage, "new.md"), "new content");
    throw new Error("render failed");
  }), /render failed/);
  assert.deepEqual(readdirSync(root).sort(), [".docs.snapshot-transaction.json.lock.sqlite", "docs"]);
  assert.equal(readFileSync(join(target, "old.md"), "utf8"), "old content");
  await assert.rejects(replaceDirectoryAtomically(target, async (stage) => {
    writeFileSync(join(stage, "new.md"), "new content");
  }, { beforeInstall() { throw new Error("rename failed"); } }), /rename failed/);
  assert.deepEqual(readdirSync(root).sort(), [".docs.snapshot-transaction.json.lock.sqlite", "docs"]);
  assert.equal(readFileSync(join(target, "old.md"), "utf8"), "old content");
  await replaceDirectoryAtomically(target, async (stage) => writeFileSync(join(stage, "new.md"), "new content"));
  assert.deepEqual(readdirSync(root).sort(), [".docs.snapshot-transaction.json.lock.sqlite", "docs"]);
  assert.deepEqual(readdirSync(target), ["new.md"]);
}));

test("an interrupted directory swap restores the old tree before the next inspection", () => fixture(async (root) => {
  const target = join(root, "docs");
  mkdirSync(target);
  writeFileSync(join(target, "old.md"), "old content");
  const moduleUrl = new URL("../core/atomic-files.ts", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { writeFileSync } from "node:fs";
    import { join } from "node:path";
    import { replaceDirectoryAtomically } from ${JSON.stringify(moduleUrl)};
    await replaceDirectoryAtomically(${JSON.stringify(target)}, async (stage) => {
      writeFileSync(join(stage, "new.md"), "new content");
    }, { beforeInstall() { process.exit(74); } });
  `], { encoding: "utf8" });
  assert.equal(child.status, 74, child.stderr);
  await recoverDirectorySnapshot(target);
  assert.equal(readFileSync(join(target, "old.md"), "utf8"), "old content");
  assert.deepEqual(readdirSync(root).sort(), [".docs.snapshot-transaction.json.lock.sqlite", "docs"]);
}));


test("checking absent journals does not create configuration directories or lock files", () => fixture(async (root) => {
  recoverFileTransactionSync(join(root, "missing", "transaction.json"));
  await recoverDirectorySnapshot(join(root, "also-missing", "docs"));
  assert.deepEqual(readdirSync(root), []);
}));

test("a slow snapshot reserves before build and excludes writers and recovery across process environments", () => fixture(async (root) => {
  const target = join(root, "docs");
  const alias = join(root, "alias");
  symlinkSync(root, alias, process.platform === "win32" ? "junction" : "dir");
  let releaseBuild;
  let stagePath;
  const blocked = new Promise((resolve) => { releaseBuild = resolve; });
  const first = replaceDirectoryAtomically(target, async (stage) => {
    stagePath = stage;
    writeFileSync(join(stage, "first.md"), "first");
    await blocked;
    throw new Error("first build failed");
  });
  let secondBuilt = false;
  await assert.rejects(replaceDirectoryAtomically(target, async () => { secondBuilt = true; }), /Publication is in progress/);
  await assert.rejects(recoverDirectorySnapshot(target), /Publication is in progress/);
  const moduleUrl = new URL("../core/atomic-files.ts", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { recoverDirectorySnapshot, replaceDirectoryAtomically } from ${JSON.stringify(moduleUrl)};
    for (const action of [
      () => recoverDirectorySnapshot(${JSON.stringify(join(alias, "docs"))}),
      () => replaceDirectoryAtomically(${JSON.stringify(target)}, async () => { throw new Error("BUILDER RAN"); }),
    ]) {
      try { await action(); process.exit(81); }
      catch (error) { if (!/Publication is in progress/.test(String(error))) throw error; }
    }
  `], { encoding: "utf8", env: { ...process.env, TMPDIR: root, TEMP: root, TMP: root, HOME: root } });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(secondBuilt, false);
  assert.equal(existsSync(stagePath), true, "failed competitors must not recover the live stage");
  releaseBuild();
  await assert.rejects(first, /first build failed/);
  assert.equal(existsSync(target), false);
  await replaceDirectoryAtomically(target, async (stage) => writeFileSync(join(stage, "second.md"), "second"));
  assert.equal(readFileSync(join(target, "second.md"), "utf8"), "second");
}));

test("a process dying during snapshot staging leaves the old target intact and releases ownership", () => fixture(async (root) => {
  const target = join(root, "docs");
  mkdirSync(target);
  writeFileSync(join(target, "old.md"), "old");
  const moduleUrl = new URL("../core/atomic-files.ts", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { writeFileSync } from "node:fs";
    import { join } from "node:path";
    import { replaceDirectoryAtomically } from ${JSON.stringify(moduleUrl)};
    await replaceDirectoryAtomically(${JSON.stringify(target)}, async (stage) => {
      writeFileSync(join(stage, "partial.md"), "partial");
      process.exit(75);
    });
  `], { encoding: "utf8" });
  assert.equal(child.status, 75, child.stderr);
  const journal = join(root, ".docs.snapshot-transaction.json");
  assert.equal(JSON.parse(readFileSync(journal, "utf8")).phase, "staging");
  await recoverDirectorySnapshot(target);
  assert.equal(readFileSync(join(target, "old.md"), "utf8"), "old");
  assert.deepEqual(readdirSync(root).sort(), [".docs.snapshot-transaction.json.lock.sqlite", "docs"]);
}));

test("backup staging excludes a concurrent process before copying any original", () => fixture((root) => {
  const first = join(root, "first");
  const second = join(root, "second");
  writeFileSync(first, "old first");
  writeFileSync(second, "old second");
  const journalPath = join(root, "transaction.json");
  const fs = createRequire(import.meta.url)("node:fs");
  const copy = fs.copyFileSync;
  const moduleUrl = new URL("../core/atomic-files.ts", import.meta.url).href;
  let copies = 0;
  fs.copyFileSync = (source, destination, ...rest) => {
    copies++;
    assert.equal(JSON.parse(readFileSync(journalPath, "utf8")).phase, "staging");
    if (copies === 1) {
      const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
        import { commitFileTransactionSync, recoverFileTransactionSync } from ${JSON.stringify(moduleUrl)};
        for (const action of [
          () => recoverFileTransactionSync(${JSON.stringify(journalPath)}),
          () => commitFileTransactionSync([{ path: ${JSON.stringify(first)}, data: "competing" }], { journalPath: ${JSON.stringify(journalPath)} }),
        ]) {
          try { action(); process.exit(82); }
          catch (error) { if (!/Publication is in progress/.test(String(error))) throw error; }
        }
      `], { encoding: "utf8", env: { ...process.env, TMPDIR: root, HOME: root } });
      assert.equal(child.status, 0, child.stderr);
    } else throw new Error("backup copy failed");
    return copy(source, destination, ...rest);
  };
  syncBuiltinESMExports();
  try {
    assert.throws(() => commitFileTransactionSync([{ path: first, data: "new first" }, { path: second, data: "new second" }], { journalPath }), /backup copy failed/);
  } finally {
    fs.copyFileSync = copy;
    syncBuiltinESMExports();
  }
  assert.equal(readFileSync(first, "utf8"), "old first");
  assert.equal(readFileSync(second, "utf8"), "old second");
  assert.deepEqual(readdirSync(root).sort(), [".transaction.json.lock.sqlite", "first", "second"]);
}));

test("recovery after a backup-stage crash never restores incomplete backups", () => fixture((root) => {
  const first = join(root, "first");
  const second = join(root, "second");
  writeFileSync(first, "old first");
  writeFileSync(second, "old second");
  const journalPath = join(root, "transaction.json");
  const moduleUrl = new URL("../core/atomic-files.ts", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { createRequire, syncBuiltinESMExports } from "node:module";
    import { commitFileTransactionSync } from ${JSON.stringify(moduleUrl)};
    const fs = createRequire(import.meta.url)("node:fs");
    const copy = fs.copyFileSync;
    let count = 0;
    fs.copyFileSync = (...args) => { if (++count === 2) process.exit(76); return copy(...args); };
    syncBuiltinESMExports();
    commitFileTransactionSync(${JSON.stringify([{ path: first, data: "new first" }, { path: second, data: "new second" }])}, { journalPath: ${JSON.stringify(journalPath)} });
  `], { encoding: "utf8" });
  assert.equal(child.status, 76, child.stderr);
  recoverFileTransactionSync(journalPath);
  assert.equal(readFileSync(first, "utf8"), "old first");
  assert.equal(readFileSync(second, "utf8"), "old second");
  assert.deepEqual(readdirSync(root).sort(), [".transaction.json.lock.sqlite", "first", "second"]);
}));

test("snapshot rollback preserves an unrelated replacement and retains its original for retry", () => fixture(async (root) => {
  const target = join(root, "docs");
  mkdirSync(target);
  writeFileSync(join(target, "old.md"), "old");
  await assert.rejects(replaceDirectoryAtomically(target, async (stage) => {
    writeFileSync(join(stage, "new.md"), "new");
  }, { beforeInstall() {
    mkdirSync(target);
    writeFileSync(join(target, "foreign.md"), "foreign");
    throw new Error("install failed");
  } }), /recovery journal retained/);
  assert.equal(readFileSync(join(target, "foreign.md"), "utf8"), "foreign");
  const journalPath = join(root, ".docs.snapshot-transaction.json");
  const journal = JSON.parse(readFileSync(journalPath, "utf8"));
  assert.equal(readFileSync(join(journal.backup, "old.md"), "utf8"), "old");
  await assert.rejects(recoverDirectorySnapshot(target), /destination changed outside/);
  assert.equal(existsSync(journalPath), true);
  rmSync(target, { recursive: true });
  await recoverDirectorySnapshot(target);
  assert.equal(readFileSync(join(target, "old.md"), "utf8"), "old");
  assert.equal(existsSync(journalPath), false);
}));

test("an absent snapshot's failed publisher never deletes a foreign directory", () => fixture(async (root) => {
  const target = join(root, "docs");
  await assert.rejects(replaceDirectoryAtomically(target, async (stage) => {
    writeFileSync(join(stage, "new.md"), "new");
  }, { beforeInstall() {
    mkdirSync(target);
    writeFileSync(join(target, "foreign.md"), "foreign");
    throw new Error("install failed");
  } }), /install failed/);
  assert.equal(readFileSync(join(target, "foreign.md"), "utf8"), "foreign");
  assert.deepEqual(readdirSync(root).sort(), [".docs.snapshot-transaction.json.lock.sqlite", "docs"]);
}));
