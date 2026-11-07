import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { saveLocalSetup } from "../dist/pi/setup.js";
import { configurationJournalPath, normalizeGrclankerSettings, readModelsConfig } from "../dist/pi/settings.js";
import { syncBundledAssets } from "../dist/bootstrap/sync.js";

function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-config-commit-"));
  try { return run(root); } finally { rmSync(root, { recursive: true, force: true }); }
}

test("failed local setup publication rolls back both model providers and settings", () => fixture((root) => {
  const models = join(root, "models.json");
  const settings = join(root, "settings.json");
  writeFileSync(models, '{"providers":{"custom":{"sentinel":true}}}\n');
  writeFileSync(settings, '{"defaultProvider":"previous"}\n');
  const before = [readFileSync(models, "utf8"), readFileSync(settings, "utf8")];
  assert.throws(() => saveLocalSetup(settings, models, {}, "http://localhost:11434/v1", "gemma4", {}, {
    beforeCommit(index) { if (index === 1) throw new Error("settings publication failed"); },
  }), /settings publication failed/);
  assert.deepEqual([readFileSync(models, "utf8"), readFileSync(settings, "utf8")], before);
  assert.deepEqual(readdirSync(root).sort(), [".configuration-transaction.json.lock.sqlite", "models.json", "settings.json"]);
}));

test("launch normalization leaves an unchanged settings inode and bytes intact", () => fixture((root) => {
  const bundled = join(root, "bundled.json");
  const settings = join(root, "settings.json");
  writeFileSync(bundled, "{}\n");
  normalizeGrclankerSettings(settings, bundled);
  const before = statSync(settings);
  const contents = readFileSync(settings, "utf8");
  normalizeGrclankerSettings(settings, bundled);
  assert.equal(statSync(settings).ino, before.ino);
  assert.equal(statSync(settings).mtimeMs, before.mtimeMs);
  assert.equal(readFileSync(settings, "utf8"), contents);
}));

test("a configuration reader recovers a killed setup before returning model providers", () => fixture((root) => {
  const models = join(root, "models.json");
  const settings = join(root, "settings.json");
  writeFileSync(models, '{"providers":{"previous":{}}}\n');
  writeFileSync(settings, '{"defaultProvider":"previous"}\n');
  const helper = new URL("../core/atomic-files.ts", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { commitFileTransactionSync } from ${JSON.stringify(helper)};
    commitFileTransactionSync(${JSON.stringify([
      { path: models, data: '{"providers":{"next":{}}}\n' },
      { path: settings, data: '{"defaultProvider":"next"}\n' },
    ])}, {
      journalPath: ${JSON.stringify(configurationJournalPath(settings))},
      beforeCommit(index) { if (index === 1) process.exit(73); }
    });
  `], { encoding: "utf8" });
  assert.equal(child.status, 73, child.stderr);
  assert.deepEqual(readModelsConfig(models), { providers: { previous: {} } });
  assert.deepEqual(JSON.parse(readFileSync(settings, "utf8")), { defaultProvider: "previous" });
}));

test("bootstrap publishes assets and their management state together or restores the previous set", () => fixture((root) => {
  const previousHome = process.env.GRCLANKER_HOME;
  process.env.GRCLANKER_HOME = join(root, "home");
  try {
    const app = join(root, "app");
    const source = join(app, ".grclanker", "themes");
    const agent = join(root, "home", ".grclanker", "agent");
    mkdirSync(source, { recursive: true });
    writeFileSync(join(source, "theme.json"), "old theme");
    syncBundledAssets(app, agent);
    const target = join(agent, "themes", "theme.json");
    const state = join(root, "home", ".grclanker", ".state", "bootstrap.json");
    const oldState = readFileSync(state, "utf8");
    writeFileSync(join(source, "theme.json"), "new theme");
    assert.throws(() => syncBundledAssets(app, agent, { beforeCommit(index) { if (index === 1) throw new Error("state publication failed"); } }), /state publication failed/);
    assert.equal(readFileSync(target, "utf8"), "old theme");
    assert.equal(readFileSync(state, "utf8"), oldState);
    assert.deepEqual(syncBundledAssets(app, agent).updated, ["theme.json"]);
    assert.equal(readFileSync(target, "utf8"), "new theme");
  } finally {
    if (previousHome === undefined) delete process.env.GRCLANKER_HOME;
    else process.env.GRCLANKER_HOME = previousHome;
  }
}));
