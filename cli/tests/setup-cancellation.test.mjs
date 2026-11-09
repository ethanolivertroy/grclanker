import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const cliRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const hooksUrl = pathToFileURL(join(cliRoot, "tests", "helpers", "setup-cancel-mock-hooks.mjs")).href;
const preload = `data:text/javascript,${encodeURIComponent([
  'import { register } from "node:module";',
  `register(${JSON.stringify(hooksUrl)});`,
  'Object.defineProperty(process.stdin, "isTTY", { value: true });',
  'Object.defineProperty(process.stdout, "isTTY", { value: true });',
].join("\n"))}`;

for (const args of [[], ["investigate", "test", "--compute", "docker"], ["setup"]]) {
  test(`cancelling ${args.length ? args.join(" ") : "first-run startup"} exits without launching Pi`, () => {
    const base = mkdtempSync(join(tmpdir(), "grclanker-setup-cancel-"));
    const recordPath = join(base, "pi-launch.json");
    try {
      const run = spawnSync(process.execPath, ["--import", preload, join(cliRoot, "dist", "index.js"), ...args], {
        encoding: "utf8",
        timeout: 30_000,
        cwd: base,
        env: { ...process.env, GRCLANKER_HOME: base, GRCLANKER_TEST_PI_LAUNCH_RECORD: recordPath },
      });
      assert.equal(run.status, 0, `${run.stdout}${run.stderr}`);
      assert.match(run.stdout, /Setup cancelled\./);
      assert.equal(existsSync(recordPath), false, "cancelled setup must not import and launch Pi");
      const settings = JSON.parse(readFileSync(join(base, ".grclanker", "agent", "settings.json"), "utf8"));
      assert.equal(settings.modelMode, undefined, "cancelled setup must not persist a partial model selection");
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
}
