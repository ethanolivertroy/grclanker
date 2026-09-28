import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const CLI_ROOT = resolve(import.meta.dirname, "..");
const REPO_ROOT = resolve(CLI_ROOT, "..");

test("launcher minimum matches the package Node engine", () => {
  const packageJson = JSON.parse(readFileSync(resolve(CLI_ROOT, "package.json"), "utf8"));
  const launcher = readFileSync(resolve(CLI_ROOT, "bin", "grclanker.js"), "utf8");

  assert.equal(packageJson.engines.node, ">=22.19.0");
  assert.match(launcher, /const MIN_NODE = \[22, 19, 0\];/);
  assert.match(launcher, /requires Node\.js 22\.19\.0 or newer/);
});

test("bundle installer links the launcher and directs first run to setup", () => {
  const tempRoot = mkdtempSync(join(tmpdir(), "grclanker-install-first-run-"));
  const payloadDir = resolve(tempRoot, "payload");
  const archivePath = resolve(tempRoot, "grclanker-test-linux-x64.tar.gz");
  const installDir = resolve(tempRoot, "install");
  const binDir = resolve(tempRoot, "bin");
  const launcherPath = resolve(payloadDir, "grclanker");

  try {
    mkdirSync(payloadDir, { recursive: true });
    writeFileSync(launcherPath, "#!/usr/bin/env bash\nprintf 'test launcher\\n'\n");
    chmodSync(launcherPath, 0o755);

    const archive = spawnSync("tar", ["-czf", archivePath, "-C", payloadDir, "."], {
      encoding: "utf8",
    });
    assert.equal(archive.status, 0, archive.stderr);

    const result = spawnSync(
      "bash",
      [resolve(REPO_ROOT, "public", "install"), "9.9.9"],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GRCLANKER_ASSET_URL: `file://${archivePath}`,
          GRCLANKER_BIN_DIR: binDir,
          GRCLANKER_INSTALL_DIR: installDir,
          GRCLANKER_INSTALL_TARGET: "linux-x64",
          HOME: resolve(tempRoot, "home"),
        },
      },
    );

    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /Ready\. Run grclanker setup to start\./);
    assert.equal(realpathSync(resolve(binDir, "grclanker")), resolve(installDir, "grclanker"));
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
});
