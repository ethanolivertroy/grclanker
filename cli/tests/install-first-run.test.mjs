import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
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

test("bundle installer handles a symlinked TMPDIR and directs first run to setup", () => {
  const backingRoot = mkdtempSync(join(realpathSync(tmpdir()), "grclanker-install-backing-"));
  const realTempDir = resolve(backingRoot, "real-tmp");
  const linkedTempDir = resolve(backingRoot, "linked-tmp");
  mkdirSync(realTempDir);
  symlinkSync(realTempDir, linkedTempDir, "dir");

  const tempRoot = mkdtempSync(join(linkedTempDir, "grclanker-install-first-run-"));
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
          TMPDIR: linkedTempDir,
        },
      },
    );

    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /Ready\. Run grclanker setup to start\./);
    assert.notEqual(tempRoot, realpathSync(tempRoot));
    assert.equal(
      realpathSync(resolve(binDir, "grclanker")),
      realpathSync(resolve(installDir, "grclanker")),
    );
  } finally {
    rmSync(backingRoot, { recursive: true, force: true });
  }
});

test("install surfaces use the canonical source fallback and PowerShell directs setup", () => {
  const sourceInstallCommands = [
    "npm install --prefix cli",
    "npm --prefix cli run build",
    "npm install --global ./cli",
  ];
  const surfaces = [
    resolve(REPO_ROOT, "README.md"),
    resolve(REPO_ROOT, "public", "install"),
    resolve(REPO_ROOT, "public", "install.ps1"),
    resolve(REPO_ROOT, "src", "content", "docs", "docs", "getting-started", "installation.md"),
  ];

  for (const surface of surfaces) {
    const contents = readFileSync(surface, "utf8");
    let previousIndex = -1;
    for (const command of sourceInstallCommands) {
      const commandIndex = contents.indexOf(command);
      assert.ok(commandIndex > previousIndex, `${surface} must include ${command} in order`);
      previousIndex = commandIndex;
    }
  }

  const powershellInstaller = readFileSync(resolve(REPO_ROOT, "public", "install.ps1"), "utf8");
  assert.doesNotMatch(
    powershellInstaller,
    /Write-Host "    (?:npm|bun) install -g @grclanker\/cli"/,
  );
  assert.match(powershellInstaller, /Ready\. Run grclanker setup to start\./);
});
