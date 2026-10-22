import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  DEFAULT_NODE_VERSION,
  downloadVerifiedUrl,
  loadExpectedNodeChecksum,
  readNodeArchiveChecksum,
  verifyOrRedownloadNodeArchive,
} from "../scripts/build-native-bundle.mjs";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const INSTALL_SCRIPT = resolve(REPO_ROOT, "public", "install");

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function writeExecutable(path, contents) {
  writeFileSync(path, contents);
  chmodSync(path, 0o755);
}

function writeArchive(archivePath, entries) {
  const writer = spawnSync("python3", ["-c", `
import io, json, os, tarfile
spec = json.loads(os.environ["ARCHIVE_SPEC"])
with tarfile.open(os.environ["ARCHIVE_PATH"], "w:gz") as tar:
    for name, body in spec.items():
        data = body.encode()
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
`], {
    encoding: "utf8",
    env: {
      ...process.env,
      ARCHIVE_PATH: archivePath,
      ARCHIVE_SPEC: JSON.stringify(entries),
    },
  });
  assert.equal(writer.status, 0, writer.stderr);
}

function stageCheckout(names, { packageVersion = "9.9.9", sums = null } = {}) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-release-local-"));
  const releaseDir = resolve(root, "cli", "release");
  const stubBin = resolve(root, "stub-bin");
  mkdirSync(releaseDir, { recursive: true });
  mkdirSync(resolve(root, "public"), { recursive: true });
  mkdirSync(stubBin, { recursive: true });
  writeFileSync(resolve(root, "cli", "package.json"), JSON.stringify({ version: packageVersion }));
  copyFileSync(INSTALL_SCRIPT, resolve(root, "public", "install"));
  const archives = {};
  for (const name of names) {
    const archivePath = resolve(releaseDir, name);
    writeArchive(archivePath, { grclanker: "#!/usr/bin/env bash\nprintf 'ok\\n'\n" });
    archives[name] = archivePath;
  }
  if (sums !== null) {
    writeFileSync(resolve(releaseDir, "SHA256SUMS.txt"), sums);
  }
  writeExecutable(resolve(stubBin, "sort"), "#!/bin/bash\nprintf 'sort %s\\n' \"$*\" >> \"$STUB_SORT_LOG\"\nexit 2\n");
  writeExecutable(resolve(stubBin, "curl"), `#!/bin/bash
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -w|-H) shift ;;
    file://*|http*) url="$1" ;;
  esac
  shift
done
case "$url" in
  file://*) cp "\${url#file://}" "$out" ;;
  *)
    printf '%s\\n' "$url" >> "$STUB_CURL_LOG"
    exit 22
    ;;
esac
`);
  return { root, releaseDir, stubBin, archives };
}

function runStagedInstall(stage, args = []) {
  const curlLog = resolve(stage.root, "curl.log");
  const sortLog = resolve(stage.root, "sort.log");
  const installDir = resolve(stage.root, "install");
  const result = spawnSync("bash", [resolve(stage.root, "public", "install"), ...args], {
    cwd: stage.root,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${stage.stubBin}:${process.env.PATH}`,
      HOME: resolve(stage.root, "home"),
      GRCLANKER_ASSET_URL: "",
      GRCLANKER_RELEASE_BASE_URL: "",
      GRCLANKER_VERSION: "",
      STUB_CURL_LOG: curlLog,
      STUB_SORT_LOG: sortLog,
      GRCLANKER_BIN_DIR: resolve(stage.root, "bin"),
      GRCLANKER_INSTALL_DIR: installDir,
      GRCLANKER_INSTALL_TARGET: "linux-x64",
    },
  });
  return {
    result,
    installDir,
    curlLog: existsSync(curlLog) ? readFileSync(curlLog, "utf8") : "",
    sortLog: existsSync(sortLog) ? readFileSync(sortLog, "utf8") : "",
  };
}

test("bundled Node, CI, and release workflows pin Node 24 LTS", () => {
  assert.equal(DEFAULT_NODE_VERSION, "24.22.0");
  assert.equal(readFileSync(resolve(REPO_ROOT, ".nvmrc"), "utf8").trim(), "24");
  const pins = {
    ".github/workflows/ci.yml": /node-version:\s*"24"/,
    ".github/workflows/fedramp-sync.yml": /node-version:\s*"24\.22\.0"/,
    ".github/workflows/release-bundles.yml": /node-version:\s*"24\.22\.0"/,
  };
  for (const [relative, pattern] of Object.entries(pins)) {
    const contents = readFileSync(resolve(REPO_ROOT, relative), "utf8");
    assert.match(contents, pattern, relative);
    assert.doesNotMatch(contents, /22\.23\.3/);
    assert.doesNotMatch(contents, /node-version:\s*"22"/);
  }
  assert.equal(JSON.parse(readFileSync(resolve(REPO_ROOT, "cli/package.json"), "utf8")).engines.node, ">=22.19.0");
  assert.equal(JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf8")).engines.node, ">=22.22.0");
});

test("a failed node download does not leave a partial archive", () => {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-node-download-"));
  const destination = join(dir, "node.tar.xz");
  try {
    assert.throws(
      () => downloadVerifiedUrl("https://nodejs.org/dist/v24.22.0/node.tar.xz", destination, (_command, args) => {
        writeFileSync(args[args.indexOf("-o") + 1], "partial");
        throw new Error("curl failed with exit code 18");
      }),
      /Download failed for https:\/\/nodejs\.org\/dist\/v24\.22\.0\/node\.tar\.xz: curl failed/,
    );
    assert.equal(existsSync(destination), false);
    assert.equal(existsSync(`${destination}.partial`), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a node download that writes no file is an error", () => {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-node-empty-"));
  const destination = join(dir, "node.tar.xz");
  try {
    assert.throws(
      () => downloadVerifiedUrl("https://example.test/node.tar.xz", destination, () => {}),
      /curl did not write a file/,
    );
    assert.equal(existsSync(destination), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("node checksum lookup accepts the official two-space SHASUMS256 line", () => {
  const hash = "a".repeat(64);
  const text = `${hash}  node-v24.22.0-linux-x64.tar.xz\r\n${"b".repeat(64)}  other.tar.xz\n`;
  assert.equal(readNodeArchiveChecksum(text, "node-v24.22.0-linux-x64.tar.xz"), hash);
  assert.equal(readNodeArchiveChecksum(`${hash} node-v24.22.0-linux-x64.tar.xz\n`, "node-v24.22.0-linux-x64.tar.xz"), null);
  assert.equal(readNodeArchiveChecksum(`abcd  node-v24.22.0-linux-x64.tar.xz\n`, "node-v24.22.0-linux-x64.tar.xz"), null);
  assert.equal(readNodeArchiveChecksum(text, "missing.tar.xz"), null);
});

test("a cached SHASUMS256.txt without the archive entry is replaced", () => {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-node-sums-"));
  const checksumsPath = join(dir, "SHASUMS256.txt");
  const archiveName = "node-v24.22.0-linux-x64.tar.xz";
  const hash = "c".repeat(64);
  writeFileSync(checksumsPath, "not a checksum file\n");
  let calls = 0;
  try {
    const actual = loadExpectedNodeChecksum({
      checksumsPath,
      archiveName,
      checksumsUrl: "https://nodejs.org/dist/v24.22.0/SHASUMS256.txt",
      runCommand(_command, args) {
        calls += 1;
        writeFileSync(args[args.indexOf("-o") + 1], `${hash}  ${archiveName}\n`);
      },
    });
    assert.equal(actual, hash);
    assert.equal(calls, 1);
    assert.equal(readFileSync(checksumsPath, "utf8"), `${hash}  ${archiveName}\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a SHASUMS256.txt that still has no entry is removed", () => {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-node-sums-missing-"));
  const checksumsPath = join(dir, "SHASUMS256.txt");
  try {
    assert.throws(
      () => loadExpectedNodeChecksum({
        checksumsPath,
        archiveName: "node-v24.22.0-linux-x64.tar.xz",
        checksumsUrl: "https://nodejs.org/dist/v24.22.0/SHASUMS256.txt",
        runCommand(_command, args) {
          writeFileSync(args[args.indexOf("-o") + 1], "nope\n");
        },
      }),
      /Missing checksum entry for node-v24\.22\.0-linux-x64\.tar\.xz/,
    );
    assert.equal(existsSync(checksumsPath), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a checksum mismatch downloads the node archive a second time", () => {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-node-retry-"));
  const archivePath = join(dir, "node.tar.xz");
  const hash = sha256("good");
  let calls = 0;
  const rejected = [];
  try {
    verifyOrRedownloadNodeArchive({
      archivePath,
      archiveUrl: "https://nodejs.org/dist/v24.22.0/node.tar.xz",
      expectedHash: hash,
      onReject() {
        rejected.push("reject");
      },
      runCommand(_command, args) {
        calls += 1;
        writeFileSync(args[args.indexOf("-o") + 1], calls === 1 ? "bad" : "good");
      },
    });
    assert.equal(readFileSync(archivePath, "utf8"), "good");
    assert.equal(calls, 2);
    assert.deepEqual(rejected, ["reject"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a repeated node checksum mismatch removes the archive", () => {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-node-bad-"));
  const archivePath = join(dir, "node.tar.xz");
  let calls = 0;
  let rejected = 0;
  try {
    assert.throws(
      () => verifyOrRedownloadNodeArchive({
        archivePath,
        archiveUrl: "https://nodejs.org/dist/v24.22.0/node.tar.xz",
        expectedHash: sha256("good"),
        onReject() {
          rejected += 1;
        },
        runCommand(_command, args) {
          calls += 1;
          writeFileSync(args[args.indexOf("-o") + 1], "bad");
        },
      }),
      /Checksum mismatch for node\.tar\.xz after a fresh download/,
    );
    assert.equal(existsSync(archivePath), false);
    assert.equal(calls, 2);
    assert.equal(rejected, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("local bundle selection compares versions numerically and keeps prerelease names", () => {
  const stage = stageCheckout([
    "grclanker-0.1.2-linux-x64.tar.gz",
    "grclanker-0.1.10-linux-x64.tar.gz",
    "grclanker-0.2.0-rc.2-linux-x64.tar.gz",
    "grclanker-0.2.0-rc.10-linux-x64.tar.gz",
  ]);
  try {
    const { result, sortLog, curlLog } = runStagedInstall(stage);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /Using local artifact grclanker-0\.2\.0-rc\.10-linux-x64\.tar\.gz/);
    assert.match(result.stdout, /GRCLANKER v0\.2\.0-rc\.10/);
    assert.doesNotMatch(result.stdout, /GRCLANKER vgrclanker-/);
    assert.equal(sortLog, "");
    assert.equal(curlLog, "");
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("a stable local bundle is newer than its release candidate", () => {
  const stage = stageCheckout([
    "grclanker-0.1.10-linux-x64.tar.gz",
    "grclanker-0.2.0-rc.10-linux-x64.tar.gz",
    "grclanker-0.2.0-linux-x64.tar.gz",
  ]);
  try {
    const { result } = runStagedInstall(stage);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /Using local artifact grclanker-0\.2\.0-linux-x64\.tar\.gz/);
    assert.match(result.stdout, /GRCLANKER v0\.2\.0 /);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("a local SHA256SUMS.txt that omits the archive stops the install", () => {
  const name = "grclanker-1.0.0-linux-x64.tar.gz";
  const stage = stageCheckout([name], {
    packageVersion: "1.0.0",
    sums: `${"a".repeat(64)}  grclanker-0.0.1-linux-x64.tar.gz\n`,
  });
  try {
    const { result, installDir } = runStagedInstall(stage);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /No checksum entry for grclanker-1\.0\.0-linux-x64\.tar\.gz/);
    assert.equal(existsSync(installDir), false);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("a local archive with no SHA256SUMS.txt still installs", () => {
  const stage = stageCheckout(["grclanker-1.0.0-linux-x64.tar.gz"], { packageVersion: "1.0.0" });
  try {
    const { result, installDir } = runStagedInstall(stage);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /No SHA256SUMS\.txt found alongside local artifact, skipping verification/);
    assert.equal(existsSync(resolve(installDir, "grclanker")), true);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("a local SHA256SUMS.txt with the matching digest verifies the archive", () => {
  const name = "grclanker-1.0.0-linux-x64.tar.gz";
  const stage = stageCheckout([name], { packageVersion: "1.0.0" });
  const digest = sha256(readFileSync(stage.archives[name]));
  writeFileSync(resolve(stage.releaseDir, "SHA256SUMS.txt"), `${digest}  ${name}\n`);
  try {
    const { result } = runStagedInstall(stage);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /Integrity verified/);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

function writeTruncatedArchive(archivePath) {
  const payload = mkdtempSync(join(tmpdir(), "grclanker-release-payload-"));
  try {
    writeExecutable(resolve(payload, "grclanker"), "#!/usr/bin/env bash\nprintf 'new\\n'\n");
    // Random bytes do not compress, so cutting the archive in half cuts into file data.
    writeFileSync(resolve(payload, "payload.bin"), randomBytes(256 * 1024));
    const packed = spawnSync("tar", ["-czf", archivePath, "-C", payload, "."], { encoding: "utf8" });
    assert.equal(packed.status, 0, packed.stderr);
    truncateSync(archivePath, Math.floor(statSync(archivePath).size / 2));
  } finally {
    rmSync(payload, { recursive: true, force: true });
  }
}

// The listing prints one safe entry and then fails, while extraction still runs the real tar.
function stubFailingTarListing(stage) {
  const realTar = spawnSync("sh", ["-c", "command -v tar"], { encoding: "utf8" }).stdout.trim();
  const log = resolve(stage.root, "tar.log");
  writeExecutable(resolve(stage.stubBin, "tar"), `#!/bin/sh
printf '%s\\n' "$*" >> '${log}'
case "$1" in
  -t*) printf 'grclanker\\n'; exit 2 ;;
esac
exec '${realTar}' "$@"
`);
  return log;
}

test("a failed archive listing stops the install even when extraction would work", () => {
  const name = "grclanker-1.0.0-linux-x64.tar.gz";
  const stage = stageCheckout([name], { packageVersion: "1.0.0" });
  const tarLog = stubFailingTarListing(stage);
  const installDir = resolve(stage.root, "install");
  mkdirSync(installDir);
  writeFileSync(resolve(installDir, "grclanker"), "previous\n");
  try {
    const { result } = runStagedInstall(stage);
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr, /Could not list the entries in grclanker-1\.0\.0-linux-x64\.tar\.gz, so nothing was installed/);
    assert.equal(readFileSync(resolve(installDir, "grclanker"), "utf8"), "previous\n");
    assert.deepEqual(readdirSync(stage.root).filter((entry) => entry.startsWith("install.")), []);
    assert.doesNotMatch(readFileSync(tarLog, "utf8"), /^-x/m);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("a truncated archive is refused before the previous install moves", () => {
  const name = "grclanker-1.0.0-linux-x64.tar.gz";
  const stage = stageCheckout([name], { packageVersion: "1.0.0" });
  writeTruncatedArchive(stage.archives[name]);
  const installDir = resolve(stage.root, "install");
  mkdirSync(installDir);
  writeFileSync(resolve(installDir, "grclanker"), "previous\n");
  try {
    const { result } = runStagedInstall(stage);
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr, /Could not list the entries in grclanker-1\.0\.0-linux-x64\.tar\.gz, so nothing was installed/);
    assert.equal(readFileSync(resolve(installDir, "grclanker"), "utf8"), "previous\n");
    assert.deepEqual(readdirSync(stage.root).filter((entry) => entry.startsWith("install.")), []);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("a failed extraction puts the previous install back", () => {
  const name = "grclanker-1.0.0-linux-x64.tar.gz";
  const stage = stageCheckout([name], { packageVersion: "1.0.0" });
  // tar lists a 300-character name, but filesystems cap names at 255 bytes, so extraction fails partway.
  writeArchive(stage.archives[name], { grclanker: "new\n", ["x".repeat(300)]: "too long\n" });
  const installDir = resolve(stage.root, "install");
  mkdirSync(installDir);
  writeFileSync(resolve(installDir, "grclanker"), "previous\n");
  mkdirSync(resolve(stage.root, "install.old-0badc0de"));
  try {
    const { result } = runStagedInstall(stage);
    assert.notEqual(result.status, 0, result.stdout);
    assert.match(result.stderr, /Could not extract grclanker-1\.0\.0-linux-x64\.tar\.gz, so the previous install was restored/);
    assert.equal(readFileSync(resolve(installDir, "grclanker"), "utf8"), "previous\n");
    // A failed run keeps an earlier aside, which may be the only complete copy.
    assert.deepEqual(readdirSync(stage.root).filter((entry) => entry.startsWith("install.")), ["install.old-0badc0de"]);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("a successful install removes asides an interrupted earlier run left behind", () => {
  const stage = stageCheckout(["grclanker-1.0.0-linux-x64.tar.gz"], { packageVersion: "1.0.0" });
  const installDir = resolve(stage.root, "install");
  mkdirSync(installDir);
  writeFileSync(resolve(installDir, "stale.txt"), "from the previous install\n");
  mkdirSync(resolve(stage.root, "install.old-0badc0de", "app"), { recursive: true });
  writeFileSync(resolve(stage.root, "install.old-0badc0de", "app", "left.js"), "left behind\n");
  mkdirSync(resolve(stage.root, "install.old-ABCDEF12"));
  mkdirSync(resolve(stage.root, "install.old-backup12"));
  try {
    const { result } = runStagedInstall(stage);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.equal(existsSync(resolve(installDir, "grclanker")), true);
    assert.equal(existsSync(resolve(installDir, "stale.txt")), false);
    // Only names the installer generates are removed.
    assert.deepEqual(readdirSync(stage.root).filter((entry) => entry.startsWith("install.")).sort(), [
      "install.old-ABCDEF12",
      "install.old-backup12",
    ]);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

const REMOTE_CURL = `#!/usr/bin/env bash
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -w|-H) shift ;;
    http*|file*) url="$1" ;;
  esac
  shift
done
printf '%s\\n' "$url" >> "$STUB_CURL_LOG"
case "$url" in
  */SHA256SUMS.txt)
    if [ "\${STUB_SUMS_MODE:-fail}" = "fail" ]; then
      exit 22
    fi
    cp "$STUB_SUMS" "$out"
    ;;
  *)
    cp "$STUB_ARCHIVE" "$out"
    ;;
esac
`;

function runRemoteInstall({ version = "8.8.8", sumsMode = "fail", sums = "", baseUrl = "" } = {}) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-release-remote-"));
  const stubBin = resolve(root, "stub-bin");
  const payload = resolve(root, "payload");
  mkdirSync(stubBin, { recursive: true });
  mkdirSync(resolve(root, "public"), { recursive: true });
  mkdirSync(payload, { recursive: true });
  copyFileSync(INSTALL_SCRIPT, resolve(root, "public", "install"));
  writeFileSync(resolve(payload, "grclanker"), "#!/usr/bin/env bash\n");
  const archivePath = resolve(root, "archive.tar.gz");
  const packed = spawnSync("tar", ["-czf", archivePath, "-C", payload, "."], { encoding: "utf8" });
  assert.equal(packed.status, 0, packed.stderr);
  const digest = sha256(readFileSync(archivePath));
  const assetName = `grclanker-${version}-linux-x64.tar.gz`;
  if (sumsMode === "match") {
    sums = `${digest}  ${assetName}\n`;
    sumsMode = "file";
  }
  writeFileSync(resolve(root, "SHA256SUMS.txt"), sums);
  writeExecutable(resolve(stubBin, "curl"), REMOTE_CURL);
  const curlLog = resolve(root, "curl.log");
  const installDir = resolve(root, "install");
  try {
    const result = spawnSync("bash", [resolve(root, "public", "install"), version], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${stubBin}:${process.env.PATH}`,
        HOME: resolve(root, "home"),
        STUB_ARCHIVE: archivePath,
        STUB_SUMS: resolve(root, "SHA256SUMS.txt"),
        STUB_SUMS_MODE: sumsMode,
        STUB_CURL_LOG: curlLog,
        GRCLANKER_BIN_DIR: resolve(root, "bin"),
        GRCLANKER_INSTALL_DIR: installDir,
        GRCLANKER_INSTALL_TARGET: "linux-x64",
        GRCLANKER_ASSET_URL: "",
        GRCLANKER_VERSION: "",
        GRCLANKER_RELEASE_BASE_URL: baseUrl,
      },
    });
    return {
      result,
      installDir,
      requests: existsSync(curlLog) ? readFileSync(curlLog, "utf8").trim().split("\n") : [],
      assetName,
      digest,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("an official download without SHA256SUMS.txt is refused", () => {
  const { result, installDir, assetName } = runRemoteInstall();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, new RegExp(`Could not fetch SHA256SUMS\\.txt from https://github.com/ethanolivertroy/grclanker/releases/download/v8\\.8\\.8/SHA256SUMS\\.txt`));
  assert.match(result.stderr, new RegExp(`Refusing to install ${assetName} without a checksum`));
  assert.equal(existsSync(installDir), false);
});

test("an official checksum file with no entry for the archive is refused", () => {
  const { result, installDir } = runRemoteInstall({
    sumsMode: "file",
    sums: `${"d".repeat(64)}  grclanker-0.0.1-linux-x64.tar.gz\n`,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /No checksum entry for grclanker-8\.8\.8-linux-x64\.tar\.gz/);
  assert.equal(existsSync(installDir), false);
});

test("an official checksum mismatch is refused", () => {
  const { result, installDir } = runRemoteInstall({
    sumsMode: "file",
    sums: `${"e".repeat(64)}  grclanker-8.8.8-linux-x64.tar.gz\n`,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Checksum mismatch for grclanker-8\.8\.8-linux-x64\.tar\.gz/);
  assert.equal(existsSync(installDir), false);
});

test("a release base URL without SHA256SUMS.txt is refused", () => {
  const { result, installDir } = runRemoteInstall({
    version: "1.2.3",
    baseUrl: "https://example.test/releases",
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Could not fetch SHA256SUMS\.txt from https:\/\/example\.test\/releases\/SHA256SUMS\.txt/);
  assert.equal(existsSync(installDir), false);
});

test("a matching official checksum still installs", () => {
  const { result } = runRemoteInstall({ sumsMode: "match" });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /Integrity verified/);
});

test("archive entries that escape the install directory are refused", () => {
  const root = mkdtempSync(join(tmpdir(), "grclanker-release-slip-"));
  const archivePath = resolve(root, "slip.tar.gz");
  const installDir = resolve(root, "install");
  const escaped = resolve(root, "escaped.txt");
  mkdirSync(resolve(root, "public"), { recursive: true });
  copyFileSync(INSTALL_SCRIPT, resolve(root, "public", "install"));
  writeArchive(archivePath, {
    grclanker: "#!/usr/bin/env bash\n",
    "../escaped.txt": "pwned\n",
    "nested/../../also-escaped.txt": "pwned\n",
  });
  try {
    const result = spawnSync("bash", [resolve(root, "public", "install"), "9.9.9"], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        HOME: resolve(root, "home"),
        GRCLANKER_ASSET_URL: `file://${archivePath}`,
        GRCLANKER_BIN_DIR: resolve(root, "bin"),
        GRCLANKER_INSTALL_DIR: installDir,
        GRCLANKER_INSTALL_TARGET: "linux-x64",
      },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Refusing to extract unsafe archive entry: \.\.\/escaped\.txt/);
    assert.equal(existsSync(escaped), false);
    assert.equal(existsSync(resolve(root, "also-escaped.txt")), false);
    assert.equal(existsSync(installDir), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function runDetect(extraEnv) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-release-detect-"));
  const stubBin = resolve(root, "stub-bin");
  mkdirSync(stubBin, { recursive: true });
  mkdirSync(resolve(root, "public"), { recursive: true });
  copyFileSync(INSTALL_SCRIPT, resolve(root, "public", "install"));
  writeExecutable(resolve(stubBin, "uname"), `#!/bin/bash
case "$1" in
  -s) printf '%s\\n' "\${STUB_UNAME_S:-Linux}" ;;
  -m) printf '%s\\n' "\${STUB_UNAME_M:-x86_64}" ;;
esac
`);
  writeExecutable(resolve(stubBin, "getconf"), `#!/bin/bash
if [ "\${STUB_GETCONF_OK:-}" = "1" ]; then
  printf 'glibc 2.39\\n'
  exit 0
fi
exit 1
`);
  writeExecutable(resolve(stubBin, "ldd"), `#!/bin/bash
printf '%s\\n' "\${STUB_LDD:-}"
`);
  writeExecutable(resolve(stubBin, "curl"), "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$STUB_CURL_LOG\"\nexit 22\n");
  const curlLog = resolve(root, "curl.log");
  try {
    const result = spawnSync("bash", [resolve(root, "public", "install")], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${stubBin}:/usr/bin:/bin`,
        HOME: resolve(root, "home"),
        GRCLANKER_ASSET_URL: "",
        GRCLANKER_RELEASE_BASE_URL: "",
        GRCLANKER_VERSION: "",
        GRCLANKER_INSTALL_TARGET: "",
        STUB_CURL_LOG: curlLog,
        GRCLANKER_BIN_DIR: resolve(root, "bin"),
        GRCLANKER_INSTALL_DIR: resolve(root, "install"),
        ...extraEnv,
      },
    });
    return {
      result,
      curled: existsSync(curlLog),
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("a musl host is told to build from source", () => {
  const { result, curled } = runDetect({ STUB_LDD: "musl libc (x86_64)\nVersion 1.2.5" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Linux musl hosts are not supported/);
  assert.match(result.stderr, /npm --prefix cli run build/);
  assert.doesNotMatch(result.stderr, /Release bundle unavailable/);
  assert.equal(curled, false);
});

test("an unidentified C library stops before a bundle download", () => {
  const { result, curled } = runDetect({ STUB_LDD: "busybox" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /C library could not be confirmed/);
  assert.match(result.stderr, /Node\.js 22\.19\+/);
  assert.doesNotMatch(result.stderr, /Release bundle unavailable/);
  assert.equal(curled, false);
});

test("glibc reported by ldd is accepted when getconf cannot identify it", () => {
  const { result } = runDetect({ STUB_LDD: "ldd (Ubuntu GLIBC 2.39) 2.39" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Release bundle unavailable for linux-x64/);
  assert.doesNotMatch(result.stderr, /C library could not be confirmed/);
});

test("an unsupported architecture names the architecture", () => {
  const { result } = runDetect({ STUB_GETCONF_OK: "1", STUB_UNAME_M: "i686" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsupported architecture: i686/);
});

const pwshBin = process.env.PWSH || "pwsh";
const hasPwsh = spawnSync(pwshBin, ["-NoProfile", "-Command", "exit 0"]).status === 0;

function writeZip(archivePath, entries) {
  const specPath = `${archivePath}.spec.json`;
  writeFileSync(specPath, JSON.stringify(entries));
  const writer = spawnSync("python3", ["-c", `
import json, os, zipfile
with open(os.environ["ZIP_SPEC"], encoding="utf-8") as handle:
    entries = json.load(handle)
with zipfile.ZipFile(os.environ["ZIP_PATH"], "w") as archive:
    for name, body in entries.items():
        archive.writestr(name, body)
`], {
    encoding: "utf8",
    env: {
      ...process.env,
      ZIP_PATH: archivePath,
      ZIP_SPEC: specPath,
    },
  });
  rmSync(specPath, { force: true });
  assert.equal(writer.status, 0, writer.stderr);
}

function runPwshInstallAsync(root, env) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(pwshBin, ["-NoProfile", "-File", resolve(root, "public", "install.ps1")], {
      cwd: root,
      // spawnSync would freeze this process, so a local HTTP server could never answer.
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HOME: resolve(root, "home"),
        GRCLANKER_BIN_DIR: resolve(root, "bin"),
        GRCLANKER_INSTALL_DIR: resolve(root, "install"),
        GRCLANKER_INSTALL_TARGET: "win32-x64",
        GRCLANKER_ASSET_URL: "",
        GRCLANKER_RELEASE_BASE_URL: "",
        GRCLANKER_VERSION: "",
        ...env,
      },
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 20000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      rejectRun(error);
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolveRun({ status, stdout, stderr });
    });
  });
}

function runPwshInstall(root, env, pwshArgs = ["-File", resolve(root, "public", "install.ps1")]) {
  return spawnSync(pwshBin, ["-NoProfile", ...pwshArgs], {
    cwd: root,
    encoding: "utf8",
    // An open empty stdin pipe makes pwsh block, and a progress bar deadlocks a full stdout pipe.
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 20000,
    env: {
      ...process.env,
      HOME: resolve(root, "home"),
      GRCLANKER_BIN_DIR: resolve(root, "bin"),
      GRCLANKER_INSTALL_DIR: resolve(root, "install"),
      GRCLANKER_INSTALL_TARGET: "win32-x64",
      GRCLANKER_ASSET_URL: "",
      GRCLANKER_RELEASE_BASE_URL: "",
      GRCLANKER_VERSION: "",
      ...env,
    },
  });
}

function stagePwshCheckout(names, { packageVersion = "9.9.9", sums = null, entries = { "ok.txt": "ok\n" } } = {}) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-release-ps-"));
  const releaseDir = resolve(root, "cli", "release");
  mkdirSync(releaseDir, { recursive: true });
  mkdirSync(resolve(root, "public"), { recursive: true });
  writeFileSync(resolve(root, "cli", "package.json"), JSON.stringify({ version: packageVersion }));
  copyFileSync(resolve(REPO_ROOT, "public", "install.ps1"), resolve(root, "public", "install.ps1"));
  for (const name of names) {
    writeZip(resolve(releaseDir, name), entries);
  }
  if (sums !== null) {
    writeFileSync(resolve(releaseDir, "SHA256SUMS.txt"), sums);
  }
  return { root, releaseDir };
}

test("PowerShell local bundle selection keeps numeric order and prerelease names", { skip: !hasPwsh }, () => {
  const stage = stagePwshCheckout([
    "grclanker-0.1.2-win32-x64.zip",
    "grclanker-0.1.10-win32-x64.zip",
    "grclanker-0.2.0-rc.2-win32-x64.zip",
    "grclanker-0.2.0-rc.10-win32-x64.zip",
  ]);
  try {
    const result = runPwshInstall(stage.root);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /Using local release artifact grclanker-0\.2\.0-rc\.10-win32-x64\.zip/);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("PowerShell prefers a stable local bundle over its release candidate", { skip: !hasPwsh }, () => {
  const stage = stagePwshCheckout([
    "grclanker-0.1.10-win32-x64.zip",
    "grclanker-0.2.0-rc.10-win32-x64.zip",
    "grclanker-0.2.0-win32-x64.zip",
  ]);
  try {
    const result = runPwshInstall(stage.root);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /Using local release artifact grclanker-0\.2\.0-win32-x64\.zip/);
    assert.doesNotMatch(result.stdout, /grclanker-0\.2\.0-rc/);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("PowerShell refuses a local checksum file that omits the archive", { skip: !hasPwsh }, () => {
  const name = "grclanker-1.0.0-win32-x64.zip";
  const stage = stagePwshCheckout([name], {
    packageVersion: "1.0.0",
    sums: `${"a".repeat(64)}  grclanker-0.0.1-win32-x64.zip\n`,
  });
  try {
    const result = runPwshInstall(stage.root);
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /No checksum entry for grclanker-1\.0\.0-win32-x64\.zip/);
    assert.equal(existsSync(resolve(stage.root, "install")), false);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("PowerShell refuses zip entries that escape the install directory", { skip: !hasPwsh }, () => {
  const root = mkdtempSync(join(tmpdir(), "grclanker-release-ps-slip-"));
  const releaseDir = resolve(root, "cli", "release");
  mkdirSync(releaseDir, { recursive: true });
  mkdirSync(resolve(root, "public"), { recursive: true });
  writeFileSync(resolve(root, "cli", "package.json"), JSON.stringify({ version: "1.0.0" }));
  copyFileSync(resolve(REPO_ROOT, "public", "install.ps1"), resolve(root, "public", "install.ps1"));
  writeZip(resolve(releaseDir, "grclanker-1.0.0-win32-x64.zip"), {
    "ok.txt": "ok\n",
    "../escaped.txt": "pwned\n",
    "C:/evil.txt": "pwned\n",
  });
  try {
    const result = runPwshInstall(root);
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /Refusing to extract unsafe archive entry: \.\.\/escaped\.txt/);
    assert.equal(existsSync(resolve(root, "escaped.txt")), false);
    assert.equal(existsSync(resolve(root, "install")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("PowerShell verifies the bundle, then replaces the install with its full layout", { skip: !hasPwsh }, () => {
  const name = "grclanker-1.0.0-win32-x64.zip";
  const entries = {
    "app/bin/grclanker.js": "console.log('grclanker');\n",
    "app/node_modules/pkg/lib/index.js": "module.exports = 'na\u00efve \u2603';\n",
    "app/empty/": "",
    "node/node.exe": "MZ\n",
  };
  const stage = stagePwshCheckout([name], { packageVersion: "1.0.0", entries });
  const archive = readFileSync(resolve(stage.releaseDir, name));
  writeFileSync(resolve(stage.releaseDir, "SHA256SUMS.txt"), `${sha256(archive)}  ${name}\n`);
  const installDir = resolve(stage.root, "install");
  mkdirSync(resolve(installDir, "app"), { recursive: true });
  writeFileSync(resolve(installDir, "app", "stale.js"), "from the previous install\n");
  try {
    const result = runPwshInstall(stage.root);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const verified = result.stdout.indexOf("Integrity verified");
    const installed = result.stdout.indexOf(`Installed bundle into ${installDir}`);
    assert.ok(verified > 0 && installed > verified, result.stdout);

    for (const [entry, body] of Object.entries(entries)) {
      if (entry.endsWith("/")) {
        assert.ok(statSync(resolve(installDir, entry)).isDirectory(), entry);
      } else {
        assert.equal(readFileSync(resolve(installDir, entry), "utf8"), body, entry);
      }
    }
    assert.equal(existsSync(resolve(installDir, "app", "stale.js")), false);
    assert.deepEqual(readdirSync(stage.root).filter((name) => name.startsWith("install.")), []);
    const launcher = readFileSync(resolve(stage.root, "bin", "grclanker.cmd"), "utf8");
    assert.ok(launcher.includes(`set "GRCLANKER_INSTALL_DIR=${installDir}"`), launcher);
    assert.ok(launcher.includes(String.raw`"%GRCLANKER_INSTALL_DIR%\node\node.exe" "%GRCLANKER_INSTALL_DIR%\app\bin\grclanker.js" %*`), launcher);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("PowerShell puts the previous install back when extraction fails", { skip: !hasPwsh }, () => {
  // The file named app passes the entry check, then blocks the app/ directory the next entry needs.
  const stage = stagePwshCheckout(["grclanker-1.0.0-win32-x64.zip"], {
    packageVersion: "1.0.0",
    entries: { app: "not a directory\n", "app/bin/grclanker.js": "console.log('new');\n" },
  });
  const installDir = resolve(stage.root, "install");
  const previousLauncher = resolve(installDir, "app", "bin", "grclanker.js");
  mkdirSync(resolve(installDir, "app", "bin"), { recursive: true });
  writeFileSync(previousLauncher, "console.log('previous');\n");
  mkdirSync(resolve(stage.root, "install.old-0badc0de"));
  try {
    const result = runPwshInstall(stage.root);
    assert.notEqual(result.status, 0, result.stdout);
    assert.doesNotMatch(result.stdout, /Installed bundle into/);
    assert.match(result.stdout, /Extraction failed, so the previous install was restored/);
    assert.equal(readFileSync(previousLauncher, "utf8"), "console.log('previous');\n");
    // A failed run keeps an earlier aside, which may be the only complete copy.
    assert.deepEqual(readdirSync(stage.root).filter((name) => name.startsWith("install.")), ["install.old-0badc0de"]);
    assert.equal(existsSync(resolve(stage.root, "bin", "grclanker.cmd")), false);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("PowerShell removes asides an interrupted earlier run left behind", { skip: !hasPwsh }, () => {
  const stage = stagePwshCheckout(["grclanker-1.0.0-win32-x64.zip"], { packageVersion: "1.0.0" });
  const installDir = resolve(stage.root, "install");
  mkdirSync(installDir);
  writeFileSync(resolve(installDir, "stale.txt"), "from the previous install\n");
  mkdirSync(resolve(stage.root, "install.old-0badc0de", "app"), { recursive: true });
  writeFileSync(resolve(stage.root, "install.old-0badc0de", "app", "left.js"), "left behind\n");
  mkdirSync(resolve(stage.root, "install.old-ABCDEF12"));
  mkdirSync(resolve(stage.root, "install.old-backup12"));
  try {
    const result = runPwshInstall(stage.root);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.equal(readFileSync(resolve(installDir, "ok.txt"), "utf8"), "ok\n");
    assert.equal(existsSync(resolve(installDir, "stale.txt")), false);
    // Only names the installer generates are removed.
    assert.deepEqual(readdirSync(stage.root).filter((name) => name.startsWith("install.")).sort(), [
      "install.old-ABCDEF12",
      "install.old-backup12",
    ]);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("PowerShell resolves a relative install directory from its location, not the process directory", { skip: !hasPwsh }, () => {
  const stage = stagePwshCheckout(["grclanker-1.0.0-win32-x64.zip"], { packageVersion: "1.0.0" });
  const elsewhere = resolve(stage.root, "elsewhere");
  mkdirSync(elsewhere);
  try {
    const result = runPwshInstall(stage.root, { GRCLANKER_INSTALL_DIR: "relative-install" }, [
      "-Command",
      `Set-Location -LiteralPath '${elsewhere}'; & '${resolve(stage.root, "public", "install.ps1")}'`,
    ]);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.equal(readFileSync(resolve(elsewhere, "relative-install", "ok.txt"), "utf8"), "ok\n");
    assert.equal(existsSync(resolve(stage.root, "relative-install")), false);
  } finally {
    rmSync(stage.root, { recursive: true, force: true });
  }
});

test("PowerShell refuses a release base URL whose checksum file is missing", { skip: !hasPwsh }, async () => {
  const root = mkdtempSync(join(tmpdir(), "grclanker-release-ps-base-"));
  mkdirSync(resolve(root, "public"), { recursive: true });
  copyFileSync(resolve(REPO_ROOT, "public", "install.ps1"), resolve(root, "public", "install.ps1"));
  const zipPath = resolve(root, "grclanker-1.2.3-win32-x64.zip");
  writeZip(zipPath, { "ok.txt": "ok\n" });
  const zipBytes = readFileSync(zipPath);
  const server = http.createServer((request, response) => {
    if (request.url === "/grclanker-1.2.3-win32-x64.zip") {
      response.end(zipBytes);
      return;
    }
    response.statusCode = 404;
    response.end("missing");
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const { port } = server.address();
  try {
    const result = await runPwshInstallAsync(root, {
      GRCLANKER_VERSION: "1.2.3",
      GRCLANKER_RELEASE_BASE_URL: `http://127.0.0.1:${port}`,
    });
    assert.notEqual(result.status, 0);
    const output = `${result.stdout}\n${result.stderr}`;
    assert.match(output, /Could not fetch SHA256SUMS\.txt/);
    assert.match(output, new RegExp(`http://127\\.0\\.0\\.1:${port}/SHA256SUMS\\.txt`));
    assert.equal(existsSync(resolve(root, "install")), false);
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
    rmSync(root, { recursive: true, force: true });
  }
});

test("PowerShell rejects a non-http release base URL instead of hanging", { skip: !hasPwsh }, () => {
  const root = mkdtempSync(join(tmpdir(), "grclanker-release-ps-scheme-"));
  mkdirSync(resolve(root, "public"), { recursive: true });
  copyFileSync(resolve(REPO_ROOT, "public", "install.ps1"), resolve(root, "public", "install.ps1"));
  try {
    const result = runPwshInstall(root, {
      GRCLANKER_VERSION: "9.9.9",
      GRCLANKER_RELEASE_BASE_URL: "file:///tmp/not-a-release",
    });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /must be an http or https URL/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the PowerShell installer fails closed and checks zip entries before expanding", () => {
  const contents = readFileSync(resolve(REPO_ROOT, "public", "install.ps1"), "utf8");
  const verify = contents.indexOf("$verified = Verify-Checksum -ArchivePath $ArchivePath");
  const check = contents.indexOf("Assert-ZipEntriesSafe -ArchivePath $ArchivePath");
  const expand = contents.indexOf("Expand-Bundle -ArchivePath $ArchivePath");
  const setAside = contents.indexOf("Move-Item -LiteralPath $InstallPath -Destination $PreviousInstall");
  assert.ok(verify > 0 && check > verify && setAside > check && expand > setAside);
  assert.match(contents, /Refusing to extract unsafe archive entry/);
  assert.match(contents, /\^\[A-Za-z\]:/);
  assert.match(contents, /Could not fetch SHA256SUMS\.txt/);
  assert.match(contents, /No checksum entry for \$AssetName/);
  assert.match(contents, /is not a SHA-256 hex digest/);
  assert.match(contents, /function Test-VersionNewer/);
  assert.match(contents, /function Assert-HttpUrl/);
  assert.match(contents, /\$ProgressPreference = "SilentlyContinue"/);
  assert.doesNotMatch(contents, /Sort-Object/);
});

test("the PowerShell installer extracts in one ZipFile call, not per entry with Expand-Archive", () => {
  const code = readFileSync(resolve(REPO_ROOT, "public", "install.ps1"), "utf8")
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");
  assert.match(code, /\[System\.IO\.Compression\.ZipFile\]::ExtractToDirectory\(\$ArchivePath, \$DestinationPath\)/);
  assert.doesNotMatch(code, /Expand-Archive/);
});
