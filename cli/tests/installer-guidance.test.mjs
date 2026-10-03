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
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const REPO_ROOT = resolve(import.meta.dirname, "../..");

const STUB_CURL = `#!/usr/bin/env bash
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -w|-H) shift ;;
    http*) url="$1" ;;
  esac
  shift
done
printf '%s\\n' "$url" >> "$STUB_CURL_LOG"
case "$url" in
  https://api.github.com/*)
    [ -n "\${STUB_API_RESPONSE:-}" ] || exit 22
    cat "$STUB_API_RESPONSE"
    ;;
  */releases/latest)
    [ -n "\${STUB_LATEST_TAG:-}" ] || exit 22
    printf 'https://github.com/ethanolivertroy/grclanker/releases/tag/%s' "$STUB_LATEST_TAG"
    ;;
  */SHA256SUMS.txt) cp "$STUB_SUMS" "$out" ;;
  */releases/download/*/grclanker-0.1.0-linux-x64.tar.gz) cp "$STUB_ARCHIVE" "$out" ;;
  *) exit 22 ;;
esac
`;

function releaseFixture(tag, { prerelease = false, assets = [] } = {}) {
  return {
    tag_name: tag,
    name: `GRC Clanker ${tag}`,
    draft: false,
    prerelease,
    assets: assets.map((name) => ({
      name,
      browser_download_url: `https://github.com/ethanolivertroy/grclanker/releases/download/${tag}/${name}`,
    })),
  };
}

function runLatestInstall({ apiReleases, latestTag } = {}) {
  const tempRoot = mkdtempSync(join(realpathSync(tmpdir()), "grclanker-install-latest-"));
  const payloadDir = resolve(tempRoot, "payload");
  const stubBin = resolve(tempRoot, "stub-bin");
  const archivePath = resolve(tempRoot, "grclanker-0.1.0-linux-x64.tar.gz");
  const sumsPath = resolve(tempRoot, "SHA256SUMS.txt");
  const curlLog = resolve(tempRoot, "curl.log");
  const installDir = resolve(tempRoot, "install");

  mkdirSync(payloadDir, { recursive: true });
  mkdirSync(stubBin, { recursive: true });
  writeFileSync(resolve(payloadDir, "grclanker"), "#!/usr/bin/env bash\n");
  chmodSync(resolve(payloadDir, "grclanker"), 0o755);
  const archive = spawnSync("tar", ["-czf", archivePath, "-C", payloadDir, "."], { encoding: "utf8" });
  assert.equal(archive.status, 0, archive.stderr);
  const digest = createHash("sha256").update(readFileSync(archivePath)).digest("hex");
  writeFileSync(sumsPath, `${digest}  grclanker-0.1.0-linux-x64.tar.gz\n`);
  writeFileSync(resolve(stubBin, "curl"), STUB_CURL);
  chmodSync(resolve(stubBin, "curl"), 0o755);

  const stubEnv = {};
  if (apiReleases) {
    stubEnv.STUB_API_RESPONSE = resolve(tempRoot, "releases.json");
    writeFileSync(stubEnv.STUB_API_RESPONSE, JSON.stringify(apiReleases, null, 2));
  }
  if (latestTag) {
    stubEnv.STUB_LATEST_TAG = latestTag;
  }

  try {
    const result = spawnSync("bash", [resolve(REPO_ROOT, "public", "install")], {
      cwd: tempRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        ...stubEnv,
        PATH: `${stubBin}:${process.env.PATH}`,
        STUB_ARCHIVE: archivePath,
        STUB_SUMS: sumsPath,
        STUB_CURL_LOG: curlLog,
        GRCLANKER_BIN_DIR: resolve(tempRoot, "bin"),
        GRCLANKER_INSTALL_DIR: installDir,
        GRCLANKER_INSTALL_TARGET: "linux-x64",
        HOME: resolve(tempRoot, "home"),
      },
    });
    return { result, requests: readFileSync(curlLog, "utf8").trim().split("\n") };
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

test("bundle installer resolves latest to the newest full release with a bundle", () => {
  const { result, requests } = runLatestInstall({
    apiReleases: [
      releaseFixture("v0.2.0-rc.1", { prerelease: true, assets: ["grclanker-0.2.0-rc.1-linux-x64.tar.gz"] }),
      releaseFixture("specs-v3"),
      releaseFixture("v0.1.0", { assets: ["grclanker-0.1.0-linux-x64.tar.gz", "SHA256SUMS.txt"] }),
      releaseFixture("v0.0.1", { prerelease: true, assets: ["grclanker-0.0.1-linux-x64.tar.gz"] }),
    ],
  });

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /GRCLANKER v0\.1\.0/);
  assert.match(result.stdout, /Integrity verified/);
  assert.ok(requests.includes(
    "https://github.com/ethanolivertroy/grclanker/releases/download/v0.1.0/grclanker-0.1.0-linux-x64.tar.gz",
  ));
  assert.ok(!requests.some((url) => url.endsWith("/releases/latest")), "API success must not use the redirect fallback");
});

test("bundle installer falls back to the releases/latest redirect when the API is rate limited", () => {
  const { result, requests } = runLatestInstall({ latestTag: "v0.1.0" });

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /GRCLANKER v0\.1\.0/);
  assert.match(result.stdout, /Integrity verified/);
  assert.deepEqual(requests, [
    "https://api.github.com/repos/ethanolivertroy/grclanker/releases?per_page=30",
    "https://github.com/ethanolivertroy/grclanker/releases/latest",
    "https://github.com/ethanolivertroy/grclanker/releases/download/v0.1.0/grclanker-0.1.0-linux-x64.tar.gz",
    "https://github.com/ethanolivertroy/grclanker/releases/download/v0.1.0/SHA256SUMS.txt",
  ]);
});

test("bundle installer still points at a source build when no release can be resolved", () => {
  const { result } = runLatestInstall();

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Release bundle unavailable for linux-x64/);
  assert.match(result.stderr, /npm --prefix cli run build/);
});

test("PowerShell installer skips prereleases and falls back to the releases/latest redirect", () => {
  const contents = readFileSync(resolve(REPO_ROOT, "public", "install.ps1"), "utf8");
  assert.match(contents, /if \(\$release\.draft -or \$release\.prerelease\) \{\s*continue/);
  assert.match(contents, /Resolve-LatestReleaseAssetFromRedirect/);
  assert.match(contents, /github\.com\/\$RepoOwner\/\$RepoName\/releases\/latest/);
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

test("installers use the same source fallback and direct first run to setup", () => {
  const sourceInstallCommands = [
    "npm --prefix cli ci",
    "npm --prefix cli run build",
    "node cli/bin/grclanker.js",
  ];
  const surfaces = [
    resolve(REPO_ROOT, "public", "install"),
    resolve(REPO_ROOT, "public", "install.ps1"),
  ];

  for (const surface of surfaces) {
    const contents = readFileSync(surface, "utf8");
    assert.doesNotMatch(contents, /(?:npm|bun) install -g @grclanker\/cli/);

    let previousIndex = -1;
    for (const command of sourceInstallCommands) {
      const commandIndex = contents.indexOf(command);
      assert.ok(commandIndex > previousIndex, `${surface} must include ${command} in order`);
      previousIndex = commandIndex;
    }

    assert.match(contents, /Ready\..*grclanker setup.*to start\./);
  }
});
