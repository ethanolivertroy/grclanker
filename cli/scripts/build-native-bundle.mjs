#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  lutimesSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const companionDir = resolve(scriptDir, "..");
const releaseDir = resolve(companionDir, "release");
const cacheDir = resolve(companionDir, ".cache", "node");
const packageJson = JSON.parse(readFileSync(join(companionDir, "package.json"), "utf8"));

const companionVersion = process.env.GRCLANKER_VERSION || packageJson.version;
// Node 24 Krypton is the active LTS. Node 22 reaches end of life on 2027-04-30.
export const DEFAULT_NODE_VERSION = "24.22.0";
const nodeVersion = process.env.GRCLANKER_NODE_VERSION || DEFAULT_NODE_VERSION;
// Zip entries store DOS timestamps, which cannot represent anything before 1980-01-01.
const MIN_ARCHIVE_EPOCH = 315532800;

function parseArgs(argv) {
  const targets = [];
  let all = false;
  let outputDir = releaseDir;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--all") {
      all = true;
      continue;
    }
    if (arg === "--target") {
      const value = argv[i + 1];
      if (!value) {
        throw new Error("Missing value for --target");
      }
      targets.push(value);
      i += 1;
      continue;
    }
    if (arg === "--output-dir") {
      const value = argv[i + 1];
      if (!value) {
        throw new Error("Missing value for --output-dir");
      }
      outputDir = resolve(value);
      i += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return { all, outputDir, targets };
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? companionDir,
    stdio: options.stdio ?? "inherit",
    env: options.env ?? process.env,
    shell: false,
  });

  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
  }

  return result;
}

export function findPythonCommand() {
  const candidates = [
    { command: "python3", args: ["--version"] },
    { command: "python", args: ["--version"] },
    { command: "py", args: ["-3", "--version"] },
  ];

  for (const candidate of candidates) {
    const result = spawnSync(candidate.command, candidate.args, {
      stdio: "ignore",
      shell: false,
    });
    if (result.status === 0) {
      return candidate;
    }
  }

  throw new Error("Could not find python3, python, or py for zip archive handling");
}

export function getTargetDefinitions(version) {
  return {
    "darwin-arm64": {
      id: "darwin-arm64",
      archiveExt: "tar.gz",
      nodeArchive: `node-v${version}-darwin-arm64.tar.gz`,
      nodeRootDir: `node-v${version}-darwin-arm64`,
      launcher: "unix",
      npmPlatform: "darwin",
      npmArch: "arm64",
    },
    "darwin-x64": {
      id: "darwin-x64",
      archiveExt: "tar.gz",
      nodeArchive: `node-v${version}-darwin-x64.tar.gz`,
      nodeRootDir: `node-v${version}-darwin-x64`,
      launcher: "unix",
      npmPlatform: "darwin",
      npmArch: "x64",
    },
    "linux-arm64": {
      id: "linux-arm64",
      archiveExt: "tar.gz",
      nodeArchive: `node-v${version}-linux-arm64.tar.xz`,
      nodeRootDir: `node-v${version}-linux-arm64`,
      launcher: "unix",
      npmPlatform: "linux",
      npmArch: "arm64",
      npmLibc: "glibc",
    },
    "linux-x64": {
      id: "linux-x64",
      archiveExt: "tar.gz",
      nodeArchive: `node-v${version}-linux-x64.tar.xz`,
      nodeRootDir: `node-v${version}-linux-x64`,
      launcher: "unix",
      npmPlatform: "linux",
      npmArch: "x64",
      npmLibc: "glibc",
    },
    "win32-arm64": {
      id: "win32-arm64",
      archiveExt: "zip",
      nodeArchive: `node-v${version}-win-arm64.zip`,
      nodeRootDir: `node-v${version}-win-arm64`,
      launcher: "windows",
      npmPlatform: "win32",
      npmArch: "arm64",
    },
    "win32-x64": {
      id: "win32-x64",
      archiveExt: "zip",
      nodeArchive: `node-v${version}-win-x64.zip`,
      nodeRootDir: `node-v${version}-win-x64`,
      launcher: "windows",
      npmPlatform: "win32",
      npmArch: "x64",
    },
  };
}

function detectHostTarget(definitions) {
  const platform = process.platform;
  const arch = process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : process.arch;
  const key = `${platform}-${arch}`;
  if (!definitions[key]) {
    throw new Error(`Unsupported host target: ${key}`);
  }
  return key;
}

export function readNodeArchiveChecksum(checksumsText, archiveName) {
  const suffix = `  ${archiveName}`;
  const line = checksumsText.split(/\r?\n/).find((entry) => entry.endsWith(suffix));
  if (!line) {
    return null;
  }
  const hash = line.slice(0, line.length - suffix.length);
  return /^[0-9a-f]{64}$/.test(hash) ? hash : null;
}

// curl writes the destination as it goes. A failed download must not leave that
// partial file, or the next build treats it as a finished archive.
export function downloadVerifiedUrl(url, destination, runCommand = run) {
  const partial = `${destination}.partial`;
  rmSync(partial, { force: true });
  try {
    runCommand("curl", [
      "-fsSL",
      "--retry", "3",
      "--retry-delay", "1",
      "--connect-timeout", "20",
      url,
      "-o",
      partial,
    ]);
  } catch (error) {
    rmSync(partial, { force: true });
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Download failed for ${url}: ${reason}`);
  }
  if (!existsSync(partial)) {
    throw new Error(`Download failed for ${url}: curl did not write a file`);
  }
  rmSync(destination, { force: true });
  renameSync(partial, destination);
}

export function loadExpectedNodeChecksum({ checksumsPath, archiveName, checksumsUrl, runCommand = run }) {
  const readHash = () => (
    existsSync(checksumsPath)
      ? readNodeArchiveChecksum(readFileSync(checksumsPath, "utf8"), archiveName)
      : null
  );

  const cached = readHash();
  if (cached) {
    return cached;
  }

  rmSync(checksumsPath, { force: true });
  downloadVerifiedUrl(checksumsUrl, checksumsPath, runCommand);
  const downloaded = readHash();
  if (!downloaded) {
    rmSync(checksumsPath, { force: true });
    throw new Error(`Missing checksum entry for ${archiveName} in SHASUMS256.txt`);
  }
  return downloaded;
}

export function verifyOrRedownloadNodeArchive({
  archivePath,
  archiveUrl,
  expectedHash,
  runCommand = run,
  onReject,
}) {
  const archiveName = basename(archivePath);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (!existsSync(archivePath)) {
      downloadVerifiedUrl(archiveUrl, archivePath, runCommand);
    }
    if (sha256(archivePath) === expectedHash) {
      return;
    }
    rmSync(archivePath, { force: true });
    if (onReject) {
      onReject();
    }
    if (attempt === 0) {
      console.warn(`Checksum mismatch for ${archiveName}; downloading it again.`);
      continue;
    }
    throw new Error(`Checksum mismatch for ${archiveName} after a fresh download.`);
  }
}

function ensureNodeArchive(target, pythonCommand) {
  const archivePath = join(cacheDir, target.nodeArchive);
  const extractedRoot = join(cacheDir, target.nodeRootDir);
  const checksumsPath = join(cacheDir, `SHASUMS256-v${nodeVersion}.txt`);

  mkdirSync(cacheDir, { recursive: true });

  const expectedHash = loadExpectedNodeChecksum({
    checksumsPath,
    archiveName: target.nodeArchive,
    checksumsUrl: `https://nodejs.org/dist/v${nodeVersion}/SHASUMS256.txt`,
  });
  verifyOrRedownloadNodeArchive({
    archivePath,
    archiveUrl: `https://nodejs.org/dist/v${nodeVersion}/${target.nodeArchive}`,
    expectedHash,
    onReject() {
      rmSync(extractedRoot, { recursive: true, force: true });
    },
  });

  if (!existsSync(extractedRoot)) {
    const extractParent = dirname(extractedRoot);
    rmSync(extractedRoot, { recursive: true, force: true });

    if (target.nodeArchive.endsWith(".zip")) {
      run(pythonCommand.command, [...pythonCommand.args.slice(0, -1), "-m", "zipfile", "-e", archivePath, extractParent]);
    } else {
      run("tar", ["-xf", archivePath, "-C", extractParent]);
    }
  }

  return extractedRoot;
}

export function copyApp(stageAppDir, target, runCommand = run) {
  const entries = [
    ".grclanker",
    "bin",
    "dist",
    "extensions",
    "prompts",
    "scripts",
    "skills",
    "LICENSE",
    "NOTICE",
    "package.json",
    "package-lock.json",
  ];

  mkdirSync(stageAppDir, { recursive: true });

  for (const entry of entries) {
    cpSync(join(companionDir, entry), join(stageAppDir, entry), { recursive: true });
  }

  const npmArgs = [
    "ci",
    "--omit=dev",
    "--include=optional",
    `--os=${target.npmPlatform}`,
    `--cpu=${target.npmArch}`,
  ];
  const npmEnv = {
    ...process.env,
    npm_config_os: target.npmPlatform,
    npm_config_cpu: target.npmArch,
  };
  if (target.npmLibc) {
    npmArgs.push(`--libc=${target.npmLibc}`);
    npmEnv.npm_config_libc = target.npmLibc;
  }

  runCommand("npm", npmArgs, { cwd: stageAppDir, env: npmEnv });
  runCommand("node", [join(companionDir, "scripts", "patch-embedded-pi.mjs"), "--root", stageAppDir], {
    cwd: stageAppDir,
  });
}

function writeLauncher(bundleDir, target) {
  if (target.launcher === "windows") {
    writeFileSync(
      join(bundleDir, "grclanker.cmd"),
      [
        "@echo off",
        "setlocal",
        "set \"BASE_DIR=%~dp0\"",
        "\"%BASE_DIR%node\\node.exe\" \"%BASE_DIR%app\\bin\\grclanker.js\" %*",
        "",
      ].join("\r\n"),
      "utf8",
    );
    return;
  }

  const launcherPath = join(bundleDir, "grclanker");
  writeFileSync(
    launcherPath,
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      'SOURCE="${BASH_SOURCE[0]}"',
      'while [ -L "$SOURCE" ]; do',
      '  BASE_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"',
      '  SOURCE="$(readlink "$SOURCE")"',
      '  [[ "$SOURCE" != /* ]] && SOURCE="$BASE_DIR/$SOURCE"',
      "done",
      'BASE_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"',
      'exec "$BASE_DIR/node/bin/node" "$BASE_DIR/app/bin/grclanker.js" "$@"',
      "",
    ].join("\n"),
    "utf8",
  );
  run("chmod", ["+x", launcherPath]);
}

export function resolveSourceDateEpoch({ env = process.env, cwd = companionDir } = {}) {
  const configured = env.SOURCE_DATE_EPOCH;
  if (configured !== undefined && configured !== "") {
    if (!/^\d+$/.test(configured)) {
      throw new Error(`SOURCE_DATE_EPOCH must be a whole number of seconds, got ${JSON.stringify(configured)}`);
    }
    return Math.max(Number(configured), MIN_ARCHIVE_EPOCH);
  }

  const result = spawnSync("git", ["log", "-1", "--format=%ct"], { cwd, encoding: "utf8", shell: false });
  const commitTime = result.status === 0 ? result.stdout.trim() : "";
  return /^\d+$/.test(commitTime) ? Math.max(Number(commitTime), MIN_ARCHIVE_EPOCH) : MIN_ARCHIVE_EPOCH;
}

export const STAGED_DIRECTORY_MODE = 0o755;
export const STAGED_EXECUTABLE_MODE = 0o755;
export const STAGED_FILE_MODE = 0o644;

// Archive bytes must depend only on content and the executable bit, never on the
// builder's umask or source checkout permissions.
export function normalizeStagedTree(root, epoch) {
  const timestamp = new Date(epoch * 1000);
  const visit = (path) => {
    const stats = lstatSync(path);
    if (stats.isDirectory()) {
      chmodSync(path, STAGED_DIRECTORY_MODE);
      for (const entry of readdirSync(path)) {
        visit(join(path, entry));
      }
    } else if (stats.isFile()) {
      chmodSync(path, stats.mode & 0o111 ? STAGED_EXECUTABLE_MODE : STAGED_FILE_MODE);
    } else if (!stats.isSymbolicLink()) {
      throw new Error(`Unsupported file type in release bundle: ${path}`);
    }
    lutimesSync(path, timestamp, timestamp);
  };
  visit(root);
}

let gnuTarDetected;
function isGnuTar() {
  if (gnuTarDetected === undefined) {
    const result = spawnSync("tar", ["--version"], { encoding: "utf8", shell: false });
    gnuTarDetected = result.status === 0 && /GNU tar/.test(result.stdout);
  }
  return gnuTarDetected;
}

export function createArchive(bundleDir, artifactPath, archiveExt, { pythonCommand, epoch }) {
  rmSync(artifactPath, { force: true });
  normalizeStagedTree(bundleDir, epoch);

  if (archiveExt === "zip") {
    const entries = readdirSync(bundleDir).sort();
    run(
      pythonCommand.command,
      [...pythonCommand.args.slice(0, -1), "-m", "zipfile", "-c", artifactPath, ...entries],
      // zipfile stores local wall-clock time, so pin the zone for stable timestamps.
      { cwd: bundleDir, env: { ...process.env, TZ: "UTC" } },
    );
    return;
  }

  const reproducibleTarArgs = isGnuTar()
    ? ["--sort=name", "--format=gnu", "--owner=0", "--group=0", "--numeric-owner", `--mtime=@${epoch}`]
    : [];
  if (reproducibleTarArgs.length === 0) {
    console.warn(
      "GNU tar not found (for example, macOS ships BSD tar): tar.gz archives keep this builder's " +
        "ownership, directory order, and gzip timestamp, so they will not match release builds or " +
        "each other byte for byte. Reproducible tar.gz bundles require GNU tar, as used by the " +
        "Ubuntu release workflow.",
    );
  }
  const { GZIP: _ignoredGzipOptions, ...tarEnv } = process.env;
  run("tar", [...reproducibleTarArgs, "-czf", artifactPath, "-C", bundleDir, "."], { env: tarEnv });
}

function sha256(filePath) {
  const hash = createHash("sha256");
  hash.update(readFileSync(filePath));
  return hash.digest("hex");
}

function buildBundle(targetId, target, outputDir, pythonCommand, epoch) {
  console.log(`\nBuilding ${targetId}`);
  const workingDir = mkdtempSync(join(tmpdir(), `grclanker-${targetId}-`));
  const bundleDir = join(workingDir, "bundle");
  const nodeDir = join(bundleDir, "node");
  const appDir = join(bundleDir, "app");
  const nodeSourceDir = ensureNodeArchive(target, pythonCommand);

  mkdirSync(bundleDir, { recursive: true });
  cpSync(nodeSourceDir, nodeDir, { recursive: true });
  copyApp(appDir, target);
  writeLauncher(bundleDir, target);

  const artifactName = `grclanker-${companionVersion}-${targetId}.${target.archiveExt}`;
  const artifactPath = join(outputDir, artifactName);

  createArchive(bundleDir, artifactPath, target.archiveExt, { pythonCommand, epoch });
  rmSync(workingDir, { recursive: true, force: true });

  return artifactPath;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const pythonCommand = findPythonCommand();
  const definitions = getTargetDefinitions(nodeVersion);
  const targetIds =
    args.targets.length > 0
      ? args.targets
      : args.all
        ? Object.keys(definitions)
        : [detectHostTarget(definitions)];

  mkdirSync(args.outputDir, { recursive: true });

  console.log(`Building grclanker release bundles v${companionVersion}`);
  console.log(`Bundled Node runtime: v${nodeVersion}`);
  const epoch = resolveSourceDateEpoch();
  console.log(`Archive timestamp (SOURCE_DATE_EPOCH): ${epoch}`);

  run("npm", ["run", "build"]);
  run("node", [join(companionDir, "scripts", "patch-embedded-pi.mjs")]);

  const artifacts = [];
  for (const targetId of targetIds) {
    const target = definitions[targetId];
    if (!target) {
      throw new Error(`Unsupported target: ${targetId}`);
    }
    artifacts.push(buildBundle(targetId, target, args.outputDir, pythonCommand, epoch));
  }

  const checksumLines = artifacts
    .map((artifactPath) => `${sha256(artifactPath)}  ${basename(artifactPath)}`)
    .join("\n");
  writeFileSync(join(args.outputDir, "SHA256SUMS.txt"), `${checksumLines}\n`, "utf8");

  console.log("\nArtifacts");
  for (const artifact of artifacts) {
    console.log(`- ${artifact}`);
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Bundle build failed: ${message}`);
    process.exit(1);
  }
}
