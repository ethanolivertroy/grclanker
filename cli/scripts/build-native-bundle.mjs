#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const companionDir = resolve(scriptDir, "..");
const releaseDir = resolve(companionDir, "release");
const cacheDir = resolve(companionDir, ".cache", "node");
const packageJson = JSON.parse(readFileSync(join(companionDir, "package.json"), "utf8"));

const companionVersion = process.env.GRCLANKER_VERSION || packageJson.version;
const nodeVersion = process.env.GRCLANKER_NODE_VERSION || "22.20.0";

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

function findPythonCommand() {
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

function getTargetDefinitions(version) {
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

function ensureNodeArchive(target, pythonCommand) {
  const archivePath = join(cacheDir, target.nodeArchive);
  const extractedRoot = join(cacheDir, target.nodeRootDir);
  const checksumsPath = join(cacheDir, `SHASUMS256-v${nodeVersion}.txt`);

  mkdirSync(cacheDir, { recursive: true });

  if (!existsSync(archivePath)) {
    const url = `https://nodejs.org/dist/v${nodeVersion}/${target.nodeArchive}`;
    console.log(`Downloading ${target.nodeArchive}`);
    run("curl", ["-fsSL", url, "-o", archivePath]);
  }

  if (!existsSync(checksumsPath)) {
    const url = `https://nodejs.org/dist/v${nodeVersion}/SHASUMS256.txt`;
    run("curl", ["-fsSL", url, "-o", checksumsPath]);
  }

  const checksumLines = readFileSync(checksumsPath, "utf8").split("\n");
  const expectedLine = checksumLines.find((line) => line.endsWith(`  ${target.nodeArchive}`));
  if (!expectedLine) {
    throw new Error(`Missing checksum entry for ${target.nodeArchive} in SHASUMS256.txt`);
  }

  const expectedHash = expectedLine.split(/\s+/)[0];
  const actualHash = sha256(archivePath);
  if (actualHash !== expectedHash) {
    rmSync(archivePath, { force: true });
    throw new Error(`Checksum mismatch for ${target.nodeArchive}`);
  }

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

function copyApp(stageAppDir, target) {
  const entries = [
    ".grclanker",
    "bin",
    "dist",
    "extensions",
    "prompts",
    "scripts",
    "skills",
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

  run("npm", npmArgs, { cwd: stageAppDir, env: npmEnv });
  run("node", [join(companionDir, "scripts", "patch-embedded-pi.mjs"), "--root", stageAppDir], {
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

function createArchive(bundleDir, artifactPath, target, pythonCommand) {
  rmSync(artifactPath, { force: true });

  if (target.archiveExt === "zip") {
    const entries = readdirSync(bundleDir);
    run(
      pythonCommand.command,
      [...pythonCommand.args.slice(0, -1), "-m", "zipfile", "-c", artifactPath, ...entries],
      { cwd: bundleDir },
    );
    return;
  }

  run("tar", ["-czf", artifactPath, "-C", bundleDir, "."]);
}

function sha256(filePath) {
  const hash = createHash("sha256");
  hash.update(readFileSync(filePath));
  return hash.digest("hex");
}

function buildBundle(targetId, target, outputDir, pythonCommand) {
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

  createArchive(bundleDir, artifactPath, target, pythonCommand);
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

  run("npm", ["run", "build"]);
  run("node", [join(companionDir, "scripts", "patch-embedded-pi.mjs")]);

  const artifacts = [];
  for (const targetId of targetIds) {
    const target = definitions[targetId];
    if (!target) {
      throw new Error(`Unsupported target: ${targetId}`);
    }
    artifacts.push(buildBundle(targetId, target, args.outputDir, pythonCommand));
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

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Bundle build failed: ${message}`);
  process.exit(1);
}
