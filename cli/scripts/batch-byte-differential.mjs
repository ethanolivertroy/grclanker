import { spawnSync } from "node:child_process";
import {
  cpSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..", "..");
const runRoot = mkdtempSync(join(tmpdir(), "grclanker-byte-differential-"));
const mainWorktree = join(runRoot, "main");
const mainFixtures = join(runRoot, "fixtures-main");
const branchFixtures = join(runRoot, "fixtures-branch");
const exportRoot = join(runRoot, "exports");
const testFiles = [
  "okta.test.mjs",
  "duo.test.mjs",
  "gws.test.mjs",
  "box.test.mjs",
  "slack.test.mjs",
  "zoom.test.mjs",
  "azure.test.mjs",
  "gcp.test.mjs",
  "oci.test.mjs",
  "cloudflare.test.mjs",
  "paloalto.test.mjs",
  "zscaler.test.mjs",
];

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: { ...process.env, ...options.env },
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.status !== 0) {
    const detail = options.capture ? `${result.stdout}\n${result.stderr}`.trim() : "";
    throw new Error(`${command} ${args.join(" ")} failed with exit ${result.status}${detail ? `\n${detail}` : ""}`);
  }
  return result;
}

function instrumentedMainTest(source) {
  return source
    .replace(/assertBundlePathsMatchSpec, /g, "")
    .replace(/^import \{ OKTA_SPEC \} from .*okta\.spec\.js";\n/m, "")
    .replace(/^import \{ DUO_SPEC \} from .*duo\.spec\.js";\n/m, "")
    .replace(/^import \{ GWS_SPEC \} from .*gws\.spec\.js";\n/m, "")
    .replace(/^import \{ BOX_SPEC \} from .*box\.spec\.js";\n/m, "")
    .replace(/^import \{ SLACK_SPEC \} from .*slack\.spec\.js";\n/m, "")
    .replace(/^import \{ ZOOM_SPEC \} from .*zoom\.spec\.js";\n/m, "")
    .replace(
      'import { assertBundlePathsMatchSpec, assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";',
      'import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";',
    )
    .replace(/^import \{ assertBundlePathsMatchSpec \} from "\.\/helpers\/bundle-contents\.mjs";\n/m, "")
    .replace(/^  assertBundlePathsMatchSpec\(assert, .*;\n/gm, "");
}

function copyDifferentialTestsToMain() {
  const sourceTests = join(repoRoot, "cli", "tests");
  const targetTests = join(mainWorktree, "cli", "tests");
  for (const testFile of testFiles) {
    const source = readFileSync(join(sourceTests, testFile), "utf8");
    writeFileSync(join(targetTests, testFile), instrumentedMainTest(source));
  }
  for (const helper of ["byte-differential-fixtures.mjs", "freeze-time.mjs"]) {
    cpSync(join(sourceTests, "helpers", helper), join(targetTests, "helpers", helper));
  }
}

function runFixtureSuite(root, fixtureDirectory) {
  mkdirSync(fixtureDirectory, { recursive: true });
  run(process.execPath, [
    "--import",
    join(root, "cli", "tests", "helpers", "freeze-time.mjs"),
    "--test",
    "--test-concurrency=1",
    "--test-name-pattern=^byte differential fixtures:",
    ...testFiles.map((testFile) => join(root, "cli", "tests", testFile)),
  ], {
    cwd: root,
    env: {
      GRC_BYTE_FIXTURE_DIR: fixtureDirectory,
      GRC_BYTE_EXPORT_ROOT: exportRoot,
    },
    capture: true,
  });
}

function filesUnder(root, relativePath = "") {
  const directory = join(root, relativePath);
  return readdirSync(directory).flatMap((name) => {
    const child = join(relativePath, name);
    return lstatSync(join(root, child)).isDirectory() ? filesUnder(root, child) : [child];
  }).sort();
}

function compareFixtureTrees() {
  const expectedPaths = filesUnder(mainFixtures);
  const actualPaths = filesUnder(branchFixtures);
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    throw new Error(`fixture path mismatch\nmain: ${expectedPaths.join(", ")}\nbranch: ${actualPaths.join(", ")}`);
  }
  for (const path of expectedPaths) {
    const expected = readFileSync(join(mainFixtures, path));
    const actual = readFileSync(join(branchFixtures, path));
    if (!actual.equals(expected)) {
      throw new Error(`byte mismatch for ${path} (main=${expected.length} bytes, branch=${actual.length} bytes)`);
    }
  }
  return expectedPaths;
}

let worktreeAdded = false;
try {
  run("git", ["worktree", "add", "--detach", mainWorktree, "origin/main"]);
  worktreeAdded = true;
  symlinkSync(join(repoRoot, "cli", "node_modules"), join(mainWorktree, "cli", "node_modules"), "dir");
  copyDifferentialTestsToMain();

  run("npm", ["--prefix", join(mainWorktree, "cli"), "run", "build"]);
  run("npm", ["--prefix", join(repoRoot, "cli"), "run", "build"]);
  runFixtureSuite(mainWorktree, mainFixtures);
  runFixtureSuite(repoRoot, branchFixtures);

  const compared = compareFixtureTrees();
  const classes = [...new Set(compared.map((path) => path.split("/").at(-1).replace(/\.json$/, "")))].sort();
  console.log(`Byte differential passed: ${compared.length} exact fixtures across ${testFiles.length} integrations.`);
  console.log(`Fixture classes: ${classes.join(", ")}.`);
} finally {
  if (worktreeAdded) {
    spawnSync("git", ["worktree", "remove", "--force", mainWorktree], { cwd: repoRoot, stdio: "ignore" });
  }
  rmSync(runRoot, { recursive: true, force: true });
}
