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
// Immutable stack base integrated immediately before final validation. Update
// this SHA only when a newer parent head is merged into this branch.
const baselineRef = "b01d01943ca407efd4752ddb0ed9e7dd3dd85c56";
const mainWorktree = join(runRoot, "stacked-parent");
const mainFixtures = join(runRoot, "fixtures-stacked-parent");
const branchFixtures = join(runRoot, "fixtures-branch");
const mainCorpus = join(runRoot, "corpus-main");
const branchCorpus = join(runRoot, "corpus-branch");
const exportRoot = join(runRoot, "exports");
const testFiles = [
  "okta.test.mjs",
  "duo.test.mjs",
  "gws.test.mjs",
  "box.test.mjs",
  "slack.test.mjs",
  "zoom.test.mjs",
  "zendesk.test.mjs",
  "salesforce.test.mjs",
  "servicenow.test.mjs",
  "azure.test.mjs",
  "gcp.test.mjs",
  "oci.test.mjs",
  "cloudflare.test.mjs",
  "paloalto.test.mjs",
  "zscaler.test.mjs",
];
const fixtureClasses = ["boundary", "compliant", "denied", "export", "missing-null", "partial", "representative"];
const batch2Integrations = ["azure", "cloudflare", "gcp", "oci", "paloalto", "zscaler"];

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
    .replace(/^import \{ ZENDESK_SPEC \} from .*zendesk\.spec\.js";\n/m, "")
    .replace(/^import \{ SALESFORCE_SPEC \} from .*salesforce\.spec\.js";\n/m, "")
    .replace(/^import \{ SERVICENOW_SPEC \} from .*servicenow\.spec\.js";\n/m, "")
    .replace(/^import \{ captureBatchDecisionFacts \} from .*batch-spec-builder\.js";\n/m, "")
    .replace(/^import \{\n  captureBatchDecisionFacts,\n  evaluateBatchCheckVerdict,\n\} from .*batch-spec-builder\.js";\n/m, "")
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

function instrumentAssessmentExports(root) {
  for (const testFile of testFiles) {
    const moduleName = testFile.replace(/\.test\.mjs$/, "");
    const modulePath = join(root, "cli", "dist", "extensions", "grc-tools", `${moduleName}.js`);
    let source = readFileSync(modulePath, "utf8");
    const wrappers = [];
    source = source.replace(
      /export (async )?function (assess[A-Z][A-Za-z0-9_]*)\(/g,
      (_match, asyncKeyword = "", functionName) => {
        const originalName = `__corpus_original_${functionName}`;
        wrappers.push({ async: Boolean(asyncKeyword), functionName, originalName });
        return `${asyncKeyword}function ${originalName}(`;
      },
    );
    if (wrappers.length === 0) throw new Error(`No assessment exports found in ${modulePath}`);
    const recorder = `
import { appendFileSync as __corpusAppendFileSync, mkdirSync as __corpusMkdirSync } from "node:fs";
function __corpusRecord(name, kind, value) {
  const directory = process.env.GRC_CORPUS_FIXTURE_DIR;
  if (!directory) return;
  __corpusMkdirSync(directory, { recursive: true });
  const serialized = JSON.stringify({ name, kind, value })
    .replace(/127\\.0\\.0\\.1:\\d+/g, "127.0.0.1:<ephemeral-port>")
    .replace(/http:\\/\\/localhost:\\d+/g, "http://localhost:<ephemeral-port>");
  __corpusAppendFileSync(
    directory + "/${moduleName}.jsonl",
    serialized + "\\n",
  );
}
const __corpusSweepFunctions = new Set([
  "assessOktaAuthentication", "assessOktaAdminAccess", "assessOktaIntegrations", "assessOktaMonitoring",
  "assessDuoAuthentication", "assessDuoAdminAccess", "assessDuoIntegrations", "assessDuoMonitoring",
  "assessGwsIdentity", "assessGwsAdminAccess", "assessGwsIntegrations", "assessGwsMonitoring",
  "assessBoxIdentityAccessData", "assessBoxSharingCollaborationData", "assessBoxDataGovernanceData", "assessBoxShieldMonitoringData",
  "assessZoomIdentityFromSnapshot", "assessZoomCollaborationGovernanceFromSnapshot", "assessZoomMeetingSecurityFromSnapshot",
  "assessSalesforcePlatformData", "assessSalesforceIdentityData", "assessSalesforceDataProtectionData", "assessSalesforceMonitoringData",
  "assessServicenowIdentityAccessData", "assessServicenowPlatformHardeningData", "assessServicenowAccessControlData", "assessServicenowOperationsGovernanceData",
]);
const __corpusSweptInputs = new Set();
function __corpusSweep(name, args, original) {
  if (!__corpusSweepFunctions.has(name) || !args[0] || typeof args[0] !== "object") return;
  const signature = name + ":" + JSON.stringify(args[0]);
  if (__corpusSweptInputs.has(signature)) return;
  __corpusSweptInputs.add(signature);
  for (const [datasetName, dataset] of Object.entries(args[0])) {
    if (!dataset || typeof dataset !== "object" || Array.isArray(dataset)) continue;
    const collectionKey = Array.isArray(dataset.data) ? "data" : Array.isArray(dataset.rows) ? "rows" : Array.isArray(dataset.items) ? "items" : undefined;
    if (!collectionKey) continue;
    for (const mode of ["truncated", "denied", "empty"]) {
      const mutatedArgs = structuredClone(args);
      const mutated = mutatedArgs[0][datasetName];
      const rows = mutated[collectionKey];
      if (mode === "denied") {
        mutated[collectionKey] = [];
        if (Object.hasOwn(mutated, "status")) mutated.status = "forbidden";
        mutated.error = "403 Forbidden";
        mutated.notCollected = true;
        mutated.truncated = false;
        mutated.partial = false;
        if (Object.hasOwn(mutated, "seen")) mutated.seen = 0;
        if (Object.hasOwn(mutated, "total")) mutated.total = undefined;
      } else if (mode === "empty") {
        mutated[collectionKey] = [];
        if (Object.hasOwn(mutated, "status")) mutated.status = "ok";
        delete mutated.error;
        mutated.notCollected = false;
        mutated.truncated = false;
        mutated.partial = false;
        if (Object.hasOwn(mutated, "seen")) mutated.seen = 0;
        if (Object.hasOwn(mutated, "total")) mutated.total = 0;
      } else {
        if (Object.hasOwn(mutated, "status")) mutated.status = "ok";
        delete mutated.error;
        mutated.notCollected = false;
        mutated.truncated = true;
        mutated.partial = true;
        if (Object.hasOwn(mutated, "seen")) mutated.seen = rows.length;
        if (Object.hasOwn(mutated, "total")) mutated.total = Math.max(rows.length + 1, Number(mutated.total) || 0);
      }
      try {
        __corpusRecord(name + "::sweep::" + mode + "::" + datasetName, "result", original(...mutatedArgs));
      } catch (error) {
        __corpusRecord(name + "::sweep::" + mode + "::" + datasetName, "error", {
          name: error instanceof Error ? error.name : typeof error,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }
}
`;
    const wrapperSource = wrappers.map(({ async, functionName, originalName }) => async
      ? `
export async function ${functionName}(...args) {
  try {
    const result = await ${originalName}(...args);
    __corpusRecord(${JSON.stringify(functionName)}, "result", result);
    return result;
  } catch (error) {
    __corpusRecord(${JSON.stringify(functionName)}, "error", {
      name: error instanceof Error ? error.name : typeof error,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}`
      : `
export function ${functionName}(...args) {
  try {
    const result = ${originalName}(...args);
    __corpusRecord(${JSON.stringify(functionName)}, "result", result);
    __corpusSweep(${JSON.stringify(functionName)}, args, ${originalName});
    return result;
  } catch (error) {
    __corpusRecord(${JSON.stringify(functionName)}, "error", {
      name: error instanceof Error ? error.name : typeof error,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}`).join("\n");
    writeFileSync(modulePath, `${recorder}${source}\n${wrapperSource}\n`);
  }
}

function runCorpusSuite(root, fixtureDirectory) {
  mkdirSync(fixtureDirectory, { recursive: true });
  const result = run(process.execPath, [
    "--import",
    join(root, "cli", "tests", "helpers", "freeze-time.mjs"),
    "--test",
    "--test-concurrency=1",
    ...testFiles.map((testFile) => join(root, "cli", "tests", testFile)),
  ], {
    cwd: root,
    env: { GRC_CORPUS_FIXTURE_DIR: fixtureDirectory },
    capture: true,
  });
  const tests = Number(result.stdout.match(/# tests (\d+)/)?.[1] ?? 0);
  const skipped = Number(result.stdout.match(/# skipped (\d+)/)?.[1] ?? 0);
  return { executed: tests - skipped, skipped, total: tests };
}

function filesUnder(root, relativePath = "") {
  const directory = join(root, relativePath);
  return readdirSync(directory).flatMap((name) => {
    const child = join(relativePath, name);
    return lstatSync(join(root, child)).isDirectory() ? filesUnder(root, child) : [child];
  }).sort();
}

function compareTrees(expectedRoot, actualRoot, label) {
  const expectedPaths = filesUnder(expectedRoot);
  const actualPaths = filesUnder(actualRoot);
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    throw new Error(`${label} path mismatch\nmain: ${expectedPaths.join(", ")}\nbranch: ${actualPaths.join(", ")}`);
  }
  for (const path of expectedPaths) {
    const expected = readFileSync(join(expectedRoot, path));
    const actual = readFileSync(join(actualRoot, path));
    if (!actual.equals(expected)) {
      let offset = 0;
      while (offset < expected.length && offset < actual.length && expected[offset] === actual[offset]) offset += 1;
      const contextStart = Math.max(0, offset - 160);
      const contextEnd = offset + 320;
      const mainContext = expected.subarray(contextStart, contextEnd).toString("utf8");
      const branchContext = actual.subarray(contextStart, contextEnd).toString("utf8");
      throw new Error(
        `${label} byte mismatch for ${path} (main=${expected.length} bytes, branch=${actual.length} bytes, first offset=${offset})`
        + `\nmain context: ${JSON.stringify(mainContext)}`
        + `\nbranch context: ${JSON.stringify(branchContext)}`,
      );
    }
  }
  return expectedPaths;
}

function corpusCallCount(root, paths) {
  return paths.reduce((total, path) => total + readFileSync(join(root, path), "utf8").trim().split("\n").filter(Boolean).length, 0);
}

function corpusSweepCounts(root, paths) {
  const counts = { truncated: 0, denied: 0, empty: 0 };
  for (const path of paths) {
    for (const line of readFileSync(join(root, path), "utf8").trim().split("\n").filter(Boolean)) {
      const name = JSON.parse(line).name;
      for (const mode of Object.keys(counts)) {
        if (name.includes(`::sweep::${mode}::`)) counts[mode] += 1;
      }
    }
  }
  return counts;
}

let worktreeAdded = false;
try {
  const baselineSha = run("git", ["rev-parse", `${baselineRef}^{commit}`], { capture: true }).stdout.trim();
  const headSha = run("git", ["rev-parse", "HEAD^{commit}"], { capture: true }).stdout.trim();
  if (baselineSha === headSha) {
    throw new Error(`Differential baseline resolved to HEAD (${headSha}); self-comparison is forbidden`);
  }
  run("git", ["merge-base", "--is-ancestor", baselineSha, headSha], { capture: true });
  const batchSpecificPaths = [
    "cli/extensions/grc-tools/azure.ts",
    "cli/extensions/grc-tools/cloudflare.ts",
    "cli/extensions/grc-tools/gcp.ts",
    "cli/extensions/grc-tools/oci.ts",
    "cli/extensions/grc-tools/paloalto.ts",
    "cli/extensions/grc-tools/zscaler.ts",
  ];
  const batchDiff = spawnSync("git", ["diff", "--quiet", baselineSha, headSha, "--", ...batchSpecificPaths], {
    cwd: repoRoot,
    stdio: "ignore",
  });
  if (batchDiff.status === 0) {
    throw new Error(`No batch-2 runtime diff exists between immutable base ${baselineSha} and HEAD ${headSha}`);
  }
  if (batchDiff.status !== 1) {
    throw new Error(`Unable to inspect batch-2 diff between ${baselineSha} and ${headSha}`);
  }
  run("git", ["worktree", "add", "--detach", mainWorktree, baselineRef]);
  worktreeAdded = true;
  symlinkSync(join(repoRoot, "cli", "node_modules"), join(mainWorktree, "cli", "node_modules"), "dir");
  copyDifferentialTestsToMain();

  run("npm", ["--prefix", join(mainWorktree, "cli"), "run", "build"]);
  run("npm", ["--prefix", join(repoRoot, "cli"), "run", "build"]);
  instrumentAssessmentExports(mainWorktree);
  instrumentAssessmentExports(repoRoot);
  const mainCorpusTests = runCorpusSuite(mainWorktree, mainCorpus);
  const branchCorpusTests = runCorpusSuite(repoRoot, branchCorpus);
  if (JSON.stringify(mainCorpusTests) !== JSON.stringify(branchCorpusTests)) {
    throw new Error(`corpus test-count mismatch: main=${JSON.stringify(mainCorpusTests)} branch=${JSON.stringify(branchCorpusTests)}`);
  }
  const corpusPaths = compareTrees(mainCorpus, branchCorpus, "assessment corpus");
  const corpusCalls = corpusCallCount(mainCorpus, corpusPaths);
  const sweepCounts = corpusSweepCounts(mainCorpus, corpusPaths);

  // Rebuild after instrumentation so the curated export run uses unmodified modules.
  run("npm", ["--prefix", join(mainWorktree, "cli"), "run", "build"]);
  run("npm", ["--prefix", join(repoRoot, "cli"), "run", "build"]);
  runFixtureSuite(mainWorktree, mainFixtures);
  runFixtureSuite(repoRoot, branchFixtures);

  const compared = compareTrees(mainFixtures, branchFixtures, "curated fixture");
  for (const integration of batch2Integrations) {
    const representative = readFileSync(join(branchFixtures, integration, "representative.json"));
    const compliant = readFileSync(join(branchFixtures, integration, "compliant.json"));
    if (representative.equals(compliant)) {
      throw new Error(`${integration}: representative fixture is byte-identical to compliant`);
    }
  }
  const classes = [...new Set(compared.map((path) => path.split("/").at(-1).replace(/\.json$/, "")))].sort();
  console.log(`Whole-corpus replay passed against immutable stack base ${baselineSha}: ${mainCorpusTests.executed}/${mainCorpusTests.total} non-skipped tests and ${corpusCalls} exact serialized assessment calls matched the stacked parent.`);
  console.log(`Realistic single-dataset sweeps matched the stacked parent: ${sweepCounts.truncated} truncated, ${sweepCounts.denied} denied, ${sweepCounts.empty} empty.`);
  console.log(`Byte differential passed: ${compared.length} exact fixtures across ${testFiles.length} integrations.`);
  console.log(`Fixture classes: ${classes.join(", ")}.`);
} finally {
  if (worktreeAdded) {
    spawnSync("git", ["worktree", "remove", "--force", mainWorktree], { cwd: repoRoot, stdio: "ignore" });
  }
  rmSync(runRoot, { recursive: true, force: true });
}
