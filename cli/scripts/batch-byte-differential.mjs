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
const baselineRef = "fd770ee84b188ed8a3e3360f2d9e9828dc3b4d8d";
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
  "crowdstrike.test.mjs",
  "tenable.test.mjs",
  "qualys.test.mjs",
  "veracode.test.mjs",
  "knowbe4.test.mjs",
];
const fixtureClasses = ["boundary", "compliant", "denied", "export", "missing-null", "partial", "representative"];
const batch2Integrations = ["azure", "cloudflare", "gcp", "oci", "paloalto", "zscaler"];
const representativeDistinctIntegrations = [...batch2Integrations, "crowdstrike", "qualys", "veracode"];

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
    .replace(/^import \{ AZURE_COMPLETENESS_SOURCES, AZURE_SPEC \} from .*azure\.spec\.js";\n/m, "")
    .replace(/^import \{ CLOUDFLARE_COMPLETENESS_SOURCES, CLOUDFLARE_SPEC \} from .*cloudflare\.spec\.js";\n/m, "")
    .replace(/^import \{ GCP_COMPLETENESS_SOURCES, GCP_SPEC \} from .*gcp\.spec\.js";\n/m, "")
    .replace(/^import \{ OCI_COMPLETENESS_SOURCES, OCI_SPEC \} from .*oci\.spec\.js";\n/m, "")
    .replace(/^import \{ PALOALTO_COMPLETENESS_SOURCES, PALOALTO_SPEC \} from .*paloalto\.spec\.js";\n/m, "")
    .replace(/^import \{ ZSCALER_COMPLETENESS_SOURCES, ZSCALER_SPEC \} from .*zscaler\.spec\.js";\n/m, "")
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
  "assessCrowdstrikePreventionPolicies", "assessCrowdstrikeResponseReadiness", "assessCrowdstrikeDeviceFirewall", "assessCrowdstrikeSensorCoverage", "assessCrowdstrikeAccessGovernance",
  "assessTenableScanProgram", "assessTenableSensorCoverage", "assessTenableAccessControl", "assessTenableVulnerabilityManagement",
  "assessQualysScanCoverage", "assessQualysAssetInventory", "assessQualysVulnerabilityManagement", "assessQualysAdministration",
  "assessVeracodeScanCoverage", "assessVeracodePolicyCompliance", "assessVeracodeFindingsHygiene", "assessVeracodeScaPosture", "assessVeracodeAccessControls",
  "assessKnowbe4PhishingProgram", "assessKnowbe4TrainingProgram", "assessKnowbe4UserRisk", "assessKnowbe4AccountGovernance",
]);
const __corpusSweptInputs = new Set();
const __corpusSweptAsyncInputs = new Set();
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
function __corpusClientMethods(client) {
  const domainReadMethod = /^(?:list|search|get(?:Device|Dynamic|Firewall|Sca|Self|Summary|User|Users))/;
  const transportMethods = new Set([
    "get",
    "getByIds",
    "getJson",
    "getResources",
    "getText",
    "getTotal",
    "getXml",
    "listAfter",
    "listHal",
    "listOffset",
    "listXml",
    "postJson",
    "postQps",
    "searchQps",
  ]);
  const methods = new Set();
  for (let value = client; value && value !== Object.prototype; value = Object.getPrototypeOf(value)) {
    for (const name of Object.getOwnPropertyNames(value)) {
      if (
        name !== "constructor"
        && name !== "getResolvedConfig"
        && domainReadMethod.test(name)
        && !transportMethods.has(name)
        && typeof client[name] === "function"
      ) methods.add(name);
    }
  }
  return [...methods].sort();
}
function __corpusMutateCollection(value, mode) {
  if (Array.isArray(value)) {
    if (mode === "empty") return [];
    return value;
  }
  if (!value || typeof value !== "object" || !Array.isArray(value.items)) return mode === "empty" ? {} : value;
  if (mode === "empty") {
    return { ...value, items: [], truncated: false, complete: true, total: 0, totalElements: 0, totalPages: 1 };
  }
  return {
    ...value,
    truncated: true,
    truncationReason: "independent differential truncation",
    complete: false,
    total: Math.max(value.items.length + 1, Number(value.total) || 0),
    totalElements: Math.max(value.items.length + 1, Number(value.totalElements) || 0),
    totalPages: Math.max(2, Number(value.totalPages) || 0),
  };
}
async function __corpusAsyncSweep(name, args, original) {
  if (!__corpusSweepFunctions.has(name) || !args[0] || typeof args[0] !== "object") return;
  const signature = name + ":" + JSON.stringify(args.slice(1));
  if (__corpusSweptAsyncInputs.has(signature)) return;
  __corpusSweptAsyncInputs.add(signature);
  const client = args[0];
  const methodNames = __corpusClientMethods(client);
  const modes = ["truncated", "denied", "empty"];
  const override = (proxy, methodName, mode) => {
    proxy[methodName] = async (...methodArgs) => {
      if (mode === "denied") throw new Error("403 Forbidden from independent differential " + methodName);
      return __corpusMutateCollection(await client[methodName](...methodArgs), mode);
    };
  };
  for (const methodName of methodNames) {
    for (const mode of modes) {
      const proxy = Object.create(client);
      override(proxy, methodName, mode);
      const mutatedArgs = [proxy, ...args.slice(1)];
      try {
        __corpusRecord(name + "::sweep::" + mode + "::" + methodName, "result", await original(...mutatedArgs));
      } catch (error) {
        __corpusRecord(name + "::sweep::" + mode + "::" + methodName, "error", {
          name: error instanceof Error ? error.name : typeof error,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }
  for (let left = 0; left < methodNames.length; left += 1) {
    for (let right = left + 1; right < methodNames.length; right += 1) {
      for (const leftMode of modes) {
        for (const rightMode of modes) {
          const leftMethod = methodNames[left];
          const rightMethod = methodNames[right];
          const proxy = Object.create(client);
          override(proxy, leftMethod, leftMode);
          override(proxy, rightMethod, rightMode);
          const mutatedArgs = [proxy, ...args.slice(1)];
          const recordName = name + "::pairwise::" + leftMode + "::" + leftMethod + "::" + rightMode + "::" + rightMethod;
          try {
            __corpusRecord(recordName, "result", await original(...mutatedArgs));
          } catch (error) {
            __corpusRecord(recordName, "error", {
              name: error instanceof Error ? error.name : typeof error,
              message: error instanceof Error ? error.message : String(error),
            });
          }
        }
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
    await __corpusAsyncSweep(${JSON.stringify(functionName)}, args, ${originalName});
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
    "--test-skip-pattern=^(?:all 25 (?:Palo Alto|Zscaler) checks replay|SNOW-08 counts an active non-IdP integration TLS certificate|AZURE-SUB-04 network-watcher truncation|CF-IAM-06 treats token-list 404|CF-TRF-06 preserves the unpaginated|OCI prerequisite and nested-read failures)",
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

function describeJsonlMismatches(expected, actual, limit = 25) {
  let expectedStart = 0;
  let actualStart = 0;
  let mismatchCount = 0;
  const descriptions = [];
  const seenDescriptions = new Set();
  while (expectedStart < expected.length || actualStart < actual.length) {
    const expectedNewline = expected.indexOf(0x0a, expectedStart);
    const actualNewline = actual.indexOf(0x0a, actualStart);
    const expectedEnd = expectedNewline === -1 ? expected.length : expectedNewline;
    const actualEnd = actualNewline === -1 ? actual.length : actualNewline;
    const expectedLine = expected.subarray(expectedStart, expectedEnd);
    const actualLine = actual.subarray(actualStart, actualEnd);
    if (!expectedLine.equals(actualLine)) {
      mismatchCount += 1;
      if (descriptions.length < limit) {
        try {
          const expectedRecord = JSON.parse(expectedLine.toString("utf8"));
          const actualRecord = JSON.parse(actualLine.toString("utf8"));
          const expectedStatuses = new Map((expectedRecord.value?.findings ?? []).map((finding) => [finding.id, finding.status]));
          const actualStatuses = new Map((actualRecord.value?.findings ?? []).map((finding) => [finding.id, finding.status]));
          const statusChanges = [...new Set([...expectedStatuses.keys(), ...actualStatuses.keys()])]
            .filter((id) => expectedStatuses.get(id) !== actualStatuses.get(id))
            .map((id) => `${id}:${expectedStatuses.get(id) ?? "<missing>"}->${actualStatuses.get(id) ?? "<missing>"}`);
          const description =
            `${expectedRecord.name ?? actualRecord.name ?? "<unnamed>"}`
            + (statusChanges.length > 0 ? ` [${statusChanges.join(", ")}]` : " [serialized evidence differs]");
          if (!seenDescriptions.has(description)) {
            seenDescriptions.add(description);
            descriptions.push(description);
          }
        } catch {
          if (!seenDescriptions.has("<unparseable record>")) {
            seenDescriptions.add("<unparseable record>");
            descriptions.push("<unparseable record>");
          }
        }
      }
    }
    expectedStart = expectedEnd + (expectedNewline === -1 ? 0 : 1);
    actualStart = actualEnd + (actualNewline === -1 ? 0 : 1);
  }
  return mismatchCount === 0
    ? ""
    : `\n${mismatchCount} JSONL records differ; first ${descriptions.length}: ${descriptions.join("; ")}`;
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
      const lineStart = path.endsWith(".jsonl") ? expected.lastIndexOf(0x0a, Math.max(0, offset - 1)) + 1 : -1;
      const lineEnd = path.endsWith(".jsonl") ? expected.indexOf(0x0a, offset) : -1;
      let recordName = "";
      if (lineStart >= 0 && lineEnd > lineStart) {
        try {
          recordName = `, record=${JSON.parse(expected.subarray(lineStart, lineEnd).toString("utf8")).name}`;
        } catch {
          recordName = ", record=<unparseable>";
        }
      }
      throw new Error(
        `${label} byte mismatch for ${path} (main=${expected.length} bytes, branch=${actual.length} bytes, first offset=${offset}${recordName})`
        + (path.endsWith(".jsonl") ? describeJsonlMismatches(expected, actual) : "")
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
  const counts = { truncated: 0, denied: 0, empty: 0, pairwise: 0 };
  for (const path of paths) {
    for (const line of readFileSync(join(root, path), "utf8").trim().split("\n").filter(Boolean)) {
      const name = JSON.parse(line).name;
      for (const mode of ["truncated", "denied", "empty"]) {
        if (name.includes(`::sweep::${mode}::`)) counts[mode] += 1;
      }
      if (name.includes("::pairwise::")) counts.pairwise += 1;
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
    "cli/extensions/grc-tools/crowdstrike.ts",
    "cli/extensions/grc-tools/tenable.ts",
    "cli/extensions/grc-tools/qualys.ts",
    "cli/extensions/grc-tools/veracode.ts",
    "cli/extensions/grc-tools/knowbe4.ts",
  ];
  const batchDiff = spawnSync("git", ["diff", "--quiet", baselineSha, headSha, "--", ...batchSpecificPaths], {
    cwd: repoRoot,
    stdio: "ignore",
  });
  if (batchDiff.status === 0) {
    throw new Error(`No batch-3 runtime diff exists between immutable base ${baselineSha} and HEAD ${headSha}`);
  }
  if (batchDiff.status !== 1) {
    throw new Error(`Unable to inspect batch-3 diff between ${baselineSha} and ${headSha}`);
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

  const expectedFixturePaths = testFiles.flatMap((testFile) => {
    const integration = testFile.replace(/\.test\.mjs$/, "");
    return fixtureClasses.map((fixtureClass) => `${integration}/${fixtureClass}.json`);
  }).sort();
  const mainFixturePaths = filesUnder(mainFixtures);
  if (JSON.stringify(mainFixturePaths) !== JSON.stringify(expectedFixturePaths)) {
    throw new Error(`stacked-parent fixture registry mismatch\nexpected: ${expectedFixturePaths.join(", ")}\nactual: ${mainFixturePaths.join(", ")}`);
  }
  const compared = compareTrees(mainFixtures, branchFixtures, "curated fixture");
  for (const integration of representativeDistinctIntegrations) {
    const representative = readFileSync(join(branchFixtures, integration, "representative.json"));
    const compliant = readFileSync(join(branchFixtures, integration, "compliant.json"));
    const partial = readFileSync(join(branchFixtures, integration, "partial.json"));
    if (representative.equals(compliant)) {
      throw new Error(`${integration}: representative fixture is byte-identical to compliant`);
    }
    if (representative.equals(partial)) {
      throw new Error(`${integration}: representative fixture is byte-identical to partial`);
    }
  }
  const classes = [...new Set(compared.map((path) => path.split("/").at(-1).replace(/\.json$/, "")))].sort();
  console.log(`Whole-corpus replay passed against immutable stack base ${baselineSha}: ${mainCorpusTests.executed}/${mainCorpusTests.total} non-skipped tests and ${corpusCalls} exact serialized assessment calls matched the stacked parent.`);
  console.log(`Realistic single-dataset sweeps matched the stacked parent: ${sweepCounts.truncated} truncated, ${sweepCounts.denied} denied, ${sweepCounts.empty} empty.`);
  console.log(`Realistic pairwise source-state sweeps matched the stacked parent: ${sweepCounts.pairwise} exact serialized assessment calls.`);
  console.log(`Byte differential passed: ${compared.length} exact fixtures across ${testFiles.length} integrations.`);
  console.log(`Fixture classes: ${classes.join(", ")}.`);
} finally {
  if (worktreeAdded) {
    spawnSync("git", ["worktree", "remove", "--force", mainWorktree], { cwd: repoRoot, stdio: "ignore" });
  }
  rmSync(runRoot, { recursive: true, force: true });
}
