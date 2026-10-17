import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
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
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..", "..");
const runtimeDirectory = join("cli", "extensions", "grc-tools");
const defaultBaselineRef = "origin/main";
const fixtureClasses = ["boundary", "compliant", "denied", "export", "missing-null", "partial", "representative"];
const relativeImport = /^import\s+([^;]*?)\s+from\s+(["'])(\.{1,2}\/[^"']+)\2;?[ \t]*$/gm;
const unavailableBindingSource = `function __differentialUnavailable(specifier, name) {
  const fail = () => {
    throw new Error(\`\${name} from \${specifier} does not exist in the differential baseline; use it only inside portableContractTest\`);
  };
  return new Proxy(function unavailable() {}, { apply: fail, construct: fail, get: fail, has: fail, set: fail });
}
`;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: { ...process.env, ...options.env },
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.status !== 0) {
    const detail = options.capture ? `${result.stdout}\n${result.stderr}`.trim() : "";
    throw new Error(`${command} ${args.join(" ")} failed with exit ${result.status}${detail ? `\n${detail}` : ""}`);
  }
  return result;
}

/** A vendor test joins the differential by writing fixtures; adding one needs no harness edit. */
export function discoverDifferentialTests(root) {
  const testsDirectory = join(root, "cli", "tests");
  return readdirSync(testsDirectory)
    .filter((name) => name.endsWith(".test.mjs"))
    .filter((name) => existsSync(join(root, runtimeDirectory, name.replace(/\.test\.mjs$/, ".ts"))))
    .filter((name) => readFileSync(join(testsDirectory, name), "utf8").includes("writeByteDifferentialFixture("))
    .sort();
}

function importBindings(clause) {
  const bindings = [];
  let rest = clause.trim();
  const defaultBinding = /^([A-Za-z_$][\w$]*)\s*(?:,\s*)?/.exec(rest);
  if (defaultBinding) {
    bindings.push({ imported: "default", local: defaultBinding[1] });
    rest = rest.slice(defaultBinding[0].length);
  }
  const namespace = /^\*\s*as\s+([A-Za-z_$][\w$]*)$/.exec(rest);
  if (namespace) {
    bindings.push({ imported: "*", local: namespace[1] });
  } else if (rest.startsWith("{") && rest.endsWith("}")) {
    for (const entry of rest.slice(1, -1).split(",").map((part) => part.trim()).filter(Boolean)) {
      const named = /^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/.exec(entry);
      if (!named) throw new Error(`Unsupported import binding: ${entry}`);
      bindings.push({ imported: named[1], local: named[2] ?? named[1] });
    }
  } else if (rest) {
    throw new Error(`Unsupported import clause: ${clause}`);
  }
  return bindings;
}

function importStatement(bindings, specifier) {
  const defaultBinding = bindings.find(({ imported }) => imported === "default");
  const namespace = bindings.find(({ imported }) => imported === "*");
  const named = bindings.filter(({ imported }) => imported !== "default" && imported !== "*");
  const clause = [
    ...(defaultBinding ? [defaultBinding.local] : []),
    ...(namespace ? [`* as ${namespace.local}`] : []),
    ...(named.length > 0
      ? [`{ ${named.map(({ imported, local }) => imported === local ? local : `${imported} as ${local}`).join(", ")} }`]
      : []),
  ].join(", ");
  return `import ${clause} from ${JSON.stringify(specifier)};`;
}

/**
 * Rewrites relative imports the baseline cannot satisfy into bindings that throw
 * on first use, so a branch test that imports a new spec still loads there.
 * `exportsFor(specifier)` returns the baseline's export names, null when the
 * module is absent, or undefined to keep the import unchanged.
 */
export function stubUnavailableImports(source, exportsFor) {
  let stubbed = false;
  const rewritten = source.replace(relativeImport, (statement, clause, _quote, specifier) => {
    const available = exportsFor(specifier);
    if (available === undefined) return statement;
    const bindings = importBindings(clause);
    const missing = bindings.filter(({ imported }) =>
      available === null || (imported !== "*" && !available.includes(imported)));
    if (missing.length === 0) return statement;
    stubbed = true;
    const kept = bindings.filter((binding) => !missing.includes(binding));
    return [
      ...(kept.length > 0 ? [importStatement(kept, specifier)] : []),
      ...missing.map(({ imported, local }) =>
        `const ${local} = __differentialUnavailable(${JSON.stringify(specifier)}, ${JSON.stringify(imported)});`),
    ].join("\n");
  });
  return stubbed ? `${unavailableBindingSource}${rewritten}` : rewritten;
}

function filesUnder(root, relativePath = "") {
  const directory = join(root, relativePath);
  return readdirSync(directory).flatMap((name) => {
    const child = join(relativePath, name);
    return lstatSync(join(root, child)).isDirectory() ? filesUnder(root, child) : [child];
  }).sort();
}

function baselineExports(root, targets) {
  const inspector = [
    'import { existsSync } from "node:fs";',
    'import { pathToFileURL } from "node:url";',
    "const exports = {};",
    "for (const target of JSON.parse(process.argv[1])) {",
    "  exports[target] = existsSync(target) ? Object.keys(await import(pathToFileURL(target).href)) : null;",
    "}",
    "process.stdout.write(JSON.stringify(exports));",
  ].join("\n");
  const result = run(process.execPath, ["--input-type=module", "--eval", inspector, JSON.stringify(targets)], {
    cwd: root,
    capture: true,
  });
  return JSON.parse(result.stdout);
}

function copyTestsToBaseline(baselineRoot, testFiles) {
  const sourceTests = join(repoRoot, "cli", "tests");
  const targetTests = join(baselineRoot, "cli", "tests");
  cpSync(join(sourceTests, "helpers"), join(targetTests, "helpers"), { recursive: true });
  for (const testFile of testFiles) cpSync(join(sourceTests, testFile), join(targetTests, testFile));
  const copied = [
    ...testFiles.map((testFile) => join(targetTests, testFile)),
    ...filesUnder(join(targetTests, "helpers")).filter((path) => path.endsWith(".mjs")).map((path) => join(targetTests, "helpers", path)),
  ];
  const copiedSet = new Set(copied);
  const sources = new Map(copied.map((file) => [file, readFileSync(file, "utf8")]));
  const targetOf = (file, specifier) => resolve(dirname(file), specifier);
  const external = new Set();
  for (const [file, source] of sources) {
    for (const match of source.matchAll(relativeImport)) {
      const target = targetOf(file, match[3]);
      if (!copiedSet.has(target)) external.add(target);
    }
  }
  const exportsByTarget = baselineExports(baselineRoot, [...external].sort());
  const stubbedFiles = [];
  for (const [file, source] of sources) {
    const rewritten = stubUnavailableImports(source, (specifier) => {
      const target = targetOf(file, specifier);
      return copiedSet.has(target) ? undefined : exportsByTarget[target];
    });
    if (rewritten === source) continue;
    writeFileSync(file, rewritten);
    stubbedFiles.push(file.slice(targetTests.length + 1));
  }
  return stubbedFiles;
}

function runFixtureSuite(root, testFiles, fixtureDirectory, exportRoot) {
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

function instrumentAssessmentExports(root, testFiles) {
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
import { AsyncLocalStorage as __CorpusAsyncLocalStorage } from "node:async_hooks";
import { appendFileSync as __corpusAppendFileSync, mkdirSync as __corpusMkdirSync } from "node:fs";
// Sweep replays run in the module-load context, outside any decision-fact capture the calling test holds.
const __corpusDetachedContext = __CorpusAsyncLocalStorage.snapshot();
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
function __corpusDatasets(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return [];
  return Object.entries(input).flatMap(([datasetName, dataset]) => {
    if (!dataset || typeof dataset !== "object" || Array.isArray(dataset)) return [];
    const collectionKey = ["data", "rows", "items"].find((key) => Array.isArray(dataset[key]));
    return collectionKey ? [[datasetName, collectionKey]] : [];
  });
}
const __corpusSweptInputs = new Set();
function __corpusSweep(name, args, original) {
  const datasets = __corpusDatasets(args[0]);
  if (datasets.length === 0) return;
  const signature = name + ":" + JSON.stringify(args[0]);
  if (__corpusSweptInputs.has(signature)) return;
  __corpusSweptInputs.add(signature);
  for (const [datasetName, collectionKey] of datasets) {
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
        __corpusRecord(
          name + "::sweep::" + mode + "::" + datasetName,
          "result",
          __corpusDetachedContext(() => original(...mutatedArgs)),
        );
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

function runCorpusSuite(root, testFiles, fixtureDirectory) {
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

function compareTrees(expectedRoot, actualRoot, label) {
  const expectedPaths = filesUnder(expectedRoot);
  const actualPaths = filesUnder(actualRoot);
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    throw new Error(`${label} path mismatch\nbaseline: ${expectedPaths.join(", ")}\nbranch: ${actualPaths.join(", ")}`);
  }
  for (const path of expectedPaths) {
    const expected = readFileSync(join(expectedRoot, path));
    const actual = readFileSync(join(actualRoot, path));
    if (!actual.equals(expected)) {
      let offset = 0;
      while (offset < expected.length && offset < actual.length && expected[offset] === actual[offset]) offset += 1;
      const contextStart = Math.max(0, offset - 160);
      const contextEnd = offset + 320;
      const baselineContext = expected.subarray(contextStart, contextEnd).toString("utf8");
      const branchContext = actual.subarray(contextStart, contextEnd).toString("utf8");
      throw new Error(
        `${label} byte mismatch for ${path} (baseline=${expected.length} bytes, branch=${actual.length} bytes, first offset=${offset})`
        + `\nbaseline context: ${JSON.stringify(baselineContext)}`
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

/** Verdict semantics are the evidence inputs, derived facts, constants, and ordered rules of every check. */
function verdictSemantics(root) {
  const dump = [
    `import { PUBLISHED_INTEGRATION_SPECS } from ${JSON.stringify(pathToFileURL(join(root, "cli", "dist", "extensions", "grc-tools", "spec-registry.js")).href)};`,
    "const semantics = {};",
    "for (const { contract } of PUBLISHED_INTEGRATION_SPECS) {",
    "  semantics[contract.identity.slug] = contract.checks.map((check) => ({",
    "    id: check.id,",
    "    evidenceFields: check.evidenceFields,",
    "    derivedFactRules: Object.entries(check.derivedFactRules ?? {}).map(([name, rule]) => [name, rule.condition]),",
    "    constants: check.criteria.constants,",
    "    rules: check.criteria.rules.map((rule) => ({ status: rule.status, condition: rule.condition })),",
    "  }));",
    "}",
    "process.stdout.write(JSON.stringify(semantics));",
  ].join("\n");
  return JSON.parse(run(process.execPath, ["--input-type=module", "--eval", dump], { cwd: root, capture: true }).stdout);
}

/**
 * Every spec published on both sides must keep identical verdict semantics, so
 * each threshold and rule boundary is the baseline's. New specs are reported.
 */
function compareVerdictSemantics(baselineRoot) {
  const baseline = verdictSemantics(baselineRoot);
  const branch = verdictSemantics(repoRoot);
  const changed = Object.keys(branch).filter((slug) => slug in baseline
    && JSON.stringify(branch[slug]) !== JSON.stringify(baseline[slug]));
  const removed = Object.keys(baseline).filter((slug) => !(slug in branch));
  if (changed.length > 0 || removed.length > 0) {
    throw new Error(`verdict semantics differ from the baseline: changed ${changed.join(", ") || "none"}; removed ${removed.join(", ") || "none"}`);
  }
  return {
    unchanged: Object.keys(branch).filter((slug) => slug in baseline),
    added: Object.keys(branch).filter((slug) => !(slug in baseline)),
  };
}

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function resolveBaseline() {
  const requested = argumentValue("--base") ?? process.env.GRC_DIFFERENTIAL_BASE;
  if (requested) return run("git", ["rev-parse", `${requested}^{commit}`], { capture: true }).stdout.trim();
  const mergeBase = spawnSync("git", ["merge-base", "HEAD", defaultBaselineRef], { cwd: repoRoot, encoding: "utf8" });
  if (mergeBase.status !== 0) {
    throw new Error(`Unable to find the merge base with ${defaultBaselineRef}; run git fetch origin main or pass --base <ref>`);
  }
  return mergeBase.stdout.trim();
}

function main() {
  const runRoot = mkdtempSync(join(tmpdir(), "grclanker-byte-differential-"));
  const baselineRoot = join(runRoot, "baseline");
  const exportRoot = join(runRoot, "exports");
  let worktreeAdded = false;
  try {
    const baselineSha = resolveBaseline();
    run("git", ["merge-base", "--is-ancestor", baselineSha, "HEAD"], { capture: true });
    const runtimeDiff = spawnSync("git", ["diff", "--quiet", baselineSha, "--", "cli/extensions"], { cwd: repoRoot, stdio: "ignore" });
    if (runtimeDiff.status === 0) {
      throw new Error(`The working tree has no runtime change under cli/extensions relative to ${baselineSha}; there is nothing to compare`);
    }
    if (runtimeDiff.status !== 1) throw new Error(`Unable to inspect the runtime diff against ${baselineSha}`);

    run("git", ["worktree", "add", "--detach", baselineRoot, baselineSha]);
    worktreeAdded = true;
    symlinkSync(join(repoRoot, "cli", "node_modules"), join(baselineRoot, "cli", "node_modules"), "dir");
    const branchTests = discoverDifferentialTests(repoRoot);
    const testFiles = branchTests.filter((testFile) =>
      existsSync(join(baselineRoot, runtimeDirectory, testFile.replace(/\.test\.mjs$/, ".ts"))));
    if (testFiles.length === 0) throw new Error("No differential test has a baseline runtime to compare against");
    const withoutBaseline = branchTests.filter((testFile) => !testFiles.includes(testFile));

    run("npm", ["--prefix", join(baselineRoot, "cli"), "run", "build"]);
    run("npm", ["--prefix", join(repoRoot, "cli"), "run", "build"]);
    const stubbedFiles = copyTestsToBaseline(baselineRoot, testFiles);
    const semantics = compareVerdictSemantics(baselineRoot);

    instrumentAssessmentExports(baselineRoot, testFiles);
    instrumentAssessmentExports(repoRoot, testFiles);
    const baselineCorpus = join(runRoot, "corpus-baseline");
    const branchCorpus = join(runRoot, "corpus-branch");
    const baselineCorpusTests = runCorpusSuite(baselineRoot, testFiles, baselineCorpus);
    const branchCorpusTests = runCorpusSuite(repoRoot, testFiles, branchCorpus);
    if (JSON.stringify(baselineCorpusTests) !== JSON.stringify(branchCorpusTests)) {
      throw new Error(`corpus test-count mismatch: baseline=${JSON.stringify(baselineCorpusTests)} branch=${JSON.stringify(branchCorpusTests)}`);
    }
    const corpusPaths = compareTrees(baselineCorpus, branchCorpus, "assessment corpus");
    const corpusCalls = corpusCallCount(baselineCorpus, corpusPaths);
    const sweepCounts = corpusSweepCounts(baselineCorpus, corpusPaths);

    // Rebuild after instrumentation so the curated export run uses unmodified modules.
    run("npm", ["--prefix", join(baselineRoot, "cli"), "run", "build"]);
    run("npm", ["--prefix", join(repoRoot, "cli"), "run", "build"]);
    const baselineFixtures = join(runRoot, "fixtures-baseline");
    const branchFixtures = join(runRoot, "fixtures-branch");
    runFixtureSuite(baselineRoot, testFiles, baselineFixtures, exportRoot);
    runFixtureSuite(repoRoot, testFiles, branchFixtures, exportRoot);

    const expectedFixturePaths = testFiles.flatMap((testFile) => {
      const integration = testFile.replace(/\.test\.mjs$/, "");
      return fixtureClasses.map((fixtureClass) => `${integration}/${fixtureClass}.json`);
    }).sort();
    const baselineFixturePaths = filesUnder(baselineFixtures);
    if (JSON.stringify(baselineFixturePaths) !== JSON.stringify(expectedFixturePaths)) {
      throw new Error(`baseline fixture registry mismatch\nexpected: ${expectedFixturePaths.join(", ")}\nactual: ${baselineFixturePaths.join(", ")}`);
    }
    const compared = compareTrees(baselineFixtures, branchFixtures, "curated fixture");
    for (const testFile of testFiles) {
      const integration = testFile.replace(/\.test\.mjs$/, "");
      const representative = readFileSync(join(branchFixtures, integration, "representative.json"));
      const compliant = readFileSync(join(branchFixtures, integration, "compliant.json"));
      if (representative.equals(compliant)) {
        throw new Error(`${integration}: representative fixture is byte-identical to compliant`);
      }
    }
    const classes = [...new Set(compared.map((path) => path.split("/").at(-1).replace(/\.json$/, "")))].sort();
    console.log(`Baseline ${baselineSha}; differential tests: ${testFiles.join(", ")}.`);
    if (withoutBaseline.length > 0) console.log(`No baseline runtime, so not compared: ${withoutBaseline.join(", ")}.`);
    if (stubbedFiles.length > 0) console.log(`Imports the baseline lacks were stubbed in: ${stubbedFiles.join(", ")}.`);
    console.log(`Verdict semantics match the baseline for ${semantics.unchanged.length} published specs${semantics.added.length > 0 ? `; new on this branch: ${semantics.added.join(", ")}` : ""}.`);
    console.log(`Whole-corpus replay passed: ${baselineCorpusTests.executed}/${baselineCorpusTests.total} non-skipped tests and ${corpusCalls} exact serialized assessment calls matched the baseline.`);
    console.log(`Single-dataset sweeps matched the baseline: ${sweepCounts.truncated} truncated, ${sweepCounts.denied} denied, ${sweepCounts.empty} empty.`);
    console.log(`Byte differential passed: ${compared.length} exact fixtures across ${testFiles.length} integrations.`);
    console.log(`Fixture classes: ${classes.join(", ")}.`);
  } finally {
    if (worktreeAdded) {
      spawnSync("git", ["worktree", "remove", "--force", baselineRoot], { cwd: repoRoot, stdio: "ignore" });
    }
    rmSync(runRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
