import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { DEFAULT_NODE_VERSION, getTargetDefinitions } from "../scripts/build-native-bundle.mjs";

const REPO_ROOT = resolve(import.meta.dirname, "../..");

function readWorkflow(name) {
  return parseYaml(readFileSync(resolve(REPO_ROOT, ".github", "workflows", name), "utf8"));
}

function smokeJobIds(jobs) {
  return Object.keys(jobs).filter((name) => name.startsWith("smoke"));
}

// -latest labels are refused: macos-latest already moved from Intel to Apple silicon once.
const NATIVE_RUNNERS = {
  "darwin-arm64": /^macos-\d+$/,
  "darwin-x64": /^macos-\d+-intel$/,
  "linux-arm64": /^ubuntu-\d+\.\d+-arm$/,
  "linux-x64": /^ubuntu-\d+\.\d+$/,
  "win32-arm64": /^windows-\d+-arm$/,
  "win32-x64": /^windows-\d+$/,
};

test("CI test shards run the test:cli command over every test file", () => {
  const { scripts } = JSON.parse(readFileSync(resolve(REPO_ROOT, "cli", "package.json"), "utf8"));
  const testCli = /^npm run build && node --test (\S.*)$/.exec(scripts["test:cli"]);
  assert.ok(testCli, "test:cli changed shape; update the cli-tests shards in ci.yml to match it");

  const job = readWorkflow("ci.yml").jobs["cli-tests"];
  assert.deepEqual(Object.keys(job.strategy.matrix), ["shard"]);
  const shards = job.strategy.matrix.shard;
  assert.deepEqual(shards, shards.map((_, index) => index + 1), "shards must be numbered 1 through N");

  const runs = job.steps.map((step) => step.run);
  const testStep = job.steps.find((step) => step.run?.startsWith("node --test"));
  assert.equal(testStep.run, `node --test --test-shard="$SHARD/$SHARD_TOTAL" ${testCli[1]}`);
  assert.deepEqual(testStep.env, { SHARD: "${{ matrix.shard }}", SHARD_TOTAL: "${{ strategy.job-total }}" });
  assert.ok(runs.indexOf("npm run build") >= 0 && runs.indexOf("npm run build") < runs.indexOf(testStep.run));
});

test("the verify job waits on every other CI job", () => {
  const { jobs } = readWorkflow("ci.yml");
  const others = Object.keys(jobs).filter((name) => name !== "verify");
  assert.deepEqual([...jobs.verify.needs].sort(), others.sort());
});

test("release-bundles smokes every bundle it builds on a runner of the bundle's own OS and architecture", () => {
  const { jobs } = readWorkflow("release-bundles.yml");
  const build = jobs.build.steps.find((step) => step.name === "Build release bundles");
  assert.equal(build.run, "npm run build:bundle -- --all");

  const smoked = [];
  for (const id of smokeJobIds(jobs)) {
    const job = jobs[id];
    assert.equal(job.needs, "build");
    assert.equal(job["runs-on"], "${{ matrix.runner }}");
    const { matrix } = job.strategy;
    if (matrix.target) {
      assert.deepEqual([...matrix.target].sort(), matrix.include.map((leg) => leg.target).sort(), `${id} has a target without a runner`);
    }
    for (const { target, runner } of matrix.include) {
      assert.ok(NATIVE_RUNNERS[target], `no native runner is known for ${target}`);
      assert.match(runner, NATIVE_RUNNERS[target], `${target} has to run on its own OS and architecture, not ${runner}`);
      smoked.push(target);
    }
  }
  assert.deepEqual(smoked.sort(), Object.keys(getTargetDefinitions(DEFAULT_NODE_VERSION)).sort());
  assert.deepEqual(jobs["smoke-windows"].strategy.matrix.installer, ["powershell", "pwsh"]);
  // GitHub only adds pipefail when bash is named, and the runner OS comes from the matrix.
  assert.equal(jobs["smoke-unix"].defaults.run.shell, "bash");
  assert.equal(jobs["smoke-windows"].defaults.run.shell, "pwsh");
});

test("release-bundles publishes only from a tag push after every bundle passed its smoke check", () => {
  const workflow = readWorkflow("release-bundles.yml");
  const { jobs } = workflow;
  assert.deepEqual(workflow.on.push.tags, ["v*"]);
  // Pushes to main run too, so tag-only steps have to check the ref, not the event.
  const verifyTag = jobs.build.steps.find((step) => step.name === "Verify tag matches CLI version");
  assert.equal(verifyTag.if, "github.ref_type == 'tag'");

  const smokes = smokeJobIds(jobs);
  assert.ok(smokes.length > 0);
  const gate = jobs["release-gate"];
  assert.deepEqual([...gate.needs].sort(), ["build", ...smokes].sort());
  assert.equal(gate.if, "${{ !cancelled() }}");
  assert.equal(gate.steps.at(-1).env.NEEDS, "${{ toJSON(needs) }}");

  assert.deepEqual([...jobs.publish.needs].sort(), ["build", "release-gate", ...smokes].sort());
  assert.equal(jobs.publish.if, "success() && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')");

  for (const [id, job] of Object.entries(jobs)) {
    if (id === "publish") continue;
    const permissions = job.permissions ?? workflow.permissions;
    assert.equal(typeof permissions, "object", `${id} must list its permissions`);
    assert.ok(!Object.values(permissions).includes("write"), `only publish may write, but ${id} can`);
  }
});

test("pull requests and pushes to main that touch a bundle input or an installer run the release build and smoke checks", () => {
  const triggers = readWorkflow("release-bundles.yml").on;
  assert.ok("workflow_dispatch" in triggers);
  const { paths } = triggers.pull_request;
  assert.deepEqual(triggers.push.branches, ["main"]);
  assert.deepEqual(triggers.push.paths, paths);
  for (const required of [
    ".github/workflows/release-bundles.yml",
    "cli/bin/**",
    "cli/index.ts",
    "cli/scripts/build-native-bundle.mjs",
    "public/install",
    "public/install.ps1",
  ]) {
    assert.ok(paths.includes(required), `${required} must trigger the release dry run`);
  }
  for (const path of paths) {
    assert.ok(existsSync(resolve(REPO_ROOT, path.replace(/\/\*\*$/, ""))), `${path} no longer exists`);
  }
});
