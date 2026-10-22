import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";

const REPO_ROOT = resolve(import.meta.dirname, "../..");

function readWorkflow(name) {
  return parseYaml(readFileSync(resolve(REPO_ROOT, ".github", "workflows", name), "utf8"));
}

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

test("the Windows bundle smoke runs when the bundle, installer, or CLI entry changes", () => {
  const triggers = readWorkflow("windows-bundle.yml").on;
  const paths = triggers.pull_request.paths;
  assert.deepEqual(triggers.push.paths, paths);
  for (const required of [
    ".github/workflows/windows-bundle.yml",
    "cli/bin/**",
    "cli/index.ts",
    "cli/scripts/build-native-bundle.mjs",
    "public/install.ps1",
  ]) {
    assert.ok(paths.includes(required), `${required} must trigger the Windows bundle smoke`);
  }
  for (const path of paths) {
    assert.ok(existsSync(resolve(REPO_ROOT, path.replace(/\/\*\*$/, ""))), `${path} no longer exists`);
  }
});
