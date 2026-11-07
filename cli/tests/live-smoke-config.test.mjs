import test from "node:test";
import assert from "node:assert/strict";
import { MissingAuthenticationError } from "../dist/extensions/grc-tools/auth-errors.js";
import { resolveLiveSmokeConfiguration } from "../scripts/live-smoke-config.mjs";
import { resolveGitHubConfiguration } from "../dist/extensions/grc-tools/github.js";

test("live smoke preflight uses the canonical resolver once and preserves its ready configuration", async () => {
  const config = { token: "synthetic token", sourceChain: ["default-config-file"] };
  let calls = 0;
  const result = await resolveLiveSmokeConfiguration("fixture", async () => { calls += 1; return config; });
  assert.equal(result.kind, "ready");
  assert.equal(result.config, config);
  assert.equal(calls, 1);
});

test("only a typed missing-auth result skips a live smoke", async (t) => {
  const logs = [];
  t.mock.method(console, "log", (message) => logs.push(message));
  assert.deepEqual(await resolveLiveSmokeConfiguration("fixture", () => { throw new MissingAuthenticationError("Set FIXTURE_TOKEN."); }), { kind: "unconfigured" });
  assert.deepEqual(logs, ["Skipping live fixture smoke test: Set FIXTURE_TOKEN."]);
  const invalid = new Error("Credentials are required, but the configured file is malformed");
  await assert.rejects(resolveLiveSmokeConfiguration("fixture", () => { throw invalid; }), (error) => error === invalid);
  assert.equal(logs.length, 1, "an invalid configuration must fail instead of becoming a skipped smoke");
});

test("a GitHub smoke without target scope or credentials remains an optional skipped check", async (t) => {
  t.mock.method(console, "log", () => {});
  for (const env of [{}, { GITHUB_ORG: "synthetic-org" }]) {
    const result = await resolveLiveSmokeConfiguration("GitHub", () => resolveGitHubConfiguration({}, env));
    assert.equal(result.kind, "unconfigured");
  }
});
