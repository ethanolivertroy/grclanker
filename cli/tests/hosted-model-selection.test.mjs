import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { ModelRuntime, parseArgs } from "@earendil-works/pi-coding-agent";
import { resolveCliModel } from "../node_modules/@earendil-works/pi-coding-agent/dist/core/model-resolver.js";
import { buildCliLaunchArgs } from "../dist/pi/launch.js";

const cliRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const hooksUrl = pathToFileURL(join(cliRoot, "tests", "helpers", "setup-cancel-mock-hooks.mjs")).href;
const preload = `data:text/javascript,${encodeURIComponent([
  'import { register } from "node:module";',
  `register(${JSON.stringify(hooksUrl)});`,
  'Object.defineProperty(process.stdin, "isTTY", { value: true });',
  'Object.defineProperty(process.stdout, "isTTY", { value: true });',
].join("\n"))}`;

test("Anthropic setup defaults to Sonnet 4.6 and pins new sessions without overriding resumed sessions", () => {
  const base = mkdtempSync(join(tmpdir(), "grclanker-hosted-model-"));
  const recordPath = join(base, "pi-launch.json");
  const options = {
    encoding: "utf8",
    timeout: 30_000,
    cwd: base,
    env: {
      ...process.env,
      GRCLANKER_HOME: base,
      GRCLANKER_TEST_SETUP_MODE: "anthropic",
      GRCLANKER_TEST_PI_LAUNCH_RECORD: recordPath,
    },
  };
  try {
    const run = spawnSync(process.execPath, ["--import", preload, join(cliRoot, "dist", "index.js")], options);
    assert.equal(run.status, 0, `${run.stdout}${run.stderr}`);
    const settings = JSON.parse(readFileSync(join(base, ".grclanker", "agent", "settings.json"), "utf8"));
    assert.equal(settings.defaultProvider, "anthropic");
    assert.equal(settings.defaultModel, "claude-sonnet-4-6");
    const fresh = JSON.parse(readFileSync(recordPath, "utf8"));
    assert.equal(parseArgs(fresh.args).model, "anthropic/claude-sonnet-4-6");

    const resumed = spawnSync(process.execPath, [
      "--import", preload, join(cliRoot, "dist", "index.js"), "--session", "saved-session",
    ], options);
    assert.equal(resumed.status, 0, `${resumed.stdout}${resumed.stderr}`);
    const restored = parseArgs(JSON.parse(readFileSync(recordPath, "utf8")).args);
    assert.equal(restored.session, "saved-session");
    assert.equal(restored.model, undefined, "Pi must restore the hosted session's own model");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("a retired hosted model is sent as its exact custom ID rather than silently selecting Pi's default", async () => {
  const base = mkdtempSync(join(tmpdir(), "grclanker-hosted-retired-model-"));
  try {
    const runtime = await ModelRuntime.create({
      authPath: join(base, "auth.json"),
      modelsPath: null,
      modelsStorePath: join(base, "models-cache.json"),
      refreshOnCreate: false,
      allowModelNetwork: false,
    });
    assert.ok(runtime.getModel("anthropic", "claude-sonnet-4-6"));
    assert.equal(runtime.getModel("anthropic", "claude-sonnet-4-20250514"), undefined);
    const args = parseArgs(buildCliLaunchArgs(cliRoot, join(base, "agent"), {
      modelMode: "hosted",
      defaultProvider: "anthropic",
      defaultModel: "claude-sonnet-4-20250514",
    }));
    const resolved = resolveCliModel({ cliModel: args.model, modelRuntime: runtime });
    assert.equal(resolved.error, undefined);
    assert.equal(resolved.model.provider, "anthropic");
    assert.equal(resolved.model.id, "claude-sonnet-4-20250514");
    assert.match(resolved.warning, /Using custom model id/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
