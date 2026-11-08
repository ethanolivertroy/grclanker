import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { assertCanaryWindowsAbsent } from "./helpers/canary-windows.mjs";
import { waitForText } from "./helpers/terminal-screen.mjs";

const cliRoot = fileURLToPath(new URL("../", import.meta.url));
const cliEntry = "dist/adapters/claude-api/cli.js";
const scriptVersion = spawnSync("script", ["--version"], { encoding: "utf8" });
const hasUtilLinuxScript = scriptVersion.status === 0 && /util-linux/.test(`${scriptVersion.stdout}${scriptVersion.stderr}`);

// Preserve source-test resolution preloads without accidentally starting the CLI as another test runner.
function childPreloads() {
  const args = [];
  for (let index = 0; index < process.execArgv.length; index += 1) {
    const arg = process.execArgv[index];
    if (arg === "--import") args.push(arg, process.execArgv[++index]);
    else if (arg.startsWith("--import=")) args.push(arg);
  }
  return args;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function scratchDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-claude-api-cli-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function fakeApi(t, answer) {
  const requests = [];
  const failures = [];
  const server = createServer(async (request, response) => {
    try {
      let raw = "";
      for await (const chunk of request) raw += chunk;
      const body = JSON.parse(raw);
      requests.push({ body, url: request.url });
      await answer({ request, response, body, requests });
    } catch (error) {
      failures.push(error);
      response.destroy();
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    assert.deepEqual(failures, [], "the fake Messages API handled each request");
  });
  return { requests, baseURL: `http://127.0.0.1:${server.address().port}` };
}

function message(response, model, content, stopReason = "end_turn") {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({
    id: "msg_cli_fixture", type: "message", role: "assistant", model, content,
    stop_reason: stopReason, stop_sequence: null,
    usage: { input_tokens: 1, output_tokens: 1 },
  }));
}

function startCli(t, api, args = [], { terminal = false, extraEnv = {} } = {}) {
  const home = scratchDir(t);
  const command = [process.execPath, ...childPreloads(), cliEntry, ...args];
  const child = terminal
    ? spawn("script", ["-qfec", `exec ${command.map(shellQuote).join(" ")}`, "/dev/null"], {
      cwd: cliRoot,
      env: childEnv(home, api, extraEnv),
    })
    : spawn(command[0], command.slice(1), {
      cwd: cliRoot,
      env: childEnv(home, api, extraEnv),
      stdio: ["pipe", "pipe", "pipe"],
    });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  const closed = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, closed, output: () => `${stdout}${stderr}` };
}

function childEnv(home, api, extra) {
  return {
    ...process.env,
    HOME: home,
    ANTHROPIC_API_KEY: "offline-cli-fixture-key",
    ANTHROPIC_AUTH_TOKEN: "",
    ANTHROPIC_BASE_URL: api.baseURL,
    ANTHROPIC_LOG: "off",
    TERM: "xterm-256color",
    ...extra,
  };
}

async function exitWithin(run, milliseconds = 5000) {
  let timer;
  try {
    return await Promise.race([
      run.closed,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`CLI did not exit within ${milliseconds} ms: ${run.output()}`)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

test("the Claude API CLI distinguishes completed answers from incomplete and refused turns", { timeout: 35000 }, async (t) => {
  const unknownReason = "Wz6Np4Hx8Fq2Rv9Km3Bt7Lc5";
  const scenarios = [
    { name: "end_turn", reason: "end_turn" },
    { name: "max_tokens", reason: "max_tokens", failure: /max_tokens/ },
    { name: "model_context_window_exceeded", reason: "model_context_window_exceeded", failure: /model_context_window_exceeded/ },
    { name: "refusal", reason: "refusal", failure: /declin|refus/i },
    { name: "unknown reason containing private data", reason: unknownReason, failure: /unknown stop reason/i },
    { name: "null reason", reason: null, failure: /unknown stop reason/i },
    { name: "end_turn without final text", reason: "end_turn", noText: true, failure: /no final text/i },
  ];
  for (const scenario of scenarios) {
    await t.test(scenario.name, async (t) => {
      const api = await fakeApi(t, ({ response, body }) => message(response, body.model, scenario.noText ? [] : [{ type: "text", text: "Assessment fixture text." }], scenario.reason));
      const result = await exitWithin(startCli(t, api, ["Assess the supplied evidence."]));
      assert.equal(api.requests.length, 1);
      assert.equal(result.signal, null);
      if (!scenario.failure) {
        assert.equal(result.code, 0, result.stderr);
        assert.equal(result.stdout, "Assessment fixture text.\n");
        assert.equal(result.stderr, "");
      } else {
        assert.notEqual(result.code, 0, "a partial assessment cannot be reported as successful");
        assert.equal(result.stdout, "", "incomplete text is not printed as the final answer");
        assert.match(result.stderr, scenario.failure);
        assertCanaryWindowsAbsent(assert, `${result.stdout}${result.stderr}`, [unknownReason], `${scenario.name} completion diagnostic`);
      }
    });
  }
});

test("the noninteractive Claude API CLI denies writers and redacts their approval arguments", { timeout: 15000 }, async (t) => {
  const workspace = scratchDir(t);
  const target = join(workspace, "denied-export");
  const secret = "Bp5Hx8Rq2Lm7Nv4Kz9Wt3Fc6";
  const api = await fakeApi(t, ({ response, body, requests }) => {
    message(response, body.model, requests.length === 1
      ? [{ type: "tool_use", id: "toolu_denied_writer", name: "github_export_audit_bundle", input: { organization: "fixture", api_token: secret, api_base_url: api.baseURL, output_dir: target } }]
      : [{ type: "text", text: "The export was declined; nothing was written." }], requests.length === 1 ? "tool_use" : "end_turn");
  });
  const result = await exitWithin(startCli(t, api, ["--tools", "github_export_audit_bundle", "Export the supplied organization evidence."]));
  assert.equal(result.signal, null);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /export was declined/);
  assert.match(result.stderr, /No interactive terminal; write denied\./);
  assert.match(result.stderr, /Approval required: github_export_audit_bundle/);
  assert.match(result.stderr, /\[redacted\]/i);
  assertCanaryWindowsAbsent(assert, `${result.stdout}${result.stderr}`, [secret], "noninteractive approval display");
  assert.equal(existsSync(target), false);
  assert.equal(api.requests.length, 2);
  const toolResult = api.requests[1].body.messages.flatMap((entry) => Array.isArray(entry.content) ? entry.content : [])
    .find((entry) => entry.type === "tool_result" && entry.tool_use_id === "toolu_denied_writer");
  assert.ok(toolResult);
  assert.equal(toolResult.is_error, true);
  assert.match(JSON.stringify(toolResult.content), /did not approve/);
});

test("the Claude API CLI bounds provider and malformed-response diagnostics without echoing private data", { timeout: 25000 }, async (t) => {
  const canaries = ["Lj7Rw2Mq9Vb4Hs6Kp8Yt5Zx3", "Cn8Fp4Vq2Rz6Hw9Jm3Kx7Lb5", "Qt4Gv8Np2Wm6Lx9Rz3Hk7Fb5"];
  const privateURL = `https://private-provider.invalid/tenant/${canaries[0]}?api_key=${canaries[1]}`;
  for (const shape of ["json400", "text502", "malformed200"]) {
    await t.test(shape, async (t) => {
      const api = await fakeApi(t, ({ response }) => {
        response.writeHead(shape === "json400" ? 400 : shape === "text502" ? 502 : 200, {
          "content-type": shape === "text502" ? "text/plain" : "application/json",
          "request-id": canaries[2],
          "x-private-header": canaries[1],
          "retry-after": "0",
        });
        response.end(shape === "json400"
          ? JSON.stringify({ type: "error", error: { type: "invalid_request_error", message: `api_key=${canaries[0]} upstream=${privateURL}` } })
          : shape === "text502" ? `gateway private response ${canaries[0]} ${privateURL}` : `${canaries[0]} is not JSON ${privateURL}`);
      });
      const result = await exitWithin(startCli(t, api, ["Assess the supplied evidence."]), 10000);
      assert.equal(result.signal, null);
      assert.notEqual(result.code, 0);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /Claude API|request|response|transport/i);
      assertCanaryWindowsAbsent(assert, `${result.stdout}${result.stderr}`, canaries, `${shape} CLI diagnostics`);
      assert.doesNotMatch(result.stderr, /private-provider\.invalid|x-private-header|invalid_request_error/);
      assert.ok(result.stderr.length < 300, "provider diagnostics are bounded instead of serializing the response");
      if (shape === "json400") assert.match(result.stderr, /400/);
      if (shape === "text502") assert.match(result.stderr, /502/);
    });
  }
});

test("SIGTERM cancels an outstanding Claude request without another model turn", {
  skip: process.platform === "win32" ? "needs POSIX signal delivery" : false,
  timeout: 15000,
}, async (t) => {
  let received;
  const requestStarted = new Promise((resolve) => { received = resolve; });
  let disconnected;
  const requestClosed = new Promise((resolve) => { disconnected = resolve; });
  const api = await fakeApi(t, ({ response }) => {
    response.once("close", disconnected);
    received();
  });
  const run = startCli(t, api, ["Assess the supplied evidence."]);
  await requestStarted;
  run.child.kill("SIGTERM");
  const result = await exitWithin(run);
  await requestClosed;
  assert.equal(result.signal, null, "the CLI handles the signal and closes its request");
  assert.equal(result.code, 143);
  assert.match(result.stderr, /cancel/i);
  assert.equal(result.stdout, "");
  assert.equal(api.requests.length, 1, "a cancelled run cannot request a continuation");
});

test("Ctrl-C ends a pending terminal approval and cancels queued writers without effects", {
  skip: hasUtilLinuxScript ? false : "needs util-linux script(1) for a pseudo-terminal",
  timeout: 15000,
}, async (t) => {
  const workspace = scratchDir(t);
  const targets = [join(workspace, "writer-one"), join(workspace, "writer-two")];
  const api = await fakeApi(t, ({ response, body, requests }) => {
    message(response, body.model, requests.length === 1
      ? targets.map((target, index) => ({ type: "tool_use", id: `toolu_write_${index}`, name: "oscal_init_workspace", input: { workspace_dir: target } }))
      : [{ type: "text", text: "A cancelled run must not request this answer." }], requests.length === 1 ? "tool_use" : "end_turn");
  });
  const run = startCli(t, api, ["--tools", "oscal_init_workspace", "Initialize the two evidence workspaces."], {
    terminal: true,
    extraEnv: { GRCLANKER_TRESTLE_BIN: join(workspace, "unavailable-trestle") },
  });
  await waitForText(run.output, (text) => text.includes("Approve this call? [y/N]"), "the interactive write approval", 8000);
  assert.ok(targets.every((target) => !existsSync(target)), "approval is pending before either writer starts");
  run.child.stdin.write("\x03");
  const result = await exitWithin(run);
  const output = `${result.stdout}${result.stderr}`;
  assert.equal(result.signal, null);
  assert.equal(result.code, 130, output);
  assert.match(output, /cancel/i);
  assert.equal((output.match(/Approve this call\? \[y\/N\]/g) ?? []).length, 1, "the queued approval is cancelled instead of opening another question");
  assert.equal(api.requests.length, 1, "approval cancellation ends the model run");
  assert.ok(targets.every((target) => !existsSync(target)), "neither pending write can create its workspace after cancellation");
});

test("terminal approval still executes the exact requested writer and completes the model turn", {
  skip: hasUtilLinuxScript ? false : "needs util-linux script(1) for a pseudo-terminal",
  timeout: 15000,
}, async (t) => {
  const workspace = scratchDir(t);
  const target = join(workspace, "approved-workspace");
  const trestle = join(workspace, "fixture-trestle");
  writeFileSync(trestle, "#!/bin/sh\nmkdir .trestle\n", { mode: 0o700 });
  const api = await fakeApi(t, ({ response, body, requests }) => {
    message(response, body.model, requests.length === 1
      ? [{ type: "tool_use", id: "toolu_approved_writer", name: "oscal_init_workspace", input: { workspace_dir: target, mode: "local" } }]
      : [{ type: "text", text: "The approved workspace was initialized." }], requests.length === 1 ? "tool_use" : "end_turn");
  });
  const run = startCli(t, api, ["--tools", "oscal_init_workspace", "Initialize the requested evidence workspace."], {
    terminal: true,
    extraEnv: { GRCLANKER_TRESTLE_BIN: trestle },
  });
  await waitForText(run.output, (text) => text.includes("Approve this call? [y/N]"), "the interactive write approval", 8000);
  assert.equal(existsSync(target), false, "no native effect precedes operator approval");
  run.child.stdin.write("y\n");
  const result = await exitWithin(run);
  assert.equal(result.signal, null);
  assert.equal(result.code, 0, `${result.stdout}${result.stderr}`);
  assert.ok(existsSync(join(target, ".trestle")), "the approved native writer ran with the requested output path");
  assert.equal(api.requests.length, 2);
  const toolResult = api.requests[1].body.messages.flatMap((entry) => Array.isArray(entry.content) ? entry.content : [])
    .find((entry) => entry.type === "tool_result" && entry.tool_use_id === "toolu_approved_writer");
  assert.ok(toolResult, "the SDK sends the result of the approved call to the model");
  assert.notEqual(toolResult.is_error, true);
  assert.match(`${result.stdout}${result.stderr}`, /The approved workspace was initialized\./);
});
