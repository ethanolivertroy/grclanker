import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtempSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Anthropic from "@anthropic-ai/sdk";
import { Type } from "typebox";
import {
  createClaudeApiGrcTool,
  createGrclankerClaudeApiAgent,
  DEFAULT_CLAUDE_API_GRC_TOOLS,
  SERVER_SIDE_FALLBACK_BETA,
} from "../dist/adapters/claude-api/agent.js";
import { collectRegisteredGrcTools } from "../dist/core/registry.js";
import { runRunnableTool } from "@anthropic-ai/sdk/lib/tools/BetaRunnableTool";
import { assertCanaryWindowsAbsent } from "./helpers/canary-windows.mjs";

const offlineClient = () => new Anthropic({ apiKey: "offline-placeholder-key", baseURL: "http://127.0.0.1:9", maxRetries: 0 });

function fixture(name, execute) {
  return {
    name,
    label: name,
    description: "Offline adapter fixture",
    parameters: Type.Object({ query: Type.String(), api_token: Type.Optional(Type.String()) }),
    execute,
  };
}

const toolUse = { id: "toolu_fixture", type: "tool_use", name: "fixture", input: {} };

function message(content, stopReason = "end_turn") {
  return { id: "msg_fixture", type: "message", role: "assistant", model: "claude-opus-5-5", content, stop_reason: stopReason, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } };
}

async function withMessagesApi(respond, run) {
  const requests = [];
  const server = createServer(async (request, response) => {
    let text = "";
    for await (const chunk of request) text += chunk;
    const body = JSON.parse(text);
    requests.push(body);
    const reply = await respond(body, requests.length);
    response.writeHead(reply.status ?? 200, { "content-type": "application/json", ...reply.headers });
    response.end(typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const client = new Anthropic({ apiKey: "offline-placeholder-key", baseURL: `http://127.0.0.1:${server.address().port}`, maxRetries: 0 });
  try {
    return await run(client, requests);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

function toolResult(request, callId) {
  return request.messages.flatMap((entry) => Array.isArray(entry.content) ? entry.content : [])
    .find((block) => block.type === "tool_result" && block.tool_use_id === callId);
}

test("Claude API agent defaults to public-data tools, reviewers, and cached instructions", () => {
  const agent = createGrclankerClaudeApiAgent(offlineClient());
  assert.deepEqual(agent.tools.map((tool) => tool.name), [
    ...DEFAULT_CLAUDE_API_GRC_TOOLS, "grclanker_load_workflow", "grclanker_load_skill", "auditor", "verifier",
  ]);
  const { params } = agent;
  assert.equal(params.model, "claude-opus-5-5");
  assert.equal(params.thread, false);
  assert.deepEqual(params.thinking, { type: "adaptive" });
  assert.deepEqual(params.betas, [SERVER_SIDE_FALLBACK_BETA]);
  assert.equal(params.fallbacks, "default");
  assert.equal(params.system[0].cache_control.type, "ephemeral");
  assert.match(params.system[0].text, /Evidence over opinion/);
  assert.match(params.system[0].text, /Claude API tool runner runtime/);
  const noFallback = createGrclankerClaudeApiAgent(offlineClient(), { serverSideFallback: false }).params;
  assert.equal(noFallback.fallbacks, undefined);
  assert.equal(noFallback.betas, undefined);
  assert.throws(() => createGrclankerClaudeApiAgent(offlineClient(), { toolNames: ["missing_tool"] }), /Unknown grclanker tool/);
});

test("every registered domain tool adapts with its native name and an object schema", () => {
  for (const nativeTool of collectRegisteredGrcTools()) {
    const adapted = createClaudeApiGrcTool(nativeTool);
    assert.equal(adapted.name, nativeTool.name);
    assert.equal(adapted.input_schema.type, "object");
    assert.equal(typeof adapted.run, "function");
  }
});

test("Claude API tools validate input, mark failures as errors, and redact credential echoes", async () => {
  let calls = 0;
  const tool = createClaudeApiGrcTool(fixture("example_check_access", async (_id, args) => {
    calls += 1;
    if (args.query === "fail") {
      return { content: [{ type: "text", text: `denied for ${args.api_token}` }], isError: true };
    }
    return { content: [{ type: "text", text: "reachable" }] };
  }));
  assert.deepEqual(await tool.run({ query: "ok" }, { toolUse }), [{ type: "text", text: "reachable" }]);
  await assert.rejects(tool.run({}, { toolUse }), (error) => error.name === "ToolError");
  assert.equal(calls, 1, "invalid input never reaches the native tool");
  await assert.rejects(tool.run({ query: "fail", api_token: "sekret-value-123" }, { toolUse }), (error) => {
    const text = JSON.stringify(error.content);
    return error.name === "ToolError" && !text.includes("sekret-value-123");
  });
});

test("Claude API write tools run only after operator approval", async () => {
  let calls = 0;
  const native = fixture("example_export_bundle", async () => {
    calls += 1;
    return { content: [{ type: "text", text: "written" }] };
  });
  await assert.rejects(createClaudeApiGrcTool(native).run({ query: "x" }, { toolUse }), /did not approve/);
  const requests = [];
  const denied = createClaudeApiGrcTool(native, async (request) => { requests.push(request); return false; });
  await assert.rejects(denied.run({ query: "x" }, { toolUse }), /did not approve/);
  assert.equal(calls, 0);
  assert.deepEqual(requests, [{ toolName: "example_export_bundle", input: { query: "x" } }]);
  const approved = createClaudeApiGrcTool(native, async () => true);
  assert.deepEqual(await approved.run({ query: "x" }, { toolUse }), [{ type: "text", text: "written" }]);
  assert.equal(calls, 1);
  for (const value of ["yes", 1, {}, null]) {
    await assert.rejects(createClaudeApiGrcTool(native, async () => value).run({ query: "x" }, { toolUse }), /did not approve/);
  }
  assert.equal(calls, 1, "a JavaScript callback must return exactly true to authorize a write");
});

test("reviewers mark incomplete responses as errors before the SDK sends them to the parent model", async (t) => {
  const privateText = "Vg9Km3Qp7Lb2Rt6Hx4Ns8Zc5";
  const cases = [
    { reason: "end_turn", success: true },
    { reason: "stop_sequence", success: true },
    ...["max_tokens", "model_context_window_exceeded", "pause_turn", "tool_use", "refusal", null, `unknown-${privateText}`].map((reason) => ({ reason, success: false })),
    { reason: "end_turn", success: false, empty: true },
  ];
  for (const scenario of cases) {
    await t.test(`${scenario.reason ?? "null"}${scenario.empty ? " without text" : ""}`, async () => {
      const review = scenario.empty ? "  " : scenario.success ? "The cited evidence supports the stated control." : `Unfinished review: ${privateText}`;
      await withMessagesApi((_body, index) => ({ body: index === 1
        ? message([{ type: "tool_use", id: "review", name: "verifier", input: { evidence: "Inspect the supplied control citations." } }], "tool_use")
        : index === 2 ? message([{ type: "text", text: review }], scenario.reason)
          : message([{ type: "text", text: "Review outcome acknowledged." }]) }), async (client, requests) => {
        const agent = createGrclankerClaudeApiAgent(client);
        await client.beta.messages.toolRunner({ ...agent.params, stream: false, max_iterations: 4, messages: [{ role: "user", content: "Verify the audit evidence." }] });
        assert.equal(requests.length, 3);
        const result = toolResult(requests[2], "review");
        assert.ok(result);
        assert.equal(result.is_error === true, !scenario.success);
        const rendered = JSON.stringify(result.content);
        if (scenario.success) assert.match(rendered, /cited evidence supports/);
        else {
          assertCanaryWindowsAbsent(assert, rendered, [privateText], "incomplete review result");
          assert.match(rendered, /declined|before a final answer|no final text/);
        }
      });
    });
  }
});

test("reviewer provider failures expose only bounded diagnostics through the real SDK loop", async (t) => {
  const canary = "Bq6Tv9Mk3Hs7Wp2Lz8Jc4Ry5";
  for (const scenario of [
    { name: "provider JSON error", status: 400, body: { type: "error", error: { type: "invalid_request_error", message: `api_key=${canary}` }, request_id: canary } },
    { name: "malformed successful body", status: 200, body: `private transport body api_key=${canary}` },
  ]) {
    await t.test(scenario.name, async () => {
      await withMessagesApi((_body, index) => index === 2 ? { status: scenario.status, body: scenario.body, headers: { "request-id": canary } } : { body: index === 1
        ? message([{ type: "tool_use", id: "review-error", name: "auditor", input: { evidence: "Review these citations." } }], "tool_use")
        : message([{ type: "text", text: "The review service failed; no review is claimed." }]) }, async (client, requests) => {
        const agent = createGrclankerClaudeApiAgent(client);
        await client.beta.messages.toolRunner({ ...agent.params, stream: false, max_iterations: 4, messages: [{ role: "user", content: "Audit the supplied evidence." }] });
        assert.equal(requests.length, 3);
        const result = toolResult(requests[2], "review-error");
        assert.equal(result.is_error, true);
        assertCanaryWindowsAbsent(assert, JSON.stringify(result.content), [canary], "model-visible failure result");
        assert.match(JSON.stringify(result.content), /Claude API .*failed/);
      });
    });
  }
  const agent = createGrclankerClaudeApiAgent({ messages: { async create() { throw new Error(`provider endpoint https://private.invalid/?api_key=${canary}`); } } });
  const result = await runRunnableTool(agent.tools.find((entry) => entry.name === "verifier"), { evidence: "Review these citations." }, { toolUse });
  assert.equal(result.isError, true);
  assertCanaryWindowsAbsent(assert, JSON.stringify(result.content), [canary], "model-visible failure result");
  assert.doesNotMatch(JSON.stringify(result.content), /private\.invalid/);
});

test("approval failures are bounded error results and never reach the native writer", async () => {
  const canary = "Fh8Nz4Qw7Xp2Vm6Kr9Lb3Tc5";
  let nativeCalls = 0;
  await withMessagesApi((_body, index) => ({ body: index === 1
    ? message([{ type: "tool_use", id: "approval-error", name: "example_export_bundle", input: { query: "scope" } }], "tool_use")
    : message([{ type: "text", text: "The export did not run." }]) }), async (client, requests) => {
    const tool = createClaudeApiGrcTool(fixture("example_export_bundle", async () => { nativeCalls += 1; return { content: [{ type: "text", text: "written" }] }; }), async () => { throw new Error(`api_token=${canary}`); });
    const agent = createGrclankerClaudeApiAgent(client);
    await client.beta.messages.toolRunner({ ...agent.params, tools: [tool], stream: false, messages: [{ role: "user", content: "Export the evidence." }] });
    assert.equal(nativeCalls, 0);
    assert.equal(requests.length, 2);
    const result = toolResult(requests[1], "approval-error");
    assert.equal(result.is_error, true);
    assertCanaryWindowsAbsent(assert, JSON.stringify(result.content), [canary], "model-visible failure result");
  });
});

test("cancelling the real SDK loop interrupts a deferred approval without effects or a continuation", { timeout: 5000 }, async () => {
  const controller = new AbortController();
  const canary = "Zr4Hk8Wm2Np6Qv9Lc3Tx7Fb5";
  let nativeCalls = 0;
  let beginApproval;
  let resolveApproval;
  let approvalSignal;
  const approvalStarted = new Promise((resolve) => { beginApproval = resolve; });
  const approval = new Promise((resolve) => { resolveApproval = resolve; });
  await withMessagesApi(() => ({ body: message([{ type: "tool_use", id: "approval-cancel", name: "example_export_bundle", input: { query: "scope" } }], "tool_use") }), async (client, requests) => {
    const tool = createClaudeApiGrcTool(fixture("example_export_bundle", async () => { nativeCalls += 1; return { content: [{ type: "text", text: "written" }] }; }), async ({ signal }) => {
      approvalSignal = signal;
      beginApproval();
      return approval;
    });
    const agent = createGrclankerClaudeApiAgent(client);
    const completion = client.beta.messages.toolRunner({ ...agent.params, tools: [tool], stream: false, messages: [{ role: "user", content: "Export the evidence." }] }, { signal: controller.signal })
      .then((result) => ({ result }), (error) => ({ error }));
    try {
      await approvalStarted;
      assert.ok(approvalSignal);
      controller.abort(new Error(`operator cancelled api_key=${canary}`));
      let timer;
      const outcome = await Promise.race([completion, new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("cancelled approval did not settle promptly")), 1500);
      })]).finally(() => clearTimeout(timer));
      assert.ok(outcome.error, "the SDK run must report cancellation");
      assertCanaryWindowsAbsent(assert, String(outcome.error), [canary], "cancelled SDK run");
      assert.equal(approvalSignal.aborted, true);
      assert.equal(nativeCalls, 0);
      assert.equal(requests.length, 1, "an aborted run must not send a model continuation");
      resolveApproval(true);
      await new Promise(setImmediate);
      assert.equal(nativeCalls, 0, "late approval cannot restart an aborted call");
      assert.equal(requests.length, 1);
    } finally {
      controller.abort();
      resolveApproval(false);
      await completion;
    }
  });
  const native = fixture("example_export_bundle", async () => { nativeCalls += 1; return { content: [{ type: "text", text: "written" }] }; });
  const outcome = await runRunnableTool(createClaudeApiGrcTool(native, async () => { assert.fail("already-aborted calls cannot ask for approval"); }), { query: "scope" }, { toolUse, signal: controller.signal });
  assert.equal(outcome.isError, true);
  assertCanaryWindowsAbsent(assert, JSON.stringify(outcome.content), [canary], "cancelled approval result");
  assert.match(JSON.stringify(outcome.content), /cancelled/);
  assert.equal(nativeCalls, 0);
});

test("the SDK tool runner drives a read tool, a declined writer, and the final answer", async () => {
  const workspace = mkdtempSync(join(tmpdir(), "grclanker-claude-api-"));
  mkdirSync(join(workspace, ".trestle"), { recursive: true });
  const forbidden = join(workspace, "forbidden");
  const savedTrestle = process.env.GRCLANKER_TRESTLE_BIN;
  process.env.GRCLANKER_TRESTLE_BIN = join(workspace, "unavailable-trestle");
  const requests = [];
  const script = [
    { type: "tool_use", id: "toolu_read", name: "oscal_check_trestle", input: { workspace_dir: workspace } },
    { type: "tool_use", id: "toolu_write", name: "oscal_init_workspace", input: { workspace_dir: forbidden } },
    { type: "text", text: "offline tool runner result" },
  ];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    const parsed = JSON.parse(body);
    requests.push({ url: request.url, beta: request.headers["anthropic-beta"], body: parsed });
    const block = script[Math.min(requests.length - 1, script.length - 1)];
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      id: `msg_${requests.length}`,
      type: "message",
      role: "assistant",
      model: parsed.model,
      content: [block],
      stop_reason: block.type === "tool_use" ? "tool_use" : "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 1 },
    }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const client = new Anthropic({ apiKey: "offline-placeholder-key", baseURL: `http://127.0.0.1:${server.address().port}`, maxRetries: 0 });
    const asked = [];
    const agent = createGrclankerClaudeApiAgent(client, {
      toolNames: ["oscal_check_trestle", "oscal_init_workspace"],
      approveWrite: async (request) => { asked.push(request.toolName); return false; },
    });
    const final = await client.beta.messages.toolRunner({
      ...agent.params,
      stream: false,
      messages: [{ role: "user", content: "Inspect the temporary OSCAL workspace." }],
    });
    assert.equal(final.content[0].text, "offline tool runner result");
    assert.equal(requests.length, 3);
    for (const { url, beta, body } of requests) {
      assert.match(url, /^\/v1\/messages/);
      assert.match(beta ?? "", new RegExp(SERVER_SIDE_FALLBACK_BETA));
      assert.equal(body.fallbacks, "default");
      assert.equal(body.thread, undefined);
      assert.equal(body.max_iterations, undefined, "runner settings stay client-side");
      assert.equal(body.system[0].cache_control.type, "ephemeral");
      assert.deepEqual(body.tools.map((tool) => tool.name), ["oscal_check_trestle", "oscal_init_workspace", "grclanker_load_workflow", "grclanker_load_skill", "auditor", "verifier"]);
    }
    const results = requests[2].body.messages.flatMap((message) => Array.isArray(message.content) ? message.content : []).filter((block) => block.type === "tool_result");
    const read = results.find((block) => block.tool_use_id === "toolu_read");
    const write = results.find((block) => block.tool_use_id === "toolu_write");
    assert.notEqual(read.is_error, true);
    assert.match(JSON.stringify(read.content), /Trestle is not available yet/);
    assert.equal(write.is_error, true);
    assert.match(JSON.stringify(write.content), /did not approve/);
    assert.deepEqual(asked, ["oscal_init_workspace"]);
    assert.equal(existsSync(forbidden), false);
  } finally {
    server.close();
    if (savedTrestle === undefined) delete process.env.GRCLANKER_TRESTLE_BIN;
    else process.env.GRCLANKER_TRESTLE_BIN = savedTrestle;
    rmSync(workspace, { recursive: true, force: true });
  }
});
