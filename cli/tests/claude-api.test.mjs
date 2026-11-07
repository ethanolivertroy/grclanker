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
