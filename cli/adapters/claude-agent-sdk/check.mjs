import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, mkdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { query } from "@anthropic-ai/claude-agent-sdk";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { createGrclankerClaudeOptions, mcpToolName } from "./agent.mjs";
import { approvalKey, createGrclankerMcpServer, WriteApprovals } from "./server.mjs";
import { DEFAULT_CLAUDE_GRC_TOOLS, selectTools } from "./tools.mjs";

// Tool selection and approval bookkeeping.
assert.deepEqual(selectTools().map((tool) => tool.name), DEFAULT_CLAUDE_GRC_TOOLS);
assert.deepEqual(selectTools(["oscal_check_trestle", "oscal_check_trestle"]).map((tool) => tool.name), ["oscal_check_trestle"]);
assert.throws(() => selectTools([]), /at least one/);
assert.throws(() => selectTools([""]), /at least one/);
assert.throws(() => selectTools(["missing_tool"]), /Unknown grclanker tool/);
assert.equal(approvalKey("t", { b: 1, a: [{ d: 2, c: 3 }] }), approvalKey("t", { a: [{ c: 3, d: 2 }], b: 1 }));
const ledger = new WriteApprovals();
ledger.grant("t", { a: 1 });
assert.equal(ledger.consume("t", { a: 2 }), false);
assert.equal(ledger.consume("t", { a: 1 }), true);
assert.equal(ledger.consume("t", { a: 1 }), false);

const built = createGrclankerClaudeOptions({ toolNames: ["oscal_check_trestle", "oscal_init_workspace"] });
const isolation = built.options;
const signal = new AbortController().signal;
assert.deepEqual(isolation.tools, ["Agent"]);
assert.deepEqual(isolation.settingSources, []);
assert.equal(isolation.strictMcpConfig, true);
assert.equal(isolation.persistSession, false);
assert.equal(isolation.allowedTools, undefined);
assert.ok(built.readTools.includes(mcpToolName("oscal_check_trestle")));
assert.deepEqual(built.approvalTools, [mcpToolName("oscal_init_workspace")]);
const sdkServerInfo = { name: "grclanker", source: "sdk" };
assert.equal((await isolation.canUseTool(mcpToolName("oscal_check_trestle"), {}, { signal, toolUseID: "r", mcpServer: sdkServerInfo })).behavior, "allow");
assert.equal((await isolation.canUseTool("Agent", {}, { signal, toolUseID: "a" })).behavior, "allow");
// A configured server reusing the name is not the host's in-process server.
assert.equal((await isolation.canUseTool(mcpToolName("oscal_check_trestle"), {}, { signal, toolUseID: "p", mcpServer: { name: "grclanker", source: "project" } })).behavior, "deny");
for (const name of ["auditor", "verifier"]) assert.deepEqual(isolation.agents[name].tools, []);
const denied = await isolation.canUseTool(mcpToolName("oscal_init_workspace"), {}, { signal, toolUseID: "x", mcpServer: sdkServerInfo });
assert.equal(denied.behavior, "deny");
const foreign = await isolation.canUseTool("Bash", { command: "id" }, { signal, toolUseID: "y" });
assert.equal(foreign.behavior, "deny");

function textResult(result) {
  const parsed = CallToolResultSchema.parse(result);
  return { ...parsed, text: parsed.content.filter((item) => item.type === "text").map((item) => item.text).join("\n") };
}

const fixture = await mkdtemp(join(tmpdir(), "grclanker-claude-check-"));
const savedTrestle = process.env.GRCLANKER_TRESTLE_BIN;
process.env.GRCLANKER_TRESTLE_BIN = join(fixture, "unavailable-trestle");
try {
  const workspace = join(fixture, "workspace");
  await mkdir(join(workspace, ".trestle"), { recursive: true });
  await mkdir(join(workspace, "catalogs", "sample-catalog"), { recursive: true });
  const forbidden = join(fixture, "forbidden");

  // The in-process MCP server: discovery, validation, allowlist, and write gate.
  const approvals = new WriteApprovals();
  const sdkServer = createGrclankerMcpServer(selectTools(["oscal_check_trestle", "oscal_init_workspace", "kevs_get_epss"]), approvals);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await sdkServer.instance.connect(serverTransport);
  const client = new Client({ name: "grclanker-claude-check", version: "0.1.0" });
  await client.connect(clientTransport);
  try {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name), ["oscal_check_trestle", "oscal_init_workspace", "kevs_get_epss", "grclanker_load_workflow", "grclanker_load_skill"]);
    assert.equal(tools[0].inputSchema.type, "object");
    assert.equal(tools[0].annotations?.readOnlyHint, true);
    assert.equal(tools[1].annotations?.readOnlyHint, false);
    const invalid = textResult(await client.callTool({ name: "kevs_get_epss", arguments: { cve_ids: [] } }));
    assert.equal(invalid.isError, true);
    assert.match(invalid.text, /requires at least one CVE ID/);
    const unselected = textResult(await client.callTool({ name: "github_export_audit_bundle", arguments: {} }));
    assert.equal(unselected.isError, true);
    assert.match(unselected.text, /not enabled/);
    const unapproved = textResult(await client.callTool({ name: "oscal_init_workspace", arguments: { workspace_dir: forbidden } }));
    assert.equal(unapproved.isError, true);
    assert.match(unapproved.text, /requires operator approval/);
    await assert.rejects(stat(forbidden), { code: "ENOENT" });
    const workflow = textResult(await client.callTool({ name: "grclanker_load_workflow", arguments: { name: "audit" } }));
    assert.notEqual(workflow.isError, true);
    assert.match(workflow.text, /audit/i);
    const badWorkflow = textResult(await client.callTool({ name: "grclanker_load_workflow", arguments: { name: "nope" } }));
    assert.equal(badWorkflow.isError, true);
  } finally {
    await client.close();
  }

  // Run the real SDK and its bundled Claude Code executable against a local
  // fake Messages API. The script calls a read tool, then a writer the
  // operator denies, then answers.
  const requests = [];
  const script = [
    { type: "tool_use", id: "toolu_read", name: mcpToolName("oscal_check_trestle"), input: { workspace_dir: workspace } },
    { type: "tool_use", id: "toolu_write", name: mcpToolName("oscal_init_workspace"), input: { workspace_dir: forbidden } },
    { type: "text", text: "offline SDK result" },
  ];
  const api = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    const parsed = body ? JSON.parse(body) : {};
    const main = Array.isArray(parsed.tools) && parsed.tools.some((tool) => tool.name === mcpToolName("oscal_check_trestle"));
    if (!request.url?.startsWith("/v1/messages") || request.url.includes("count_tokens")) {
      response.writeHead(request.url?.includes("count_tokens") ? 200 : 404, { "content-type": "application/json" });
      response.end(JSON.stringify({ input_tokens: 1 }));
      return;
    }
    if (main) requests.push(parsed);
    const results = main ? parsed.messages.flatMap((message) => Array.isArray(message.content) ? message.content : []).filter((block) => block.type === "tool_result").length : 0;
    const block = main ? script[Math.min(results, script.length - 1)] : { type: "text", text: "ok" };
    const message = {
      id: `msg_${requests.length}`,
      type: "message",
      role: "assistant",
      model: parsed.model,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 1 },
    };
    const stopReason = block.type === "tool_use" ? "tool_use" : "end_turn";
    if (!parsed.stream) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ...message, content: [block], stop_reason: stopReason }));
      return;
    }
    response.writeHead(200, { "content-type": "text/event-stream" });
    const send = (event, data) => response.write(`event: ${event}\ndata: ${JSON.stringify({ type: event, ...data })}\n\n`);
    send("message_start", { message });
    if (block.type === "tool_use") {
      send("content_block_start", { index: 0, content_block: { ...block, input: {} } });
      send("content_block_delta", { index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) } });
    } else {
      send("content_block_start", { index: 0, content_block: { type: "text", text: "" } });
      send("content_block_delta", { index: 0, delta: { type: "text_delta", text: block.text } });
    }
    send("content_block_stop", { index: 0 });
    send("message_delta", { delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 1 } });
    send("message_stop", {});
    response.end();
  });
  await new Promise((resolve) => api.listen(0, "127.0.0.1", resolve));
  try {
    const approvalsAsked = [];
    const { options } = createGrclankerClaudeOptions({
      toolNames: ["oscal_check_trestle", "oscal_init_workspace"],
      model: "claude-offline-check",
      cwd: fixture,
      env: {
        PATH: process.env.PATH,
        HOME: join(fixture, "home"),
        ANTHROPIC_API_KEY: "offline-placeholder-key",
        ANTHROPIC_BASE_URL: `http://127.0.0.1:${api.address().port}`,
        NO_PROXY: "127.0.0.1,localhost",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        DISABLE_AUTOUPDATER: "1",
      },
      async approveWrite(request) {
        approvalsAsked.push(request);
        return false;
      },
    });
    await mkdir(join(fixture, "home"), { recursive: true });
    let result;
    let stderrText = "";
    for await (const event of query({ prompt: "Inspect the temporary OSCAL workspace.", options: { ...options, stderr: (data) => { stderrText += data; } } })) {
      if (event.type === "result") result = event;
    }
    assert.ok(result, `no result message. stderr:\n${stderrText}`);
    assert.equal(result.subtype, "success", stderrText);
    assert.equal(result.result, "offline SDK result");
    assert.ok(requests.length >= 3, `expected three main-loop model requests, saw ${requests.length}`);

    const first = requests[0];
    const system = Array.isArray(first.system) ? first.system.map((part) => part.text).join("\n") : String(first.system);
    assert.match(system, /Claude Agent SDK runtime/);
    const offered = first.tools.map((tool) => tool.name);
    assert.ok(offered.includes(mcpToolName("oscal_check_trestle")));
    assert.ok(offered.includes(mcpToolName("oscal_init_workspace")));
    for (const builtin of ["Bash", "Read", "Write", "Edit", "WebFetch", "WebSearch"]) assert.ok(!offered.includes(builtin), `${builtin} must not be offered`);

    const toolResults = requests.at(-1).messages.flatMap((message) => Array.isArray(message.content) ? message.content : []).filter((block) => block.type === "tool_result");
    const resultText = (id) => {
      const entry = toolResults.find((block) => block.tool_use_id === id);
      assert.ok(entry, `missing tool_result for ${id}`);
      return typeof entry.content === "string" ? entry.content : entry.content.map((part) => part.text ?? "").join("\n");
    };
    assert.ok(resultText("toolu_read").includes(`Workspace dir: ${workspace}`));
    assert.match(resultText("toolu_read"), /Trestle is not available yet/);
    assert.match(resultText("toolu_write"), /did not approve/);
    assert.equal(approvalsAsked.length, 1);
    assert.equal(approvalsAsked[0].toolName, "oscal_init_workspace");
    await assert.rejects(stat(forbidden), { code: "ENOENT" });
  } finally {
    await new Promise((resolve) => api.close(resolve));
  }
  console.log("Claude Agent SDK isolation options, in-process MCP discovery, input validation, tool allowlist, and write approval passed; the real SDK ran a read tool and a denied writer against a local fake Messages API. No real API credentials or network calls used.");
} finally {
  if (savedTrestle === undefined) delete process.env.GRCLANKER_TRESTLE_BIN;
  else process.env.GRCLANKER_TRESTLE_BIN = savedTrestle;
  await rm(fixture, { recursive: true, force: true });
}
