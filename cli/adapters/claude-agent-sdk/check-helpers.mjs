/** Local fake Messages API for exercising the real SDK executable without credentials. */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { query } from "@anthropic-ai/claude-agent-sdk";
import { createGrclankerClaudeOptions } from "./agent.mjs";

export const toolResults = (request) => request.messages.flatMap((message) => Array.isArray(message.content) ? message.content : [])
  .filter((block) => block.type === "tool_result");

export function resultText(request, id) {
  const entry = toolResults(request).find((block) => block.tool_use_id === id);
  assert.ok(entry, `missing tool_result for ${id}`);
  return typeof entry.content === "string" ? entry.content : entry.content.map((part) => part.text ?? "").join("\n");
}

export async function runOfflineScenario({ fixture, mainScript, childScript = [{ type: "text", text: "review complete" }], approveWrite, toolNames }) {
  const requests = [];
  const subagentStarts = [];
  const hookInputs = [];
  const api = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += chunk;
    const parsed = body ? JSON.parse(body) : {};
    const main = Array.isArray(parsed.tools) && parsed.tools.some((tool) => tool.name === "Agent");
    if (!request.url?.startsWith("/v1/messages") || request.url.includes("count_tokens")) {
      response.writeHead(request.url?.includes("count_tokens") ? 200 : 404, { "content-type": "application/json" });
      response.end(JSON.stringify({ input_tokens: 1 }));
      return;
    }
    requests.push(parsed);
    const results = toolResults(parsed).length;
    const script = main ? mainScript : childScript;
    const block = script[Math.min(results, script.length - 1)];
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
    const { options } = createGrclankerClaudeOptions({
      toolNames, approveWrite, model: "claude-offline-check", cwd: fixture,
      env: {
        PATH: process.env.PATH,
        HOME: await mkdtemp(join(fixture, "home-")),
        ANTHROPIC_API_KEY: "offline-placeholder-key",
        ANTHROPIC_BASE_URL: `http://127.0.0.1:${api.address().port}`,
        NO_PROXY: "127.0.0.1,localhost",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        DISABLE_AUTOUPDATER: "1",
      },
    });
    const enforcement = options.hooks.PreToolUse[0].hooks[0];
    options.hooks.PreToolUse[0].hooks = [async (...args) => { hookInputs.push(args[0]); return enforcement(...args); }];
    options.hooks.SubagentStart = [{ hooks: [async (input) => { subagentStarts.push(input); return {}; }] }];
    let result;
    let stderrText = "";
    for await (const event of query({ prompt: "Follow the offline GRC test scenario.", options: {
      ...options, maxTurns: mainScript.length + 3, stderr: (data) => { stderrText += data; },
    } })) if (event.type === "result") result = event;
    assert.ok(result, `no result message. stderr:\n${stderrText}`);
    assert.equal(result.subtype, "success", stderrText);
    const mainRequests = requests.filter((request) => request.tools?.some((tool) => tool.name === "Agent"));
    const childRequests = requests.filter((request) => !request.tools?.some((tool) => tool.name === "Agent"));
    return { requests: mainRequests, childRequests, subagentStarts, hookInputs, result };
  } finally {
    api.closeAllConnections();
    await new Promise((resolve) => api.close(resolve));
  }
}
