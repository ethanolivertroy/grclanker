import test from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { once } from "node:events";
import { readFileSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { promisify } from "node:util";
import { Agent, RunContext, Runner } from "@openai/agents";
import { ScriptedModel, assistantMessage, functionCall, modelResponder } from "@openai/agents/testing";
import { Type } from "typebox";
import {
  createGrclankerOpenAIAgent,
  createOpenAIGrcTool,
  DEFAULT_OPENAI_GRC_TOOLS,
  MAX_OPENAI_GRC_TOOLS,
} from "../dist/adapters/openai-agents/agent.js";
import { collectRegisteredGrcTools } from "../dist/core/registry.js";
import { isGrcWriteTool } from "../dist/core/effects.js";

function fixture(name, execute) {
  return {
    name,
    label: name,
    description: "Offline adapter fixture",
    parameters: Type.Object({ query: Type.String() }),
    execute,
  };
}

const execFileAsync = promisify(execFile);

test("OpenAI agent defaults to public-data tools and includes independent workflow and evidence review tools", () => {
  const agent = createGrclankerOpenAIAgent();
  assert.deepEqual(agent.tools.map((entry) => entry.name), [
    ...DEFAULT_OPENAI_GRC_TOOLS, "grclanker_load_workflow", "grclanker_load_skill", "auditor", "verifier",
  ]);
  assert.match(agent.instructions, /Evidence over opinion/);
  assert.match(agent.instructions, /OpenAI Agents SDK runtime/);
  assert.doesNotMatch(agent.instructions, /Cursor Agent SDK|(?:agent-sdk|cursor-grok)\/prompts/);
  assert.equal(agent.modelSettings.parallelToolCalls, false);
});

test("every registered domain tool adapts with its native name and approval classification", async () => {
  const context = new RunContext();
  for (const nativeTool of collectRegisteredGrcTools()) {
    const adapted = createOpenAIGrcTool(nativeTool);
    assert.equal(adapted.name, nativeTool.name);
    assert.equal(adapted.strict, false);
    assert.equal(adapted.parameters.type, "object");
    assert.equal(await adapted.needsApproval(context, {}), isGrcWriteTool(nativeTool.name));
  }
});

test("OpenAI adapter validates native inputs, retains errors, and redacts credential echoes", async () => {
  let calls = 0;
  const native = fixture("example_check_access", async () => {
    calls += 1;
    return { content: [{ type: "text", text: "reachable" }], details: { internal: true } };
  });
  const adapted = createOpenAIGrcTool(native);
  const invalid = await adapted.invoke(new RunContext(), JSON.stringify({}));
  assert.equal(invalid.isError, true);
  assert.equal(calls, 0);
  assert.deepEqual(await adapted.invoke(new RunContext(), JSON.stringify({ query: "test" })), {
    content: [{ type: "text", text: "reachable" }],
  });
  assert.equal(calls, 1);

  const failing = createOpenAIGrcTool({
    ...native,
    parameters: Type.Object({ api_token: Type.String() }),
    execute: async (_id, args) => { throw new Error(`rejected ${args.api_token}`); },
  });
  const failure = await failing.invoke(new RunContext(), JSON.stringify({ api_token: "private-test-token" }));
  assert.equal(failure.isError, true);
  assert.doesNotMatch(JSON.stringify(failure), /private-test-token/);
});

test("OpenAI runner executes a read tool with normalized native arguments and supplies evidence to the next turn", async () => {
  let observed;
  const nativeTool = {
    ...fixture("example_check_access", async (callId, args) => {
      observed = { callId, args };
      return {
        content: [{ type: "text", text: "evidence-fixture: tenant access confirmed" }],
        details: { internal: "must-not-reach-model" },
      };
    }),
    parameters: Type.Object({ query: Type.String(), limit: Type.Optional(Type.Number()) }),
    prepareArguments: (input) => ({ query: input.q, limit: input.limit }),
  };
  const model = new ScriptedModel([
    [functionCall(nativeTool.name, { q: "tenant", limit: "2" }, { callId: "read-1" })],
    modelResponder(({ request }) => {
      const replay = JSON.stringify(request.input);
      assert.match(replay, /evidence-fixture: tenant access confirmed/);
      assert.doesNotMatch(replay, /must-not-reach-model/);
      return [assistantMessage("Verified from the supplied tenant access evidence")];
    }),
  ]);
  const agent = new Agent({ name: "read-test", model, tools: [createOpenAIGrcTool(nativeTool)] });
  const result = await new Runner({ tracingDisabled: true }).run(agent, "Check access");
  assert.equal(result.interruptions.length, 0);
  assert.deepEqual(observed, { callId: "read-1", args: { query: "tenant", limit: 2 } });
  assert.match(result.finalOutput, /tenant access evidence/);
  model.assertComplete();
});

test("cancelling an OpenAI run aborts its in-flight native request and prevents another model turn", { timeout: 5000 }, async () => {
  const controller = new AbortController();
  let start;
  const started = new Promise((resolve) => { start = resolve; });
  let nativeAborted = false;
  const nativeTool = fixture("example_check_access", async (_callId, _args, signal) => {
    start(signal);
    assert.ok(signal, "the SDK abort signal must reach the native tool");
    return new Promise((_resolve, reject) => {
      const cancel = () => {
        nativeAborted = true;
        reject(signal.reason);
      };
      if (signal.aborted) cancel();
      else signal.addEventListener("abort", cancel, { once: true });
    });
  });
  const model = new ScriptedModel([
    [functionCall(nativeTool.name, { query: "tenant" }, { callId: "cancel-1" })],
  ]);
  const agent = new Agent({ name: "abort-test", model, tools: [createOpenAIGrcTool(nativeTool)] });
  const completion = new Runner({ tracingDisabled: true }).run(agent, "Check access", { signal: controller.signal })
    .then((result) => ({ result }), (error) => ({ error }));
  const nativeSignal = await started;
  controller.abort(new Error("operator cancelled this request"));
  const outcome = await completion;
  assert.ok(nativeSignal, "native request received no cancellation signal");
  assert.equal(nativeSignal.aborted, true);
  assert.equal(nativeAborted, true);
  assert.match(outcome.error?.message ?? "", /operator cancelled/);
  assert.equal(model.calls.length, 1, "an aborted run must not request a continuation");
  model.assertComplete();
});

test("OpenAI runner pauses writers and executes only the approved call", async () => {
  for (const approve of [false, true]) {
    let calls = 0;
    const adapted = createOpenAIGrcTool(fixture("example_export_bundle", async () => {
      calls += 1;
      return { content: [{ type: "text", text: "bundle written" }] };
    }));
    const model = new ScriptedModel([
      [functionCall(adapted.name, { query: "scope" }, { callId: "writer-1" })],
      [assistantMessage("Finished")],
    ]);
    const agent = new Agent({ name: "approval-test", model, tools: [adapted] });
    const runner = new Runner({ tracingDisabled: true });
    const pending = await runner.run(agent, "Export the fixture bundle");
    assert.equal(pending.interruptions.length, 1);
    assert.equal(calls, 0, "native writer must not run before approval");
    if (approve) pending.state.approve(pending.interruptions[0]);
    else pending.state.reject(pending.interruptions[0]);
    const result = await runner.run(agent, pending.state);
    assert.equal(result.finalOutput, "Finished");
    assert.equal(calls, approve ? 1 : 0);
    model.assertComplete();
  }
});

test("workflow and crypto methodology load without a provider request", async () => {
  const agent = createGrclankerOpenAIAgent({ toolNames: [] });
  const workflow = agent.tools.find((entry) => entry.name === "grclanker_load_workflow");
  assert.match(await workflow.invoke(new RunContext(), '{"name":"assess"}'), /assess|posture/i);
  const invalid = await workflow.invoke(new RunContext(), '{"name":"invented"}');
  assert.equal(invalid.isError, true);
  const skill = agent.tools.find((entry) => entry.name === "grclanker_load_skill");
  assert.match(await skill.invoke(new RunContext(), "{}"), /cryptograph|FIPS/i);
});

test("OpenAI deployments reject unknown tools and oversized selections", () => {
  assert.throws(() => createGrclankerOpenAIAgent({ toolNames: ["missing_check_access"] }), /Unknown grclanker tool/);
  const names = collectRegisteredGrcTools().slice(0, MAX_OPENAI_GRC_TOOLS + 1).map((entry) => entry.name);
  assert.throws(() => createGrclankerOpenAIAgent({ toolNames: names }), /Select at most/);
});

test("OpenAI adapter has no Cursor project imports and --check requires no credentials", () => {
  for (const filename of readdirSync(new URL("../adapters/openai-agents/", import.meta.url))) {
    if (!filename.endsWith(".ts")) continue;
    const source = readFileSync(new URL(`../adapters/openai-agents/${filename}`, import.meta.url), "utf8");
    assert.doesNotMatch(source, /from ["'][^"']*(?:agent-sdk|cursor-grok|@grok|@cursor)/);
  }
  const output = execFileSync(process.execPath, ["dist/adapters/openai-agents/cli.js", "--check"], {
    cwd: new URL("../", import.meta.url),
    env: { ...process.env, OPENAI_API_KEY: "" },
    encoding: "utf8",
  });
  assert.equal(JSON.parse(output).name, "grclanker");
  const withoutKey = execFileSync(process.execPath, ["dist/adapters/openai-agents/cli.js", "--list-tools"], {
    cwd: new URL("../", import.meta.url),
    env: { ...process.env, OPENAI_API_KEY: "" },
    encoding: "utf8",
  });
  assert.equal(JSON.parse(withoutKey).length, collectRegisteredGrcTools().length);
});

test("the real noninteractive CLI rejects writers and never displays credential arguments", { timeout: 20000 }, async (t) => {
  for (const malformed of [false, true]) {
    await t.test(malformed ? "malformed writer arguments fail before approval without leaking input" : "valid approval arguments are redacted", async () => {
      const requests = [];
      const secret = "do-not-print-this-synthetic-token";
      const args = malformed
        ? `{"api_token":"${secret}`
        : JSON.stringify({ api_token: secret, output_dir: "/tmp/grclanker-cli-approval-test" });
      const server = createServer(async (request, response) => {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        requests.push({ url: request.url, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        const output = requests.length === 1
          ? [{ type: "function_call", id: "fc_writer", call_id: "writer-cli-1", name: "github_export_audit_bundle", arguments: args, status: "completed" }]
          : [{ type: "message", id: "msg_final", role: "assistant", status: "completed", content: [{ type: "output_text", text: "The export was denied; no evidence was written.", annotations: [] }] }];
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({
          id: `resp_cli_${requests.length}`,
          object: "response",
          created_at: 1,
          status: "completed",
          model: "gpt-5.4",
          output,
          usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, input_tokens_details: { cached_tokens: 0 }, output_tokens_details: { reasoning_tokens: 0 } },
        }));
      });
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      try {
        const { stdout, stderr } = await execFileAsync(process.execPath, [
          "dist/adapters/openai-agents/cli.js", "--tools", "github_export_audit_bundle", "Export a GitHub evidence bundle",
        ], {
          cwd: new URL("../", import.meta.url),
          env: { ...process.env, OPENAI_API_KEY: "synthetic-local-test-key", OPENAI_BASE_URL: `http://127.0.0.1:${server.address().port}/v1` },
          encoding: "utf8",
          timeout: 12000,
        });
        assert.match(stdout, /export was denied/);
        assert.doesNotMatch(`${stdout}\n${stderr}`, new RegExp(secret));
        assert.doesNotMatch(stderr, /Approve this call\?/);
        if (malformed) assert.equal(stderr, "");
        else {
          assert.match(stderr, /Approval required: github_export_audit_bundle/);
          assert.match(stderr, /\[redacted\]/);
          assert.match(stderr, /grclanker-cli-approval-test/);
        }
        assert.equal(requests.length, 2);
        assert.ok(requests.every((entry) => entry.url === "/v1/responses"));
        const toolResult = requests[1].body.input.find((entry) => entry.type === "function_call_output");
        assert.equal(toolResult.call_id, "writer-cli-1");
        if (malformed) {
          assert.match(toolResult.output, /error occurred while parsing tool arguments/);
          assert.doesNotMatch(toolResult.output, new RegExp(secret));
        } else assert.equal(toolResult.output, "Tool execution was not approved.");
      } finally {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
      }
    });
  }
});
