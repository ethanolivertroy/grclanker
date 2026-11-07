import test from "node:test";
import assert from "node:assert/strict";
import { Type } from "typebox";
import * as v from "valibot";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GrclankerToolError, renderGrcToolContent, toFlueTool } from "../dist/flue/tools.js";
import { runToolCall } from "../dist/extensions/grc-tools/abort.js";
import { writeBundleAtomically } from "../dist/extensions/grc-tools/atomic-output.js";
import { writeSecureTextFile } from "../dist/extensions/grc-tools/secure-output.js";

function context(data, signal) {
  return { data, signal, toolCallId: "flue-core-test" };
}

test("Flue prepares a non-idempotent shim exactly once before common execution", async () => {
  let preparations = 0;
  const executions = [];
  const tool = toFlueTool({
    name: "sample_search_items", label: "Sample", description: "Sample read tool",
    parameters: Type.Object({ query: Type.String() }),
    prepareArguments(input) { preparations += 1; return { query: `${input.query}:prepared` }; },
    async execute(id, input) { executions.push({ id, input }); return { content: [{ type: "text", text: input.query }], details: {}, terminate: true }; },
  });
  const input = { query: "request" };
  const parsed = v.parse(tool.input, input);
  assert.deepEqual(await tool.run(context(parsed)), { output: "request:prepared", terminate: true });
  assert.equal(preparations, 1);
  assert.deepEqual(executions, [{ id: "flue-core-test", input: { query: "request:prepared" } }]);
  assert.deepEqual(input, { query: "request" });
});

test("direct Flue run cannot bypass native validation", async () => {
  let effects = 0;
  const tool = toFlueTool({
    name: "sample_search_items", label: "Sample", description: "Sample read tool",
    parameters: Type.Object({ count: Type.Integer() }),
    async execute() { effects += 1; return { content: [{ type: "text", text: "executed" }] }; },
  });
  await assert.rejects(tool.run(context({ count: "4" })), (error) => {
    assert.ok(error instanceof GrclankerToolError);
    assert.match(error.message, /Validation failed/);
    return true;
  });
  assert.equal(effects, 0);
});

test("Flue restores cancellation control flow when native execution fails after aborting", async () => {
  const controller = new AbortController();
  const reason = new Error("operator cancelled");
  const tool = toFlueTool({
    name: "sample_search_items", label: "Sample", description: "Sample read tool",
    parameters: Type.Object({}),
    async execute(_id, _input, signal) {
      assert.equal(signal, controller.signal);
      controller.abort(reason);
      throw reason;
    },
  });
  await assert.rejects(tool.run(context({}, controller.signal)), (error) => error === reason);
});

test("Flue preserves a committed export report when cancellation arrives after publication", async () => {
  const root = mkdtempSync(join(tmpdir(), "grclanker-flue-committed-"));
  const controller = new AbortController();
  const call = { committed: false };
  try {
    const tool = toFlueTool({
      name: "sample_export_bundle", label: "Sample", description: "Sample export tool",
      parameters: Type.Object({}),
      async execute() {
        return runToolCall(call, async () => {
          const bundle = await writeBundleAtomically({ root, names: ["evidence"] }, (staged) =>
            writeSecureTextFile(staged.dir, "report.txt", "reviewed evidence"));
          controller.abort(new Error("stopped after publication"));
          return { content: [{ type: "text", text: bundle.outputDir }], details: bundle };
        });
      },
    });
    const report = await tool.run(context({}, controller.signal));
    assert.equal(call.committed, true);
    assert.equal(report.output, join(root, "evidence"));
    assert.equal(existsSync(join(report.output, "report.txt")), true);
    assert.equal(readFileSync(join(report.output, "report.txt"), "utf8"), "reviewed evidence");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Flue preserves a native AbortError's identity without a host signal", async () => {
  const reason = new DOMException("native request stopped", "AbortError");
  const tool = toFlueTool({
    name: "sample_search_items", label: "Sample", description: "Sample read tool",
    parameters: Type.Object({}),
    async execute() { throw reason; },
  });
  await assert.rejects(tool.run(context({})), (error) => error === reason);
});

test("Flue input uses common optional-null normalization without dropping nullable fields", async () => {
  let argumentsSeen;
  const tool = toFlueTool({
    name: "sample_search_items", label: "Sample", description: "Sample read tool",
    parameters: Type.Object({ optional: Type.Optional(Type.String()), nullable: Type.Optional(Type.Union([Type.String(), Type.Null()])) }),
    async execute(_id, args) { argumentsSeen = args; return { content: [{ type: "text", text: "ok" }] }; },
  });
  const raw = { optional: null, nullable: null };
  await tool.run(context(v.parse(tool.input, raw)));
  assert.deepEqual(argumentsSeen, { nullable: null });
  assert.deepEqual(raw, { optional: null, nullable: null });
});

test("common execution retains error metadata while redacting credentials for Flue", async () => {
  const credential = "flue-core-secret-canary";
  const tool = toFlueTool({
    name: "sample_check_access", label: "Sample", description: "Sample read tool",
    parameters: Type.Object({ api_token: Type.String(), organization: Type.String() }),
    async execute(_id, args) {
      return { content: [{ type: "text", text: `Rejected ${args.api_token}` }], isError: true, details: args };
    },
  });
  await assert.rejects(tool.run(context({ api_token: credential, organization: "example" })), (error) => {
    assert.ok(error instanceof GrclankerToolError);
    assert.doesNotMatch(error.message, /flue-core-secret-canary/);
    assert.notEqual(error.details.api_token, credential);
    assert.equal(error.details.organization, "example");
    return true;
  });
});


test("unsupported Flue content never echoes unknown payloads into thrown errors", () => {
  const secret = "unknown-block-secret";
  assert.throws(() => renderGrcToolContent([{ type: "unknown", payload: secret }]),
    (error) => error.message === "Unsupported native tool content block." && !error.message.includes(secret));
});
