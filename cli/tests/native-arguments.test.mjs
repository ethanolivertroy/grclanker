import test from "node:test";
import assert from "node:assert/strict";
import { Type } from "typebox";
import { prepareGrcToolArguments } from "../dist/core/arguments.js";
import { executeGrcTool } from "../dist/core/tools.js";
import { validateToolArguments } from "@earendil-works/pi-ai";
import { toPiToolDefinition } from "../dist/pi/tool-adapter.js";
import { collectDomainToolDefinitions } from "../dist/core/domain-tools.js";

test("native validation preserves nullable values and omits only optional non-nullable fields without mutating input", () => {
  const parameters = Type.Object({
    nullable: Type.Optional(Type.Union([Type.String(), Type.Null()])),
    absent: Type.Optional(Type.Number()),
    nested: Type.Array(Type.Object({ limit: Type.Optional(Type.Number()) })),
    required: Type.Union([Type.String(), Type.Null()]),
  });
  const input = { nullable: null, absent: null, nested: [{ limit: null }], required: null };
  const before = structuredClone(input);
  assert.deepEqual(prepareGrcToolArguments({ name: "example_search", parameters }, "call", input), {
    nullable: null, nested: [{}], required: null,
  });
  assert.deepEqual(input, before);
  assert.throws(() => prepareGrcToolArguments({ name: "example_search", parameters }, "call", {
    nested: [], required: undefined,
  }), /required/);
});

test("native preparation owns explicit normalization and strict validation precedes effects", async () => {
  let preparations = 0;
  let effects = 0;
  const tool = {
    name: "example_search",
    label: "Example",
    description: "Exercise the native contract.",
    parameters: Type.Object({ limit: Type.Integer({ minimum: 1 }), api_token: Type.Optional(Type.String()) }),
    prepareArguments(input) {
      preparations += 1;
      return typeof input === "number" ? { limit: input } : input;
    },
    async execute(id, input) {
      effects += 1;
      return { content: [{ type: "text", text: `${id}: ${input.limit}` }], details: { count: input.limit } };
    },
  };
  const invalid = await executeGrcTool(tool, { limit: "private-invalid-number", api_token: "private-token" });
  assert.equal(invalid.isError, true);
  assert.doesNotMatch(JSON.stringify(invalid), /private-invalid-number|private-token/);
  assert.equal(effects, 0);
  const valid = await executeGrcTool(tool, 3, { toolCallId: "call" });
  assert.equal(preparations, 2);
  assert.equal(effects, 1);
  assert.deepEqual(valid, { content: [{ type: "text", text: "call: 3" }], details: { count: 3 } });
});

test("the actual Pi validator and native validator agree through the Pi host adapter", () => {
  for (const tool of collectDomainToolDefinitions()) {
    const pi = toPiToolDefinition(tool);
    assert.equal(Symbol.for("TypeBox.Kind") in tool.parameters, false, `${tool.name} native schema is unmarked`);
    assert.equal(pi.parameters[Symbol.for("TypeBox.Kind")], "Object");
    for (const input of [{}, { limit: null }, { limit: "5" }, { query: "sample", limit: 5 }]) {
      let nativeArgs, piArgs, nativeError, piError;
      try { nativeArgs = prepareGrcToolArguments(tool, "call", structuredClone(input)); } catch (error) { nativeError = error; }
      try {
        const prepared = tool.prepareArguments ? tool.prepareArguments(structuredClone(input)) : structuredClone(input);
        piArgs = validateToolArguments(pi, { type: "toolCall", id: "call", name: tool.name, arguments: prepared });
      } catch (error) { piError = error; }
      const context = `${tool.name}: ${JSON.stringify(input)}`;
      assert.equal(Boolean(nativeError), Boolean(piError), context);
      if (!nativeError) assert.deepEqual(nativeArgs, piArgs, context);
    }
  }
});
