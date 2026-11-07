import test from "node:test";
import assert from "node:assert/strict";
import { Type } from "typebox";
import { validateToolArguments } from "@earendil-works/pi-ai/utils/validation";
import { toDurableTool } from "../dist/durable/tools.js";
import { toPiToolDefinition } from "../dist/pi/tool-adapter.js";

test("Pi and Pi Durable reject coercible mistypes through their actual harness validator", () => {
  const parameters = Type.Object({ count: Type.Integer(), enabled: Type.Boolean(), label: Type.String() });
  const native = {
    name: "sample_check_count", label: "Sample", description: "Sample domain tool", parameters,
    async execute() { return { content: [{ type: "text", text: "ok" }] }; },
  };
  const valid = { count: 4, enabled: true, label: "reviewed" };
  for (const host of [toPiToolDefinition(native), toDurableTool(native)]) {
    const call = (args) => ({ type: "toolCall", id: "strict-host-check", name: native.name, arguments: args });
    assert.deepEqual(validateToolArguments(host, call(valid)), valid);
    for (const invalid of [{ ...valid, count: "4" }, { ...valid, count: 4.5 }, { ...valid, enabled: "true" }, { ...valid, label: 42 }]) {
      assert.throws(() => validateToolArguments(host, call(invalid)), /Validation failed/);
    }
    assert.deepEqual(JSON.parse(JSON.stringify(host.parameters)), JSON.parse(JSON.stringify(parameters)));
  }
});
