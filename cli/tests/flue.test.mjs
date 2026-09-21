import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Type } from "@sinclair/typebox";
import * as v from "valibot";
import { init, setProvider, useModel, useSandbox, useSkill, useSubagent, useTool } from "@flue/runtime";
import { start } from "@flue/runtime/node";

import {
  isToolInputObjectSchema,
  jsonSchemaToToolInput,
  jsonSchemaToValibot,
} from "../dist/flue/schema.js";
import {
  GrclankerToolError,
  collectGrclankerDomainTools,
  createGrclankerFlueTools,
  renderPiToolContent,
  toFlueTool,
  toFlueToolResult,
} from "../dist/flue/tools.js";
import {
  loadGrclankerAgentContent,
  parseSkillMarkdown,
  parseSubagentRole,
  resolveFlueAppRoot,
  summarizeMarkdownPrompt,
  workflowSkillFromPrompt,
} from "../dist/flue/content.js";
import {
  DEFAULT_FLUE_MODEL,
  GrclankerFlueConfigError,
  buildFlueInstructions,
  createSubagentDefinition,
  renderGrclankerAgent,
  resolveFlueModel,
  resolveFlueSandboxMode,
} from "../dist/flue/render.js";
import {
  createFlueActivityFormatter,
  describeAgentRunError,
  exitCodeForOutcome,
  resolveFlueDatabasePath,
  runGrclankerFlueAgent,
} from "../dist/flue/run.js";
import { formatFlueHelp, formatFlueRunOutcome, parseFlueRunArgs, runFlueCommand } from "../dist/flue/cli.js";
import {
  createCustomProvider,
  listCustomProviderConfigs,
  localProviderConfigFromSettings,
  registerGrclankerProviders,
  resolveApiKeyValue,
} from "../dist/flue/providers.js";

const testDir = dirname(fileURLToPath(import.meta.url));
const cliRoot = resolve(testDir, "..");
const distFlueDir = resolve(cliRoot, "dist", "flue");

// Keep the tests independent from the developer's real ~/.grclanker settings.
process.env.GRCLANKER_HOME = mkdtempSync(resolve(tmpdir(), "grclanker-flue-test-"));
delete process.env.GRCLANKER_FLUE_MODEL;
delete process.env.GRCLANKER_FLUE_SANDBOX;

const { Grclanker, prepareGrclankerAgent } = await import("../dist/flue/agent.js");

const AGENT_IDENTITY_PATTERN = /^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*$/;
const DOMAIN_TOOL_COUNT = 107;

// The Pi CLI's own argument validation (pi-ai 0.80.2, the copy the CLI runs),
// used as the oracle the adapter is compared against.
const { validateToolArguments: piCliValidate } = await import(
  pathToFileURL(resolve(dirname(fileURLToPath(import.meta.resolve("@earendil-works/pi-ai"))), "utils/validation.js")).href
);

function createRecordingHooks() {
  const calls = { models: [], tools: [], skills: [], subagents: [], sandboxes: [] };
  const hooks = {
    useModel: (model) => calls.models.push(model),
    useTool: (tool) => calls.tools.push(tool),
    useSkill: (skill) => calls.skills.push(skill),
    useSubagent: (subagent) => calls.subagents.push(subagent),
    useSandbox: (sandbox) => calls.sandboxes.push(sandbox),
  };
  return { hooks, calls };
}

function createFakePiTool(overrides = {}) {
  const executions = [];
  const tool = {
    name: "kevs_probe",
    label: "Probe KEV entries",
    description: "Probe tool used by the Flue adapter tests.",
    parameters: Type.Object({
      query: Type.String({ description: "CVE ID or keyword." }),
      limit: Type.Optional(Type.Number({ default: 5 })),
    }),
    prepareArguments: (args) => ({ query: args.query ?? args.cve, limit: args.limit }),
    async execute(toolCallId, params, signal) {
      executions.push({ toolCallId, params, signal });
      return { content: [{ type: "text", text: `probe saw ${params.query}` }], details: { params } };
    },
    ...overrides,
  };
  return { tool, executions };
}

function fakeRunContext(data, extra = {}) {
  return {
    data,
    toolCallId: "call-1",
    signal: undefined,
    log: { info() {}, warn() {}, error() {} },
    ...extra,
  };
}

/**
 * Import a file from a package as `@flue/runtime` itself resolves it (nested
 * or hoisted), mirroring Node's module walk, so test doubles share Flue's
 * registries and the gate probes use Flue's own Pi copy.
 */
async function importFromFlueDependency(relativePath) {
  const flueDist = dirname(fileURLToPath(import.meta.resolve("@flue/runtime")));
  const candidates = [resolve(flueDist, "../node_modules", relativePath), resolve(flueDist, "../../..", relativePath)];
  const found = candidates.find((candidate) => existsSync(candidate));
  assert.ok(found, `${relativePath} used by @flue/runtime should be resolvable`);
  return import(pathToFileURL(found).href);
}

const importFluePiAi = () => importFromFlueDependency("@earendil-works/pi-ai/dist/index.js");

test("schema conversion mirrors TypeBox tool parameters in Valibot", () => {
  const parameters = Type.Object({
    query: Type.String({ description: "Search term." }),
    limit: Type.Optional(Type.Number({ default: 10, minimum: 1, maximum: 180 })),
    count: Type.Optional(Type.Integer()),
    ids: Type.Optional(Type.Array(Type.String(), { description: "CVE IDs." })),
    refresh: Type.Optional(Type.Boolean()),
    mode: Type.Optional(Type.Union([Type.Literal("20x"), Type.Literal("rev5"), Type.Literal("both")])),
    size: Type.Optional(Type.Union([Type.String(), Type.Integer()])),
  });

  const schema = jsonSchemaToToolInput(parameters, "probe");
  assert.equal(schema.type, "loose_object");
  assert.ok(isToolInputObjectSchema(schema));

  const valid = v.safeParse(schema, { query: "CVE-2024-3400", limit: 5, count: 2, ids: ["a"], refresh: true, mode: "rev5", size: 3 });
  assert.ok(valid.success);
  assert.deepEqual(valid.output, { query: "CVE-2024-3400", limit: 5, count: 2, ids: ["a"], refresh: true, mode: "rev5", size: 3 });

  assert.equal(v.safeParse(schema, {}).success, false, "required keys stay required");
  assert.equal(v.safeParse(schema, { query: "x", limit: 0 }).success, false, "minimum is enforced");
  assert.equal(v.safeParse(schema, { query: "x", count: 1.5 }).success, false, "integer is enforced");
  assert.equal(v.safeParse(schema, { query: "x", mode: "nope" }).success, false, "literal unions become picklists");
  assert.equal(v.safeParse(schema, { query: "x", size: true }).success, false, "mixed unions stay unions");

  // The Pi CLI checks strictly after prepareArguments (no type coercion), and so does the adapter.
  for (const [key, value] of [["query", 4282], ["limit", "5"], ["refresh", "true"], ["ids", "CVE-2024-1"], ["count", "0x10"]]) {
    assert.equal(v.safeParse(schema, { query: "x", [key]: value }).success, false, `${key}: ${JSON.stringify(value)} is not coerced`);
  }
  assert.equal(v.safeParse(schema, { query: "x", size: 3 }).output.size, 3);
  assert.equal(v.safeParse(schema, { query: "x", size: "3" }).output.size, "3");

  const defaults = v.safeParse(schema, { query: "x" });
  assert.ok(defaults.success);
  assert.equal("limit" in defaults.output, false, "defaults are not applied at parse time, matching Pi");

  const aliased = v.safeParse(schema, { query: "x", cve: "CVE-2024-1" });
  assert.ok(aliased.success);
  assert.equal(aliased.output.cve, "CVE-2024-1", "unknown keys survive for prepareArguments shims");

  const property = schema.entries.limit;
  assert.equal(property.type, "optional");
  assert.ok(Array.isArray(property.wrapped.pipe), "annotations are carried as pipe metadata");
  const metadata = property.wrapped.pipe.find((item) => item.type === "metadata");
  assert.deepEqual(metadata.metadata, { default: 10 });
});

test("schema conversion handles strict objects, enums, nullables, and unknown constructs", () => {
  const strict = jsonSchemaToValibot({ type: "object", properties: { a: { type: "string" } }, additionalProperties: false });
  assert.equal(strict.type, "strict_object");
  assert.equal(v.safeParse(strict, { a: "x", extra: 1 }).success, false);

  const rest = jsonSchemaToValibot({ type: "object", properties: {}, additionalProperties: { type: "number" } });
  assert.equal(rest.type, "object_with_rest");
  assert.equal(v.safeParse(rest, { any: 1 }).success, true);
  assert.equal(v.safeParse(rest, { any: "no" }).success, false);

  const picklist = jsonSchemaToValibot({ type: "string", enum: ["json", "yaml"] });
  assert.equal(picklist.type, "picklist");
  assert.equal(v.safeParse(picklist, "yaml").output, "yaml");
  assert.equal(v.safeParse(picklist, "xml").success, false);

  const nullable = jsonSchemaToValibot({ type: ["string", "null"] });
  assert.equal(nullable.type, "union");
  assert.equal(v.safeParse(nullable, null).success, true);
  assert.equal(v.safeParse(nullable, "x").success, true);
  assert.equal(v.safeParse(nullable, 1).success, false);

  assert.equal(jsonSchemaToValibot(undefined).type, "unknown");
  assert.equal(jsonSchemaToValibot({ type: "mystery" }).type, "unknown");
  assert.equal(jsonSchemaToValibot({ const: "fixed" }).type, "literal");
  assert.equal(v.safeParse(jsonSchemaToValibot({ const: 7 }), 7).success, true);
  assert.equal(v.safeParse(jsonSchemaToValibot({ const: 7 }), "7").success, false);

  assert.throws(() => jsonSchemaToToolInput(Type.String(), "bad"), /must be a JSON Schema object/);
});

test("tool input schemas run prepareArguments before validation and still render the declared schema", () => {
  const { tool } = createFakePiTool();
  const withShim = jsonSchemaToToolInput(tool.parameters, tool.name, tool.prepareArguments);
  const withoutShim = jsonSchemaToToolInput(tool.parameters, tool.name);

  assert.equal(withShim.type, "loose_object", "the pipe keeps Flue's top-level object type");
  assert.ok(isToolInputObjectSchema(withShim));

  const aliased = v.safeParse(withShim, { cve: "CVE-2024-3400", limit: 5 });
  assert.ok(aliased.success);
  assert.deepEqual(aliased.output, { query: "CVE-2024-3400", limit: 5 }, "the shim's own return value is what gets validated");
  assert.equal(v.safeParse(withoutShim, { cve: "CVE-2024-3400" }).success, false, "without the shim the alias is not enough");

  const failing = v.safeParse(withShim, { cve: "CVE-2024-3400", limit: "5" });
  assert.equal(failing.success, false, "validation after the shim is as strict as the Pi CLI's");
  assert.deepEqual(
    failing.issues.map((issue) => issue.path?.map((segment) => segment.key).join(".")),
    ["limit"],
    "issues point at the offending field after normalization",
  );

  const throwing = jsonSchemaToToolInput(tool.parameters, tool.name, () => {
    throw new Error("shim exploded");
  });
  const thrown = v.safeParse(throwing, { query: "x" });
  assert.equal(thrown.success, false);
  assert.match(thrown.issues[0].message, /kevs_probe could not normalize its arguments: shim exploded/);
});

/** The Pi CLI's tool loop: `prepareArguments` (a throw becomes an error result), then pi-ai's `validateToolArguments`. */
function piVerdict(tool, raw) {
  let prepared;
  try {
    prepared = tool.prepareArguments ? tool.prepareArguments(structuredClone(raw)) : raw;
  } catch {
    return { ok: false, threw: true };
  }
  try {
    const args = piCliValidate({ name: tool.name, parameters: tool.parameters }, { id: "probe", name: tool.name, arguments: prepared });
    return { ok: true, args: JSON.parse(JSON.stringify(args)) };
  } catch {
    return { ok: false };
  }
}

// Flue mounts custom tools as Pi `AgentTool`s, so its Pi loop validates the raw
// call against the rendered JSON Schema (its own JSON-schema coercion rules, no
// prepareArguments) before Flue's Valibot parse runs. Reproduce that stack with
// Flue's own Pi copy and its JSON Schema renderer.
const { validateToolArguments: flueGateValidate } = await importFromFlueDependency(
  "@earendil-works/pi-ai/dist/utils/validation.js",
);
const { toJsonSchema } = await importFromFlueDependency("@valibot/to-json-schema/dist/index.mjs");

function renderedToolSchema(tool) {
  const { $schema, ...rendered } = toJsonSchema(tool.input, { errorMode: "ignore" });
  return rendered;
}

const GATE_REASONS = [
  ["required", /must have required properties/],
  ["enum", /must be equal to one of the allowed values/],
  ["array", /must be array/],
  ["integer", /must be integer/],
  ["object", /must be object/],
  ["type", /must be (string|number|boolean)/],
  ["range", /must be (>=|<=)/],
];

/** Flue's gate: Pi 0.83 `validateToolArguments` against the rendered schema; returns coerced args or a reason. */
function flueGate(tool, raw) {
  try {
    const args = flueGateValidate(
      { name: tool.name, parameters: renderedToolSchema(tool) },
      { id: "probe", name: tool.name, arguments: structuredClone(raw) },
    );
    return { ok: true, args };
  } catch (error) {
    const reason = GATE_REASONS.find(([, pattern]) => pattern.test(error.message))?.[0] ?? "other";
    return { ok: false, reason, message: error.message };
  }
}

/** The adapter's own stage: Flue's Valibot parse of whatever the gate handed over. */
function adapterVerdict(tool, gatedArgs) {
  const result = v.safeParse(tool.input, structuredClone(gatedArgs));
  return result.success ? { ok: true, args: JSON.parse(JSON.stringify(result.output)) } : { ok: false };
}

/** The full Flue runtime path for one raw model payload. */
function flueVerdict(tool, raw) {
  const gate = flueGate(tool, raw);
  if (!gate.ok) return { ok: false, stage: "gate", reason: gate.reason };
  const adapter = adapterVerdict(tool, gate.args);
  return adapter.ok ? { ok: true, args: adapter.args } : { ok: false, stage: "adapter" };
}

function canonical(value) {
  return JSON.stringify(value, (_key, entry) =>
    entry && typeof entry === "object" && !Array.isArray(entry)
      ? Object.fromEntries(Object.keys(entry).sort().map((key) => [key, entry[key]]))
      : entry,
  );
}

function sampleValue(property) {
  if (Array.isArray(property.anyOf)) {
    const literal = property.anyOf.find((variant) => variant.const !== undefined);
    return literal ? literal.const : "sample";
  }
  switch (property.type) {
    case "number":
      return property.minimum ?? 5;
    case "integer":
      return property.minimum ?? 3;
    case "boolean":
      return true;
    case "array":
      return ["a", "b"];
    default:
      return "sample";
  }
}

const PROBE_VALUES = ["true", "false", "1", "0", 1, 0, null, true, {}, [], "bogus", 5, 1.5, "1e3", " 7 ", "", "null", -1, "0x10", "yes"];

test("the adapter stage accepts and normalizes arguments exactly like the Pi CLI loop for every domain tool", () => {
  const piTools = collectGrclankerDomainTools();
  const flueTools = new Map(createGrclankerFlueTools(piTools).map((tool) => [tool.name, tool]));
  const mismatches = [];
  const gateReasons = new Map();
  const lenientWithoutCoercion = [];
  let compared = 0;
  let gated = 0;
  let lenient = 0;

  for (const piTool of piTools) {
    const flueTool = flueTools.get(piTool.name);
    const properties = piTool.parameters.properties ?? {};
    const required = piTool.parameters.required ?? [];
    const base = Object.fromEntries(required.map((key) => [key, sampleValue(properties[key])]));
    const inputs = [{}, base, { ...base, extra_key: "x" }];
    for (const [key, property] of Object.entries(properties)) {
      const sample = sampleValue(property);
      for (const value of [sample, String(sample), ...PROBE_VALUES]) inputs.push({ ...base, [key]: value });
      if (property.type === "array") inputs.push({ ...base, [key]: "a" }, { ...base, [key]: 1 }, { ...base, [key]: [null] });
    }
    for (const key of required) {
      const missing = { ...base };
      delete missing[key];
      inputs.push(missing);
    }

    for (const input of inputs) {
      compared += 1;
      // The adapter stage on its own must equal the Pi CLI's loop on the same payload.
      const direct = adapterVerdict(flueTool, input);
      const pi = piVerdict(piTool, input);
      if (!(pi.ok === direct.ok && (!pi.ok || canonical(pi.args) === canonical(direct.args)))) {
        mismatches.push({ stage: "adapter", tool: piTool.name, input, pi, flue: direct });
      }

      // Through the real stack, whatever Flue's gate hands over must be handled like the Pi CLI would handle it,
      // and any payload Flue accepts that the Pi CLI rejects must be explained by the gate's own coercion.
      const gate = flueGate(flueTool, input);
      if (!gate.ok) {
        gated += 1;
        if (pi.ok) gateReasons.set(gate.reason, (gateReasons.get(gate.reason) ?? 0) + 1);
        continue;
      }
      const runtime = adapterVerdict(flueTool, gate.args);
      const piOnGated = piVerdict(piTool, gate.args);
      if (!(piOnGated.ok === runtime.ok && (!piOnGated.ok || canonical(piOnGated.args) === canonical(runtime.args)))) {
        mismatches.push({ stage: "runtime", tool: piTool.name, input, gated: gate.args, pi: piOnGated, flue: runtime });
      }
      if (runtime.ok && !pi.ok) {
        lenient += 1;
        if (canonical(gate.args) === canonical(input)) lenientWithoutCoercion.push({ tool: piTool.name, input });
      }
    }
  }

  assert.ok(compared > 10000, `expected a broad probe matrix, compared ${compared}`);
  assert.ok(gated > 0 && gated < compared / 2, `the gate should reject a minority of probes (rejected ${gated} of ${compared})`);
  assert.deepEqual(mismatches.slice(0, 10), [], `${mismatches.length} verdicts differ between the Pi CLI and the adapter`);
  assert.ok(lenient > 0, "the gate's coercion admits some payloads the Pi CLI rejects");
  assert.deepEqual(lenientWithoutCoercion, [], "Flue is more permissive than the Pi CLI only where the gate coerced a value");
  assert.deepEqual(
    [...gateReasons.keys()].sort(),
    ["array", "enum", "integer", "range", "required", "type"],
    "payloads the Pi CLI accepts are turned away by the gate only for the documented reasons",
  );
});

test("reviewer probe cases: the gate is the only difference from the Pi CLI, in both directions", () => {
  const piTools = collectGrclankerDomainTools();
  const flueTools = new Map(createGrclankerFlueTools(piTools).map((tool) => [tool.name, tool]));
  // `pi` is the Pi CLI verdict on the raw payload. For Flue, `pass` means accepted with the
  // Pi CLI's exact arguments, `coerced` means accepted after the gate's own coercion changed a
  // value the normalizer then saw, `lenient` means accepted although the Pi CLI rejects it (gate
  // coercion again), and the rest name the gate rejection reason (docs page, Limitations).
  const cases = [
    ["kevs_search", { query: "CVE-2024-3400", limit: "5" }, "accept", "pass"],
    ["kevs_search", { cve: "CVE-2024-3400" }, "accept", "required"],
    ["kevs_search", {}, "accept", "required"],
    ["kevs_recent", { days: "7" }, "accept", "pass"],
    ["kevs_recent", { days: null }, "accept", "coerced"],
    ["kevs_get_epss", { cve_ids: "CVE-2024-3400" }, "accept", "array"],
    ["kevs_get_epss", { cve_ids: [1] }, "accept", "pass"],
    ["kevs_get_epss", {}, "accept", "required"],
    ["cmvp_get_module", { cert_number: 4282 }, "accept", "pass"],
    ["cmvp_get_module", { certificate: "4282" }, "accept", "required"],
    ["cmvp_get_module", {}, "accept", "required"],
    ["fedramp_search_frmr", { query: "CDS", section: "bogus" }, "accept", "enum"],
    ["fedramp_search_frmr", { query: "CDS", limit: "5" }, "accept", "pass"],
    ["fedramp_search_frmr", { section: "any" }, "accept", "required"],
    ["oscal_create_model", { workspace_dir: "w", model_type: "ssp", name: "n", format: "xml" }, "accept", "enum"],
    ["oscal_create_model", { workspace_dir: "w", model_type: "ssp" }, "accept", "required"],
    ["oscal_create_model", { workspace_dir: "w", model_type: "ssp", name: "n", include_optional_fields: "true" }, "accept", "pass"],
    ["github_check_access", { installation_id: true }, "accept", "coerced"],
    ["github_check_access", { lookback_days: "1" }, "accept", "pass"],
    ["okta_check_access", { scopes: "okta.users.read" }, "accept", "array"],
    ["okta_check_access", { scopes: [1] }, "accept", "coerced"],
    ["gws_export_audit_bundle", { lookback_days: "1" }, "reject", "lenient"],
    ["gws_export_audit_bundle", { lookback_days: 1.5 }, "reject", "integer"],
    ["aws_export_audit_bundle", { user_limit: "10" }, "accept", "pass"],
    ["oscal_generate_ssp_markdown", { workspace_dir: "w", profile: "p", output: "o" }, "accept", "pass"],
    ["oscal_assemble_ssp", { workspace_dir: "w", markdown: "m", output: "o" }, "accept", "pass"],
  ];

  for (const [name, input, piExpected, flueExpected] of cases) {
    const label = `${name} ${JSON.stringify(input)}`;
    const pi = piVerdict(piTools.find((tool) => tool.name === name), input);
    const flue = flueVerdict(flueTools.get(name), input);
    assert.equal(pi.ok, piExpected === "accept", `${label}: Pi CLI verdict`);
    switch (flueExpected) {
      case "pass":
        assert.ok(flue.ok, `${label} should pass Flue`);
        assert.equal(canonical(flue.args), canonical(pi.args), `${label} normalizes identically`);
        break;
      case "coerced":
        assert.ok(flue.ok, `${label} should pass Flue after gate coercion`);
        assert.notEqual(canonical(flue.args), canonical(pi.args), `${label} reaches the tool with gate-coerced values`);
        break;
      case "lenient":
        assert.ok(flue.ok, `${label} is admitted by the gate's coercion although the Pi CLI rejects it`);
        break;
      default:
        assert.deepEqual({ ok: flue.ok, stage: flue.stage, reason: flue.reason }, { ok: false, stage: "gate", reason: flueExpected }, label);
    }
  }

  const kevsSearch = flueTools.get("kevs_search");
  assert.deepEqual(v.safeParse(kevsSearch.input, { cve: "CVE-2024-3400" }).output, { query: "CVE-2024-3400" }, "the adapter itself honors the alias");
  const bare = flueGate(kevsSearch, "CVE-2024-3400");
  assert.equal(bare.ok, false);
  assert.equal(bare.reason, "object", "a bare non-object payload never reaches tool code under Flue");
});

test("every grclanker domain tool bridges into a Flue tool definition", () => {
  const piTools = collectGrclankerDomainTools();
  assert.equal(piTools.length, DOMAIN_TOOL_COUNT);
  assert.ok(piTools.every((tool) => !["bash", "read", "write", "edit", "ls", "find", "grep"].includes(tool.name)));

  const flueTools = createGrclankerFlueTools(piTools);
  assert.equal(flueTools.length, DOMAIN_TOOL_COUNT);
  assert.deepEqual(
    flueTools.map((tool) => tool.name),
    piTools.map((tool) => tool.name),
    "registration order is preserved",
  );
  assert.equal(new Set(flueTools.map((tool) => tool.name)).size, DOMAIN_TOOL_COUNT, "names stay unique");

  for (const tool of flueTools) {
    assert.ok(Object.isFrozen(tool), `${tool.name} should come out of defineTool() frozen`);
    assert.ok(tool.description.length > 0);
    assert.ok(isToolInputObjectSchema(tool.input), `${tool.name} input must be a top-level object schema`);
    assert.equal(typeof tool.run, "function");
  }

  for (const name of ["kevs_search", "cmvp_search_modules", "fedramp_check_sources", "aws_export_audit_bundle", "oscal_validate_model"]) {
    assert.ok(flueTools.some((tool) => tool.name === name), `${name} should be mounted`);
  }

  const kevsRecent = flueTools.find((tool) => tool.name === "kevs_recent");
  const parsed = v.safeParse(kevsRecent.input, { days: 7 });
  assert.ok(parsed.success);
  assert.deepEqual(parsed.output, { days: 7 });
});

test("bridged tools validate through the shim, execute once, and return Flue envelopes", async () => {
  const { tool, executions } = createFakePiTool();
  const flueTool = toFlueTool(tool);
  const signal = new AbortController().signal;

  // Flue parses `input` (which runs prepareArguments first) before calling `run`.
  const data = v.parse(flueTool.input, { cve: "CVE-2024-3400", limit: 5 });
  assert.deepEqual(data, { query: "CVE-2024-3400", limit: 5 });

  const result = await flueTool.run(fakeRunContext(data, { toolCallId: "call-42", signal }));
  assert.deepEqual(result, { output: "probe saw CVE-2024-3400" });
  assert.equal(executions.length, 1);
  assert.equal(executions[0].toolCallId, "call-42");
  assert.equal(executions[0].signal, signal);
  assert.equal(executions[0].params, data, "run hands the validated arguments to execute without re-normalizing");

  const terminating = toFlueTool(
    createFakePiTool({
      async execute() {
        return { content: [{ type: "text", text: "done" }], details: {}, terminate: true };
      },
    }).tool,
  );
  assert.deepEqual(await terminating.run(fakeRunContext({ query: "x" })), { output: "done", terminate: true });

  const failing = toFlueTool(
    createFakePiTool({
      async execute() {
        return { content: [{ type: "text", text: "kevs_probe requires a query." }], details: { tool: "kevs_probe" }, isError: true };
      },
    }).tool,
  );
  await assert.rejects(failing.run(fakeRunContext({ query: "x" })), (error) => {
    assert.ok(error instanceof GrclankerToolError);
    assert.equal(error.message, "kevs_probe requires a query.");
    assert.equal(error.toolName, "kevs_probe");
    assert.deepEqual(error.details, { tool: "kevs_probe" });
    return true;
  });

  assert.equal(
    renderPiToolContent([
      { type: "text", text: "first" },
      { type: "image", data: "AAAA", mimeType: "image/png" },
    ]),
    "first\n[image content omitted: image/png]",
  );
  assert.deepEqual(toFlueToolResult("t", { content: [{ type: "text", text: " padded " }], details: {} }), { output: "padded" });
});

test("shipped prompts load as the instruction document, workflow skills, and subagent roles", () => {
  const appRoot = resolveFlueAppRoot(distFlueDir);
  assert.equal(appRoot, cliRoot);
  assert.throws(() => resolveFlueAppRoot(tmpdir()), /Unable to locate the grclanker CLI root/);

  const content = loadGrclankerAgentContent(appRoot);
  assert.match(content.systemPrompt, /^# GRC Clanker/);
  assert.equal(content.systemPrompt, readFileSync(resolve(cliRoot, ".grclanker", "SYSTEM.md"), "utf8").trim());

  assert.deepEqual(
    content.workflows.map((skill) => skill.name),
    ["assess", "audit", "investigate", "validate"],
  );
  const audit = content.workflows.find((skill) => skill.name === "audit");
  assert.match(audit.description, /Compliance Audit workflow\./);
  assert.match(audit.description, /\/audit workflow/);
  assert.ok(audit.description.length <= 1024);
  assert.equal(audit.instructions, readFileSync(resolve(cliRoot, "prompts", "audit.md"), "utf8").trim());
  assert.ok(Object.isFrozen(audit), "defineSkill() validates and freezes workflow skills");

  assert.deepEqual(content.skills.map((skill) => skill.name), ["crypto-validation"]);
  assert.match(content.skills[0].description, /FIPS/);
  assert.equal(content.skills[0].instructions.startsWith("---"), false, "frontmatter is stripped from instructions");

  assert.deepEqual(content.roles.map((role) => role.name), ["auditor", "verifier"]);
  const auditor = content.roles.find((role) => role.name === "auditor");
  assert.match(auditor.description, /^Analyze evidence against compliance framework requirements/);
  assert.equal(auditor.allowedTools.length, 8);
  assert.ok(auditor.allowedTools.includes("cmvp_get_module"));
  assert.ok(auditor.allowedTools.includes("kevs_check_ransomware"));
});

test("prompt parsing helpers extract titles, frontmatter, and persona fields", () => {
  assert.deepEqual(summarizeMarkdownPrompt("# Title\n\nFirst line.\ncontinues here.\n\n## Phase 1\n\nMore."), {
    title: "Title",
    summary: "First line. continues here.",
  });

  const skill = workflowSkillFromPrompt("triage", "# Triage Run\n\nTriage things quickly.\n");
  assert.equal(skill.name, "triage");
  assert.equal(skill.description, "Triage Run workflow. Triage things quickly. Use when the user asks for the grclanker /triage workflow or equivalent work.");

  const parsed = parseSkillMarkdown("---\nname: demo\ndescription: Demo skill.\nlicense: MIT\n---\n\n# Demo\n\nBody.\n");
  assert.deepEqual(parsed.frontmatter, { name: "demo", description: "Demo skill.", license: "MIT" });
  assert.equal(parsed.body, "# Demo\n\nBody.");
  assert.deepEqual(parseSkillMarkdown("plain body"), { frontmatter: {}, body: "plain body" });

  const role = parseSubagentRole("fallback", "Name: checker\n\nPurpose: Check things.\n\n## Tool Access\n\nAllowed: a_tool, b_tool\n");
  assert.equal(role.name, "checker");
  assert.equal(role.description, "Check things.");
  assert.deepEqual(role.allowedTools, ["a_tool", "b_tool"]);
  assert.equal(parseSubagentRole("fallback", "No labels here.").name, "fallback");
});

test("agent render declares model, sandbox, tools, skills, and subagents through the hooks", () => {
  const content = loadGrclankerAgentContent(cliRoot);
  const tools = createGrclankerFlueTools();
  const { hooks, calls } = createRecordingHooks();
  const sandboxOptions = [];

  const instructions = renderGrclankerAgent(hooks, {
    model: "openai/gpt-5.5",
    sandbox: "local",
    cwd: "/work/evidence",
    content,
    tools,
    createLocalSandbox: (options) => {
      sandboxOptions.push(options);
      return { fake: "sandbox" };
    },
  });

  assert.deepEqual(calls.models, ["openai/gpt-5.5"]);
  assert.deepEqual(sandboxOptions, [{ cwd: "/work/evidence" }]);
  assert.deepEqual(calls.sandboxes, [{ fake: "sandbox" }]);
  assert.equal(calls.tools.length, DOMAIN_TOOL_COUNT);
  assert.deepEqual(
    calls.skills.map((skill) => skill.name),
    ["assess", "audit", "investigate", "validate", "crypto-validation"],
  );
  assert.deepEqual(calls.subagents.map((subagent) => subagent.name), ["auditor", "verifier"]);

  assert.match(instructions, /^# GRC Clanker/);
  assert.match(instructions, /## Flue Runtime/);
  assert.match(instructions, /activate `assess`, `audit`, `investigate`, `validate`/);
  assert.match(instructions, /`auditor` and `verifier` roles are available as subagents/);
  assert.match(instructions, /A local sandbox provides file and shell tools/);

  const auditorRender = createRecordingHooks();
  const auditor = calls.subagents.find((subagent) => subagent.name === "auditor");
  const auditorInstructions = auditor.agent();
  assert.match(auditorInstructions, /^Name: auditor/);
  assert.equal(typeof auditor.description, "string");

  const scoped = createSubagentDefinition(content.roles[0], tools, auditorRender.hooks);
  scoped.agent();
  assert.deepEqual(
    auditorRender.calls.tools.map((tool) => tool.name).sort(),
    [...content.roles[0].allowedTools].sort(),
    "subagents mount only their allowed tools",
  );

  const noSandbox = createRecordingHooks();
  const text = renderGrclankerAgent(noSandbox.hooks, {
    model: DEFAULT_FLUE_MODEL,
    sandbox: "none",
    cwd: "/work",
    content,
    tools: [],
    createLocalSandbox: () => {
      throw new Error("should not be called");
    },
  });
  assert.equal(noSandbox.calls.sandboxes.length, 0);
  assert.match(text, /No sandbox is attached/);
  assert.equal(buildFlueInstructions(content, "none").includes("A local sandbox"), false);
});

test("model and sandbox resolution follow env, hosted settings, then Flue defaults", () => {
  assert.equal(resolveFlueModel({ GRCLANKER_FLUE_MODEL: " openai/gpt-5.5 " }, { modelMode: "local" }), "openai/gpt-5.5");
  assert.equal(
    resolveFlueModel({}, { modelMode: "hosted", defaultProvider: "google", defaultModel: "gemini-2.5-pro" }),
    "google/gemini-2.5-pro",
  );
  assert.equal(resolveFlueModel({}, {}), DEFAULT_FLUE_MODEL);
  assert.equal(
    resolveFlueModel({}, { modelMode: "local", defaultProvider: "ollama", defaultModel: "gemma4" }, ["ollama"]),
    "ollama/gemma4",
    "a local-first setup resolves once its provider is registered",
  );
  assert.throws(
    () => resolveFlueModel({}, { modelMode: "local", defaultProvider: "ollama", defaultModel: "gemma4" }, []),
    (error) =>
      error instanceof GrclankerFlueConfigError &&
      /ollama\/gemma4/.test(error.message) &&
      /models\.json/.test(error.message) &&
      /GRCLANKER_FLUE_MODEL/.test(error.message),
  );

  assert.equal(resolveFlueSandboxMode({}), "local");
  assert.equal(resolveFlueSandboxMode({ GRCLANKER_FLUE_SANDBOX: "LOCAL" }), "local");
  assert.equal(resolveFlueSandboxMode({ GRCLANKER_FLUE_SANDBOX: "none" }), "none");
  assert.throws(() => resolveFlueSandboxMode({ GRCLANKER_FLUE_SANDBOX: "docker" }), GrclankerFlueConfigError);
});

test("the 'use agent' module exports one Flue agent wired to the real hooks", () => {
  const source = readFileSync(resolve(cliRoot, "flue", "agent.ts"), "utf8");
  assert.ok(source.startsWith("'use agent';"), "directive must be the first statement");
  assert.match(source, /^export function Grclanker\(\)/m, "flue run scans for exported capitalized function declarations");
  assert.match(source, /^Grclanker\.agentName = "grclanker";/m, "agentName must be a top-level string literal");

  assert.equal(typeof Grclanker, "function");
  assert.equal(Grclanker.agentName, "grclanker");
  assert.match(Grclanker.agentName, AGENT_IDENTITY_PATTERN);
  assert.equal(typeof prepareGrclankerAgent, "function");

  const options = prepareGrclankerAgent();
  assert.equal(options.model, DEFAULT_FLUE_MODEL);
  assert.equal(options.sandbox, "local");
  assert.equal(options.tools.length, DOMAIN_TOOL_COUNT);
  assert.equal(options.content.workflows.length, 4);
  assert.equal(prepareGrclankerAgent(), options, "options are loaded once and reused across renders");

  assert.throws(() => Grclanker(), /useModel\(\) was called outside an agent function/);
});

test("runner boots Flue, streams tool activity, and reports the settled reply", async () => {
  const stderr = [];
  const startCalls = [];
  let stopped = 0;
  let prepared = 0;
  const agent = () => "fake";
  const events = [
    { type: "tool-input", conversationId: "c", messageId: "m", toolCallId: "t1", toolName: "kevs_search", input: { query: "CVE-2024-3400" }, position: { batch: 1, index: 0 } },
    { type: "message-delta", conversationId: "c", messageId: "m", kind: "text", delta: "hello", position: { batch: 1, index: 1 } },
    { type: "tool-output", conversationId: "c", toolCallId: "t1", output: "ok", durationMs: 12, position: { batch: 2, index: 0 } },
    { type: "tool-output-error", conversationId: "c", toolCallId: "t1", errorText: "boom", position: { batch: 2, index: 1 } },
  ];

  const outcome = await runGrclankerFlueAgent(
    { message: "Check CVE-2024-3400", id: "conv-1", db: ":memory:" },
    {
      prepare: () => {
        prepared += 1;
      },
      start: async (options) => {
        startCalls.push(options);
        return {
          stop: async () => {
            stopped += 1;
          },
        };
      },
      sqlite: (path) => ({ fakeAdapter: path }),
      init: (target, options) => {
        assert.equal(target, agent);
        return {
          id: options.id,
          dispatch: async (message) => {
            assert.equal(message, "Check CVE-2024-3400");
            return { submissionId: "sub-1", acceptedAt: "now", uid: "inst-1" };
          },
          read: async (receipt, readOptions) => {
            assert.equal(receipt.submissionId, "sub-1");
            for (const event of events) readOptions.onEvent(event);
            return { text: "BoringCrypto holds certificate #4407.", data: {}, submissionId: "sub-1" };
          },
          abort: async () => {},
        };
      },
      agent,
      writeErr: (line) => stderr.push(line),
    },
  );

  assert.equal(prepared, 1);
  assert.equal(stopped, 1);
  assert.equal(startCalls.length, 1);
  assert.deepEqual(startCalls[0].agents, [agent]);
  assert.deepEqual(startCalls[0].db, { fakeAdapter: ":memory:" });
  assert.deepEqual(outcome, {
    id: "conv-1",
    agent: "grclanker",
    submissionId: "sub-1",
    outcome: "completed",
    message: "BoringCrypto holds certificate #4407.",
  });
  assert.deepEqual(stderr, [
    "conversation: conv-1",
    '-> kevs_search {"query":"CVE-2024-3400"}',
    "<- kevs_search ok (12ms)",
    "<- kevs_search error: boom",
  ]);
});

test("runner surfaces failed settlements with Flue's recorded reason and still stops the runtime", async () => {
  let stopped = 0;
  const failure = Object.assign(new Error("[flue] Agent run failed (submission sub-9)."), {
    outcome: "failed",
    submissionId: "sub-9",
    cause: { name: "FlueError", message: "dispatch(sub-9) failed: Provider is not configured: anthropic", meta: { reason: "Provider is not configured: anthropic" } },
  });

  const outcome = await runGrclankerFlueAgent(
    { message: "hi", db: ":memory:" },
    {
      prepare: () => {},
      start: async () => ({
        stop: async () => {
          stopped += 1;
        },
      }),
      sqlite: () => undefined,
      init: () => ({
        id: "fresh-id",
        dispatch: async () => ({ submissionId: "sub-9", acceptedAt: "now", uid: "u" }),
        read: async () => {
          throw failure;
        },
        abort: async () => {},
      }),
      agent: () => "fake",
      writeErr: () => {},
    },
  );

  assert.equal(stopped, 1);
  assert.deepEqual(outcome, {
    id: "fresh-id",
    agent: "grclanker",
    submissionId: "sub-9",
    outcome: "failed",
    error: "Provider is not configured: anthropic",
  });
  assert.equal(describeAgentRunError(new Error("plain")), "plain");
  assert.equal(describeAgentRunError(Object.assign(new Error("outer"), { cause: { message: "inner" } })), "inner");

  await assert.rejects(
    runGrclankerFlueAgent(
      { message: "hi", db: ":memory:" },
      {
        prepare: () => {},
        start: async () => ({ stop: async () => {} }),
        sqlite: () => undefined,
        init: () => ({
          id: "x",
          dispatch: async () => {
            throw new TypeError("unexpected");
          },
          read: async () => ({ text: "", data: {}, submissionId: "s" }),
          abort: async () => {},
        }),
        agent: () => "fake",
        writeErr: () => {},
      },
    ),
    TypeError,
    "non-settlement errors propagate",
  );
});

test("runner helpers resolve database paths, activity lines, and exit codes", () => {
  assert.equal(resolveFlueDatabasePath(":memory:", "/home/x/.grclanker"), ":memory:");
  assert.equal(resolveFlueDatabasePath(undefined, "/home/x/.grclanker"), resolve("/home/x/.grclanker", "flue", "conversations.db"));
  assert.equal(resolveFlueDatabasePath("./runs/a.db", "/home/x/.grclanker"), resolve("./runs/a.db"));

  const format = createFlueActivityFormatter();
  assert.equal(format({ type: "message-started", conversationId: "c", messageId: "m", position: { batch: 0, index: 0 } }), undefined);
  assert.equal(format({ type: "tool-output", conversationId: "c", toolCallId: "unknown", output: 1, position: { batch: 0, index: 1 } }), "<- unknown ok");

  assert.equal(exitCodeForOutcome("completed"), 0);
  assert.equal(exitCodeForOutcome("failed"), 1);
  assert.equal(exitCodeForOutcome("aborted"), 130);
});

test("grclanker flue command parses arguments and formats outcomes", async () => {
  assert.deepEqual(parseFlueRunArgs(["-m", "hello", "--id", "c1", "--db", ":memory:", "--json"]), {
    request: { message: "hello", id: "c1", db: ":memory:" },
    json: true,
  });
  assert.deepEqual(parseFlueRunArgs(["--message", "hello"]), { request: { message: "hello", id: undefined, db: undefined }, json: false });
  assert.throws(() => parseFlueRunArgs([]), /requires --message/);
  assert.throws(() => parseFlueRunArgs(["-m"]), /requires a value/);
  assert.throws(() => parseFlueRunArgs(["-m", "hi", "--bogus"]), /Unknown option/);

  assert.deepEqual(formatFlueRunOutcome({ id: "c", agent: "grclanker", outcome: "completed", message: "done" }, false), { out: "done" });
  assert.deepEqual(formatFlueRunOutcome({ id: "c", agent: "grclanker", outcome: "failed", error: "nope" }, false), {
    err: "grclanker flue run failed: nope",
  });
  assert.match(formatFlueRunOutcome({ id: "c", agent: "grclanker", outcome: "aborted" }, true).out, /"outcome":"aborted"/);
  assert.match(formatFlueHelp(), /grclanker flue run --message/);
  assert.match(formatFlueHelp(), /GRCLANKER_FLUE_MODEL/);

  const out = [];
  const err = [];
  const io = { writeOut: (line) => out.push(line), writeErr: (line) => err.push(line) };

  assert.equal(await runFlueCommand([], io), 0);
  assert.match(out.at(-1), /grclanker flue/);
  assert.equal(await runFlueCommand(["--help"], io), 0);
  assert.equal(await runFlueCommand(["deploy"], io), 1);
  assert.match(err.at(-2), /Unknown flue subcommand: deploy/);
  assert.equal(await runFlueCommand(["run"], io), 1);
  assert.match(err.at(-2), /requires --message/);

  const configFailure = await runFlueCommand(["run", "-m", "hi"], io, {
    prepare: () => {
      throw new GrclankerFlueConfigError("bad config");
    },
  });
  assert.equal(configFailure, 1);
  assert.equal(err.at(-1), "bad config");

  const fakeDeps = {
    prepare: () => {},
    start: async () => ({ stop: async () => {} }),
    sqlite: () => undefined,
    init: () => ({
      id: "json-1",
      dispatch: async () => ({ submissionId: "sub-2", acceptedAt: "now", uid: "u" }),
      read: async () => ({ text: "reply text", data: {}, submissionId: "sub-2" }),
      abort: async () => {},
    }),
    agent: () => "fake",
  };
  out.length = 0;
  assert.equal(await runFlueCommand(["run", "-m", "hi", "--id", "json-1", "--db", ":memory:", "--json"], io, fakeDeps), 0);
  assert.deepEqual(JSON.parse(out[0]), { id: "json-1", agent: "grclanker", submissionId: "sub-2", outcome: "completed", message: "reply text" });

  out.length = 0;
  assert.equal(await runFlueCommand(["run", "-m", "hi", "--db", ":memory:"], io, fakeDeps), 0);
  assert.deepEqual(out, ["reply text"]);
});

test("the agent runs end-to-end on the real Flue runtime with a faux model (no live provider)", async () => {
  const { fauxProvider, fauxAssistantMessage, fauxToolCall } = await importFluePiAi();
  const faux = fauxProvider({ models: [{ id: "grc-test" }] });
  const content = loadGrclankerAgentContent(cliRoot);
  const probe = createFakePiTool();
  const failing = createFakePiTool({
    name: "kevs_failing_probe",
    description: "Always fails.",
    async execute() {
      return { content: [{ type: "text", text: "probe failed on purpose" }], details: {}, isError: true };
    },
  });
  const tools = [toFlueTool(probe.tool), toFlueTool(failing.tool)];

  function GrclankerFauxTest() {
    return renderGrclankerAgent(
      { useModel, useSandbox, useSkill, useSubagent, useTool },
      {
        model: "faux/grc-test",
        sandbox: "none",
        cwd: process.cwd(),
        content,
        tools,
        createLocalSandbox: () => {
          throw new Error("no sandbox in this test");
        },
      },
    );
  }
  GrclankerFauxTest.agentName = "grclanker-faux-test";

  const modelContexts = [];
  const recordContext = (context) => {
    modelContexts.push({
      systemPrompt: context.systemPrompt,
      tools: context.tools?.map((tool) => ({ name: tool.name, parameters: tool.parameters })),
      messages: context.messages.map((message) => ({ role: message.role, isError: message.isError, toolName: message.toolName })),
    });
  };
  faux.setResponses([
    (context) => {
      recordContext(context);
      // The extra alias key proves the Pi `prepareArguments` shim (which rebuilds the object)
      // runs inside Flue's validation; the numeric string is coerced by Flue's gate first.
      return fauxAssistantMessage([fauxToolCall("kevs_probe", { query: "CVE-2024-3400", cve: "alias", limit: "5" })], {
        stopReason: "toolUse",
      });
    },
    (context) => {
      recordContext(context);
      return fauxAssistantMessage([fauxToolCall("kevs_failing_probe", { query: "x" })], { stopReason: "toolUse" });
    },
    (context) => {
      recordContext(context);
      return fauxAssistantMessage("CVE-2024-3400 is a known exploited vulnerability.");
    },
  ]);

  const flue = await start({ agents: [GrclankerFauxTest], providers: [faux.provider] });
  const chunks = [];
  try {
    const handle = init(GrclankerFauxTest, { id: "faux-e2e-1" });
    const receipt = await handle.dispatch("Check CVE-2024-3400 against KEV.");
    const reply = await handle.read(receipt, { onEvent: (chunk) => chunks.push(chunk) });
    assert.equal(reply.text, "CVE-2024-3400 is a known exploited vulnerability.");
    assert.equal(reply.submissionId, receipt.submissionId);
  } finally {
    await flue.stop();
  }

  assert.equal(faux.state.callCount, 3);
  assert.equal(probe.executions.length, 1);
  assert.deepEqual(probe.executions[0].params, { query: "CVE-2024-3400", limit: 5 });
  assert.equal(typeof probe.executions[0].toolCallId, "string");

  const first = modelContexts[0];
  assert.match(first.systemPrompt, /# GRC Clanker/);
  assert.match(first.systemPrompt, /## Flue Runtime/);
  assert.match(first.systemPrompt, /crypto-validation/, "mounted skills appear in the system prompt catalog");
  assert.deepEqual(
    first.tools.map((tool) => tool.name).sort(),
    ["activate_skill", "kevs_failing_probe", "kevs_probe", "task"].sort(),
    "the model sees the bridged tools plus Flue's skill and subagent tools",
  );
  const probeSchema = first.tools.find((tool) => tool.name === "kevs_probe").parameters;
  assert.equal(probeSchema.type, "object");
  assert.deepEqual(probeSchema.required, ["query"]);
  assert.deepEqual(probeSchema.properties.query, { type: "string", description: "CVE ID or keyword." });
  assert.deepEqual(probeSchema.properties.limit, { type: "number", default: 5 });

  const afterFailure = modelContexts[2];
  const toolResults = afterFailure.messages.filter((message) => message.role === "toolResult");
  assert.deepEqual(
    toolResults.map((message) => [message.toolName, message.isError]),
    [["kevs_probe", false], ["kevs_failing_probe", true]],
    "Pi errorResult() surfaces to the model as a Flue tool error",
  );

  const toolInputs = chunks.filter((chunk) => chunk.type === "tool-input").map((chunk) => chunk.toolName);
  assert.deepEqual(toolInputs, ["kevs_probe", "kevs_failing_probe"]);
  assert.ok(chunks.some((chunk) => chunk.type === "tool-output"));
  assert.ok(chunks.some((chunk) => chunk.type === "tool-output-error"));
  assert.ok(chunks.some((chunk) => chunk.type === "submission-settled" && chunk.outcome === "completed"));
});

const OLLAMA_MODELS_JSON = {
  providers: {
    ollama: {
      baseUrl: "http://localhost:11434/v1",
      api: "openai-completions",
      apiKey: "ollama",
      compat: { supportsDeveloperRole: false, supportsReasoningEffort: false },
      models: [{ id: "gemma4", name: "gemma4 (Local)", reasoning: false, input: ["text"] }],
    },
  },
};

test("custom providers are read from Pi models.json the way grclanker setup writes them", () => {
  const configs = listCustomProviderConfigs({
    ...OLLAMA_MODELS_JSON,
    providers: {
      ...OLLAMA_MODELS_JSON.providers,
      "override-only": { baseUrl: "https://example.test" },
      broken: { models: [{ name: "no id" }] },
    },
  });
  assert.deepEqual(
    configs.map((config) => config.id),
    ["ollama"],
    "entries without their own models are Pi overrides, not providers to register",
  );
  assert.equal(configs[0].apiKey, "ollama");
  assert.deepEqual(configs[0].models, [{ id: "gemma4", name: "gemma4 (Local)", api: undefined, baseUrl: undefined, reasoning: false, input: ["text"], cost: undefined, contextWindow: undefined, maxTokens: undefined, compat: undefined }]);
  assert.deepEqual(listCustomProviderConfigs({}), []);

  assert.deepEqual(
    localProviderConfigFromSettings({ modelMode: "local", defaultProvider: "ollama", defaultModel: "gemma4", providerBaseUrl: "http://localhost:11434/v1" }),
    { id: "ollama", baseUrl: "http://localhost:11434/v1", api: "openai-completions", models: [{ id: "gemma4", name: "gemma4 (Local)" }] },
  );
  assert.equal(localProviderConfigFromSettings({ modelMode: "hosted", defaultProvider: "anthropic", defaultModel: "x" }), undefined);
  assert.equal(localProviderConfigFromSettings({ modelMode: "local", defaultProvider: "ollama" }), undefined);

  assert.equal(resolveApiKeyValue("ollama", {}), "ollama");
  assert.equal(resolveApiKeyValue("$LOCAL_KEY", { LOCAL_KEY: "abc" }), "abc");
  assert.equal(resolveApiKeyValue("Bearer ${LOCAL_KEY}", { LOCAL_KEY: "abc" }), "Bearer abc");
  assert.equal(resolveApiKeyValue("$MISSING_KEY", {}), undefined, "an unset env var means the provider is not configured");
  assert.throws(() => resolveApiKeyValue("!security find-generic-password", {}), GrclankerFlueConfigError);
});

test("custom providers build Pi Provider objects with Pi's models.json defaults", () => {
  const warnings = [];
  const provider = createCustomProvider(listCustomProviderConfigs(OLLAMA_MODELS_JSON)[0], {}, warnings);
  assert.equal(provider.id, "ollama");
  assert.deepEqual(warnings, []);
  const models = provider.getModels();
  assert.equal(models.length, 1);
  assert.deepEqual(
    { ...models[0] },
    {
      id: "gemma4",
      name: "gemma4 (Local)",
      api: "openai-completions",
      provider: "ollama",
      baseUrl: "http://localhost:11434/v1",
      reasoning: false,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000,
      maxTokens: 16384,
      compat: { supportsDeveloperRole: false, supportsReasoningEffort: false },
    },
  );

  const mixed = createCustomProvider(
    {
      id: "mixed",
      baseUrl: "https://mixed.test/v1",
      apiKey: "$MIXED_KEY",
      models: [
        { id: "chat", api: "openai-completions" },
        { id: "claude-ish", api: "anthropic-messages", baseUrl: "https://mixed.test/anthropic", contextWindow: 200000 },
        { id: "unsupported", api: "google-generative-ai" },
        { id: "no-url", api: "openai-responses", baseUrl: undefined },
      ],
    },
    { MIXED_KEY: "k" },
    warnings,
  );
  assert.deepEqual(mixed.getModels().map((model) => [model.id, model.api, model.baseUrl, model.contextWindow]), [
    ["chat", "openai-completions", "https://mixed.test/v1", 128000],
    ["claude-ish", "anthropic-messages", "https://mixed.test/anthropic", 200000],
    ["no-url", "openai-responses", "https://mixed.test/v1", 128000],
  ]);
  assert.deepEqual(warnings, [
    'Skipping mixed/unsupported for Flue: api "google-generative-ai" is not one of openai-completions, openai-responses, anthropic-messages.',
  ]);

  assert.equal(createCustomProvider({ id: "empty", models: [{ id: "x", api: "openai-completions" }] }, {}, []), undefined, "no baseUrl anywhere means nothing to serve");

  const registered = [];
  const result = registerGrclankerProviders({
    env: {},
    settings: { modelMode: "local", defaultProvider: "ollama", defaultModel: "gemma4", providerBaseUrl: "http://localhost:11434/v1" },
    modelsConfig: OLLAMA_MODELS_JSON,
    setProvider: (candidate) => registered.push(candidate.id),
  });
  assert.deepEqual(result, { providerIds: ["ollama"], warnings: [] });
  assert.deepEqual(registered, ["ollama"], "models.json wins over the settings fallback for the same id");

  const fallback = registerGrclankerProviders({
    env: {},
    settings: { modelMode: "local", defaultProvider: "lmstudio", defaultModel: "qwen", providerBaseUrl: "http://localhost:1234/v1" },
    modelsConfig: {},
    setProvider: (candidate) => registered.push(candidate.id),
  });
  assert.deepEqual(fallback.providerIds, ["lmstudio"]);
  assert.deepEqual(registerGrclankerProviders({ env: {}, settings: {}, modelsConfig: {}, setProvider: () => assert.fail("nothing to register") }), {
    providerIds: [],
    warnings: [],
  });
});

test("a local-first grclanker setup runs under Flue through setProvider() against an OpenAI-compatible endpoint", async () => {
  const requests = [];
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      requests.push({ url: request.url, authorization: request.headers.authorization, body: JSON.parse(body) });
      response.writeHead(200, { "content-type": "text/event-stream" });
      const chunk = (delta, finish) =>
        `data: ${JSON.stringify({ id: "chatcmpl-1", object: "chat.completion.chunk", created: 1, model: "gemma4", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      response.write(chunk({ role: "assistant", content: "BoringCrypto holds " }, null));
      response.write(chunk({ content: "certificate #4407." }, null));
      response.write(chunk({}, "stop"));
      response.write("data: [DONE]\n\n");
      response.end();
    });
  });
  await new Promise((ready) => server.listen(0, "127.0.0.1", ready));
  const baseUrl = `http://127.0.0.1:${server.address().port}/v1`;

  try {
    const settings = { modelMode: "local", providerKind: "ollama", providerBaseUrl: baseUrl, defaultProvider: "ollama", defaultModel: "gemma4" };
    const modelsConfig = { providers: { ollama: { ...OLLAMA_MODELS_JSON.providers.ollama, baseUrl } } };
    const registered = registerGrclankerProviders({ env: {}, settings, modelsConfig, setProvider });
    assert.deepEqual(registered, { providerIds: ["ollama"], warnings: [] });

    const model = resolveFlueModel({}, settings, registered.providerIds);
    assert.equal(model, "ollama/gemma4");

    const content = loadGrclankerAgentContent(cliRoot);
    function GrclankerLocalTest() {
      return renderGrclankerAgent(
        { useModel, useSandbox, useSkill, useSubagent, useTool },
        { model, sandbox: "none", cwd: process.cwd(), content, tools: [], createLocalSandbox: () => assert.fail("no sandbox") },
      );
    }
    GrclankerLocalTest.agentName = "grclanker-local-test";

    const flue = await start({ agents: [GrclankerLocalTest] });
    try {
      const handle = init(GrclankerLocalTest, { id: "local-e2e-1" });
      const reply = await handle.read(await handle.dispatch("Is BoringCrypto FIPS validated?"));
      assert.equal(reply.text, "BoringCrypto holds certificate #4407.");
    } finally {
      await flue.stop();
    }

    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, "/v1/chat/completions");
    assert.equal(requests[0].authorization, "Bearer ollama", "the models.json apiKey is sent as in the Pi CLI");
    assert.equal(requests[0].body.model, "gemma4");
    assert.equal(requests[0].body.stream, true);
    assert.match(requests[0].body.messages.find((message) => message.role === "system").content, /GRC Clanker/);
  } finally {
    await new Promise((closed) => server.close(closed));
  }
});
