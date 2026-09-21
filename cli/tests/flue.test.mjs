import test from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
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
  readLabeledLine,
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
  collectToolParameterSchemas,
  createFlueActivityFormatter,
  describeAgentRunError,
  exitCodeForOutcome,
  resolveFlueDatabasePath,
  runGrclankerFlueAgent,
} from "../dist/flue/run.js";
import {
  ARGUMENTS_WITHHELD_NOTE,
  REDACTED_VALUE,
  collectSensitiveValues,
  isSensitiveArgumentKey,
  redactSensitiveArguments,
  scrubSensitiveValues,
  scrubbedFormsOf,
  withholdEchoedArguments,
} from "../dist/flue/redact.js";
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
  ["pattern", /must match pattern/],
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

test("string patterns render for the model and are enforced by Flue's gate, without compiling schema input into a RegExp", () => {
  const piTool = {
    name: "pattern_probe",
    label: "Pattern probe",
    description: "Probe.",
    parameters: Type.Object({ code: Type.String({ pattern: "^[A-Z]{3}-[0-9]+$" }), note: Type.Optional(Type.String({ minLength: 2 })) }),
    execute: async () => ({ content: [{ type: "text", text: "ok" }], details: {} }),
  };
  const [flueTool] = createGrclankerFlueTools([piTool]);

  const rendered = renderedToolSchema(flueTool);
  assert.equal(rendered.properties.code.pattern, "^[A-Z]{3}-[0-9]+$", "the model-facing schema keeps the pattern");
  assert.equal(rendered.properties.note.minLength, 2);

  assert.deepEqual(flueVerdict(flueTool, { code: "ABC-12" }), { ok: true, args: { code: "ABC-12" } });
  assert.deepEqual(flueVerdict(flueTool, { code: "nope" }), { ok: false, stage: "gate", reason: "pattern" }, "a non-matching value stops at Flue's gate");
  assert.match(flueGate(flueTool, { code: "nope" }).message, /code: must match pattern/);
  const shortNote = flueGate(flueTool, { code: "ABC-1", note: "x" });
  assert.equal(shortNote.ok, false);
  assert.match(shortNote.message, /note/);

  // The adapter stage itself only checks what Valibot expresses natively; the pattern is delegated to the gate above.
  assert.equal(v.safeParse(flueTool.input, { code: "nope" }).success, true);
  assert.equal(v.safeParse(flueTool.input, { code: "ABC-1", note: "x" }).success, false);
});

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
  const crlf = parseSkillMarkdown("---\r\nname: crlf\r\n---\r\n\r\nBody.\r\n");
  assert.deepEqual(crlf, { frontmatter: { name: "crlf" }, body: "Body." });

  const role = parseSubagentRole("fallback", "Name: checker\n\nPurpose: Check things.\n\n## Tool Access\n\nAllowed: a_tool, b_tool\n");
  assert.equal(role.name, "checker");
  assert.equal(role.description, "Check things.");
  assert.deepEqual(role.allowedTools, ["a_tool", "b_tool"]);
  assert.equal(parseSubagentRole("fallback", "No labels here.").name, "fallback");

  // Labeled lines are matched by literal prefix at the start of a line: no regex is built from the label.
  assert.equal(readLabeledLine("Name: checker\n", "Name"), "checker");
  assert.equal(readLabeledLine("Name:   spaced  \r\nPurpose: x\r\n", "Name"), "spaced", "CRLF endings and padding are trimmed");
  assert.equal(readLabeledLine("Name:\nPurpose: x\n", "Name"), undefined, "an empty value is treated as absent");
  assert.equal(readLabeledLine("Name:    \n", "Name"), undefined, "a whitespace-only value is treated as absent");
  assert.equal(readLabeledLine("The Name: not at line start\n", "Name"), undefined, "the label must start the line");
  assert.equal(readLabeledLine("Nameplate: no\nName: yes\n", "Name"), "yes", "the colon must follow the label directly");
  assert.equal(readLabeledLine("AxB: no\nA.B: yes\n", "A.B"), "yes", "label characters are literal, not regex syntax");
  assert.equal(parseSubagentRole("fallback", "Name:   \nPurpose: p\n").name, "fallback", "a blank Name falls back");
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

test("credential-bearing tool arguments are redacted before serialization, at any depth", () => {
  const redacted = redactSensitiveArguments({
    query: "CVE-2024-3400",
    limit: 5,
    api_token: "cf-token-VALUE",
    client_secret: "zoom-secret-VALUE",
    ClientSecret: "camel-secret-VALUE",
    private_key: "-----BEGIN PRIVATE KEY-----",
    app_private_key: "-----BEGIN RSA PRIVATE KEY-----",
    apiKey: "api-key-VALUE",
    password: "pw-VALUE",
    passphrase: "phrase-VALUE",
    credentials_json: { type: "service_account", private_key_id: "kid", private_key: "gcp-key-VALUE" },
    authorization: "Bearer bearer-VALUE",
    client_assertion: "jwt-VALUE",
    skey: "duo-skey-VALUE",
    ikey: "duo-ikey-VALUE",
    nested: { access_token: "nested-token-VALUE", region: "us-east-1", deeper: [{ scim_token: "array-token-VALUE", ok: true }] },
    list: ["plain", { management_token: "list-token-VALUE" }],
    auth_mode: "app",
    cert_number: "4282",
    max_keys: 3,
  });

  const serialized = JSON.stringify(redacted);
  assert.equal(serialized.includes("VALUE"), false, `no secret survives: ${serialized}`);
  assert.equal(serialized.includes("BEGIN"), false, "private keys are replaced wholesale");
  assert.deepEqual(redacted.credentials_json, REDACTED_VALUE, "a sensitive object is replaced wholesale, not walked");
  assert.deepEqual(redacted.nested, { access_token: REDACTED_VALUE, region: "us-east-1", deeper: [{ scim_token: REDACTED_VALUE, ok: true }] });
  assert.deepEqual(redacted.list, ["plain", { management_token: REDACTED_VALUE }]);
  assert.equal(redacted.query, "CVE-2024-3400");
  assert.equal(redacted.limit, 5);
  assert.equal(redacted.auth_mode, "app");
  assert.equal(redacted.cert_number, "4282");
  assert.equal(redacted.max_keys, 3);

  // Non-object inputs pass through untouched.
  assert.equal(redactSensitiveArguments("plain"), "plain");
  assert.equal(redactSensitiveArguments(null), null);
  assert.deepEqual(redactSensitiveArguments([1, "two"]), [1, "two"]);

  // Fields the schema marks sensitive are redacted even when their names look harmless.
  const schema = {
    type: "object",
    properties: {
      passcode: { type: "string", writeOnly: true },
      pin: { type: "string", format: "password" },
      handle: { type: "string", sensitive: true },
      accounts: { type: "array", items: { type: "object", properties: { seed: { type: "string", writeOnly: true } } } },
      label: { type: "string" },
    },
  };
  assert.deepEqual(
    redactSensitiveArguments({ passcode: "1234", pin: "0000", handle: "h", accounts: [{ seed: "s", name: "n" }], label: "ok" }, schema),
    { passcode: REDACTED_VALUE, pin: REDACTED_VALUE, handle: REDACTED_VALUE, accounts: [{ seed: REDACTED_VALUE, name: "n" }], label: "ok" },
  );

  // Every credential-bearing parameter declared by a shipped domain tool is caught by the name pattern.
  const declaredKeys = new Set();
  const walk = (node) => {
    for (const [key, property] of Object.entries(node?.properties ?? {})) {
      declaredKeys.add(key);
      walk(property);
      walk(property?.items);
    }
  };
  for (const parameters of collectToolParameterSchemas().values()) walk(parameters);
  const credentialKeys = [
    "access_token", "api_key", "api_token", "app_private_key", "client_assertion", "client_secret", "credentials_json",
    "graph_token", "ikey", "management_token", "private_key", "scim_token", "skey", "token",
  ];
  for (const key of credentialKeys) {
    assert.ok(declaredKeys.has(key), `${key} is still a declared tool parameter`);
    assert.ok(isSensitiveArgumentKey(key), `${key} is redacted`);
  }
  for (const key of ["query", "limit", "cert_number", "auth_mode", "max_keys", "org_url", "workspace_dir", "cve_ids", "installation_id"]) {
    assert.equal(isSensitiveArgumentKey(key), false, `${key} stays visible`);
  }

  // Names the delta review listed as slipping past the old pattern, plus camelCase and hyphenated spellings.
  for (const key of [
    "pin_code", "pinCode", "passcode", "otp_code", "totp", "bearer", "bearer_token", "signing_key", "encryption_key", "shared_key",
    "client_key", "service_account_key", "license_key", "licenseKey", "access_key_id", "connection_string", "connectionString",
    "hmac", "hmac_secret", "signature", "cookie", "session_id", "sessionId", "dsn", "jwt", "sas_url", "sas", "kubeconfig",
    "webhook_url", "webhookUrl", "auth_header", "basic_auth", "cert_pem", "x-api-key", "apiKey", "ClientSecret", "accessToken",
    // Concatenated spellings the old private_?key / api_?key pattern covered, plus a few more of the same shape.
    "apikey", "APIKEY", "x-apikey", "APIKey", "privatekey", "PRIVATEKEY", "accesskey", "signingkey", "sshkey", "masterkey", "secretkey",
  ]) {
    assert.ok(isSensitiveArgumentKey(key), `${key} is redacted`);
  }
  // Thresholds, durations, counts, and file references stay visible even when they mention a credential word.
  for (const key of [
    "token_limit", "stale_token_days", "stale_credential_days", "app_private_key_path", "credentials_file", "webhook_limit",
    "max_keys", "min_key_length", "max_session_hours", "license_limit", "keyword", "monkey", "bypass", "compass", "certificate_count",
  ]) {
    assert.equal(isSensitiveArgumentKey(key), false, `${key} stays visible`);
  }

  // Guard against future parameters: any declared name that even loosely smells like a credential must be
  // redacted by the pattern or be listed here as reviewed and known to be safe to print.
  const looselySensitive =
    /secret|key|token|pass|auth|cert|cookie|session|credential|assertion|jwt|pin(?:_|\b)|otp|dsn|bearer|signature|hmac|kubeconfig|connection|webhook|\bsas\b|pem\b|license/i;
  const reviewedSafeKeys = new Set([
    "app_private_key_path", // path to the key file, not the key
    "auth_mode", // selects an authentication strategy, not a credential
    "cert_number", // CMVP certificate number, public
    "credentials_file", // path to the credentials file, not its contents
    "license_limit", // count threshold
    "max_keys", // count threshold
    "max_session_hours", // duration threshold
    "oauth_base_url", // endpoint
    "stale_credential_days", // age threshold
    "stale_token_days", // age threshold
    "token_limit", // count threshold
    "webhook_limit", // count threshold
  ]);
  const unclassified = [...declaredKeys].filter(
    (key) => looselySensitive.test(key) && !isSensitiveArgumentKey(key) && !reviewedSafeKeys.has(key),
  );
  assert.deepEqual(unclassified, [], "new credential-looking parameters must be redacted or explicitly reviewed as safe");
  for (const key of reviewedSafeKeys) assert.ok(declaredKeys.has(key), `${key} is still declared; drop it from the safe list otherwise`);
});

test("tool error text loses Pi's echoed payload and any sensitive value from the matching input", () => {
  const piError = 'Validation failed for tool "probe":\n  - lookback_days: must be >= 1\n\nReceived arguments:\n{\n  "skey": "s3cr3t",\n  "lookback_days": 0\n}';
  assert.equal(withholdEchoedArguments(piError), `Validation failed for tool "probe":\n  - lookback_days: must be >= 1 ${ARGUMENTS_WITHHELD_NOTE}`);
  assert.equal(withholdEchoedArguments("plain failure"), "plain failure", "text without the marker is unchanged");

  const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----";
  const values = collectSensitiveValues(
    { api_token: "tok_1234567890", private_key: pem, credentials_json: { client_email: "svc@example.iam", private_key: "nested_secret_value" }, short: "x", passcode: "0000" },
    { type: "object", properties: { passcode: { type: "string", writeOnly: true } } },
  );
  assert.deepEqual(
    values,
    [pem, "nested_secret_value", "svc@example.iam", "tok_1234567890", "0000"],
    "everything inside a sensitive object counts, sorted longest first; values under four characters are dropped",
  );
  assert.equal(
    scrubSensitiveValues(`token tok_1234567890 rejected; key ${pem} and ${JSON.stringify(pem)} invalid`, values),
    `token ${REDACTED_VALUE} rejected; key ${REDACTED_VALUE} and "${REDACTED_VALUE}" invalid`,
    "raw and JSON-escaped forms are both scrubbed",
  );
});

test("scrubbing recognizes transformed echoes: encodings, reflowed PEM, case changes, short and numeric values", () => {
  const token = "tok_Live/AbC+dEf=9Q";
  const base64 = Buffer.from(token, "utf8").toString("base64");
  const base64url = Buffer.from(token, "utf8").toString("base64url");
  const urlEncoded = encodeURIComponent(token);
  assert.notEqual(base64, base64url, "the token was chosen so that base64 and base64url differ");
  assert.notEqual(urlEncoded, token);
  assert.ok(scrubbedFormsOf(token).includes(base64) && scrubbedFormsOf(token).includes(base64url) && scrubbedFormsOf(token).includes(urlEncoded));

  const values = collectSensitiveValues({ api_token: token });
  const echo = `upstream said: raw ${token}; b64 ${base64}; b64url ${base64url}; url ${urlEncoded}; upper ${token.toUpperCase()}; lower ${token.toLowerCase()}`;
  assert.equal(
    scrubSensitiveValues(echo, values),
    `upstream said: raw ${REDACTED_VALUE}; b64 ${REDACTED_VALUE}; b64url ${REDACTED_VALUE}; url ${REDACTED_VALUE}; upper ${REDACTED_VALUE}; lower ${REDACTED_VALUE}`,
  );

  // Standard base64 with the padding stripped and URL-encoded base64, for a value whose base64 carries +, /, and padding
  // (base64url would not cover the stripped form there).
  const awkward = "tok_?>???x";
  const awkwardBase64 = Buffer.from(awkward, "utf8").toString("base64");
  assert.match(awkwardBase64, /[+/].*==$/, "the value was chosen so its base64 has + or / and padding");
  const stripped = awkwardBase64.replace(/=+$/, "");
  const urlEncodedBase64 = encodeURIComponent(awkwardBase64);
  assert.notEqual(stripped, Buffer.from(awkward, "utf8").toString("base64url"));
  assert.match(urlEncodedBase64, /%2B|%2F/);
  assert.equal(
    scrubSensitiveValues(`stripped ${stripped}; encoded ${urlEncodedBase64}; padded ${awkwardBase64}`, collectSensitiveValues({ api_token: awkward })),
    `stripped ${REDACTED_VALUE}; encoded ${REDACTED_VALUE}; padded ${REDACTED_VALUE}`,
  );

  // A PEM re-flowed by a tool: newlines turned into spaces, removed, or one body line quoted alone.
  const body1 = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
  const body2 = "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu";
  const pem = `-----BEGIN PRIVATE KEY-----\n${body1}\n${body2}\n-----END PRIVATE KEY-----`;
  const pemValues = collectSensitiveValues({ private_key: pem });
  for (const reflowed of [pem.replace(/\n/g, " "), pem.replace(/\n/g, ""), `bad key line "${body2}"`, `lower ${body1.toLowerCase()}`]) {
    const scrubbed = scrubSensitiveValues(reflowed, pemValues);
    assert.equal(scrubbed.includes(body1) || scrubbed.includes(body2) || scrubbed.toLowerCase().includes(body1.toLowerCase()), false, `no body line survives in: ${scrubbed}`);
  }
  assert.equal(scrubSensitiveValues(pem.replace(/\n/g, " "), pemValues), REDACTED_VALUE, "a whole re-flowed PEM collapses to one marker");

  // Four to seven character values are scrubbed as whole tokens only; shorter ones never are.
  const shortValues = collectSensitiveValues({ passcode: "4711", pin: "12", otp: "918273" });
  assert.deepEqual(shortValues, ["918273", "4711"]);
  assert.equal(scrubSensitiveValues("passcode 4711 rejected, otp 918273 expired", shortValues), `passcode ${REDACTED_VALUE} rejected, otp ${REDACTED_VALUE} expired`);
  assert.equal(scrubSensitiveValues("submission sub_4711abc kept, id 47119 kept", shortValues), "submission sub_4711abc kept, id 47119 kept", "short values inside longer tokens are left alone");
  assert.equal(scrubSensitiveValues("(4711) and 4711.", shortValues), `(${REDACTED_VALUE}) and ${REDACTED_VALUE}.`, "punctuation counts as a token boundary");
  assert.equal(scrubSensitiveValues("pin 12 wrong", shortValues), "pin 12 wrong", "values under four characters are not scrubbed");

  // A numeric secret (a Duo ikey sent as a JSON number) is scrubbed in the decimal form JSON.stringify prints.
  const numericValues = collectSensitiveValues({ ikey: 12345678901234567890, skey: 4242 });
  assert.deepEqual(numericValues, [String(12345678901234567890), "4242"]);
  const numericEcho = `Received: ${JSON.stringify({ ikey: 12345678901234567890, skey: 4242 })}`;
  assert.equal(scrubSensitiveValues(numericEcho, numericValues), `Received: {"ikey":${REDACTED_VALUE},"skey":${REDACTED_VALUE}}`);

  // The formatter applies all of it to a tool-authored error that echoes the input in transformed forms.
  const format = createFlueActivityFormatter();
  format({ type: "tool-input", conversationId: "c", messageId: "m", toolCallId: "t1", toolName: "probe", input: { api_token: token, passcode: "4711" }, position: { batch: 1, index: 0 } });
  const line = format({
    type: "tool-output-error",
    conversationId: "c",
    toolCallId: "t1",
    errorText: `rejected ${base64} / ${urlEncoded} / ${token.toUpperCase()} / passcode 4711`,
    position: { batch: 2, index: 0 },
  });
  assert.equal(line, `<- probe error: rejected ${REDACTED_VALUE} / ${REDACTED_VALUE} / ${REDACTED_VALUE} / passcode ${REDACTED_VALUE}`);
});

test("regression: gate validation errors for shipped credential tools never put the secret on stderr", () => {
  const piTools = collectGrclankerDomainTools();
  const flueTools = new Map(createGrclankerFlueTools(piTools).map((tool) => [tool.name, tool]));
  const cases = [
    ["duo_check_access", "skey", "s".repeat(40), { ikey: "DIXXXXXXXXXXXXXXXXXX", api_host: "api-xxxx.duosecurity.com", lookback_days: 0 }, /lookback_days: must be >= 1/],
    ["okta_check_access", "client_assertion", `eyJ${"a".repeat(49)}`, { scopes: "okta.users.read" }, /scopes: must be array/],
    ["cloudflare_check_access", "api_token", `cf-${"t".repeat(38)}`, { account_id: "acct", timeout_seconds: "x" }, /timeout_seconds: must be number/],
    ["zoom_check_access", "client_secret", "z".repeat(32), { client_id: "app", account_id: "acct", timeout_seconds: "soon" }, /timeout_seconds: must be number/],
  ];

  for (const [name, secretKey, secret, rest, reason] of cases) {
    const payload = { [secretKey]: secret, ...rest };
    const gate = flueGate(flueTools.get(name), payload);
    assert.equal(gate.ok, false, `${name}: the gate rejects the malformed call`);
    assert.ok(gate.message.includes(secret), `${name}: Pi's real error text does embed the raw ${secretKey}`);

    // With the matching tool-input seen first (the normal stream order).
    const format = createFlueActivityFormatter({ parameterSchemas: collectToolParameterSchemas() });
    const inputLine = format({ type: "tool-input", conversationId: "c", messageId: "m", toolCallId: "t1", toolName: name, input: payload, position: { batch: 1, index: 0 } });
    const errorLine = format({ type: "tool-output-error", conversationId: "c", toolCallId: "t1", errorText: gate.message, position: { batch: 2, index: 0 } });
    for (const line of [inputLine, errorLine]) {
      assert.equal(line.includes(secret), false, `${name}: ${secretKey} must not appear in "${line}"`);
      assert.equal(line.includes(secret.slice(0, 12)), false, `${name}: not even a prefix of ${secretKey}`);
    }
    assert.match(errorLine, reason, `${name}: the field-level reason survives`);
    assert.ok(errorLine.endsWith(ARGUMENTS_WITHHELD_NOTE) || errorLine.endsWith("..."), `${name}: the payload is withheld: ${errorLine}`);

    // Without a preceding tool-input (nothing to scrub by value), the structural cut alone must suffice.
    const bare = createFlueActivityFormatter()({ type: "tool-output-error", conversationId: "c", toolCallId: "t9", errorText: gate.message, position: { batch: 2, index: 0 } });
    assert.equal(bare.includes(secret), false, `${name}: structural withholding alone hides ${secretKey}`);
    assert.match(bare, reason);
  }
});

test("runner activity lines never echo credentials passed as tool arguments", async () => {
  const stderr = [];
  const agent = () => "fake";
  const apiToken = "cfut_9f8e7d6c5b4a-SECRET-TOKEN";
  const clientSecret = "zsk_0123456789-SECRET-CLIENT";
  const passcode = "otp-4711-SECRET-PASSCODE";
  const events = [
    { type: "tool-input", conversationId: "c", messageId: "m", toolCallId: "t1", toolName: "cloudflare_check_access", input: { api_token: apiToken, account_id: "acct-1" }, position: { batch: 1, index: 0 } },
    { type: "tool-input", conversationId: "c", messageId: "m", toolCallId: "t2", toolName: "zoom_check_access", input: { client_id: "zoom-app", client_secret: clientSecret, account_id: "zoom-acct" }, position: { batch: 1, index: 1 } },
    { type: "tool-input", conversationId: "c", messageId: "m", toolCallId: "t3", toolName: "vault_probe", input: { passcode, region: "eu" }, position: { batch: 1, index: 2 } },
    { type: "tool-output", conversationId: "c", toolCallId: "t1", output: "ok", position: { batch: 2, index: 0 } },
    // Pi's validation error echoes the raw payload after "Received arguments:".
    {
      type: "tool-output-error",
      conversationId: "c",
      toolCallId: "t2",
      errorText: `Validation failed for tool "zoom_check_access":\n  - timeout_seconds: must be number\n\nReceived arguments:\n${JSON.stringify({ client_id: "zoom-app", client_secret: clientSecret, account_id: "zoom-acct" }, null, 2)}`,
      position: { batch: 2, index: 1 },
    },
    // A tool-authored message that repeats the credential verbatim.
    { type: "tool-output-error", conversationId: "c", toolCallId: "t3", errorText: `vault rejected passcode ${passcode} for region eu`, position: { batch: 2, index: 2 } },
  ];

  await runGrclankerFlueAgent(
    { message: "Check access", id: "conv-secrets", db: ":memory:" },
    {
      prepare: () => {},
      start: async () => ({ stop: async () => {} }),
      sqlite: (path) => ({ fakeAdapter: path }),
      init: (_target, options) => ({
        id: options.id,
        dispatch: async () => ({ submissionId: "sub-1", acceptedAt: "now", uid: "inst-1" }),
        read: async (_receipt, readOptions) => {
          for (const event of events) readOptions.onEvent(event);
          return { text: "done", data: {}, submissionId: "sub-1" };
        },
        abort: async () => {},
      }),
      agent,
      writeErr: (line) => stderr.push(line),
      toolParameterSchemas: () =>
        new Map([...collectToolParameterSchemas(), ["vault_probe", { type: "object", properties: { passcode: { type: "string", writeOnly: true } } }]]),
    },
  );

  const captured = stderr.join("\n");
  for (const secret of [apiToken, clientSecret, passcode, "SECRET"]) {
    assert.equal(captured.includes(secret), false, `stderr must not contain ${secret}:\n${captured}`);
  }
  assert.deepEqual(stderr, [
    "conversation: conv-secrets",
    '-> cloudflare_check_access {"api_token":"[redacted]","account_id":"acct-1"}',
    '-> zoom_check_access {"client_id":"zoom-app","client_secret":"[redacted]","account_id":"zoom-acct"}',
    '-> vault_probe {"passcode":"[redacted]","region":"eu"}',
    "<- cloudflare_check_access ok",
    `<- zoom_check_access error: Validation failed for tool "zoom_check_access": - timeout_seconds: must be number ${ARGUMENTS_WITHHELD_NOTE}`,
    "<- vault_probe error: vault rejected passcode [redacted] for region eu",
  ]);

  // The default runner wiring redacts by name even without schema knowledge of the tool.
  const format = createFlueActivityFormatter();
  const line = format({ type: "tool-input", conversationId: "c", messageId: "m", toolCallId: "t9", toolName: "custom_tool", input: { api_key: apiToken, nested: { private_key: "-----BEGIN" } }, position: { batch: 1, index: 0 } });
  assert.equal(line, '-> custom_tool {"api_key":"[redacted]","nested":{"private_key":"[redacted]"}}');
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
