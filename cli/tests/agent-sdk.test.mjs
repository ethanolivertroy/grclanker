import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { register } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Type } from "@sinclair/typebox";

import { AGENT_DESCRIPTION, grclankerAgentConfig, MODEL_ENV_VAR } from "../dist/agent-sdk/lib/agent.js";
import { classifyGrcToolEffect, isGrcWriteTool } from "../dist/agent-sdk/lib/effects.js";
import { buildGrclankerInstructions } from "../dist/agent-sdk/lib/instructions.js";
import { parsePersona, personaAgentConfig } from "../dist/agent-sdk/lib/personas.js";
import {
  collectRegisteredGrcTools,
  getRegisteredGrcTool,
  listRegisteredGrcToolNames,
} from "../dist/agent-sdk/lib/registry.js";
import { toSdkToolResult } from "../dist/agent-sdk/lib/results.js";
import { toJsonSchema } from "../dist/agent-sdk/lib/schema.js";
import {
  bundledSkillConfig,
  parseFrontmatter,
  WORKFLOW_NAMES,
  workflowSkillConfig,
} from "../dist/agent-sdk/lib/skills.js";
import { buildSdkToolConfig, executeGrcTool, grclankerToolConfig } from "../dist/agent-sdk/lib/tools.js";
import { clearGrcSharedCachesForTests } from "../dist/extensions/grc-tools/shared.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { buildAgentSdkToolSource, listAgentSdkToolFiles } from "../scripts/generate-agent-sdk-tools.mjs";

// Stub @cursor/july before any agent entry file is imported. The adapter
// library only uses type imports from the SDK, so it loads unmocked above.
register("./helpers/cursor-july-mock-hooks.mjs", import.meta.url);

const cliRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const agentSdkRoot = resolve(cliRoot, "agent-sdk");
const distAgentDir = resolve(cliRoot, "dist", "agent-sdk", "agent");
const COMPUTE_TOOL_NAMES = ["bash", "read", "write", "edit", "ls", "find", "grep"];
const WRITE_MARKER = /_(export|generate|collect|init|import|create|assemble)_/;
const EXPECTED_WRITE_TOOLS = [
  "ansible_export_audit_bundle",
  "aws_export_audit_bundle",
  "azure_export_audit_bundle",
  "cloudflare_export_audit_bundle",
  "duo_export_audit_bundle",
  "fedramp_generate_ads_bundle",
  "fedramp_generate_ads_site",
  "gcp_export_audit_bundle",
  "github_export_audit_bundle",
  "gws_export_audit_bundle",
  "gws_ops_collect_evidence_bundle",
  "oci_export_audit_bundle",
  "okta_export_audit_bundle",
  "oscal_assemble_ssp",
  "oscal_create_model",
  "oscal_generate_ssp_markdown",
  "oscal_import_model",
  "oscal_init_workspace",
  "slack_export_audit_bundle",
  "vanta_export_audit",
  "webex_export_audit_bundle",
  "zoom_export_audit_bundle",
];

function importAgentEntry(...segments) {
  return import(pathToFileURL(resolve(distAgentDir, ...segments)).href);
}

function mockCalls() {
  return globalThis.__grclankerCursorJulyMockCalls ?? [];
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function fakeTool(overrides = {}) {
  const calls = [];
  const tool = {
    name: "fake_search_things",
    label: "Fake search",
    description: "Fake tool for adapter tests.",
    parameters: Type.Object({
      query: Type.String(),
      limit: Type.Optional(Type.Number({ default: 5 })),
    }),
    prepareArguments: (args) => (typeof args === "string" ? { query: args } : args),
    async execute(toolCallId, args) {
      calls.push({ toolCallId, args });
      return { content: [{ type: "text", text: `found ${args.query}` }], details: { count: 1 } };
    },
    ...overrides,
  };
  return { tool, calls };
}

test("agent sdk registry exposes every domain tool and excludes compute backend tools", () => {
  const tools = collectRegisteredGrcTools();
  const names = tools.map((tool) => tool.name);
  const expected = getRegisteredToolSummaries()
    .filter((tool) => tool.kind === "domain")
    .map((tool) => tool.name);

  assert.equal(tools.length, 107);
  assert.deepEqual(names, expected);
  assert.equal(new Set(names).size, names.length);
  for (const computeTool of COMPUTE_TOOL_NAMES) {
    assert.ok(!names.includes(computeTool), `${computeTool} must stay with the Cursor harness`);
  }
  for (const tool of tools) {
    assert.ok(tool.description.trim().length > 0, `${tool.name} needs a description`);
    assert.equal(typeof tool.execute, "function", `${tool.name} needs execute`);
    assert.equal(tool.parameters.type, "object", `${tool.name} needs an object schema`);
  }
  assert.equal(getRegisteredGrcTool("cmvp_search_modules").label, "Search FIPS Validated Modules");
  assert.throws(() => getRegisteredGrcTool("not_a_tool"), /Unknown grclanker tool "not_a_tool"/);
});

test("toJsonSchema strips TypeBox metadata and collapses literal unions to enum", () => {
  const schema = Type.Object({
    query: Type.String({ description: "Search term" }),
    section: Type.Optional(Type.Union([Type.Literal("process"), Type.Literal("ksi")])),
    limit: Type.Optional(Type.Number({ default: 10 })),
    tags: Type.Optional(Type.Array(Type.String())),
  });

  const json = toJsonSchema(schema);

  assert.equal(Object.getOwnPropertySymbols(json).length, 0);
  assert.equal(Object.getOwnPropertySymbols(json.properties.section).length, 0);
  assert.equal(json.type, "object");
  assert.deepEqual(json.required, ["query"]);
  assert.deepEqual(json.properties.query, { description: "Search term", type: "string" });
  assert.deepEqual(json.properties.section, { enum: ["process", "ksi"], type: "string" });
  assert.deepEqual(json.properties.limit, { default: 10, type: "number" });
  assert.deepEqual(json.properties.tags, { type: "array", items: { type: "string" } });
});

test("toJsonSchema keeps mixed unions, recurses into nested objects, and falls back to an empty object", () => {
  const json = toJsonSchema(
    Type.Object({
      installation_id: Type.Optional(Type.Union([Type.String(), Type.Integer()], { description: "id" })),
      nested: Type.Object({ mode: Type.Union([Type.Literal("a"), Type.Literal("b")]) }),
    }),
  );

  assert.deepEqual(json.properties.installation_id, {
    anyOf: [{ type: "string" }, { type: "integer" }],
    description: "id",
  });
  assert.deepEqual(json.properties.nested.properties.mode, { enum: ["a", "b"], type: "string" });
  assert.deepEqual(json.required, ["nested"]);
  assert.deepEqual(toJsonSchema(undefined), { type: "object", properties: {} });
  assert.deepEqual(toJsonSchema(Type.Object({})), { type: "object", properties: {} });
});

test("every registered tool converts to a plain object input schema without const literals", () => {
  for (const tool of collectRegisteredGrcTools()) {
    const schema = toJsonSchema(tool.parameters);
    const serialized = JSON.stringify(schema);

    assert.equal(schema.type, "object", tool.name);
    assert.equal(typeof schema.properties, "object", tool.name);
    assert.ok(!serialized.includes('"const"'), `${tool.name} still advertises const literals`);
    assert.deepEqual(JSON.parse(serialized), schema, `${tool.name} schema must be JSON-stable`);
  }
});

test("effect classification marks query tools read-only and lets write verbs win", () => {
  assert.equal(classifyGrcToolEffect("cmvp_search_modules"), "read");
  assert.equal(classifyGrcToolEffect("gws_ops_check_cli"), "read");
  assert.equal(classifyGrcToolEffect("kevs_recent"), "read");
  assert.equal(classifyGrcToolEffect("oscal_validate_model"), "read");
  assert.equal(classifyGrcToolEffect("okta_assess_identity"), "read");
  assert.equal(classifyGrcToolEffect("fedramp_plan_ads_package"), "read");
  assert.equal(classifyGrcToolEffect("aws_export_audit_bundle"), undefined);
  assert.equal(classifyGrcToolEffect("fedramp_generate_ads_site"), undefined);
  assert.equal(classifyGrcToolEffect("oscal_init_workspace"), undefined);
  assert.equal(classifyGrcToolEffect("future_check_and_export_bundle"), undefined);
  assert.equal(classifyGrcToolEffect("future_upload_report"), undefined);
  assert.equal(isGrcWriteTool("vanta_export_audit"), true);
  assert.equal(isGrcWriteTool("vanta_list_audits"), false);
});

test("every registered tool is classified in the expected direction", () => {
  const names = listRegisteredGrcToolNames();
  const undeclared = names.filter((name) => classifyGrcToolEffect(name) === undefined).sort();
  const read = names.filter((name) => classifyGrcToolEffect(name) === "read");

  assert.deepEqual(undeclared, EXPECTED_WRITE_TOOLS);
  assert.equal(read.length, names.length - EXPECTED_WRITE_TOOLS.length);
  for (const name of names) {
    if (WRITE_MARKER.test(name)) {
      assert.equal(classifyGrcToolEffect(name), undefined, `${name} writes and must stay undeclared`);
    } else {
      assert.equal(classifyGrcToolEffect(name), "read", `${name} reads and must declare effect: "read"`);
    }
  }
});

test("buildSdkToolConfig bridges prepareArguments, Pi argument validation, and the result envelope", async () => {
  const { tool, calls } = fakeTool();
  const config = buildSdkToolConfig(tool);

  assert.equal(config.description, tool.description);
  assert.equal(config.effect, "read");
  assert.deepEqual(config.inputSchema.required, ["query"]);
  assert.deepEqual(config.inputSchema.properties.limit, { default: 5, type: "number" });

  const result = await config.execute({ query: "openssl", limit: 3 }, { toolCallId: "call_1" });
  assert.deepEqual(result, { content: [{ type: "text", text: "found openssl" }] });

  const shimmed = await config.execute("boringssl", { toolCallId: "call_2" });
  assert.deepEqual(shimmed, { content: [{ type: "text", text: "found boringssl" }] });

  assert.deepEqual(calls, [
    { toolCallId: "call_1", args: { query: "openssl", limit: 3 } },
    { toolCallId: "call_2", args: { query: "boringssl" } },
  ]);

  // Pi validates TypeBox schemas without coercing primitives, so a string
  // where a number is declared is rejected before execute runs.
  const rejected = await config.execute({ query: "openssl", limit: "3" }, { toolCallId: "call_3" });
  assert.equal(rejected.isError, true);
  assert.match(rejected.content[0].text, /limit: must be number/);
  assert.equal(calls.length, 2);
});

test("executeGrcTool returns error envelopes for invalid arguments and thrown errors", async () => {
  const { tool, calls } = fakeTool();
  const invalid = await executeGrcTool(tool, { limit: 2 }, "call_2");

  assert.equal(invalid.isError, true);
  assert.match(invalid.content[0].text, /Validation failed for tool "fake_search_things"/);
  assert.match(invalid.content[0].text, /query/);
  assert.equal(calls.length, 0);

  const { tool: throwing } = fakeTool({
    async execute() {
      throw new Error("boom");
    },
  });
  const thrown = await executeGrcTool(throwing, { query: "x" }, "call_3");

  assert.deepEqual(thrown, {
    content: [{ type: "text", text: "fake_search_things failed: boom" }],
    isError: true,
  });
});

test("toSdkToolResult keeps text and image content, drops details, and carries isError", () => {
  assert.deepEqual(
    toSdkToolResult({
      content: [
        { type: "text", text: "hi", textSignature: "sig" },
        { type: "image", data: "abc", mimeType: "image/png" },
      ],
      details: { count: 1 },
    }),
    {
      content: [
        { type: "text", text: "hi" },
        { type: "image", data: "abc", mimeType: "image/png" },
      ],
    },
  );
  assert.deepEqual(toSdkToolResult({ content: [{ type: "text", text: "bad" }], details: {}, isError: true }), {
    content: [{ type: "text", text: "bad" }],
    isError: true,
  });
});

test("grclankerToolConfig runs a registered tool end to end with stubbed network access", async () => {
  const originalFetch = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (input) => {
    const url = String(input);
    urls.push(url);
    if (url.endsWith("/modules.json")) {
      return jsonResponse({
        metadata: { total_modules: 1 },
        modules: [
          {
            "Certificate Number": "4407",
            "Vendor Name": "Google, Inc.",
            "Module Name": "BoringCrypto",
            "Module Type": "Software",
            "Validation Date": "2023-01-01",
            standard: "FIPS 140-2",
            status: "Active",
            overall_level: 1,
          },
        ],
      });
    }
    throw new Error(`unexpected fetch ${url}`);
  };

  try {
    const config = grclankerToolConfig("cmvp_search_modules");
    const result = await config.execute({ query: "boringcrypto" }, { toolCallId: "call_cmvp" });

    assert.equal(result.isError, undefined);
    assert.match(result.content[0].text, /Found 1 active FIPS module\(s\) matching "boringcrypto"/);
    assert.match(result.content[0].text, /Certificate #4407 - BoringCrypto/);
    assert.equal(urls.length, 1);
  } finally {
    globalThis.fetch = originalFetch;
    clearGrcSharedCachesForTests();
  }
});

test("agent instructions compose SYSTEM.md with the Agent SDK runtime note", () => {
  const markdown = buildGrclankerInstructions();
  const systemPrompt = readFileSync(resolve(cliRoot, ".grclanker", "SYSTEM.md"), "utf8").trimEnd();

  assert.ok(markdown.startsWith(systemPrompt));
  assert.match(markdown, /## Cursor Agent SDK Runtime/);
  assert.match(markdown, /`investigate`, `audit`, `assess`, and `validate`/);
  assert.match(markdown, /`auditor` and `verifier` personas are available as subagents/);
});

test("workflow prompts and the bundled skill map onto skill configs", () => {
  assert.deepEqual([...WORKFLOW_NAMES], ["investigate", "audit", "assess", "validate"]);
  for (const name of WORKFLOW_NAMES) {
    const skill = workflowSkillConfig(name);
    assert.equal(skill.markdown, readFileSync(resolve(cliRoot, "prompts", `${name}.md`), "utf8").trim());
    assert.match(skill.description, /^Use when /);
  }

  const crypto = bundledSkillConfig("crypto-validation");
  assert.match(crypto.description, /^Validate cryptographic module FIPS compliance/);
  assert.match(crypto.markdown, /^# Cryptographic Module Validation/);

  assert.deepEqual(parseFrontmatter("---\nname: x\ndescription: a: b\n---\nbody\n"), {
    fields: { name: "x", description: "a: b" },
    body: "body\n",
  });
  assert.deepEqual(parseFrontmatter("plain"), { fields: {}, body: "plain" });
});

test("bundled personas become subagent configs with a description and inline instructions", () => {
  const auditor = personaAgentConfig("auditor");
  const verifier = personaAgentConfig("verifier");

  assert.match(auditor.description, /^Analyze evidence against compliance framework requirements/);
  assert.match(auditor.instructions, /^## Operating Principles/);
  assert.ok(!auditor.instructions.includes("Name: auditor"));
  assert.match(verifier.description, /^Validate findings, confirm evidence chains/);
  assert.throws(() => parsePersona("# no purpose"), /missing a Purpose: line/);
});

test("root agent config runs on the local harness and honors the model override", () => {
  assert.deepEqual(grclankerAgentConfig({}), {
    name: "grclanker",
    description: AGENT_DESCRIPTION,
    runtime: "local",
    model: undefined,
  });
  assert.equal(grclankerAgentConfig({ [MODEL_ENV_VAR]: " composer-2.5 " }).model, "composer-2.5");
  assert.equal(grclankerAgentConfig({ [MODEL_ENV_VAR]: "  " }).model, undefined);
});

test("agent/tools has exactly one generated entry per registered domain tool", async () => {
  const toolsDir = resolve(agentSdkRoot, "agent", "tools");
  const files = await listAgentSdkToolFiles(toolsDir);
  const names = [...listRegisteredGrcToolNames()].sort();

  assert.equal(files.length, 107);
  assert.deepEqual(files, names);
  for (const name of names) {
    const source = readFileSync(resolve(toolsDir, `${name}.ts`), "utf8");
    assert.equal(source, buildAgentSdkToolSource(name), `${name}.ts is stale; run npm run sync:agent-sdk-tools`);
  }
});

test("agent entry files hand the adapter configs to the mocked Agent SDK define helpers", async () => {
  const agent = (await importAgentEntry("agent.js")).default;
  assert.equal(agent.__agentServe, "agent");
  assert.equal(agent.__mockHelper, "defineAgent");
  assert.equal(agent.name, "grclanker");
  assert.equal(agent.runtime, "local");

  const instructions = (await importAgentEntry("instructions.js")).default;
  assert.equal(instructions.__agentServe, "instructions");
  assert.equal(instructions.markdown, buildGrclankerInstructions());

  const skill = (await importAgentEntry("skills", "investigate.js")).default;
  assert.equal(skill.__agentServe, "skill");
  assert.deepEqual({ description: skill.description, markdown: skill.markdown }, workflowSkillConfig("investigate"));

  const cryptoSkill = (await importAgentEntry("skills", "crypto-validation.js")).default;
  assert.equal(cryptoSkill.__agentServe, "skill");
  assert.equal(cryptoSkill.description, bundledSkillConfig("crypto-validation").description);

  const auditor = (await importAgentEntry("subagents", "auditor", "agent.js")).default;
  assert.equal(auditor.__agentServe, "agent");
  assert.deepEqual(
    { description: auditor.description, instructions: auditor.instructions },
    personaAgentConfig("auditor"),
  );

  const helpers = mockCalls().map((call) => call.helper);
  assert.ok(helpers.includes("defineAgent"));
  assert.ok(helpers.includes("defineInstructions"));
  assert.ok(helpers.includes("defineSkill"));
});

test("every generated tool entry registers a server tool for its filename", async () => {
  const before = mockCalls().filter((call) => call.helper === "defineTool").length;

  for (const name of listRegisteredGrcToolNames()) {
    const tool = (await importAgentEntry("tools", `${name}.js`)).default;
    const registered = getRegisteredGrcTool(name);

    assert.equal(tool.__agentServe, "tool", name);
    assert.equal(tool.__mockHelper, "defineTool", name);
    assert.equal(tool.description, registered.description, name);
    assert.equal(tool.execution, undefined, `${name} must stay a server tool`);
    assert.equal(tool.inputSchema.type, "object", name);
    assert.deepEqual(tool.inputSchema, toJsonSchema(registered.parameters), name);
    assert.equal(tool.effect, classifyGrcToolEffect(name), name);
    assert.equal(typeof tool.execute, "function", name);
  }

  const after = mockCalls().filter((call) => call.helper === "defineTool").length;
  assert.equal(after - before, 107);
});
