import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Type } from "@sinclair/typebox";
import * as v from "valibot";
import { init, useModel, useSandbox, useSkill, useSubagent, useTool } from "@flue/runtime";
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
 * Resolve the pi-ai copy `@flue/runtime` itself imports (nested or hoisted),
 * mirroring Node's own module walk, so the faux provider shares Flue's registry.
 */
async function importFluePiAi() {
  const flueDist = dirname(fileURLToPath(import.meta.resolve("@flue/runtime")));
  const candidates = [
    resolve(flueDist, "../node_modules/@earendil-works/pi-ai/dist/index.js"),
    resolve(flueDist, "../../../@earendil-works/pi-ai/dist/index.js"),
  ];
  const found = candidates.find((candidate) => existsSync(candidate));
  assert.ok(found, "pi-ai used by @flue/runtime should be resolvable");
  return import(pathToFileURL(found).href);
}

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

  const nullable = jsonSchemaToValibot({ type: ["string", "null"] });
  assert.equal(v.safeParse(nullable, null).success, true);
  assert.equal(v.safeParse(nullable, "x").success, true);
  assert.equal(v.safeParse(nullable, 1).success, false);

  assert.equal(jsonSchemaToValibot(undefined).type, "unknown");
  assert.equal(jsonSchemaToValibot({ type: "mystery" }).type, "unknown");
  assert.equal(jsonSchemaToValibot({ const: "fixed" }).type, "literal");

  assert.throws(() => jsonSchemaToToolInput(Type.String(), "bad"), /must be a JSON Schema object/);
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

test("bridged tools run prepareArguments then execute and return Flue envelopes", async () => {
  const { tool, executions } = createFakePiTool();
  const flueTool = toFlueTool(tool);
  const signal = new AbortController().signal;

  const result = await flueTool.run(fakeRunContext({ cve: "CVE-2024-3400" }, { toolCallId: "call-42", signal }));
  assert.deepEqual(result, { output: "probe saw CVE-2024-3400" });
  assert.equal(executions.length, 1);
  assert.equal(executions[0].toolCallId, "call-42");
  assert.equal(executions[0].signal, signal);
  assert.deepEqual(executions[0].params, { query: "CVE-2024-3400", limit: undefined });

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
  assert.throws(
    () => resolveFlueModel({}, { modelMode: "local", defaultProvider: "ollama", defaultModel: "gemma4" }),
    (error) => error instanceof GrclankerFlueConfigError && /ollama\/gemma4/.test(error.message) && /GRCLANKER_FLUE_MODEL/.test(error.message),
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
      // Flue validates against the converted schema before `run`, so `query` is required;
      // the extra alias key shows unknown keys still reach the Pi `prepareArguments` shim.
      return fauxAssistantMessage([fauxToolCall("kevs_probe", { query: "CVE-2024-3400", cve: "alias" })], {
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
  assert.deepEqual(probe.executions[0].params, { query: "CVE-2024-3400", limit: undefined });
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
