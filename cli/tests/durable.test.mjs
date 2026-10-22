import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Type } from "@sinclair/typebox";
import { copyJson, isJsonValue } from "@earendil-works/chord";
import { BACKGROUND_CONTEXT, withAbortSignal } from "@earendil-works/chord/context";
import { createModels } from "@earendil-works/pi-ai/models";
import { fauxAssistantMessage, fauxProvider, fauxText, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";
import { CURRENT_SQLITE_SCHEMA_VERSION } from "@earendil-works/pi-durable/storage/sqlite";

import { classifyGrcToolEffect, hasWriteVerb, WRITE_VERBS } from "../dist/agent-sdk/lib/effects.js";
import { readGrclankerSystemPrompt } from "../dist/agent-sdk/lib/instructions.js";
import { collectRegisteredGrcTools, getRegisteredGrcTool } from "../dist/agent-sdk/lib/registry.js";
import {
  DURABLE_EXPERIMENTAL_BANNER,
  exitCodeForDurableOutcome,
  formatDurableHelp,
  formatDurableReport,
  parseDurableArgs,
  runDurableCommand,
} from "../dist/durable/cli.js";
import { emptyAssessmentState, recordToolOutcome, renderAssessmentSummary } from "../dist/durable/document.js";
import { DurableUsageError, DurableUserError } from "../dist/durable/errors.js";
import { CIRCULAR_PLACEHOLDER, isJsonObject, toStrictJson } from "../dist/durable/json.js";
import { acquireSessionLock, DurableSessionLockedError } from "../dist/durable/lock.js";
import {
  assertModelAvailable,
  DURABLE_MODEL_ENV,
  formatModelRef,
  loadGrclankerModels,
  parseModelSpecifier,
  resolveDurableModelChoice,
} from "../dist/durable/models.js";
import {
  buildDurableSystemPrompt,
  createGrclankerDurableExtension,
  DURABLE_EXTENSION_NAME,
  DURABLE_RUNTIME_NOTE,
} from "../dist/durable/prompts.js";
import { durableReplayPolicy } from "../dist/durable/replay.js";
import { formatDurableActivity, runDurable } from "../dist/durable/run.js";
import {
  durableSessionExists,
  durableSessionsDir,
  isValidDurableSessionId,
  newDurableSessionId,
  resolveDurableSession,
} from "../dist/durable/session.js";
import { createDurableGrcTools, toDurableTool, toDurableToolResult, toolFailureResult } from "../dist/durable/tools.js";
import { ConfigFileError } from "../dist/extensions/grc-tools/hardening/config-file.js";
import { CLI_HELP } from "../dist/pi/cli-help.js";
import { routeCliInvocation } from "../dist/pi/cli-routing.js";

const cliRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

const MODEL = { provider: "faux", modelId: "faux-1" };
const READ_TOOL = "fakegrc_assess_controls";
const WRITE_TOOL = "fakegrc_export_bundle";
const SECRET = "pd_secret_value_0123456789";
// A registry tool that reads several PagerDuty datasets at once.
const ONCALL_TOOL = "pagerduty_assess_oncall_coverage";

function scratchDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-durable-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Point grclanker at a scratch home for the test, with no durable model in the environment. */
function useGrclankerHome(t) {
  const base = scratchDir(t);
  const saved = { GRCLANKER_HOME: process.env.GRCLANKER_HOME, [DURABLE_MODEL_ENV]: process.env[DURABLE_MODEL_ENV] };
  process.env.GRCLANKER_HOME = base;
  delete process.env[DURABLE_MODEL_ENV];
  t.after(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  return join(base, ".grclanker");
}

function captureIo() {
  const io = { out: [], err: [] };
  return { io, writer: { writeOut: (line) => io.out.push(line), writeErr: (line) => io.err.push(line) } };
}

function fakeTool(name, execute) {
  return toDurableTool({
    name,
    description: `Test tool ${name}.`,
    parameters: Type.Object({ output_dir: Type.Optional(Type.String()) }),
    execute,
  });
}

function readResult() {
  return {
    content: [{ type: "text", text: "2 controls assessed" }],
    details: {
      findings: [
        { id: "AC-1", status: "fail", severity: "high", title: "MFA is not enforced" },
        { id: "AC-2", status: "pass", severity: null, title: "Admins reviewed" },
      ],
      // Pi accepted details like these; the durable session store does not, so the adapter converts them.
      score: Number.NaN,
      total: 2n,
      checkedAt: new Date("2026-10-19T00:00:00Z"),
      skipped: undefined,
    },
  };
}

function writeResult(dir) {
  return {
    content: [{ type: "text", text: "bundle written" }],
    details: { output_dir: dir, zip_path: join(dir, "bundle.zip") },
  };
}

/** The prompt sections in effect: system messages declare them, and later ones replace or remove them by name. */
function promptSections(messages) {
  const sections = new Map();
  for (const message of messages) {
    if (message.role !== "system" || !message.sections) continue;
    for (const [name, text] of Object.entries(message.sections)) {
      if (text === null) sections.delete(name);
      else sections.set(name, text);
    }
  }
  return sections;
}

/** Pi's faux provider answering through `plan`, with a record of what each model call saw. */
function scriptedModel(plan) {
  const views = [];
  const faux = fauxProvider({ models: [{ id: MODEL.modelId }] });
  const respond = (context) => {
    const messages = context.messages;
    const lastUser = messages.findLastIndex((message) => message.role === "user");
    const view = {
      userMessages: messages.filter((message) => message.role === "user").length,
      toolResults: messages.slice(lastUser + 1).filter((message) => message.role === "toolResult"),
      sections: promptSections(messages),
    };
    views.push(view);
    return plan(view);
  };
  faux.setResponses(Array.from({ length: 50 }, () => respond));
  const models = createModels();
  models.setProvider(faux.provider);
  return { views, loadModels: async () => models };
}

/** The first request gets one round calling both tools, then a summary of their results; later requests get a summary. */
function toolRoundThenSummary(view) {
  if (view.userMessages === 1 && view.toolResults.length === 0) {
    return fauxAssistantMessage(
      [
        fauxToolCall(READ_TOOL, {}, { id: "call-read" }),
        fauxToolCall(WRITE_TOOL, { output_dir: "out" }, { id: "call-write" }),
      ],
      { stopReason: "toolUse" },
    );
  }
  const results = view.toolResults.map((result) => `${result.toolName}: ${result.isError ? "error" : "ok"}`).sort();
  return fauxAssistantMessage([fauxText(`answer ${view.userMessages}: ${results.join(", ") || "no tools"}`)]);
}

function byTool(report) {
  return Object.fromEntries(
    report.tools.map((tool) => [tool.tool, { callId: tool.callId, replay: tool.replay, status: tool.status }]),
  );
}

function withoutTimestamp(call) {
  const { recordedAt, ...rest } = call;
  assert.ok(Number.isFinite(Date.parse(recordedAt)), `recordedAt is a timestamp: ${recordedAt}`);
  return rest;
}

/** Replace fetch for the test with one whose requests settle only when their signal aborts, like a stalled API. */
function hangingFetch(t, onRequest = () => {}) {
  const saved = globalThis.fetch;
  const requests = [];
  globalThis.fetch = (input, init = {}) => {
    const signal = init.signal ?? (input instanceof Request ? input.signal : undefined);
    const request = { url: input instanceof Request ? input.url : String(input), signal };
    requests.push(request);
    onRequest(request);
    return new Promise((_, reject) => {
      if (signal?.aborted) reject(signal.reason);
      else signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
    });
  };
  t.after(() => {
    globalThis.fetch = saved;
  });
  return requests;
}

/** Run SQL on a session database outside Pi Durable, as another release or tool would. */
function editDatabase(path, ...statements) {
  const database = new DatabaseSync(path);
  try {
    for (const statement of statements) database.exec(statement);
  } finally {
    database.close();
  }
}

/** Fake PagerDuty arguments, with an empty config file so the operator's own config stays out of the test. */
function pagerdutyArgs(t) {
  const configFile = join(scratchDir(t), "pagerduty.json");
  writeFileSync(configFile, "{}\n");
  return { api_token: SECRET, region: "us", config_file: configFile };
}

/** A registry tool whose calls record the signal they got and the native promise they returned. */
function watchedRegistryTool(name) {
  const registered = getRegisteredGrcTool(name);
  const calls = [];
  const tool = {
    ...registered,
    execute: (callId, args, signal) => {
      const running = registered.execute(callId, args, signal);
      calls.push({ signal, running });
      return running;
    },
  };
  return { tool, calls };
}

async function waitUntil(predicate, description) {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, `timed out waiting for ${description}`);
    await sleep(5);
  }
}

/** How `promise` settles within `ms`: resolved with a value, rejected with an error, or still pending. */
async function settleWithin(promise, ms) {
  const timer = new AbortController();
  try {
    return await Promise.race([
      promise.then(
        (value) => ({ status: "resolved", value }),
        (error) => ({ status: "rejected", error }),
      ),
      sleep(ms, { status: "pending" }, { signal: timer.signal }),
    ]);
  } finally {
    timer.abort();
  }
}

test("replay policy is derived from the registry: read-only tools replay, writers and unclassified tools never do", () => {
  const registered = collectRegisteredGrcTools();
  const durable = createDurableGrcTools(registered);
  assert.ok(registered.length > 200, `the registry lists every domain tool (${registered.length})`);
  assert.deepEqual(
    durable.map((tool) => tool.name),
    registered.map((tool) => tool.name),
  );

  for (const [index, tool] of registered.entries()) {
    const expected = classifyGrcToolEffect(tool.name) === "read" ? "safe" : "unsafe";
    assert.equal(durable[index].replay, expected, tool.name);
    assert.equal(durableReplayPolicy(tool.name), expected, tool.name);
    if (hasWriteVerb(tool.name)) assert.equal(durable[index].replay, "unsafe", `${tool.name} has a write verb`);
    if (tool.name.includes("_export_")) assert.equal(durable[index].replay, "unsafe", `${tool.name} exports`);
  }

  const policies = new Set(durable.map((tool) => tool.replay));
  assert.deepEqual([...policies].sort(), ["safe", "unsafe"]);
  assert.equal(durableReplayPolicy("pagerduty_assess_access_control"), "safe");
  assert.equal(durableReplayPolicy("pagerduty_export_audit_bundle"), "unsafe");
});

test("a write verb blocks replay wherever it sits in the name, and a name with no known verb never replays", () => {
  for (const verb of WRITE_VERBS) {
    assert.equal(durableReplayPolicy(`demo_${verb}_report`), "unsafe", verb);
    assert.equal(durableReplayPolicy(`demo_assess_then_${verb}`), "unsafe", verb);
  }
  assert.equal(durableReplayPolicy("demo_assess_controls"), "safe");
  assert.equal(durableReplayPolicy("demo_frobnicate_controls"), "unsafe");
});

test("the session lock admits one holder at a time, and release is idempotent", (t) => {
  const path = join(scratchDir(t), "session.lock");
  const first = acquireSessionLock(path);
  assert.equal(first.path, path);
  assert.throws(
    () => acquireSessionLock(path),
    (error) => {
      assert.ok(error instanceof DurableSessionLockedError);
      assert.ok(error instanceof DurableUserError, "printed as a user error, without a stack");
      assert.equal(error.name, "DurableSessionLockedError");
      assert.equal(error.lockPath, path);
      assert.match(error.message, /^Another grclanker durable process is using this session\./);
      return true;
    },
  );
  first.release();
  first.release();
  acquireSessionLock(path).release();
});

test("a session lock held by a process killed with SIGKILL is free again at once", async (t) => {
  const path = join(scratchDir(t), "session.lock");
  const lockModule = pathToFileURL(join(cliRoot, "dist", "durable", "lock.js")).href;
  const holder = spawn(process.execPath, [
    "--input-type=module",
    "-e",
    [
      `import { acquireSessionLock } from ${JSON.stringify(lockModule)};`,
      `acquireSessionLock(${JSON.stringify(path)});`,
      `process.stdout.write("locked\\n");`,
      "setInterval(() => {}, 60_000);",
    ].join("\n"),
  ]);
  t.after(() => holder.kill("SIGKILL"));
  let stderr = "";
  holder.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
  const closed = new Promise((resolve) => holder.once("close", (_code, signal) => resolve(signal)));
  await new Promise((resolve, reject) => {
    holder.stdout.setEncoding("utf8").on("data", (chunk) => chunk.includes("locked") && resolve());
    holder.once("exit", (code) => reject(new Error(`the lock holder exited early (${code}): ${stderr}`)));
  });

  assert.throws(() => acquireSessionLock(path), DurableSessionLockedError);
  holder.kill("SIGKILL");
  assert.equal(await closed, "SIGKILL");
  acquireSessionLock(path).release();
});

test("toStrictJson matches JSON.parse(JSON.stringify(value)) wherever that works", () => {
  class Point {
    constructor() {
      this.x = 1;
      this.y = undefined;
    }
    get z() {
      return 3;
    }
  }
  const samples = [
    null,
    true,
    "text",
    0,
    -0,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    [1, undefined, () => 1, Symbol("s"), Number.NEGATIVE_INFINITY],
    { a: 1, b: undefined, c: () => 1, d: Symbol("s"), e: [], f: {} },
    new Date("2026-10-19T12:00:00Z"),
    new Map([["k", 1]]),
    new Set([1]),
    new Number(5),
    new String("ab"),
    new Boolean(false),
    Buffer.from("hi"),
    new Uint8Array([1, 2]),
    new Point(),
    { toJSON: () => ({ replaced: true }) },
    { nested: { toJSON: () => "inner" } },
    {
      self: {
        value: 1,
        toJSON() {
          return this;
        },
      },
    },
    Object.assign(() => 1, { toJSON: () => "a function with toJSON" }),
    [, 1], // eslint-disable-line no-sparse-arrays
  ];
  for (const sample of samples) {
    const text = JSON.stringify(sample);
    assert.deepEqual(toStrictJson(sample), JSON.parse(text), text);
  }
  for (const omitted of [undefined, () => 1, Symbol("s")]) assert.equal(toStrictJson(omitted), undefined);
});

test("toStrictJson keeps what JSON.stringify throws on or loses: bigints, cycles, and errors; and drops __proto__", () => {
  const cyclic = { name: "loop" };
  cyclic.self = cyclic;
  cyclic.list = [cyclic];
  assert.deepEqual(toStrictJson(cyclic), { name: "loop", self: CIRCULAR_PLACEHOLDER, list: [CIRCULAR_PLACEHOLDER] });
  const shared = { v: 1 };
  assert.deepEqual(toStrictJson({ a: shared, b: shared }), { a: { v: 1 }, b: { v: 1 } }, "a repeated object is not a cycle");
  const wrapsItself = {
    toJSON() {
      return { inner: wrapsItself };
    },
  };
  assert.deepEqual(toStrictJson(wrapsItself), { inner: CIRCULAR_PLACEHOLDER });
  const fnWrapsItself = Object.assign(() => 1, { toJSON: () => ({ fn: fnWrapsItself }) });
  assert.deepEqual(toStrictJson(fnWrapsItself), { fn: CIRCULAR_PLACEHOLDER });

  assert.equal(toStrictJson(12345678901234567890n), "12345678901234567890");
  assert.equal(toStrictJson(Object(7n)), "7");

  const error = new TypeError("bad input");
  error.code = "E_BAD";
  assert.deepEqual(toStrictJson({ error }), { error: { name: "TypeError", message: "bad input", code: "E_BAD" } });

  const clean = toStrictJson(JSON.parse('{"__proto__": {"admin": true}, "ok": 1}'));
  assert.deepEqual(clean, { ok: 1 });
  assert.equal(clean.admin, undefined);

  assert.equal(isJsonObject(clean), true);
  for (const value of [[], null, "x", 1, undefined]) assert.equal(isJsonObject(value), false);
});

test("the assessment document keys calls by call id and findings by domain, so a rerun overwrites instead of adding", () => {
  const state = emptyAssessmentState();
  assert.notEqual(emptyAssessmentState(), state, "each conversation starts from a fresh document");

  recordToolOutcome(state, {
    callId: "c1",
    tool: "okta_assess_mfa",
    replay: "safe",
    isError: false,
    recordedAt: "2026-10-19T00:00:00.000Z",
    details: {
      findings: [
        { id: "MFA-1", status: "fail", severity: "high", title: "Admins without MFA" },
        { id: "MFA-2", status: "pass" },
        { id: "", status: "fail" },
        { id: "MFA-3" },
        "not a finding",
      ],
    },
  });
  assert.deepEqual(state.calls.c1, {
    tool: "okta_assess_mfa",
    replay: "safe",
    status: "completed",
    findings: 2,
    recordedAt: "2026-10-19T00:00:00.000Z",
  });
  assert.deepEqual(Object.keys(state.findings), ["okta:MFA-1", "okta:MFA-2"]);
  assert.deepEqual(state.findings["okta:MFA-2"], {
    tool: "okta_assess_mfa",
    callId: "c1",
    status: "pass",
    severity: null,
    title: null,
  });

  recordToolOutcome(state, {
    callId: "c1",
    tool: "okta_assess_mfa",
    replay: "safe",
    isError: false,
    recordedAt: "2026-10-19T00:05:00.000Z",
    details: { findings: [{ id: "MFA-1", status: "pass" }] },
  });
  assert.deepEqual(Object.keys(state.calls), ["c1"]);
  assert.equal(state.calls.c1.recordedAt, "2026-10-19T00:05:00.000Z");
  assert.equal(state.calls.c1.findings, 1);
  assert.equal(state.findings["okta:MFA-1"].status, "pass");

  recordToolOutcome(state, {
    callId: "c2",
    tool: "okta_review_admins",
    replay: "safe",
    isError: false,
    recordedAt: "2026-10-19T00:06:00.000Z",
    details: { findings: [{ id: "MFA-1", status: "fail", severity: "medium" }] },
  });
  assert.deepEqual(state.findings["okta:MFA-1"], {
    tool: "okta_review_admins",
    callId: "c2",
    status: "fail",
    severity: "medium",
    title: null,
  });

  recordToolOutcome(state, {
    callId: "c3",
    tool: "okta_assess_policies",
    replay: "safe",
    isError: true,
    recordedAt: "2026-10-19T00:07:00.000Z",
    details: { findings: [{ id: "P-1", status: "fail" }], zip_path: "/tmp/ignored.zip" },
  });
  assert.equal(state.calls.c3.status, "error");
  assert.equal(state.calls.c3.findings, 0);
  assert.equal(state.findings["okta:P-1"], undefined, "an error result records no findings");

  recordToolOutcome(state, {
    callId: "c4",
    tool: "okta_export_audit_bundle",
    replay: "unsafe",
    isError: false,
    recordedAt: "2026-10-19T00:08:00.000Z",
    details: { zip_path: "/tmp/okta.zip", output_dir: "  " },
  });
  assert.deepEqual({ ...state.artifacts }, { c4: { tool: "okta_export_audit_bundle", zipPath: "/tmp/okta.zip", outputDir: null } });

  recordToolOutcome(state, {
    callId: "c5",
    tool: "okta_list_users",
    replay: "safe",
    isError: false,
    recordedAt: "2026-10-19T00:09:00.000Z",
    details: ["not", "an", "object"],
  });
  assert.equal(state.calls.c5.findings, 0);
});

test("the assessment summary stays short: counts, open findings only, and export paths", () => {
  assert.equal(renderAssessmentSummary(undefined), undefined);
  assert.equal(renderAssessmentSummary(emptyAssessmentState()), undefined);

  const state = emptyAssessmentState();
  const record = (callId, tool, isError, details) =>
    recordToolOutcome(state, { callId, tool, replay: durableReplayPolicy(tool), isError, details, recordedAt: "t" });
  record("c1", "aws_assess_iam", false, {
    findings: [
      { id: "IAM-1", status: "fail", severity: "high", title: "Root access keys exist" },
      { id: "IAM-2", status: "Passed", severity: "low", title: "Password policy" },
      { id: "IAM-3", status: "manual" },
    ],
  });
  record("c2", "aws_export_bundle", false, { output_dir: "/tmp/aws" });
  record("c3", "aws_check_access", true, undefined);
  assert.equal(
    renderAssessmentSummary(state),
    [
      "Recorded tool calls: 3 (completed 2, error 1).",
      "Findings: 3 (fail 1, manual 1, Passed 1).",
      "- aws:IAM-1: fail high Root access keys exist",
      "- aws:IAM-3: manual",
      "Exports: 1 (aws_export_bundle 1).",
      "- aws_export_bundle: /tmp/aws",
    ].join("\n"),
  );

  const many = emptyAssessmentState();
  recordToolOutcome(many, {
    callId: "c1",
    tool: "gws_assess_all",
    replay: "safe",
    isError: false,
    recordedAt: "t",
    details: { findings: Array.from({ length: 30 }, (_, index) => ({ id: `F-${index}`, status: "fail" })) },
  });
  const lines = renderAssessmentSummary(many).split("\n");
  assert.equal(lines.length, 2 + 25 + 1);
  assert.equal(lines.at(-1), "- ... 5 more not shown");
});

test("the assessment summary caps exports like findings: a count per tool and the ten most recent paths", () => {
  const toolFor = (index) => (index % 3 === 0 ? "okta_export_audit_bundle" : "aws_export_bundle");
  const exportsOf = (count) => {
    const state = emptyAssessmentState();
    for (let index = 0; index < count; index += 1) {
      recordToolOutcome(state, {
        callId: `c${index}`,
        tool: toolFor(index),
        replay: "unsafe",
        isError: false,
        recordedAt: "t",
        details: { zip_path: `/tmp/export-${index}.zip` },
      });
    }
    return renderAssessmentSummary(state).split("\n");
  };

  assert.deepEqual(exportsOf(30), [
    "Recorded tool calls: 30 (completed 30).",
    "Exports: 30 (aws_export_bundle 20, okta_export_audit_bundle 10).",
    ...Array.from({ length: 10 }, (_, offset) => `- ${toolFor(20 + offset)}: /tmp/export-${20 + offset}.zip`),
    "- ... 20 earlier exports not shown",
  ]);
  assert.equal(exportsOf(300).length, exportsOf(30).length, "a longer session adds no lines");
  assert.equal(exportsOf(10).at(-1), `- ${toolFor(9)}: /tmp/export-9.zip`, "ten exports are all listed");
});

test("the exports listed are the ten most recently recorded, even when integer-like call ids and reruns reorder the keys", () => {
  const state = emptyAssessmentState();
  const record = (callId, minute) =>
    recordToolOutcome(state, {
      callId,
      tool: "aws_export_bundle",
      replay: "unsafe",
      isError: false,
      recordedAt: new Date(Date.UTC(2026, 9, 19, 0, minute)).toISOString(),
      details: { zip_path: `/tmp/${callId}-at-${minute}.zip` },
    });
  for (let minute = 0; minute < 12; minute += 1) record(`call-${minute}`, minute);
  record("7", 12);
  record("call-0", 13);
  assert.deepEqual(Object.keys(state.artifacts).slice(0, 3), ["7", "call-0", "call-1"], "the two newest enumerate first");
  assert.deepEqual(renderAssessmentSummary(state).split("\n"), [
    "Recorded tool calls: 13 (completed 13).",
    "Exports: 13 (aws_export_bundle 13).",
    ...Array.from({ length: 8 }, (_, offset) => `- aws_export_bundle: /tmp/call-${4 + offset}-at-${4 + offset}.zip`),
    "- aws_export_bundle: /tmp/7-at-12.zip",
    "- aws_export_bundle: /tmp/call-0-at-13.zip",
    "- ... 3 earlier exports not shown",
  ]);
});

test("a model-chosen call id such as __proto__ is recorded as its own entry, and the state stays strict JSON", () => {
  const state = emptyAssessmentState();
  for (const callId of ["__proto__", "c2"]) {
    recordToolOutcome(state, {
      callId,
      tool: "aws_export_bundle",
      replay: "unsafe",
      isError: false,
      recordedAt: "t",
      details: { zip_path: `/tmp/${callId}.zip` },
    });
  }
  const call = { tool: "aws_export_bundle", replay: "unsafe", status: "completed", findings: 0, recordedAt: "t" };
  const artifact = (callId) => ({ tool: "aws_export_bundle", zipPath: `/tmp/${callId}.zip`, outputDir: null });
  assert.deepEqual(Object.keys(state.calls), ["__proto__", "c2"]);
  assert.deepEqual(Object.keys(state.artifacts), ["__proto__", "c2"]);
  assert.ok(isJsonValue(state), "Chord accepts the state as strict JSON");
  assert.deepEqual(JSON.parse(JSON.stringify(copyJson(state))), {
    calls: { ["__proto__"]: call, c2: call },
    findings: {},
    artifacts: { ["__proto__"]: artifact("__proto__"), c2: artifact("c2") },
  });
  assert.equal(
    renderAssessmentSummary(state),
    [
      "Recorded tool calls: 2 (completed 2).",
      "Exports: 2 (aws_export_bundle 2).",
      "- aws_export_bundle: /tmp/__proto__.zip",
      "- aws_export_bundle: /tmp/c2.zip",
    ].join("\n"),
  );
});

test("a __proto__ call id from the model stays in the runtime's report, summary, and stored document", async (t) => {
  const home = scratchDir(t);
  const session = resolveDurableSession("proto-call-id", home);
  const model = scriptedModel((view) => {
    if (view.toolResults.length > 0) return fauxAssistantMessage([fauxText(`answer ${view.userMessages}`)]);
    const [tool, id] = view.userMessages === 1 ? [READ_TOOL, "call-read"] : [WRITE_TOOL, "__proto__"];
    return fauxAssistantMessage([fauxToolCall(tool, {}, { id })], { stopReason: "toolUse" });
  });
  const deps = {
    loadModels: model.loadModels,
    tools: () => [fakeTool(READ_TOOL, async () => readResult()), fakeTool(WRITE_TOOL, async () => writeResult(home))],
  };
  const request = { command: "run", session, model: MODEL, message: "Assess.", requestId: "req-1" };
  await runDurable(request, deps);
  // The second request reopens the session, so the draft writes `__proto__` into a document reloaded as ordinary objects.
  const report = await runDurable({ ...request, message: "Export.", requestId: "req-2" }, deps);
  assert.deepEqual(byTool(report), { [WRITE_TOOL]: { callId: "__proto__", replay: "unsafe", status: "ok" } });
  assert.deepEqual(Object.keys(report.assessment.calls), ["call-read", "__proto__"]);
  assert.deepEqual(report.assessment.artifacts, {
    ["__proto__"]: { tool: WRITE_TOOL, zipPath: join(home, "bundle.zip"), outputDir: home },
  });
  const summary = model.views.at(-1).sections.get("assessment_state");
  assert.ok(summary.includes("Recorded tool calls: 2 (completed 2)."), summary);
  assert.ok(summary.includes(`- ${WRITE_TOOL}: ${join(home, "bundle.zip")}`), summary);

  const reopened = await runDurable({ command: "resume", session, model: MODEL }, deps);
  assert.equal(reopened.outcome, "nothing_to_resume");
  assert.deepEqual(reopened.assessment, report.assessment, "the stored document replays with the entry");
});

test("the tool adapter keeps the registry tool's name, schema, and argument repair, and adds the replay policy", () => {
  const parameters = Type.Object({ ids: Type.Array(Type.String()) });
  const native = {
    name: "fakegrc_list_users",
    description: "List users.",
    parameters,
    // Mutates its input, as some native repairs do.
    prepareArguments: (args) => {
      args.ids = [].concat(args.ids ?? []);
      return args;
    },
    execute: async () => ({ content: [] }),
  };
  const tool = toDurableTool(native);
  assert.equal(tool.name, native.name);
  assert.equal(tool.description, native.description);
  assert.equal(tool.parameters, parameters);
  assert.equal(tool.replay, "safe");

  const input = { ids: "U1" };
  assert.deepEqual(tool.prepareArguments(input), { ids: ["U1"] });
  assert.deepEqual(input, { ids: "U1" }, "the repair ran on a copy");

  const writer = toDurableTool({ ...native, name: "fakegrc_export_users", prepareArguments: undefined });
  assert.equal(writer.replay, "unsafe");
  assert.equal(writer.prepareArguments, undefined);
});

test("tool results become durable results with strict-JSON details", () => {
  const tool = { name: READ_TOOL, parameters: Type.Object({}) };
  const result = toDurableToolResult(tool, {}, {
    content: [
      { type: "text", text: "done" },
      { type: "image", data: "aGVsbG8=", mimeType: "image/png" },
    ],
    details: {
      score: Number.POSITIVE_INFINITY,
      total: 3n,
      when: new Date("2026-10-19T00:00:00Z"),
      skipped: undefined,
      nested: [undefined, Number.NaN],
    },
  });
  assert.deepEqual(result, {
    output: [
      { type: "text", text: "done" },
      { type: "image", data: "aGVsbG8=", mimeType: "image/png" },
    ],
    details: { score: null, total: "3", when: "2026-10-19T00:00:00.000Z", nested: [null, null] },
  });

  assert.deepEqual(toDurableToolResult(tool, {}, { content: [] }), { output: [] });
  assert.deepEqual(toDurableToolResult(tool, {}, { summary: "no content array" }), {
    output: [{ type: "text", text: '{"summary":"no content array"}' }],
  });
});

test("error results and thrown errors lose credential values before they reach the session", () => {
  const tool = { name: "fakegrc_check_access", parameters: Type.Object({ api_token: Type.String(), org: Type.String() }) };
  const args = { api_token: SECRET, org: "acme" };

  assert.deepEqual(
    toDurableToolResult(tool, args, {
      isError: true,
      content: [{ type: "text", text: `401 for token ${SECRET} in acme` }],
      details: { api_token: SECRET, status: 401 },
    }),
    {
      output: [{ type: "text", text: "401 for token [redacted] in acme" }],
      isError: true,
      details: { api_token: "[redacted]", status: 401 },
    },
  );
  assert.deepEqual(toDurableToolResult(tool, args, { isError: true, content: [] }), {
    output: [{ type: "text", text: "fakegrc_check_access failed without a message." }],
    isError: true,
  });
  assert.deepEqual(toolFailureResult(tool, args, new Error(`request with ${SECRET} timed out`)), {
    output: [{ type: "text", text: "fakegrc_check_access failed: request with [redacted] timed out" }],
    isError: true,
  });
});

test("the tool adapter passes the invocation's abort signal to the registry tool, so an abort cancels its requests and stops it", async (t) => {
  const requests = hangingFetch(t);
  const { tool, calls } = watchedRegistryTool(ONCALL_TOOL);
  const commits = [];
  const api = { callId: "call-oncall", conversationId: "conversation", commit: async () => commits.push("commit") };
  const controller = new AbortController();
  const context = withAbortSignal(controller.signal, BACKGROUND_CONTEXT);

  const invocation = toDurableTool(tool).execute(pagerdutyArgs(t), api, context);
  await waitUntil(() => requests.length > 0, "the assessment's first request");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].signal, context.abortSignal, "the registry tool runs with the invocation's signal");

  const reason = new Error("the harness closed");
  controller.abort(reason);
  await assert.rejects(invocation, (error) => error === reason);
  const native = await settleWithin(calls[0].running, 1000);
  assert.equal(native.status, "rejected", "the registry tool stopped instead of running on after the invocation ended");
  assert.equal(native.error, reason);
  assert.ok(requests.every((request) => request.signal?.aborted), "every request in flight saw the abort");
  assert.deepEqual(commits, [], "an aborted call records nothing");

  const refused = watchedRegistryTool(ONCALL_TOOL);
  const cancelled = withAbortSignal(AbortSignal.abort(reason), BACKGROUND_CONTEXT);
  await assert.rejects(toDurableTool(refused.tool).execute(pagerdutyArgs(t), api, cancelled), (error) => error === reason);
  assert.equal(refused.calls.length, 0, "a cancelled invocation never starts the tool");
});

test("the durable extension carries every registry tool and the grclanker prompt with the durable runtime note", () => {
  const prompt = buildDurableSystemPrompt();
  assert.ok(prompt.startsWith(readGrclankerSystemPrompt()));
  assert.ok(prompt.endsWith(DURABLE_RUNTIME_NOTE));
  assert.match(DURABLE_RUNTIME_NOTE, /^## Durable Runtime \(experimental\)\n/);

  const extension = createGrclankerDurableExtension();
  assert.equal(extension.name, DURABLE_EXTENSION_NAME);
  assert.deepEqual(
    extension.tools.map((tool) => tool.name),
    collectRegisteredGrcTools().map((tool) => tool.name),
  );
  assert.deepEqual(
    extension.sections.map((section) => [section.key, section.tag]),
    [
      ["grclanker", false],
      ["assessment_state", undefined],
    ],
  );
});

test("session ids are single path segments, and sessions live under the grclanker home", (t) => {
  for (const id of ["a", "crash-run", "2026.10.19_run-1", "A".repeat(64), newDurableSessionId()]) {
    assert.equal(isValidDurableSessionId(id), true, id);
  }
  for (const id of ["", ".", "..", "../x", "a/b", "a\\b", "-x", ".hidden", "_x", "A".repeat(65), "with space", "caf\u00e9"]) {
    assert.equal(isValidDurableSessionId(id), false, id);
    assert.throws(() => resolveDurableSession(id, "/srv/grclanker"), DurableUsageError, id);
  }

  const base = resolve("/srv/grclanker");
  assert.equal(durableSessionsDir(base), resolve(base, "durable", "sessions"));
  assert.deepEqual(resolveDurableSession("crash-run", base), {
    id: "crash-run",
    dir: resolve(base, "durable", "sessions", "crash-run"),
    database: resolve(base, "durable", "sessions", "crash-run", "session.sqlite"),
    lock: resolve(base, "durable", "sessions", "crash-run", "session.lock"),
  });
  assert.match(newDurableSessionId(new Date("2026-10-19T14:30:12.345Z")), /^20261019-143012-[0-9a-f]{6}$/);

  const session = resolveDurableSession("fresh", scratchDir(t));
  assert.equal(durableSessionExists(session), false);
  mkdirSync(session.dir, { recursive: true });
  writeFileSync(session.database, "");
  assert.equal(durableSessionExists(session), true);
});

test("the durable model comes from --model, then GRCLANKER_DURABLE_MODEL, then the grclanker setup choice", () => {
  const settings = { defaultProvider: "anthropic", defaultModel: "claude-sonnet-4-6", defaultThinkingLevel: "high" };
  assert.deepEqual(resolveDurableModelChoice({ flag: "openai/gpt-5", env: { [DURABLE_MODEL_ENV]: "faux/faux-1" }, settings }), {
    model: { provider: "openai", modelId: "gpt-5" },
    thinkingLevel: "high",
  });
  assert.deepEqual(resolveDurableModelChoice({ env: { [DURABLE_MODEL_ENV]: " faux/faux-1 " }, settings }), {
    model: MODEL,
    thinkingLevel: "high",
  });
  assert.deepEqual(
    resolveDurableModelChoice({ env: { [DURABLE_MODEL_ENV]: "  " }, settings: { ...settings, defaultThinkingLevel: "turbo" } }),
    { model: { provider: "anthropic", modelId: "claude-sonnet-4-6" } },
  );
  assert.throws(
    () => resolveDurableModelChoice({ env: {}, settings: { defaultProvider: "anthropic" } }),
    (error) => error instanceof DurableUserError && error.message.includes(DURABLE_MODEL_ENV),
  );
  assert.throws(() => resolveDurableModelChoice({ flag: "gpt-5", env: {}, settings }), {
    name: "DurableUserError",
    message: '--model must look like <provider>/<model>, for example anthropic/claude-sonnet-4-6 (got "gpt-5").',
  });

  assert.deepEqual(parseModelSpecifier("openrouter/meta-llama/llama-4", "--model"), {
    provider: "openrouter",
    modelId: "meta-llama/llama-4",
  });
  for (const bad of ["", "faux", "/faux-1", "faux/", "  /  "]) {
    assert.throws(() => parseModelSpecifier(bad, DURABLE_MODEL_ENV), new RegExp(`${DURABLE_MODEL_ENV} must look like`), bad);
  }
  assert.equal(formatModelRef(MODEL), "faux/faux-1");
});

test("model access reads grclanker's models.json without echoing a malformed one, and rejects unknown models", async (t) => {
  const agentDir = scratchDir(t);
  const models = await loadGrclankerModels(agentDir);
  assert.throws(() => assertModelAvailable(models, { provider: "nope", modelId: "x" }), {
    name: "DurableUserError",
    message: "Unknown model nope/x. Check the provider and model id, or rerun grclanker setup.",
  });

  const faux = await scriptedModel(() => fauxAssistantMessage("unused")).loadModels();
  assertModelAvailable(faux, MODEL);
  assert.throws(() => assertModelAvailable(faux, { provider: "faux", modelId: "faux-2" }), /Unknown model faux\/faux-2\./);

  writeFileSync(join(agentDir, "models.json"), `{"providers": {"custom": {"apiKey": "${SECRET}",`);
  await assert.rejects(loadGrclankerModels(agentDir), (error) => {
    assert.ok(error instanceof ConfigFileError);
    assert.match(error.message, /models\.json/);
    assert.equal(error.message.includes(SECRET), false, "the malformed file's content is not echoed");
    return true;
  });
});

test("durable arguments: run needs a message, resume needs a session and takes no message", () => {
  assert.deepEqual(
    parseDurableArgs("run", ["-m", "Assess Okta", "--session", "s1", "--request-id", "r1", "--model", "faux/faux-1", "--json"]),
    { command: "run", message: "Assess Okta", session: "s1", requestId: "r1", model: "faux/faux-1", json: true },
  );
  assert.deepEqual(parseDurableArgs("resume", ["--session", "s1"]), { command: "resume", session: "s1", json: false });

  const resumeTakesNoMessage =
    "'grclanker durable resume' takes no message. Use 'grclanker durable run --session <id> --message <text>' to continue a session.";
  const cases = [
    ["run", [], "'grclanker durable run' requires --message <text>."],
    ["run", ["--message", "   "], "'grclanker durable run' requires --message <text>."],
    ["run", ["--message"], "--message requires a value."],
    ["run", ["--message", "--json"], "--message requires a value."],
    ["run", ["-m", "x", "--request-id", "  "], "--request-id must not be empty."],
    ["run", ["-m", "x", "--verbose"], "Unknown option for 'grclanker durable run': --verbose"],
    ["run", ["-m", "x", "stray"], "Unknown option for 'grclanker durable run': stray"],
    ["resume", [], "'grclanker durable resume' requires --session <id>."],
    ["resume", ["--session", "s1", "-m", "more"], resumeTakesNoMessage],
    ["resume", ["--session", "s1", "--request-id", "r1"], resumeTakesNoMessage],
  ];
  for (const [command, argv, message] of cases) {
    assert.throws(() => parseDurableArgs(command, argv), (error) => error instanceof DurableUsageError && error.message === message, argv.join(" "));
  }
});

test("help, exit codes, and reports label the durable mode experimental and point at resume", () => {
  const help = formatDurableHelp();
  assert.equal(DURABLE_EXPERIMENTAL_BANNER, "grclanker durable (experimental)");
  assert.ok(help.startsWith(`${DURABLE_EXPERIMENTAL_BANNER}\n`));
  assert.match(help, /^Experimental: the commands, output, and session format may change between releases\.$/m);
  assert.match(help, /^ {2}grclanker durable run --message <text>/m);
  assert.match(help, /^ {2}grclanker durable resume --session <id>/m);
  assert.match(CLI_HELP, /grclanker durable run -m <text>\n\s+Experimental:/);
  assert.match(CLI_HELP, /grclanker durable resume --session <id>\n\s+Experimental:/);

  assert.equal(exitCodeForDurableOutcome("completed"), 0);
  assert.equal(exitCodeForDurableOutcome("nothing_to_resume"), 0);
  assert.equal(exitCodeForDurableOutcome("unanswered"), 1);
  assert.equal(exitCodeForDurableOutcome("interrupted"), 130);

  const report = {
    experimental: true,
    command: "run",
    session: "s1",
    sessionDir: "/tmp/s1",
    conversationId: 1,
    model: "faux/faux-1",
    requestId: "r1",
    submissionId: 1,
    outcome: "completed",
    answer: "All good.",
    tools: [
      { callId: "a", tool: READ_TOOL, replay: "safe", status: "ok" },
      { callId: "b", tool: WRITE_TOOL, replay: "unsafe", status: "interrupted" },
    ],
    assessment: emptyAssessmentState(),
  };
  assert.deepEqual(formatDurableReport(report, true), { out: [JSON.stringify(report)], err: [] });
  assert.deepEqual(formatDurableReport(report, false), {
    out: ["All good."],
    err: [`Interrupted and not rerun: ${WRITE_TOOL}. Check what they wrote before running them again.`],
  });
  assert.deepEqual(formatDurableReport({ ...report, outcome: "nothing_to_resume", answer: undefined, tools: [] }, false), {
    out: [],
    err: ["Nothing to resume: every request in session s1 has settled."],
  });
});

test("activity lines cover resumed tool rounds, top-level tool starts, retries, failures, and compaction", () => {
  assert.equal(formatDurableActivity({ type: "snapshot", tools: [] }), undefined);
  assert.equal(formatDurableActivity({ type: "snapshot", tools: [{ name: READ_TOOL, status: "done" }] }), undefined);
  assert.equal(
    formatDurableActivity({
      type: "snapshot",
      tools: [
        { name: READ_TOOL, status: "done" },
        { name: WRITE_TOOL, status: "running" },
      ],
    }),
    `resuming a tool round left by an earlier process: 1 finished and kept, unfinished: ${WRITE_TOOL}`,
  );
  assert.equal(formatDurableActivity({ type: "tool_execution_start", toolName: READ_TOOL }), `-> ${READ_TOOL}`);
  assert.equal(formatDurableActivity({ type: "tool_execution_start", toolName: READ_TOOL, parentToolCallId: "p" }), undefined);
  assert.equal(
    formatDurableActivity({ type: "tool_execution_end", toolName: READ_TOOL, entry: undefined }),
    `<- ${READ_TOOL} ended without a result`,
  );
  assert.equal(
    formatDurableActivity({ type: "auto_retry_start", attempt: 2, errorMessage: `overloaded\n\n${"x".repeat(300)}` }),
    `model request failed, retry 2: overloaded ${"x".repeat(186)}...`,
  );
  assert.equal(formatDurableActivity({ type: "task_failed", kind: "tool", message: "boom" }), "task tool failed: boom");
  assert.equal(formatDurableActivity({ type: "compaction_start", reason: "threshold" }), "compacting the conversation (threshold)");
  for (const type of ["run_start", "turn_end", "message_update", "entry_appended", "usage_changed"]) {
    assert.equal(formatDurableActivity({ type }), undefined, type);
  }
});

test("runDurable answers a request, records the assessment, and continues the same conversation on the next run", async (t) => {
  const home = scratchDir(t);
  const exportDir = join(home, "exports");
  const session = resolveDurableSession("in-process", home);
  const model = scriptedModel(toolRoundThenSummary);
  const executions = { read: 0, write: 0 };
  const deps = {
    loadModels: model.loadModels,
    tools: () => [
      fakeTool(READ_TOOL, async () => {
        executions.read += 1;
        return readResult();
      }),
      fakeTool(WRITE_TOOL, async () => {
        executions.write += 1;
        return writeResult(exportDir);
      }),
    ],
  };
  const request = { command: "run", session, model: MODEL, message: "Assess and export.", requestId: "req-1" };

  const first = await runDurable(request, deps);
  assert.equal(first.experimental, true);
  assert.equal(first.command, "run");
  assert.equal(first.session, "in-process");
  assert.equal(first.sessionDir, session.dir);
  assert.equal(first.model, "faux/faux-1");
  assert.equal(first.requestId, "req-1");
  assert.equal(first.outcome, "completed");
  assert.equal(first.answer, `answer 1: ${READ_TOOL}: ok, ${WRITE_TOOL}: ok`);
  assert.deepEqual(byTool(first), {
    [READ_TOOL]: { callId: "call-read", replay: "safe", status: "ok" },
    [WRITE_TOOL]: { callId: "call-write", replay: "unsafe", status: "ok" },
  });
  assert.deepEqual(executions, { read: 1, write: 1 });
  assert.ok(durableSessionExists(session));

  const { calls, findings, artifacts } = first.assessment;
  assert.deepEqual(withoutTimestamp(calls["call-read"]), { tool: READ_TOOL, replay: "safe", status: "completed", findings: 2 });
  assert.deepEqual(withoutTimestamp(calls["call-write"]), { tool: WRITE_TOOL, replay: "unsafe", status: "completed", findings: 0 });
  assert.deepEqual(findings, {
    "fakegrc:AC-1": { tool: READ_TOOL, callId: "call-read", status: "fail", severity: "high", title: "MFA is not enforced" },
    "fakegrc:AC-2": { tool: READ_TOOL, callId: "call-read", status: "pass", severity: null, title: "Admins reviewed" },
  });
  assert.deepEqual(artifacts, {
    "call-write": { tool: WRITE_TOOL, zipPath: join(exportDir, "bundle.zip"), outputDir: exportDir },
  });

  const [toolRound, answerRound] = model.views;
  assert.ok(toolRound.sections.get("grclanker").includes(readGrclankerSystemPrompt()));
  assert.ok(toolRound.sections.get("grclanker").includes(DURABLE_RUNTIME_NOTE));
  assert.equal(toolRound.sections.has("assessment_state"), false, "nothing is recorded before the first tool round");
  const state = answerRound.sections.get("assessment_state");
  assert.ok(state.includes("Recorded tool calls: 2 (completed 2)."), state);
  assert.ok(state.includes("- fakegrc:AC-1: fail high MFA is not enforced"), state);
  assert.equal(state.includes("fakegrc:AC-2"), false, "passing findings are counted, not listed");

  const second = await runDurable({ ...request, message: "What is still open?", requestId: "req-2" }, deps);
  assert.equal(second.outcome, "completed");
  assert.equal(second.conversationId, first.conversationId);
  assert.notEqual(second.submissionId, first.submissionId);
  assert.equal(second.answer, "answer 2: no tools");
  assert.deepEqual(second.tools, []);
  assert.deepEqual(second.assessment, first.assessment);
  assert.equal(model.views[2].userMessages, 2, "the second request sees the first one");
  assert.ok(model.views[2].sections.get("assessment_state").includes("Recorded tool calls: 2"));

  const idle = await runDurable({ command: "resume", session, model: MODEL }, deps);
  assert.equal(idle.outcome, "nothing_to_resume");
  assert.equal(idle.requestId, undefined);
  assert.deepEqual(idle.tools, []);
  assert.deepEqual(idle.assessment, first.assessment);

  const replayed = await runDurable(request, deps);
  assert.equal(replayed.submissionId, first.submissionId);
  assert.equal(replayed.answer, first.answer);
  assert.deepEqual(replayed.tools, first.tools);
  assert.equal(model.views.length, 3, "settled requests ask the model nothing");
  assert.deepEqual(executions, { read: 1, write: 1 });
});

test("an aborted run keeps its tool round for resume: the read-only tool reruns, the writer is reported and not rerun", async (t) => {
  const home = scratchDir(t);
  const session = resolveDurableSession("aborted", home);
  const model = scriptedModel(toolRoundThenSummary);
  const firstRun = { read: 0, write: 0 };
  const controller = new AbortController();
  const lines = [];

  const aborted = await runDurable(
    { command: "run", session, model: MODEL, message: "Assess and export.", requestId: "req-1" },
    {
      loadModels: model.loadModels,
      tools: () => [
        // Never settle, like calls still waiting on an API when the operator presses Ctrl-C.
        fakeTool(READ_TOOL, () => {
          firstRun.read += 1;
          return new Promise(() => {});
        }),
        fakeTool(WRITE_TOOL, () => {
          firstRun.write += 1;
          return new Promise(() => {});
        }),
      ],
      signal: controller.signal,
      onActivity: (line) => {
        lines.push(line);
        if (lines.includes(`-> ${READ_TOOL}`) && lines.includes(`-> ${WRITE_TOOL}`)) controller.abort();
      },
    },
  );
  assert.equal(aborted.outcome, "interrupted");
  assert.equal(aborted.requestId, "req-1");
  assert.deepEqual(aborted.tools, []);
  assert.deepEqual(aborted.assessment, emptyAssessmentState());
  assert.deepEqual(firstRun, { read: 1, write: 1 });
  assert.deepEqual(formatDurableReport(aborted, false), {
    out: [],
    err: ["Stopped. The session keeps its unfinished work: grclanker durable resume --session aborted"],
  });

  const secondRun = { read: 0, write: 0 };
  const resumedLines = [];
  const resumed = await runDurable(
    { command: "resume", session, model: MODEL },
    {
      loadModels: model.loadModels,
      tools: () => [
        fakeTool(READ_TOOL, async () => {
          secondRun.read += 1;
          return readResult();
        }),
        fakeTool(WRITE_TOOL, async () => {
          secondRun.write += 1;
          return writeResult(home);
        }),
      ],
      onActivity: (line) => resumedLines.push(line),
    },
  );
  assert.equal(resumed.outcome, "completed");
  assert.equal(resumed.requestId, "req-1");
  assert.deepEqual(secondRun, { read: 1, write: 0 });
  assert.deepEqual(byTool(resumed), {
    [READ_TOOL]: { callId: "call-read", replay: "safe", status: "ok" },
    [WRITE_TOOL]: { callId: "call-write", replay: "unsafe", status: "interrupted" },
  });
  assert.equal(resumed.answer, `answer 1: ${READ_TOOL}: ok, ${WRITE_TOOL}: error`);
  assert.deepEqual(Object.keys(resumed.assessment.calls), ["call-read"], "the writer recorded nothing");
  for (const line of [
    `resuming a tool round left by an earlier process: 0 finished and kept, unfinished: ${READ_TOOL}, ${WRITE_TOOL}`,
    `<- ${READ_TOOL} ok`,
    `<- ${WRITE_TOOL} interrupted; not rerun because it can write`,
  ]) {
    assert.ok(resumedLines.includes(line), `${line}\n${resumedLines.join("\n")}`);
  }
});

test("stopping a run aborts the registry tools still waiting on an API, so none keeps running after runDurable returns", async (t) => {
  const controller = new AbortController();
  const requests = hangingFetch(t, () => setImmediate(() => controller.abort()));
  const { tool, calls } = watchedRegistryTool(ONCALL_TOOL);
  const args = pagerdutyArgs(t);
  const model = scriptedModel((view) =>
    view.toolResults.length === 0
      ? fauxAssistantMessage([fauxToolCall(ONCALL_TOOL, args, { id: "call-oncall" })], { stopReason: "toolUse" })
      : fauxAssistantMessage([fauxText("done")]),
  );

  const report = await runDurable(
    { command: "run", session: resolveDurableSession("stopped", scratchDir(t)), model: MODEL, message: "Check on-call.", requestId: "r" },
    { loadModels: model.loadModels, tools: () => [toDurableTool(tool)], signal: controller.signal },
  );
  assert.equal(report.outcome, "interrupted");
  assert.equal(calls.length, 1);
  const native = await settleWithin(calls[0].running, 1000);
  assert.equal(native.status, "rejected", "the registry tool stopped with the run instead of running on");
  assert.ok(requests.length > 0, "the tool was waiting on its requests when the run stopped");
  assert.ok(requests.every((request) => request.signal?.aborted), "every request in flight saw the abort");
});

test("a tool that throws becomes a redacted error result, recorded as an error in the assessment", async (t) => {
  const tool = "fakegrc_check_access";
  const model = scriptedModel((view) =>
    view.toolResults.length === 0
      ? fauxAssistantMessage([fauxToolCall(tool, { api_token: SECRET }, { id: "call-check" })], { stopReason: "toolUse" })
      : fauxAssistantMessage([fauxText(view.toolResults[0].content.map((block) => block.text).join(""))]),
  );
  const throwing = toDurableTool({
    name: tool,
    description: "Check access.",
    parameters: Type.Object({ api_token: Type.String() }),
    execute: async (_callId, args) => {
      throw new Error(`token ${args.api_token} was rejected`);
    },
  });

  const report = await runDurable(
    { command: "run", session: resolveDurableSession("throws", scratchDir(t)), model: MODEL, message: "Check.", requestId: "r" },
    { loadModels: model.loadModels, tools: () => [throwing] },
  );
  assert.equal(report.outcome, "completed");
  assert.equal(report.answer, `${tool} failed: token [redacted] was rejected`);
  assert.deepEqual(byTool(report), { [tool]: { callId: "call-check", replay: "safe", status: "error" } });
  assert.deepEqual(withoutTimestamp(report.assessment.calls["call-check"]), { tool, replay: "safe", status: "error", findings: 0 });
});

test("a request the model cannot answer settles as unanswered, with the reason", async (t) => {
  const model = scriptedModel(() => fauxAssistantMessage("", { stopReason: "error", errorMessage: "upstream returned 500" }));
  const report = await runDurable(
    { command: "run", session: resolveDurableSession("unanswered", scratchDir(t)), model: MODEL, message: "hi", requestId: "r" },
    { loadModels: model.loadModels, tools: () => [], settings: { retry: { enabled: false } } },
  );
  assert.equal(report.outcome, "unanswered");
  assert.equal(report.reason, "model_error: upstream returned 500");
  assert.equal(report.answer, undefined);
  assert.equal(exitCodeForDurableOutcome(report.outcome), 1);
  assert.deepEqual(formatDurableReport(report, false), {
    out: [],
    err: ["The request settled without an answer: model_error: upstream returned 500"],
  });
});

test("runDurable checks the model and the session lock before it opens the session", async (t) => {
  const home = scratchDir(t);
  const model = scriptedModel(() => fauxAssistantMessage("done"));
  const deps = { loadModels: model.loadModels, tools: () => [] };
  const request = (session, ref = MODEL) => ({ command: "run", session, model: ref, message: "hi", requestId: "r" });

  const unknown = resolveDurableSession("unknown-model", home);
  await assert.rejects(runDurable(request(unknown, { provider: "faux", modelId: "missing" }), deps), {
    name: "DurableUserError",
    message: "Unknown model faux/missing. Check the provider and model id, or rerun grclanker setup.",
  });
  assert.equal(existsSync(unknown.dir), false, "nothing was created for a command that cannot run");

  const locked = resolveDurableSession("locked", home);
  mkdirSync(locked.dir, { recursive: true });
  const holder = acquireSessionLock(locked.lock);
  t.after(() => holder.release());
  await assert.rejects(
    runDurable(request(locked), deps),
    (error) => error instanceof DurableSessionLockedError && error.lockPath === locked.lock,
  );
  assert.equal(existsSync(locked.database), false, "the session database was never opened");
  assert.equal(model.views.length, 0);

  holder.release();
  const report = await runDurable(request(locked), deps);
  assert.equal(report.outcome, "completed");
  assert.equal(report.answer, "done");
});

test("grclanker durable prints help, and reports usage and configuration problems with exit code 1", async (t) => {
  const home = useGrclankerHome(t);
  for (const argv of [[], ["--help"], ["-h"], ["run", "--help"], ["resume", "--session", "x", "-h"]]) {
    const { io, writer } = captureIo();
    assert.equal(await runDurableCommand(argv, writer), 0, argv.join(" "));
    assert.deepEqual(io, { out: [formatDurableHelp()], err: [] }, argv.join(" "));
  }

  const helpPointer = "Run 'grclanker durable --help' for usage.";
  const cases = [
    [["start"], ["Unknown durable subcommand: start", helpPointer]],
    [["run"], ["'grclanker durable run' requires --message <text>.", helpPointer]],
    [
      ["run", "-m", "hi", "--model", "faux/faux-1", "--session", "../escape"],
      [
        'Invalid session id "../escape": use up to 64 letters, digits, dots, dashes, or underscores, starting with a letter or digit.',
        helpPointer,
      ],
    ],
    [
      ["run", "-m", "hi"],
      [`No model is configured. Run grclanker setup, or pass --model <provider>/<model> (or set ${DURABLE_MODEL_ENV}).`],
    ],
    [["resume", "--session", "missing", "--model", "faux/faux-1"], [`No durable session "missing" in ${durableSessionsDir(home)}.`]],
  ];
  for (const [argv, err] of cases) {
    const { io, writer } = captureIo();
    assert.equal(await runDurableCommand(argv, writer), 1, argv.join(" "));
    assert.deepEqual(io, { out: [], err }, argv.join(" "));
  }

  mkdirSync(join(home, "agent"), { recursive: true });
  writeFileSync(join(home, "agent", "settings.json"), '{"defaultProvider": "faux", ');
  const { io, writer } = captureIo();
  assert.equal(await runDurableCommand(["run", "-m", "hi"], writer), 1);
  assert.equal(io.err.length, 1, io.err.join("\n"));
  assert.match(io.err[0], /settings\.json/);
});

test("grclanker durable run and resume print the answer or a JSON report, with progress on stderr", async (t) => {
  const home = useGrclankerHome(t);
  const model = scriptedModel(toolRoundThenSummary);
  const deps = {
    loadModels: model.loadModels,
    tools: () => [fakeTool(READ_TOOL, async () => readResult()), fakeTool(WRITE_TOOL, async () => writeResult(home))],
  };
  const session = resolveDurableSession("cli-session", home);
  const runArgs = ["run", "--session", session.id, "--request-id", "req-1", "--model", "faux/faux-1", "-m", "Assess and export."];
  const sigintListeners = process.listenerCount("SIGINT");

  const text = captureIo();
  assert.equal(await runDurableCommand(runArgs, text.writer, deps), 0, text.io.err.join("\n"));
  assert.deepEqual(text.io.out, [`answer 1: ${READ_TOOL}: ok, ${WRITE_TOOL}: ok`]);
  assert.deepEqual(text.io.err.slice(0, 3), [DURABLE_EXPERIMENTAL_BANNER, `session ${session.id} (${session.dir})`, "request req-1"]);
  for (const line of [`-> ${READ_TOOL}`, `<- ${READ_TOOL} ok`, `-> ${WRITE_TOOL}`, `<- ${WRITE_TOOL} ok`]) {
    assert.ok(text.io.err.includes(line), `${line}\n${text.io.err.join("\n")}`);
  }
  assert.equal(process.listenerCount("SIGINT"), sigintListeners, "the Ctrl-C handler is removed when the command ends");

  const json = captureIo();
  assert.equal(await runDurableCommand([...runArgs, "--json"], json.writer, deps), 0, json.io.err.join("\n"));
  assert.equal(json.io.out.length, 1);
  const report = JSON.parse(json.io.out[0]);
  assert.equal(report.experimental, true);
  assert.equal(report.outcome, "completed");
  assert.equal(report.requestId, "req-1");
  assert.equal(report.answer, text.io.out[0]);
  assert.equal(report.tools.length, 2);
  assert.equal(model.views.length, 2, "the same request id returned the stored answer without asking the model");

  const idle = captureIo();
  assert.equal(await runDurableCommand(["resume", "--session", session.id, "--model", "faux/faux-1"], idle.writer, deps), 0);
  assert.deepEqual(idle.io.out, []);
  assert.equal(idle.io.err.at(-1), `Nothing to resume: every request in session ${session.id} has settled.`);
});

test("a session from a newer Pi Durable schema is refused with a message before Pi Durable opens it, and left as it was", async (t) => {
  const home = useGrclankerHome(t);
  const model = scriptedModel(() => fauxAssistantMessage("done"));
  const deps = { loadModels: model.loadModels, tools: () => [] };
  const session = resolveDurableSession("from-newer", home);
  const run = ["run", "--session", session.id, "--model", "faux/faux-1", "-m", "hi"];
  assert.equal(await runDurableCommand(run, captureIo().writer, deps), 0);

  const newer = CURRENT_SQLITE_SCHEMA_VERSION + 1;
  editDatabase(session.database, `UPDATE durable_schema SET version = ${newer} WHERE singleton = 1`);
  const refusal = `Session "from-newer" was written by a newer grclanker: its database is at schema version ${newer}, and this grclanker reads up to version ${CURRENT_SQLITE_SCHEMA_VERSION}. Open it with the newer grclanker, or start a new session. The session was not changed.`;
  const commands = [run, [...run, "--json"], ["resume", "--session", session.id, "--model", "faux/faux-1"]];
  const written = readFileSync(session.database);
  for (const argv of commands) {
    const { io, writer } = captureIo();
    assert.equal(await runDurableCommand(argv, writer, deps), 1, argv.join(" "));
    assert.deepEqual(io.out, [], argv.join(" "));
    assert.equal(io.err.at(-1), refusal, argv.join(" "));
    assert.ok(readFileSync(session.database).equals(written), `${argv.join(" ")} left the database as it was`);
  }
  assert.equal(model.views.length, 1, "no refused command reached the model");

  // Opening for writing would switch the file back to WAL mode before Pi Durable reads its version.
  editDatabase(session.database, "PRAGMA journal_mode = DELETE");
  const unopened = readFileSync(session.database);
  const { io, writer } = captureIo();
  assert.equal(await runDurableCommand(run, writer, deps), 1);
  assert.equal(io.err.at(-1), refusal);
  assert.ok(readFileSync(session.database).equals(unopened), "the database was not opened for writing");
});

test("a session file that is not a database is refused with a message, and left as it was", async (t) => {
  const home = useGrclankerHome(t);
  const model = scriptedModel(() => fauxAssistantMessage("done"));
  const deps = { loadModels: model.loadModels, tools: () => [] };
  const session = resolveDurableSession("not-a-database", home);
  mkdirSync(session.dir, { recursive: true });
  const contents = Buffer.from("not a database\n".repeat(300));
  writeFileSync(session.database, contents);

  const refusal = `Session "not-a-database" cannot be opened: ${session.database} is not a SQLite database. Move it aside to start the session over, or use another --session.`;
  for (const argv of [
    ["run", "--session", session.id, "--model", "faux/faux-1", "-m", "hi"],
    ["resume", "--session", session.id, "--model", "faux/faux-1"],
  ]) {
    const { io, writer } = captureIo();
    assert.equal(await runDurableCommand(argv, writer, deps), 1, argv.join(" "));
    assert.deepEqual(io.out, [], argv.join(" "));
    assert.equal(io.err.at(-1), refusal, argv.join(" "));
    assert.ok(readFileSync(session.database).equals(contents), `${argv.join(" ")} left the file as it was`);
  }
  assert.equal(model.views.length, 0);
});

test("durable is a reserved command root, so a mistyped durable command is never sent to the model as a prompt", () => {
  assert.deepEqual(routeCliInvocation(["durable", "statr"], ["investigate"]), { kind: "unknown-command", command: "durable" });
});
