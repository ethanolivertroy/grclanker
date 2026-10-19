import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Type } from "@sinclair/typebox";
import { createModels } from "@earendil-works/pi-ai/models";
import { fauxAssistantMessage, fauxProvider, fauxText, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";
import {
  buildDurableRequest,
  DURABLE_EXPERIMENTAL_BANNER,
  formatDurableHelp,
  parseDurableArgs,
  runDurableCommand,
} from "../dist/durable/cli.js";
import { emptyAssessmentState } from "../dist/durable/document.js";
import { DurableUsageError } from "../dist/durable/errors.js";
import { DURABLE_MODEL_ENV } from "../dist/durable/models.js";
import { durableSessionsDir, resolveDurableSession } from "../dist/durable/session.js";
import { toDurableTool } from "../dist/durable/tools.js";
import { openDurableTui } from "../dist/durable/tui/runtime.js";
import { describeAssessment, runDurableTui } from "../dist/durable/tui/tui.js";
import { CLI_HELP } from "../dist/pi/cli-help.js";
import { screenText, ScreenTerminal, stripTerminal, waitForText } from "./helpers/terminal-screen.mjs";

const cliRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const cliEntry = join(cliRoot, "dist", "index.js");
const preload = pathToFileURL(join(cliRoot, "tests", "helpers", "durable-e2e-preload.mjs")).href;

const MODEL = { provider: "faux", modelId: "faux-1" };
const READ_TOOL = "fakegrc_assess_controls";
const WRITE_TOOL = "fakegrc_export_bundle";

function scratchDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-durable-tui-"));
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
  return base;
}

function fakeTool(name, execute) {
  return toDurableTool({
    name,
    description: `Test tool ${name}.`,
    parameters: Type.Object({ output_dir: Type.Optional(Type.String()) }),
    execute,
  });
}

/** Pi's faux provider: one round calling both tools for the first request, then a summary of the results. */
function scriptedModel() {
  const calls = [];
  const faux = fauxProvider({ models: [{ id: MODEL.modelId }] });
  const respond = (context) => {
    const messages = context.messages;
    const lastUser = messages.findLastIndex((message) => message.role === "user");
    const results = messages.slice(lastUser + 1).filter((message) => message.role === "toolResult");
    const userMessages = messages.filter((message) => message.role === "user").length;
    calls.push({ userMessages, toolResults: results.length });
    if (userMessages === 1 && results.length === 0) {
      return fauxAssistantMessage(
        [
          fauxToolCall(READ_TOOL, {}, { id: "call-read" }),
          fauxToolCall(WRITE_TOOL, { output_dir: "out" }, { id: "call-write" }),
        ],
        { stopReason: "toolUse" },
      );
    }
    const summary = results.map((result) => `${result.toolName}: ${result.isError ? "error" : "ok"}`).sort();
    return fauxAssistantMessage([fauxText(`answer ${userMessages}: ${summary.join(", ") || "no tools"}`)]);
  };
  faux.setResponses(Array.from({ length: 20 }, () => respond));
  const models = createModels();
  models.setProvider(faux.provider);
  return { calls, loadModels: async () => models };
}

function fakeTools(dir, counts) {
  return () => [
    fakeTool(READ_TOOL, async () => {
      counts.read += 1;
      return {
        content: [{ type: "text", text: "2 controls assessed" }],
        details: {
          findings: [
            { id: "AC-1", status: "fail", severity: "high", title: "MFA is not enforced" },
            { id: "AC-2", status: "pass", severity: null, title: "Admins reviewed" },
          ],
        },
      };
    }),
    fakeTool(WRITE_TOOL, async () => {
      counts.write += 1;
      return {
        content: [{ type: "text", text: "bundle written" }],
        details: { output_dir: dir, zip_path: join(dir, "bundle.zip") },
      };
    }),
  ];
}

/** Open the session and run the terminal app on a screen the test reads and types into. */
async function openApp(t, session, deps, columns = 120) {
  const durable = await openDurableTui({ session, model: MODEL }, deps);
  const terminal = new ScreenTerminal(columns, 100);
  let running = true;
  const exited = runDurableTui(durable.view, durable.controller, {
    agentDir: join(session.dir, "agent"),
    banner: DURABLE_EXPERIMENTAL_BANNER,
    terminal,
  }).finally(() => {
    running = false;
  });
  const exit = async (key) => {
    if (running) terminal.type(key);
    await exited;
    await durable.close();
  };
  // A failed assertion leaves the app running; exit it so its timers do not keep the test process alive.
  t.after(() => exit("\x03"));
  await terminal.waitFor((screen) => screen.includes(`session ${session.id}`), "the footer");
  return { terminal, exit };
}

test("durable tui takes --session and --model; messages, request ids, and --json belong to run", () => {
  assert.deepEqual(parseDurableArgs("tui", []), { command: "tui", json: false });
  assert.deepEqual(parseDurableArgs("tui", ["--session", "s1", "--model", "faux/faux-1"]), {
    command: "tui",
    session: "s1",
    model: "faux/faux-1",
    json: false,
  });

  const onlySessionAndModel =
    "'grclanker durable tui' takes only --session and --model. Type messages in the terminal app, or use 'grclanker durable run' to send one from the command line.";
  const cases = [
    [["-m", "hi"], onlySessionAndModel],
    [["--request-id", "r1"], onlySessionAndModel],
    [["--json"], onlySessionAndModel],
    [["--session"], "--session requires a value."],
    [["--verbose"], "Unknown option for 'grclanker durable tui': --verbose"],
  ];
  for (const [argv, message] of cases) {
    assert.throws(
      () => parseDurableArgs("tui", argv),
      (error) => error instanceof DurableUsageError && error.message === message,
      argv.join(" "),
    );
  }

  const help = formatDurableHelp();
  assert.match(help, /^ {2}grclanker durable tui \[--session <id>\] \[--model <provider\/model>\]$/m);
  assert.match(help, /^ {2}tui {6}Chat in a terminal app: starts a new session, or opens the one named by --session$/m);
  assert.match(CLI_HELP, /grclanker durable tui \[--session <id>\]\n\s+Experimental:/);
});

// `node --test` runs each file with piped stdio, so the process has no terminal unless the file is run by hand.
const HAS_TERMINAL = process.stdin.isTTY && process.stdout.isTTY ? "this process has a terminal" : false;

test("durable tui without --session starts a new session, and outside a terminal it points at durable run", { skip: HAS_TERMINAL }, async (t) => {
  useGrclankerHome(t);
  const env = { [DURABLE_MODEL_ENV]: "faux/faux-1" };
  const first = buildDurableRequest(parseDurableArgs("tui", []), env);
  const second = buildDurableRequest(parseDurableArgs("tui", []), env);
  assert.equal(first.command, "tui");
  assert.deepEqual(first.model, MODEL);
  assert.match(first.session.id, /^\d{8}-\d{6}-[0-9a-f]{6}$/);
  assert.notEqual(first.session.id, second.session.id);

  const io = { out: [], err: [] };
  const code = await runDurableCommand(["tui", "--session", "s1", "--model", "faux/faux-1"], {
    writeOut: (line) => io.out.push(line),
    writeErr: (line) => io.err.push(line),
  });
  assert.equal(code, 1);
  assert.deepEqual(io, {
    out: [],
    err: [
      DURABLE_EXPERIMENTAL_BANNER,
      "'grclanker durable tui' needs an interactive terminal. From a script or a pipe, use 'grclanker durable run --message <text>'.",
    ],
  });
  assert.ok(!existsSync(durableSessionsDir()), "no session was opened");
});

test("the footer counts what the assessment recorded and says nothing before the first tool call", () => {
  const state = emptyAssessmentState();
  assert.equal(describeAssessment(state), undefined);
  state.calls.a = {};
  assert.equal(describeAssessment(state), "1 tool call");
  state.calls.b = {};
  state.findings["okta:OKTA-1"] = {};
  assert.equal(describeAssessment(state), "2 tool calls, 1 finding");
  state.findings["okta:OKTA-2"] = {};
  state.artifacts.b = {};
  assert.equal(describeAssessment(state), "2 tool calls, 2 findings, 1 export");
});

test("the terminal app runs a durable turn, and reopening the session shows it again without asking the model", async (t) => {
  const home = scratchDir(t);
  const session = resolveDurableSession("tui-turn", home);
  const model = scriptedModel();
  const counts = { read: 0, write: 0 };
  const deps = { loadModels: model.loadModels, tools: fakeTools(home, counts) };

  const app = await openApp(t, session, deps);
  assert.ok(app.terminal.screen().startsWith(` ${DURABLE_EXPERIMENTAL_BANNER} · session tui-turn\n`), app.terminal.screen());
  assert.match(app.terminal.screen(), /^ Tasks \(0 live, \/tasks to hide\)$/m);
  app.terminal.type("Assess and export.");
  app.terminal.type("\r");
  const answered = await app.terminal.waitFor(
    (screen) => screen.includes(`answer 1: ${READ_TOOL}: ok, ${WRITE_TOOL}: ok`),
    "the answer",
  );
  for (const text of ["Assess and export.", READ_TOOL, "2 controls assessed", WRITE_TOOL, "bundle written"]) {
    assert.ok(answered.includes(text), `${text}\n${answered}`);
  }
  assert.match(answered, /^ .*\$0\.000.* {2}assessment: 2 tool calls, 2 findings, 1 export {2}session tui-turn$/m);
  assert.match(answered, /^ faux\/faux-1 · thinking:off \(shift\+tab\) · .* ctrl\+c exit$/m);
  assert.deepEqual(model.calls, [
    { userMessages: 1, toolResults: 0 },
    { userMessages: 1, toolResults: 2 },
  ]);
  assert.deepEqual(counts, { read: 1, write: 1 });

  app.terminal.type("/tasks");
  app.terminal.type("\r");
  await app.terminal.waitFor((screen) => !screen.includes("Tasks ("), "the task panel to close");
  await app.exit("\x03");

  const reopened = await openApp(t, session, deps);
  const shown = await reopened.terminal.waitFor(
    (screen) => screen.includes(`answer 1: ${READ_TOOL}: ok, ${WRITE_TOOL}: ok`),
    "the stored answer",
  );
  assert.ok(shown.includes("Assess and export."), shown);
  assert.match(shown, / {2}assessment: 2 tool calls, 2 findings, 1 export {2}session tui-turn$/m);
  assert.equal(model.calls.length, 2, "reopening asked the model nothing");
  assert.deepEqual(counts, { read: 1, write: 1 }, "reopening ran no tool");
  await reopened.exit("\x04");
});

test("an app closed mid tool round keeps it: on reopen the read-only tool reruns, the writer is reported and not rerun, and the notices wrap", async (t) => {
  const home = scratchDir(t);
  const session = resolveDurableSession("tui-close", home);
  const model = scriptedModel();
  const first = { read: 0, write: 0 };
  // Never settle, like calls still waiting on an API when the operator exits.
  const hanging = () => [
    fakeTool(READ_TOOL, () => {
      first.read += 1;
      return new Promise(() => {});
    }),
    fakeTool(WRITE_TOOL, () => {
      first.write += 1;
      return new Promise(() => {});
    }),
  ];
  const app = await openApp(t, session, { loadModels: model.loadModels, tools: hanging }, 72);
  app.terminal.type("Assess and export.");
  app.terminal.type("\r");
  await app.terminal.waitFor(() => first.read === 1 && first.write === 1, "both tools to start");
  await app.exit("\x03");

  const second = { read: 0, write: 0 };
  const reopened = await openApp(t, session, { loadModels: model.loadModels, tools: fakeTools(home, second) }, 72);
  const settled = await reopened.terminal.waitFor((screen) => screen.includes("answer 1:"), "the answer");
  // A 72-column screen wraps both notices; joined back, each reads in full.
  const text = settled.replace(/\s+/g, " ");
  for (const sentence of [
    `Resuming a tool round left by an earlier process: 0 finished and kept, unfinished: ${READ_TOOL}, ${WRITE_TOOL}.`,
    `${WRITE_TOOL} was interrupted and not rerun because it can write. Check what it wrote before running it again.`,
    `answer 1: ${READ_TOOL}: ok, ${WRITE_TOOL}: error`,
  ]) {
    assert.ok(text.includes(sentence), `${sentence}\n${settled}`);
  }
  assert.deepEqual(first, { read: 1, write: 1 });
  assert.deepEqual(second, { read: 1, write: 0 });
  assert.deepEqual(model.calls, [
    { userMessages: 1, toolResults: 0 },
    { userMessages: 1, toolResults: 2 },
  ]);
  await reopened.exit("\x03");
});

test("terminal app commands: /model opens the model list, Esc closes it, and an unsupported thinking change is a notice", async (t) => {
  const home = scratchDir(t);
  const session = resolveDurableSession("tui-commands", home);
  const model = scriptedModel();
  const app = await openApp(t, session, { loadModels: model.loadModels, tools: fakeTools(home, { read: 0, write: 0 }) });

  app.terminal.type("/model");
  app.terminal.type("\r");
  const listed = await app.terminal.waitFor((screen) => screen.includes("Select model:"), "the model list");
  assert.match(listed, /faux-1/);
  app.terminal.type("\x1b");
  await app.terminal.waitFor((screen) => !screen.includes("Select model:"), "the editor to return");

  app.terminal.type("\x1b[Z");
  await app.terminal.waitFor((screen) => screen.includes("Current model does not support thinking"), "the notice");
  assert.deepEqual(model.calls, [], "no command reached the model");
  await app.exit("\x03");
});

// The real `grclanker durable tui` in a pseudo-terminal, crashed with SIGKILL partway through a parallel tool
// round and opened again. The preload swaps in Pi's faux provider and a mocked PagerDuty API.
const FAST_READ_TOOL = "pagerduty_assess_access_control";
const SLOW_READ_TOOL = "pagerduty_assess_oncall_coverage";
const PAGERDUTY_WRITE_TOOL = "pagerduty_export_audit_bundle";
const MESSAGE = "Assess PagerDuty access control and on-call coverage, and export an audit bundle.";
// The on-call assessment reads these, and so does the export, so both are mid-collection at the kill.
const HANGING_PATHS = ["/schedules", "/oncalls"];
// Read by the access control assessment and by the export, never by the on-call assessment.
const ACCESS_CONTROL_PATHS = ["/abilities", "/teams"];
// Read only by the export.
const EXPORT_ONLY_PATHS = [
  "/services",
  "/escalation_policies",
  "/priorities",
  "/incident_workflows",
  "/audit/records",
  "/extensions",
  "/webhook_subscriptions",
  "/business_services",
  "/change_events",
];
const TIMEOUT_MS = 60_000;

const scriptVersion = spawnSync("script", ["--version"], { encoding: "utf8" });
const hasUtilLinuxScript = scriptVersion.status === 0 && /util-linux/.test(`${scriptVersion.stdout}${scriptVersion.stderr}`);

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function e2eHome(t) {
  const home = scratchDir(t);
  // An explicit config file keeps the operator's ~/.config/grclanker/pagerduty.json out of the run.
  writeFileSync(join(home, "pagerduty.json"), "{}\n");
  return home;
}

function childEnv(home, extra) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("PAGERDUTY_") || key.startsWith("GRCLANKER_")) delete env[key];
  }
  return {
    ...env,
    GRCLANKER_HOME: home,
    PAGERDUTY_API_TOKEN: "pd_mock_token_not_a_real_credential",
    PAGERDUTY_CONFIG_FILE: join(home, "pagerduty.json"),
    GRCLANKER_TEST_DURABLE_LOG: join(home, "events.jsonl"),
    SHELL: "/bin/sh",
    TERM: "xterm-256color",
    ...extra,
  };
}

/** `grclanker durable tui` on a 200-column pseudo-terminal from util-linux script(1). */
function startTui(t, home, session, extraEnv = {}) {
  const command = [process.execPath, "--import", preload, cliEntry, "durable", "tui", "--session", session, "--model", "faux/faux-1"]
    .map(shellQuote)
    .join(" ");
  const child = spawn("script", ["-qfec", `stty cols 200 rows 60 && exec ${command}`, "/dev/null"], {
    cwd: home,
    env: childEnv(home, extraEnv),
  });
  t.after(() => child.kill("SIGKILL"));
  let output = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => (output += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk) => (output += chunk));
  const closed = new Promise((resolve) => child.once("close", (code, signal) => resolve({ code, signal })));
  return {
    closed,
    output: () => output,
    screen: () => screenText(output),
    waitFor: (predicate, description) => waitForText(() => screenText(output), predicate, description, TIMEOUT_MS),
    write: (data) => child.stdin.write(data),
  };
}

async function runDurable(t, home, args) {
  const child = spawn(process.execPath, ["--import", preload, cliEntry, "durable", ...args], {
    cwd: home,
    env: childEnv(home),
  });
  t.after(() => child.kill("SIGKILL"));
  const output = { stdout: "", stderr: "" };
  child.stdout.setEncoding("utf8").on("data", (chunk) => (output.stdout += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk) => (output.stderr += chunk));
  const code = await new Promise((resolve) => child.once("close", resolve));
  return { code, ...output };
}

function readEvents(home) {
  const path = join(home, "events.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

function eventsOf(home, pid, kind) {
  return readEvents(home).filter((event) => event.pid === pid && event.kind === kind);
}

async function waitForEvents(home, predicate, description) {
  const started = Date.now();
  while (!predicate(readEvents(home))) {
    if (Date.now() - started > TIMEOUT_MS) throw new Error(`Timed out waiting for ${description}`);
    await sleep(25);
  }
}

/** Open the app and send the request; resolves once the access control assessment is recorded while the on-call
 * assessment and the export both wait on /schedules. */
async function startStalledRound(t, home, session) {
  const app = startTui(t, home, session, { GRCLANKER_TEST_DURABLE_HANG: HANGING_PATHS.join(",") });
  await app.waitFor((screen) => screen.includes(`session ${session}`), "the terminal app");
  app.write(MESSAGE);
  await sleep(200);
  app.write("\r");
  await app.waitFor((screen) => screen.includes("assessment: 1 tool call, "), "the first tool to finish");
  await waitForEvents(
    home,
    (events) => events.filter((event) => event.kind === "request" && event.path === "/schedules").length === 2,
    "both other tools to block on /schedules",
  );
  return app;
}

test(
  "grclanker durable tui killed with SIGKILL mid tool round resumes when opened again: the finished read is kept and the writer is not rerun",
  { skip: hasUtilLinuxScript ? false : "needs util-linux script(1) for a pseudo-terminal" },
  async (t) => {
    const home = e2eHome(t);
    const session = "crash-tui";

    const crashed = await startStalledRound(t, home, session);
    const [firstCall, ...otherCalls] = readEvents(home).filter((event) => event.kind === "model");
    assert.equal(otherCalls.length, 0, "the app asked the model once, for the tool round");
    assert.equal(firstCall.toolResults, 0);
    const crashedPid = firstCall.pid;
    assert.match(crashed.screen(), new RegExp(`Running ${SLOW_READ_TOOL}\\.\\.\\.`));

    // The open app holds the session lock.
    const contender = await runDurable(t, home, ["resume", "--session", session, "--model", "faux/faux-1"]);
    assert.equal(contender.code, 1, contender.stderr);
    assert.match(contender.stderr, /Another grclanker durable process is using this session/);

    process.kill(crashedPid, "SIGKILL");
    await crashed.closed;
    assert.ok(!existsSync(join(home, "bundles")), "the export was killed before it wrote anything");

    const resumed = startTui(t, home, session);
    const settled = await resumed.waitFor(
      (screen) => screen.includes("Assessment summary:") && screen.includes("assessment: 2 tool calls, "),
      "the resumed answer",
    );
    for (const line of [
      ` Resuming a tool round left by an earlier process: 1 finished and kept, unfinished: ${SLOW_READ_TOOL}, ${PAGERDUTY_WRITE_TOOL}.`,
      ` ${PAGERDUTY_WRITE_TOOL} was interrupted and not rerun because it can write. Check what it wrote before running it again.`,
      ` - ${FAST_READ_TOOL}: ok`,
      ` - ${SLOW_READ_TOOL}: ok`,
      ` - ${PAGERDUTY_WRITE_TOOL}: error`,
    ]) {
      assert.ok(settled.split("\n").includes(line), `${line}\n${settled}`);
    }
    resumed.write("\x03");
    const exit = await resumed.closed;
    assert.equal(exit.code, 0, stripTerminal(resumed.output()));
    assert.ok(
      stripTerminal(resumed.output()).includes(
        `Session ${session} is saved. Open it again with: grclanker durable tui --session ${session}\n`,
      ),
      stripTerminal(resumed.output()),
    );

    const resumedCalls = readEvents(home).filter((event) => event.kind === "model" && event.pid !== crashedPid);
    assert.equal(resumedCalls.length, 1, "the resumed app asked the model once, for the answer");
    assert.equal(resumedCalls[0].userMessages, 1, "the request was not asked twice");
    assert.equal(resumedCalls[0].toolResults, 3);
    assert.equal(resumedCalls[0].assessmentState, true, "the prompt lists what the tools recorded");
    const paths = eventsOf(home, resumedCalls[0].pid, "request").map((event) => event.path);
    assert.ok(paths.includes("/schedules"), `the interrupted read-only assessment reran: ${paths.join(", ")}`);
    for (const path of ACCESS_CONTROL_PATHS) {
      assert.ok(!paths.includes(path), `neither the finished assessment nor the export reran (requested ${path})`);
    }
    for (const path of EXPORT_ONLY_PATHS) {
      assert.ok(!paths.includes(path), `the interrupted export did not rerun (requested ${path})`);
    }
    assert.ok(!existsSync(join(home, "bundles")), "no bundle was written");

    const idle = await runDurable(t, home, ["resume", "--session", session, "--model", "faux/faux-1"]);
    assert.equal(idle.code, 0, idle.stderr);
    assert.match(idle.stderr, new RegExp(`Nothing to resume: every request in session ${session} has settled\\.`));
  },
);

test(
  "grclanker durable tui closed with Ctrl+C mid tool round exits at once, and resume finishes the round without rerunning the writer",
  { skip: hasUtilLinuxScript ? false : "needs util-linux script(1) for a pseudo-terminal" },
  async (t) => {
    const home = e2eHome(t);
    const session = "close-tui";
    const app = await startStalledRound(t, home, session);

    app.write("\x03");
    // Waiting for the two stalled tools would keep the process alive for good.
    const exit = await Promise.race([app.closed, sleep(10_000, "still running after 10s", { ref: false })]);
    assert.deepEqual(exit, { code: 0, signal: null }, stripTerminal(app.output()));
    assert.ok(
      stripTerminal(app.output()).includes(
        `Closed with work in flight; it continues when session ${session} is opened again: grclanker durable tui --session ${session} (or grclanker durable resume --session ${session} to finish it without the terminal app).\n`,
      ),
      stripTerminal(app.output()),
    );

    const resumed = await runDurable(t, home, ["resume", "--session", session, "--model", "faux/faux-1"]);
    assert.equal(resumed.code, 0, resumed.stderr);
    assert.ok(
      resumed.stderr.includes(
        `Interrupted and not rerun: ${PAGERDUTY_WRITE_TOOL}. Check what they wrote before running them again.`,
      ),
      resumed.stderr,
    );
    assert.ok(resumed.stdout.includes(`- ${SLOW_READ_TOOL}: ok`), resumed.stdout);
    assert.ok(!existsSync(join(home, "bundles")), "no bundle was written");
  },
);
