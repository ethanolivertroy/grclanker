import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

// The real `grclanker durable` command, crashed with SIGKILL partway through a parallel tool round and
// resumed in a new process. The preload swaps in Pi's faux provider and a mocked PagerDuty API.
const cliRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const cliEntry = join(cliRoot, "dist", "index.js");
const preload = pathToFileURL(join(cliRoot, "tests", "helpers", "durable-e2e-preload.mjs")).href;

const MODEL = "faux/faux-1";
const FAST_READ_TOOL = "pagerduty_assess_access_control";
const SLOW_READ_TOOL = "pagerduty_assess_oncall_coverage";
const WRITE_TOOL = "pagerduty_export_audit_bundle";
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

function scratchHome(t) {
  const home = mkdtempSync(join(tmpdir(), "grclanker-durable-e2e-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));
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
    ...extra,
  };
}

function startDurable(t, home, args, extraEnv = {}) {
  const child = spawn(process.execPath, ["--import", preload, cliEntry, "durable", ...args], {
    cwd: home,
    env: childEnv(home, extraEnv),
  });
  t.after(() => child.kill("SIGKILL"));
  const output = { stdout: "", stderr: "" };
  child.stdout.setEncoding("utf8").on("data", (chunk) => (output.stdout += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk) => (output.stderr += chunk));
  const closed = new Promise((resolve) => child.once("close", (code, signal) => resolve({ code, signal })));
  return { child, output, closed };
}

async function runDurable(t, home, args) {
  const run = startDurable(t, home, args);
  const timer = new AbortController();
  const timeout = sleep(TIMEOUT_MS, undefined, { signal: timer.signal }).then(() => {
    throw new Error(`grclanker durable ${args.join(" ")} did not exit within ${TIMEOUT_MS} ms:\n${run.output.stderr}`);
  });
  timeout.catch(() => undefined);
  try {
    const { code, signal } = await Promise.race([run.closed, timeout]);
    return { code, signal, pid: run.child.pid, ...run.output };
  } finally {
    timer.abort();
  }
}

async function waitFor(predicate, description) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > TIMEOUT_MS) throw new Error(`Timed out waiting for ${description}`);
    await sleep(25);
  }
}

function readEvents(home) {
  const path = join(home, "events.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

function eventsOf(home, pid, kind) {
  return readEvents(home).filter((event) => event.pid === pid && event.kind === kind);
}

function runArgs(session, requestId, ...extra) {
  return ["run", "--session", session, "--request-id", requestId, "--model", MODEL, "--message", MESSAGE, ...extra];
}

/** Start a request and SIGKILL it once one tool has finished and the other two are blocked mid-collection. */
async function crashMidToolRound(t, home, session, requestId) {
  const run = startDurable(t, home, runArgs(session, requestId, "--json"), {
    GRCLANKER_TEST_DURABLE_HANG: HANGING_PATHS.join(","),
  });
  await waitFor(
    () =>
      run.output.stderr.includes(`<- ${FAST_READ_TOOL} ok`) &&
      run.output.stderr.includes(`-> ${SLOW_READ_TOOL}`) &&
      run.output.stderr.includes(`-> ${WRITE_TOOL}`),
    `the first tool to finish while the other two run:\n${run.output.stderr}`,
  );

  // The session lock turns away a second process while the first one holds the session.
  const contender = await runDurable(t, home, ["resume", "--session", session, "--model", MODEL]);
  assert.equal(contender.code, 1, contender.stderr);
  assert.match(contender.stderr, /Another grclanker durable process is using this session/);

  const killedAt = Date.now();
  run.child.kill("SIGKILL");
  const { signal } = await run.closed;
  assert.equal(signal, "SIGKILL");
  assert.equal(run.output.stdout, "", "the killed run printed no report");
  assert.ok(!existsSync(join(home, "bundles")), "the export was killed before it wrote anything");

  const [firstCall, ...otherCalls] = eventsOf(home, run.child.pid, "model");
  assert.equal(otherCalls.length, 0, "the killed process asked the model once, for the tool round");
  assert.equal(firstCall.toolResults, 0);
  assert.equal(firstCall.durableNote, true, "the prompt carries the durable runtime note");
  assert.equal(firstCall.assessmentState, false, "nothing was recorded before the first request");
  return { pid: run.child.pid, killedAt };
}

function toolStatuses(report) {
  return Object.fromEntries(report.tools.map((tool) => [tool.tool, { replay: tool.replay, status: tool.status }]));
}

/** What the resumed process did: kept the finished tool, reran the read-only one, and settled the writer as interrupted. */
function assertResumedOnce(home, pid) {
  const paths = eventsOf(home, pid, "request").map((event) => event.path);
  assert.ok(paths.includes("/schedules"), `the interrupted read-only assessment reran: ${paths.join(", ")}`);
  for (const path of ACCESS_CONTROL_PATHS) {
    assert.ok(!paths.includes(path), `neither the finished assessment nor the export reran (requested ${path})`);
  }
  for (const path of EXPORT_ONLY_PATHS) {
    assert.ok(!paths.includes(path), `the interrupted export did not rerun (requested ${path})`);
  }
  assert.ok(!existsSync(join(home, "bundles")), "no bundle was written");

  const calls = eventsOf(home, pid, "model");
  assert.equal(calls.length, 1, "the resumed process asked the model once, for the answer");
  assert.equal(calls[0].userMessages, 1, "the request was not asked twice");
  assert.equal(calls[0].toolResults, 3);
  assert.equal(calls[0].assessmentState, true, "the prompt lists what the tools recorded");
}

test("a crashed durable run resumes with the same request id: finished tools kept, read-only tools rerun, writers reported", async (t) => {
  const home = scratchHome(t);
  const session = "crash-run";
  const requestId = "assessment-run-1";
  const crash = await crashMidToolRound(t, home, session, requestId);

  const resumed = await runDurable(t, home, runArgs(session, requestId, "--json"));
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.match(resumed.stderr, /^grclanker durable \(experimental\)$/m);
  assert.match(
    resumed.stderr,
    new RegExp(`resuming a tool round left by an earlier process: 1 finished and kept, unfinished: .*${SLOW_READ_TOOL}`),
  );
  assert.ok(resumed.stderr.includes(`<- ${SLOW_READ_TOOL} ok`), resumed.stderr);
  assert.ok(resumed.stderr.includes(`<- ${WRITE_TOOL} interrupted; not rerun because it can write`), resumed.stderr);
  assertResumedOnce(home, resumed.pid);

  const report = JSON.parse(resumed.stdout);
  assert.equal(report.experimental, true);
  assert.equal(report.command, "run");
  assert.equal(report.session, session);
  assert.equal(report.requestId, requestId);
  assert.equal(report.model, MODEL);
  assert.equal(report.outcome, "completed");
  assert.deepEqual(toolStatuses(report), {
    [FAST_READ_TOOL]: { replay: "safe", status: "ok" },
    [SLOW_READ_TOOL]: { replay: "safe", status: "ok" },
    [WRITE_TOOL]: { replay: "unsafe", status: "interrupted" },
  });
  assert.match(report.answer, new RegExp(`- ${FAST_READ_TOOL}: ok`));
  assert.match(report.answer, new RegExp(`- ${SLOW_READ_TOOL}: ok`));
  assert.match(report.answer, new RegExp(`- ${WRITE_TOOL}: error`));

  const { calls, findings } = report.assessment;
  assert.deepEqual(Object.keys(calls).sort(), ["call-access", "call-oncall"]);
  assert.ok(Date.parse(calls["call-access"].recordedAt) < crash.killedAt, "the finished assessment was recorded before the kill");
  assert.ok(Date.parse(calls["call-oncall"].recordedAt) > crash.killedAt, "the rerun assessment was recorded after it");
  const findingTools = new Set(Object.values(findings).map((finding) => finding.tool));
  assert.deepEqual([...findingTools].sort(), [FAST_READ_TOOL, SLOW_READ_TOOL]);
  assert.ok(Object.keys(findings).every((key) => key.startsWith("pagerduty:PD-")), Object.keys(findings).join(", "));

  // Settled: resume finds nothing to do, and the same request id returns the stored answer without new work.
  const idle = await runDurable(t, home, ["resume", "--session", session, "--model", MODEL]);
  assert.equal(idle.code, 0, idle.stderr);
  assert.equal(idle.stdout, "");
  assert.match(idle.stderr, new RegExp(`Nothing to resume: every request in session ${session} has settled\\.`));

  const replayed = await runDurable(t, home, runArgs(session, requestId, "--json"));
  assert.equal(replayed.code, 0, replayed.stderr);
  const again = JSON.parse(replayed.stdout);
  assert.equal(again.submissionId, report.submissionId);
  assert.equal(again.answer, report.answer);
  assert.deepEqual(again.tools, report.tools);
  assert.deepEqual(eventsOf(home, replayed.pid, "model"), []);
  assert.deepEqual(eventsOf(home, replayed.pid, "request"), []);
});

test("grclanker durable resume finishes a crashed run and prints the answer and the interrupted writers", async (t) => {
  const home = scratchHome(t);
  const session = "crash-resume";
  await crashMidToolRound(t, home, session, "assessment-run-2");

  const resumed = await runDurable(t, home, ["resume", "--session", session, "--model", MODEL]);
  assert.equal(resumed.code, 0, resumed.stderr);
  assertResumedOnce(home, resumed.pid);
  assert.match(resumed.stdout, /^Assessment summary:\n/);
  assert.match(resumed.stdout, new RegExp(`- ${WRITE_TOOL}: error`));
  assert.ok(
    resumed.stderr.includes(
      `Interrupted and not rerun: ${WRITE_TOOL}. Check what they wrote before running them again.`,
    ),
    resumed.stderr,
  );
});
