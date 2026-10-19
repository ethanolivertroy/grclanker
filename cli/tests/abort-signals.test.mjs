import test from "node:test";
import assert from "node:assert/strict";
import { AsyncLocalStorage } from "node:async_hooks";
import childProcess from "node:child_process";
import { setMaxListeners } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { collectRegisteredGrcTools, getRegisteredGrcTool } from "../dist/agent-sdk/lib/registry.js";
import { abortableFetch, abortableSleep, ToolCallAbortedError, unlessAborted } from "../dist/extensions/grc-tools/abort.js";
import { createTlsOptOutFetch } from "../dist/extensions/grc-tools/ansible.js";
import { defaultCertificateProbe } from "../dist/extensions/grc-tools/mulesoft.js";
import { createInsecureFetch } from "../dist/extensions/grc-tools/paloalto.js";
import { createInsecureTlsFetch } from "../dist/extensions/grc-tools/splunk.js";
import { resolveToolGroup } from "../dist/pi/tool-catalog.js";

const FAKE_URL = "https://grclanker-abort.example.test";
// Hex and 32 characters long, so resolvers that check a key's length or alphabet accept it.
const FAKE_SECRET = "0123456789abcdef0123456789abcdef";
// A tool gets this long to send its first request before the sweep aborts it, and must reject this soon after the abort.
const REACH_MS = 5_000;
const SETTLE_MS = 1000;
// After one call rejects, a concurrent call that shared its request would fail within this window.
const SHARED_MS = 50;
// The sweep fails when fewer tools than this reach the mocked fetch, so a resolver change that stops a family before
// its first request cannot quietly shrink it.
const NETWORK_COVERAGE_FLOOR = 216;

// Families whose requests never pass through global fetch, so a hanging fetch cannot show whether they stop.
const NOT_FETCH = [
  ["aws_", "the AWS SDK sends requests through its own HTTP handler, not fetch"],
  ["gws_ops_", "runs the gws CLI"],
  ["oci_", "runs the oci CLI"],
  ["oscal_", "runs compliance-trestle and other local OSCAL tooling"],
];

// Arguments the generic rules in fakeValue get wrong for a family's config resolver; undefined drops the argument.
const FAMILY_ARGS = {
  // Only the Microsoft login hosts are accepted; without one the public cloud is used.
  azure_: { authority_host: undefined },
  datadog_: { site: "datadoghq.com" },
  newrelic_: { region: "US" },
  pagerduty_: { region: "us" },
  // The PAN-OS tools need a firewall host, which the generic rules do not fill.
  paloalto_: { panos_hosts: "fw1.example.test" },
  // A private key selects key-pair JWT auth, which needs a real PEM key.
  snowflake_: { private_key: undefined },
  // ZIA needs a username alongside the key and password.
  zscaler_: { zia_username: "auditor" },
};
const TOOL_ARGS = {
  // Only a Tenable Vulnerability Management (cloud) URL selects the platform this assessment reads.
  tenable_assess_vulnerability_management: { url: "https://cloud.tenable.com" },
};

const PAGERDUTY_FIXTURE = {
  abilities: ["sso"],
  users: [
    { id: "U1", name: "Alice", email: "alice@example.test", role: "owner", teams: [] },
    { id: "U2", name: "Bob", email: "bob@example.test", role: "admin", teams: [] },
  ],
  teams: [],
  schedules: [{ id: "S1", name: "Primary", users: [{ id: "U2" }], escalation_policies: [] }],
  oncalls: [],
  more: false,
};
// Read for on-call coverage, which the export collects after access control and incident response.
const PAGERDUTY_HANGING_PATHS = new Set(["/schedules", "/oncalls"]);

const CHILD_PROCESS_FUNCTIONS = ["exec", "execFile", "execFileSync", "execSync", "fork", "spawn", "spawnSync"];
const KEEP_ENV = /^(PATH|TMPDIR|TMP|TEMP|LANG|LC_[A-Z_]+|TZ|NODE_[A-Z_]+)$/;

const currentRun = new AsyncLocalStorage();

/**
 * Isolate one test: a clean environment whose home, config, and working directories are empty temporary directories;
 * fetch replaced by a mock whose requests settle only when their signal aborts, unless `respond` answers them; and
 * child processes and sockets refused. Requests, child processes, and socket attempts are recorded with the call
 * (from startRun) that made them.
 */
function sandbox(t, respond = () => undefined) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-abort-"));
  const home = join(root, "home");
  const cwd = join(root, "cwd");
  mkdirSync(home);
  mkdirSync(cwd);
  const box = { root, home, cwd, requests: [], reached: new Set(), spawns: [], sockets: [], open: true };

  const savedEnv = { ...process.env };
  const savedCwd = process.cwd();
  const savedFetch = globalThis.fetch;
  const savedConnect = net.Socket.prototype.connect;
  const savedChildProcess = Object.fromEntries(CHILD_PROCESS_FUNCTIONS.map((name) => [name, childProcess[name]]));

  for (const key of Object.keys(process.env)) if (!KEEP_ENV.test(key)) delete process.env[key];
  Object.assign(process.env, {
    HOME: home,
    USERPROFILE: home,
    GRCLANKER_HOME: join(home, ".grclanker"),
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_CACHE_HOME: join(home, ".cache"),
    XDG_DATA_HOME: join(home, ".local", "share"),
    AWS_EC2_METADATA_DISABLED: "true",
  });
  process.chdir(cwd);

  globalThis.fetch = (input, init = {}) => {
    if (!box.open) return new Promise(() => {});
    const request = input instanceof Request ? input : undefined;
    const signal = init.signal ?? request?.signal;
    const run = currentRun.getStore();
    const call = { url: request?.url ?? String(input), run, tool: run?.tool.name, signal };
    box.requests.push(call);
    if (run) {
      run.reached = true;
      box.reached.add(call.tool);
    }
    const response = respond(call);
    if (response) return Promise.resolve(response);
    return new Promise((_, reject) => {
      const abort = () => {
        if (box.open) reject(signal.reason);
      };
      if (signal?.aborted) abort();
      else signal?.addEventListener("abort", abort, { once: true });
    });
  };
  net.Socket.prototype.connect = function connect() {
    box.sockets.push({ tool: currentRun.getStore()?.tool.name });
    throw new Error("Sockets are closed in the abort tests; requests go through the mocked fetch.");
  };
  for (const name of CHILD_PROCESS_FUNCTIONS) {
    childProcess[name] = (command) => {
      box.spawns.push({ tool: currentRun.getStore()?.tool.name, command: String(command) });
      throw Object.assign(new Error(`${command} cannot run in the abort tests.`), { code: "ENOENT" });
    };
  }
  syncBuiltinESMExports();

  t.after(() => {
    process.chdir(savedCwd);
    for (const key of Object.keys(process.env)) delete process.env[key];
    Object.assign(process.env, savedEnv);
    rmSync(root, { recursive: true, force: true });
    // A call that ignored its abort is still running: it keeps a fetch that never answers, and no sockets or processes.
    if (!box.open) return;
    globalThis.fetch = savedFetch;
    net.Socket.prototype.connect = savedConnect;
    Object.assign(childProcess, savedChildProcess);
    syncBuiltinESMExports();
  });
  return box;
}

/** Wait until `predicate` holds or `ms` pass; true when it held. */
async function waitUntil(predicate, ms) {
  const deadline = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() >= deadline) return false;
    await sleep(2);
  }
  return true;
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

function listTree(dir, prefix = "") {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((entry) => {
      const path = `${prefix}${entry.name}`;
      return entry.isDirectory() ? [`${path}/`, ...listTree(join(dir, entry.name), `${path}/`)] : [path];
    })
    .sort();
}

function describeError(error) {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

function firstLine(result) {
  return String(result?.content?.[0]?.text ?? "").split("\n")[0].slice(0, 160);
}

function fakeValue(name, schema, outputDir) {
  if (Array.isArray(schema.anyOf) && schema.anyOf.every((option) => "const" in option)) return schema.anyOf[0].const;
  if (Array.isArray(schema.enum)) return schema.enum[0];
  if (schema.type !== "string") return undefined;
  if (["output_dir", "workspace_dir", "config_dir", "output"].includes(name)) return outputDir;
  if (/(_file|_path)$/.test(name) || name.startsWith("config_") || name === "credentials_json") return undefined;
  if (/(^|_)url$|(^|_)host$|endpoint/.test(name)) return FAKE_URL;
  if (/token|secret|password|passphrase|assertion|(^|_)key(_|$)|ikey|skey/.test(name)) return FAKE_SECRET;
  if (name.includes("email")) return "auditor@example.test";
  if (name === "username" || name === "user") return "auditor";
  if (/(^|_)id$|^(subdomain|org|organization|account|domain|site|instance|enterprise|stack|deployment|platform|region)$|^tenant|^project/.test(name)) {
    return "example";
  }
  return undefined;
}

/** Arguments that let a tool resolve its configuration and send its first request, all fake. */
function fakeArgs(tool, outputDir) {
  const properties = tool.parameters.properties ?? {};
  const args = {};
  for (const [name, schema] of Object.entries(properties)) {
    const value = fakeValue(name, schema, outputDir);
    if (value !== undefined) args[name] = value;
  }
  for (const name of tool.parameters.required ?? []) {
    args[name] ??= properties[name]?.type === "array" ? ["CVE-2021-44228"] : "example";
  }
  const family = Object.keys(FAMILY_ARGS).find((prefix) => tool.name.startsWith(prefix));
  for (const [name, value] of Object.entries({ ...FAMILY_ARGS[family], ...TOOL_ARGS[tool.name] })) {
    if (value === undefined) delete args[name];
    else args[name] = value;
  }
  return args;
}

function familyOf(tool) {
  return resolveToolGroup(tool.name).group;
}

/** One tool from each family per round, so calls of two tools that share a family's module state never overlap. */
function familyRounds(tools) {
  const rounds = [];
  for (const family of Map.groupBy(tools, familyOf).values()) {
    family.forEach((tool, index) => (rounds[index] ??= []).push(tool));
  }
  return rounds;
}

/** Call `tool` with fake arguments, recording whether it reached the mocked fetch and how it settled. */
function startRun(tool, outputDir, signal = new AbortController().signal) {
  const run = { tool, outputDir, reached: false, settled: false };
  run.promise = currentRun.run(run, () => tool.execute(`abort-test-${tool.name}`, fakeArgs(tool, outputDir), signal));
  run.promise.then(
    (value) => Object.assign(run, { settled: true, value }),
    (error) => Object.assign(run, { settled: true, rejected: true, error }),
  );
  return run;
}

/** Start a call of `tool` the sweep can abort with a reason of its own. */
function startAbortableRun(tool, outputDir) {
  const controller = new AbortController();
  const run = startRun(tool, outputDir, controller.signal);
  return Object.assign(run, { controller, reason: new Error(`the abort sweep stopped a call of ${tool.name}`) });
}

/** Abort `run`, noting what its output directory held at that moment. */
function abortRun(run) {
  run.aborted = true;
  run.before = existsSync(run.outputDir) ? listTree(run.outputDir) : undefined;
  run.controller.abort(run.reason);
}

function describeOutcome(run) {
  return run.rejected ? `rejected with ${describeError(run.error)}` : `resolved: ${firstLine(run.value)}`;
}

/** What `run` did wrong after its abort: kept running, settled some other way than rejecting with the reason, or wrote. */
function abortProblems(run, requests) {
  const found = [];
  if (!run.settled) {
    const sent = requests.filter((request) => request.run === run);
    const cancelled = sent.filter((request) => request.signal?.aborted).length;
    found.push(`hung: still running ${SETTLE_MS} ms after the abort (${cancelled} of ${sent.length} requests saw the abort)`);
  } else if (!run.rejected) {
    found.push(`resolved after the abort instead of rejecting: ${firstLine(run.value)}`);
  } else if (run.error !== run.reason) {
    found.push(`rejected with ${describeError(run.error)} instead of the abort reason`);
  }
  if (existsSync(run.outputDir)) {
    const written = listTree(run.outputDir).filter((path) => !run.before?.includes(path));
    if (run.before === undefined) found.push(`created its output directory after the abort${written.length > 0 ? `, with ${written.join(", ")}` : ""}`);
    else if (written.length > 0) found.push(`wrote ${written.join(", ")} after the abort`);
  }
  return found;
}

function pagerdutyResponder(call) {
  const path = new URL(call.url).pathname;
  return PAGERDUTY_HANGING_PATHS.has(path) ? undefined : Response.json(PAGERDUTY_FIXTURE);
}

test("abortableFetch without a signal is the fetch it was given", () => {
  const fetchImpl = async () => new Response("ok");
  assert.equal(abortableFetch(fetchImpl, undefined), fetchImpl);
});

test("abortableFetch gives each request a signal that aborts on the request's own signal or the call's", async () => {
  const seen = [];
  const call = new AbortController();
  const fetchWithAbort = abortableFetch(async (input, init) => {
    seen.push({ input, init });
    return new Response("ok");
  }, call.signal);

  const timeout = new AbortController();
  const init = { method: "POST", headers: { accept: "application/json" }, signal: timeout.signal };
  await fetchWithAbort("https://api.example.test/timed", init);
  await fetchWithAbort("https://api.example.test/plain");
  const [timed, plain] = seen;

  assert.equal(timed.input, "https://api.example.test/timed");
  assert.equal(timed.init.method, "POST");
  assert.deepEqual(timed.init.headers, { accept: "application/json" });
  assert.equal(init.signal, timeout.signal, "the caller's init is left as it was");
  assert.notEqual(timed.init.signal, timeout.signal);
  assert.notEqual(timed.init.signal, call.signal);

  const timedOut = new Error("request timed out");
  timeout.abort(timedOut);
  assert.equal(timed.init.signal.reason, timedOut, "the request's own timeout still aborts it");
  assert.equal(call.signal.aborted, false, "a request timing out does not abort the call");
  assert.equal(plain.init.signal.aborted, false);

  const stopped = new Error("call stopped");
  call.abort(stopped);
  assert.equal(plain.init.signal.reason, stopped, "the call's abort reaches a request that had no signal of its own");
});

test("abortableFetch rejects with ToolCallAbortedError the moment the call aborts, even when fetch ignores its signal", async () => {
  const controller = new AbortController();
  const request = abortableFetch(() => new Promise(() => {}), controller.signal)("https://api.example.test/slow");
  const reason = new Error("operator stopped the call");
  controller.abort(reason);

  const outcome = await settleWithin(request, 100);
  assert.equal(outcome.status, "rejected");
  assert.ok(outcome.error instanceof ToolCallAbortedError);
  assert.equal(outcome.error.name, "ToolCallAbortedError");
  assert.equal(outcome.error.message, "The tool call was aborted.");
  assert.equal(outcome.error.cause, reason);
});

test("abortableFetch never sends a request once the call has aborted", async () => {
  let sent = 0;
  const fetchWithAbort = abortableFetch(async () => {
    sent += 1;
    return new Response("ok");
  }, AbortSignal.abort());
  await assert.rejects(fetchWithAbort("https://api.example.test/late"), { name: "ToolCallAbortedError" });
  assert.equal(sent, 0);
});

test("requests and waits in flight at once add no listeners to the call's signal, so no listener leak is reported", async () => {
  const warnings = [];
  const onWarning = (warning) => warnings.push(warning);
  process.on("warning", onWarning);
  try {
    const controller = new AbortController();
    // A caller may cap its signal's listeners at Node's usual ten; one listener per request would pass that cap.
    setMaxListeners(10, controller.signal);
    const fetchWithAbort = abortableFetch(() => new Promise(() => {}), controller.signal);
    const wait = abortableSleep(controller.signal);
    const pending = Array.from({ length: 25 }, (_, index) => [
      fetchWithAbort(`https://api.example.test/${index}`, { signal: new AbortController().signal }),
      wait(60_000),
      unlessAborted(new Promise(() => {}), controller.signal),
    ]).flat();
    controller.abort();
    const outcomes = await Promise.allSettled(pending);
    assert.ok(outcomes.every((outcome) => outcome.status === "rejected" && outcome.reason instanceof ToolCallAbortedError));

    const live = new AbortController();
    setMaxListeners(10, live.signal);
    const answered = abortableFetch(async () => new Response("ok"), live.signal);
    await Promise.all(Array.from({ length: 25 }, (_, index) => answered(`https://api.example.test/${index}`)));

    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(warnings.filter((warning) => warning.name === "MaxListenersExceededWarning").map(String), []);
  } finally {
    process.off("warning", onWarning);
  }
});

test("abortableSleep waits with an injected sleep, and without a signal returns it unchanged", async () => {
  const waits = [];
  const sleepImpl = async (ms) => {
    waits.push(ms);
  };
  assert.equal(abortableSleep(undefined, sleepImpl), sleepImpl);
  await abortableSleep(new AbortController().signal, sleepImpl)(250);
  assert.deepEqual(waits, [250]);
});

test("abortableSleep rejects with ToolCallAbortedError as soon as the call aborts, and refuses to wait after it", async () => {
  let waits = 0;
  const controller = new AbortController();
  const wait = abortableSleep(controller.signal, () => {
    waits += 1;
    return new Promise(() => {});
  });
  const waiting = wait(60_000);
  const reason = new Error("operator stopped the call");
  controller.abort(reason);

  const outcome = await settleWithin(waiting, 100);
  assert.equal(outcome.status, "rejected");
  assert.ok(outcome.error instanceof ToolCallAbortedError);
  assert.equal(outcome.error.cause, reason);
  await assert.rejects(wait(10), { name: "ToolCallAbortedError" });
  assert.equal(waits, 1, "the wait after the abort never reached the sleep");
});

test("abortableSleep's own timer is cleared by the abort, so an aborted retry wait does not keep the process alive", async () => {
  const timers = () => process.getActiveResourcesInfo().filter((type) => type === "Timeout").length;
  const before = timers();
  const controller = new AbortController();
  const waiting = abortableSleep(controller.signal)(60_000);
  assert.equal(timers(), before + 1, "the wait holds a timer");
  controller.abort();
  assert.equal(timers(), before, "the abort cleared it");
  await assert.rejects(waiting, { name: "ToolCallAbortedError" });
});

test("unlessAborted settles as its promise does until the signal aborts, then rejects with ToolCallAbortedError", async () => {
  const work = Promise.resolve("value");
  assert.equal(unlessAborted(work, undefined), work, "without a signal it is the same promise");
  assert.equal(await unlessAborted(Promise.resolve("done"), new AbortController().signal), "done");
  const failure = new Error("upstream returned 500");
  await assert.rejects(unlessAborted(Promise.reject(failure), new AbortController().signal), (error) => error === failure);

  const controller = new AbortController();
  const reason = new Error("operator stopped the call");
  const waiting = unlessAborted(new Promise(() => {}), controller.signal);
  controller.abort(reason);
  await assert.rejects(waiting, (error) => error instanceof ToolCallAbortedError && error.cause === reason);

  const unhandled = [];
  const onUnhandled = (error) => unhandled.push(error);
  process.on("unhandledRejection", onUnhandled);
  try {
    let fail;
    const late = new Promise((_, reject) => {
      fail = reject;
    });
    await assert.rejects(unlessAborted(late, controller.signal), { name: "ToolCallAbortedError" });
    fail(new Error("failed after the abort"));
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(unhandled, [], "the abandoned promise's rejection is handled");
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

// The sweeps below refuse sockets, so the transports that skip fetch when TLS verification is turned off are checked
// here against a server that accepts the connection and never answers the handshake.
test("the raw TLS transports close their connection when the request aborts", async (t) => {
  const connections = [];
  const closed = new Set();
  const server = net.createServer((socket) => {
    connections.push(socket);
    socket.on("error", () => {});
    socket.once("close", () => closed.add(socket));
    // Discard the client hello: a socket holding unread data never reports the client's close.
    socket.resume();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    for (const socket of connections) socket.destroy();
    server.close();
  });
  const { port } = server.address();
  const url = `https://127.0.0.1:${port}/`;
  const transports = {
    "ansible verify_ssl: false": (signal) => createTlsOptOutFetch()(url, { signal }),
    "paloalto verify_tls: false": (signal) => createInsecureFetch()(url, { signal }),
    "splunk verify_ssl: false": (signal) => createInsecureTlsFetch()(url, { signal }),
    "mulesoft certificate probe": (signal) => defaultCertificateProbe("127.0.0.1", 60_000, "localhost", port, signal),
  };

  for (const [name, request] of Object.entries(transports)) {
    const opened = connections.length;
    const controller = new AbortController();
    const call = request(controller.signal);
    assert.ok(await waitUntil(() => connections.length > opened, 5000), `${name} connected`);
    const connection = connections.at(-1);
    controller.abort(new Error(`stopped ${name}`));
    const outcome = await settleWithin(call, SETTLE_MS);
    assert.equal(outcome.status, "rejected", `${name} ${outcome.status} instead of rejecting`);
    assert.ok(await waitUntil(() => closed.has(connection), SETTLE_MS), `${name} kept its connection open after the abort`);
  }
});

test("aborting pagerduty_check_access mid-request cancels the request and rejects at once with the abort reason", async (t) => {
  const box = sandbox(t);
  const controller = new AbortController();
  const call = getRegisteredGrcTool("pagerduty_check_access").execute(
    "call-check",
    { api_token: FAKE_SECRET, region: "us" },
    controller.signal,
  );
  assert.ok(await waitUntil(() => box.requests.length > 0, 5000), "the check sent its first request");

  const reason = new Error("operator stopped the call");
  controller.abort(reason);
  const outcome = await settleWithin(call, SETTLE_MS);
  assert.equal(outcome.status, "rejected", `the call ${outcome.status} instead of rejecting`);
  assert.equal(outcome.error, reason);
  assert.match(box.requests[0].url, /^https:\/\/api\.pagerduty\.com\//);
  assert.ok(box.requests.every((request) => request.signal.aborted), "every request in flight saw the abort");

  const sent = box.requests.length;
  await sleep(20);
  assert.equal(box.requests.length, sent, "nothing is sent after the abort");
});

test("aborting pagerduty_export_audit_bundle mid-collection writes nothing, not even its output directory", async (t) => {
  const box = sandbox(t, pagerdutyResponder);
  const outputRoot = join(box.cwd, "exports");
  const isHanging = (request) => PAGERDUTY_HANGING_PATHS.has(new URL(request.url).pathname);
  const controller = new AbortController();
  const call = getRegisteredGrcTool("pagerduty_export_audit_bundle").execute(
    "call-export",
    { api_token: FAKE_SECRET, region: "us", output_dir: outputRoot },
    controller.signal,
  );
  assert.ok(await waitUntil(() => box.requests.some(isHanging), 10_000), "the export reached the on-call datasets");
  assert.ok(box.requests.some((request) => !isHanging(request)), "the export collected other datasets first");

  const reason = new Error("operator stopped the export");
  controller.abort(reason);
  const outcome = await settleWithin(call, SETTLE_MS);
  assert.equal(outcome.status, "rejected", `the export ${outcome.status} instead of rejecting`);
  assert.equal(outcome.error, reason);
  assert.ok(box.requests.filter(isHanging).every((request) => request.signal.aborted), "the requests in flight saw the abort");

  assert.deepEqual(listTree(box.root).filter((path) => /\.zip$|\.grclanker-staging-|audit-bundle/.test(path)), []);
  assert.equal(existsSync(outputRoot), false, `the export created its output directory: ${listTree(box.cwd).join(", ")}`);
});

test("every registered tool refuses a call whose signal already aborted: it rejects with the reason and sends, runs, and writes nothing", async (t) => {
  const box = sandbox(t);
  const outputDir = join(box.root, "out");
  mkdirSync(outputDir);
  const before = listTree(box.root);
  const tools = collectRegisteredGrcTools();
  assert.ok(tools.length > 200, `the registry lists every domain tool (${tools.length})`);

  const problems = [];
  for (const tool of tools) {
    const reason = new Error(`${tool.name} was aborted before it started`);
    const outcome = await settleWithin(startRun(tool, outputDir, AbortSignal.abort(reason)).promise, SETTLE_MS);
    if (outcome.status === "rejected" && outcome.error === reason) continue;
    problems.push(
      `${tool.name}: ${outcome.status === "rejected" ? `rejected with ${describeError(outcome.error)}` : outcome.status === "resolved" ? `resolved: ${firstLine(outcome.value)}` : "never settled"}`,
    );
  }

  assert.equal(problems.length, 0, `${problems.length} tools ran despite an aborted signal:\n${problems.join("\n")}`);
  assert.deepEqual(box.requests.map((request) => `${request.tool} ${request.url}`), [], "no tool sent a request");
  assert.deepEqual(box.spawns.map((spawn) => `${spawn.tool} ${spawn.command}`), [], "no tool started a process");
  assert.deepEqual(box.sockets.map((socket) => String(socket.tool)), [], "no tool opened a socket");
  assert.deepEqual(listTree(box.root), before, "no tool wrote a file");
});

/**
 * Each tool runs twice at once with the same arguments, as when one process serves two sessions with the same
 * credentials. The first call is aborted mid-request; the second must keep running, so a request or token the two
 * shared cannot carry the first call's abort into it. Then the second is aborted too.
 */
test("every tool that requests through fetch stops when aborted mid-request: it rejects within a second with the abort reason, writes nothing, and leaves a concurrent call running", async (t) => {
  const box = sandbox(t);
  const swept = collectRegisteredGrcTools().filter((tool) => !NOT_FETCH.some(([prefix]) => tool.name.startsWith(prefix)));
  const pairs = [];

  for (const round of familyRounds(swept)) {
    const started = round.map((tool) => ({
      tool,
      first: startAbortableRun(tool, join(box.root, "out", tool.name, "first")),
      second: startAbortableRun(tool, join(box.root, "out", tool.name, "second")),
    }));
    await waitUntil(() => started.every(({ first }) => first.settled || first.reached), REACH_MS);
    for (const pair of started) {
      pair.reached = box.reached.has(pair.tool.name);
      if (pair.first.settled) continue;
      pair.secondRunning = !pair.second.settled;
      abortRun(pair.first);
    }
    await waitUntil(() => started.every(({ first }) => first.settled), SETTLE_MS);
    await sleep(SHARED_MS);
    for (const pair of started) {
      pair.secondEnded = pair.secondRunning && pair.second.settled;
      if (!pair.second.settled) abortRun(pair.second);
    }
    await waitUntil(() => started.every(({ second }) => second.settled), SETTLE_MS);
    pairs.push(...started);
  }

  const problems = pairs
    .filter(({ first }) => first.aborted)
    .flatMap(({ tool, first, second, secondRunning, secondEnded }) => {
      const found = abortProblems(first, box.requests);
      if (found.length === 0 && secondRunning) {
        if (secondEnded) found.push(`a concurrent call ended when this one was aborted: ${describeOutcome(second)}`);
        else found.push(...abortProblems(second, box.requests).map((problem) => `the concurrent call ${problem}`));
      }
      return found.map((problem) => `${tool.name}: ${problem}`);
    });
  if (pairs.some(({ first, second }) => !first.settled || !second.settled)) box.open = false;

  const reached = pairs.filter((pair) => pair.reached);
  t.diagnostic(`${pairs.length} tools swept, ${reached.length} reached the mocked fetch before the abort`);
  for (const [prefix, reason] of NOT_FETCH) t.diagnostic(`not swept: ${prefix}* (${reason})`);
  for (const { tool, first } of pairs.filter((pair) => !pair.reached)) {
    t.diagnostic(`sent no request: ${tool.name} (${first.aborted ? "aborted before its first request" : `settled first: ${describeOutcome(first)}`})`);
  }
  if (box.spawns.length > 0) t.diagnostic(`refused processes: ${box.spawns.map((spawn) => `${spawn.tool} ran ${spawn.command}`).join("; ")}`);

  assert.equal(problems.length, 0, `${problems.length} problems after aborting tools mid-request:\n${problems.join("\n")}`);
  assert.deepEqual(box.sockets.map((socket) => String(socket.tool)), [], "every swept tool sends its requests through fetch");
  assert.ok(
    reached.length >= NETWORK_COVERAGE_FLOOR,
    `only ${reached.length} of ${pairs.length} tools reached the mocked fetch; the floor is ${NETWORK_COVERAGE_FLOOR}`,
  );
  const silent = [...new Set(pairs.map((pair) => familyOf(pair.tool)))].filter(
    (family) => !reached.some((pair) => familyOf(pair.tool) === family),
  );
  assert.deepEqual(silent, [], "every swept family has a tool that reaches the mocked fetch");
});
