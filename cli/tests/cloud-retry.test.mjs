import test from "node:test";
import assert from "node:assert/strict";

import { abortableFetch, ToolCallAbortedError } from "../dist/extensions/grc-tools/abort.js";
import {
  attemptsNote,
  backoffDelayMs,
  CLOUD_MAX_RETRIES,
  CLOUD_MAX_RETRY_WAIT_MS,
  CLOUD_REQUEST_TIMEOUT_MS,
  CLOUD_RETRY_BASE_DELAY_MS,
  CLOUD_RETRY_POLICY_TEXT,
  CLOUD_RETRYABLE_STATUSES,
  cloudRetryPolicy,
  exchangeWithRetries,
  retryAfterMs,
  retryStopNote,
  timeoutReason,
  unansweredProbesNote,
} from "../dist/extensions/grc-tools/cloud-retry.js";

const NOW = new Date("2026-10-23T12:00:00Z");
const TARGET = "https://api.example.test/v1/items";

/** A policy on a fixed clock whose waits are recorded instead of slept. */
function recordingPolicy(options = {}) {
  const waits = [];
  const policy = cloudRetryPolicy({ now: () => NOW, sleepImpl: async (ms) => { waits.push(ms); }, ...options });
  return { waits, policy };
}

/** A transport that answers attempt n with answers[n - 1], repeating the last answer once the list runs out. */
function scriptedFetch(answers) {
  const sent = [];
  const fetchImpl = async (url, init) => {
    sent.push({ url, init });
    return answers[Math.min(sent.length, answers.length) - 1](init);
  };
  return { sent, fetchImpl };
}

const answer = (status, headers = {}, body = "") => () => new Response(body, { status, headers });
const rejectWith = (makeError) => () => {
  throw makeError();
};
const stalledBody = (status) => () => new Response(new ReadableStream({ start() {} }), { status });

test("the retry contract: 429, 500, 502, 503, and 504 are retried up to three times within a 30 s timeout per attempt, waiting 1 s, 2 s, then 4 s and never more than 30 s, and the spec text is built from those constants", () => {
  assert.deepEqual([...CLOUD_RETRYABLE_STATUSES], [429, 500, 502, 503, 504]);
  assert.ok(Object.isFrozen(CLOUD_RETRYABLE_STATUSES));
  assert.equal(CLOUD_MAX_RETRIES, 3);
  assert.equal(CLOUD_REQUEST_TIMEOUT_MS, 30_000);
  assert.equal(CLOUD_RETRY_BASE_DELAY_MS, 1_000);
  assert.equal(CLOUD_MAX_RETRY_WAIT_MS, 30_000);
  assert.deepEqual([1, 2, 3, 4, 5, 6, 20].map(backoffDelayMs), [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
  for (const phrase of [
    "Retry 429, 500, 502, 503, 504 responses, transport failures, and attempts that run past the 30 s per-request timeout up to 3 times (4 attempts in all), token requests included.",
    "otherwise 1 s, 2 s, 4 s.",
    "A Retry-After above 30 s ends the retries at once, and the error names the wait the server asked for.",
    "a list that fails on a later page keeps none of its earlier pages.",
  ]) {
    assert.ok(CLOUD_RETRY_POLICY_TEXT.includes(phrase), `the policy text states: ${phrase}`);
  }
  assert.doesNotMatch(CLOUD_RETRY_POLICY_TEXT, /\u2014/);
});

test("retryAfterMs reads delta-seconds and the three HTTP-date forms against the clock, reads asctime as UTC whatever the local zone, and leaves any other value to the backoff", () => {
  assert.equal(retryAfterMs("0", NOW), 0);
  assert.equal(retryAfterMs("7", NOW), 7_000);
  assert.equal(retryAfterMs(" 12 ", NOW), 12_000);
  assert.equal(retryAfterMs("99999999999999999999", NOW), Number.MAX_SAFE_INTEGER);
  const previousZone = process.env.TZ;
  try {
    for (const zone of ["UTC", "America/Los_Angeles", "Asia/Kolkata"]) {
      process.env.TZ = zone;
      assert.equal(NOW.getTimezoneOffset() === 0, zone === "UTC", `the local zone is ${zone}`);
      assert.equal(retryAfterMs("Fri, 23 Oct 2026 12:00:05 GMT", NOW), 5_000, `IMF-fixdate in ${zone}`);
      assert.equal(retryAfterMs("Friday, 23-Oct-26 12:00:05 GMT", NOW), 5_000, `RFC 850 date in ${zone}`);
      assert.equal(retryAfterMs("Fri Oct 23 12:00:05 2026", NOW), 5_000, `asctime date in ${zone}`);
    }
  } finally {
    if (previousZone === undefined) delete process.env.TZ;
    else process.env.TZ = previousZone;
  }
  assert.equal(retryAfterMs("Sat Oct  3 12:00:05 2026", new Date("2026-10-03T12:00:00Z")), 5_000, "asctime pads a one-digit day with a space");
  assert.equal(retryAfterMs("Fri, 23 Oct 2026 11:59:00 GMT", NOW), 0, "a date already past asks for no wait");
  for (const value of [null, "", "   ", "soon", "-5", "1.5", "5s", "Fri, 23 Oct 2026 12:00:05 PST", "2026-10-23T12:00:05Z"]) {
    assert.equal(retryAfterMs(value, NOW), undefined, `${JSON.stringify(value)} is not a Retry-After value`);
  }
});

test("a retryable status is retried with the backoff until an attempt succeeds, each attempt sends the same request under its own deadline, and the success comes back with its body and the attempt count", async () => {
  const { waits, policy } = recordingPolicy();
  const { sent, fetchImpl } = scriptedFetch([answer(503), answer(502), answer(500), answer(200, {}, '{"ok":true}')]);
  const exchange = await exchangeWithRetries(fetchImpl, TARGET, { method: "POST", body: "grant_type=client_credentials" }, policy);
  assert.deepEqual(
    { kind: exchange.kind, status: exchange.response.status, text: exchange.text, attempts: exchange.attempts, refused: exchange.refusedRetryAfterMs },
    { kind: "response", status: 200, text: '{"ok":true}', attempts: 4, refused: undefined },
  );
  assert.deepEqual(waits, [1_000, 2_000, 4_000]);
  assert.equal(sent.length, 4);
  for (const { url, init } of sent) {
    assert.deepEqual({ url, method: init.method, body: init.body }, { url: TARGET, method: "POST", body: "grant_type=client_credentials" });
    assert.ok(init.signal instanceof AbortSignal && !init.signal.aborted, "every attempt carries a live deadline signal");
  }
  assert.equal(new Set(sent.map(({ init }) => init.signal)).size, 4, "each attempt gets a deadline of its own");
});

test("a retryable status that persists comes back as the last answer, body included, after four attempts, and any other status comes back at once even with a Retry-After", async () => {
  for (const status of CLOUD_RETRYABLE_STATUSES) {
    const { waits, policy } = recordingPolicy();
    const { sent, fetchImpl } = scriptedFetch([answer(status, {}, `body of ${status}`)]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual(
      { kind: exchange.kind, status: exchange.response.status, text: exchange.text, attempts: exchange.attempts, sent: sent.length, waits },
      { kind: "response", status, text: `body of ${status}`, attempts: 4, sent: 4, waits: [1_000, 2_000, 4_000] },
      `${status} is retried`,
    );
    assert.equal(retryStopNote(exchange), " after 4 attempts");
  }
  for (const status of [200, 400, 401, 403, 404, 409, 501, 505]) {
    const { waits, policy } = recordingPolicy();
    const { sent, fetchImpl } = scriptedFetch([answer(status, { "retry-after": "1" }, "once")]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual(
      { status: exchange.response.status, text: exchange.text, attempts: exchange.attempts, sent: sent.length, waits },
      { status, text: "once", attempts: 1, sent: 1, waits: [] },
      `${status} is not retried`,
    );
    assert.equal(retryStopNote(exchange), "");
  }
});

test("Retry-After sets the wait in place of the backoff, as delta-seconds or an HTTP-date, up to and including the 30 s limit; a value that is neither form leaves the backoff in place", async () => {
  const cases = [
    ["delta-seconds", "3", 3_000],
    ["an HTTP-date", new Date(NOW.getTime() + 7_000).toUTCString(), 7_000],
    ["a date already past", new Date(NOW.getTime() - 60_000).toUTCString(), 0],
    ["exactly the limit", "30", 30_000],
    ["an unreadable value", "later", 1_000],
  ];
  for (const [label, retryAfter, wait] of cases) {
    const { waits, policy } = recordingPolicy();
    const { fetchImpl } = scriptedFetch([answer(429, { "retry-after": retryAfter }), answer(200, {}, "{}")]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual({ status: exchange.response.status, attempts: exchange.attempts, waits }, { status: 200, attempts: 2, waits: [wait] }, label);
  }
});

test("a Retry-After above 30 s ends the retries at once, without waiting, and the stop note names the wait the server asked for", async () => {
  {
    const { waits, policy } = recordingPolicy();
    const { sent, fetchImpl } = scriptedFetch([answer(429, { "retry-after": "31" }, "slow down")]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual(
      { status: exchange.response.status, text: exchange.text, attempts: exchange.attempts, refused: exchange.refusedRetryAfterMs, sent: sent.length, waits },
      { status: 429, text: "slow down", attempts: 1, refused: 31_000, sent: 1, waits: [] },
    );
    assert.equal(retryStopNote(exchange), " (the server asked to retry after 31 s, more than the 30 s limit)");
  }
  {
    const { waits, policy } = recordingPolicy();
    const { sent, fetchImpl } = scriptedFetch([answer(503), answer(503, { "retry-after": new Date(NOW.getTime() + 120_000).toUTCString() })]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual(
      { attempts: exchange.attempts, refused: exchange.refusedRetryAfterMs, sent: sent.length, waits },
      { attempts: 2, refused: 120_000, sent: 2, waits: [1_000] },
    );
    assert.equal(retryStopNote(exchange), " after 2 attempts (the server asked to retry after 120 s, more than the 30 s limit)");
  }
});

test("a transport failure, or a lower layer's own TimeoutError, is retried with the backoff and comes back as the last failure once the attempts run out; any other rejection comes back at once", async () => {
  {
    const thrown = [];
    const { waits, policy } = recordingPolicy();
    const { sent, fetchImpl } = scriptedFetch([rejectWith(() => {
      const error = new TypeError("fetch failed");
      thrown.push(error);
      return error;
    })]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual(
      { kind: exchange.kind, timedOut: exchange.timedOut, attempts: exchange.attempts, sent: sent.length, waits },
      { kind: "failure", timedOut: false, attempts: 4, sent: 4, waits: [1_000, 2_000, 4_000] },
    );
    assert.equal(exchange.error, thrown.at(-1), "the last attempt's error comes back");
  }
  {
    const { waits, policy } = recordingPolicy();
    const { fetchImpl } = scriptedFetch([
      rejectWith(() => Object.assign(new Error("The operation was aborted due to timeout"), { name: "TimeoutError" })),
      rejectWith(() => new TypeError("fetch failed")),
      answer(200, {}, "{}"),
    ]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual({ status: exchange.response.status, attempts: exchange.attempts, waits }, { status: 200, attempts: 3, waits: [1_000, 2_000] });
  }
  for (const error of [new Error("unexpected"), new RangeError("invalid header value"), new SyntaxError("Unexpected token < in JSON")]) {
    const { waits, policy } = recordingPolicy();
    const { sent, fetchImpl } = scriptedFetch([rejectWith(() => error)]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.equal(exchange.error, error, error.name);
    assert.deepEqual(
      { kind: exchange.kind, timedOut: exchange.timedOut, attempts: exchange.attempts, sent: sent.length, waits },
      { kind: "failure", timedOut: false, attempts: 1, sent: 1, waits: [] },
      `${error.name} is not retried`,
    );
  }
});

test("an attempt that runs past its timeout is cut off and retried whether the request hangs, honours its signal, or stalls in a 2xx body; an error status whose body stalls still comes back as that status", async () => {
  {
    const { waits, policy } = recordingPolicy({ requestTimeoutMs: 20 });
    const { sent, fetchImpl } = scriptedFetch([() => new Promise(() => {})]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual(
      { kind: exchange.kind, timedOut: exchange.timedOut, attempts: exchange.attempts, sent: sent.length, waits },
      { kind: "failure", timedOut: true, attempts: 4, sent: 4, waits: [1_000, 2_000, 4_000] },
    );
    assert.deepEqual({ name: exchange.error.name, message: exchange.error.message }, { name: "TimeoutError", message: "The request did not complete within 20 ms." });
  }
  {
    const { policy } = recordingPolicy({ requestTimeoutMs: 20 });
    const honoursSignal = (init) => new Promise((resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true }));
    const { fetchImpl } = scriptedFetch([honoursSignal, answer(200, {}, "{}")]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual({ status: exchange.response.status, attempts: exchange.attempts }, { status: 200, attempts: 2 });
  }
  {
    const { policy } = recordingPolicy({ requestTimeoutMs: 20 });
    const { fetchImpl } = scriptedFetch([stalledBody(200), answer(200, {}, '{"ok":true}')]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual({ text: exchange.text, attempts: exchange.attempts }, { text: '{"ok":true}', attempts: 2 }, "a 2xx body that stalls is a timed-out attempt");
  }
  {
    const { waits, policy } = recordingPolicy({ requestTimeoutMs: 20 });
    const { sent, fetchImpl } = scriptedFetch([stalledBody(403)]);
    const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    assert.deepEqual(
      { kind: exchange.kind, status: exchange.response.status, text: exchange.text, attempts: exchange.attempts, sent: sent.length, waits },
      { kind: "response", status: 403, text: "", attempts: 1, sent: 1, waits: [] },
    );
  }
  assert.equal(timeoutReason(CLOUD_REQUEST_TIMEOUT_MS), "TimeoutError: the request did not complete within 30 s");
  assert.equal(timeoutReason(20), "TimeoutError: the request did not complete within 20 ms");
});

test("a transport that hands back its Response directly instead of a promise is read and retried like any other", async () => {
  const { waits, policy } = recordingPolicy();
  const answers = [answer(503), answer(200, {}, '{"ok":true}')];
  let sent = 0;
  const exchange = await exchangeWithRetries(() => answers[sent++](), TARGET, {}, policy);
  assert.deepEqual(
    { kind: exchange.kind, status: exchange.response.status, text: exchange.text, attempts: exchange.attempts, waits },
    { kind: "response", status: 200, text: '{"ok":true}', attempts: 2, waits: [1_000] },
  );
});

test("each attempt's timer is cleared when the attempt settles, so a finished exchange leaves no timer behind to hold the process open", async () => {
  const timers = () => process.getActiveResourcesInfo().filter((type) => type === "Timeout").length;
  const before = timers();
  const { policy } = recordingPolicy();
  const { fetchImpl } = scriptedFetch([answer(503), rejectWith(() => new TypeError("fetch failed")), answer(200, {}, "{}")]);
  const exchange = await exchangeWithRetries(fetchImpl, TARGET, {}, policy);
  assert.equal(exchange.attempts, 3);
  assert.equal(timers(), before);
});

test("the tool call's abort is never retried: it rejects with ToolCallAbortedError during the wait before a retry, during a request, or when a failure lands with the abort, and no further request is sent", async () => {
  {
    const controller = new AbortController();
    let waitStarted;
    const waiting = new Promise((resolve) => {
      waitStarted = resolve;
    });
    const policy = cloudRetryPolicy({
      signal: controller.signal,
      sleepImpl: () => {
        waitStarted();
        return new Promise(() => {});
      },
    });
    const { sent, fetchImpl } = scriptedFetch([answer(503)]);
    const exchanging = exchangeWithRetries(fetchImpl, TARGET, {}, policy);
    await waiting;
    const reason = new Error("operator stopped the call");
    controller.abort(reason);
    await assert.rejects(exchanging, (error) => error instanceof ToolCallAbortedError && error.cause === reason);
    assert.equal(sent.length, 1, "the abort ended the wait before the retry");
  }
  {
    const controller = new AbortController();
    let requestStarted;
    const started = new Promise((resolve) => {
      requestStarted = resolve;
    });
    const { waits, policy } = recordingPolicy({ signal: controller.signal });
    const { sent, fetchImpl } = scriptedFetch([() => {
      requestStarted();
      return new Promise(() => {});
    }]);
    const exchanging = exchangeWithRetries(abortableFetch(fetchImpl, controller.signal), TARGET, {}, policy);
    await started;
    controller.abort();
    await assert.rejects(exchanging, { name: "ToolCallAbortedError" });
    assert.deepEqual({ sent: sent.length, waits }, { sent: 1, waits: [] });
  }
  {
    const controller = new AbortController();
    const { waits, policy } = recordingPolicy({ signal: controller.signal });
    const { sent, fetchImpl } = scriptedFetch([() => {
      controller.abort();
      throw new TypeError("fetch failed");
    }]);
    await assert.rejects(exchangeWithRetries(fetchImpl, TARGET, {}, policy), { name: "ToolCallAbortedError" });
    assert.deepEqual({ sent: sent.length, waits }, { sent: 1, waits: [] });
  }
});

test("cloudRetryPolicy defaults to the 30 s timeout and the real clock, and refuses a timeout that is not a positive number of milliseconds", () => {
  const policy = cloudRetryPolicy();
  assert.equal(policy.requestTimeoutMs, CLOUD_REQUEST_TIMEOUT_MS);
  assert.equal(policy.signal, undefined);
  assert.ok(Math.abs(policy.now().getTime() - Date.now()) < 1_000);
  for (const requestTimeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => cloudRetryPolicy({ requestTimeoutMs }), /^Error: requestTimeoutMs must be a positive number of milliseconds/, String(requestTimeoutMs));
  }
});

test("attemptsNote stays empty for a single attempt, and retryStopNote adds a refused wait rounded up to whole seconds", () => {
  assert.equal(attemptsNote(1), "");
  assert.equal(attemptsNote(2), " after 2 attempts");
  assert.equal(attemptsNote(CLOUD_MAX_RETRIES + 1), " after 4 attempts");
  assert.equal(retryStopNote({ attempts: 1 }), "");
  assert.equal(retryStopNote({ attempts: 3 }), " after 3 attempts");
  assert.equal(retryStopNote({ attempts: 1, refusedRetryAfterMs: 30_500 }), " (the server asked to retry after 31 s, more than the 30 s limit)");
  assert.equal(retryStopNote({ attempts: 2, refusedRetryAfterMs: 3_600_000 }), " after 2 attempts (the server asked to retry after 3600 s, more than the 30 s limit)");
});

test("unansweredProbesNote says nothing when every probe got an answer, and otherwise names the probes and calls their readability unknown", () => {
  assert.deepEqual(unansweredProbesNote([]), []);
  assert.deepEqual(unansweredProbesNote(["projects"]), [
    "This check is incomplete: the probes for projects ran out of retries without an answer (each surface records its last error), so whether that surface is readable is unknown.",
  ]);
  assert.deepEqual(unansweredProbesNote(["organization", "log_sinks"]), [
    "This check is incomplete: the probes for organization, log_sinks ran out of retries without an answer (each surface records its last error), so whether those surfaces are readable is unknown.",
  ]);
});
