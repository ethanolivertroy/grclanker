import test from "node:test";
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";

import {
  cachedFetch,
  clearGrcSharedCachesForTests,
  mapWithConcurrency,
  setGrcFetchTimingForTests,
  throttledFetch,
} from "../dist/extensions/grc-tools/shared.js";

test("mapWithConcurrency returns results in input order and runs at most `limit` items at once", async () => {
  let running = 0;
  let peak = 0;
  const results = await mapWithConcurrency([30, 5, 20, 10, 1, 15], 3, async (delay, index) => {
    running += 1;
    peak = Math.max(peak, running);
    await sleep(delay);
    running -= 1;
    return `${index}:${delay}`;
  });

  assert.deepEqual(results, ["0:30", "1:5", "2:20", "3:10", "4:1", "5:15"]);
  assert.equal(peak, 3);
  assert.deepEqual(await mapWithConcurrency([], 3, async () => assert.fail("there is no item to run")), []);
});

test("once a worker fails, mapWithConcurrency starts no further item and rejects with the first failure after the running items settle", async () => {
  const started = [];
  const settled = [];
  const failure = new Error("item 1 failed");
  const mapping = mapWithConcurrency([0, 1, 2, 3, 4, 5, 6, 7], 3, async (item) => {
    started.push(item);
    await sleep(item === 1 ? 5 : 25);
    settled.push(item);
    if (item === 1) throw failure;
    if (item === 2) throw new Error("item 2 failed later");
    return item;
  });

  await assert.rejects(mapping, (error) => error === failure);
  assert.deepEqual(started, [0, 1, 2]);
  assert.deepEqual(settled.sort((left, right) => left - right), [0, 1, 2]);
});

const DATA_URL = "https://data.example/api/items.json?cve=CVE-2024-3400";
const DATA_ENDPOINT = "https://data.example/api/items.json";
const START_MS = Date.parse("2026-10-23T00:00:00Z");

/**
 * Runs `run` with each request answered by `respond(attempt, init)` and a
 * virtual clock: every wait the fetch helpers take is recorded and advances
 * the clock instead of sleeping.
 */
async function withFetch(respond, run) {
  const originalFetch = globalThis.fetch;
  const requests = [];
  const waits = [];
  let clock = START_MS;
  globalThis.fetch = async (input, init) => {
    requests.push(String(input));
    return respond(requests.length, init);
  };
  setGrcFetchTimingForTests({
    now: () => clock,
    sleep: async (ms) => {
      waits.push(ms);
      clock += ms;
    },
  });
  clearGrcSharedCachesForTests();
  try {
    await run({ requests, waits });
  } finally {
    globalThis.fetch = originalFetch;
    setGrcFetchTimingForTests();
    clearGrcSharedCachesForTests();
  }
}

function failure(status, statusText, headers = {}) {
  return new Response("upstream error", { status, statusText, headers });
}

function hangUntilAborted(init) {
  return new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true }));
}

const nextTurn = () => new Promise((resolve) => setImmediate(resolve));

test("cachedFetch retries 429, 500, 502, 503, and 504 with exponential backoff", async () => {
  for (const status of [429, 500, 502, 503, 504]) {
    await withFetch(
      (attempt) => (attempt < 4 ? failure(status, "Busy") : Response.json({ status })),
      async ({ requests, waits }) => {
        assert.deepEqual(await cachedFetch(DATA_URL), { status }, `status ${status}`);
        assert.equal(requests.length, 4, `status ${status}`);
        assert.deepEqual(waits, [1_000, 2_000, 4_000], `status ${status}`);
      },
    );
  }
});

test("cachedFetch retries a transport failure", async () => {
  await withFetch(
    (attempt) => (attempt === 1 ? Promise.reject(new TypeError("fetch failed")) : Response.json({ ok: true })),
    async ({ requests, waits }) => {
      assert.deepEqual(await cachedFetch(DATA_URL), { ok: true });
      assert.equal(requests.length, 2);
      assert.deepEqual(waits, [1_000]);
    },
  );
});

test("cachedFetch ends an attempt that runs for 30 s and retries it", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let firstAttemptStarted;
  const started = new Promise((resolve) => (firstAttemptStarted = resolve));

  await withFetch(
    (attempt, init) => {
      if (attempt > 1) return Response.json({ ok: true });
      firstAttemptStarted();
      return hangUntilAborted(init);
    },
    async ({ requests, waits }) => {
      const pending = cachedFetch(DATA_URL);
      await started;
      t.mock.timers.tick(29_999);
      await nextTurn();
      assert.equal(requests.length, 1, "the first attempt is still running before 30 s");
      t.mock.timers.tick(1);
      assert.deepEqual(await pending, { ok: true });
      assert.equal(requests.length, 2);
      assert.deepEqual(waits, [1_000]);
    },
  );
});

test("cachedFetch reports an endpoint that timed out on every attempt", async () => {
  await withFetch(
    () => Promise.reject(new DOMException("The operation was aborted due to timeout", "TimeoutError")),
    async ({ requests, waits }) => {
      await assert.rejects(cachedFetch(DATA_URL), {
        message: `Fetch failed: ${DATA_ENDPOINT} (timed out after 30000 ms) after 4 attempts`,
      });
      assert.equal(requests.length, 4);
      assert.deepEqual(waits, [1_000, 2_000, 4_000]);
    },
  );
});

test("cachedFetch waits as long as Retry-After asks, in seconds or as an HTTP date on the injected clock, up to 30 s", async () => {
  await withFetch(
    (attempt) => {
      if (attempt === 1) return failure(503, "Service Unavailable", { "retry-after": "7" });
      // The clock has moved 7 s by the second attempt, so this date is 12 s away.
      if (attempt === 2) return failure(429, "Too Many Requests", { "retry-after": new Date(START_MS + 19_000).toUTCString() });
      if (attempt === 3) return failure(503, "Service Unavailable", { "retry-after": "30" });
      return Response.json({ ok: true });
    },
    async ({ requests, waits }) => {
      assert.deepEqual(await cachedFetch(DATA_URL), { ok: true });
      assert.equal(requests.length, 4);
      assert.deepEqual(waits, [7_000, 12_000, 30_000]);
    },
  );
});

test("cachedFetch fails closed without waiting when Retry-After asks for more than 30 s", async () => {
  const cases = [
    [{ "retry-after": "120" }, "120 s"],
    [{ "retry-after": new Date(START_MS + 5 * 60_000).toUTCString() }, "300 s"],
  ];
  for (const [headers, asked] of cases) {
    await withFetch(
      () => failure(429, "Too Many Requests", headers),
      async ({ requests, waits }) => {
        await assert.rejects(cachedFetch(DATA_URL), {
          message:
            `Fetch failed: ${DATA_ENDPOINT} (429 Too Many Requests; the server asked to wait ${asked} ` +
            "before retrying, longer than the 30 s limit)",
        });
        assert.equal(requests.length, 1, asked);
        assert.deepEqual(waits, [], asked);
      },
    );
  }
});

test("cachedFetch reports the last status and the attempt count without the query string once retries run out", async () => {
  await withFetch(
    () => failure(502, "Bad Gateway"),
    async ({ requests, waits }) => {
      await assert.rejects(cachedFetch(DATA_URL), {
        message: `Fetch failed: ${DATA_ENDPOINT} (502 Bad Gateway) after 4 attempts`,
      });
      assert.deepEqual(requests, [DATA_URL, DATA_URL, DATA_URL, DATA_URL]);
      assert.deepEqual(waits, [1_000, 2_000, 4_000]);
    },
  );
});

test("cachedFetch does not retry a 404 or another client error", async () => {
  for (const [status, statusText] of [[400, "Bad Request"], [403, "Forbidden"], [404, "Not Found"]]) {
    await withFetch(
      () => failure(status, statusText),
      async ({ requests, waits }) => {
        await assert.rejects(cachedFetch(DATA_URL), { message: `Fetch failed: ${DATA_ENDPOINT} (${status} ${statusText})` });
        assert.equal(requests.length, 1, `status ${status}`);
        assert.deepEqual(waits, [], `status ${status}`);
      },
    );
  }
});

test("cachedFetch never caches a failure, and caches the next success", async () => {
  await withFetch(
    (attempt) => (attempt <= 4 ? failure(503, "Service Unavailable") : Response.json({ attempt })),
    async ({ requests }) => {
      await assert.rejects(cachedFetch(DATA_URL), /after 4 attempts$/);
      assert.deepEqual(await cachedFetch(DATA_URL), { attempt: 5 });
      assert.deepEqual(await cachedFetch(DATA_URL), { attempt: 5 });
      assert.equal(requests.length, 5);
    },
  );
});

test("cachedFetch describes an unreadable 200 body without echoing it and does not retry it", async () => {
  await withFetch(
    () => new Response("<html>session=abc123</html>", { status: 200, headers: { "content-type": "text/html" } }),
    async ({ requests }) => {
      await assert.rejects(cachedFetch(DATA_URL), {
        message: `Fetch failed: ${DATA_ENDPOINT} (unreadable JSON: non-JSON body (text/html, 27 bytes))`,
      });
      assert.equal(requests.length, 1);
    },
  );
});

test("cachedFetch leaves a reason phrase that is not plain text out of the error", async () => {
  await withFetch(
    () => failure(404, "Not Found password=hunter2"),
    async () => {
      await assert.rejects(cachedFetch(DATA_URL), { message: `Fetch failed: ${DATA_ENDPOINT} (404)` });
    },
  );
});

test("an abort during a retry wait ends cachedFetch at once without another request", async () => {
  const controller = new AbortController();
  await withFetch(
    () => failure(503, "Service Unavailable"),
    async ({ requests }) => {
      const waits = [];
      setGrcFetchTimingForTests({
        sleep: (ms) => {
          waits.push(ms);
          setImmediate(() => controller.abort());
          return new Promise(() => {});
        },
      });
      await assert.rejects(cachedFetch(DATA_URL, undefined, controller.signal), { name: "ToolCallAbortedError" });
      await nextTurn();
      assert.equal(requests.length, 1);
      assert.deepEqual(waits, [1_000]);
    },
  );
});

test("an abort during a request ends cachedFetch without a retry", async () => {
  const controller = new AbortController();
  await withFetch(
    (_attempt, init) => {
      setImmediate(() => controller.abort());
      return hangUntilAborted(init);
    },
    async ({ requests, waits }) => {
      await assert.rejects(cachedFetch(DATA_URL, undefined, controller.signal), { name: "ToolCallAbortedError" });
      await nextTurn();
      assert.equal(requests.length, 1);
      assert.deepEqual(waits, []);
    },
  );
});

test("throttledFetch spaces requests to one origin and retries on the same terms as cachedFetch", async () => {
  await withFetch(
    (attempt) => (attempt === 2 ? failure(503, "Service Unavailable") : Response.json({ attempt })),
    async ({ requests, waits }) => {
      assert.deepEqual(await throttledFetch(DATA_URL), { attempt: 1 });
      assert.deepEqual(await throttledFetch(DATA_URL), { attempt: 3 });
      assert.equal(requests.length, 3);
      // 100 ms after the first request, then the backoff, which already spaces the retry.
      assert.deepEqual(waits, [100, 1_000]);
    },
  );
});
