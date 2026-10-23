import test from "node:test";
import assert from "node:assert/strict";

import { registerCmvpTools } from "../dist/extensions/grc-tools/cmvp.js";
import { clearGrcSharedCachesForTests, setGrcFetchTimingForTests } from "../dist/extensions/grc-tools/shared.js";

const API = "https://ethanolivertroy.github.io/nist-cmvp-api/api";

const ACTIVE_MODULES = {
  metadata: {
    generated_at: "2026-10-20T00:00:00Z",
    total_modules: 1,
    total_historical_modules: 0,
    total_modules_in_process: 0,
    source: "NIST CMVP",
    version: "1",
  },
  modules: [
    {
      "Certificate Number": "4282",
      "Vendor Name": "Acme Corp",
      "Module Name": "Acme Crypto Library",
      "Module Type": "Software",
      "Validation Date": "2025-01-15",
      standard: "FIPS 140-3",
      status: "Active",
      overall_level: 1,
    },
  ],
};

function loadCmvpTools() {
  const tools = new Map();
  registerCmvpTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  return tools;
}

/**
 * Runs `run` with each request answered by `respond(url, attempt)`, where
 * `attempt` counts the requests for that URL, on a virtual clock that records
 * every wait instead of sleeping.
 */
async function withCmvpApi(respond, run) {
  const originalFetch = globalThis.fetch;
  const requests = [];
  const waits = [];
  let clock = Date.parse("2026-10-23T00:00:00Z");
  globalThis.fetch = async (input) => {
    const url = String(input);
    requests.push(url);
    return respond(url, requests.filter((request) => request === url).length);
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
    await run({ tools: loadCmvpTools(), requests, waits });
  } finally {
    globalThis.fetch = originalFetch;
    setGrcFetchTimingForTests();
    clearGrcSharedCachesForTests();
  }
}

test("cmvp_search_modules retries a 5xx from the CMVP API and answers from the next successful read", async () => {
  await withCmvpApi(
    (_url, attempt) =>
      attempt === 1 ? new Response("unavailable", { status: 503, statusText: "Service Unavailable" }) : Response.json(ACTIVE_MODULES),
    async ({ tools, requests, waits }) => {
      const result = await tools.get("cmvp_search_modules").execute("call-1", { query: "acme" });

      assert.equal(result.isError, undefined);
      assert.ok(result.content[0].text.startsWith('Found 1 active FIPS module(s) matching "acme" (of 1 total):\n'));
      assert.match(result.content[0].text, /^Certificate #4282 - Acme Crypto Library$/m);
      assert.deepEqual(result.details, { query: "acme", count: 1, source: "active" });
      assert.deepEqual(requests, [`${API}/modules.json`, `${API}/modules.json`]);
      assert.deepEqual(waits, [1_000]);
    },
  );
});

test("cmvp_search_modules reports exhausted retries as an error with the attempt count, never as no matching modules", async () => {
  await withCmvpApi(
    () => new Response("bad gateway", { status: 502, statusText: "Bad Gateway" }),
    async ({ tools, requests, waits }) => {
      const result = await tools.get("cmvp_search_modules").execute("call-1", { query: "acme" });

      assert.equal(result.isError, true);
      assert.equal(result.content[0].text, `CMVP API error: Fetch failed: ${API}/modules.json (502 Bad Gateway) after 4 attempts`);
      assert.doesNotMatch(result.content[0].text, /No active CMVP modules found/);
      assert.deepEqual(result.details, { query: "acme", source: "active" });
      assert.equal(requests.length, 4);
      assert.deepEqual(waits, [1_000, 2_000, 4_000]);
    },
  );
});

test("cmvp_get_module does not report a certificate as missing when the historical list cannot be read", async () => {
  await withCmvpApi(
    (url) =>
      url.endsWith("/historical-modules.json")
        ? new Response("gateway timeout", { status: 504, statusText: "Gateway Timeout" })
        : Response.json(ACTIVE_MODULES),
    async ({ tools, requests }) => {
      const result = await tools.get("cmvp_get_module").execute("call-1", { cert_number: "1234" });

      assert.equal(result.isError, true);
      assert.equal(
        result.content[0].text,
        `CMVP API error: Fetch failed: ${API}/historical-modules.json (504 Gateway Timeout) after 4 attempts`,
      );
      assert.doesNotMatch(result.content[0].text, /No CMVP module found/);
      assert.equal(requests.filter((url) => url === `${API}/historical-modules.json`).length, 4);
    },
  );
});
