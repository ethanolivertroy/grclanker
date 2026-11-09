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
      assert.ok(result.content[0].text.startsWith('Found 1 active FIPS module(s) matching "acme".\n'));
      assert.match(result.content[0].text, /Catalog size: 1 modules across all vendors; matching this query: 1; returned: 1/);
      assert.match(result.content[0].text, /^Certificate #4282 - Acme Crypto Library$/m);
      assert.deepEqual(result.details, { query: "acme", count: 1, total_matches: 1, catalog_count: 1, source: "active" });
      assert.deepEqual(requests, [`${API}/modules.json`, `${API}/modules.json`]);
      assert.deepEqual(waits, [1_000]);
    },
  );
});

const SEARCH_TOOLS = [
  { name: "cmvp_search_modules", source: "active" },
  { name: "cmvp_search_historical", source: "historical" },
  { name: "cmvp_search_in_process", source: "in_process" },
];

function searchCatalog() {
  const modules = Array.from({ length: 12 }, (_, index) => ({
    ...ACTIVE_MODULES.modules[0],
    "Certificate Number": String(4282 + index),
    "Module Name": `Acme Crypto Library ${index}`,
  }));
  modules.push({ ...ACTIVE_MODULES.modules[0], "Module Name": "Other Library", "Vendor Name": "Other Vendor" });
  return {
    metadata: {
      ...ACTIVE_MODULES.metadata,
      total_modules: 4315,
      total_historical_modules: 4315,
      total_modules_in_process: 4315,
    },
    modules,
    modules_in_process: modules.map((module) => ({
      "Module Name": module["Module Name"],
      "Vendor Name": module["Vendor Name"],
      Standard: "FIPS 140-3",
      Status: "In Review",
    })),
  };
}

for (const { name, source } of SEARCH_TOOLS) {
  test(`${name} distinguishes returned records, all matching records, and the catalog total`, async () => {
    await withCmvpApi(() => Response.json(searchCatalog()), async ({ tools }) => {
      const result = await tools.get(name).execute("limited", { query: "acme", limit: 2 });
      assert.equal(result.isError, undefined);
      assert.match(result.content[0].text, /^Showing 2 of 12 /);
      assert.match(result.content[0].text, /Catalog size: 4315 modules across all vendors; matching this query: 12; returned: 2/);
      assert.deepEqual(result.details, { query: "acme", count: 2, total_matches: 12, catalog_count: 4315, source });
      assert.match(result.content[0].text, /Acme Crypto Library 0/);
      assert.match(result.content[0].text, /Acme Crypto Library 1/);
      assert.doesNotMatch(result.content[0].text, /Acme Crypto Library 2/);
      assert.doesNotMatch(result.content[0].text, /Other Library/);
    });
  });

  test(`${name} normalizes nonpositive limits instead of reporting false empty or shortened results`, async () => {
    await withCmvpApi(() => Response.json(searchCatalog()), async ({ tools }) => {
      for (const limit of [undefined, 0, -1, -0.5, 0.9, NaN, Infinity]) {
        const result = await tools.get(name).execute("default-limit", { query: "acme", limit });
        assert.equal(result.details.count, 10, `limit ${limit}`);
        assert.equal(result.details.total_matches, 12, `limit ${limit}`);
        assert.match(result.content[0].text, /^Showing 10 of 12 /);
      }
      const fractional = await tools.get(name).execute("fractional-limit", { query: "acme", limit: 1.9 });
      assert.equal(fractional.details.count, 1);
      assert.equal(fractional.details.total_matches, 12);
    });
  });

  test(`${name} qualifies an empty phrase search and can find matches on a broader retry`, async () => {
    await withCmvpApi(() => Response.json(searchCatalog()), async ({ tools }) => {
      const query = "Acme Crypto Library future-version";
      const empty = await tools.get(name).execute("narrow", { query });
      assert.equal(empty.isError, undefined);
      assert.match(empty.content[0].text, /No matches for this phrase do not establish/);
      assert.match(empty.content[0].text, /broader vendor or module name/);
      assert.deepEqual(empty.details, { query, count: 0, total_matches: 0, catalog_count: 4315, source });

      const broad = await tools.get(name).execute("broad", { query: "acme", limit: 20 });
      assert.equal(broad.details.count, 12);
      assert.equal(broad.details.total_matches, 12);
      assert.equal(broad.details.catalog_count, 4315);
      assert.match(broad.content[0].text, /^Found 12 /);
    });
  });
}

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
