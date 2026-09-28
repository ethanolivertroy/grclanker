import test from "node:test";
import assert from "node:assert/strict";

import { registerKevsTools } from "../dist/extensions/grc-tools/kevs.js";
import { clearGrcSharedCachesForTests } from "../dist/extensions/grc-tools/shared.js";

const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const EPSS_DATE = "2024-05-01";

function kevEntry(index) {
  const id = `CVE-2024-${String(index).padStart(4, "0")}`;
  return {
    cveID: id,
    vendorProject: "Acme",
    product: `Gateway ${index}`,
    vulnerabilityName: `Acme Gateway ${index} Command Injection`,
    dateAdded: "2024-05-01",
    shortDescription: `Acme Gateway ${index} allows remote command injection.`,
    requiredAction: "Apply mitigations per vendor instructions.",
    dueDate: "2024-05-22",
    knownRansomwareCampaignUse: "Unknown",
    notes: `https://acme.example/advisories/${index}`,
  };
}

function expectedBlock(index) {
  const entry = kevEntry(index);
  return [
    `${entry.cveID} - ${entry.vulnerabilityName}`,
    `  Vendor:      ${entry.vendorProject}`,
    `  Product:     ${entry.product}`,
    `  Added:       ${entry.dateAdded}`,
    `  Due:         ${entry.dueDate}`,
    `  Ransomware:  ${entry.knownRansomwareCampaignUse}`,
    `  Action:      ${entry.requiredAction}`,
    `  Description: ${entry.shortDescription}`,
    `  EPSS:        12.5% probability (90.0th percentile), scored ${EPSS_DATE}`,
    `  Notes:       ${entry.notes}`,
  ].join("\n");
}

function scoreDates(count) {
  return Object.fromEntries(Array.from({ length: count }, (_, index) => [kevEntry(index + 1).cveID, EPSS_DATE]));
}

async function runSearch(args, matchCount) {
  const vulnerabilities = Array.from({ length: matchCount }, (_, index) => kevEntry(index + 1));
  const catalog = { title: "KEV", catalogVersion: "1", dateReleased: "2024-05-01", count: matchCount, vulnerabilities };
  const tools = new Map();
  registerKevsTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const tool = tools.get("kevs_search");

  clearGrcSharedCachesForTests();
  const originalFetch = globalThis.fetch;
  const epssRequests = [];
  globalThis.fetch = async (url) => {
    const href = String(url);
    if (href === KEV_URL) return new Response(JSON.stringify(catalog));
    const cves = new URL(href).searchParams.get("cve").split(",");
    epssRequests.push(cves);
    return new Response(JSON.stringify({
      status: "OK",
      total: cves.length,
      data: cves.map((cve) => ({ cve, epss: "0.125", percentile: "0.9", date: EPSS_DATE })),
    }));
  };
  try {
    const result = await tool.execute("call-1", tool.prepareArguments(args));
    return { tool, result, text: result.content[0].text, epssRequests };
  } finally {
    globalThis.fetch = originalFetch;
    clearGrcSharedCachesForTests();
  }
}

test("kevs_search caps an oversized limit at 50 results and says how many matched", async () => {
  const { result, text, epssRequests } = await runSearch({ query: "acme", limit: 10000 }, 120);
  const [heading, ...rest] = text.split("\n\n");

  assert.equal(
    heading,
    'Showing 50 of 120 KEV entries matching "acme" (catalog size: 120). Results are capped at 50; narrow the query to a CVE ID, vendor, or product to see the rest.',
  );
  assert.equal(rest.length, 50);
  assert.equal(rest[0], expectedBlock(1), "the first retained entry renders every field");
  assert.equal(rest[49], expectedBlock(50), "the last retained entry renders every field");
  assert.ok(!text.includes("CVE-2024-0051"), "entries beyond the cap are not rendered");
  assert.deepEqual(result.details, { query: "acme", count: 50, total_matches: 120, capped: true, epss_score_dates: scoreDates(50) });
  assert.deepEqual(epssRequests.flat().length, 50, "EPSS is only requested for shown entries");
});

test("kevs_search output is unchanged when the cap does not remove results", async () => {
  const byDefault = await runSearch({ query: "acme" }, 120);
  assert.ok(byDefault.text.startsWith('Found 10 KEV entries matching "acme" (catalog size: 120):\n\n'));
  assert.equal(byDefault.text.split("\n\n").length, 11);
  assert.deepEqual(byDefault.result.details, { query: "acme", count: 10, epss_score_dates: scoreDates(10) });

  const atBound = await runSearch({ query: "acme", limit: 50 }, 120);
  assert.ok(atBound.text.startsWith('Found 50 KEV entries matching "acme" (catalog size: 120):\n\n'));
  assert.deepEqual(atBound.result.details, { query: "acme", count: 50, epss_score_dates: scoreDates(50) });

  const fewMatches = await runSearch({ query: "acme", limit: 10000 }, 3);
  assert.ok(fewMatches.text.startsWith('Found 3 KEV entries matching "acme" (catalog size: 3):\n\n'));
  assert.equal(fewMatches.text.split("\n\n").at(-1), expectedBlock(3));
  assert.deepEqual(fewMatches.result.details, { query: "acme", count: 3, epss_score_dates: scoreDates(3) });
});

test("kevs_search treats zero, negative, and sub-1 limits as the default of 10", async () => {
  for (const limit of [0, -1, -10000, 0.5, "0", "-1"]) {
    const { result, text } = await runSearch({ query: "acme", limit }, 120);
    const label = `limit ${JSON.stringify(limit)}`;
    assert.ok(text.startsWith('Found 10 KEV entries matching "acme" (catalog size: 120):\n\n'), label);
    assert.equal(text.split("\n\n").length, 11, label);
    assert.equal(text.split("\n\n").at(-1), expectedBlock(10), label);
    assert.deepEqual(result.details, { query: "acme", count: 10, epss_score_dates: scoreDates(10) }, label);
  }
});

test("kevs_search honors the smallest positive limit and truncates fractional limits", async () => {
  const one = await runSearch({ query: "acme", limit: 1 }, 120);
  assert.equal(one.text, `Found 1 KEV entry matching "acme" (catalog size: 120):\n\n${expectedBlock(1)}`);

  const fractionalAtBound = await runSearch({ query: "acme", limit: 50.9 }, 120);
  assert.ok(fractionalAtBound.text.startsWith('Found 50 KEV entries matching "acme" (catalog size: 120):\n\n'));
  assert.deepEqual(fractionalAtBound.result.details, { query: "acme", count: 50, epss_score_dates: scoreDates(50) });

  const justOver = await runSearch({ query: "acme", limit: 51 }, 120);
  assert.ok(justOver.text.startsWith("Showing 50 of 120 KEV entries"));
  assert.deepEqual(justOver.result.details, { query: "acme", count: 50, total_matches: 120, capped: true, epss_score_dates: scoreDates(50) });
});

test("kevs_search advertises both limit bounds in its schema", async () => {
  const { tool } = await runSearch({ query: "acme" }, 1);
  const limit = tool.parameters.properties.limit;
  assert.equal(limit.default, 10);
  assert.equal(
    limit.description,
    "Maximum results to show (default: 10). Values below 1 use the default; values above 50 are capped at 50, so narrow the query instead of raising it.",
  );
  assert.equal(limit.minimum, undefined, "out-of-range limits are normalized, not rejected by schema validation");
  assert.equal(limit.maximum, undefined, "out-of-range limits are normalized, not rejected by schema validation");
});

const KEV_CATALOG = {
  title: "CISA Catalog of Known Exploited Vulnerabilities",
  catalogVersion: "2026.09.27",
  dateReleased: "2026-09-27T00:00:00.000Z",
  count: 2,
  vulnerabilities: [
    {
      cveID: "CVE-2024-3400",
      vendorProject: "Palo Alto Networks",
      product: "PAN-OS",
      vulnerabilityName: "PAN-OS Command Injection Vulnerability",
      dateAdded: "2024-04-12",
      shortDescription: "Command injection in GlobalProtect.",
      requiredAction: "Apply mitigations per vendor instructions.",
      dueDate: "2024-04-19",
      knownRansomwareCampaignUse: "Unknown",
      notes: "",
    },
    {
      cveID: "CVE-2023-0001",
      vendorProject: "Example",
      product: "Widget",
      vulnerabilityName: "Widget Example Vulnerability",
      dateAdded: "2023-01-10",
      shortDescription: "Example issue.",
      requiredAction: "Apply updates.",
      dueDate: "2023-01-31",
      knownRansomwareCampaignUse: "Unknown",
      notes: "",
    },
  ],
};

const EPSS_ENTRIES = {
  "CVE-2024-3400": { cve: "CVE-2024-3400", epss: "0.94321", percentile: "0.99912", date: "2026-09-27" },
  "CVE-2023-0001": { cve: "CVE-2023-0001", epss: "0.01000", percentile: "0.50000" },
};

function loadKevsTools() {
  const tools = new Map();
  registerKevsTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  return tools;
}

async function withMockedFetch(run) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.hostname === "raw.githubusercontent.com") {
      return Response.json(KEV_CATALOG);
    }
    if (url.hostname === "api.first.org") {
      const cves = (url.searchParams.get("cve") ?? "").split(",");
      const data = cves.map((cve) => EPSS_ENTRIES[cve]).filter(Boolean);
      return Response.json({ status: "OK", total: data.length, data });
    }
    return new Response("not found", { status: 404, statusText: "Not Found" });
  };
  clearGrcSharedCachesForTests();

  try {
    await run(loadKevsTools());
  } finally {
    globalThis.fetch = originalFetch;
    clearGrcSharedCachesForTests();
  }
}

test("kevs_get_epss shows the EPSS score date when the API provides it", async () => {
  await withMockedFetch(async (tools) => {
    const result = await tools.get("kevs_get_epss").execute("call-1", { cve_ids: ["CVE-2024-3400"] });
    const text = result.content[0].text;

    assert.match(text, /Score Date/);
    assert.match(text, /CVE-2024-3400\s+│\s+94\.32%\s+│\s+99\.9th\s+│\s+2026-09-27/);
    assert.deepEqual(result.details.epss_score_dates, { "CVE-2024-3400": "2026-09-27" });
  });
});

test("kevs_get_epss keeps the original table when no score date is provided", async () => {
  await withMockedFetch(async (tools) => {
    const result = await tools.get("kevs_get_epss").execute("call-2", { cve_ids: ["CVE-2023-0001"] });
    const text = result.content[0].text;

    assert.doesNotMatch(text, /Score Date/);
    assert.match(text, /CVE-2023-0001\s+│\s+1\.00%\s+│\s+50\.0th/);
    assert.deepEqual(result.details, { cve_ids: ["CVE-2023-0001"], count: 1 });
  });
});

test("kevs_search EPSS lines include the score date only when the API provides it", async () => {
  await withMockedFetch(async (tools) => {
    const dated = await tools.get("kevs_search").execute("call-3", { query: "CVE-2024-3400" });
    assert.match(
      dated.content[0].text,
      /EPSS:\s+94\.3% probability \(99\.9th percentile\), scored 2026-09-27/,
    );
    assert.deepEqual(dated.details.epss_score_dates, { "CVE-2024-3400": "2026-09-27" });

    const undated = await tools.get("kevs_search").execute("call-4", { query: "CVE-2023-0001" });
    assert.match(undated.content[0].text, /EPSS:\s+1\.0% probability \(50\.0th percentile\)$/m);
    assert.doesNotMatch(undated.content[0].text, /scored/);
    assert.deepEqual(undated.details, { query: "CVE-2023-0001", count: 1 });
  });
});
