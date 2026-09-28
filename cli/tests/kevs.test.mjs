import test from "node:test";
import assert from "node:assert/strict";

import { registerKevsTools } from "../dist/extensions/grc-tools/kevs.js";
import { clearGrcSharedCachesForTests } from "../dist/extensions/grc-tools/shared.js";

const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";

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
    "  EPSS:        12.5% probability (90.0th percentile)",
    `  Notes:       ${entry.notes}`,
  ].join("\n");
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
      data: cves.map((cve) => ({ cve, epss: "0.125", percentile: "0.9", date: "2024-05-01" })),
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
  assert.deepEqual(result.details, { query: "acme", count: 50, total_matches: 120, capped: true });
  assert.deepEqual(epssRequests.flat().length, 50, "EPSS is only requested for shown entries");
});

test("kevs_search output is unchanged when the cap does not remove results", async () => {
  const byDefault = await runSearch({ query: "acme" }, 120);
  assert.ok(byDefault.text.startsWith('Found 10 KEV entries matching "acme" (catalog size: 120):\n\n'));
  assert.equal(byDefault.text.split("\n\n").length, 11);
  assert.deepEqual(byDefault.result.details, { query: "acme", count: 10 });

  const atBound = await runSearch({ query: "acme", limit: 50 }, 120);
  assert.ok(atBound.text.startsWith('Found 50 KEV entries matching "acme" (catalog size: 120):\n\n'));
  assert.deepEqual(atBound.result.details, { query: "acme", count: 50 });

  const fewMatches = await runSearch({ query: "acme", limit: 10000 }, 3);
  assert.ok(fewMatches.text.startsWith('Found 3 KEV entries matching "acme" (catalog size: 3):\n\n'));
  assert.equal(fewMatches.text.split("\n\n").at(-1), expectedBlock(3));
  assert.deepEqual(fewMatches.result.details, { query: "acme", count: 3 });
});

test("kevs_search treats zero, negative, and sub-1 limits as the default of 10", async () => {
  for (const limit of [0, -1, -10000, 0.5, "0", "-1"]) {
    const { result, text } = await runSearch({ query: "acme", limit }, 120);
    const label = `limit ${JSON.stringify(limit)}`;
    assert.ok(text.startsWith('Found 10 KEV entries matching "acme" (catalog size: 120):\n\n'), label);
    assert.equal(text.split("\n\n").length, 11, label);
    assert.equal(text.split("\n\n").at(-1), expectedBlock(10), label);
    assert.deepEqual(result.details, { query: "acme", count: 10 }, label);
  }
});

test("kevs_search honors the smallest positive limit and truncates fractional limits", async () => {
  const one = await runSearch({ query: "acme", limit: 1 }, 120);
  assert.equal(one.text, `Found 1 KEV entry matching "acme" (catalog size: 120):\n\n${expectedBlock(1)}`);

  const fractionalAtBound = await runSearch({ query: "acme", limit: 50.9 }, 120);
  assert.ok(fractionalAtBound.text.startsWith('Found 50 KEV entries matching "acme" (catalog size: 120):\n\n'));
  assert.deepEqual(fractionalAtBound.result.details, { query: "acme", count: 50 });

  const justOver = await runSearch({ query: "acme", limit: 51 }, 120);
  assert.ok(justOver.text.startsWith("Showing 50 of 120 KEV entries"));
  assert.deepEqual(justOver.result.details, { query: "acme", count: 50, total_matches: 120, capped: true });
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
