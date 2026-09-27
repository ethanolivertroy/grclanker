import test from "node:test";
import assert from "node:assert/strict";

import { GitHubAuditorClient } from "../dist/extensions/grc-tools/github.js";
import { NewrelicApiClient } from "../dist/extensions/grc-tools/newrelic.js";
import { QualysApiClient } from "../dist/extensions/grc-tools/qualys.js";
import { WebexApiClient } from "../dist/extensions/grc-tools/webex.js";
import { assertNoLeaks, runLeakProbe } from "./helpers/leak-probe-harness.mjs";

function jsonResponse(value, nextLink) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: {
      "content-type": "application/json",
      ...(nextLink ? { link: `<${nextLink}>; rel="next"` } : {}),
    },
  });
}

function xmlResponse(value) {
  return new Response(value, {
    status: 200,
    headers: { "content-type": "application/xml" },
  });
}

function recordRequest(requests, input, init = {}) {
  requests.push({
    url: input.toString(),
    method: init.method ?? "GET",
    headers: init.headers ?? {},
  });
}

async function webexNextLinkRunner({ nextLink, requests, origin }) {
  let page = 0;
  const client = new WebexApiClient({
    token: "webex-leak-probe-token",
    orgId: "org-1",
    baseUrl: origin,
    timeoutMs: 30_000,
    sourceChain: ["tests"],
  }, {
    fetchImpl: async (input, init) => {
      page += 1;
      if (page === 1) return jsonResponse({ items: [{ id: "person-1" }] }, nextLink);
      recordRequest(requests, input, init);
      return jsonResponse({ items: [] });
    },
  });
  const result = await client.listPeople(10);
  return { findings: [], errorTexts: [], truncated: result.truncated };
}

async function newrelicNextLinkRunner({ nextLink, requests, origin }) {
  let page = 0;
  const client = new NewrelicApiClient({
    apiKey: "newrelic-leak-probe-key",
    accountIds: [],
    region: "US",
    nerdgraphUrl: `${origin}/graphql`,
    restBaseUrl: origin,
    timeoutMs: 30_000,
    auditWindowDays: 30,
    sourceChain: ["tests"],
  }, {
    fetchImpl: async (input, init) => {
      page += 1;
      if (page === 1) return jsonResponse({ users: [{ id: 1 }] }, nextLink);
      recordRequest(requests, input, init);
      return jsonResponse({ users: [] });
    },
  });
  const result = await client.listRestUsers(10);
  return { findings: [], errorTexts: [], truncated: !result.complete, note: result.note };
}

async function githubNextLinkRunner({ nextLink, requests, origin }) {
  let page = 0;
  const client = new GitHubAuditorClient({
    organization: "example-org",
    authMode: "pat",
    apiToken: "github-leak-probe-token",
    apiBaseUrl: origin,
    lookbackDays: 30,
    sourceChain: ["tests"],
  }, async (input, init) => {
    page += 1;
    if (page === 1) return jsonResponse([{ full_name: "example-org/repo-one" }], nextLink);
    recordRequest(requests, input, init);
    return jsonResponse([]);
  });
  try {
    await client.listRepositories();
    return { findings: [], errorTexts: [], truncated: false };
  } catch (error) {
    return {
      findings: [],
      errorTexts: [],
      truncated: true,
      note: error instanceof Error ? error.message : String(error),
    };
  }
}

async function qualysNextLinkRunner({ nextLink, requests, origin }) {
  let page = 0;
  const client = new QualysApiClient({
    username: "qualys-user",
    password: "qualys-password",
    authMode: "basic",
    platform: "custom",
    baseUrl: origin,
    gatewayUrl: origin,
    timeoutMs: 30_000,
    maxRetries: 0,
    lookbackDays: 30,
    sourceChain: ["tests"],
  }, {
    fetchImpl: async (input, init) => {
      page += 1;
      if (page === 1) {
        return xmlResponse(`<HOST_LIST_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>1</ID></HOST></HOST_LIST><WARNING><URL><![CDATA[${nextLink}]]></URL></WARNING></RESPONSE></HOST_LIST_OUTPUT>`);
      }
      recordRequest(requests, input, init);
      return xmlResponse("<HOST_LIST_OUTPUT><RESPONSE><HOST_LIST /></RESPONSE></HOST_LIST_OUTPUT>");
    },
    sleepImpl: async () => {},
  });
  const result = await client.listHosts(10);
  return { findings: [], errorTexts: [], truncated: result.truncated, note: result.truncationReason };
}

test("credentialed pagination integrations pass the class 8 next-link leak probe", async () => {
  for (const [integration, nextLinkRunner] of [
    ["Webex", webexNextLinkRunner],
    ["New Relic", newrelicNextLinkRunner],
    ["GitHub", githubNextLinkRunner],
    ["Qualys", qualysNextLinkRunner],
  ]) {
    const result = await runLeakProbe({ integration, nextLinkRunner });
    assertNoLeaks(result);
  }
});

test("credentialed pagination resolves query- and path-relative links from the current page", async () => {
  const cases = [
    {
      name: "Webex",
      runner: webexNextLinkRunner,
      base: "https://api.example.com/custom/v1",
      queryPath: "/custom/v1/people",
      relativePath: "/custom/v1/next",
    },
    {
      name: "New Relic",
      runner: newrelicNextLinkRunner,
      base: "https://api.example.com/custom",
      queryPath: "/custom/v2/users.json",
      relativePath: "/custom/v2/next",
    },
    {
      name: "GitHub",
      runner: githubNextLinkRunner,
      base: "https://api.example.com/api/v3",
      queryPath: "/api/v3/orgs/example-org/repos",
      relativePath: "/api/v3/orgs/example-org/next",
    },
    {
      name: "Qualys",
      runner: qualysNextLinkRunner,
      base: "https://api.example.com/custom",
      queryPath: "/custom/api/2.0/fo/asset/host/",
      relativePath: "/custom/api/2.0/fo/asset/host/next",
    },
  ];

  for (const entry of cases) {
    const queryRequests = [];
    const queryResult = await entry.runner({
      nextLink: "?cursor=query-relative",
      requests: queryRequests,
      origin: entry.base,
    });
    assert.equal(queryResult.truncated, false, `${entry.name} query-relative walk completes`);
    assert.equal(queryRequests.length, 1, `${entry.name} follows the query-relative page`);
    const queryUrl = new URL(queryRequests[0].url);
    assert.equal(queryUrl.pathname, entry.queryPath, `${entry.name} keeps the current endpoint path`);
    assert.equal(queryUrl.searchParams.get("cursor"), "query-relative");

    const pathRequests = [];
    const pathResult = await entry.runner({
      nextLink: "next?cursor=path-relative",
      requests: pathRequests,
      origin: entry.base,
    });
    assert.equal(pathResult.truncated, false, `${entry.name} path-relative walk completes`);
    assert.equal(pathRequests.length, 1, `${entry.name} follows the path-relative page`);
    const pathUrl = new URL(pathRequests[0].url);
    assert.equal(pathUrl.pathname, entry.relativePath, `${entry.name} resolves from the current page directory`);
    assert.equal(pathUrl.searchParams.get("cursor"), "path-relative");
  }
});
