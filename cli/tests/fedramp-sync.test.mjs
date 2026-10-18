import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  clearFedrampCachesForTests,
  fetchFedrampDocsSources,
  inspectFedrampOfficialSources,
} from "../dist/extensions/grc-tools/fedramp-source.js";
import { buildFedrampDocsSnapshot } from "../dist/extensions/grc-tools/fedramp-docs.js";

const RAW_URL = "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json";
const RULES_REPO_URL = "https://api.github.com/repos/FedRAMP/rules";
const RULES_FILE_URL =
  "https://api.github.com/repos/FedRAMP/rules/contents/fedramp-consolidated-rules.json?ref=main";
const MARKDOWN_REPO_URL = "https://api.github.com/repos/FedRAMP/2026-markdown";
const MARKDOWN_CONTENTS_URL = "https://api.github.com/repos/FedRAMP/2026-markdown/contents/?ref=main";
const BLOB_SHA = "abcdef1234567890abcdef1234567890abcdef12";
const FILE_HTML_URL = "https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json";
const TOKEN = "fixture-token-1f2e3d4c5b6a";

const rulesFixture = {
  info: {
    title: "FedRAMP Consolidated Rules for 2026",
    version: "2026.07.02.02",
    last_updated: "2026-07-02",
  },
};

function jsonResponse(payload) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function healthyRoutes() {
  return {
    [RAW_URL]: () => jsonResponse(rulesFixture),
    [RULES_REPO_URL]: () =>
      jsonResponse({
        html_url: "https://github.com/FedRAMP/rules",
        updated_at: "2026-04-13T17:52:17Z",
        default_branch: "main",
      }),
    [RULES_FILE_URL]: () => jsonResponse({ sha: BLOB_SHA, html_url: FILE_HTML_URL }),
    [MARKDOWN_REPO_URL]: () =>
      jsonResponse({
        html_url: "https://github.com/FedRAMP/2026-markdown",
        updated_at: "2026-07-02T15:15:27Z",
        default_branch: "main",
      }),
    [MARKDOWN_CONTENTS_URL]: () =>
      jsonResponse([
        { name: "README.md", type: "file" },
        { name: "_sources.json", type: "file" },
      ]),
  };
}

async function withMockedFetch(overrides, run) {
  const routes = { ...healthyRoutes(), ...overrides };
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, authorization: new Headers(init?.headers).get("authorization") });
    const route = routes[url];
    return route ? route() : new Response("not found", { status: 404, statusText: "Not Found" });
  };
  try {
    return await run(calls);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function syncFailure(env, overrides) {
  return withMockedFetch(overrides, async () => {
    const error = await fetchFedrampDocsSources(env).then(
      () => assert.fail("the sync read should have failed"),
      (failure) => failure,
    );
    assert.ok(error instanceof Error);
    assert.ok(!error.message.includes(TOKEN), `the token leaked into: ${error.message}`);
    return error.message;
  });
}

function isApiCall(call) {
  return call.url.startsWith("https://api.github.com/");
}

function readTree(dir) {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => {
      const path = join(entry.parentPath, entry.name);
      return [path, readFileSync(path, "utf8")];
    })
    .sort(([left], [right]) => left.localeCompare(right));
}

test("fetchFedrampDocsSources sends GITHUB_TOKEN to the GitHub API only and returns verified provenance", async () => {
  await withMockedFetch({}, async (calls) => {
    const { catalog, primary, secondary } = await fetchFedrampDocsSources({ GITHUB_TOKEN: TOKEN });

    assert.equal(primary.blobSha, BLOB_SHA);
    assert.equal(primary.fileHtmlUrl, FILE_HTML_URL);
    assert.equal(primary.version, "2026.07.02.02");
    assert.equal(secondary.state, "ready");
    assert.deepEqual(
      calls.map((call) => call.url).sort(),
      [RAW_URL, RULES_REPO_URL, RULES_FILE_URL, MARKDOWN_REPO_URL, MARKDOWN_CONTENTS_URL].sort(),
    );
    for (const call of calls) {
      assert.equal(call.authorization, isApiCall(call) ? `Bearer ${TOKEN}` : null, call.url);
    }

    const files = buildFedrampDocsSnapshot(catalog, { primary, secondary });
    const overview = files.find((file) => file.path === "fedramp/index.md")?.content ?? "";
    assert.ok(
      overview.includes(
        `- Source path: [\`fedramp-consolidated-rules.json\`](${FILE_HTML_URL}) on \`main\` at blob \`abcdef123456\`.`,
      ),
    );
    for (const file of files) {
      assert.ok(!file.content.includes(TOKEN), `${file.path} contains the token`);
    }
  });
});

test("fetchFedrampDocsSources falls back to GH_TOKEN and reads anonymously without a token", async () => {
  await withMockedFetch({}, async (calls) => {
    await fetchFedrampDocsSources({ GITHUB_TOKEN: "", GH_TOKEN: TOKEN });
    assert.ok(calls.filter(isApiCall).every((call) => call.authorization === `Bearer ${TOKEN}`));

    calls.length = 0;
    await fetchFedrampDocsSources({ GITHUB_TOKEN: "github-token", GH_TOKEN: "gh-token" });
    assert.ok(calls.filter(isApiCall).every((call) => call.authorization === "Bearer github-token"));

    calls.length = 0;
    const anonymous = await fetchFedrampDocsSources({});
    assert.equal(anonymous.primary.blobSha, BLOB_SHA);
    assert.equal(calls.length, 5);
    assert.ok(calls.every((call) => call.authorization === null));
  });
});

test("fetchFedrampDocsSources fails with the reset time and a token hint when the anonymous rate limit runs out", async () => {
  const reset = 1792335600;
  const message = await syncFailure({}, {
    [RULES_FILE_URL]: () =>
      new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
        status: 403,
        statusText: "rate limit exceeded",
        headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(reset) },
      }),
  });

  assert.equal(
    message,
    `Fetch failed: ${RULES_FILE_URL} (403 rate limit exceeded). GitHub rate limit exceeded; it resets at ${new Date(reset * 1000).toISOString()}. Set GITHUB_TOKEN or GH_TOKEN to authenticate GitHub API reads.`,
  );
});

test("fetchFedrampDocsSources fails when an authenticated read is rate-limited", async () => {
  const message = await syncFailure({ GITHUB_TOKEN: TOKEN }, {
    [MARKDOWN_CONTENTS_URL]: () =>
      new Response("{}", { status: 429, statusText: "Too Many Requests", headers: { "retry-after": "60" } }),
  });

  assert.equal(
    message,
    `Fetch failed: ${MARKDOWN_CONTENTS_URL} (429 Too Many Requests). GitHub rate limit exceeded; retry after 60 seconds.`,
  );
});

test("fetchFedrampDocsSources fails on any non-2xx read, including the narrative repo", async () => {
  const cases = [
    [RAW_URL, 500, "Internal Server Error"],
    [RULES_REPO_URL, 404, "Not Found"],
    [RULES_FILE_URL, 404, "Not Found"],
    [MARKDOWN_REPO_URL, 502, "Bad Gateway"],
    [MARKDOWN_CONTENTS_URL, 404, "Not Found"],
  ];
  for (const [url, status, statusText] of cases) {
    const message = await syncFailure({ GITHUB_TOKEN: TOKEN }, {
      [url]: () => new Response("upstream error", { status, statusText }),
    });
    assert.equal(message, `Fetch failed: ${url} (${status} ${statusText})`);
  }
});

test("fetchFedrampDocsSources fails instead of returning placeholder provenance", async () => {
  const missingProvenance =
    "GitHub returned no blob SHA or file URL for FedRAMP/rules/fedramp-consolidated-rules.json on main.";
  assert.equal(
    await syncFailure({}, { [RULES_FILE_URL]: () => jsonResponse({ html_url: FILE_HTML_URL }) }),
    missingProvenance,
  );
  assert.equal(
    await syncFailure({}, { [RULES_FILE_URL]: () => jsonResponse({ sha: BLOB_SHA }) }),
    missingProvenance,
  );
  assert.equal(
    await syncFailure({}, { [RAW_URL]: () => jsonResponse({ info: { last_updated: "2026-07-02" } }) }),
    `${RAW_URL} has no info.version or info.last_updated.`,
  );
});

test("fetchFedrampDocsSources keeps the token out of rejected-token, network, and unreadable-body errors", async () => {
  assert.equal(
    await syncFailure({ GITHUB_TOKEN: TOKEN }, {
      [RULES_REPO_URL]: () => new Response("{}", { status: 401, statusText: "Unauthorized" }),
    }),
    `Fetch failed: ${RULES_REPO_URL} (401 Unauthorized). GitHub rejected the token from GITHUB_TOKEN or GH_TOKEN.`,
  );
  assert.equal(
    await syncFailure({ GITHUB_TOKEN: TOKEN }, {
      [RULES_FILE_URL]: () => {
        throw new TypeError(`Headers.append: "Bearer ${TOKEN}" is an invalid header value.`);
      },
    }),
    `Fetch failed: ${RULES_FILE_URL} (Headers.append: "Bearer [REDACTED]" is an invalid header value.)`,
  );
  assert.match(
    await syncFailure({ GITHUB_TOKEN: TOKEN }, {
      [MARKDOWN_REPO_URL]: () => new Response("<html>busy</html>", { status: 200 }),
    }),
    /^Fetch failed: https:\/\/api\.github\.com\/repos\/FedRAMP\/2026-markdown \(unreadable JSON: /,
  );
});

test("inspectFedrampOfficialSources still reports an unreadable narrative repo as unavailable", async () => {
  const homeDir = mkdtempSync(join(tmpdir(), "grclanker-fedramp-sync-"));
  clearFedrampCachesForTests();
  try {
    await withMockedFetch(
      {
        [MARKDOWN_CONTENTS_URL]: () => new Response("", { status: 503, statusText: "Service Unavailable" }),
      },
      async () => {
        const status = await inspectFedrampOfficialSources({ refresh: true, homeDir });
        assert.equal(status.primary.blobSha, BLOB_SHA);
        assert.equal(status.secondary.state, "unavailable");
        assert.equal(
          status.secondary.notes[0],
          `Unable to inspect FedRAMP/2026-markdown: Fetch failed: ${MARKDOWN_CONTENTS_URL} (503 Service Unavailable)`,
        );
      },
    );
  } finally {
    clearFedrampCachesForTests();
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test("sync-fedramp exits non-zero, leaves the docs alone, and never prints the token when a GitHub read fails", () => {
  const cliRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const docsDir = join(cliRoot, "..", "src", "content", "docs", "docs", "fedramp");
  const preload = `data:text/javascript,${encodeURIComponent(`
    globalThis.fetch = async (input) =>
      String(input).startsWith("https://api.github.com/")
        ? new Response("{}", {
            status: 403,
            statusText: "rate limit exceeded",
            headers: { "x-ratelimit-remaining": "0" },
          })
        : new Response(${JSON.stringify(JSON.stringify(rulesFixture))}, { status: 200 });
  `)}`;
  const before = readTree(docsDir);
  assert.ok(before.length > 0, "the generated FedRAMP docs are checked in");

  const run = spawnSync(
    process.execPath,
    ["--import", preload, "--import", "tsx", join("scripts", "sync-fedramp.ts")],
    { cwd: cliRoot, encoding: "utf8", timeout: 60_000, env: { ...process.env, GITHUB_TOKEN: TOKEN } },
  );

  assert.equal(run.status, 1, `sync-fedramp exited ${run.status}: ${run.stdout}${run.stderr}`);
  assert.equal(run.stdout, "");
  assert.match(
    run.stderr,
    /^FedRAMP sync failed: Fetch failed: https:\/\/api\.github\.com\/repos\/FedRAMP\/\S+ \(403 rate limit exceeded\)\. GitHub rate limit exceeded\.$/m,
  );
  assert.ok(!`${run.stdout}${run.stderr}`.includes(TOKEN), "the token leaked into the sync output");
  assert.deepEqual(readTree(docsDir), before);
});
