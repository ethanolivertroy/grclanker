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
import { setGrcFetchTimingForTests } from "../dist/extensions/grc-tools/shared.js";
import { assertFragmentsAbsent, assertPlantedValuesWellFormed } from "./helpers/planted-values.mjs";

const RAW_URL = "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json";
const RULES_REPO_URL = "https://api.github.com/repos/FedRAMP/rules";
const RULES_FILE_URL =
  "https://api.github.com/repos/FedRAMP/rules/contents/fedramp-consolidated-rules.json?ref=main";
const MARKDOWN_REPO_URL = "https://api.github.com/repos/FedRAMP/2026-markdown";
const MARKDOWN_CONTENTS_URL = "https://api.github.com/repos/FedRAMP/2026-markdown/contents/?ref=main";
const RESET_EPOCH_SECONDS = 1792335600;
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
    const call = { url, authorization: new Headers(init?.headers).get("authorization") };
    calls.push(call);
    const route = routes[url];
    return route ? route(call) : new Response("not found", { status: 404, statusText: "Not Found" });
  };
  try {
    return await run(calls);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

/**
 * Runs `run` with the shared fetch's clock pinned at `nowMs` and its retry waits
 * recorded instead of slept, so retry tests take no real time.
 */
async function withFetchClock(nowMs, run) {
  const waits = [];
  setGrcFetchTimingForTests({ now: () => nowMs, sleep: async (ms) => void waits.push(ms) });
  try {
    return await run(waits);
  } finally {
    setGrcFetchTimingForTests();
  }
}

async function syncAttempts(env, overrides) {
  return withMockedFetch(overrides, async (calls) => {
    const error = await fetchFedrampDocsSources(env).then(
      () => assert.fail("the sync read should have failed"),
      (failure) => failure,
    );
    assert.ok(error instanceof Error);
    assert.ok(!error.message.includes(TOKEN), `the token leaked into: ${error.message}`);
    return { message: error.message, calls };
  });
}

async function syncFailure(env, overrides) {
  return withFetchClock(Date.now(), async () => (await syncAttempts(env, overrides)).message);
}

function isApiCall(call) {
  return call.url.startsWith("https://api.github.com/");
}

/** Error text names the endpoint without its query string. */
function endpoint(url) {
  return url.split("?")[0];
}

function rateLimited(reset = RESET_EPOCH_SECONDS) {
  return new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
    status: 403,
    statusText: "rate limit exceeded",
    headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(reset) },
  });
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

test("fetchFedrampDocsSources fails at once, with the reset time and a token hint, when the anonymous rate limit resets past the retry cap", async () => {
  const { message, calls, waits } = await withFetchClock((RESET_EPOCH_SECONDS - 3600) * 1000, async (waits) => ({
    ...(await syncAttempts({}, { [RULES_FILE_URL]: () => rateLimited() })),
    waits,
  }));

  assert.equal(
    message,
    `Fetch failed: ${endpoint(RULES_FILE_URL)} (403 rate limit exceeded; the server asked to wait 3600 s before retrying, longer than the 30 s limit). GitHub rate limit exceeded; it resets at ${new Date(RESET_EPOCH_SECONDS * 1000).toISOString()}. Set GITHUB_TOKEN or GH_TOKEN to authenticate GitHub API reads.`,
  );
  assert.equal(calls.filter((call) => call.url === RULES_FILE_URL).length, 1, "a wait past the cap is not retried");
  assert.deepEqual(waits, []);
});

test("fetchFedrampDocsSources waits out a GitHub rate limit that resets within the retry cap, then reads again", async () => {
  let attempts = 0;
  await withFetchClock(RESET_EPOCH_SECONDS * 1000 - 20_000, async (waits) => {
    await withMockedFetch(
      {
        [RULES_FILE_URL]: () => {
          attempts += 1;
          return attempts === 1 ? rateLimited() : jsonResponse({ sha: BLOB_SHA, html_url: FILE_HTML_URL });
        },
      },
      async () => {
        const { primary } = await fetchFedrampDocsSources({});
        assert.equal(primary.blobSha, BLOB_SHA);
      },
    );
    assert.equal(attempts, 2);
    assert.deepEqual(waits, [20_000], "the wait runs to x-ratelimit-reset");
  });
});

test("fetchFedrampDocsSources honors Retry-After on a rate-limited authenticated read and fails at once past the cap", async () => {
  const { message, calls, waits } = await withFetchClock(Date.now(), async (waits) => ({
    ...(await syncAttempts({ GITHUB_TOKEN: TOKEN }, {
      [MARKDOWN_CONTENTS_URL]: () =>
        new Response("{}", { status: 429, statusText: "Too Many Requests", headers: { "retry-after": "60" } }),
    })),
    waits,
  }));
  assert.equal(
    message,
    `Fetch failed: ${endpoint(MARKDOWN_CONTENTS_URL)} (429 Too Many Requests; the server asked to wait 60 s before retrying, longer than the 30 s limit). GitHub rate limit exceeded; retry after 60 seconds.`,
  );
  assert.equal(calls.filter((call) => call.url === MARKDOWN_CONTENTS_URL).length, 1);
  assert.deepEqual(waits, []);

  let attempts = 0;
  await withFetchClock(Date.now(), async (retryWaits) => {
    await withMockedFetch(
      {
        [MARKDOWN_CONTENTS_URL]: () => {
          attempts += 1;
          return attempts === 1
            ? new Response("{}", { status: 429, statusText: "Too Many Requests", headers: { "retry-after": "5" } })
            : jsonResponse([{ name: "_sources.json", type: "file" }]);
        },
      },
      async () => {
        const { secondary } = await fetchFedrampDocsSources({ GITHUB_TOKEN: TOKEN });
        assert.equal(secondary.state, "ready");
      },
    );
    assert.equal(attempts, 2);
    assert.deepEqual(retryWaits, [5_000]);
  });
});

test("fetchFedrampDocsSources fails on any non-2xx read, retrying 5xx answers with backoff first", async () => {
  const cases = [
    [RAW_URL, 500, "Internal Server Error", 4],
    [RULES_REPO_URL, 404, "Not Found", 1],
    [RULES_FILE_URL, 404, "Not Found", 1],
    [MARKDOWN_REPO_URL, 502, "Bad Gateway", 4],
    [MARKDOWN_CONTENTS_URL, 404, "Not Found", 1],
  ];
  for (const [url, status, statusText, attempts] of cases) {
    await withFetchClock(Date.now(), async (waits) => {
      const { message, calls } = await syncAttempts({ GITHUB_TOKEN: TOKEN }, {
        [url]: () => new Response("upstream error", { status, statusText }),
      });
      const count = attempts > 1 ? ` after ${attempts} attempts` : "";
      assert.equal(message, `Fetch failed: ${endpoint(url)} (${status} ${statusText})${count}`);
      assert.equal(calls.filter((call) => call.url === url).length, attempts, url);
      assert.deepEqual(waits, attempts > 1 ? [1_000, 2_000, 4_000] : [], url);
    });
  }
});

test("fetchFedrampDocsSources recovers when a 5xx clears on retry", async () => {
  let attempts = 0;
  await withFetchClock(Date.now(), async (waits) => {
    await withMockedFetch(
      {
        [RAW_URL]: () => {
          attempts += 1;
          return attempts === 1
            ? new Response("busy", { status: 503, statusText: "Service Unavailable" })
            : jsonResponse(rulesFixture);
        },
      },
      async () => {
        const { primary } = await fetchFedrampDocsSources({ GITHUB_TOKEN: TOKEN });
        assert.equal(primary.version, "2026.07.02.02");
      },
    );
    assert.equal(attempts, 2);
    assert.deepEqual(waits, [1_000]);
  });
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
    `Fetch failed: ${endpoint(RULES_FILE_URL)} (Headers.append: "Bearer [REDACTED]" is an invalid header value.) after 4 attempts`,
  );
  assert.match(
    await syncFailure({ GITHUB_TOKEN: TOKEN }, {
      [MARKDOWN_REPO_URL]: () => new Response("<html>busy</html>", { status: 200 }),
    }),
    /^Fetch failed: https:\/\/api\.github\.com\/repos\/FedRAMP\/2026-markdown \(unreadable JSON: /,
  );
});

const PLANTED_TOKEN = "ghpQx7Lm2Vb9Rt4Kz8Wn3Ys6Pd1Hg5Jc0Fa";

/**
 * Failing answers that echo back whatever Authorization header the request
 * carried, in the body, the headers, the reason phrase, and transport errors.
 */
const ECHOING_FAILURES = [
  ({ authorization: sent }) =>
    new Response(JSON.stringify({ message: `Bad credentials: ${sent}` }), {
      status: 401,
      statusText: "Unauthorized",
      headers: { "content-type": "application/json", "www-authenticate": `${sent}`, "x-echo": `${sent}` },
    }),
  ({ authorization: sent }) =>
    new Response(JSON.stringify({ message: `API rate limit exceeded for ${sent}` }), {
      status: 403,
      statusText: "rate limit exceeded",
      headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": `${sent}`, "retry-after": `${sent}` },
    }),
  ({ authorization: sent }) => new Response(`upstream ${sent}`, { status: 502, statusText: `Upstream ${sent}` }),
  ({ authorization: sent }) =>
    new Response(`<p>${sent}</p>`, { status: 200, headers: { "content-type": `text/html; echo=${String(sent).replace(/\s/g, "")}` } }),
  ({ authorization: sent }) =>
    new Response(`{"message": "${sent}"`, { status: 200, headers: { "content-type": "application/json" } }),
  ({ authorization: sent }) => {
    throw new TypeError(`Headers.append: "${sent}" is an invalid header value.`);
  },
  ({ authorization: sent }) => {
    throw new TypeError(`fetch failed: https://x-access-token:${String(sent).replace(/^Bearer /, "")}@api.github.com/`);
  },
];

const API_URLS = [RULES_REPO_URL, RULES_FILE_URL, MARKDOWN_REPO_URL, MARKDOWN_CONTENTS_URL];

test("a planted GITHUB_TOKEN that failing GitHub reads echo back reaches no error, source note, cache, or generated doc", async () => {
  const healthyDocs = await withMockedFetch({}, async () => {
    const { catalog, primary, secondary } = await fetchFedrampDocsSources({});
    return buildFedrampDocsSnapshot(catalog, { primary, secondary }).map((file) => [file.path, file.content]);
  });
  assertPlantedValuesWellFormed(assert, { GITHUB_TOKEN: PLANTED_TOKEN }, [
    ["routes", [RAW_URL, ...API_URLS, FILE_HTML_URL, BLOB_SHA].join("\n")],
    ["rules fixture", JSON.stringify(rulesFixture)],
    ...healthyDocs,
  ]);

  const messages = [];
  for (const [index, failure] of ECHOING_FAILURES.entries()) {
    for (const url of API_URLS) {
      const message = await withFetchClock(Date.now(), async () =>
        (await syncAttempts({ GITHUB_TOKEN: PLANTED_TOKEN }, { [url]: failure })).message,
      );
      messages.push(`shape ${index} at ${url}: ${message}`);
    }
  }
  assert.ok(messages.some((message) => message.includes("[REDACTED]")), "the echoes reached the error path");
  assertFragmentsAbsent(assert, messages.join("\n"), [PLANTED_TOKEN], "sync errors");

  const answered = new Set();
  const recovering = Object.fromEntries(
    Object.entries(healthyRoutes()).map(([url, healthy]) => [
      url,
      (call) => {
        if (answered.has(url)) return healthy(call);
        answered.add(url);
        return ECHOING_FAILURES[2](call);
      },
    ]),
  );
  const files = await withFetchClock(Date.now(), () =>
    withMockedFetch(recovering, async () => {
      const { catalog, primary, secondary } = await fetchFedrampDocsSources({ GITHUB_TOKEN: PLANTED_TOKEN });
      return buildFedrampDocsSnapshot(catalog, { primary, secondary });
    }),
  );
  assert.ok(files.length > 0);
  assertFragmentsAbsent(assert, files.map((file) => file.content).join("\n"), [PLANTED_TOKEN], "generated docs");

  const homeDir = mkdtempSync(join(tmpdir(), "grclanker-fedramp-planted-"));
  const originalToken = process.env.GITHUB_TOKEN;
  process.env.GITHUB_TOKEN = PLANTED_TOKEN;
  clearFedrampCachesForTests();
  try {
    for (const failure of ECHOING_FAILURES) {
      const routes = Object.fromEntries(API_URLS.map((url) => [url, failure]));
      const status = await withFetchClock(Date.now(), () =>
        withMockedFetch(routes, async (calls) => {
          const result = await inspectFedrampOfficialSources({ refresh: true, homeDir });
          assert.ok(calls.every((call) => call.authorization === null), "the FedRAMP tools never send a token");
          return result;
        }),
      );
      const written = readTree(homeDir).map(([, content]) => content).join("\n");
      assertFragmentsAbsent(assert, `${JSON.stringify(status)}\n${written}`, [PLANTED_TOKEN], "source status and caches");
    }
  } finally {
    if (originalToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = originalToken;
    clearFedrampCachesForTests();
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test("inspectFedrampOfficialSources still reports an unreadable narrative repo as unavailable", async () => {
  const homeDir = mkdtempSync(join(tmpdir(), "grclanker-fedramp-sync-"));
  clearFedrampCachesForTests();
  try {
    await withFetchClock(Date.now(), () =>
      withMockedFetch(
        {
          [MARKDOWN_CONTENTS_URL]: () => new Response("", { status: 503, statusText: "Service Unavailable" }),
        },
        async () => {
          const status = await inspectFedrampOfficialSources({ refresh: true, homeDir });
          assert.equal(status.primary.blobSha, BLOB_SHA);
          assert.equal(status.secondary.state, "unavailable");
          assert.equal(
            status.secondary.notes[0],
            `Unable to inspect FedRAMP/2026-markdown: Fetch failed: ${endpoint(MARKDOWN_CONTENTS_URL)} (503 Service Unavailable) after 4 attempts`,
          );
        },
      ),
    );
  } finally {
    clearFedrampCachesForTests();
    rmSync(homeDir, { recursive: true, force: true });
  }
});

test("inspectFedrampOfficialSources says why the rules provenance is missing, live and from the cache", async () => {
  const homeDir = mkdtempSync(join(tmpdir(), "grclanker-fedramp-sync-"));
  const metadataNote =
    `GitHub metadata for FedRAMP/rules is unavailable, so the blob SHA, file URL, and repo update time are missing: ` +
    `Fetch failed: ${RULES_REPO_URL} (403 rate limit exceeded). GitHub rate limit exceeded.`;
  clearFedrampCachesForTests();
  try {
    await withFetchClock(Date.now(), () =>
      withMockedFetch(
        {
          [RULES_REPO_URL]: () =>
            new Response("{}", { status: 403, statusText: "rate limit exceeded", headers: { "x-ratelimit-remaining": "0" } }),
        },
        async () => {
          const live = await inspectFedrampOfficialSources({ refresh: true, homeDir });
          assert.equal(live.cacheStatus, "live");
          assert.equal(live.primary.blobSha, null);
          assert.equal(live.primary.version, "2026.07.02.02", "the catalog itself still loaded");
          assert.deepEqual(live.notes, [metadataNote]);
        },
      ),
    );

    clearFedrampCachesForTests();
    await withMockedFetch({}, async (calls) => {
      const cached = await inspectFedrampOfficialSources({ homeDir });
      assert.equal(calls.length, 0, "the source status came from the disk cache");
      assert.equal(cached.cacheStatus, "cached");
      assert.equal(cached.primary.blobSha, null);
      assert.deepEqual(cached.notes, [metadataNote]);
    });
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
