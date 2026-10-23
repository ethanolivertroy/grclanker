import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  VantaAuditorClient,
  checkVantaAuditorAccess,
  clearVantaTokenCacheForTests,
  resolveSecureOutputPath,
  resolveVantaCredentials,
  exportVantaAuditPackage,
  escapeCsvCell,
  registerVantaTools,
  sanitizeFilename,
} from "../dist/extensions/grc-tools/vanta.js";
import { assertNoPartialBundleOnWriteFailure, writeFailureTest } from "./helpers/atomic-output.mjs";
import { readZipEntries } from "./helpers/bundle-contents.mjs";
import { assertFragmentsAbsent, assertPlantedValuesWellFormed } from "./helpers/planted-values.mjs";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const noSleep = async () => {};

function recordSleeps() {
  const sleeps = [];
  return { sleeps, sleep: async (ms) => { sleeps.push(ms); } };
}

/** A response that never arrives; it rejects as fetch does once the request's signal aborts. */
function hangUntilAborted(init) {
  return new Promise((_, reject) => {
    init.signal.addEventListener("abort", () => {
      reject(Object.assign(new Error("This operation was aborted"), { name: "AbortError" }));
    }, { once: true });
  });
}

function vantaClient(fetchImpl, credentials = { clientId: "client-id", clientSecret: "client-secret" }, options = {}) {
  return new VantaAuditorClient(credentials, {
    baseUrl: "http://vanta.test/v1",
    tokenUrl: "http://vanta.test/oauth/token",
    fetchImpl,
    sleep: noSleep,
    ...options,
  });
}

function withVantaToken(handleApi) {
  return async (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    if ((init.method ?? "GET") === "POST" && requestUrl.pathname === "/oauth/token") {
      return jsonResponse({ access_token: "token-1", expires_in: 3600 });
    }
    return handleApi(requestUrl, init);
  };
}

function auditPage(id, pageInfo) {
  return {
    results: {
      data: [{
        id,
        customerDisplayName: "Acme Security",
        customerOrganizationName: "Acme Security LLC",
        framework: "SOC 2",
        auditStartDate: "2026-01-01T00:00:00.000Z",
        auditEndDate: "2026-12-31T00:00:00.000Z",
      }],
      pageInfo,
    },
  };
}

test("resolveVantaCredentials prefers explicit args and falls back per field to env", () => {
  const explicit = resolveVantaCredentials(
    { clientId: " arg-id ", clientSecret: " arg-secret " },
    {
      VANTA_CLIENT_ID: "env-id",
      VANTA_CLIENT_SECRET: "env-secret",
    },
  );
  assert.deepEqual(explicit, {
    clientId: "arg-id",
    clientSecret: "arg-secret",
  });

  const mixed = resolveVantaCredentials(
    { clientId: "arg-id" },
    {
      VANTA_CLIENT_ID: "env-id",
      VANTA_CLIENT_SECRET: "env-secret",
    },
  );
  assert.deepEqual(mixed, {
    clientId: "arg-id",
    clientSecret: "env-secret",
  });

  assert.throws(
    () => resolveVantaCredentials({}, {}),
    /Vanta credentials are required/,
  );
});

test("VantaAuditorClient paginates audits, retries on 401, and treats 404 evidence URLs as empty", async () => {
  const state = {
    tokenRequests: 0,
    activeToken: "",
    evidence401Triggered: false,
  };

  const fetchImpl = async (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    const method = init.method ?? "GET";
    const authorization = init.headers && typeof init.headers === "object" && !Array.isArray(init.headers)
      ? init.headers.authorization
      : undefined;

    if (method === "POST" && requestUrl.pathname === "/oauth/token") {
      state.tokenRequests += 1;
      state.activeToken = `token-${state.tokenRequests}`;
      return new Response(JSON.stringify({
        access_token: state.activeToken,
        expires_in: 3600,
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (authorization !== `Bearer ${state.activeToken}`) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    }

    if (method === "GET" && requestUrl.pathname === "/v1/audits") {
      const cursor = requestUrl.searchParams.get("pageCursor");
      if (!cursor) {
        return new Response(JSON.stringify({
          results: {
            data: [
              {
                id: "audit-1",
                customerDisplayName: "Acme Security",
                customerOrganizationName: "Acme Security LLC",
                framework: "SOC 2",
                auditStartDate: "2026-01-01T00:00:00.000Z",
                auditEndDate: "2026-12-31T00:00:00.000Z",
              },
            ],
            pageInfo: { hasNextPage: true, endCursor: "cursor-1" },
          },
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      return new Response(JSON.stringify({
        results: {
          data: [
            {
              id: "audit-2",
              customerDisplayName: null,
              customerOrganizationName: "Bravo Corp",
              framework: "ISO 27001",
              auditStartDate: "2026-02-01T00:00:00.000Z",
              auditEndDate: "2026-08-01T00:00:00.000Z",
            },
            ],
          pageInfo: { hasNextPage: false, endCursor: null },
        },
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (method === "GET" && requestUrl.pathname === "/v1/audits/audit-1/evidence") {
      if (!state.evidence401Triggered) {
        state.evidence401Triggered = true;
        return new Response(JSON.stringify({ error: "token rotated" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        });
      }

      return new Response(JSON.stringify({
        results: {
          data: [
            {
              id: "audit-evidence-1",
              evidenceId: "evidence-1",
              name: "Quarterly access review",
              status: "SUBMITTED",
              description: "Review package",
              evidenceType: "UPLOADED_DOCUMENT",
              testStatus: null,
              relatedControls: [{ name: "Access control" }],
              creationDate: "2026-01-10T00:00:00.000Z",
              statusUpdatedDate: "2026-01-11T00:00:00.000Z",
            },
          ],
          pageInfo: { hasNextPage: false, endCursor: null },
        },
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    if (
      method === "GET"
      && requestUrl.pathname === "/v1/audits/audit-1/evidence/audit-evidence-1/urls"
    ) {
      return new Response(JSON.stringify({ error: "no urls" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "not found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  };

  const client = new VantaAuditorClient(
    { clientId: "client-id", clientSecret: "client-secret" },
    {
      baseUrl: "http://vanta.test/v1",
      tokenUrl: "http://vanta.test/oauth/token",
      fetchImpl,
    },
  );

  const audits = await client.listAudits();
  const evidence = await client.listEvidence("audit-1");
  const urls = await client.listEvidenceUrls("audit-1", "audit-evidence-1");

  assert.equal(audits.length, 2);
  assert.equal(evidence.length, 1);
  assert.deepEqual(urls, []);
  assert.equal(state.tokenRequests, 2);
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient refuses a next page with no cursor instead of returning a partial list", async () => {
  clearVantaTokenCacheForTests();
  let auditRequests = 0;
  const client = vantaClient(withVantaToken(async (url) => {
    if (url.pathname !== "/v1/audits") return jsonResponse({ error: "not found" }, 404);
    auditRequests += 1;
    return jsonResponse(auditPage("audit-1", { hasNextPage: true, endCursor: null }));
  }));

  await assert.rejects(client.listAudits(), /reported another page but no endCursor after 1 item/);
  assert.equal(auditRequests, 1);
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient refuses a repeated page cursor instead of looping", async () => {
  clearVantaTokenCacheForTests();
  let auditRequests = 0;
  const client = vantaClient(withVantaToken(async (url) => {
    if (url.pathname !== "/v1/audits") return jsonResponse({ error: "not found" }, 404);
    auditRequests += 1;
    return jsonResponse(auditPage(`audit-${auditRequests}`, { hasNextPage: true, endCursor: "stuck" }));
  }));

  await assert.rejects(client.listAudits(), /repeated a page cursor after 2 item/);
  assert.equal(auditRequests, 2);
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient stops at the page cap instead of following an endless new cursor", async () => {
  clearVantaTokenCacheForTests();
  let auditRequests = 0;
  const client = vantaClient(withVantaToken(async (url) => {
    if (url.pathname !== "/v1/audits") return jsonResponse({ error: "not found" }, 404);
    auditRequests += 1;
    return jsonResponse(auditPage(`audit-${auditRequests}`, { hasNextPage: true, endCursor: `cursor-${auditRequests}` }));
  }));

  await assert.rejects(client.listAudits(), /exceeded 500 pages after 500 item/);
  assert.equal(auditRequests, 500);
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient does not drop earlier pages when a later evidence URL page is 404", async () => {
  clearVantaTokenCacheForTests();
  const client = vantaClient(withVantaToken(async (url) => {
    if (url.pathname !== "/v1/audits/audit-1/evidence/ae-1/urls") {
      return jsonResponse({ error: "not found" }, 404);
    }
    if (!url.searchParams.get("pageCursor")) {
      return jsonResponse({
        results: {
          data: [{
            id: "url-1",
            url: "https://downloads.example.com/evidence-1.pdf",
            filename: "evidence-1.pdf",
            isDownloadable: true,
          }],
          pageInfo: { hasNextPage: true, endCursor: "cursor-1" },
        },
      });
    }
    return jsonResponse({ error: "missing page" }, 404);
  }));

  await assert.rejects(
    client.listEvidenceUrls("audit-1", "ae-1"),
    /returned 404 after 1 fetched page\(s\); refusing to treat a partial page as a complete list/,
  );
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient does not treat a later 404 as complete when an earlier page was empty", async () => {
  clearVantaTokenCacheForTests();
  const client = vantaClient(withVantaToken(async (url) => {
    if (url.pathname !== "/v1/audits/audit-1/evidence/ae-1/urls") {
      return jsonResponse({ error: "not found" }, 404);
    }
    if (!url.searchParams.get("pageCursor")) {
      return jsonResponse({
        results: {
          data: [],
          pageInfo: { hasNextPage: true, endCursor: "cursor-1" },
        },
      });
    }
    return jsonResponse({ error: "missing page" }, 404);
  }));

  await assert.rejects(
    client.listEvidenceUrls("audit-1", "ae-1"),
    /returned 404 after 1 fetched page\(s\); refusing to treat a partial page as a complete list/,
  );
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient redacts credentials echoed in authentication and API errors", async () => {
  clearVantaTokenCacheForTests();
  const clientSecret = "vanta-client-secret-should-not-leak";
  const accessToken = "vanta-access-token-should-not-leak";
  let tokenCalls = 0;
  const fetchImpl = async (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    if ((init.method ?? "GET") === "POST" && requestUrl.pathname === "/oauth/token") {
      tokenCalls += 1;
      if (tokenCalls === 1) {
        return jsonResponse({ error: "invalid_client", client_secret: clientSecret }, 401);
      }
      return jsonResponse({ access_token: accessToken, expires_in: 3600 });
    }
    return jsonResponse({ error: "boom", access_token: accessToken, client_secret: clientSecret }, 500);
  };
  const client = vantaClient(fetchImpl, { clientId: "vanta-client-id-value", clientSecret });

  await assert.rejects(client.listAudits(), (error) => {
    assert.match(error.message, /Vanta authentication failed/);
    assert.equal(error.message.includes(clientSecret), false);
    assert.match(error.message, /\[redacted\]/);
    return true;
  });
  await assert.rejects(client.listAudits(), (error) => {
    assert.match(error.message, /Vanta API request failed/);
    assert.equal(error.message.includes(clientSecret), false);
    assert.equal(error.message.includes(accessToken), false);
    assert.match(error.message, /\[redacted\]/);
    return true;
  });
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient redacts a secret that straddles the error body limit", async () => {
  clearVantaTokenCacheForTests();
  const accessToken = `token-head-${"A".repeat(80)}-token-tail-${"B".repeat(80)}`;
  const filler = "x".repeat(200);
  const client = vantaClient(async (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    if ((init.method ?? "GET") === "POST" && requestUrl.pathname === "/oauth/token") {
      return jsonResponse({ access_token: accessToken, expires_in: 3600 });
    }
    return jsonResponse({ error: `${filler}${accessToken}` }, 500);
  });

  await assert.rejects(client.listAudits(), (error) => {
    assert.match(error.message, /Vanta API request failed/);
    assert.equal(error.message.includes(accessToken), false);
    assert.equal(error.message.includes("token-head"), false);
    assert.equal(error.message.includes("token-tail"), false);
    assert.equal(error.message.includes("A".repeat(10)), false);
    assert.match(error.message, /\[redacted\]/);
    return true;
  });
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient retries the token grant and API reads on transport errors, 429, and 5xx, honoring Retry-After", async () => {
  clearVantaTokenCacheForTests();
  const { sleeps, sleep } = recordSleeps();
  const tokenOutcomes = ["transport", 503, 200];
  const auditOutcomes = [429, 502, 200];
  const calls = [];
  const client = vantaClient(async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push(`${init.method ?? "GET"} ${url.pathname}`);
    if (url.pathname === "/oauth/token") {
      const outcome = tokenOutcomes.shift();
      if (outcome === "transport") throw new TypeError("fetch failed");
      if (outcome === 503) return jsonResponse({ error: "unavailable" }, 503);
      return jsonResponse({ access_token: "token-1", expires_in: 3600 });
    }
    const outcome = auditOutcomes.shift();
    if (outcome === 429) return new Response("slow down", { status: 429, headers: { "retry-after": "2" } });
    if (outcome === 502) return new Response("bad gateway", { status: 502 });
    return jsonResponse(auditPage("audit-1", { hasNextPage: false, endCursor: null }));
  }, undefined, { sleep });

  assert.deepEqual((await client.listAudits()).map((audit) => audit.id), ["audit-1"]);
  assert.deepEqual(calls, [
    "POST /oauth/token",
    "POST /oauth/token",
    "POST /oauth/token",
    "GET /v1/audits",
    "GET /v1/audits",
    "GET /v1/audits",
  ]);
  assert.deepEqual(sleeps, [500, 1000, 2000, 1000], "exponential backoff, except where Retry-After names the wait");
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient measures an HTTP-date Retry-After against its clock", async () => {
  clearVantaTokenCacheForTests();
  const { sleeps, sleep } = recordSleeps();
  const now = Date.parse("Wed, 21 Oct 2026 07:28:00 GMT");
  const retryAfter = ["Wed, 21 Oct 2026 07:28:05 GMT", "Tue, 20 Oct 2026 07:28:00 GMT"];
  const client = vantaClient(withVantaToken(async () => {
    const value = retryAfter.shift();
    if (value) return new Response("busy", { status: 503, headers: { "retry-after": value } });
    return jsonResponse(auditPage("audit-1", { hasNextPage: false, endCursor: null }));
  }), undefined, { sleep, now: () => now });

  assert.equal((await client.listAudits()).length, 1);
  assert.deepEqual(sleeps, [5000, 0], "a future date waits until then and a past date retries at once");
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient fails closed when retries run out partway through pagination", async () => {
  clearVantaTokenCacheForTests();
  const { sleeps, sleep } = recordSleeps();
  let secondPageRequests = 0;
  const client = vantaClient(withVantaToken(async (url) => {
    if (!url.searchParams.get("pageCursor")) {
      return jsonResponse(auditPage("audit-1", { hasNextPage: true, endCursor: "cursor-1" }));
    }
    secondPageRequests += 1;
    return new Response("upstream unavailable", { status: 503, statusText: "Service Unavailable" });
  }), undefined, { sleep });

  await assert.rejects(
    client.listAudits(),
    /^Error: Vanta API request failed for \/audits \(503 Service Unavailable\) after 4 attempts: upstream unavailable$/,
  );
  assert.equal(secondPageRequests, 4, "the first try and three retries");
  assert.deepEqual(sleeps, [500, 1000, 2000]);
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient fails closed at once when Retry-After asks for more than 30 seconds", async () => {
  clearVantaTokenCacheForTests();
  const { sleeps, sleep } = recordSleeps();
  let requests = 0;
  const client = vantaClient(withVantaToken(async () => {
    requests += 1;
    return new Response("rate limited", {
      status: 429,
      statusText: "Too Many Requests",
      headers: { "retry-after": "120" },
    });
  }), undefined, { sleep });

  await assert.rejects(
    client.listAudits(),
    /\(429 Too Many Requests\): the server asked to retry after 120 s, more than the 30 s limit: rate limited$/,
  );
  assert.equal(requests, 1);
  assert.deepEqual(sleeps, []);
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient times out a hung request, retries it, and names the timeout when retries run out", async () => {
  clearVantaTokenCacheForTests();
  const { sleeps, sleep } = recordSleeps();
  let auditRequests = 0;
  const recovering = vantaClient(withVantaToken(async (_url, init) => {
    auditRequests += 1;
    if (auditRequests === 1) return hangUntilAborted(init);
    return jsonResponse(auditPage("audit-1", { hasNextPage: false, endCursor: null }));
  }), undefined, { sleep, timeoutMs: 20 });
  assert.equal((await recovering.listAudits()).length, 1);
  assert.equal(auditRequests, 2);
  assert.deepEqual(sleeps, [500]);

  clearVantaTokenCacheForTests();
  // A body that never finishes is a timeout too, since the timer runs until the body is read.
  const stalledBody = vantaClient(withVantaToken(async (_url, init) => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("{\"results\":"));
      init.signal.addEventListener("abort", () => controller.error(init.signal.reason), { once: true });
    },
  }))), undefined, { timeoutMs: 20 });
  await assert.rejects(stalledBody.listAudits(), /^Error: Vanta API request failed for \/audits after 4 attempts: timed out after 20 ms$/);
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient stops a retry wait as soon as the tool call aborts", async () => {
  clearVantaTokenCacheForTests();
  const controller = new AbortController();
  let waits = 0;
  const client = vantaClient(withVantaToken(async () => new Response("busy", { status: 503 })), undefined, {
    signal: controller.signal,
    sleep: () => {
      waits += 1;
      controller.abort(new Error("operator stopped the call"));
      return new Promise(() => {});
    },
  });

  await assert.rejects(client.listAudits(), { name: "ToolCallAbortedError" });
  assert.equal(waits, 1);
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient ends a read with the abort, not a retry, when the tool call aborts while the body is read", async () => {
  clearVantaTokenCacheForTests();
  const controller = new AbortController();
  let auditRequests = 0;
  const client = vantaClient(withVantaToken(async (_url, init) => {
    auditRequests += 1;
    return new Response(new ReadableStream({
      start(stream) {
        stream.enqueue(new TextEncoder().encode("{\"results\":"));
        init.signal.addEventListener("abort", () => stream.error(init.signal.reason), { once: true });
        setTimeout(() => controller.abort(new Error("operator stopped the call")), 5);
      },
    }));
  }), undefined, { signal: controller.signal });

  await assert.rejects(client.listAudits(), { name: "ToolCallAbortedError" });
  assert.equal(auditRequests, 1, "no attempt follows the abort");
  clearVantaTokenCacheForTests();
});

test("VantaAuditorClient keeps credentials out of errors when retries run out", async () => {
  const planted = {
    clientId: "Kd4Rw8Nq2Lx6Hv1Z",
    clientSecret: "Tm9Fb3Yc7Gs5Pj0W",
    accessToken: "Ua6Xe2Vk8Qn4Dr1J",
  };
  assertPlantedValuesWellFormed(assert, planted, [
    JSON.stringify(auditPage("audit-1", { hasNextPage: false, endCursor: null })),
    "Vanta API request failed for /audits (503 Service Unavailable) after 4 attempts: timed out after 20 ms",
  ]);
  const credentials = { clientId: planted.clientId, clientSecret: planted.clientSecret };
  const tokenEcho = JSON.stringify({ error: "unavailable", ...credentials });
  const echo = JSON.stringify({ error: "unavailable", ...planted });
  const failures = [];
  const capture = async (promise) => {
    await assert.rejects(promise, (error) => {
      failures.push(error.message);
      return true;
    });
  };

  clearVantaTokenCacheForTests();
  await capture(vantaClient(async () => new Response(tokenEcho, { status: 503, statusText: "Service Unavailable" }), credentials).listAudits());

  clearVantaTokenCacheForTests();
  await capture(vantaClient(async (input) => {
    if (new URL(String(input)).pathname === "/oauth/token") throw new TypeError(`connect failed for ${planted.clientSecret}`);
    return jsonResponse(auditPage("audit-1", { hasNextPage: false, endCursor: null }));
  }, credentials).listAudits());

  for (const apiFailure of [
    async () => new Response(echo, { status: 503, statusText: "Service Unavailable" }),
    async () => new Response(echo, { status: 429, statusText: "Too Many Requests", headers: { "retry-after": "90" } }),
    async () => { throw new TypeError(`socket hang up after Bearer ${planted.accessToken}`); },
  ]) {
    clearVantaTokenCacheForTests();
    await capture(vantaClient(async (input, init = {}) => {
      if ((init.method ?? "GET") === "POST") return jsonResponse({ access_token: planted.accessToken, expires_in: 3600 });
      return apiFailure();
    }, credentials).listAudits());
  }
  clearVantaTokenCacheForTests();

  assert.equal(failures.length, 5);
  assert.match(failures[0], /^Vanta authentication failed \(503 Service Unavailable\) after 4 attempts: /);
  assert.match(failures[1], /^Vanta authentication failed after 4 attempts: connect failed for \[redacted\]$/);
  assert.match(failures[2], /^Vanta API request failed for \/audits \(503 Service Unavailable\) after 4 attempts: /);
  assert.match(failures[3], /^Vanta API request failed for \/audits \(429 Too Many Requests\): the server asked to retry after 90 s/);
  assert.match(failures[4], /^Vanta API request failed for \/audits after 4 attempts: socket hang up after Bearer \[redacted\]$/);
  assertFragmentsAbsent(assert, failures.join("\n"), Object.values(planted), "Vanta retry errors");
});

test("checkVantaAuditorAccess reports healthy access when audits are visible", async () => {
  const result = await checkVantaAuditorAccess({
    async listAudits() {
      return [
        {
          id: "audit-2",
          customerDisplayName: null,
          customerOrganizationName: "Bravo Corp",
          framework: "ISO 27001",
          auditStartDate: "2026-02-01T00:00:00.000Z",
          auditEndDate: "2026-08-01T00:00:00.000Z",
        },
        {
          id: "audit-1",
          customerDisplayName: "Acme Security",
          customerOrganizationName: "Acme Security LLC",
          framework: "SOC 2",
          auditStartDate: "2026-01-01T00:00:00.000Z",
          auditEndDate: "2026-12-31T00:00:00.000Z",
        },
      ];
    },
  });

  assert.equal(result.status, "healthy");
  assert.equal(result.visibleAuditCount, 2);
  assert.equal(result.sampleAudits[0]?.id, "audit-1");
  assert.match(
    result.recommendedNextStep,
    /vanta_list_audits|vanta_export_audit/,
  );
  assert.match(result.notes[0] ?? "", /one active access token/i);
});

test("checkVantaAuditorAccess explains the no-audit case", async () => {
  const result = await checkVantaAuditorAccess({
    async listAudits() {
      return [];
    },
  });

  assert.equal(result.status, "authorized_no_audits");
  assert.equal(result.visibleAuditCount, 0);
  assert.deepEqual(result.sampleAudits, []);
  assert.match(result.notes[0] ?? "", /No audits were returned/i);
  assert.match(result.recommendedNextStep, /app type|auditor scopes|active audits/i);
});

test("exportVantaAuditPackage writes offline evidence package and zip archive", async () => {
  const audit = {
    id: "audit-1234567890",
    customerDisplayName: "Acme Security",
    customerOrganizationName: "Acme Security LLC",
    framework: "SOC 2",
    auditStartDate: "2026-01-01T00:00:00.000Z",
    auditEndDate: "2026-12-31T00:00:00.000Z",
  };

  const evidence = [
    {
      id: "ae-1",
      evidenceId: "ev-1",
      name: "=Danger Evidence",
      status: "SUBMITTED",
      description: "Customer uploaded artifact",
      evidenceType: "UPLOADED_DOCUMENT",
      testStatus: null,
      relatedControls: [{ name: "Access / IAM" }],
      creationDate: "2026-01-02T00:00:00.000Z",
      statusUpdatedDate: "2026-01-03T00:00:00.000Z",
    },
    {
      id: "ae-2",
      evidenceId: "ev-2",
      name: "Encryption policy",
      status: "REQUESTED",
      description: "Mapped to two controls",
      evidenceType: "VANTA_DOCUMENT",
      testStatus: "PASS",
      relatedControls: [{ name: "Access / IAM" }, { name: "Crypto" }],
      creationDate: "2026-01-04T00:00:00.000Z",
      statusUpdatedDate: "2026-01-05T00:00:00.000Z",
    },
    {
      id: "ae-3",
      evidenceId: "ev-3",
      name: "No control item",
      status: "REQUESTED",
      description: null,
      evidenceType: "LINK",
      testStatus: null,
      relatedControls: [],
      creationDate: "2026-01-06T00:00:00.000Z",
      statusUpdatedDate: "2026-01-07T00:00:00.000Z",
    },
  ];

  const mockClient = {
    async listEvidence() {
      return evidence;
    },
    async listEvidenceUrls(_auditId, auditEvidenceId) {
      if (auditEvidenceId === "ae-1") {
        return [
          {
            id: "url-1",
            url: "https://downloads.example.com/evidence-1.pdf",
            filename: "control-evidence.pdf",
            isDownloadable: true,
          },
        ];
      }

      if (auditEvidenceId === "ae-2") {
        return [
          {
            id: "url-2",
            url: "https://downloads.example.com/evidence-2.pdf",
            filename: "control-evidence.pdf",
            isDownloadable: true,
          },
        ];
      }

      return [];
    },
  };

  const fetchImpl = async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/evidence-1.pdf")) {
      return new Response(Buffer.from("pdf-one"), {
        status: 200,
        headers: { "content-length": "7" },
      });
    }
    if (url.endsWith("/evidence-2.pdf")) {
      return new Response(Buffer.from("pdf-two"), {
        status: 200,
        headers: { "content-length": "7" },
      });
    }
    throw new Error(`unexpected download URL: ${url}`);
  };

  const base = createTempBase("grclanker-vanta-export-");
  const outputRoot = resolve(base, "exports");
  const result = await exportVantaAuditPackage(mockClient, audit, outputRoot, {
    fetchImpl,
    downloadConcurrency: 2,
  });

  assert.equal(result.totalEvidenceItems, 3);
  assert.equal(result.totalFilesExported, 3);
  assert.equal(result.totalControlFolders, 3);
  assert.equal(result.errorCount, 0);
  assert.equal(result.complete, true);
  assert.deepEqual(result.incompleteEvidence, []);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(readFileSync(result.zipPath).subarray(0, 2).toString("utf8"), "PK");

  const auditInfo = JSON.parse(readFileSync(join(result.outputDir, "_audit_info.json"), "utf8"));
  assert.equal(auditInfo.customer_name, "Acme Security");
  assert.equal(auditInfo.total_files_exported, 3);
  assert.equal(auditInfo.complete, true);
  assert.deepEqual(auditInfo.incomplete_evidence, []);

  const csv = readFileSync(join(result.outputDir, "_index.csv"), "utf8");
  assert.match(csv, /'=Danger Evidence/);
  assert.match(csv.split("\n")[0], /,"export_status"$/);
  assert.equal(csv.trim().split("\n").slice(1).every((row) => row.endsWith(',"complete"')), true);

  const accessMetadata = JSON.parse(
    readFileSync(join(result.outputDir, "IAM", "metadata.json"), "utf8"),
  );
  assert.equal(accessMetadata.evidence_items.length, 2);
  assert.deepEqual(accessMetadata.evidence_items[0].files, ["control-evidence.pdf"]);
  assert.equal(accessMetadata.evidence_items[0].export_status, "complete");
  assert.equal("missing_files" in accessMetadata.evidence_items[0], false);

  const cryptoMetadata = JSON.parse(
    readFileSync(join(result.outputDir, "Crypto", "metadata.json"), "utf8"),
  );
  assert.equal(cryptoMetadata.evidence_items.length, 1);
  assert.deepEqual(cryptoMetadata.evidence_items[0].files, ["control-evidence.pdf"]);

  const unassignedMetadata = JSON.parse(
    readFileSync(join(result.outputDir, "_Unassigned", "metadata.json"), "utf8"),
  );
  assert.equal(unassignedMetadata.evidence_items.length, 1);
  assert.deepEqual(unassignedMetadata.evidence_items[0].files, []);
});

test("exportVantaAuditPackage records partial download failures in _errors.log", async () => {
  const audit = {
    id: "audit-abcdef1234",
    customerDisplayName: null,
    customerOrganizationName: "Bravo Corp",
    framework: "ISO 27001",
    auditStartDate: "2026-02-01T00:00:00.000Z",
    auditEndDate: "2026-08-01T00:00:00.000Z",
  };

  const mockClient = {
    async listEvidence() {
      return [
        {
          id: "ae-1",
          evidenceId: "ev-1",
          name: "Broken file",
          status: "REQUESTED",
          description: null,
          evidenceType: "UPLOADED_DOCUMENT",
          testStatus: null,
          relatedControls: [{ name: "Failures" }],
          creationDate: "2026-02-10T00:00:00.000Z",
          statusUpdatedDate: "2026-02-11T00:00:00.000Z",
        },
      ];
    },
    async listEvidenceUrls() {
      return [
        {
          id: "url-bad",
          url: "https://downloads.example.com/broken.pdf",
          filename: "broken.pdf",
          isDownloadable: true,
        },
      ];
    },
  };

  const fetchImpl = async () =>
    new Response("nope", {
      status: 500,
      statusText: "Internal Server Error",
    });

  const base = createTempBase("grclanker-vanta-errors-");
  const result = await exportVantaAuditPackage(mockClient, audit, resolve(base, "exports"), {
    fetchImpl,
    sleep: noSleep,
  });

  assert.equal(result.errorCount, 1);
  assert.equal(result.complete, false);
  assert.ok(existsSync(join(result.outputDir, "_errors.log")));
  assert.match(
    readFileSync(join(result.outputDir, "_errors.log"), "utf8"),
    /Failed to download broken\.pdf for Broken file \(Failures\): Download failed \(500 Internal Server Error\) after 4 attempts/,
  );
});

test("exportVantaAuditPackage allocates fresh bundles on sequential reruns", async () => {
  const audit = {
    id: "audit-rerun-123456",
    customerDisplayName: "Collision Test",
    customerOrganizationName: "Collision Test LLC",
    framework: "SOC 2",
    auditStartDate: "2026-01-01T00:00:00.000Z",
    auditEndDate: "2026-12-31T00:00:00.000Z",
  };
  const evidence = [{
    id: "ae-rerun",
    evidenceId: "ev-rerun",
    name: "Rerun evidence",
    status: "SUBMITTED",
    description: null,
    evidenceType: "UPLOADED_DOCUMENT",
    testStatus: null,
    relatedControls: [{ name: "IAM" }],
    creationDate: "2026-01-02T00:00:00.000Z",
    statusUpdatedDate: "2026-01-03T00:00:00.000Z",
  }];
  const client = {
    async listEvidence() {
      return evidence;
    },
    async listEvidenceUrls() {
      return [
        {
          id: "url-rerun-stale",
          url: "https://downloads.example.com/stale.txt",
          filename: "stale.txt",
          isDownloadable: true,
        },
        {
          id: "url-rerun-flaky",
          url: "https://downloads.example.com/flaky.txt",
          filename: "flaky.txt",
          isDownloadable: true,
        },
      ];
    },
  };
  let failDownload = true;
  const fetchImpl = async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    if (failDownload && url.endsWith("/flaky.txt")) {
      return new Response("failed", { status: 500, statusText: "Internal Server Error" });
    }
    const body = failDownload ? "stale-run" : "fresh-run";
    return new Response(body, {
      status: 200,
      headers: { "content-length": String(body.length) },
    });
  };
  const base = createTempBase("grclanker-vanta-rerun-");
  const outputRoot = resolve(base, "exports");

  const first = await exportVantaAuditPackage(client, audit, outputRoot, { fetchImpl, sleep: noSleep });
  const firstZipBytes = readFileSync(first.zipPath);
  assert.equal(first.errorCount, 1);
  assert.equal(first.complete, false);
  assert.ok(existsSync(join(first.outputDir, "_errors.log")));
  assert.ok([...readZipEntries(first.zipPath).values()].includes("stale-run"));

  failDownload = false;
  const second = await exportVantaAuditPackage(client, audit, outputRoot, { fetchImpl, sleep: noSleep });

  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.deepEqual(readFileSync(first.zipPath), firstZipBytes);
  assert.equal(second.errorCount, 0);
  assert.equal(second.complete, true);
  assert.equal(existsSync(join(second.outputDir, "_errors.log")), false);
  const secondZipEntries = readZipEntries(second.zipPath);
  assert.ok([...secondZipEntries.keys()].every((name) => !name.endsWith("/_errors.log")));
  assert.ok([...secondZipEntries.values()].includes("fresh-run"));
  assert.ok([...secondZipEntries.values()].every((content) => content !== "stale-run"));
});

test("exportVantaAuditPackage allocates distinct bundles for concurrent exports", async () => {
  const audit = {
    id: "audit-concurrent-123456",
    customerDisplayName: "Concurrent Test",
    customerOrganizationName: "Concurrent Test LLC",
    framework: "ISO 27001",
    auditStartDate: "2026-01-01T00:00:00.000Z",
    auditEndDate: "2026-12-31T00:00:00.000Z",
  };
  const client = {
    async listEvidence() {
      return [];
    },
    async listEvidenceUrls() {
      return [];
    },
  };
  const base = createTempBase("grclanker-vanta-concurrent-");
  const outputRoot = resolve(base, "exports");

  const [first, second] = await Promise.all([
    exportVantaAuditPackage(client, audit, outputRoot),
    exportVantaAuditPackage(client, audit, outputRoot),
  ]);

  assert.notEqual(first.outputDir, second.outputDir);
  assert.notEqual(first.zipPath, second.zipPath);
  assert.ok(existsSync(first.outputDir));
  assert.ok(existsSync(second.outputDir));
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
});

test("exportVantaAuditPackage writes the bundle again with fresh counts when another process takes its name mid-export", async () => {
  const audit = {
    id: "audit-race-123456",
    customerDisplayName: "Race Test",
    customerOrganizationName: "Race Test LLC",
    framework: "SOC 2",
    auditStartDate: "2026-01-01T00:00:00.000Z",
    auditEndDate: "2026-12-31T00:00:00.000Z",
  };
  const client = {
    async listEvidence() {
      return [{
        id: "ae-race",
        evidenceId: "ev-race",
        name: "Race evidence",
        status: "SUBMITTED",
        description: null,
        evidenceType: "UPLOADED_DOCUMENT",
        testStatus: null,
        relatedControls: [{ name: "IAM" }],
        creationDate: "2026-01-02T00:00:00.000Z",
        statusUpdatedDate: "2026-01-03T00:00:00.000Z",
      }];
    },
    async listEvidenceUrls() {
      return [
        { id: "url-race-good", url: "https://downloads.example.com/good.txt", filename: "good.txt", isDownloadable: true },
        { id: "url-race-bad", url: "https://downloads.example.com/bad.txt", filename: "bad.txt", isDownloadable: true },
      ];
    },
  };
  const base = createTempBase("grclanker-vanta-race-");
  const outputRoot = resolve(base, "exports");
  let takenName;
  let fetches = 0;
  const fetchImpl = async (input) => {
    fetches += 1;
    if (!takenName) {
      const [staging] = readdirSync(outputRoot).filter((name) => name.startsWith(".grclanker-staging-"));
      [takenName] = readdirSync(join(outputRoot, staging));
      mkdirSync(join(outputRoot, takenName));
    }
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/bad.txt")) return new Response("failed", { status: 500, statusText: "Internal Server Error" });
    return new Response("evidence", { status: 200, headers: { "content-length": "8" } });
  };

  const result = await exportVantaAuditPackage(client, audit, outputRoot, { fetchImpl, downloadConcurrency: 1, sleep: noSleep });

  assert.equal(result.outputDir, join(outputRoot, `${takenName}_1`));
  // Each run fetches good.txt once and bad.txt four times: the first try and three retries of its 500.
  assert.equal(fetches, 10, "the second run downloads the evidence again");
  assert.equal(result.totalFilesExported, 1);
  assert.equal(result.totalSizeBytes, 8);
  assert.equal(result.errorCount, 1);
  assert.equal(result.filesNotDownloaded, 1, "the rerun counts the missing file once");
  assert.deepEqual(result.incompleteEvidence.map((entry) => entry.missingFiles), [["IAM/bad.txt"]]);
  const auditInfo = JSON.parse(readFileSync(join(result.outputDir, "_audit_info.json"), "utf8"));
  assert.equal(auditInfo.total_files_exported, 1);
  assert.equal(auditInfo.files_not_downloaded, 1);
  assert.equal(readFileSync(join(result.outputDir, "_errors.log"), "utf8").trim().split("\n").length, 1);
  const [raceItem] = JSON.parse(readFileSync(join(result.outputDir, "IAM", "metadata.json"), "utf8")).evidence_items;
  assert.deepEqual(raceItem.files, ["good.txt", "bad.txt"]);
  assert.deepEqual(raceItem.missing_files, ["bad.txt"]);
  assert.ok([...readZipEntries(result.zipPath).keys()].every((name) => name.startsWith(`${takenName}_1/`)));
  assert.deepEqual(readdirSync(join(outputRoot, takenName)), [], "the other process's directory is untouched");
  assert.deepEqual(readdirSync(outputRoot).sort(), [takenName, `${takenName}_1`, `${takenName}_1.zip`].sort());
});

test("exportVantaAuditPackage omits signed URL secrets from redirect errors", async () => {
  const signature = "super-secret-signature";
  const audit = {
    id: "audit-redirect-1234",
    customerDisplayName: "Redirect Test",
    customerOrganizationName: "Redirect Test LLC",
    framework: "SOC 2",
    auditStartDate: "2026-01-01T00:00:00.000Z",
    auditEndDate: "2026-12-31T00:00:00.000Z",
  };
  const client = {
    async listEvidence() {
      return [{
        id: "ae-redirect",
        evidenceId: "ev-redirect",
        name: "Signed file",
        status: "SUBMITTED",
        description: null,
        evidenceType: "UPLOADED_DOCUMENT",
        testStatus: null,
        relatedControls: [{ name: "IAM" }],
        creationDate: "2026-01-02T00:00:00.000Z",
        statusUpdatedDate: "2026-01-03T00:00:00.000Z",
      }];
    },
    async listEvidenceUrls() {
      return [{
        id: "url-redirect",
        url: "https://downloads.example.com/file.pdf",
        filename: "file.pdf",
        isDownloadable: true,
      }];
    },
  };
  const fetchImpl = async () => new Response(null, {
    status: 302,
    headers: {
      location: `http://signed-user:${signature}@downloads.example.com/file.pdf?X-Amz-Signature=${signature}`,
    },
  });
  const base = createTempBase("grclanker-vanta-redirect-");
  const result = await exportVantaAuditPackage(client, audit, resolve(base, "exports"), { fetchImpl });
  const log = readFileSync(join(result.outputDir, "_errors.log"), "utf8");

  assert.equal(result.errorCount, 1);
  assert.match(log, /Redirected to non-HTTPS URL: http:\/\/downloads\.example\.com\/file\.pdf/);
  assert.equal(log.includes(signature), false);
  assert.equal(log.includes("signed-user"), false);
});

const GAP_AUDIT = {
  id: "audit-gap-123456",
  customerDisplayName: "Gap Test",
  customerOrganizationName: "Gap Test LLC",
  framework: "SOC 2",
  auditStartDate: "2026-01-01T00:00:00.000Z",
  auditEndDate: "2026-12-31T00:00:00.000Z",
};

function evidenceItem(id, name) {
  return {
    id,
    evidenceId: `ev-${id}`,
    name,
    status: "SUBMITTED",
    description: null,
    evidenceType: "UPLOADED_DOCUMENT",
    testStatus: null,
    relatedControls: [{ name: "IAM" }],
    creationDate: "2026-01-02T00:00:00.000Z",
    statusUpdatedDate: "2026-01-03T00:00:00.000Z",
  };
}

function resultsPage(data, pageInfo = { hasNextPage: false, endCursor: null }) {
  return { results: { data, pageInfo } };
}

function downloadable(filename) {
  return { id: `url-${filename}`, url: `https://downloads.example.com/${filename}`, filename, isDownloadable: true };
}

/** _index.csv rows keyed by audit evidence ID; every cell is quoted and none of these fixtures holds a quote. */
function readIndexRows(outputDir) {
  const [header, ...rows] = readFileSync(join(outputDir, "_index.csv"), "utf8").trim().split("\n");
  const cells = (line) => line.slice(1, -1).split("\",\"");
  const columns = cells(header);
  return new Map(rows.map((line) => {
    const record = Object.fromEntries(cells(line).map((cell, index) => [columns[index], cell]));
    return [record.audit_evidence_id, record];
  }));
}

function readControlItems(outputDir, control) {
  const metadata = JSON.parse(readFileSync(join(outputDir, control, "metadata.json"), "utf8"));
  return new Map(metadata.evidence_items.map((item) => [item.id, item]));
}

test("exportVantaAuditPackage marks evidence whose file listing ran out of retries as unknown, not empty", async () => {
  clearVantaTokenCacheForTests();
  const evidence = [
    evidenceItem("ae-listed", "Listed evidence"),
    evidenceItem("ae-unlisted", "Unlisted evidence"),
    evidenceItem("ae-empty", "Evidence with no files"),
  ];
  let unlistedRequests = 0;
  const client = vantaClient(withVantaToken(async (url) => {
    const path = url.pathname;
    if (path === `/v1/audits/${GAP_AUDIT.id}/evidence`) return jsonResponse(resultsPage(evidence));
    if (path.endsWith("/ae-listed/urls")) return jsonResponse(resultsPage([downloadable("listed.txt")]));
    if (path.endsWith("/ae-empty/urls")) return jsonResponse(resultsPage([]));
    if (path.endsWith("/ae-unlisted/urls")) {
      unlistedRequests += 1;
      if (!url.searchParams.get("pageCursor")) {
        return jsonResponse(resultsPage([downloadable("first-page.txt")], { hasNextPage: true, endCursor: "cursor-2" }));
      }
      return new Response("upstream unavailable", { status: 503, statusText: "Service Unavailable" });
    }
    return jsonResponse({ error: "not found" }, 404);
  }));
  const downloads = [];
  const fetchImpl = async (input) => {
    downloads.push(String(input));
    return new Response("evidence", { status: 200, headers: { "content-length": "8" } });
  };

  const result = await exportVantaAuditPackage(client, GAP_AUDIT, resolve(createTempBase("grclanker-vanta-unlisted-"), "exports"), {
    fetchImpl,
    sleep: noSleep,
  });

  assert.equal(unlistedRequests, 5, "the first page, then the first try and three retries of the second");
  assert.deepEqual(downloads, ["https://downloads.example.com/listed.txt"], "a failed listing's first page is not exported as its whole list");
  assert.equal(result.complete, false);
  assert.equal(result.evidenceWithUnknownUrls, 1);
  assert.equal(result.evidenceWithMissingFiles, 0);
  assert.equal(result.totalFilesExported, 1);
  const listingError = `Vanta API request failed for /audits/${GAP_AUDIT.id}/evidence/ae-unlisted/urls (503 Service Unavailable) after 4 attempts: upstream unavailable`;
  assert.deepEqual(result.incompleteEvidence, [
    { id: "ae-unlisted", name: "Unlisted evidence", status: "urls_unknown", missingFiles: [], reason: listingError },
  ]);

  const rows = readIndexRows(result.outputDir);
  assert.deepEqual([rows.get("ae-listed").file_count, rows.get("ae-listed").export_status], ["1", "complete"]);
  assert.deepEqual([rows.get("ae-unlisted").file_count, rows.get("ae-unlisted").export_status], ["unknown", "urls_unknown"]);
  assert.deepEqual([rows.get("ae-empty").file_count, rows.get("ae-empty").export_status], ["0", "complete"]);

  const items = readControlItems(result.outputDir, "IAM");
  assert.equal(items.get("ae-unlisted").files, null, "unknown files are not written as an empty list");
  assert.equal(items.get("ae-unlisted").export_status, "urls_unknown");
  assert.equal(items.get("ae-unlisted").export_error, listingError);
  assert.deepEqual(items.get("ae-empty").files, []);
  assert.equal(items.get("ae-empty").export_status, "complete");

  const auditInfo = JSON.parse(readFileSync(join(result.outputDir, "_audit_info.json"), "utf8"));
  assert.equal(auditInfo.complete, false);
  assert.equal(auditInfo.evidence_items_with_unknown_urls, 1);
  assert.equal(auditInfo.files_not_downloaded, 0);
  assert.deepEqual(auditInfo.incomplete_evidence, [
    { id: "ae-unlisted", name: "Unlisted evidence", export_status: "urls_unknown", missing_files: [], reason: listingError },
  ]);
  assert.ok(
    readFileSync(join(result.outputDir, "_errors.log"), "utf8")
      .includes(`Failed to list evidence URLs for Unlisted evidence (ae-unlisted): ${listingError}`),
  );
  clearVantaTokenCacheForTests();
});

test("exportVantaAuditPackage retries a download after 503 and a transport error, then keeps the file", async () => {
  const { sleeps, sleep } = recordSleeps();
  const client = {
    async listEvidence() {
      return [evidenceItem("ae-retry", "Retried evidence")];
    },
    async listEvidenceUrls() {
      return [downloadable("retried.txt")];
    },
  };
  let attempts = 0;
  const fetchImpl = async () => {
    attempts += 1;
    if (attempts === 1) return new Response("busy", { status: 503, headers: { "retry-after": "3" } });
    if (attempts === 2) throw new TypeError("fetch failed");
    return new Response("evidence", { status: 200, headers: { "content-length": "8" } });
  };

  const result = await exportVantaAuditPackage(client, GAP_AUDIT, resolve(createTempBase("grclanker-vanta-download-retry-"), "exports"), {
    fetchImpl,
    sleep,
  });

  assert.equal(attempts, 3);
  assert.deepEqual(sleeps, [3000, 1000]);
  assert.equal(result.complete, true);
  assert.equal(result.errorCount, 0);
  assert.equal(readFileSync(join(result.outputDir, "IAM", "retried.txt"), "utf8"), "evidence");
});

test("exportVantaAuditPackage removes a download whose body stalls or breaks partway and records it missing", async () => {
  const client = {
    async listEvidence() {
      return [evidenceItem("ae-partial", "Partial evidence")];
    },
    async listEvidenceUrls() {
      return [downloadable("stalled.txt"), downloadable("broken.txt"), downloadable("whole.txt")];
    },
  };
  const fetchImpl = async (input) => {
    const filename = String(input).split("/").pop();
    if (filename === "whole.txt") return new Response("evidence", { status: 200, headers: { "content-length": "8" } });
    return new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("partial "));
        if (filename === "broken.txt") setTimeout(() => controller.error(new Error("connection reset")), 5);
      },
    }), { status: 200 });
  };

  const result = await exportVantaAuditPackage(client, GAP_AUDIT, resolve(createTempBase("grclanker-vanta-partial-"), "exports"), {
    fetchImpl,
    timeoutMs: 50,
  });

  assert.equal(result.complete, false);
  assert.equal(result.totalFilesExported, 1);
  assert.equal(result.filesNotDownloaded, 2);
  const [gap] = result.incompleteEvidence;
  assert.deepEqual(gap.missingFiles, ["IAM/broken.txt", "IAM/stalled.txt"]);
  assert.equal(gap.reason, "Download failed partway: connection reset; Download stalled: no data for 50 ms");
  assert.deepEqual(readdirSync(join(result.outputDir, "IAM")).sort(), ["metadata.json", "whole.txt"], "no truncated file stays in the package");
  assert.deepEqual([...readZipEntries(result.zipPath).keys()].filter((name) => /stalled|broken/.test(name)), []);
  const item = readControlItems(result.outputDir, "IAM").get("ae-partial");
  assert.deepEqual(item.files, ["stalled.txt", "broken.txt", "whole.txt"]);
  assert.deepEqual(item.missing_files, ["broken.txt", "stalled.txt"]);
  assert.equal(item.export_status, "files_missing");
  assert.equal(readIndexRows(result.outputDir).get("ae-partial").export_status, "files_missing");
});

test("vanta_export_audit says in its text and details that a package with gaps is incomplete", async (t) => {
  clearVantaTokenCacheForTests();
  const tools = new Map();
  registerVantaTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const evidence = [
    evidenceItem("ae-whole", "Whole evidence"),
    evidenceItem("ae-forbidden", "Forbidden evidence"),
    evidenceItem("ae-missing", "Missing evidence"),
  ];
  const savedFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = savedFetch;
    clearVantaTokenCacheForTests();
  });
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    if ((init.method ?? "GET") === "POST" && url.pathname.endsWith("/oauth/token")) {
      return jsonResponse({ access_token: "token-1", expires_in: 3600 });
    }
    if (url.pathname.endsWith("/v1/audits")) return jsonResponse(resultsPage([GAP_AUDIT]));
    if (url.pathname.endsWith(`/audits/${GAP_AUDIT.id}/evidence`)) return jsonResponse(resultsPage(evidence));
    if (url.pathname.endsWith("/ae-whole/urls")) return jsonResponse(resultsPage([downloadable("whole.txt")]));
    if (url.pathname.endsWith("/ae-forbidden/urls")) {
      return new Response(JSON.stringify({ error: "forbidden" }), { status: 403, statusText: "Forbidden" });
    }
    if (url.pathname.endsWith("/ae-missing/urls")) return jsonResponse(resultsPage([downloadable("missing.txt")]));
    if (url.href === "https://downloads.example.com/whole.txt") {
      return new Response("evidence", { status: 200, headers: { "content-length": "8" } });
    }
    if (url.href === "https://downloads.example.com/missing.txt") return new Response("gone", { status: 404, statusText: "Not Found" });
    throw new Error(`unexpected request: ${url.href}`);
  };

  const result = await tools.get("vanta_export_audit").execute("call-incomplete", {
    audit_id: GAP_AUDIT.id,
    client_id: "client-id",
    client_secret: "client-secret",
    output_dir: resolve(createTempBase("grclanker-vanta-tool-incomplete-"), "exports"),
  });

  const text = result.content[0].text;
  assert.equal(result.isError, undefined);
  assert.match(text, /^Exported Vanta audit "Gap Test - SOC 2" as an incomplete package\./);
  assert.ok(text.includes(
    "The package is incomplete: 1 evidence item has unknown files because its file URL listing failed, "
      + "and 1 file for 1 evidence item could not be downloaded. See _errors.log and _audit_info.json.",
  ), text);
  assert.ok(text.includes(
    `  - Forbidden evidence (ae-forbidden): file URLs unknown: Vanta API request failed for /audits/${GAP_AUDIT.id}/evidence/ae-forbidden/urls (403 Forbidden): {"error":"forbidden"}`,
  ), text);
  assert.ok(text.includes("  - Missing evidence (ae-missing): 1 file not downloaded (IAM/missing.txt): Download failed (404 Not Found)"), text);
  assert.equal(result.details.complete, false);
  assert.match(result.details.incomplete_reason, /^The package is incomplete: /);
  assert.equal(result.details.evidence_items_with_unknown_urls, 1);
  assert.equal(result.details.evidence_items_with_missing_files, 1);
  assert.equal(result.details.files_not_downloaded, 1);
  assert.equal(result.details.total_files_exported, 1);
  assert.deepEqual(
    result.details.incomplete_evidence.map((entry) => [entry.id, entry.export_status, entry.missing_files]),
    [["ae-forbidden", "urls_unknown", []], ["ae-missing", "files_missing", ["IAM/missing.txt"]]],
  );
});

test("secure output helpers reject symlink escapes and filename helpers stay safe", () => {
  const base = createTempBase("grclanker-vanta-secure-");
  const outputRoot = resolve(base, "output");
  const outside = resolve(base, "outside");
  const linked = resolve(outputRoot, "linked");

  mkdirSync(outputRoot, { recursive: true });
  mkdirSync(outside, { recursive: true });
  symlinkSync(outside, linked, "dir");

  assert.throws(
    () => resolveSecureOutputPath(outputRoot, resolve(linked, "escape.txt")),
    /path traversal|symlink/,
  );
  assert.equal(sanitizeFilename("../../Quarterly*Report?.pdf"), "Quarterly_Report_.pdf");
  assert.equal(escapeCsvCell("=SUM(A1:A2)"), "'=SUM(A1:A2)");
});

writeFailureTest("exportVantaAuditPackage leaves nothing under the output root when a write fails partway", async () => {
  const base = createTempBase("grclanker-vanta-write-failure-");
  const audit = {
    id: "audit-write-failure-123456",
    customerDisplayName: "Write Failure Test",
    customerOrganizationName: "Write Failure Test LLC",
    framework: "SOC 2",
    auditStartDate: "2026-01-01T00:00:00.000Z",
    auditEndDate: "2026-12-31T00:00:00.000Z",
  };
  const client = {
    async listEvidence() {
      return [];
    },
    async listEvidenceUrls() {
      return [];
    },
  };
  // Without evidence the package writes only _audit_info.json and _index.csv, so the second write is the one that fails.
  await assertNoPartialBundleOnWriteFailure(base, () => exportVantaAuditPackage(client, audit, base), { failAt: 2 });
});
