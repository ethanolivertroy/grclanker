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
  sanitizeFilename,
} from "../dist/extensions/grc-tools/vanta.js";
import { assertNoPartialBundleOnWriteFailure, writeFailureTest } from "./helpers/atomic-output.mjs";
import { readZipEntries } from "./helpers/bundle-contents.mjs";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function vantaClient(fetchImpl, credentials = { clientId: "client-id", clientSecret: "client-secret" }) {
  return new VantaAuditorClient(credentials, {
    baseUrl: "http://vanta.test/v1",
    tokenUrl: "http://vanta.test/oauth/token",
    fetchImpl,
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
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(readFileSync(result.zipPath).subarray(0, 2).toString("utf8"), "PK");

  const auditInfo = JSON.parse(readFileSync(join(result.outputDir, "_audit_info.json"), "utf8"));
  assert.equal(auditInfo.customer_name, "Acme Security");
  assert.equal(auditInfo.total_files_exported, 3);

  const csv = readFileSync(join(result.outputDir, "_index.csv"), "utf8");
  assert.match(csv, /'=Danger Evidence/);

  const accessMetadata = JSON.parse(
    readFileSync(join(result.outputDir, "IAM", "metadata.json"), "utf8"),
  );
  assert.equal(accessMetadata.evidence_items.length, 2);
  assert.deepEqual(accessMetadata.evidence_items[0].files, ["control-evidence.pdf"]);

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
  });

  assert.equal(result.errorCount, 1);
  assert.ok(existsSync(join(result.outputDir, "_errors.log")));
  assert.match(
    readFileSync(join(result.outputDir, "_errors.log"), "utf8"),
    /Failed to download broken\.pdf/,
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

  const first = await exportVantaAuditPackage(client, audit, outputRoot, { fetchImpl });
  const firstZipBytes = readFileSync(first.zipPath);
  assert.equal(first.errorCount, 1);
  assert.ok(existsSync(join(first.outputDir, "_errors.log")));
  assert.ok([...readZipEntries(first.zipPath).values()].includes("stale-run"));

  failDownload = false;
  const second = await exportVantaAuditPackage(client, audit, outputRoot, { fetchImpl });

  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.deepEqual(readFileSync(first.zipPath), firstZipBytes);
  assert.equal(second.errorCount, 0);
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

  const result = await exportVantaAuditPackage(client, audit, outputRoot, { fetchImpl, downloadConcurrency: 1 });

  assert.equal(result.outputDir, join(outputRoot, `${takenName}_1`));
  assert.equal(fetches, 4, "the second run downloads the evidence again");
  assert.equal(result.totalFilesExported, 1);
  assert.equal(result.totalSizeBytes, 8);
  assert.equal(result.errorCount, 1);
  assert.equal(JSON.parse(readFileSync(join(result.outputDir, "_audit_info.json"), "utf8")).total_files_exported, 1);
  assert.equal(readFileSync(join(result.outputDir, "_errors.log"), "utf8").trim().split("\n").length, 1);
  assert.deepEqual(JSON.parse(readFileSync(join(result.outputDir, "IAM", "metadata.json"), "utf8")).evidence_items[0].files, ["good.txt", "bad.txt"]);
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
