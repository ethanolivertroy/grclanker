import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
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

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
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
