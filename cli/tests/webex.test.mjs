import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  WebexApiClient,
  assessWebexCollaborationGovernance,
  assessWebexIdentity,
  assessWebexMeetingHybridSecurity,
  checkWebexAccess,
  exportWebexAuditBundle,
  resolveSecureOutputPath,
  resolveWebexConfiguration,
} from "../dist/extensions/grc-tools/webex.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    token: "webex-token",
    orgId: "org-123",
    baseUrl: "https://webexapis.com/v1",
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

test("resolveWebexConfiguration prefers explicit args over environment values", () => {
  const resolved = resolveWebexConfiguration(
    {
      token: "arg-token",
      org_id: "org-explicit",
      base_url: "https://example.invalid/v1",
      timeout_seconds: 9,
    },
    {
      WEBEX_TOKEN: "env-token",
      WEBEX_ORG_ID: "org-env",
    },
  );

  assert.equal(resolved.token, "arg-token");
  assert.equal(resolved.orgId, "org-explicit");
  assert.equal(resolved.baseUrl, "https://example.invalid/v1");
  assert.equal(resolved.timeoutMs, 9000);
  assert.ok(resolved.sourceChain.includes("arguments-token"));
});

test("WebexApiClient follows Webex Link pagination and sends bearer auth", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      max: url.searchParams.get("max"),
      auth: init.headers?.authorization,
    });

    if (seen.length === 1) {
      return jsonResponse(
        { items: [{ id: "person-1" }] },
        { headers: { link: '<https://webexapis.com/v1/people?max=1&cursor=next>; rel="next"' } },
      );
    }

    return jsonResponse({ items: [{ id: "person-2" }] });
  };

  const client = new WebexApiClient(resolveWebexConfiguration({ token: "webex-test" }, {}), { fetchImpl });
  const people = await client.listPeople(2);

  assert.deepEqual(people.map((person) => person.id), ["person-1", "person-2"]);
  assert.deepEqual(seen.map((request) => request.auth), ["Bearer webex-test", "Bearer webex-test"]);
  assert.equal(seen[0].max, "200");
});

test("checkWebexAccess reports readable Webex audit surfaces", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getMe() {
      return { id: "me-1", displayName: "Auditor" };
    },
    async listOrganizations() {
      return [{ id: "org-123" }];
    },
    async listPeople() {
      return [{ id: "person-1" }];
    },
    async listRoles() {
      return [{ id: "role-1" }];
    },
    async listLicenses() {
      return [{ id: "license-1" }];
    },
    async listMeetings() {
      return [{ id: "meeting-1" }];
    },
    async listRecordings() {
      return [{ id: "recording-1" }];
    },
    async listEvents() {
      return [{ id: "event-1" }];
    },
    async getAdminSettings() {
      return { ssoEnabled: true };
    },
    async getSecuritySettings() {
      return { externalCommunicationsRestricted: true };
    },
    async listHybridClusters() {
      return [{ id: "cluster-1" }];
    },
    async listDevices() {
      return [{ id: "device-1" }];
    },
    async listWebhooks() {
      return [{ id: "webhook-1" }];
    },
  };

  const result = await checkWebexAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 13);
  assert.match(result.recommendedNextStep, /webex_assess_identity/);
});

test("assessWebexIdentity flags missing SSO, admin MFA gaps, and excess admins", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async listOrganizations() {
      return [{ id: "org-123" }];
    },
    async listPeople() {
      return [
        { id: "u1", roles: ["role-admin"], mfaEnabled: false },
        { id: "u2", roles: ["role-admin", "role-compliance"], mfaEnabled: true },
        { id: "u3", roles: ["role-admin"], mfaEnabled: true },
      ];
    },
    async listRoles() {
      return [
        { id: "role-admin", name: "Full Administrator" },
        { id: "role-compliance", name: "Compliance Officer" },
      ];
    },
    async getAdminSettings() {
      return {
        ssoEnabled: false,
        adminMfaRequired: false,
      };
    },
  };

  const result = await assessWebexIdentity(client, { peopleLimit: 100, maxAdmins: 2 });
  assert.equal(result.findings.find((item) => item.id === "WEBEX-ID-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-ID-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-ID-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-ID-04")?.status, "warn");
});

test("assessWebexCollaborationGovernance flags weak collaboration controls and risky webhooks", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async listOrganizations() {
      return [{ id: "org-123" }];
    },
    async getSecuritySettings() {
      return {
        externalCommunicationsRestricted: false,
        fileSharingRestricted: false,
        guestAccessEnabled: true,
      };
    },
    async getAdminSettings() {
      return {
        recordingRetentionEnabled: false,
      };
    },
    async listEvents() {
      return [];
    },
    async listRecordings() {
      return [{ id: "rec-1", organizationOwned: false }];
    },
    async listRooms() {
      return [{ id: "room-1", title: "General" }];
    },
    async listWebhooks() {
      return [{ id: "hook-1", targetUrl: "http://example.com", secret: "" }];
    },
    async listLicenses() {
      return [{ id: "lic-1", totalUnits: 10, consumedUnits: 4 }];
    },
  };

  const result = await assessWebexCollaborationGovernance(client, {
    eventLimit: 100,
    recordingLimit: 100,
    webhookLimit: 100,
    licenseLimit: 100,
    roomLimit: 100,
  });
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-01")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-05")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-COLLAB-06")?.status, "warn");
});

test("assessWebexMeetingHybridSecurity flags missing meeting guards and unhealthy hybrid posture", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async listOrganizations() {
      return [{ id: "org-123" }];
    },
    async getAdminSettings() {
      return {
        guestAccessEnabled: true,
      };
    },
    async getMeetingPreferences() {
      return {
        e2eeEnabled: false,
        lobbyEnabled: false,
        passwordRequired: false,
        virtualBackgroundEnforced: false,
      };
    },
    async listMeetingSites() {
      return [];
    },
    async listMeetings() {
      return [{ id: "meeting-1", lobbyEnabled: false, passwordRequired: false }];
    },
    async listHybridClusters() {
      return [{ id: "cluster-1", status: "degraded" }];
    },
    async listHybridConnectors() {
      return [{ id: "connector-1", status: "inactive" }];
    },
    async listDevices() {
      return [
        { id: "device-1", firmwareStatus: "outdated" },
        { id: "device-2", managed: false },
      ];
    },
    async listWorkspaces() {
      return [{ id: "workspace-1" }];
    },
  };

  const result = await assessWebexMeetingHybridSecurity(client, { meetingLimit: 50, deviceLimit: 50 });
  assert.equal(result.findings.find((item) => item.id === "WEBEX-MTG-01")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-MTG-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-MTG-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-MTG-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "WEBEX-MTG-05")?.status, "fail");
});

test("exportWebexAuditBundle writes reports, analysis, and archive", async () => {
  const base = createTempBase("grclanker-webex-export-");
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getMe() {
      return { id: "me-1", displayName: "Auditor" };
    },
    async listOrganizations() {
      return [{ id: "org-123" }];
    },
    async listPeople() {
      return [{ id: "u1", roles: ["role-admin"], mfaEnabled: true }];
    },
    async listRoles() {
      return [
        { id: "role-admin", name: "Full Administrator" },
        { id: "role-compliance", name: "Compliance Officer" },
      ];
    },
    async getAdminSettings() {
      return {
        ssoEnabled: true,
        adminMfaRequired: true,
        recordingRetentionEnabled: true,
        guestAccessRestricted: true,
        calling: { srtpRequired: true },
      };
    },
    async getSecuritySettings() {
      return {
        externalCommunicationsRestricted: true,
        fileSharingRestricted: true,
        guestAccessRestricted: true,
      };
    },
    async listLicenses() {
      return [{ id: "lic-1", totalUnits: 10, consumedUnits: 9 }];
    },
    async listMeetings() {
      return [{ id: "meeting-1", lobbyEnabled: true, passwordRequired: true }];
    },
    async listRecordings() {
      return [{ id: "rec-1", organizationOwned: true }];
    },
    async listEvents() {
      return [{ id: "event-1", action: "admin_role_added" }];
    },
    async listHybridClusters() {
      return [{ id: "cluster-1", status: "healthy" }];
    },
    async listDevices() {
      return [{ id: "device-1", firmwareStatus: "current", managed: true }];
    },
    async listWebhooks() {
      return [{ id: "hook-1", targetUrl: "https://example.com", secret: "secret" }];
    },
    async listRooms() {
      return [{ id: "room-1", title: "General", classification: "Internal" }];
    },
    async getMeetingPreferences() {
      return {
        e2eeEnabled: true,
        lobbyEnabled: true,
        passwordRequired: true,
        virtualBackgroundEnforced: true,
      };
    },
    async listMeetingSites() {
      return [{ id: "site-1", lobbyEnabled: true, passwordRequired: true }];
    },
    async listHybridConnectors() {
      return [{ id: "connector-1", status: "active" }];
    },
    async listWorkspaces() {
      return [{ id: "workspace-1" }];
    },
  };

  const result = await exportWebexAuditBundle(client, sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.fileCount >= 12);
  assert.equal(result.findingCount, 15);

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.org_id, "org-123");
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-webex-path-");
  const outside = createTempBase("grclanker-webex-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});
