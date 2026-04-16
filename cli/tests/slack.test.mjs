import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SlackApiClient,
  assessSlackAdminAccess,
  assessSlackIdentity,
  assessSlackIntegrations,
  assessSlackMonitoring,
  checkSlackAccess,
  exportSlackAuditBundle,
  resolveSlackConfiguration,
} from "../dist/extensions/grc-tools/slack.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("resolveSlackConfiguration prefers explicit non-secret args and env tokens", () => {
  const resolved = resolveSlackConfiguration(
    {
      org_id: " E123 ",
      timeout_seconds: "12",
    },
    {
      SLACK_USER_TOKEN: "xoxp-env",
      SLACK_SCIM_TOKEN: "scim-env",
    },
  );

  assert.equal(resolved.token, "xoxp-env");
  assert.equal(resolved.scimToken, "scim-env");
  assert.equal(resolved.orgId, "E123");
  assert.equal(resolved.timeoutMs, 12_000);
  assert.ok(resolved.sourceChain.includes("environment-token"));
  assert.ok(resolved.sourceChain.includes("environment-scim"));

  assert.throws(
    () => resolveSlackConfiguration({}, {}),
    /SLACK_USER_TOKEN or a token argument is required/,
  );
});

test("SlackApiClient sends bearer auth and follows Slack cursor pagination", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      cursor: url.searchParams.get("cursor"),
      auth: init.headers?.authorization,
    });

    if (!url.searchParams.get("cursor")) {
      return jsonResponse({
        ok: true,
        members: [{ id: "U1", name: "one" }],
        response_metadata: { next_cursor: "next-page" },
      });
    }

    return jsonResponse({
      ok: true,
      members: [{ id: "U2", name: "two" }],
      response_metadata: { next_cursor: "" },
    });
  };

  const client = new SlackApiClient(
    resolveSlackConfiguration({ token: "xoxp-test" }, {}),
    { fetchImpl },
  );

  const users = await client.paginateWeb("users.list", ["members"], {}, { limit: 2, pageLimit: 1 });
  assert.deepEqual(users.map((user) => user.id), ["U1", "U2"]);
  assert.deepEqual(seen.map((request) => request.auth), ["Bearer xoxp-test", "Bearer xoxp-test"]);
  assert.equal(seen[1].cursor, "next-page");
});

test("checkSlackAccess reports readable Slack audit surfaces", async () => {
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const pathname = url.pathname;

    if (pathname === "/api/auth.test") {
      return jsonResponse({ ok: true, team: "Acme", team_id: "T1", user: "auditor" });
    }
    if (pathname === "/api/admin.enterprise.info") {
      return jsonResponse({ ok: true, enterprise: { id: "E1", name: "Acme" } });
    }
    if (pathname === "/api/admin.teams.list") {
      return jsonResponse({ ok: true, teams: [{ id: "T1", name: "Core" }] });
    }
    if (pathname === "/api/users.list") {
      return jsonResponse({ ok: true, members: [{ id: "U1" }] });
    }
    if (pathname === "/api/admin.users.list") {
      return jsonResponse({ ok: true, users: [{ id: "U1" }] });
    }
    if (pathname === "/api/admin.apps.approved.list") {
      return jsonResponse({ ok: true, apps: [{ id: "A1" }] });
    }
    if (pathname === "/api/admin.apps.restricted.list") {
      return jsonResponse({ ok: true, apps: [{ id: "A2" }] });
    }
    if (pathname === "/api/admin.barriers.list") {
      return jsonResponse({ ok: true, barriers: [{ id: "B1" }] });
    }
    if (pathname === "/api/discovery.enterprise.info") {
      return jsonResponse({ ok: true, enterprise: { dlp_enabled: true } });
    }
    if (pathname === "/audit/v1/logs") {
      return jsonResponse({ entries: [{ id: "L1" }] });
    }
    if (pathname === "/audit/v1/schemas") {
      return jsonResponse({ schemas: [{ name: "user_login" }] });
    }
    if (pathname === "/scim/v2/Users") {
      return jsonResponse({ totalResults: 1, Resources: [{ id: "S1" }] });
    }
    if (pathname === "/scim/v2/Groups") {
      return jsonResponse({ totalResults: 1, Resources: [{ id: "G1" }] });
    }
    if (pathname === "/scim/v2/ServiceProviderConfig") {
      return jsonResponse({ patch: { supported: true } });
    }
    return jsonResponse({ ok: false, error: "not_found" }, 404);
  };

  const client = new SlackApiClient(
    resolveSlackConfiguration({ token: "xoxp-test", scim_token: "scim-test", org_id: "E1" }, {}),
    { fetchImpl },
  );

  const result = await checkSlackAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 13);
  assert.match(result.recommendedNextStep, /slack_assess_identity/);
});

test("assessSlackIdentity flags missing MFA and SCIM lifecycle gaps", async () => {
  const client = {
    async paginateWeb(method) {
      assert.equal(method, "users.list");
      return [
        { id: "U1", name: "no-mfa", has_2fa: false, profile: { email: "one@example.com" } },
        { id: "U2", name: "guest", has_2fa: true, is_restricted: true, profile: { email: "guest@example.com" } },
        { id: "U3", name: "deleted", deleted: true, profile: { email: "gone@example.com" } },
      ];
    },
    async scim(path) {
      assert.equal(path, "/ServiceProviderConfig");
      return { patch: { supported: true } };
    },
    async paginateScim(path) {
      assert.equal(path, "/Users");
      return [
        { id: "S1", userName: "gone@example.com", active: true },
        { id: "S2", userName: "guest@example.com", active: true },
      ];
    },
  };

  const result = await assessSlackIdentity(client);
  assert.equal(result.findings.find((item) => item.id === "SLACK-ID-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "SLACK-ID-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "SLACK-ID-03")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "SLACK-ID-04")?.status, "fail");
});

test("assessSlackAdminAccess flags excessive admins, SSO, session, and discoverability gaps", async () => {
  const client = {
    getOrgQuery() {
      return { enterprise_id: "E1" };
    },
    async paginateWeb(method) {
      assert.equal(method, "admin.teams.list");
      return [{ id: "T1", name: "Core" }];
    },
    async web(method) {
      if (method === "admin.teams.settings.info") {
        return {
          ok: true,
          team: {
            sso_required: false,
            session_duration_hours: 48,
            idle_timeout_minutes: 90,
            discoverability: "open",
          },
        };
      }
      if (method === "admin.teams.admins.list") {
        return { ok: true, admins: ["U1", "U2", "U3", "U4", "U5", "U6"] };
      }
      throw new Error(`unexpected method ${method}`);
    },
  };

  const result = await assessSlackAdminAccess(client, { maxWorkspaceAdmins: 5, maxSessionHours: 24, maxIdleMinutes: 30 });
  assert.equal(result.findings.find((item) => item.id === "SLACK-ADMIN-01")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "SLACK-ADMIN-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "SLACK-ADMIN-03")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "SLACK-ADMIN-04")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "SLACK-ADMIN-05")?.status, "warn");
});

test("assessSlackIntegrations flags custom apps, empty restricted policy, missing barriers, and no Discovery API", async () => {
  const client = {
    getOrgQuery() {
      return { enterprise_id: "E1" };
    },
    async paginateWeb(method) {
      if (method === "admin.apps.approved.list") {
        return [
          { id: "A1", name: "Custom CI", is_custom: true },
          { id: "A2", name: "Exporter", scopes: ["admin", "files:read"] },
        ];
      }
      if (method === "admin.apps.restricted.list") return [];
      if (method === "admin.barriers.list") return [];
      throw new Error(`unexpected method ${method}`);
    },
    async web(method) {
      assert.equal(method, "discovery.enterprise.info");
      throw new Error("missing_scope");
    },
  };

  const result = await assessSlackIntegrations(client);
  assert.equal(result.findings.find((item) => item.id === "SLACK-APP-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "SLACK-APP-02")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "SLACK-APP-03")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "SLACK-APP-04")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "SLACK-APP-05")?.status, "warn");
});

test("assessSlackMonitoring flags stale audit logs and missing security event visibility", async () => {
  const client = {
    getNow: () => new Date("2026-04-15T00:00:00.000Z"),
    async audit(path) {
      if (path === "/logs") {
        return {
          entries: [
            { id: "L1", action: "file_downloaded", date_create: "2026-04-10T00:00:00Z" },
          ],
        };
      }
      if (path === "/schemas") {
        throw new Error("missing_scope");
      }
      throw new Error(`unexpected path ${path}`);
    },
  };

  const result = await assessSlackMonitoring(client, { days: 30 });
  assert.equal(result.findings.find((item) => item.id === "SLACK-MON-01")?.status, "pass");
  assert.equal(result.findings.find((item) => item.id === "SLACK-MON-02")?.status, "fail");
  assert.equal(result.findings.find((item) => item.id === "SLACK-MON-03")?.status, "warn");
  assert.equal(result.findings.find((item) => item.id === "SLACK-MON-04")?.status, "warn");
});

test("exportSlackAuditBundle writes reports, normalized evidence, and archive", async () => {
  const base = createTempBase("grclanker-slack-export-");
  const client = {
    getNow: () => new Date("2026-04-15T00:00:00.000Z"),
    getOrgQuery() {
      return { enterprise_id: "E1" };
    },
    async web(method) {
      if (method === "auth.test") return { ok: true, team: "Acme", team_id: "T1", user: "auditor" };
      if (method === "admin.enterprise.info") return { ok: true, enterprise: { id: "E1" } };
      if (method === "admin.teams.list") return { ok: true, teams: [{ id: "T1", name: "Core" }] };
      if (method === "users.list") return { ok: true, members: [{ id: "U1", has_2fa: true, profile: { email: "one@example.com" } }] };
      if (method === "admin.users.list") return { ok: true, users: [{ id: "U1" }] };
      if (method === "admin.apps.approved.list") return { ok: true, apps: [{ id: "A1", name: "Good" }] };
      if (method === "admin.apps.restricted.list") return { ok: true, apps: [{ id: "A2", name: "Bad" }] };
      if (method === "admin.barriers.list") return { ok: true, barriers: [{ id: "B1" }] };
      if (method === "discovery.enterprise.info") return { ok: true, enterprise: { dlp_enabled: true } };
      if (method === "admin.teams.settings.info") {
        return { ok: true, team: { sso_required: true, session_duration_hours: 12, idle_timeout_minutes: 15 } };
      }
      if (method === "admin.teams.admins.list") return { ok: true, admins: ["U1"] };
      throw new Error(`unexpected method ${method}`);
    },
    async paginateWeb(method) {
      if (method === "users.list") return [{ id: "U1", has_2fa: true, profile: { email: "one@example.com" } }];
      if (method === "admin.teams.list") return [{ id: "T1", name: "Core" }];
      if (method === "admin.apps.approved.list") return [{ id: "A1", name: "Good" }];
      if (method === "admin.apps.restricted.list") return [{ id: "A2", name: "Bad" }];
      if (method === "admin.barriers.list") return [{ id: "B1" }];
      throw new Error(`unexpected method ${method}`);
    },
    async scim(path) {
      if (path === "/ServiceProviderConfig") return { patch: { supported: true } };
      if (path === "/Users") return { totalResults: 1, Resources: [{ id: "S1" }] };
      if (path === "/Groups") return { totalResults: 1, Resources: [{ id: "G1" }] };
      throw new Error(`unexpected path ${path}`);
    },
    async paginateScim(path) {
      assert.equal(path, "/Users");
      return [{ id: "S1", userName: "one@example.com", active: true }];
    },
    async audit(path) {
      if (path === "/logs") {
        return { entries: [{ id: "L1", action: "user_login", date_create: "2026-04-15T00:00:00Z" }] };
      }
      if (path === "/schemas") return { schemas: [{ name: "user_login" }] };
      throw new Error(`unexpected path ${path}`);
    },
  };
  const config = resolveSlackConfiguration({ token: "xoxp-test", scim_token: "scim-test", org_id: "E1" }, {});

  const result = await exportSlackAuditBundle(client, config, base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.fileCount >= 12);
  assert.equal(result.findingCount, 20);

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.target, "E1");
  assert.equal(metadata.scim_configured, true);
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
});
