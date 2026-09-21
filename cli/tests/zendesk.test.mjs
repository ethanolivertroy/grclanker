import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ZendeskApiClient,
  ZendeskApiError,
  assessZendeskAccessControl,
  assessZendeskAuthentication,
  assessZendeskDataProtection,
  assessZendeskIntegrations,
  checkZendeskAccess,
  exportZendeskAuditBundle,
  resolveSecureOutputPath,
  resolveZendeskConfiguration,
} from "../dist/extensions/grc-tools/zendesk.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const NOW = new Date("2026-09-21T12:00:00.000Z");
const DAY_MS = 24 * 60 * 60 * 1000;

function daysAgo(days) {
  return new Date(NOW.getTime() - days * DAY_MS).toISOString();
}

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    subdomain: "acme",
    baseUrl: "https://acme.zendesk.com/api/v2",
    authMode: "api_token",
    email: "auditor@example.com",
    apiToken: "secret-api-token-value",
    oauthToken: undefined,
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    statusText: options.statusText ?? "",
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function list(items, truncated = false) {
  return { items, truncated, pages: 1 };
}

function forbidden(name) {
  return () => {
    throw new ZendeskApiError(`Zendesk request failed for ${name} (403 Forbidden): You do not have access`, 403);
  };
}

function teamMember(overrides = {}) {
  return {
    id: overrides.id ?? 1,
    email: overrides.email ?? `user-${overrides.id ?? 1}@example.com`,
    name: overrides.name ?? `User ${overrides.id ?? 1}`,
    role: overrides.role ?? "agent",
    active: true,
    suspended: false,
    two_factor_auth_enabled: true,
    restricted_agent: overrides.role === "admin" ? false : true,
    last_login_at: daysAgo(3),
    ...overrides,
  };
}

function healthySettings(overrides = {}) {
  return {
    active_features: { sandbox: true, google_login: false, facebook_login: false, twitter_login: false, ...(overrides.active_features ?? {}) },
    api: { api_token_access: false, api_password_access_end_users: false, ...(overrides.api ?? {}) },
    tickets: { private_attachments: true, agent_ticket_deletion: false, email_attachments: true, ...(overrides.tickets ?? {}) },
    limits: { attachment_size: 52428800, ...(overrides.limits ?? {}) },
    google_apps: { has_google_apps: false },
  };
}

function healthyClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getCurrentUser() {
      return { id: 1, email: "auditor@example.com", role: "admin" };
    },
    async getAccountSettings() {
      return healthySettings();
    },
    async listTeamMembers() {
      return list([
        teamMember({ id: 1, role: "admin", email: "auditor@example.com" }),
        teamMember({ id: 2, role: "admin" }),
        teamMember({ id: 3, role: "agent" }),
        teamMember({ id: 4, role: "agent" }),
      ]);
    },
    async listCustomRoles() {
      return list([
        {
          id: 10,
          name: "Tier 1",
          team_member_count: 2,
          configuration: {
            manage_roles: "none",
            manage_team_members: "none",
            manage_api_credentials: false,
            manage_business_rules: false,
            manage_triggers: false,
            ticket_access: "within-groups",
            ticket_redaction: true,
            manage_deletion_schedules: "none",
          },
        },
      ]);
    },
    async listGroups() {
      return list([
        { id: 100, name: "Support", is_public: true, deleted: false },
        { id: 101, name: "Billing", is_public: false, deleted: false },
      ]);
    },
    async listGroupMemberships() {
      return list([
        { id: 1, user_id: 1, group_id: 100 },
        { id: 2, user_id: 2, group_id: 100 },
        { id: 3, user_id: 3, group_id: 101 },
        { id: 4, user_id: 4, group_id: 101 },
      ]);
    },
    async listRecentAuditLogs() {
      return list([
        { id: 1, action: "update", created_at: daysAgo(0) },
        { id: 2, action: "create", created_at: daysAgo(1) },
        { id: 3, action: "login", created_at: daysAgo(2) },
      ]);
    },
    async getOldestAuditLog() {
      return { id: 0, action: "create", created_at: daysAgo(400) };
    },
    async listOAuthClients() {
      return list([
        { id: 1, name: "Reporting", identifier: "reporting", kind: "confidential", scope: "read", redirect_uri: ["https://reports.example.com/callback"] },
      ]);
    },
    async listOAuthTokens() {
      return list([
        { id: 1, client_id: 1, scopes: ["read"], expires_at: daysAgo(-30), used_at: daysAgo(1), created_at: daysAgo(40) },
      ]);
    },
    async listAppInstallations() {
      return list([]);
    },
    async listOwnedApps() {
      return list([]);
    },
    async listBrands() {
      return list([
        { id: 1, name: "Acme", active: true, is_deleted: false, help_center_state: "enabled", has_help_center: true, host_mapping: null },
      ]);
    },
    async listWebhooks() {
      return list([
        { id: "wh1", name: "Pager", status: "active", endpoint: "https://hooks.example.com/zendesk", authentication: { type: "bearer_token" } },
      ]);
    },
    async listTargets() {
      return list([]);
    },
    async listTriggers() {
      return list([
        { id: 1, title: "Notify requester", active: true, actions: [{ field: "notification_user", value: ["requester_id", "Update", "Body"] }] },
      ]);
    },
    async listAutomations() {
      return list([
        { id: 1, title: "Close solved", active: true, actions: [{ field: "status", value: "closed" }] },
      ]);
    },
    async listSharingAgreements() {
      return list([]);
    },
    async listSuspendedTickets() {
      return list([]);
    },
    ...overrides,
  };
}

const LIST_METHODS = [
  "listTeamMembers",
  "listCustomRoles",
  "listGroups",
  "listGroupMemberships",
  "listRecentAuditLogs",
  "listOAuthClients",
  "listOAuthTokens",
  "listAppInstallations",
  "listOwnedApps",
  "listBrands",
  "listWebhooks",
  "listTargets",
  "listTriggers",
  "listAutomations",
  "listSharingAgreements",
  "listSuspendedTickets",
];

function forbiddenClient() {
  const overrides = {};
  for (const method of [...LIST_METHODS, "getAccountSettings", "getOldestAuditLog"]) {
    overrides[method] = forbidden(method);
  }
  return healthyClient(overrides);
}

function emptyClient() {
  const overrides = {};
  for (const method of LIST_METHODS) {
    overrides[method] = async () => list([]);
  }
  overrides.getOldestAuditLog = async () => undefined;
  return healthyClient(overrides);
}

function truncatedClient(role = "admin") {
  const base = healthyClient();
  const overrides = {
    async getCurrentUser() {
      return { id: 3, email: "agent@example.com", role };
    },
  };
  for (const method of LIST_METHODS) {
    overrides[method] = async (...args) => {
      const result = await base[method](...args);
      return { ...result, truncated: true };
    };
  }
  return healthyClient(overrides);
}

async function runAllAssessments(client) {
  const options = { now: () => NOW };
  return [
    await assessZendeskAuthentication(client, options),
    await assessZendeskAccessControl(client, options),
    await assessZendeskDataProtection(client, options),
    await assessZendeskIntegrations(client, options),
  ];
}

function findingById(result, id) {
  const found = result.findings.find((item) => item.id === id);
  assert.ok(found, `expected finding ${id}`);
  return found;
}

function statusMap(results) {
  const map = new Map();
  for (const result of results) {
    for (const item of result.findings) map.set(item.id, item.status);
  }
  return map;
}

test("resolveZendeskConfiguration prefers explicit args over env and config file", () => {
  const base = createTempBase("grclanker-zendesk-config-");
  const configPath = join(base, "config.json");
  writeFileSync(configPath, JSON.stringify({ subdomain: "file-sub", email: "file@example.com", api_token: "file-token", timeout_seconds: 7 }));

  const resolved = resolveZendeskConfiguration(
    { subdomain: "https://arg-sub.zendesk.com", email: "arg@example.com", api_token: "arg-token", config_file: configPath, timeout_seconds: 12 },
    { ZENDESK_SUBDOMAIN: "env-sub", ZENDESK_EMAIL: "env@example.com", ZENDESK_API_TOKEN: "env-token" },
    base,
  );

  assert.equal(resolved.subdomain, "arg-sub");
  assert.equal(resolved.email, "arg@example.com");
  assert.equal(resolved.apiToken, "arg-token");
  assert.equal(resolved.authMode, "api_token");
  assert.equal(resolved.baseUrl, "https://arg-sub.zendesk.com/api/v2");
  assert.equal(resolved.timeoutMs, 12000);
  assert.ok(resolved.sourceChain.includes("subdomain:arguments"));
});

test("resolveZendeskConfiguration prefers env over config file and falls back to the file", () => {
  const base = createTempBase("grclanker-zendesk-config-");
  const configPath = join(base, "config.json");
  writeFileSync(configPath, JSON.stringify({ subdomain: "file-sub", oauth_token: "file-oauth", timeout_seconds: 7 }));

  const fromEnv = resolveZendeskConfiguration({}, { ZENDESK_SUBDOMAIN: "env-sub", ZENDESK_OAUTH_TOKEN: "env-oauth", ZENDESK_CONFIG_FILE: configPath }, base);
  assert.equal(fromEnv.subdomain, "env-sub");
  assert.equal(fromEnv.authMode, "oauth");
  assert.equal(fromEnv.oauthToken, "env-oauth");
  assert.equal(fromEnv.timeoutMs, 7000);
  assert.ok(fromEnv.sourceChain.includes("oauth-token:environment"));

  const fromFile = resolveZendeskConfiguration({}, { ZENDESK_CONFIG_FILE: configPath }, base);
  assert.equal(fromFile.subdomain, "file-sub");
  assert.equal(fromFile.oauthToken, "file-oauth");
  assert.ok(fromFile.sourceChain.includes("subdomain:config-file"));

  mkdirSync(join(base, ".zendesk"), { recursive: true });
  writeFileSync(join(base, ".zendesk", "config.json"), JSON.stringify({ subdomain: "home-sub", email: "home@example.com", api_token: "home-token" }));
  const fromHome = resolveZendeskConfiguration({}, {}, base);
  assert.equal(fromHome.subdomain, "home-sub");
  assert.equal(fromHome.authMode, "api_token");
});

test("resolveZendeskConfiguration selects auth mode and rejects incomplete credentials", () => {
  const base = createTempBase("grclanker-zendesk-config-");
  const both = resolveZendeskConfiguration({}, { ZENDESK_SUBDOMAIN: "acme", ZENDESK_EMAIL: "a@example.com", ZENDESK_API_TOKEN: "tok", ZENDESK_OAUTH_TOKEN: "oauth" }, base);
  assert.equal(both.authMode, "oauth");
  assert.equal(both.apiToken, undefined);

  const explicitToken = resolveZendeskConfiguration({ email: "a@example.com", api_token: "tok" }, { ZENDESK_SUBDOMAIN: "acme", ZENDESK_OAUTH_TOKEN: "oauth" }, base);
  assert.equal(explicitToken.authMode, "api_token");

  assert.throws(() => resolveZendeskConfiguration({}, { ZENDESK_EMAIL: "a@example.com", ZENDESK_API_TOKEN: "tok" }, base), /subdomain is required/);
  assert.throws(() => resolveZendeskConfiguration({}, { ZENDESK_SUBDOMAIN: "acme", ZENDESK_API_TOKEN: "tok" }, base), /requires ZENDESK_EMAIL/);
  assert.throws(() => resolveZendeskConfiguration({}, { ZENDESK_SUBDOMAIN: "acme" }, base), /credentials are required/);
  assert.throws(() => resolveZendeskConfiguration({}, { ZENDESK_SUBDOMAIN: "bad domain!", ZENDESK_OAUTH_TOKEN: "x" }, base), /Invalid Zendesk subdomain/);
});

test("ZendeskApiClient sends API token basic auth and OAuth bearer headers", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, authorization: headerValue(init.headers, "authorization") });
    return jsonResponse({ user: { id: 1, role: "admin" } });
  };

  const tokenClient = new ZendeskApiClient(sampleConfig(), { fetchImpl });
  await tokenClient.getCurrentUser();
  const expectedBasic = `Basic ${Buffer.from("auditor@example.com/token:secret-api-token-value").toString("base64")}`;
  assert.equal(seen[0].authorization, expectedBasic);
  assert.equal(seen[0].url, "https://acme.zendesk.com/api/v2/users/me");

  const bearerClient = new ZendeskApiClient(sampleConfig({ authMode: "oauth", email: undefined, apiToken: undefined, oauthToken: "oauth-secret" }), { fetchImpl });
  await bearerClient.getCurrentUser();
  assert.equal(seen[1].authorization, "Bearer oauth-secret");
});

test("ZendeskApiClient follows cursor pagination to completion and records truncation", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const parsed = new URL(url);
    if (parsed.pathname.endsWith("/users")) {
      if (!parsed.searchParams.get("page[after]")) {
        return jsonResponse({ users: [{ id: 1 }, { id: 2 }], meta: { has_more: true, after_cursor: "abc" }, links: { next: "https://acme.zendesk.com/api/v2/users?page%5Bsize%5D=100&page%5Bafter%5D=abc&role%5B%5D=agent&role%5B%5D=admin" } });
      }
      return jsonResponse({ users: [{ id: 3 }], meta: { has_more: false, after_cursor: null }, links: { next: null } });
    }
    return jsonResponse({ webhooks: [{ id: "a" }], meta: { has_more: true }, links: { next: null } });
  };
  const client = new ZendeskApiClient(sampleConfig(), { fetchImpl });

  const users = await client.listTeamMembers();
  assert.equal(users.items.length, 3);
  assert.equal(users.pages, 2);
  assert.equal(users.truncated, false);
  const first = new URL(calls[0]);
  assert.equal(first.searchParams.get("page[size]"), "100");
  assert.deepEqual(first.searchParams.getAll("role[]"), ["agent", "admin"]);

  const webhooks = await client.listWebhooks();
  assert.equal(webhooks.items.length, 1);
  assert.equal(webhooks.truncated, true, "has_more without a next link must be recorded as truncated");

  const capped = new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ groups: [{ id: 1 }, { id: 2 }], meta: { has_more: true, after_cursor: "next" }, links: { next: "https://acme.zendesk.com/api/v2/groups?page%5Bafter%5D=next" } }),
  });
  const groups = await capped.listGroups(2);
  assert.equal(groups.items.length, 2);
  assert.equal(groups.truncated, true, "reaching max_items with more pages must be recorded as truncated");
});

test("ZendeskApiClient follows offset pagination until next_page is null", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (new URL(url).searchParams.get("page") === "2") {
      return jsonResponse({ things: [{ id: 3 }], next_page: null, count: 3 });
    }
    return jsonResponse({ things: [{ id: 1 }, { id: 2 }], next_page: "https://acme.zendesk.com/api/v2/things?page=2&per_page=2", count: 3 });
  };
  const client = new ZendeskApiClient(sampleConfig(), { fetchImpl });
  const result = await client.listOffset("/things", "things", {}, { perPage: 2 });
  assert.equal(result.items.length, 3);
  assert.equal(result.pages, 2);
  assert.equal(result.truncated, false);
  assert.equal(new URL(calls[0]).searchParams.get("per_page"), "2");
});

test("ZendeskApiClient retries 429 with Retry-After and 5xx before succeeding", async () => {
  const delays = [];
  let attempt = 0;
  const fetchImpl = async () => {
    attempt += 1;
    if (attempt === 1) return jsonResponse({ error: "RateLimited" }, { status: 429, headers: { "retry-after": "2" } });
    if (attempt === 2) return jsonResponse({ error: "Upstream" }, { status: 503 });
    return jsonResponse({ settings: { active_features: { sandbox: true } } });
  };
  const client = new ZendeskApiClient(sampleConfig(), { fetchImpl, sleep: async (ms) => { delays.push(ms); } });
  const settings = await client.getAccountSettings();
  assert.equal(settings.active_features.sandbox, true);
  assert.equal(attempt, 3);
  assert.equal(delays[0], 2000, "Retry-After seconds must be honored");
  assert.ok(delays[1] > 0);
});

test("ZendeskApiClient surfaces API errors with status codes and redacts secrets", async () => {
  const fetchImpl = async () => jsonResponse({ error: "Forbidden", description: "token secret-api-token-value was rejected" }, { status: 403, statusText: "Forbidden" });
  const client = new ZendeskApiClient(sampleConfig(), { fetchImpl });
  await assert.rejects(client.getAccountSettings(), (error) => {
    assert.ok(error instanceof ZendeskApiError);
    assert.equal(error.status, 403);
    assert.match(error.message, /403/);
    assert.doesNotMatch(error.message, /secret-api-token-value/);
    assert.match(error.message, /\[REDACTED\]/);
    return true;
  });

  const failing = new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async () => {
      throw new Error("connect ECONNREFUSED secret-api-token-value");
    },
  });
  await assert.rejects(failing.getCurrentUser(), /ECONNREFUSED \[REDACTED\]/);
});

test("checkZendeskAccess reports healthy when every surface is readable by an admin", async () => {
  const result = await checkZendeskAccess(healthyClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.currentUserRole, "admin");
  assert.equal(result.authMode, "api_token");
  assert.equal(result.surfaces.length, 18);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(result.missingPermissions, []);
  assert.match(result.recommendedNextStep, /zendesk_assess_authentication/);
});

test("checkZendeskAccess reports limited access and names admin-only surfaces for an agent credential", async () => {
  const client = healthyClient({
    async getCurrentUser() {
      return { id: 3, email: "agent@example.com", role: "agent" };
    },
    listCustomRoles: forbidden("/custom_roles"),
    listRecentAuditLogs: forbidden("/audit_logs"),
    listOAuthClients: forbidden("/oauth/clients"),
    listOAuthTokens: forbidden("/oauth/tokens"),
    listSuspendedTickets: forbidden("/suspended_tickets"),
    async listOwnedApps() {
      throw new ZendeskApiError("Zendesk request failed for /apps/owned (404 Not Found)", 404);
    },
  });
  const result = await checkZendeskAccess(client);
  assert.equal(result.status, "limited");
  assert.equal(result.currentUserRole, "agent");
  assert.equal(result.missingPermissions.length, 5);
  assert.ok(result.missingPermissions.some((item) => /oauth_clients requires an admin credential/.test(item)));
  assert.ok(result.missingPermissions.some((item) => /audit_logs requires an Enterprise admin credential/.test(item)));
  assert.equal(result.surfaces.find((surface) => surface.name === "owned_apps").status, "not_found");
  assert.ok(result.notes.some((note) => /not an admin/.test(note)));
  assert.match(result.recommendedNextStep, /admin API token or OAuth token/);
});

test("assessZendeskAuthentication passes 2FA only on complete documented flags and keeps API-hidden controls manual", async () => {
  const result = await assessZendeskAuthentication(healthyClient(), { now: () => NOW });
  assert.equal(result.findings.length, 6);
  assert.equal(findingById(result, "ZD-02").status, "pass");
  for (const id of ["ZD-01", "ZD-03", "ZD-04", "ZD-05", "ZD-21"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "manual", `${id} is not exposed by the published API`);
    assert.match(item.summary, /Manual evidence: capture Admin Center/);
  }
  assert.ok(findingById(result, "ZD-01").mappings.some((mapping) => mapping.startsWith("FedRAMP IA-2")));
  assert.equal(result.summary.current_user_role, "admin");
});

test("assessZendeskAuthentication fails 2FA when any active team member reports the flag false", async () => {
  const client = healthyClient({
    async listTeamMembers() {
      return list([teamMember({ id: 1, role: "admin" }), teamMember({ id: 2, role: "agent", two_factor_auth_enabled: false })]);
    },
  });
  const result = await assessZendeskAuthentication(client, { now: () => NOW });
  const item = findingById(result, "ZD-02");
  assert.equal(item.status, "fail");
  assert.match(item.summary, /1\/2 active team members report two_factor_auth_enabled=false/);
  assert.deepEqual(item.evidence.without_two_factor, ["user-2@example.com"]);
});

test("assessZendeskAuthentication downgrades when the 2FA flag is missing or the inventory is truncated", async () => {
  const missingFlag = await assessZendeskAuthentication(healthyClient({
    async listTeamMembers() {
      const member = teamMember({ id: 1, role: "admin" });
      delete member.two_factor_auth_enabled;
      return list([member]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(missingFlag, "ZD-02").status, "warn");
  assert.match(findingById(missingFlag, "ZD-02").summary, /1 did not expose the flag/);

  const truncated = await assessZendeskAuthentication(healthyClient({
    async listTeamMembers() {
      return list([teamMember({ id: 1, role: "admin" })], true);
    },
  }), { now: () => NOW });
  assert.equal(findingById(truncated, "ZD-02").status, "warn");
  assert.match(findingById(truncated, "ZD-02").summary, /truncated/);
});

test("assessZendeskAuthentication renders manual for unreadable settings and users and for an empty team", async () => {
  const unreadable = await assessZendeskAuthentication(forbiddenClient(), { now: () => NOW });
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.match(findingById(unreadable, "ZD-02").summary, /403 \(credential lacks permission\)/);
  assert.ok(unreadable.errors.some((entry) => entry.startsWith("team_members:")));

  const empty = await assessZendeskAuthentication(emptyClient(), { now: () => NOW });
  assert.equal(findingById(empty, "ZD-02").status, "manual");
  assert.match(findingById(empty, "ZD-02").summary, /Zero active agents or admins were visible/);
});

test("assessZendeskAccessControl passes least privilege, admin count, groups, API tokens, and OAuth on a complete admin view", async () => {
  const result = await assessZendeskAccessControl(healthyClient(), { now: () => NOW });
  assert.deepEqual(result.findings.map((item) => item.id), ["ZD-06", "ZD-07", "ZD-08", "ZD-13", "ZD-14"]);
  for (const id of ["ZD-06", "ZD-07", "ZD-08", "ZD-13", "ZD-14"]) {
    assert.equal(findingById(result, id).status, "pass", `${id} should pass on the healthy fixture`);
  }
  assert.match(findingById(result, "ZD-13").summary, /api_token_access=false/);
  assert.match(findingById(result, "ZD-14").summary, /read to completion/);
});

test("assessZendeskAccessControl fails admin-equivalent roles, excessive admins, and unscoped OAuth clients", async () => {
  const client = healthyClient({
    async listTeamMembers() {
      return list([1, 2, 3, 4, 5, 6].map((id) => teamMember({ id, role: "admin" })));
    },
    async listCustomRoles() {
      return list([{ id: 1, name: "Shadow admin", team_member_count: 1, configuration: { manage_roles: "all-except-self", manage_api_credentials: true } }]);
    },
    async listOAuthClients() {
      return list([{ id: 1, name: "Legacy", identifier: "legacy", kind: "confidential", scope: null, redirect_uri: ["http://legacy.example.com/cb"] }]);
    },
  });
  const result = await assessZendeskAccessControl(client, { now: () => NOW });
  assert.equal(findingById(result, "ZD-06").status, "fail");
  assert.match(findingById(result, "ZD-06").summary, /Shadow admin: manage_roles=all-except-self, manage_api_credentials=true/);
  assert.equal(findingById(result, "ZD-07").status, "fail");
  assert.match(findingById(result, "ZD-07").summary, /6 active admins exceed the threshold of 5/);
  assert.equal(findingById(result, "ZD-14").status, "fail");
  assert.match(findingById(result, "ZD-14").summary, /1\/1 OAuth clients have no scope restriction and 1 use http:\/\/ redirect URIs/);
});

test("assessZendeskAccessControl never counts undated admins or tokens as fresh", async () => {
  const client = healthyClient({
    async listTeamMembers() {
      return list([teamMember({ id: 1, role: "admin", last_login_at: null }), teamMember({ id: 2, role: "admin", last_login_at: daysAgo(200) })]);
    },
    async listOAuthTokens() {
      return list([{ id: 1, client_id: 1, scopes: ["read"], expires_at: daysAgo(-10), used_at: null }]);
    },
  });
  const result = await assessZendeskAccessControl(client, { now: () => NOW });
  const admins = findingById(result, "ZD-07");
  assert.equal(admins.status, "warn");
  assert.match(admins.summary, /1 have not signed in for more than 90 days and 1 have no last_login_at value/);
  assert.deepEqual(admins.evidence.admins_without_last_login, ["user-1@example.com"]);
  const oauth = findingById(result, "ZD-14");
  assert.equal(oauth.status, "warn");
  assert.equal(oauth.evidence.tokens_without_used_at, 1);
});

test("assessZendeskAccessControl renders manual for forbidden inventories and Enterprise-only custom roles", async () => {
  const unreadable = await assessZendeskAccessControl(forbiddenClient(), { now: () => NOW });
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.match(findingById(unreadable, "ZD-14").summary, /OAuth clients \(\/oauth\/clients, admin only\) returned 403/);

  const rolesOnly = await assessZendeskAccessControl(healthyClient({ listCustomRoles: forbidden("/custom_roles") }), { now: () => NOW });
  const leastPrivilege = findingById(rolesOnly, "ZD-06");
  assert.equal(leastPrivilege.status, "manual");
  assert.match(leastPrivilege.summary, /Enterprise plan/);

  const tokenAccessOn = await assessZendeskAccessControl(healthyClient({
    async getAccountSettings() {
      return healthySettings({ api: { api_token_access: true } });
    },
  }), { now: () => NOW });
  assert.equal(findingById(tokenAccessOn, "ZD-13").status, "manual");
  assert.match(findingById(tokenAccessOn, "ZD-13").summary, /api_token_access=true/);
});

test("assessZendeskAccessControl treats empty team, admin, and group inventories as partial views", async () => {
  const result = await assessZendeskAccessControl(emptyClient(), { now: () => NOW });
  assert.equal(findingById(result, "ZD-06").status, "manual");
  assert.equal(findingById(result, "ZD-07").status, "manual");
  assert.match(findingById(result, "ZD-07").summary, /Zero admins were visible/);
  assert.equal(findingById(result, "ZD-08").status, "manual");
  const oauth = findingById(result, "ZD-14");
  assert.equal(oauth.status, "pass");
  assert.match(oauth.summary, /readable and returned zero clients/);
});

test("assessZendeskAccessControl downgrades truncated team inventories instead of passing", async () => {
  const result = await assessZendeskAccessControl(truncatedClient("admin"), { now: () => NOW });
  for (const id of ["ZD-06", "ZD-07", "ZD-08", "ZD-14"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "warn", `${id} must not pass on a truncated inventory`);
    assert.match(item.summary, /truncated/);
  }
});

test("assessZendeskDataProtection passes audit logging, retention, attachments, and suspended queue on documented evidence", async () => {
  const result = await assessZendeskDataProtection(healthyClient(), { now: () => NOW });
  assert.deepEqual(result.findings.map((item) => item.id), ["ZD-09", "ZD-10", "ZD-11", "ZD-12", "ZD-18", "ZD-19", "ZD-20"]);
  assert.equal(findingById(result, "ZD-09").status, "pass");
  assert.equal(findingById(result, "ZD-10").status, "pass");
  assert.match(findingById(result, "ZD-10").summary, /400 days old/);
  assert.equal(findingById(result, "ZD-11").status, "manual");
  assert.equal(findingById(result, "ZD-12").status, "manual");
  assert.match(findingById(result, "ZD-12").summary, /1\/1 custom roles allow ticket redaction/);
  assert.equal(findingById(result, "ZD-18").status, "pass");
  assert.equal(findingById(result, "ZD-19").status, "manual");
  assert.match(findingById(result, "ZD-19").summary, /attachment_size=50 MB/);
  assert.equal(findingById(result, "ZD-20").status, "pass");
  assert.match(findingById(result, "ZD-20").summary, /queue is empty/);
});

test("assessZendeskDataProtection fails public attachments and warns on aged or undated suspended tickets", async () => {
  const client = healthyClient({
    async getAccountSettings() {
      return healthySettings({ tickets: { private_attachments: false } });
    },
    async listSuspendedTickets() {
      return list([
        { id: 1, cause: "Detected as spam", created_at: daysAgo(45) },
        { id: 2, cause: "Automated response", created_at: null },
      ]);
    },
  });
  const result = await assessZendeskDataProtection(client, { now: () => NOW });
  assert.equal(findingById(result, "ZD-18").status, "fail");
  const suspended = findingById(result, "ZD-20");
  assert.equal(suspended.status, "warn");
  assert.match(suspended.summary, /1 are older than 30 days \(1 undated\)/);

  const undatedOnly = await assessZendeskDataProtection(healthyClient({
    async listSuspendedTickets() {
      return list([{ id: 2, cause: "Automated response", created_at: null }]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(undatedOnly, "ZD-20").status, "warn");
  assert.match(findingById(undatedOnly, "ZD-20").summary, /cannot be aged/);
});

test("assessZendeskDataProtection renders audit log plan limits, absent flags, and empty logs as manual", async () => {
  const unreadable = await assessZendeskDataProtection(forbiddenClient(), { now: () => NOW });
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.match(findingById(unreadable, "ZD-09").summary, /Enterprise plan and admin role\) returned 403/);
  assert.match(findingById(unreadable, "ZD-09").summary, /plan or permission limitation, not a pass/);

  const notFound = await assessZendeskDataProtection(healthyClient({
    async listRecentAuditLogs() {
      throw new ZendeskApiError("Zendesk request failed for /audit_logs (404 Not Found)", 404);
    },
  }), { now: () => NOW });
  assert.equal(findingById(notFound, "ZD-09").status, "manual");
  assert.match(findingById(notFound, "ZD-09").summary, /404 \(endpoint unavailable on this account or plan\)/);
  assert.equal(findingById(notFound, "ZD-10").status, "manual");

  const empty = await assessZendeskDataProtection(emptyClient(), { now: () => NOW });
  assert.equal(findingById(empty, "ZD-09").status, "manual");
  assert.match(findingById(empty, "ZD-09").summary, /zero entries/);
  assert.equal(findingById(empty, "ZD-10").status, "manual");

  const absentFlag = await assessZendeskDataProtection(healthyClient({
    async getAccountSettings() {
      return { active_features: {}, api: {}, tickets: {}, limits: {} };
    },
  }), { now: () => NOW });
  assert.equal(findingById(absentFlag, "ZD-18").status, "manual");
  assert.match(findingById(absentFlag, "ZD-18").summary, /private_attachments was absent/);
});

test("assessZendeskDataProtection warns when retention is short or the suspended inventory is truncated", async () => {
  const shortRetention = await assessZendeskDataProtection(healthyClient({
    async getOldestAuditLog() {
      return { id: 0, created_at: daysAgo(30) };
    },
  }), { now: () => NOW });
  assert.equal(findingById(shortRetention, "ZD-10").status, "warn");

  const truncated = await assessZendeskDataProtection(healthyClient({
    async listSuspendedTickets() {
      return list([{ id: 1, cause: "spam", created_at: daysAgo(1) }], true);
    },
  }), { now: () => NOW });
  assert.equal(findingById(truncated, "ZD-20").status, "warn");
  assert.match(findingById(truncated, "ZD-20").summary, /truncated/);
});

test("assessZendeskIntegrations passes apps, sandbox, brands, sharing, https, and rule hygiene on a complete admin view", async () => {
  const result = await assessZendeskIntegrations(healthyClient(), { now: () => NOW });
  assert.deepEqual(result.findings.map((item) => item.id), ["ZD-15", "ZD-16", "ZD-17", "ZD-22", "ZD-23", "ZD-24", "ZD-25"]);
  for (const id of ["ZD-15", "ZD-16", "ZD-17", "ZD-22", "ZD-23", "ZD-24", "ZD-25"]) {
    assert.equal(findingById(result, id).status, "pass", `${id} should pass on the healthy fixture`);
  }
  assert.match(findingById(result, "ZD-15").summary, /readable and returned zero installed apps/);
  assert.match(findingById(result, "ZD-22").summary, /read to completion by an admin/);
});

test("assessZendeskIntegrations fails http destinations and flags external exfiltration actions", async () => {
  const client = healthyClient({
    async listWebhooks() {
      return list([{ id: "wh2", name: "Plain", status: "active", endpoint: "http://hooks.example.com/zendesk" }]);
    },
    async listTargets() {
      return list([{ id: 5, title: "Legacy target", active: true, target_url: "http://legacy.example.com/hook", type: "url_target_v2" }]);
    },
    async listTriggers() {
      return list([{ id: 9, title: "Ship externally", active: true, actions: [{ field: "notification_webhook", value: ["wh2", "{{ticket.description}}"] }] }]);
    },
  });
  const result = await assessZendeskIntegrations(client, { now: () => NOW });
  const https = findingById(result, "ZD-24");
  assert.equal(https.status, "fail");
  assert.match(https.summary, /1 active targets and 1 active webhooks deliver to non-https endpoints/);
  const exfil = findingById(result, "ZD-25");
  assert.equal(exfil.status, "fail");
  assert.match(exfil.summary, /1\/1 external notification actions deliver ticket data to http:\/\/ destinations/);

  const secureExternal = await assessZendeskIntegrations(healthyClient({
    async listTriggers() {
      return list([{ id: 9, title: "Notify pager", active: true, actions: [{ field: "notification_webhook", value: ["wh1", "body"] }] }]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(secureExternal, "ZD-25").status, "warn");
  assert.match(findingById(secureExternal, "ZD-25").summary, /hooks\.example\.com/);
});

test("assessZendeskIntegrations keeps installed apps and active sharing agreements manual and warns on gaps", async () => {
  const client = healthyClient({
    async listAppInstallations() {
      return list([{ id: 1, app_id: 77, product: "support", enabled: true, settings: { title: "Time Tracking" }, role_restrictions: [], group_restrictions: [] }]);
    },
    async listOwnedApps() {
      return list([{ id: 88, name: "Internal widget", visibility: "private", framework_version: "2.0", deprecated: true, parameters: [] }]);
    },
    async getAccountSettings() {
      return healthySettings({ active_features: { sandbox: false } });
    },
    async listBrands() {
      return list([
        { id: 1, name: "Acme", active: true, help_center_state: "enabled" },
        { id: 2, name: "Beta", active: true, help_center_state: "restricted" },
      ]);
    },
    async listSharingAgreements() {
      return list([{ id: 1, name: "Partner", remote_subdomain: "partner", status: "accepted", type: "outbound" }]);
    },
    async listWebhooks() {
      return list([{ id: "wh3", name: "No auth", status: "active", endpoint: "https://hooks.example.com/open" }]);
    },
  });
  const result = await assessZendeskIntegrations(client, { now: () => NOW });
  assert.equal(findingById(result, "ZD-15").status, "manual");
  assert.match(findingById(result, "ZD-15").summary, /1 marketplace app installations \(1 enabled\)/);
  assert.equal(findingById(result, "ZD-16").status, "warn");
  assert.equal(findingById(result, "ZD-17").status, "warn");
  assert.match(findingById(result, "ZD-17").summary, /sandbox=false/);
  assert.equal(findingById(result, "ZD-22").status, "warn");
  assert.match(findingById(result, "ZD-22").summary, /mixed help center states/);
  assert.equal(findingById(result, "ZD-23").status, "manual");
  assert.match(findingById(result, "ZD-23").summary, /partner/);
  assert.equal(findingById(result, "ZD-24").status, "warn");
  assert.match(findingById(result, "ZD-24").summary, /1 active webhooks have no authentication/);
});

test("assessZendeskIntegrations renders unreadable, empty, and truncated inventories without passing", async () => {
  const unreadable = await assessZendeskIntegrations(forbiddenClient(), { now: () => NOW });
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.match(findingById(unreadable, "ZD-17").summary, /Account settings returned 403/);

  const empty = await assessZendeskIntegrations(emptyClient(), { now: () => NOW });
  assert.equal(findingById(empty, "ZD-22").status, "manual");
  assert.match(findingById(empty, "ZD-22").summary, /Zero brands were visible/);
  assert.equal(findingById(empty, "ZD-25").status, "manual");
  assert.match(findingById(empty, "ZD-25").summary, /Zero active triggers or automations/);
  assert.equal(findingById(empty, "ZD-24").status, "pass");
  assert.match(findingById(empty, "ZD-24").summary, /emptiness is compliant/);

  const truncated = await assessZendeskIntegrations(truncatedClient("admin"), { now: () => NOW });
  for (const id of ["ZD-22", "ZD-24", "ZD-25"]) {
    assert.equal(findingById(truncated, id).status, "warn", `${id} must not pass on a truncated inventory`);
  }
});

test("self-check (a): when every endpoint returns 403 no assess tool reports pass", async () => {
  const results = await runAllAssessments(forbiddenClient());
  const statuses = statusMap(results);
  assert.equal(statuses.size, 25, "all 25 controls must be covered");
  for (const [id, status] of statuses) {
    assert.equal(status, "manual", `${id} must be manual when its evidence is forbidden`);
  }
  for (const result of results) {
    for (const item of result.findings) {
      assert.match(item.summary, /Manual evidence:/, `${item.id} must tell the reviewer what to collect`);
    }
  }
});

test("self-check (b): when every list is empty only intent-compliant controls pass and each states the count", async () => {
  const results = await runAllAssessments(emptyClient());
  const statuses = statusMap(results);
  assert.equal(statuses.size, 25);
  const expectedPass = new Set(["ZD-13", "ZD-14", "ZD-15", "ZD-16", "ZD-17", "ZD-18", "ZD-20", "ZD-23", "ZD-24"]);
  for (const [id, status] of statuses) {
    if (expectedPass.has(id)) {
      assert.equal(status, "pass", `${id} passes on emptiness or an explicit documented flag`);
    } else {
      assert.notEqual(status, "pass", `${id} must not pass on an empty inventory`);
    }
  }
  const passing = results.flatMap((result) => result.findings).filter((item) => item.status === "pass");
  for (const item of passing) {
    assert.match(item.summary, /zero|empty|=false|=true/i, `${item.id} must state why emptiness or the flag value is compliant`);
  }
});

test("self-check (c): a partial inventory seen by an agent-scoped credential never passes", async () => {
  const results = await runAllAssessments(truncatedClient("agent"));
  const statuses = statusMap(results);
  assert.equal(statuses.size, 25);
  for (const [id, status] of statuses) {
    assert.notEqual(status, "pass", `${id} must not pass on a partial inventory`);
  }
  const capped = results.flatMap((result) => result.findings).filter((item) => item.evidence?.verdict_capped_by_role !== undefined);
  assert.ok(capped.length > 0, "role-capped findings must record the cap in evidence");
  assert.ok(capped.every((item) => /capped at warn because the credential's role is agent/.test(item.summary)));
});

test("self-check (c) variant: an unknown credential role caps verdicts at warn", async () => {
  const results = await runAllAssessments(healthyClient({ getCurrentUser: forbidden("/users/me") }));
  const statuses = statusMap(results);
  for (const [id, status] of statuses) {
    assert.notEqual(status, "pass", `${id} must not pass when the credential role is unknown`);
  }
  assert.ok(results.every((result) => result.errors.some((entry) => entry.startsWith("current_user:"))));
});

test("every finding carries the framework mappings from the spec table", async () => {
  const results = await runAllAssessments(healthyClient());
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 25);
  for (const item of findings) {
    assert.ok(item.mappings.length >= 4, `${item.id} must carry framework mappings`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")), `${item.id} must map to FedRAMP`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("SOC 2 ")), `${item.id} must map to SOC 2`);
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
  }
});

test("resolveSecureOutputPath rejects traversal and symlinked parents", () => {
  const base = createTempBase("grclanker-zendesk-secure-");
  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, join("..", "..", "etc")), /Refusing to write outside/);

  const target = createTempBase("grclanker-zendesk-link-target-");
  const linkPath = join(base, "linked");
  symlinkSync(target, linkPath, "dir");
  assert.throws(() => resolveSecureOutputPath(base, join("linked", "bundle")), /symlinked parent/);

  const safe = resolveSecureOutputPath(base, join("nested", "bundle"));
  assert.ok(safe.startsWith(base));
});

test("exportZendeskAuditBundle writes the bundle layout, archive, and never overwrites a prior run", async () => {
  const base = createTempBase("grclanker-zendesk-export-");
  const config = sampleConfig();
  const first = await exportZendeskAuditBundle(healthyClient(), config, base, { now: () => NOW });

  assert.equal(first.findingCount, 25);
  assert.equal(first.errorCount, 0);
  assert.ok(first.outputDir.endsWith("acme-zendesk-audit-bundle"));
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  for (const relativePath of [
    "metadata.json",
    "QUICK_REFERENCE.md",
    "core_data/access_check.json",
    "core_data/account_settings.json",
    "core_data/team_members.json",
    "core_data/oauth_clients.json",
    "core_data/webhooks.json",
    "analysis/findings.json",
    "analysis/authentication.json",
    "analysis/access-control.json",
    "analysis/data-protection.json",
    "analysis/integrations.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp_compliance_report.md",
    "compliance/cmmc_compliance_report.md",
    "compliance/soc2_compliance_report.md",
    "compliance/cis_compliance_report.md",
    "compliance/pci_dss_compliance_report.md",
    "compliance/disa_stig_compliance_report.md",
    "compliance/irap_compliance_report.md",
    "compliance/ismap_compliance_report.md",
  ]) {
    assert.ok(existsSync(join(first.outputDir, relativePath)), `expected ${relativePath}`);
  }
  assert.ok(!existsSync(join(first.outputDir, "_errors.log")), "healthy runs must not write _errors.log");
  const findings = JSON.parse(readFileSync(join(first.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.length, 25);
  const executive = readFileSync(join(first.outputDir, "compliance/executive_summary.md"), "utf8");
  assert.match(executive, /Subdomain: acme/);
  assert.match(executive, /## Manual Evidence Required/);
  const rawSettings = readFileSync(join(first.outputDir, "core_data/account_settings.json"), "utf8");
  assert.doesNotMatch(rawSettings, /secret-api-token-value/);

  const second = await exportZendeskAuditBundle(healthyClient(), config, base, { now: () => NOW });
  assert.notEqual(second.outputDir, first.outputDir);
  assert.ok(second.outputDir.endsWith("acme-zendesk-audit-bundle-2"));
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath) && existsSync(second.zipPath));
  assert.equal(readdirSync(base).filter((name) => name.endsWith(".zip")).length, 2);
  assert.equal(readdirSync(base).filter((name) => !name.endsWith(".zip")).length, 2);
});

test("exportZendeskAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("grclanker-zendesk-export-errors-");
  const config = sampleConfig();
  const client = healthyClient({ listOAuthClients: forbidden("/oauth/clients"), listRecentAuditLogs: forbidden("/audit_logs") });
  const result = await exportZendeskAuditBundle(client, config, base, { now: () => NOW });
  assert.ok(result.errorCount >= 2);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /oauth_clients: .*403/);
  assert.match(errorLog, /audit_logs_recent: .*403/);
  assert.ok(!existsSync(join(result.outputDir, "core_data/oauth_clients.json")), "forbidden snapshots are not written as data");
  const executive = readFileSync(join(result.outputDir, "compliance/executive_summary.md"), "utf8");
  assert.match(executive, /## Partial Collection Warnings/);
});

test("Zendesk tools are registered in the tool catalog under the Zendesk group", () => {
  const tools = getRegisteredToolSummaries();
  const zendeskTools = tools.filter((tool) => tool.name.startsWith("zendesk_"));
  assert.deepEqual(
    zendeskTools.map((tool) => tool.name).sort(),
    [
      "zendesk_assess_access_control",
      "zendesk_assess_authentication",
      "zendesk_assess_data_protection",
      "zendesk_assess_integrations",
      "zendesk_check_access",
      "zendesk_export_audit_bundle",
    ],
  );
  assert.ok(zendeskTools.every((tool) => tool.group === "Zendesk"));
  assert.ok(zendeskTools.every((tool) => tool.kind === "domain"));
  const exportTool = zendeskTools.find((tool) => tool.name === "zendesk_export_audit_bundle");
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "output_dir"));
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "oauth_token"));
});
