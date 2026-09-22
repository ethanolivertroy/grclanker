import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
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
  describeErrorBody,
  exportZendeskAuditBundle,
  isCredentialPropertyName,
  redactCredentialProperties,
  redactCredentialValueText,
  redactErrorText,
  registerZendeskTools,
  resolveSecureOutputPath,
  resolveZendeskConfiguration,
} from "../dist/extensions/grc-tools/zendesk.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

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

function healthySecuritySettings(overrides = {}) {
  const { agent = {}, agentPassword = {}, endUser = {}, ip = {}, ...top } = overrides;
  return {
    admins_can_set_user_passwords: false,
    agent_session_timeout: 480,
    end_user_session_timeout: 480,
    maximum_session_duration: 720,
    maximum_session_duration_enabled: true,
    mobile_app_access: true,
    mobile_app_session_timeout: 300,
    two_factor_last_update: daysAgo(120),
    authentication: {
      agent: {
        security_policy_id: 350,
        security_policy_name: "recommended",
        google_login: false,
        office_365_login: false,
        zendesk_login: false,
        remote_login: true,
        enforce_sso: true,
        sso_auto_redirect: false,
        primary_external_auth: null,
        two_factor_enforce: true,
        remote_bypass: 1,
        remote_bypass_name: "owner",
        office_365_enforce_tid: false,
        office_365_allowed_tids: "",
        password: {
          password_history_length: null,
          password_length: 12,
          password_complexity: 2,
          password_in_mixed_case: true,
          failed_attempts_allowed: 5,
          max_sequence: 3,
          disallow_local_part_from_email: true,
          password_duration: null,
          ...agentPassword,
        },
        ...agent,
      },
      end_user: {
        security_policy_id: 350,
        security_policy_name: "recommended",
        google_login: false,
        office_365_login: false,
        facebook_login: false,
        zendesk_login: false,
        remote_login: true,
        enforce_sso: true,
        sso_auto_redirect: false,
        primary_external_auth: null,
        ...endUser,
      },
    },
    ip: {
      ip_ranges: "203.0.113.0/24 198.51.100.7",
      ip_restriction_enabled: true,
      enable_agent_ip_restrictions: true,
      ...ip,
    },
    ...top,
  };
}

function deletionSchedule(overrides = {}) {
  return {
    id: overrides.id ?? 1,
    title: overrides.title ?? "Delete closed tickets after 3 years",
    object: overrides.object ?? "zen:ticket",
    active: overrides.active ?? true,
    default: overrides.default ?? false,
    conditions: overrides.conditions ?? { all: [{ field: "duration_since_last_update", operator: "greater_than", value: "P3Y" }], any: [] },
    created_at: daysAgo(400),
    updated_at: daysAgo(30),
    url: `https://acme.zendesk.com/api/v2/deletion_schedules/${overrides.id ?? 1}`,
  };
}

function tokenEvent(overrides = {}) {
  return {
    id: overrides.id ?? 1,
    action: overrides.action ?? "create",
    actor_id: 1,
    actor_name: overrides.actor_name ?? "Auditor",
    change_description: overrides.change_description ?? "API token created",
    created_at: "created_at" in overrides ? overrides.created_at : daysAgo(10),
    source_id: overrides.source_id ?? 500,
    source_label: overrides.source_label ?? "Reporting integration",
    source_type: "apitoken",
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
    async getSecuritySettings() {
      return healthySecuritySettings();
    },
    async listDeletionSchedules() {
      return list([
        deletionSchedule({ id: 1 }),
        deletionSchedule({ id: 2, title: "Purge inactive end users", object: "zen:user", conditions: { all: [{ field: "duration_since_last_login", operator: "greater_than", value: "P2Y" }], any: [] } }),
      ]);
    },
    async listApiTokenAuditLogs() {
      return list([]);
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
  "listApiTokenAuditLogs",
  "listDeletionSchedules",
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
  for (const method of [...LIST_METHODS, "getAccountSettings", "getSecuritySettings", "getOldestAuditLog"]) {
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

// Config loader canaries: no two share an 8-character window, so any fragment a parser
// quotes from the file is attributable to one fixture. The short canary keeps the JSON
// short file at 20 characters, within the size at which JSON.parse quotes the whole source.
const LOADER_CANARIES = {
  yamlNestedKey: "cnrA1qz8Xw4LpT9vK2mD",
  yamlNestedBearer: "cnrB5hj3Yn7GsW2rQ8kF",
  yamlAlias: "cnrC9tb6Um1JdX3eN7wP",
  jsonUnquoted: "cnrD2vf7Zk5HcR8sL4yG",
  jsonShort: "cnrE6pm4Qa",
  jsonMultiline: "cnrF3gk8Wd2ZnT6iM9oJ",
};
const LIBRARY_ERROR_WORDING = ["Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "Unexpected token", "Expected ',' or '}'"];

function assertNoLoaderLeak(text, canaries, label) {
  for (const canary of canaries) {
    assert.ok(!text.includes(canary), `${label}: canary ${canary} leaked into: ${text}`);
    for (let index = 0; index + 8 <= canary.length; index += 1) {
      const fragment = canary.slice(index, index + 8);
      assert.ok(!text.includes(fragment), `${label}: canary fragment ${fragment} leaked into: ${text}`);
    }
  }
  for (const wording of LIBRARY_ERROR_WORDING) {
    assert.ok(!text.includes(wording), `${label}: library wording "${wording}" leaked into: ${text}`);
  }
}

test("config loader errors carry fixed text, the path, a validated code, and a structured line, never the file contents or library wording", async () => {
  const base = createTempBase("grclanker-zendesk-loader-errors-");
  const write = (name, text) => {
    const pathname = join(base, name);
    writeFileSync(pathname, text);
    return pathname;
  };
  const tools = new Map();
  registerZendeskTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const check = tools.get("zendesk_check_access");
  const checkAccessText = async (configFile) => JSON.stringify(await check.execute("call-loader", check.prepareArguments({ config_file: configFile })));

  const cases = [
    {
      // Not JSON at all: the parser quotes the first characters of the file.
      label: "YAML nested mapping",
      file: write("nested.yaml", `key: ${LOADER_CANARIES.yamlNestedKey}: Bearer ${LOADER_CANARIES.yamlNestedBearer}\n`),
      canaries: [LOADER_CANARIES.yamlNestedKey, LOADER_CANARIES.yamlNestedBearer],
      libraryThrows: true,
      expected: (pathname) => `Unable to parse Zendesk config file: invalid JSON in ${pathname} (INVALID_JSON)`,
    },
    {
      label: "YAML alias",
      file: write("alias.yaml", `key: *${LOADER_CANARIES.yamlAlias}\n`),
      canaries: [LOADER_CANARIES.yamlAlias],
      libraryThrows: true,
      expected: (pathname) => `Unable to parse Zendesk config file: invalid JSON in ${pathname} (INVALID_JSON)`,
    },
    {
      // The "Unexpected token" family quotes a 10-character window around the failure.
      label: "JSON unquoted value",
      file: write("unquoted.json", `{"api_token": ${LOADER_CANARIES.jsonUnquoted}}\n`),
      canaries: [LOADER_CANARIES.jsonUnquoted],
      libraryThrows: true,
      libraryCarriesFragment: true,
      expected: (pathname) => `Unable to parse Zendesk config file: invalid JSON in ${pathname} (INVALID_JSON)`,
    },
    {
      // At 21 characters or fewer the whole source is quoted, key on a scrub list or not.
      label: "JSON short file",
      file: write("short.json", `{"token":${LOADER_CANARIES.jsonShort}}`),
      canaries: [LOADER_CANARIES.jsonShort],
      libraryThrows: true,
      libraryCarriesCanary: true,
      expected: (pathname) => `Unable to parse Zendesk config file: invalid JSON in ${pathname} (INVALID_JSON)`,
    },
    {
      // The structural family reports a position; only that position becomes a line.
      label: "JSON missing comma",
      file: write("multiline.json", `{\n  "subdomain": "acme",\n  "oauth_token": "${LOADER_CANARIES.jsonMultiline}"\n  "email": "a@example.com"\n}\n`),
      canaries: [LOADER_CANARIES.jsonMultiline],
      libraryThrows: true,
      expected: (pathname) => `Unable to parse Zendesk config file: invalid JSON in ${pathname} at line 4 (INVALID_JSON)`,
    },
    {
      label: "EISDIR",
      file: (() => {
        const pathname = join(base, "config-dir.json");
        mkdirSync(pathname);
        return pathname;
      })(),
      canaries: [],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Zendesk config file ${pathname} (EISDIR)`,
    },
    {
      label: "ENOENT",
      file: join(base, "missing.json"),
      canaries: [],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Zendesk config file ${pathname} (ENOENT)`,
    },
    ...(process.getuid?.() === 0 ? [] : [{
      label: "EACCES",
      file: (() => {
        const pathname = write("unreadable.json", JSON.stringify({ subdomain: "acme", oauth_token: LOADER_CANARIES.jsonMultiline }));
        chmodSync(pathname, 0o000);
        return pathname;
      })(),
      canaries: [LOADER_CANARIES.jsonMultiline],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Zendesk config file ${pathname} (EACCES)`,
    }]),
  ];
  assert.ok(readFileSync(cases[3].file, "utf8").length <= 20, "the short JSON fixture stays within the size JSON.parse quotes whole");

  for (const entry of cases) {
    if (entry.libraryThrows) {
      // Positive control: JSON.parse's own message quotes the file contents.
      assert.throws(() => JSON.parse(readFileSync(entry.file, "utf8")), (error) => {
        if (entry.libraryCarriesCanary) assert.ok(error.message.includes(entry.canaries[0]), `${entry.label}: positive control expected the whole canary: ${error.message}`);
        if (entry.libraryCarriesFragment) assert.ok(error.message.includes(entry.canaries[0].slice(0, 8)), `${entry.label}: positive control expected a canary fragment: ${error.message}`);
        return true;
      });
    }
    assert.throws(() => resolveZendeskConfiguration({ config_file: entry.file }, {}, base), (error) => {
      assert.equal(error.message, entry.expected(entry.file), `${entry.label}: resolver message`);
      assertNoLoaderLeak(error.message, entry.canaries, `${entry.label} resolver`);
      return true;
    });
    assert.throws(() => resolveZendeskConfiguration({}, { ZENDESK_CONFIG_FILE: entry.file }, base), (error) => {
      assert.equal(error.message, entry.expected(entry.file), `${entry.label}: ZENDESK_CONFIG_FILE is an explicit path too`);
      return true;
    });
    const toolText = await checkAccessText(entry.file);
    assertNoLoaderLeak(toolText, entry.canaries, `${entry.label} check_access`);
    assert.ok(toolText.includes(entry.expected(entry.file)), `${entry.label}: check_access carries the fixed loader text: ${toolText}`);
  }

  // The default ~/.zendesk/config.json stays optional: absent means no file settings.
  assert.throws(() => resolveZendeskConfiguration({}, {}, base), /Zendesk subdomain is required/);
  const shape = write("list.json", "[1, 2]");
  assert.throws(() => resolveZendeskConfiguration({ config_file: shape }, {}, base), new RegExp(`Unable to parse Zendesk config file: .* must contain a JSON object \\(INVALID_CONFIG_SHAPE\\)`));
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

test("ZendeskApiClient follows links.next when has_more is absent and requests boundary indicators", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const parsed = new URL(url);
    if (parsed.pathname.endsWith("/users")) {
      if (parsed.searchParams.get("page[after]") === "cursor-2") {
        return jsonResponse({ users: [{ id: 3 }], meta: { after_cursor: null, before_cursor: "b" }, links: { next: null, prev: "https://acme.zendesk.com/api/v2/users?page%5Bbefore%5D=b" } });
      }
      return jsonResponse({
        users: [{ id: 1 }, { id: 2 }],
        meta: { after_cursor: "cursor-2", before_cursor: null },
        links: { next: "https://acme.zendesk.com/api/v2/users?page%5Bsize%5D=100&page%5Bafter%5D=cursor-2&role%5B%5D=agent&role%5B%5D=admin", prev: null },
      });
    }
    if (parsed.pathname.endsWith("/groups")) {
      if (parsed.searchParams.get("page") === "2") {
        return jsonResponse({ groups: [{ id: 30 }], next_page: null, previous_page: "https://acme.zendesk.com/api/v2/groups?page=1", count: 3 });
      }
      return jsonResponse({ groups: [{ id: 10 }, { id: 20 }], next_page: "https://acme.zendesk.com/api/v2/groups?page=2", previous_page: null, count: 3 });
    }
    return jsonResponse({});
  };
  const client = new ZendeskApiClient(sampleConfig(), { fetchImpl });

  const users = await client.listTeamMembers();
  assert.equal(users.items.length, 3, "page two must be read even though meta.has_more was never sent");
  assert.equal(users.pages, 2);
  assert.equal(users.truncated, false);
  assert.equal(new URL(calls[0]).searchParams.get("include_boundary_indicators"), "true", "List Users documents include_boundary_indicators");

  const groups = await client.listGroups();
  assert.equal(groups.items.length, 3, "an offset-shaped next_page must be treated as a continuation");
  assert.equal(groups.pages, 2);
  assert.equal(groups.truncated, false);
  const groupCalls = calls.filter((url) => new URL(url).pathname.endsWith("/groups"));
  assert.equal(new URL(groupCalls[0]).searchParams.get("include_boundary_indicators"), "true", "List Groups documents include_boundary_indicators");
});

test("ZendeskApiClient pages offset-only endpoints such as targets to completion", async () => {
  const calls = [];
  const targets = Array.from({ length: 130 }, (_, index) => ({ id: index + 1, type: "url_target", active: true, target_url: `https://hooks.example.com/${index + 1}` }));
  const fetchImpl = async (url) => {
    calls.push(url);
    const parsed = new URL(url);
    const page = Number(parsed.searchParams.get("page") ?? "1");
    const perPage = Number(parsed.searchParams.get("per_page") ?? "100");
    const slice = targets.slice((page - 1) * perPage, page * perPage);
    const hasNext = page * perPage < targets.length;
    return jsonResponse({
      targets: slice,
      next_page: hasNext ? `https://acme.zendesk.com/api/v2/targets?page=${page + 1}&per_page=${perPage}` : null,
      previous_page: page > 1 ? `https://acme.zendesk.com/api/v2/targets?page=${page - 1}&per_page=${perPage}` : null,
      count: targets.length,
    });
  };
  const client = new ZendeskApiClient(sampleConfig(), { fetchImpl });

  const result = await client.listTargets();
  assert.equal(result.items.length, 130, "130 targets across two pages must all be read");
  assert.equal(result.pages, 2);
  assert.equal(result.truncated, false);
  assert.equal(new URL(calls[0]).searchParams.get("per_page"), "100");
  assert.equal(new Set(result.items.map((item) => item.id)).size, 130);

  const capped = await new ZendeskApiClient(sampleConfig(), { fetchImpl }).listTargets(100);
  assert.equal(capped.items.length, 100);
  assert.equal(capped.truncated, true, "stopping at max_items with a next_page must be recorded as truncated");

  const silentPages = [];
  const silentClient = new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async (url) => {
      const page = Number(new URL(url).searchParams.get("page") ?? "1");
      silentPages.push(page);
      const slice = targets.slice((page - 1) * 100, page * 100);
      return jsonResponse({ targets: slice });
    },
  });
  const silent = await silentClient.listTargets();
  assert.equal(silent.items.length, 130, "a full page without next_page must trigger an explicit page=2 request");
  assert.deepEqual(silentPages, [1, 2]);
  assert.equal(silent.truncated, false);

  const repeating = await new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ targets: targets.slice(0, 100) }),
  }).listTargets();
  assert.equal(repeating.items.length, 100, "an endpoint that ignores page must not duplicate items");
  assert.equal(repeating.pages, 2);
  assert.equal(repeating.truncated, true, "a full page replayed for the next offset means the population beyond it was never seen");

  for (const [method, key] of [["listSharingAgreements", "sharing_agreements"], ["listAppInstallations", "installations"], ["listOwnedApps", "apps"], ["listCustomRoles", "custom_roles"], ["listDeletionSchedules", "deletion_schedules"]]) {
    const seenPages = [];
    const paged = new ZendeskApiClient(sampleConfig(), {
      fetchImpl: async (url) => {
        const page = Number(new URL(url).searchParams.get("page") ?? "1");
        seenPages.push(page);
        return jsonResponse(page === 1
          ? { [key]: Array.from({ length: 100 }, (_, index) => ({ id: index + 1 })), next_page: `https://acme.zendesk.com/api/v2/x?page=2`, previous_page: null }
          : { [key]: [{ id: 101 }], next_page: null, previous_page: "https://acme.zendesk.com/api/v2/x?page=1" });
      },
    });
    const outcome = await paged[method]();
    assert.equal(outcome.items.length, 101, `${method} must follow offset pagination`);
    assert.deepEqual(seenPages, [1, 2]);
  }
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
  assert.equal(result.surfaces.length, 20);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(result.missingPermissions, []);
  assert.equal(result.surfaces.find((surface) => surface.name === "security_settings").endpoint, "/api/v2/security_settings");
  assert.equal(result.surfaces.find((surface) => surface.name === "deletion_schedules").endpoint, "/api/v2/deletion_schedules");
  assert.match(result.recommendedNextStep, /zendesk_assess_authentication/);
});

test("checkZendeskAccess reports limited access and names admin-only surfaces for an agent credential", async () => {
  const client = healthyClient({
    async getCurrentUser() {
      return { id: 3, email: "agent@example.com", role: "agent" };
    },
    getSecuritySettings: forbidden("/security_settings"),
    listCustomRoles: forbidden("/custom_roles"),
    listDeletionSchedules: forbidden("/deletion_schedules"),
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
  assert.equal(result.missingPermissions.length, 7);
  assert.ok(result.missingPermissions.some((item) => /security_settings requires an admin credential \(\/api\/v2\/security_settings\)/.test(item)));
  assert.ok(result.missingPermissions.some((item) => /deletion_schedules requires an admin credential/.test(item)));
  assert.ok(result.missingPermissions.some((item) => /oauth_clients requires an admin credential/.test(item)));
  assert.ok(result.missingPermissions.some((item) => /audit_logs requires an Enterprise admin credential/.test(item)));
  assert.equal(result.surfaces.find((surface) => surface.name === "owned_apps").status, "not_found");
  assert.ok(result.notes.some((note) => /not an admin/.test(note)));
  assert.match(result.recommendedNextStep, /admin API token or OAuth token/);
});

test("assessZendeskAuthentication passes controls 1-5 and 21 from documented security settings on a compliant tenant", async () => {
  const result = await assessZendeskAuthentication(healthyClient(), { now: () => NOW });
  assert.equal(result.findings.length, 6);
  for (const id of ["ZD-01", "ZD-02", "ZD-03", "ZD-04", "ZD-05", "ZD-21"]) {
    assert.equal(findingById(result, id).status, "pass", `${id} should pass on the compliant security settings fixture`);
  }
  const sso = findingById(result, "ZD-01");
  assert.match(sso.summary, /enforce_sso=true and zendesk_login=false/);
  assert.match(sso.summary, /remote_login \(SAML or JWT\)/);
  assert.match(sso.summary, /limited to owner/);
  assert.equal(sso.evidence.remote_bypass, 1);
  assert.equal(sso.evidence.sso_auto_redirect, false);
  assert.match(findingById(result, "ZD-02").summary, /two_factor_enforce=true and all 4 active team members/);
  const password = findingById(result, "ZD-03");
  assert.match(password.summary, /security_policy_name=recommended \(security_policy_id 350\)/);
  assert.equal(password.evidence.password.password_length, 12);
  const ip = findingById(result, "ZD-04");
  assert.match(ip.summary, /ip_restriction_enabled=true with 2 allowed IP range\(s\)/);
  assert.match(ip.summary, /customers are exempt \(enable_agent_ip_restrictions=true\)/);
  assert.deepEqual(ip.evidence.ip_ranges, ["203.0.113.0/24", "198.51.100.7"]);
  const session = findingById(result, "ZD-05");
  assert.match(session.summary, /agent_session_timeout=480 minutes/);
  assert.match(session.summary, /mobile_app_session_timeout=300 minutes/);
  assert.match(session.summary, /maximum session duration of 720 minutes/);
  assert.match(session.summary, /End user sessions expire after 480 minutes/);
  const endUser = findingById(result, "ZD-21");
  assert.match(endUser.summary, /authentication\.end_user\.enforce_sso=true/);
  assert.match(endUser.summary, /Anybody can submit tickets/, "the anonymous submission portion stays a manual check");
  assert.ok(sso.mappings.some((mapping) => mapping.startsWith("FedRAMP IA-2")));
  assert.equal(result.summary.current_user_role, "admin");
  assert.equal(result.snapshots.security_settings.authentication.agent.enforce_sso, true);
});

test("assessZendeskAuthentication fails SSO, password, IP, session, and end-user controls on non-compliant security settings", async () => {
  const client = healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({
        agent: { enforce_sso: false, zendesk_login: true, remote_login: true, security_policy_name: "low", security_policy_id: 100 },
        endUser: { enforce_sso: false, zendesk_login: false, remote_login: false, google_login: false, office_365_login: false, facebook_login: false },
        ip: { ip_restriction_enabled: false, ip_ranges: null },
        agent_session_timeout: 10080,
        maximum_session_duration_enabled: false,
      });
    },
  });
  const result = await assessZendeskAuthentication(client, { now: () => NOW });
  const sso = findingById(result, "ZD-01");
  assert.equal(sso.status, "fail");
  assert.match(sso.summary, /enforce_sso=false: remote_login \(SAML or JWT\) is enabled but not enforced/);
  const password = findingById(result, "ZD-03");
  assert.equal(password.status, "fail");
  assert.match(password.summary, /security_policy_name=low/);
  const ip = findingById(result, "ZD-04");
  assert.equal(ip.status, "fail");
  assert.match(ip.summary, /ip_restriction_enabled=false/);
  const session = findingById(result, "ZD-05");
  assert.equal(session.status, "fail");
  assert.match(session.summary, /agent_session_timeout=10080 minutes exceeds the 480-minute threshold/);
  assert.match(session.summary, /No maximum session duration is enforced/);
  const endUser = findingById(result, "ZD-21");
  assert.equal(endUser.status, "fail");
  assert.match(endUser.summary, /no SSO method is enabled, so end users have no way to sign in/);
});

test("assessZendeskAuthentication warns on partially compliant security settings and honors the session threshold option", async () => {
  const result = await assessZendeskAuthentication(healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({
        agent: { enforce_sso: true, zendesk_login: true, remote_login: true, google_login: true, sso_auto_redirect: false, security_policy_name: "custom", security_policy_id: 400 },
        agentPassword: { password_length: 8, password_complexity: 1, password_history_length: 3 },
        endUser: { enforce_sso: false, zendesk_login: true, remote_login: false, security_policy_name: "medium", security_policy_id: 200 },
        ip: { ip_restriction_enabled: true, ip_ranges: "" },
        agent_session_timeout: 720,
      });
    },
  }), { now: () => NOW });
  const sso = findingById(result, "ZD-01");
  assert.equal(sso.status, "warn");
  assert.match(sso.summary, /zendesk_login=true, so email and password sign-in still appears enabled/);
  assert.match(sso.summary, /sso_auto_redirect=false, so team members choose/);
  const password = findingById(result, "ZD-03");
  assert.equal(password.status, "warn");
  assert.match(password.summary, /password_length=8 \(baseline 12\)/);
  assert.match(password.summary, /password_complexity=1/);
  assert.match(password.summary, /password_history_length=3/);
  assert.equal(findingById(result, "ZD-04").status, "warn");
  assert.match(findingById(result, "ZD-04").summary, /ip_ranges is empty/);
  assert.equal(findingById(result, "ZD-05").status, "warn");
  const endUser = findingById(result, "ZD-21");
  assert.equal(endUser.status, "warn");
  assert.match(endUser.summary, /medium password security level; raise the end user password level/);

  const relaxed = await assessZendeskAuthentication(healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({ agent_session_timeout: 720 });
    },
  }), { now: () => NOW, sessionTimeoutMinutes: 720 });
  assert.equal(findingById(relaxed, "ZD-05").status, "pass");

  const highPolicy = await assessZendeskAuthentication(healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({ agent: { security_policy_name: "high", security_policy_id: 300 } });
    },
  }), { now: () => NOW });
  assert.equal(findingById(highPolicy, "ZD-03").status, "warn");
  assert.match(findingById(highPolicy, "ZD-03").summary, /lower requirements than Recommended/);

  const customStrong = await assessZendeskAuthentication(healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({ agent: { security_policy_name: "custom", security_policy_id: 400 } });
    },
  }), { now: () => NOW });
  assert.equal(findingById(customStrong, "ZD-03").status, "pass");
  assert.match(findingById(customStrong, "ZD-03").summary, /meet the baseline/);

  const passwordEndUsers = await assessZendeskAuthentication(healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({ endUser: { enforce_sso: false, remote_login: false, zendesk_login: true, security_policy_name: "recommended" } });
    },
  }), { now: () => NOW });
  assert.equal(findingById(passwordEndUsers, "ZD-21").status, "pass");
  assert.match(findingById(passwordEndUsers, "ZD-21").summary, /zendesk_login=true under the recommended password security level/);
});

test("assessZendeskAuthentication renders security-settings controls manual when the endpoint is forbidden or fields are absent", async () => {
  const forbiddenSecurity = await assessZendeskAuthentication(healthyClient({ getSecuritySettings: forbidden("/security_settings") }), { now: () => NOW });
  for (const id of ["ZD-01", "ZD-02", "ZD-03", "ZD-04", "ZD-05", "ZD-21"]) {
    const item = findingById(forbiddenSecurity, id);
    assert.equal(item.status, "manual", `${id} must be manual when /security_settings is forbidden`);
    assert.match(item.summary, /Security settings \(\/security_settings, admin only\) returned 403/);
    assert.match(item.summary, /Manual evidence: capture/);
  }
  assert.match(findingById(forbiddenSecurity, "ZD-02").summary, /4\/4 seen team members report two_factor_auth_enabled=true, but the account-level requirement could not be verified/);

  const absentFields = await assessZendeskAuthentication(healthyClient({
    async getSecuritySettings() {
      return { authentication: { agent: {}, end_user: {} }, ip: {} };
    },
  }), { now: () => NOW });
  for (const id of ["ZD-01", "ZD-02", "ZD-03", "ZD-04", "ZD-05", "ZD-21"]) {
    assert.equal(findingById(absentFields, id).status, "manual", `${id} must not pass when the documented flag is absent`);
  }
  assert.match(findingById(absentFields, "ZD-01").summary, /did not include enforce_sso and zendesk_login/);
  assert.match(findingById(absentFields, "ZD-04").summary, /ip_restriction_enabled was absent/);
  assert.match(findingById(absentFields, "ZD-05").summary, /agent_session_timeout was absent/);
});

test("assessZendeskAuthentication never passes 2FA when account enforcement is off even if every user flag is on", async () => {
  const enforcementOff = await assessZendeskAuthentication(healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({ agent: { two_factor_enforce: false, enforce_sso: false, zendesk_login: true, remote_login: false } });
    },
  }), { now: () => NOW });
  const item = findingById(enforcementOff, "ZD-02");
  assert.equal(item.status, "fail");
  assert.match(item.summary, /two_factor_enforce=false: the account does not require 2FA/);
  assert.match(item.summary, /4\/4 seen team members report two_factor_auth_enabled=true/);
  assert.equal(item.evidence.two_factor_enforce, false);

  const ssoOnly = await assessZendeskAuthentication(healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({ agent: { two_factor_enforce: false } });
    },
  }), { now: () => NOW });
  assert.equal(findingById(ssoOnly, "ZD-02").status, "manual");
  assert.match(findingById(ssoOnly, "ZD-02").summary, /depends on the identity provider/);

  const notEnrolled = await assessZendeskAuthentication(healthyClient({
    async listTeamMembers() {
      return list([teamMember({ id: 1, role: "admin" }), teamMember({ id: 2, role: "agent", two_factor_auth_enabled: false })]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(notEnrolled, "ZD-02").status, "warn");
  assert.match(findingById(notEnrolled, "ZD-02").summary, /1 team members report two_factor_auth_enabled=false \(not yet enrolled\)/);
});

test("assessZendeskAuthentication fails 2FA when enforcement is off and an active team member reports the flag false", async () => {
  const client = healthyClient({
    async getSecuritySettings() {
      return healthySecuritySettings({ agent: { two_factor_enforce: false, enforce_sso: false, zendesk_login: true } });
    },
    async listTeamMembers() {
      return list([teamMember({ id: 1, role: "admin" }), teamMember({ id: 2, role: "agent", two_factor_auth_enabled: false })]);
    },
  });
  const result = await assessZendeskAuthentication(client, { now: () => NOW });
  const item = findingById(result, "ZD-02");
  assert.equal(item.status, "fail");
  assert.match(item.summary, /1\/2 seen team members report two_factor_auth_enabled=true and 1 report it disabled/);
  assert.deepEqual(item.evidence.without_two_factor, ["user-2@example.com"]);

  const forbiddenSecurity = await assessZendeskAuthentication(healthyClient({
    getSecuritySettings: forbidden("/security_settings"),
    async listTeamMembers() {
      return list([teamMember({ id: 1, role: "admin" }), teamMember({ id: 2, role: "agent", two_factor_auth_enabled: false })]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(forbiddenSecurity, "ZD-02").status, "fail", "a user without 2FA fails even when enforcement cannot be read");
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
  assert.equal(findingById(tokenAccessOn, "ZD-13").status, "warn");
  assert.match(findingById(tokenAccessOn, "ZD-13").summary, /api_token_access=true/);
  assert.match(findingById(tokenAccessOn, "ZD-13").summary, /authenticated with an API token, so the audit history does not cover every token/);
});

test("assessZendeskAccessControl enumerates API token events from the audit log for control 13", async () => {
  const tokenSettings = async () => healthySettings({ api: { api_token_access: true } });
  const oauthConfig = () => sampleConfig({ authMode: "oauth", email: undefined, apiToken: undefined, oauthToken: "oauth-secret" });
  const events = [
    tokenEvent({ id: 9, action: "destroy", source_id: 501, source_label: "Legacy sync", created_at: daysAgo(5), change_description: "API token deleted" }),
    tokenEvent({ id: 8, action: "create", source_id: 502, source_label: "Data warehouse", created_at: daysAgo(200), actor_name: "Ops Admin" }),
    tokenEvent({ id: 7, action: "create", source_id: 501, source_label: "Legacy sync", created_at: daysAgo(300) }),
    tokenEvent({ id: 6, action: "create", source_id: 500, source_label: "Reporting integration", created_at: daysAgo(10) }),
    tokenEvent({ id: 5, action: "create", source_id: 499, source_label: "Undated token", created_at: null }),
  ];

  const outstanding = await assessZendeskAccessControl(healthyClient({
    getResolvedConfig: oauthConfig,
    getAccountSettings: tokenSettings,
    async listApiTokenAuditLogs() {
      return list(events);
    },
  }), { now: () => NOW });
  const item = findingById(outstanding, "ZD-13");
  assert.equal(item.status, "manual", "outstanding tokens require a human review");
  assert.match(item.summary, /filter\[source_type\]=apitoken\) recorded 4 token creation and 1 deletion events/);
  assert.match(item.summary, /leaving 3 outstanding token\(s\)/);
  assert.match(item.summary, /1 were created more than 90 days ago and 1 have no creation date/);
  assert.equal(item.evidence.tokens_outstanding, 3);
  assert.deepEqual(item.evidence.outstanding_tokens.map((token) => token.label), ["Data warehouse", "Reporting integration", "Undated token"]);
  assert.equal(item.evidence.outstanding_tokens[2].age_days, null, "undated tokens are never counted as fresh");
  assert.equal(item.evidence.tokens_outstanding_over_stale_days, 1);

  const oauthClean = await assessZendeskAccessControl(healthyClient({
    getResolvedConfig: oauthConfig,
    getAccountSettings: tokenSettings,
    async listApiTokenAuditLogs() {
      return list([events[0], events[2]]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(oauthClean, "ZD-13").status, "warn");
  assert.match(findingById(oauthClean, "ZD-13").summary, /leaving 0 outstanding token\(s\)\. The audit log records events rather than an inventory/);

  const truncatedHistory = await assessZendeskAccessControl(healthyClient({
    getResolvedConfig: oauthConfig,
    getAccountSettings: tokenSettings,
    async listApiTokenAuditLogs() {
      return list([events[0], events[2]], true);
    },
  }), { now: () => NOW });
  assert.equal(findingById(truncatedHistory, "ZD-13").status, "warn");
  assert.match(findingById(truncatedHistory, "ZD-13").summary, /history truncated/);

  const noAuditLog = await assessZendeskAccessControl(healthyClient({
    getAccountSettings: tokenSettings,
    async listApiTokenAuditLogs() {
      throw new ZendeskApiError("Zendesk request failed for /audit_logs (404 Not Found)", 404);
    },
  }), { now: () => NOW });
  assert.equal(findingById(noAuditLog, "ZD-13").status, "manual");
  assert.match(findingById(noAuditLog, "ZD-13").summary, /Audit log token events \(\/audit_logs\?filter\[source_type\]=apitoken, Enterprise plan and admin role\) returned 404/);

  const disabled = await assessZendeskAccessControl(healthyClient({
    async listApiTokenAuditLogs() {
      return list(events);
    },
  }), { now: () => NOW });
  assert.equal(findingById(disabled, "ZD-13").status, "pass");
  assert.match(findingById(disabled, "ZD-13").summary, /api_token_access=false, so API tokens cannot be used/);
  assert.equal(findingById(disabled, "ZD-13").evidence.tokens_outstanding, 3);
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
  assert.match(findingById(result, "ZD-11").summary, /Neither the published Account Settings reference nor the Security Settings reference/);
  const deletion = findingById(result, "ZD-12");
  assert.equal(deletion.status, "pass");
  assert.match(deletion.summary, /2 active deletion schedule\(s\) read to completion \(1 for zen:ticket, 1 for zen:user; 0 default\)/);
  assert.match(deletion.summary, /1\/1 custom roles allow ticket redaction/);
  assert.deepEqual(deletion.evidence.active_by_object, { "zen:ticket": 1, "zen:user": 1, "zen:attachment": 0, "zen:bot_only_conversation": 0, other: 0 });
  assert.deepEqual(deletion.evidence.schedules[0].conditions_all, ["duration_since_last_update greater_than P3Y"]);
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

test("assessZendeskDataProtection evaluates deletion schedules by object and never passes on empty, inactive, or forbidden schedules", async () => {
  const none = await assessZendeskDataProtection(healthyClient({ async listDeletionSchedules() { return list([]); } }), { now: () => NOW });
  assert.equal(findingById(none, "ZD-12").status, "fail");
  assert.match(findingById(none, "ZD-12").summary, /readable and returned zero schedules, so no automated retention or deletion policy is configured/);

  const inactive = await assessZendeskDataProtection(healthyClient({
    async listDeletionSchedules() {
      return list([deletionSchedule({ id: 1, active: false })]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(inactive, "ZD-12").status, "fail");
  assert.match(findingById(inactive, "ZD-12").summary, /1 deletion schedule\(s\) exist but none is active/);

  const usersOnly = await assessZendeskDataProtection(healthyClient({
    async listDeletionSchedules() {
      return list([deletionSchedule({ id: 3, object: "zen:user", default: true })]);
    },
  }), { now: () => NOW });
  const users = findingById(usersOnly, "ZD-12");
  assert.equal(users.status, "warn");
  assert.match(users.summary, /1 active deletion schedule\(s\) \(1 for zen:user; 1 default\) but none targets zen:ticket/);

  const unconditioned = await assessZendeskDataProtection(healthyClient({
    async listDeletionSchedules() {
      return list([deletionSchedule({ id: 4, conditions: { all: [], any: [] } })]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(unconditioned, "ZD-12").status, "warn");
  assert.match(findingById(unconditioned, "ZD-12").summary, /1 active schedule\(s\) have no conditions/);

  const truncated = await assessZendeskDataProtection(healthyClient({
    async listDeletionSchedules() {
      return list([deletionSchedule({ id: 1 })], true);
    },
  }), { now: () => NOW });
  assert.equal(findingById(truncated, "ZD-12").status, "warn");
  assert.match(findingById(truncated, "ZD-12").summary, /schedule inventory was truncated/);

  const forbiddenSchedules = await assessZendeskDataProtection(healthyClient({ listDeletionSchedules: forbidden("/deletion_schedules") }), { now: () => NOW });
  assert.equal(findingById(forbiddenSchedules, "ZD-12").status, "manual");
  assert.match(findingById(forbiddenSchedules, "ZD-12").summary, /Deletion schedules \(\/deletion_schedules, admin only\) returned 403/);
  assert.match(findingById(forbiddenSchedules, "ZD-12").summary, /Manual evidence: capture Admin Center > Objects and rules > Tickets > Deletion schedules/);
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
  const expectedPass = new Set(["ZD-01", "ZD-03", "ZD-04", "ZD-05", "ZD-13", "ZD-14", "ZD-15", "ZD-16", "ZD-17", "ZD-18", "ZD-20", "ZD-21", "ZD-23", "ZD-24"]);
  for (const [id, status] of statuses) {
    if (expectedPass.has(id)) {
      assert.equal(status, "pass", `${id} passes on emptiness or an explicit documented flag`);
    } else {
      assert.notEqual(status, "pass", `${id} must not pass on an empty inventory`);
    }
  }
  assert.equal(statuses.get("ZD-12"), "fail", "zero deletion schedules means no retention policy is configured");
  assert.equal(statuses.get("ZD-02"), "manual", "zero team members is a partial view even when enforcement is on");
  const passing = results.flatMap((result) => result.findings).filter((item) => item.status === "pass");
  for (const item of passing) {
    assert.match(item.summary, /zero|empty|=false|=true|=recommended|=\d+ minutes/i, `${item.id} must state why emptiness or the flag value is compliant`);
  }
});

test("self-check (d): a compliant tenant built from documented fields passes every automatable control", async () => {
  const results = await runAllAssessments(healthyClient());
  const statuses = statusMap(results);
  assert.equal(statuses.size, 25);
  const expectedManual = new Set(["ZD-11", "ZD-19"]);
  for (const [id, status] of statuses) {
    if (expectedManual.has(id)) {
      assert.equal(status, "manual", `${id} has no documented API field and stays manual`);
    } else {
      assert.equal(status, "pass", `${id} must pass on the compliant fixture`);
    }
  }
  for (const id of ["ZD-01", "ZD-03", "ZD-04", "ZD-05", "ZD-12", "ZD-21"]) {
    assert.equal(statuses.get(id), "pass", `${id} is now verified from security settings or deletion schedules`);
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
    "core_data/security_settings.json",
    "core_data/team_members.json",
    "core_data/oauth_clients.json",
    "core_data/api_token_audit_logs.json",
    "core_data/deletion_schedules.json",
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

// Fake credential values Zendesk list endpoints can return verbatim; none may reach a bundle.
const FAKE_ZENDESK_SECRETS = {
  fullToken: "zd-full-token-fake-0123456789abcdefghijklmnopqrstuvwxyz",
  tokenPrefix: "zdtok-fake1",
  refreshToken: "zd-refresh-token-fake-0123456789abcdef",
  clientSecret: "zd-client-secret-fake-0123456789abcdef",
  webhookBearer: "zd-webhook-bearer-fake-0123456789",
  webhookApiKeyValue: "zd-webhook-api-key-value-fake",
  signingSecret: "zd-signing-secret-fake-0123456789",
  targetPassword: "zd-target-password-fake",
  targetToken: "zd-target-token-fake-0123456789",
  appApiKey: "zd-app-setting-api-key-fake",
  appApiKeyCamel: "zd-app-setting-apiKey-camel-fake",
  appClientSecretCamel: "zd-app-setting-clientSecret-camel-fake",
  appRefreshTokenCamel: "zd-app-setting-refreshToken-camel-fake",
  appAccessTokenCamel: "zd-app-setting-accessToken-camel-fake",
  appAuthorizationHeader: "Bearer zd-app-setting-authorization-header-fake",
  appXApiKeyHeader: "zd-app-setting-x-api-key-header-fake",
  webhookCustomHeaderAuthorization: "Basic zd-webhook-custom-header-authorization-fake",
  webhookCustomHeaderApiKey: "zd-webhook-custom-header-x-api-key-fake",
  webhookCustomHeaderPlain: "zd-webhook-custom-header-plain-value-fake",
  // Credentials carried inside URL and free-text string values rather than under a credential key.
  targetUrlQueryToken: "zd-target-url-query-token-fake-0123456789",
  webhookUserinfoPassword: "zd-webhook-userinfo-password-fake-0123",
  redirectUriClientSecret: "zd-redirect-uri-client-secret-fake-0123",
  slackWebhookPath: "T0FAKE0000/B0FAKE0000/zdSlackWebhookPathFake0123456789",
  ownedAppParameterToken: "zd-owned-app-parameter-api-token-fake",
  ownedAppSecureDefault: "zd-owned-app-secure-parameter-default-fake",
  jsonEncodedSettingToken: "zd-json-encoded-setting-token-fake",
};

// Header names that must survive redaction as keys or name fields.
const FAKE_ZENDESK_HEADER_NAMES = ["Authorization", "X-Api-Key", "X-Tenant"];

function secretBearingClient(overrides = {}) {
  return healthyClient({
    async listOAuthClients() {
      return list([
        { id: 1, name: "Reporting", identifier: "reporting", kind: "confidential", scope: "read", redirect_uri: ["https://reports.example.com/callback", `https://reports.example.com/cb?client_secret=${FAKE_ZENDESK_SECRETS.redirectUriClientSecret}&state=abc`], secret: FAKE_ZENDESK_SECRETS.clientSecret },
      ]);
    },
    async listOAuthTokens() {
      return list([
        { id: 1, user_id: 7, client_id: 1, scopes: ["read"], expires_at: daysAgo(-30), used_at: daysAgo(1), created_at: daysAgo(40), token: FAKE_ZENDESK_SECRETS.tokenPrefix, full_token: FAKE_ZENDESK_SECRETS.fullToken, refresh_token: FAKE_ZENDESK_SECRETS.refreshToken, url: "https://acme.zendesk.com/api/v2/oauth/tokens/1.json" },
      ]);
    },
    async listWebhooks() {
      return list([
        { id: "wh1", name: "Pager", status: "active", endpoint: "https://hooks.example.com/zendesk", authentication: { type: "bearer_token", add_position: "header", data: { token: FAKE_ZENDESK_SECRETS.webhookBearer } }, custom_headers: { Authorization: FAKE_ZENDESK_SECRETS.webhookCustomHeaderAuthorization, "X-Tenant": FAKE_ZENDESK_SECRETS.webhookCustomHeaderPlain } },
        { id: "wh2", name: "SIEM", status: "active", endpoint: "https://siem.example.com/ingest", authentication: { type: "api_key", add_position: "header", data: { name: "X-Api-Key", value: FAKE_ZENDESK_SECRETS.webhookApiKeyValue } }, signing_secret: { algorithm: "SHA256", secret: FAKE_ZENDESK_SECRETS.signingSecret }, custom_headers: [{ name: "X-Api-Key", value: FAKE_ZENDESK_SECRETS.webhookCustomHeaderApiKey }] },
        { id: "wh3", name: "Relay", status: "active", endpoint: `https://relay:${FAKE_ZENDESK_SECRETS.webhookUserinfoPassword}@relay.example.com/ingest`, authentication: { type: "basic_auth", add_position: "header", data: { username: "relay", password: FAKE_ZENDESK_SECRETS.targetPassword } } },
      ]);
    },
    async listTargets() {
      return list([
        { id: 5, title: "Legacy URL target", type: "url_target", active: true, target_url: "https://legacy.example.com/hook", method: "post", username: "svc-zendesk", password: FAKE_ZENDESK_SECRETS.targetPassword },
        { id: 6, title: "Chat room", type: "campfire_target", active: true, token: FAKE_ZENDESK_SECRETS.targetToken, room: "ops" },
        { id: 7, title: "Query token target", type: "url_target_v2", active: true, target_url: `https://legacy.example.com/hook?token=${FAKE_ZENDESK_SECRETS.targetUrlQueryToken}&room=ops`, method: "post" },
      ]);
    },
    async listOwnedApps() {
      return list([
        {
          id: 88,
          name: "Internal widget",
          visibility: "private",
          framework_version: "2.0",
          parameters: [
            { name: "api_token", kind: "text", required: true, secure: true, default_value: null, value: FAKE_ZENDESK_SECRETS.ownedAppParameterToken },
            { name: "endpoint", kind: "text", required: false, secure: true, default: FAKE_ZENDESK_SECRETS.ownedAppSecureDefault },
            { name: "region", kind: "text", required: false, secure: false, default: "us-east-1" },
          ],
        },
      ]);
    },
    async listAppInstallations() {
      return list([
        { id: 900, app_id: 42, product: "support", enabled: true, settings: { name: "Ticket enricher", title: "Ticket enricher", api_key: FAKE_ZENDESK_SECRETS.appApiKey, notify_url: `https://hooks.slack.com/services/${FAKE_ZENDESK_SECRETS.slackWebhookPath}`, connector_config: JSON.stringify({ token: FAKE_ZENDESK_SECRETS.jsonEncodedSettingToken, host: "crm.example.com" }) } },
        {
          id: 901,
          app_id: 43,
          product: "support",
          enabled: true,
          settings: {
            name: "CRM sync",
            title: "CRM sync",
            apiKey: FAKE_ZENDESK_SECRETS.appApiKeyCamel,
            clientId: "crm-client-0042",
            clientSecret: FAKE_ZENDESK_SECRETS.appClientSecretCamel,
            refreshToken: FAKE_ZENDESK_SECRETS.appRefreshTokenCamel,
            accessToken: FAKE_ZENDESK_SECRETS.appAccessTokenCamel,
            tokenExpiresAt: "2027-01-01T00:00:00Z",
            Authorization: FAKE_ZENDESK_SECRETS.appAuthorizationHeader,
            "X-Api-Key": FAKE_ZENDESK_SECRETS.appXApiKeyHeader,
            username: "crm-sync@example.com",
            scopes: "read write",
          },
        },
      ]);
    },
    async listTriggers() {
      return list([
        { id: 1, title: "Notify requester", active: true, actions: [{ field: "notification_user", value: ["requester_id", "Update", "Body"] }] },
        { id: 2, title: "Post to legacy hook", active: true, actions: [{ field: "notification_target", value: ["7", "{{ticket.title}}"] }] },
      ]);
    },
    ...overrides,
  });
}

test("redactCredentialProperties replaces credential strings and keeps identifiers, dates, and settings objects", () => {
  const token = redactCredentialProperties({ id: 1, client_id: 2, scopes: ["read"], expires_at: "2027-01-01T00:00:00Z", created_at: "2026-01-01T00:00:00Z", token: "prefix", full_token: "full", refresh_token: "refresh", used_at: null });
  assert.deepEqual(token, { id: 1, client_id: 2, scopes: ["read"], expires_at: "2027-01-01T00:00:00Z", created_at: "2026-01-01T00:00:00Z", token: "[REDACTED]", full_token: "[REDACTED]", refresh_token: "[REDACTED]", used_at: null });

  const listResult = redactCredentialProperties({ items: [{ id: 1, secret: "s3cret", identifier: "reporting" }, { id: 2, secret: null }], truncated: false, pages: 1 });
  assert.deepEqual(listResult, { items: [{ id: 1, secret: "[REDACTED]", identifier: "reporting" }, { id: 2, secret: null }], truncated: false, pages: 1 });

  const webhook = redactCredentialProperties({
    id: "wh2",
    authentication: { type: "api_key", add_position: "header", data: { name: "X-Api-Key", value: "the-key" } },
    signing_secret: { algorithm: "SHA256", secret: "signing" },
  });
  assert.deepEqual(webhook, {
    id: "wh2",
    authentication: { type: "api_key", add_position: "header", data: { name: "X-Api-Key", value: "[REDACTED]" } },
    signing_secret: { algorithm: "SHA256", secret: "[REDACTED]" },
  });
  const basicAuth = redactCredentialProperties({ authentication: { type: "basic_auth", data: { username: "svc", password: "pw" } } });
  assert.deepEqual(basicAuth, { authentication: { type: "basic_auth", data: { username: "svc", password: "[REDACTED]" } } });

  const security = redactCredentialProperties(healthySecuritySettings());
  assert.deepEqual(security, healthySecuritySettings(), "the password policy object under authentication.agent.password is not a credential");
  assert.equal(redactCredentialProperties("plain"), "plain");
  assert.equal(redactCredentialProperties(undefined), undefined);
  assert.deepEqual(redactCredentialProperties({ token: "" }), { token: "" }, "empty strings are not replaced with a marker");

  const camelSettings = redactCredentialProperties({
    settings: { apiKey: "k", APIKey: "k2", clientId: "cid", clientSecret: "cs", refreshToken: "rt", accessToken: "at", tokenExpiresAt: "2027-01-01T00:00:00Z", privateKey: "pk", publicKey: "pub", secretKey: "sk", passphrase: "pp", passwd: "pw", username: "svc", displayName: "CRM", key: "generic", keyId: "kid" },
  });
  assert.deepEqual(camelSettings, {
    settings: { apiKey: "[REDACTED]", APIKey: "[REDACTED]", clientId: "cid", clientSecret: "[REDACTED]", refreshToken: "[REDACTED]", accessToken: "[REDACTED]", tokenExpiresAt: "2027-01-01T00:00:00Z", privateKey: "[REDACTED]", publicKey: "pub", secretKey: "[REDACTED]", passphrase: "[REDACTED]", passwd: "[REDACTED]", username: "svc", displayName: "CRM", key: "generic", keyId: "kid" },
  });

  const headerSettings = redactCredentialProperties({ settings: { Authorization: "Bearer abc", "Proxy-Authorization": "Basic xyz", "X-Api-Key": "k", "X-Auth-Token": "t", "Content-Type": "application/json" } });
  assert.deepEqual(headerSettings, { settings: { Authorization: "[REDACTED]", "Proxy-Authorization": "[REDACTED]", "X-Api-Key": "[REDACTED]", "X-Auth-Token": "[REDACTED]", "Content-Type": "application/json" } });

  const customHeaders = redactCredentialProperties({
    id: "wh3",
    custom_headers: { Authorization: "Bearer abc", "X-Tenant": "acme" },
    customHeaders: [{ name: "X-Api-Key", value: "k" }, { name: "X-Trace", value: "trace-1" }],
  });
  assert.deepEqual(customHeaders, {
    id: "wh3",
    custom_headers: { Authorization: "[REDACTED]", "X-Tenant": "[REDACTED]" },
    customHeaders: [{ name: "X-Api-Key", value: "[REDACTED]" }, { name: "X-Trace", value: "[REDACTED]" }],
  }, "every header value is redacted while header names stay as keys or name fields");

  for (const name of ["token", "full_token", "refresh_token", "refreshToken", "access_token", "accessToken", "bearer_token", "api_token", "apiToken", "secret", "client_secret", "clientSecret", "signing_secret", "shared_secret", "password", "passwd", "pwd", "passphrase", "api_key", "apiKey", "APIKey", "apikey", "private_key", "privateKey", "secret_key", "access_key", "signing_key", "Authorization", "authorization", "Proxy-Authorization", "X-Api-Key", "X-Auth-Token", "oauth_token", "id_token"]) {
    assert.equal(isCredentialPropertyName(name), true, `${name} should be redacted`);
  }
  for (const name of ["id", "user_id", "client_id", "clientId", "token_id", "api_key_id", "key_id", "keyId", "scopes", "scope", "expires_at", "tokenExpiresAt", "created_at", "used_at", "username", "user_name", "name", "displayName", "email", "url", "key", "public_key", "publicKey", "token_type", "api_token_access", "api_password_access_end_users", "password_length", "password_complexity", "password_history_length", "security_policy_name", "source_type", "manage_api_credentials", "two_factor_enforce", "Content-Type", "identifier", "kind"]) {
    assert.equal(isCredentialPropertyName(name), false, `${name} should be kept`);
  }
});

test("assessZendeskAccessControl never retains OAuth token values in its snapshots, evidence, or verdicts", async () => {
  const result = await assessZendeskAccessControl(secretBearingClient(), { now: () => NOW });
  const text = JSON.stringify(result);
  for (const secret of [FAKE_ZENDESK_SECRETS.fullToken, FAKE_ZENDESK_SECRETS.tokenPrefix, FAKE_ZENDESK_SECRETS.refreshToken, FAKE_ZENDESK_SECRETS.clientSecret]) {
    assert.ok(!text.includes(secret), `${secret} leaked into the assessment result`);
  }
  const [token] = result.snapshots.oauth_tokens.items;
  assert.equal(token.token, "[REDACTED]");
  assert.equal(token.full_token, "[REDACTED]");
  assert.equal(token.refresh_token, "[REDACTED]");
  assert.equal(token.id, 1);
  assert.equal(token.client_id, 1);
  assert.deepEqual(token.scopes, ["read"]);
  assert.equal(token.expires_at, daysAgo(-30));
  assert.equal(token.created_at, daysAgo(40));
  assert.equal(result.snapshots.oauth_clients.items[0].secret, "[REDACTED]");
  assert.equal(result.snapshots.oauth_clients.items[0].identifier, "reporting");
  const oauth = result.findings.find((item) => item.id === "ZD-14");
  assert.equal(oauth.status, "pass", oauth.summary);
  assert.equal(oauth.evidence.oauth_tokens, 1);
  assert.equal(oauth.evidence.tokens_without_expiry, 0);
});

test("exportZendeskAuditBundle never writes OAuth tokens, client secrets, or webhook and target credentials into the bundle or its zip", async () => {
  const base = createTempBase("grclanker-zendesk-export-secrets-");
  const secrets = Object.values(FAKE_ZENDESK_SECRETS);
  const result = await exportZendeskAuditBundle(secretBearingClient(), sampleConfig(), base, { now: () => NOW });
  assert.equal(result.errorCount, 0);

  const files = readBundleFiles(result.outputDir);
  for (const relativePath of ["core_data/oauth_tokens.json", "core_data/oauth_clients.json", "core_data/webhooks.json", "core_data/targets.json", "core_data/app_installations.json", "analysis/access-control.json", "analysis/integrations.json"]) {
    assert.ok(files.has(join(...relativePath.split("/"))), `expected ${relativePath}`);
  }
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assert.ok(zipEntries.has("core_data/oauth_tokens.json"));
  assertSecretsAbsent(assert, zipEntries, secrets, "zip archive");

  const tokens = JSON.parse(files.get(join("core_data", "oauth_tokens.json")));
  assert.deepEqual(tokens.items[0], {
    id: 1,
    user_id: 7,
    client_id: 1,
    scopes: ["read"],
    expires_at: daysAgo(-30),
    used_at: daysAgo(1),
    created_at: daysAgo(40),
    token: "[REDACTED]",
    full_token: "[REDACTED]",
    refresh_token: "[REDACTED]",
    url: "https://acme.zendesk.com/api/v2/oauth/tokens/1.json",
  });
  const analysis = JSON.parse(files.get(join("analysis", "access-control.json")));
  assert.equal(analysis.snapshots.oauth_tokens.items[0].full_token, "[REDACTED]");
  assert.equal(analysis.snapshots.oauth_clients.items[0].secret, "[REDACTED]");
  const webhooks = JSON.parse(files.get(join("core_data", "webhooks.json")));
  assert.equal(webhooks.items[0].authentication.data.token, "[REDACTED]");
  assert.deepEqual(webhooks.items[0].custom_headers, { Authorization: "[REDACTED]", "X-Tenant": "[REDACTED]" }, "custom header values are redacted and header names stay as keys");
  assert.equal(webhooks.items[1].authentication.data.name, "X-Api-Key");
  assert.equal(webhooks.items[1].authentication.data.value, "[REDACTED]");
  assert.equal(webhooks.items[1].signing_secret.secret, "[REDACTED]");
  assert.deepEqual(webhooks.items[1].custom_headers, [{ name: "X-Api-Key", value: "[REDACTED]" }], "custom header values are redacted and header names stay as name fields");
  const targets = JSON.parse(files.get(join("core_data", "targets.json")));
  assert.equal(targets.items[0].username, "svc-zendesk");
  assert.equal(targets.items[0].password, "[REDACTED]");
  assert.equal(targets.items[1].token, "[REDACTED]");
  assert.equal(targets.items[2].target_url, "https://legacy.example.com/hook?token=[REDACTED]&room=ops", "URL query credentials are replaced while the scheme, host, path, and other parameters stay");
  assert.equal(webhooks.items[2].endpoint, "https://[REDACTED]@relay.example.com/ingest", "URL userinfo is replaced while the scheme and host stay");
  assert.equal(webhooks.items[2].authentication.data.username, "relay");
  assert.equal(webhooks.items[2].authentication.data.password, "[REDACTED]");
  const clients = JSON.parse(files.get(join("core_data", "oauth_clients.json")));
  assert.deepEqual(clients.items[0].redirect_uri, ["https://reports.example.com/callback", "https://reports.example.com/cb?client_secret=[REDACTED]&state=abc"]);
  const ownedApps = JSON.parse(files.get(join("core_data", "owned_apps.json")));
  assert.deepEqual(ownedApps.items[0].parameters, [
    { name: "api_token", kind: "text", required: true, secure: true, default_value: null, value: "[REDACTED]" },
    { name: "endpoint", kind: "text", required: false, secure: true, default: "[REDACTED]" },
    { name: "region", kind: "text", required: false, secure: false, default: "us-east-1" },
  ], "{name, value} pairs with credential names and secure parameters lose their values while names, kinds, and non-secure defaults stay");
  const installations = JSON.parse(files.get(join("core_data", "app_installations.json")));
  assert.equal(installations.items[0].settings.api_key, "[REDACTED]");
  assert.equal(installations.items[0].settings.notify_url, "https://hooks.slack.com/services/[REDACTED]", "token-in-path webhook URLs keep only the service prefix");
  assert.equal(installations.items[0].settings.connector_config, '{"token":"[REDACTED]","host":"crm.example.com"}', "credential fields inside JSON encoded as a string are replaced");
  const integrations = JSON.parse(files.get(join("analysis", "integrations.json")));
  const exfil = integrations.findings.find((item) => item.id === "ZD-25");
  assert.equal(exfil.status, "warn", exfil.summary);
  assert.equal(exfil.evidence.external_notification_actions[0].destination, "https://legacy.example.com/hook?token=[REDACTED]&room=ops", "ZD-25 destination evidence carries the redacted target URL");
  assert.match(exfil.summary, /legacy\.example\.com/);
  assert.deepEqual(installations.items[1].settings, {
    name: "CRM sync",
    title: "CRM sync",
    apiKey: "[REDACTED]",
    clientId: "crm-client-0042",
    clientSecret: "[REDACTED]",
    refreshToken: "[REDACTED]",
    accessToken: "[REDACTED]",
    tokenExpiresAt: "2027-01-01T00:00:00Z",
    Authorization: "[REDACTED]",
    "X-Api-Key": "[REDACTED]",
    username: "crm-sync@example.com",
    scopes: "read write",
  }, "camelCase and header-valued settings are redacted while client ids, expiry, usernames, and scopes stay");
  for (const headerName of FAKE_ZENDESK_HEADER_NAMES) {
    assert.ok(files.get(join("core_data", "webhooks.json")).includes(`"${headerName}"`), `${headerName} header name survives in webhooks.json`);
  }

  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  assert.equal(findings.find((item) => item.id === "ZD-14").status, "pass");
  assert.equal(findings.find((item) => item.id === "ZD-24").status, "pass", "webhooks keep their authentication objects after redaction");
  assert.match(files.get("QUICK_REFERENCE.md"), /replaced with \[REDACTED\]/);
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
  const forbiddenFile = JSON.parse(readFileSync(join(result.outputDir, "core_data/oauth_clients.json"), "utf8"));
  assert.equal(forbiddenFile.collected, false, "a forbidden snapshot is written as a not-collected marker, never as data or an empty list");
  assert.equal(forbiddenFile.status, 403);
  assert.equal(forbiddenFile.dataset_status, "forbidden");
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

// ---------------------------------------------------------------------------
// Rule 9: credentials carried inside string values, credential pairs, and error strings
// ---------------------------------------------------------------------------

test("redactCredentialProperties scrubs URL query credentials, userinfo, token-in-path webhooks, credential pairs, secure parameters, numeric secrets, and JSON encoded as a string", () => {
  assert.equal(redactCredentialValueText("https://h.example.com/p?token=abc123&x=1#frag"), "https://h.example.com/p?token=[REDACTED]&x=1#frag");
  assert.equal(redactCredentialValueText("https://h.example.com/p?x=1&api_key=abc&sig=zzz"), "https://h.example.com/p?x=1&api_key=[REDACTED]&sig=[REDACTED]");
  assert.equal(redactCredentialValueText("https://svc:pw-123@h.example.com/x"), "https://[REDACTED]@h.example.com/x");
  assert.equal(redactCredentialValueText("https://hooks.slack.com/services/T1/B1/xyz"), "https://hooks.slack.com/services/[REDACTED]");
  assert.equal(redactCredentialValueText("https://discord.com/api/webhooks/123/abc"), "https://discord.com/api/webhooks/[REDACTED]");
  assert.equal(redactCredentialValueText("https://contoso.webhook.office.com/webhookb2/aaa@bbb/IncomingWebhook/ccc/ddd"), "https://contoso.webhook.office.com/webhookb2/[REDACTED]");
  assert.equal(redactCredentialValueText('{"password":"pw","user":"u","apiKey": "k"}'), '{"password":"[REDACTED]","user":"u","apiKey": "[REDACTED]"}');
  assert.equal(redactCredentialValueText("https://h.example.com/p?state=abc&client_id=1"), "https://h.example.com/p?state=abc&client_id=1", "non-credential query parameters are kept");
  assert.equal(redactCredentialValueText("plain text that mentions a token"), "plain text that mentions a token");

  assert.deepEqual(
    redactCredentialProperties({ id: 7, target_url: "https://legacy.example.com/hook?token=abc&room=ops", email: "ops@example.com", url: "https://acme.zendesk.com/api/v2/targets/7.json" }),
    { id: 7, target_url: "https://legacy.example.com/hook?token=[REDACTED]&room=ops", email: "ops@example.com", url: "https://acme.zendesk.com/api/v2/targets/7.json" },
  );
  assert.deepEqual(
    redactCredentialProperties({ redirect_uri: ["https://a.example.com/cb", "https://a.example.com/cb?client_secret=s&state=x"], endpoint: "https://u:p@b.example.com/x" }),
    { redirect_uri: ["https://a.example.com/cb", "https://a.example.com/cb?client_secret=[REDACTED]&state=x"], endpoint: "https://[REDACTED]@b.example.com/x" },
  );

  assert.deepEqual(
    redactCredentialProperties({
      parameters: [
        { name: "api_token", kind: "text", required: true, secure: true, value: "tok", default_value: "d" },
        { name: "endpoint", kind: "text", secure: true, default: "https://x.example.com" },
        { name: "region", kind: "text", secure: false, default: "us-east-1", value: "eu-west-1" },
        { name: "password", value: "pw" },
        { name: "Authorization", value: "Bearer abc" },
      ],
    }),
    {
      parameters: [
        { name: "api_token", kind: "text", required: true, secure: true, value: "[REDACTED]", default_value: "[REDACTED]" },
        { name: "endpoint", kind: "text", secure: true, default: "[REDACTED]" },
        { name: "region", kind: "text", secure: false, default: "us-east-1", value: "eu-west-1" },
        { name: "password", value: "[REDACTED]" },
        { name: "Authorization", value: "[REDACTED]" },
      ],
    },
    "{name, value} pairs with credential names and secure: true objects lose value and default fields while names and kinds stay",
  );

  assert.deepEqual(
    redactCredentialProperties({ secret: 123456, api_key: 4242, id: 42, port: 443, password_length: 12, count: 0 }),
    { secret: "[REDACTED]", api_key: "[REDACTED]", id: 42, port: 443, password_length: 12, count: 0 },
    "numeric credentials are replaced while numeric identifiers and policy fields stay",
  );
  assert.deepEqual(
    redactCredentialProperties({ settings: { connector_config: '{"token":"t","host":"h"}', notify_url: "https://hooks.slack.com/services/T/B/x", title: "CRM" } }),
    { settings: { connector_config: '{"token":"[REDACTED]","host":"h"}', notify_url: "https://hooks.slack.com/services/[REDACTED]", title: "CRM" } },
  );
});

test("redactErrorText and describeErrorBody scrub credential-shaped text regardless of content type and never echo non-JSON bodies", () => {
  const bearer = redactErrorText("upstream said Authorization: Bearer abcdefghijklmnop and Basic dXNlcjpwYXNz then Cookie: _zendesk_session=abc123def456; Path=/");
  assert.equal(bearer, "upstream said Authorization: [REDACTED]", "a header line is withheld to its end and the marker is not re-scrubbed into a different shape");
  assert.equal(redactErrorText("Cookie: _zendesk_session=abc123def456; Path=/ was sent"), "Cookie: [REDACTED]");
  assert.equal(redactErrorText("Bearer abcdefghijklmnop rejected"), "Bearer [REDACTED] rejected");
  assert.equal(redactErrorText("Basic dXNlcjpwYXNzd29yZA== rejected"), "Basic [REDACTED] rejected");
  assert.equal(redactErrorText("_zendesk_session=abc123def456 expired"), "_zendesk_session=[REDACTED] expired");
  assert.equal(redactErrorText("see https://api.example.com/v1/x?token=abcd1234 and api_key=zzzz9999 or apiKey: 'qqqq1111'"), "see https://api.example.com/v1/x?token=[REDACTED] and api_key=[REDACTED] or apiKey=[REDACTED]'");
  assert.equal(redactErrorText("proxy https://svc:pw12345@proxy.example.com refused"), "proxy https://[REDACTED]@proxy.example.com refused");
  assert.equal(redactErrorText("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"), "jwt [REDACTED]");
  assert.equal(redactErrorText("X-Api-Key: 0123456789abcdef"), "X-Api-Key: [REDACTED]");
  assert.equal(redactErrorText("Zendesk request failed for /users/me (403 Forbidden)"), "Zendesk request failed for /users/me (403 Forbidden)", "plain error strings are unchanged");

  const html = new Response("<html><body>Bearer abcdefghijklmnop</body></html>", { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
  assert.equal(describeErrorBody(html, "<html><body>Bearer abcdefghijklmnop</body></html>"), "502 Bad Gateway; non-JSON text/html response body (49 bytes, not echoed)");
  const untyped = new Response("Bearer abcdefghijklmnop", { status: 503, statusText: "Service Unavailable" });
  assert.match(describeErrorBody(untyped, "Bearer abcdefghijklmnop"), /^503 Service Unavailable; non-JSON [a-z/;=\- ]+ response body \(23 bytes, not echoed\)$/);
  const empty = new Response(null, { status: 401, statusText: "Unauthorized" });
  assert.equal(describeErrorBody(empty, ""), "401 Unauthorized");
  const jsonBody = JSON.stringify({ error: "Forbidden", description: "token=abcdefghijklmnop was rejected for Bearer abcdefghijklmnop", extra: "Bearer zzzzzzzzzzzzzzzz" });
  assert.equal(describeErrorBody(jsonResponse({}, { status: 403, statusText: "Forbidden" }), jsonBody), "403 Forbidden; Forbidden; token=[REDACTED] was rejected for Bearer [REDACTED]", "only documented error fields are kept and each is scrubbed");
  const undocumentedBody = JSON.stringify({ detail: "Bearer abcdefghijklmnop" });
  assert.equal(describeErrorBody(jsonResponse({}, { status: 400, statusText: "Bad Request" }), undocumentedBody), `400 Bad Request; JSON response body without documented error fields (${undocumentedBody.length} bytes, not echoed)`);
  const nestedBody = JSON.stringify({ error: { title: "Invalid", message: "Bearer abcdefghijklmnop" }, errors: [{ title: "Bad", detail: "x" }, { detail: "api_key=abcdefgh" }] });
  assert.equal(describeErrorBody(jsonResponse({}, { status: 422, statusText: "Unprocessable Entity" }), nestedBody), "422 Unprocessable Entity; Invalid; Bearer [REDACTED]; Bad; api_key=[REDACTED]");
  const longBody = JSON.stringify({ error: `x`.repeat(300) });
  assert.equal(describeErrorBody(jsonResponse({}, { status: 400, statusText: "Bad Request" }), longBody), `400 Bad Request; ${"x".repeat(200)}`, "documented fields are shortened to 200 characters after scrubbing");
});

// Canary values that must never survive into any tool result, finding, summary, or bundle file.
const CANARY_BEARER = "CANARY-BEARER-9f8e7d6c5b4a3210";
const CANARY_SESSION = "CANARY-SESSION-0a1b2c3d4e5f6789";
const CANARY_API_KEY = "CANARY-APIKEY-1122334455667788";
const CANARY_URL_TOKEN = "CANARY-URLTOKEN-99aa88bb77cc66dd";
const CANARIES = [CANARY_BEARER, CANARY_SESSION, CANARY_API_KEY, CANARY_URL_TOKEN];
const CANARY_URL = `https://api.example.com/v1/x?token=${CANARY_URL_TOKEN}`;

function htmlCanaryResponse() {
  const body = `<html><head><title>502 Bad Gateway</title></head><body><p>Authorization: Bearer ${CANARY_BEARER}</p>`
    + `<p>Set-Cookie: _zendesk_session=${CANARY_SESSION}; Path=/</p><p>X-Api-Key: ${CANARY_API_KEY}</p>`
    + `<p>The upstream at ${CANARY_URL} did not answer in time, retry later.</p></body></html>`;
  return new Response(body, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

function jsonCanaryResponse() {
  return jsonResponse({
    error: "InvalidUpstream",
    description: `Upstream refused Bearer ${CANARY_BEARER} when calling ${CANARY_URL} mid-sentence; _zendesk_session=${CANARY_SESSION} and api_key=${CANARY_API_KEY} were rejected`,
  }, { status: 400, statusText: "Bad Request" });
}

function assertNoCanary(text, label) {
  for (const canary of CANARIES) assert.ok(!text.includes(canary), `${label}: ${canary} leaked`);
}

// Every HTTP surface ZendeskApiClient reads, keyed by path (the three /audit_logs reads are
// distinguished by their query), served from the same fixtures as healthyClient().
function zendeskRouteKey(url) {
  const parsed = new URL(url);
  const path = parsed.pathname.replace(/^\/api\/v2/, "");
  if (path === "/audit_logs") {
    if (parsed.searchParams.get("filter[source_type]") === "apitoken") return "/audit_logs?filter[source_type]=apitoken";
    if (parsed.searchParams.get("sort") === "created_at") return "/audit_logs?sort=created_at";
    return "/audit_logs?sort=-created_at";
  }
  return path;
}

function cursorPage(key, items) {
  return { [key]: items, meta: { has_more: false, after_cursor: null }, links: { next: null } };
}

function offsetPage(key, items) {
  return { [key]: items, next_page: null, previous_page: null, count: items.length };
}

async function healthyHttpRoutes() {
  const base = healthyClient();
  const items = async (method) => (await base[method]()).items;
  return {
    "/users/me": { user: await base.getCurrentUser() },
    "/account/settings": { settings: await base.getAccountSettings() },
    "/security_settings": { security_settings: await base.getSecuritySettings() },
    "/users": cursorPage("users", await items("listTeamMembers")),
    "/custom_roles": offsetPage("custom_roles", await items("listCustomRoles")),
    "/groups": cursorPage("groups", await items("listGroups")),
    "/group_memberships": cursorPage("group_memberships", await items("listGroupMemberships")),
    "/audit_logs?sort=-created_at": cursorPage("audit_logs", await items("listRecentAuditLogs")),
    "/audit_logs?sort=created_at": { audit_logs: [await base.getOldestAuditLog()] },
    "/audit_logs?filter[source_type]=apitoken": cursorPage("audit_logs", await items("listApiTokenAuditLogs")),
    "/deletion_schedules": offsetPage("deletion_schedules", await items("listDeletionSchedules")),
    "/oauth/clients": cursorPage("clients", await items("listOAuthClients")),
    "/oauth/tokens": cursorPage("tokens", await items("listOAuthTokens")),
    "/apps/installations": offsetPage("installations", await items("listAppInstallations")),
    "/apps/owned": offsetPage("apps", await items("listOwnedApps")),
    "/brands": cursorPage("brands", await items("listBrands")),
    "/webhooks": cursorPage("webhooks", await items("listWebhooks")),
    "/targets": offsetPage("targets", await items("listTargets")),
    "/triggers": cursorPage("triggers", await items("listTriggers")),
    "/automations": cursorPage("automations", await items("listAutomations")),
    "/sharing_agreements": offsetPage("sharing_agreements", await items("listSharingAgreements")),
    "/suspended_tickets": cursorPage("suspended_tickets", await items("listSuspendedTickets")),
  };
}

function httpClient(routes, failingSurface, makeResponse) {
  return new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async (url) => {
      const key = zendeskRouteKey(url);
      if (key === failingSurface) return makeResponse();
      const payload = routes[key];
      if (payload === undefined) throw new Error(`unrouted Zendesk request: ${url}`);
      return jsonResponse(payload);
    },
    sleep: async () => {},
  });
}

test("the HTTP-level healthy fixture reproduces the mocked-client verdicts before the canary sweep relies on it", async () => {
  const client = httpClient(await healthyHttpRoutes());
  const access = await checkZendeskAccess(client);
  assert.equal(access.status, "healthy");
  assert.equal(access.surfaces.filter((surface) => surface.status === "readable").length, 20);
  const statuses = statusMap(await runAllAssessments(client));
  assert.equal(statuses.size, 25);
  for (const [id, status] of statuses) {
    assert.equal(status, ["ZD-11", "ZD-19"].includes(id) ? "manual" : "pass", `${id} over HTTP matches the mocked-client verdict`);
  }
});

test("error-body canary sweep: every Zendesk surface failing with an HTML 502 or a JSON error body leaks no credential into any tool result, finding, or bundle file", async () => {
  const routes = await healthyHttpRoutes();
  const surfaces = Object.keys(routes);
  assert.equal(surfaces.length, 22, "every endpoint the client reads is enumerated");
  const shapes = [
    { name: "html-502", make: htmlCanaryResponse, marker: /502 Bad Gateway; non-JSON text\/html response body \(\d+ bytes, not echoed\)/ },
    { name: "json-400", make: jsonCanaryResponse, marker: /400 Bad Request; InvalidUpstream; Upstream refused Bearer \[REDACTED\] when calling https:\/\/api\.example\.com\/v1\/x\?token=\[REDACTED\] mid-sentence; _zendesk_session=\[REDACTED\] and api_key=\[REDACTED\] were rejected/ },
  ];
  for (const shape of shapes) {
    for (const surface of surfaces) {
      const label = `${shape.name} on ${surface}`;
      const client = httpClient(routes, surface, shape.make);

      const access = await checkZendeskAccess(client);
      assertNoCanary(JSON.stringify(access), `${label} access check`);
      const failedProbes = access.surfaces.filter((entry) => entry.status !== "readable");
      // The access check probes the recent audit log read only; the oldest-record and
      // token-event reads are exercised by the assessments below.
      if (!surface.startsWith("/audit_logs?") || surface === "/audit_logs?sort=-created_at") {
        assert.equal(failedProbes.length, 1, `${label}: exactly the failing surface must probe as unreadable`);
      }
      for (const probe of failedProbes) {
        assert.equal(probe.status, "error", `${label}: ${probe.name} status`);
        assert.match(probe.error, shape.marker, `${label}: access error must carry the note: ${probe.error}`);
      }

      const results = await runAllAssessments(client);
      assertNoCanary(JSON.stringify(results), `${label} assessments`);
      const errors = results.flatMap((result) => result.errors);
      assert.ok(errors.length > 0, `${label}: the failing surface must be recorded as an error`);
      for (const error of errors) {
        assert.match(error, shape.marker, `${label}: every error must carry the note: ${error}`);
        assert.doesNotMatch(error, /<html|Set-Cookie|X-Api-Key:|did not answer/i, `${label}: body text echoed: ${error}`);
      }
      for (const item of results.flatMap((result) => result.findings)) {
        if (/could not be read|502 Bad Gateway|400 Bad Request/.test(item.summary)) {
          assert.notEqual(item.status, "pass", `${label}: ${item.id} passed while naming the failed read`);
        }
      }

      const bundle = await exportZendeskAuditBundle(client, sampleConfig(), createTempBase("grclanker-zendesk-canary-"), { now: () => NOW });
      const files = readBundleFiles(bundle.outputDir);
      const zipEntries = readZipEntries(bundle.zipPath);
      assert.ok(files.size >= 15 && zipEntries.size === files.size, `${label}: bundle and zip were written`);
      assertSecretsAbsent(assert, files, CANARIES, `${label} bundle`);
      assertSecretsAbsent(assert, zipEntries, CANARIES, `${label} zip`);
      const errorLog = files.get("_errors.log");
      assert.ok(errorLog !== undefined, `${label}: _errors.log must exist`);
      assert.match(errorLog, shape.marker, `${label}: _errors.log must carry the note`);
      assert.match(files.get(join("compliance", "executive_summary.md")), /## Partial Collection Warnings/, `${label}: the executive summary names the partial collection`);
    }
  }
});

test("ZendeskApiError, transport errors, and the tool catch blocks scrub messages built at the throw site", async () => {
  const constructed = new ZendeskApiError(`Zendesk request failed for /x (500; Bearer ${CANARY_BEARER} at ${CANARY_URL}; Cookie: _zendesk_session=${CANARY_SESSION})`, 500);
  assertNoCanary(constructed.message, "constructor");
  assert.equal(constructed.message, "Zendesk request failed for /x (500; Bearer [REDACTED] at https://api.example.com/v1/x?token=[REDACTED]; Cookie: [REDACTED]", "the Cookie header line is withheld to the end of the line");
  assert.equal(constructed.status, 500);

  const transport = new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async () => { throw new Error(`connect ECONNREFUSED via https://svc:${CANARY_SESSION}@proxy.example.com sending Authorization: Bearer ${CANARY_BEARER}`); },
    sleep: async () => {},
  });
  await assert.rejects(transport.getCurrentUser(), (error) => {
    assertNoCanary(error.message, "transport error");
    assert.match(error.message, /https:\/\/\[REDACTED\]@proxy\.example\.com sending Authorization: \[REDACTED\]/);
    return true;
  });
  const transportResult = await assessZendeskAuthentication(transport, { now: () => NOW });
  assertNoCanary(JSON.stringify(transportResult), "transport error in assessment");
  assert.ok(transportResult.errors.some((entry) => entry.startsWith("current_user: ") && entry.includes("[REDACTED]@proxy.example.com")));

  const tools = new Map();
  registerZendeskTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  assert.equal(tools.size, 6);
  for (const name of ["zendesk_check_access", "zendesk_assess_access_control", "zendesk_export_audit_bundle"]) {
    const tool = tools.get(name);
    const args = tool.prepareArguments({ subdomain: `acme token=${CANARY_URL_TOKEN} Bearer ${CANARY_BEARER}`, oauth_token: "oauth-secret" });
    const result = await tool.execute("call-1", args);
    const text = JSON.stringify(result);
    assertNoCanary(text, `${name} tool error`);
    assert.match(text, /Invalid Zendesk subdomain: acme token=\[REDACTED\] Bearer \[REDACTED\]/, `${name} routes its catch block through the redacting sink`);
  }
});

// ---------------------------------------------------------------------------
// Rule 10: pagination exits that must report truncation
// ---------------------------------------------------------------------------

test("listCursor reports truncation on an empty or repeated page while has_more is true, on a stuck links.next, and stays complete on has_more=false", async () => {
  const usersUrl = (after) => `https://acme.zendesk.com/api/v2/users?page%5Bsize%5D=100&include_boundary_indicators=true${after ? `&page%5Bafter%5D=${after}` : ""}&role%5B%5D=agent&role%5B%5D=admin`;
  const page = (users, hasMore, next) => jsonResponse({ users, meta: { has_more: hasMore, after_cursor: next ?? null }, links: { next: next ? usersUrl(next) : null } });
  const scripted = (responses) => {
    let index = 0;
    return new ZendeskApiClient(sampleConfig(), { fetchImpl: async (url) => responses[Math.min(index++, responses.length - 1)](url), sleep: async () => {} });
  };

  const emptyWithMore = await scripted([() => page([{ id: 1 }], true, "c2"), () => page([], true, "c3")]).listTeamMembers();
  assert.equal(emptyWithMore.items.length, 1);
  assert.equal(emptyWithMore.truncated, true, "an empty page while has_more=true must be recorded as truncated");
  assert.equal(emptyWithMore.pages, 2);

  const repeated = await scripted([() => page([{ id: 1 }, { id: 2 }], true, "c2"), () => page([{ id: 1 }, { id: 2 }], true, "c3")]).listTeamMembers();
  assert.equal(repeated.items.length, 2);
  assert.equal(repeated.truncated, true, "a page that adds nothing while has_more=true is a stuck cursor");

  const repeatedNoMeta = await scripted([
    () => jsonResponse({ users: [{ id: 1 }], meta: { after_cursor: "c2" }, links: { next: usersUrl("c2") } }),
    () => jsonResponse({ users: [{ id: 1 }], meta: { after_cursor: "c3" }, links: { next: usersUrl("c3") } }),
  ]).listTeamMembers();
  assert.equal(repeatedNoMeta.truncated, true, "a repeated page with a continuation and no has_more flag is still partial");

  const stuck = await scripted([(url) => jsonResponse({ users: [{ id: 1 }], meta: { has_more: true, after_cursor: "same" }, links: { next: url } })]).listTeamMembers();
  assert.equal(stuck.items.length, 1);
  assert.equal(stuck.pages, 1);
  assert.equal(stuck.truncated, true, "a links.next equal to the requested URL is a cursor that stopped advancing");

  const complete = await scripted([() => page([{ id: 1 }], true, "c2"), () => page([], false)]).listTeamMembers();
  assert.equal(complete.items.length, 1);
  assert.equal(complete.truncated, false, "an empty last page with has_more=false is a completed read");

  const completeRepeat = await scripted([() => page([{ id: 1 }], true, "c2"), () => page([{ id: 1 }], false)]).listTeamMembers();
  assert.equal(completeRepeat.truncated, false, "a repeated page with has_more=false is a completed read");

  const emptyNoMeta = await scripted([() => jsonResponse({ users: [], links: { next: null } })]).listTeamMembers();
  assert.equal(emptyNoMeta.items.length, 0);
  assert.equal(emptyNoMeta.truncated, false, "an empty inventory without a continuation is complete");
});

test("listOffset reports truncation on an empty or replayed page while next_page is a URL, on a stuck next_page, and stays complete on next_page=null", async () => {
  const targetsUrl = (pageNumber) => `https://acme.zendesk.com/api/v2/targets?page=${pageNumber}&per_page=100`;
  const page = (targets, nextPage) => jsonResponse({ targets, next_page: nextPage, previous_page: null, count: 999 });
  const scripted = (responses) => {
    let index = 0;
    return new ZendeskApiClient(sampleConfig(), { fetchImpl: async (url) => responses[Math.min(index++, responses.length - 1)](url), sleep: async () => {} });
  };

  const emptyWithNext = await scripted([() => page([{ id: 1 }], targetsUrl(2)), () => page([], targetsUrl(3))]).listTargets();
  assert.equal(emptyWithNext.items.length, 1);
  assert.equal(emptyWithNext.truncated, true, "an empty page while next_page is a URL must be recorded as truncated");

  const replayed = await scripted([() => page([{ id: 1 }, { id: 2 }], targetsUrl(2)), () => page([{ id: 1 }, { id: 2 }], targetsUrl(3))]).listTargets();
  assert.equal(replayed.items.length, 2);
  assert.equal(replayed.truncated, true, "a replayed page while next_page is a URL is an offset the server ignored");

  const stuck = await scripted([(url) => page([{ id: 1 }], url)]).listTargets();
  assert.equal(stuck.pages, 1);
  assert.equal(stuck.truncated, true, "a next_page equal to the requested URL is a stuck offset");

  const complete = await scripted([() => page([{ id: 1 }], targetsUrl(2)), () => page([], null)]).listTargets();
  assert.equal(complete.items.length, 1);
  assert.equal(complete.truncated, false, "an empty last page with next_page=null is a completed read");

  const emptyNull = await scripted([() => page([], null)]).listTargets();
  assert.equal(emptyNull.truncated, false, "an empty inventory with next_page=null is complete");

  const partialNoNext = await scripted([() => jsonResponse({ targets: [{ id: 1 }, { id: 2 }] })]).listTargets();
  assert.equal(partialNoNext.truncated, false, "a short page without next_page is the whole inventory");
});

test("checkZendeskAccess marks capped probe counts as partial samples", async () => {
  const result = await checkZendeskAccess(healthyClient({
    async listTeamMembers() {
      return list([teamMember({ id: 1, role: "admin" })], true);
    },
  }));
  const team = result.surfaces.find((surface) => surface.name === "team_members");
  assert.equal(team.status, "readable");
  assert.equal(team.count, 1);
  assert.equal(team.truncated, true);
  assert.equal(result.surfaces.find((surface) => surface.name === "groups").truncated, false);
  assert.equal(result.surfaces.find((surface) => surface.name === "current_user").truncated, undefined, "single-object probes carry no truncation flag");
  assert.ok(result.notes.some((note) => /Probe counts for team_members are capped samples \(marked \+\)/.test(note)), result.notes.join("\n"));
  const healthy = await checkZendeskAccess(healthyClient());
  assert.ok(!healthy.notes.some((note) => /capped samples/.test(note)));
});

// ---------------------------------------------------------------------------
// Rule 1 corollary and null rendering: secondary inventories that could not be read
// ---------------------------------------------------------------------------

test("ZD-24 demotes when the targets inventory is truncated or unreadable and renders unread counts as null", async () => {
  const truncatedTargets = await assessZendeskIntegrations(healthyClient({
    async listTargets() {
      return list([{ id: 5, title: "Ops hook", active: true, target_url: "https://hooks.example.com/ops", type: "url_target_v2" }], true);
    },
  }), { now: () => NOW });
  const item = findingById(truncatedTargets, "ZD-24");
  assert.equal(item.status, "warn", item.summary);
  assert.equal(item.evidence.inventory_truncated, true);
  assert.match(item.summary, /The target inventory was truncated after 1 items/);
  assert.equal(item.evidence.active_targets, 1);

  const forbiddenTargets = await assessZendeskIntegrations(healthyClient({ listTargets: forbidden("/targets") }), { now: () => NOW });
  const unread = findingById(forbiddenTargets, "ZD-24");
  assert.equal(unread.status, "warn", "readable webhooks alone cannot pass when targets were unreadable");
  assert.match(unread.summary, /targets \(\/targets\) returned 403|targets returned 403/i);
  assert.equal(unread.evidence.targets_status, "forbidden");
  assert.equal(unread.evidence.active_targets, null);
  assert.equal(unread.evidence.insecure_targets, null);
  assert.equal(unread.evidence.active_webhooks, 1);
  assert.equal(forbiddenTargets.summary.targets, null);
  assert.equal(forbiddenTargets.summary.webhooks, 1);

  const forbiddenWebhooks = await assessZendeskIntegrations(healthyClient({
    listWebhooks: forbidden("/webhooks"),
    async listTargets() {
      return list([{ id: 5, title: "Legacy", active: true, target_url: "http://legacy.example.com/hook", type: "url_target_v2" }]);
    },
  }), { now: () => NOW });
  const failed = findingById(forbiddenWebhooks, "ZD-24");
  assert.equal(failed.status, "fail");
  assert.match(failed.summary, /1 active targets and an unread webhook inventory deliver to non-https endpoints/);
  assert.equal(failed.evidence.active_webhooks, null);
  assert.equal(failed.evidence.webhooks_without_authentication, null);
});

test("ZD-14 requires a readable token inventory before zero clients can pass and renders unread token counts as null", async () => {
  const tokensForbidden = await assessZendeskAccessControl(healthyClient({
    async listOAuthClients() {
      return list([]);
    },
    listOAuthTokens: forbidden("/oauth/tokens"),
  }), { now: () => NOW });
  const item = findingById(tokensForbidden, "ZD-14");
  assert.equal(item.status, "warn", item.summary);
  assert.match(item.summary, /returned zero clients, but the token inventory could not be read/);
  assert.match(item.summary, /OAuth tokens \(\/oauth\/tokens\?all=true, admin only\) returned 403/);
  assert.equal(item.evidence.oauth_clients, 0);
  assert.equal(item.evidence.oauth_tokens_status, "forbidden");
  assert.equal(item.evidence.oauth_tokens, null);
  assert.equal(item.evidence.tokens_with_write_or_impersonate, null);
  assert.equal(item.evidence.tokens_without_expiry, null);
  assert.equal(item.evidence.tokens_unused_over_stale_days, null);
  assert.equal(item.evidence.tokens_without_used_at, null);
  assert.equal(tokensForbidden.summary.oauth_tokens, null);
  assert.equal(tokensForbidden.summary.oauth_clients, 0);

  const tokensTruncated = await assessZendeskAccessControl(healthyClient({
    async listOAuthClients() {
      return list([]);
    },
    async listOAuthTokens() {
      return list([], true);
    },
  }), { now: () => NOW });
  assert.equal(findingById(tokensTruncated, "ZD-14").status, "warn");
  assert.match(findingById(tokensTruncated, "ZD-14").summary, /an inventory was truncated before completion/);

  const clientsWithTokensForbidden = await assessZendeskAccessControl(healthyClient({ listOAuthTokens: forbidden("/oauth/tokens") }), { now: () => NOW });
  const clients = findingById(clientsWithTokensForbidden, "ZD-14");
  assert.equal(clients.status, "warn");
  assert.match(clients.summary, /Token hygiene could not be reviewed/);
  assert.equal(clients.evidence.oauth_tokens, null);
});

test("ZD-13 caps the api_token_access=false pass when the token audit log is unreadable and renders its counts as null", async () => {
  const result = await assessZendeskAccessControl(healthyClient({ listApiTokenAuditLogs: forbidden("/audit_logs?filter[source_type]=apitoken") }), { now: () => NOW });
  const item = findingById(result, "ZD-13");
  assert.equal(item.status, "warn", item.summary);
  assert.match(item.summary, /api_token_access=false/);
  assert.match(item.summary, /Verdict capped at warn because a secondary inventory could not be read: Audit log token events/);
  assert.deepEqual(item.evidence.verdict_capped_by_unreadable, ["Audit log token events (/audit_logs?filter[source_type]=apitoken, Enterprise plan and admin role)"]);
  assert.equal(item.evidence.token_audit_log_status, "forbidden");
  for (const key of ["token_events_read", "token_events_truncated", "tokens_created", "tokens_destroyed", "tokens_outstanding", "tokens_outstanding_over_stale_days", "tokens_outstanding_undated", "outstanding_tokens"]) {
    assert.equal(item.evidence[key], null, `${key} must render as null when the token audit log was unreadable`);
  }

  const readable = await assessZendeskAccessControl(healthyClient(), { now: () => NOW });
  const pass = findingById(readable, "ZD-13");
  assert.equal(pass.status, "pass");
  assert.equal(pass.evidence.token_events_read, 0);
  assert.equal(pass.evidence.token_events_truncated, false);
  assert.deepEqual(pass.evidence.outstanding_tokens, []);
  assert.equal(pass.evidence.verdict_capped_by_unreadable, undefined);
});

test("ZD-12 caps its pass when account settings or custom roles are unreadable and renders unread role counts as null", async () => {
  const rolesForbidden = await assessZendeskDataProtection(healthyClient({ listCustomRoles: forbidden("/custom_roles") }), { now: () => NOW });
  const item = findingById(rolesForbidden, "ZD-12");
  assert.equal(item.status, "warn", item.summary);
  assert.match(item.summary, /2 active deletion schedule\(s\) read to completion/);
  assert.match(item.summary, /Custom roles \(\/custom_roles, Enterprise plan; redaction and deletion schedule permissions\) returned 403/);
  assert.match(item.summary, /Verdict capped at warn because a secondary inventory could not be read/);
  assert.equal(item.evidence.custom_roles_status, "forbidden");
  assert.equal(item.evidence.custom_roles_with_ticket_redaction, null);
  assert.equal(item.evidence.custom_roles_managing_deletion_schedules, null);
  assert.deepEqual(item.evidence.verdict_capped_by_unreadable, ["Custom roles (/custom_roles, Enterprise plan; redaction and deletion schedule permissions)"]);

  const settingsForbidden = await assessZendeskDataProtection(healthyClient({ getAccountSettings: forbidden("/account/settings") }), { now: () => NOW });
  const capped = findingById(settingsForbidden, "ZD-12");
  assert.equal(capped.status, "warn");
  assert.equal(capped.evidence.agent_ticket_deletion, null);
  assert.equal(capped.evidence.account_settings_status, "forbidden");
  assert.deepEqual(capped.evidence.verdict_capped_by_unreadable, ["Account settings (settings.tickets.agent_ticket_deletion)"]);
  assert.equal(settingsForbidden.summary.private_attachments, null);

  const inactive = await assessZendeskDataProtection(healthyClient({
    listCustomRoles: forbidden("/custom_roles"),
    async listDeletionSchedules() {
      return list([deletionSchedule({ id: 1, active: false })]);
    },
  }), { now: () => NOW });
  assert.equal(findingById(inactive, "ZD-12").status, "fail", "a verified gap is not softened by an unreadable secondary");
});

test("ZD-21 caps its pass when account settings are unreadable and names the unverifiable password API flag", async () => {
  const result = await assessZendeskAuthentication(healthyClient({ getAccountSettings: forbidden("/account/settings") }), { now: () => NOW });
  const item = findingById(result, "ZD-21");
  assert.equal(item.status, "warn", item.summary);
  assert.match(item.summary, /enforce_sso=true/);
  assert.match(item.summary, /settings\.api\.api_password_access_end_users could not be verified: Account settings \(\/account\/settings\) returned 403/);
  assert.match(item.summary, /Verdict capped at warn because a secondary inventory could not be read/);
  assert.equal(item.evidence.api_password_access_end_users, null);
  assert.equal(item.evidence.account_settings_status, "forbidden");
  assert.equal(item.evidence.security_settings_status, "ok");

  const zendeskLogin = await assessZendeskAuthentication(healthyClient({
    getAccountSettings: forbidden("/account/settings"),
    async getSecuritySettings() {
      return healthySecuritySettings({ endUser: { enforce_sso: false, remote_login: false, zendesk_login: true, security_policy_name: "recommended" } });
    },
  }), { now: () => NOW });
  assert.equal(findingById(zendeskLogin, "ZD-21").status, "warn");

  const healthy = findingById(await assessZendeskAuthentication(healthyClient(), { now: () => NOW }), "ZD-21");
  assert.equal(healthy.status, "pass");
  assert.equal(healthy.evidence.api_password_access_end_users, false);
  assert.equal(healthy.evidence.account_settings_status, "ok");
});

test("ZD-25 records unresolved destinations when the target or webhook inventory is unreadable and caps its pass", async () => {
  const targetsForbidden = await assessZendeskIntegrations(healthyClient({
    listTargets: forbidden("/targets"),
    async listTriggers() {
      return list([{ id: 9, title: "Post to legacy", active: true, actions: [{ field: "notification_target", value: ["77", "{{ticket.title}}"] }] }]);
    },
  }), { now: () => NOW });
  const item = findingById(targetsForbidden, "ZD-25");
  assert.equal(item.status, "warn", item.summary);
  assert.equal(item.evidence.unresolved_destinations, 1);
  assert.equal(item.evidence.targets_status, "forbidden");
  assert.equal(item.evidence.external_notification_actions[0].destination, "target 77");
  assert.equal(item.evidence.external_notification_actions[0].unresolved, true);
  assert.match(item.summary, /1 destination\(s\) could not be resolved to a URL, so their scheme was not checked: targets returned 403/);

  const noExternal = await assessZendeskIntegrations(healthyClient({ listWebhooks: forbidden("/webhooks") }), { now: () => NOW });
  const capped = findingById(noExternal, "ZD-25");
  assert.equal(capped.status, "warn", capped.summary);
  assert.match(capped.summary, /none notify external targets, webhooks, or sharing agreements\. Verdict capped at warn because a secondary inventory could not be read: Webhooks \(\/webhooks, used to resolve notification_webhook destinations\) returned 403/);
  assert.deepEqual(capped.evidence.verdict_capped_by_unreadable, ["Webhooks (/webhooks, used to resolve notification_webhook destinations)"]);
  assert.equal(capped.evidence.unresolved_destinations, 0);

  const truncatedTargets = await assessZendeskIntegrations(healthyClient({
    async listTargets() {
      return list([{ id: 5, title: "Seen", active: true, target_url: "https://seen.example.com/hook", type: "url_target_v2" }], true);
    },
    async listTriggers() {
      return list([{ id: 9, title: "Post to unseen", active: true, actions: [{ field: "notification_target", value: ["77", "{{ticket.title}}"] }] }]);
    },
  }), { now: () => NOW });
  const unseen = findingById(truncatedTargets, "ZD-25");
  assert.equal(unseen.evidence.unresolved_destinations, 1);
  assert.match(unseen.summary, /The target or webhook inventory was truncated/);
});

test("ZD-15 caps the zero-installation pass when owned apps are unreadable and renders unread marketplace counts as null", async () => {
  const result = await assessZendeskIntegrations(healthyClient({ listOwnedApps: forbidden("/apps/owned") }), { now: () => NOW });
  const item = findingById(result, "ZD-15");
  assert.equal(item.status, "warn", item.summary);
  assert.match(item.summary, /returned zero installed apps.*Verdict capped at warn because a secondary inventory could not be read: Owned apps \(\/apps\/owned/);
  assert.equal(item.evidence.owned_apps_status, "forbidden");
  assert.equal(item.evidence.marketplace_installations, null);
  assert.equal(item.evidence.enabled_marketplace_installations, null);
  assert.equal(result.summary.owned_apps, null);
  assert.equal(result.summary.app_installations, 0);
  assert.equal(findingById(result, "ZD-16").status, "manual");
});

test("ZD-02 marks named principal lists as partial when the team inventory is truncated", async () => {
  const result = await assessZendeskAuthentication(healthyClient({
    async listTeamMembers() {
      const member = teamMember({ id: 2, role: "agent", two_factor_auth_enabled: false });
      const unknown = teamMember({ id: 3, role: "agent" });
      delete unknown.two_factor_auth_enabled;
      return list([teamMember({ id: 1, role: "admin" }), member, unknown], true);
    },
  }), { now: () => NOW });
  const item = findingById(result, "ZD-02");
  assert.equal(item.status, "warn");
  assert.match(item.summary, /at least 1 team members report two_factor_auth_enabled=false \(not yet enrolled\) and at least 1 did not expose the flag/);
  assert.equal(item.evidence.inventory_truncated, true);
  assert.equal(item.evidence.without_two_factor_partial, true);
  assert.equal(item.evidence.two_factor_flag_missing_partial, true);
  assert.deepEqual(item.evidence.without_two_factor, ["user-2@example.com"]);
  assert.deepEqual(item.evidence.two_factor_flag_missing, ["user-3@example.com"]);

  const complete = findingById(await assessZendeskAuthentication(healthyClient(), { now: () => NOW }), "ZD-02");
  assert.equal(complete.evidence.without_two_factor_partial, false);
  assert.equal(complete.evidence.two_factor_flag_missing_partial, false);
});

test("assessment summaries and evidence render unread inventories as null, never 0 or []", async () => {
  const authentication = await assessZendeskAuthentication(healthyClient({ listTeamMembers: forbidden("/users") }), { now: () => NOW });
  assert.equal(authentication.summary.seen_team_members, null);
  assert.equal((await assessZendeskAuthentication(healthyClient(), { now: () => NOW })).summary.seen_team_members, 4);

  const accessControl = await assessZendeskAccessControl(healthyClient({
    listCustomRoles: forbidden("/custom_roles"),
    listGroups: forbidden("/groups"),
    listOAuthClients: forbidden("/oauth/clients"),
    listOAuthTokens: forbidden("/oauth/tokens"),
  }), { now: () => NOW });
  assert.equal(accessControl.summary.seen_team_members, 4);
  assert.equal(accessControl.summary.admins, 2);
  assert.equal(accessControl.summary.custom_roles, null);
  assert.equal(accessControl.summary.groups, null);
  assert.equal(accessControl.summary.oauth_clients, null);
  assert.equal(accessControl.summary.oauth_tokens, null);
  const leastPrivilege = findingById(accessControl, "ZD-06");
  assert.equal(leastPrivilege.status, "manual");
  assert.equal(leastPrivilege.evidence.custom_roles, null);
  assert.equal(leastPrivilege.evidence.admin_equivalent_custom_roles, null);
  assert.equal(leastPrivilege.evidence.custom_roles_status, "forbidden");

  const teamForbidden = await assessZendeskAccessControl(healthyClient({ listTeamMembers: forbidden("/users") }), { now: () => NOW });
  assert.equal(teamForbidden.summary.seen_team_members, null);
  assert.equal(teamForbidden.summary.admins, null);

  const dataProtection = await assessZendeskDataProtection(healthyClient({
    listRecentAuditLogs: forbidden("/audit_logs"),
    listDeletionSchedules: forbidden("/deletion_schedules"),
    listSuspendedTickets: forbidden("/suspended_tickets"),
  }), { now: () => NOW });
  assert.equal(dataProtection.summary.audit_log_status, "forbidden");
  assert.equal(dataProtection.summary.audit_log_entries_sampled, null);
  assert.equal(dataProtection.summary.deletion_schedules, null);
  assert.equal(dataProtection.summary.suspended_tickets, null);
  assert.equal(dataProtection.summary.private_attachments, true);

  const integrations = await assessZendeskIntegrations(healthyClient({
    listAppInstallations: forbidden("/apps/installations"),
    listOwnedApps: forbidden("/apps/owned"),
    listBrands: forbidden("/brands"),
    listWebhooks: forbidden("/webhooks"),
    listTargets: forbidden("/targets"),
  }), { now: () => NOW });
  for (const key of ["app_installations", "owned_apps", "brands", "webhooks", "targets"]) {
    assert.equal(integrations.summary[key], null, `${key} must render as null when unread`);
  }

  const healthyIntegrations = await assessZendeskIntegrations(healthyClient(), { now: () => NOW });
  assert.deepEqual(
    [healthyIntegrations.summary.app_installations, healthyIntegrations.summary.owned_apps, healthyIntegrations.summary.brands, healthyIntegrations.summary.webhooks, healthyIntegrations.summary.targets],
    [0, 0, 1, 1, 0],
    "readable empty inventories still render their real counts",
  );
});

// ---------------------------------------------------------------------------
// Collection status, request matching, and denied-list markers (addendum 5)
// ---------------------------------------------------------------------------

// Every paged read the assessments keep, keyed by the route the HTTP fixture serves,
// with the core_data/ file each one is written to.
const LIST_CORE_DATA_FILES = {
  "/users": "team_members",
  "/custom_roles": "custom_roles",
  "/groups": "groups",
  "/group_memberships": "group_memberships",
  "/oauth/clients": "oauth_clients",
  "/oauth/tokens": "oauth_tokens",
  "/audit_logs?filter[source_type]=apitoken": "api_token_audit_logs",
  "/audit_logs?sort=-created_at": "audit_logs_recent",
  "/deletion_schedules": "deletion_schedules",
  "/suspended_tickets": "suspended_tickets",
  "/apps/installations": "app_installations",
  "/apps/owned": "owned_apps",
  "/brands": "brands",
  "/sharing_agreements": "sharing_agreements",
  "/targets": "targets",
  "/webhooks": "webhooks",
  "/triggers": "triggers",
  "/automations": "automations",
};

const PROBE_NAMES_BY_ROUTE = {
  "/users": "team_members",
  "/custom_roles": "custom_roles",
  "/groups": "groups",
  "/group_memberships": "group_memberships",
  "/oauth/clients": "oauth_clients",
  "/oauth/tokens": "oauth_tokens",
  "/audit_logs?sort=-created_at": "audit_logs",
  "/deletion_schedules": "deletion_schedules",
  "/suspended_tickets": "suspended_tickets",
  "/apps/installations": "app_installations",
  "/apps/owned": "owned_apps",
  "/brands": "brands",
  "/sharing_agreements": "sharing_agreements",
  "/targets": "targets",
  "/webhooks": "webhooks",
  "/triggers": "triggers",
  "/automations": "automations",
};

function forbiddenJsonResponse() {
  return jsonResponse(
    { error: "Forbidden", description: "You do not have access to this page. Please contact the account owner of this help desk for further help." },
    { status: 403, statusText: "Forbidden" },
  );
}

function collectionEntry(files, name) {
  for (const [path, text] of files) {
    if (!path.startsWith("analysis") || !path.endsWith(".json") || path.endsWith("findings.json")) continue;
    const entry = JSON.parse(text).summary?.collection?.[name];
    if (entry) return entry;
  }
  return undefined;
}

test("denied-list markers: a denied list writes a not-collected marker in core_data with the observed status and request while a readable-but-empty list stays a list result", async () => {
  const routes = await healthyHttpRoutes();
  const outputRoot = createTempBase("grclanker-zendesk-markers-");

  for (const [route, name] of Object.entries(LIST_CORE_DATA_FILES)) {
    const client = httpClient(routes, route, forbiddenJsonResponse);
    const endpoint = `GET /api/v2${route.split("?")[0]}`;

    const access = await checkZendeskAccess(client);
    const probeName = PROBE_NAMES_BY_ROUTE[route];
    if (probeName) {
      const probe = access.surfaces.find((surface) => surface.name === probeName);
      assert.equal(probe.status, "forbidden", `${route}: the probe reports the refusal`);
      assert.equal(probe.count, null, `${route}: a refused probe counts nothing`);
      assert.equal(probe.truncated, null, `${route}: a refused probe has no paging outcome`);
      assert.equal(probe.httpStatus, 403, `${route}: the probe carries the status the request observed`);
    }

    const exported = await exportZendeskAuditBundle(client, sampleConfig(), outputRoot, { now: () => NOW });
    const files = readBundleFiles(exported.outputDir);
    const marker = JSON.parse(files.get(join("core_data", `${name}.json`)));
    assert.deepEqual(Object.keys(marker).sort(), ["collected", "dataset_status", "endpoint", "error", "status"], `${route}: the denied list is a marker object, not a list result`);
    assert.equal(marker.collected, false);
    assert.equal(marker.status, 403, `${route}: the marker carries the status the request observed`);
    assert.equal(marker.dataset_status, "forbidden");
    assert.equal(marker.endpoint, endpoint, `${route}: the marker names the request that actually failed`);
    assert.match(marker.error, /\(403 Forbidden; Forbidden; You do not have access to this page/, `${route}: the marker carries the scrubbed error`);
    assert.equal(readZipEntries(exported.zipPath).get(`core_data/${name}.json`), files.get(join("core_data", `${name}.json`)), `${route}: the zip carries the same marker`);

    const status = collectionEntry(files, name);
    assert.deepEqual(
      { status: status.status, endpoint: status.endpoint, http_status: status.http_status, seen: status.seen, truncated: status.truncated, pages: status.pages },
      { status: "forbidden", endpoint, http_status: 403, seen: null, truncated: null, pages: null },
      `${route}: seen, truncated, and pages stay null for a read that never ran`,
    );
    assert.match(status.error, /403 Forbidden/);

    // The healthy fixture serves app installations, owned apps, and targets as readable-but-empty lists.
    const controlName = name === "targets" ? "app_installations" : "targets";
    const control = JSON.parse(files.get(join("core_data", `${controlName}.json`)));
    assert.deepEqual(control, { items: [], truncated: false, pages: 1 }, `${route} denied: a readable-but-empty list is still an empty list result`);
    const controlStatus = collectionEntry(files, controlName);
    assert.deepEqual(
      { status: controlStatus.status, http_status: controlStatus.http_status, seen: controlStatus.seen, truncated: controlStatus.truncated, pages: controlStatus.pages, error: controlStatus.error },
      { status: "ok", http_status: null, seen: 0, truncated: false, pages: 1, error: null },
      `${route} denied: the readable-but-empty list reports its real counts`,
    );
  }

  // A denied single-object read is written as a marker too, and a read that was never
  // attempted because its prerequisite failed names the request that actually failed.
  const client = httpClient(routes, "/security_settings", forbiddenJsonResponse);
  const exported = await exportZendeskAuditBundle(client, sampleConfig(), outputRoot, { now: () => NOW });
  const files = readBundleFiles(exported.outputDir);
  const securityMarker = JSON.parse(files.get(join("core_data", "security_settings.json")));
  assert.equal(securityMarker.collected, false);
  assert.equal(securityMarker.status, 403);
  assert.equal(securityMarker.endpoint, "GET /api/v2/security_settings");

  const auditDenied = httpClient(routes, "/audit_logs?sort=-created_at", forbiddenJsonResponse);
  const auditExport = await exportZendeskAuditBundle(auditDenied, sampleConfig(), outputRoot, { now: () => NOW });
  const auditFiles = readBundleFiles(auditExport.outputDir);
  const oldestMarker = JSON.parse(auditFiles.get(join("core_data", "audit_log_oldest.json")));
  assert.equal(oldestMarker.collected, false, "the oldest-record lookup that was never attempted is a marker");
  assert.equal(oldestMarker.endpoint, "GET /api/v2/audit_logs", "it names the recent-log request that actually failed");
  assert.equal(oldestMarker.status, 403);
});

function recordingZendeskFetch(routes, failures, log) {
  return async (url) => {
    const parsed = new URL(url);
    const key = zendeskRouteKey(url);
    const failure = failures[key];
    const response = failure ? failure() : routes[key] === undefined ? undefined : jsonResponse(routes[key]);
    if (!response) throw new Error(`unrouted Zendesk request: ${url}`);
    log.push({ method: "GET", path: parsed.pathname, status: response.status });
    return response;
  };
}

function namedZendeskEndpoints(text) {
  const endpoints = new Set();
  for (const match of text.matchAll(/\/api\/v2\/[A-Za-z0-9_/.-]+/g)) endpoints.add(match[0].replace(/[.,;:]+$/, ""));
  // Finding summaries name the read's path in parentheses without the /api/v2 prefix.
  for (const match of text.matchAll(/\((\/(?!api\/)[a-z_]+(?:\/[a-z_]+)*)/g)) endpoints.add(`/api/v2${match[1]}`);
  return endpoints;
}

function namedZendeskStatusCodes(text) {
  const codes = new Set();
  for (const match of text.matchAll(/\((\d{3}) [A-Z][A-Za-z ]*[;)]/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/"(?:http_)?status": ?(\d{3})\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/returned (\d{3}) \(/g)) codes.add(Number(match[1]));
  return codes;
}

test("request matching: every endpoint path and HTTP status named in any output corresponds to a request the run made and observed", async () => {
  const routes = await healthyHttpRoutes();
  const log = [];
  const failures = {
    "/oauth/clients": forbiddenJsonResponse,
    "/webhooks": htmlCanaryResponse,
    "/deletion_schedules": () => new Response("", { status: 404, statusText: "Not Found" }),
  };
  const client = new ZendeskApiClient(sampleConfig(), { fetchImpl: recordingZendeskFetch(routes, failures, log), sleep: async () => {} });

  const outputs = [JSON.stringify(await checkZendeskAccess(client))];
  for (const result of await runAllAssessments(client)) outputs.push(JSON.stringify(result));
  const exported = await exportZendeskAuditBundle(client, sampleConfig(), createTempBase("grclanker-zendesk-request-log-"), { now: () => NOW });
  outputs.push(...readBundleFiles(exported.outputDir).values());

  const requestedPaths = new Set(log.map((entry) => entry.path));
  const observedStatuses = new Set(log.map((entry) => entry.status));
  assert.ok(observedStatuses.has(403) && observedStatuses.has(502) && observedStatuses.has(404), "the fixture served every failure status under test");

  const text = outputs.join("\n");
  const endpoints = namedZendeskEndpoints(text);
  const statuses = namedZendeskStatusCodes(text);
  assert.ok(endpoints.has("/api/v2/oauth/clients") && endpoints.has("/api/v2/webhooks") && endpoints.has("/api/v2/deletion_schedules"), `the outputs name the failing endpoints: ${[...endpoints].join(", ")}`);
  assert.ok(statuses.has(403) && statuses.has(502) && statuses.has(404), `the outputs name the observed failure statuses: ${[...statuses].join(", ")}`);
  for (const endpoint of endpoints) {
    assert.ok(requestedPaths.has(endpoint), `endpoint ${endpoint} is named in output but the run never requested it`);
  }
  for (const status of statuses) {
    assert.ok(observedStatuses.has(status), `status ${status} is named in output but no request observed it`);
  }
  for (const entry of log) {
    assert.ok(entry.status === 200 || Object.keys(failures).some((key) => entry.path === `/api/v2${key.split("?")[0]}`), `only the three failing surfaces answered with an error: ${entry.path} ${entry.status}`);
  }
});
