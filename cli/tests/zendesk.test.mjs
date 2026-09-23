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
import { createServer } from "node:http";
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
  configuredZendeskSecrets,
  describeErrorBody,
  exportZendeskAuditBundle,
  isCredentialKey,
  isCredentialPropertyName,
  redactConfiguredSecrets,
  redactCredentialProperties,
  redactCredentialValueText,
  redactErrorText,
  redactSecrets,
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

// The configured API token of the fixtures, which only the configured-secret pass
// (guard 2) removes: it is deliberately name-shaped, so bare in prose no carrier or
// token-shape rule touches it and its absence proves that pass ran. Its words appear
// nowhere in the module's own vocabulary, and no 6-character window of it does either
// (source_chain renders "api-token:environment", so "api-token" is out).
const FIXTURE_API_TOKEN = "fixture-teal-harbor-2026";
// The composed Basic credential the client sends for the fixture configuration.
const FIXTURE_BASIC_CREDENTIAL = Buffer.from(`auditor@example.com/token:${FIXTURE_API_TOKEN}`).toString("base64");

// The forms a configured secret can be echoed in: as is, JSON-escaped, URL-encoded, base64, base64url.
function secretForms(value) {
  return [...new Set([value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString("base64"), Buffer.from(value).toString("base64url")])];
}

// The window rule (addendum 8): every leak assertion against a planted credential checks
// the whole value and every window of it from LEAK_WINDOW_MIN to LEAK_WINDOW_MAX characters,
// so a partial echo (the 10-character window JSON.parse quotes, a token cut by a length cap,
// the head of a base64 form split by a marker) cannot pass. The planted values are alphanumeric
// and random-looking, and the fixture self-check below proves that no 6-character window of
// any of them occurs in the fixtures' legitimate text, so every failure is a real leak.
const LEAK_WINDOW_MIN = 6;
const LEAK_WINDOW_MAX = 24;
const leakWindowCache = new Map();

// The whole value plus every window of LEAK_WINDOW_MIN to LEAK_WINDOW_MAX characters, longest
// first so a failure names the largest fragment that survived, and the shortest windows on
// their own: a longer window contains its own first LEAK_WINDOW_MIN characters, so every
// window is absent exactly when the whole value and every shortest window are.
function leakWindows(canary) {
  let entry = leakWindowCache.get(canary);
  if (entry === undefined) {
    const all = [canary];
    for (let size = Math.min(LEAK_WINDOW_MAX, canary.length - 1); size >= LEAK_WINDOW_MIN; size -= 1) {
      for (let index = 0; index + size <= canary.length; index += 1) all.push(canary.slice(index, index + size));
    }
    const shortest = Math.min(LEAK_WINDOW_MIN, canary.length);
    entry = { all: [...new Set(all)], probes: [...new Set(all.filter((window) => window.length === shortest))] };
    leakWindowCache.set(canary, entry);
  }
  return entry;
}

// Neither the canary nor any window of it from 6 to 24 characters may survive in the text.
function assertNoWindow(text, canary, label) {
  const { all, probes } = leakWindows(canary);
  if (!probes.some((probe) => text.includes(probe))) return;
  const leaked = all.find((window) => text.includes(window));
  assert.fail(leaked === canary ? `${label}: ${canary} leaked` : `${label}: window ${leaked} of ${canary} leaked`);
}

// Every bundle file or zip entry against every planted secret: the shared whole-value scan, then every window.
function assertNoSecretWindows(contents, secrets, label) {
  assertSecretsAbsent(assert, contents, secrets, label);
  for (const [name, text] of contents) {
    for (const secret of secrets) assertNoWindow(text, secret, `${label} ${name}`);
  }
}

// The 6-character windows of a planted value (the value itself when shorter), for the fixture self-check.
function sixWindows(value) {
  return leakWindows(value).probes;
}

function sampleConfig(overrides = {}) {
  return {
    subdomain: "acme",
    baseUrl: "https://acme.zendesk.com/api/v2",
    authMode: "api_token",
    email: "auditor@example.com",
    apiToken: FIXTURE_API_TOKEN,
    oauthToken: undefined,
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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

test("round 7(b): environment credentials survive an argument overlay that carries unrelated or undefined keys, and the source chain names the environment", () => {
  const base = createTempBase("grclanker-zendesk-env-overlay-");
  const configPath = join(base, "config.json");
  writeFileSync(configPath, JSON.stringify({ subdomain: "file-sub", email: "file@example.com", api_token: "fileW3eR7tY1uI5oP9aS", oauth_token: "fileZ6xC2vB8nM4kL7jH" }));
  const env = { ZENDESK_CONFIG_FILE: configPath, ZENDESK_SUBDOMAIN: "env-sub", ZENDESK_EMAIL: "env@example.com", ZENDESK_API_TOKEN: "envT8yU3iO6pA1sD4fG9" };
  // The overlay a tool builds from optional arguments: one unrelated argument plus the
  // credential keys present but undefined, as a spread of an unfilled schema produces.
  const overlay = { timeout_seconds: 21, subdomain: undefined, email: undefined, api_token: undefined, oauth_token: undefined, config_file: undefined };
  const config = resolveZendeskConfiguration(overlay, env, base);
  assert.equal(config.authMode, "api_token", "the environment's API token wins over the file's OAuth token");
  assert.equal(config.apiToken, env.ZENDESK_API_TOKEN, "the environment value beats the config file and is not erased by the undefined argument");
  assert.equal(config.email, "env@example.com");
  assert.equal(config.subdomain, "env-sub");
  assert.equal(config.timeoutMs, 21_000, "the unrelated argument still applies");
  for (const source of ["subdomain:environment", "api-token:environment", "email:environment"]) {
    assert.ok(config.sourceChain.includes(source), `${source} in ${config.sourceChain.join(", ")}`);
  }
  assert.ok(!config.sourceChain.some((source) => source.endsWith(":arguments")), config.sourceChain.join(", "));

  const oauthEnv = { ZENDESK_CONFIG_FILE: configPath, ZENDESK_SUBDOMAIN: "env-sub", ZENDESK_OAUTH_TOKEN: "envQ2wE5rT8yU1iO4pA7" };
  const oauth = resolveZendeskConfiguration(overlay, oauthEnv, base);
  assert.equal(oauth.authMode, "oauth");
  assert.equal(oauth.oauthToken, oauthEnv.ZENDESK_OAUTH_TOKEN);
  assert.ok(oauth.sourceChain.includes("oauth-token:environment"), oauth.sourceChain.join(", "));
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

// Config loader canaries: no two share a 6-character window, so any fragment a parser
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
  for (const canary of canaries) assertNoWindow(text, canary, `${label} (${text})`);
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
      assert.equal(redactErrorText(error.message), error.message, `${entry.label}: the loader text survives the scrub`);
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
  const expectedBasic = `Basic ${FIXTURE_BASIC_CREDENTIAL}`;
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
  const fetchImpl = async () => jsonResponse({ error: "Forbidden", description: `token ${FIXTURE_API_TOKEN} was rejected` }, { status: 403, statusText: "Forbidden" });
  const client = new ZendeskApiClient(sampleConfig(), { fetchImpl });
  await assert.rejects(client.getAccountSettings(), (error) => {
    assert.ok(error instanceof ZendeskApiError);
    assert.equal(error.status, 403);
    assert.match(error.message, /403/);
    assertNoWindow(error.message, FIXTURE_API_TOKEN, "keygen-style denial");
    assert.match(error.message, /token \[REDACTED\] was rejected/, "a name-shaped configured secret bare in prose is removed by the configured-secret pass alone");
    return true;
  });

  const failing = new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async () => {
      throw new Error(`connect ECONNREFUSED ${FIXTURE_API_TOKEN}`);
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
  assert.ok(unreadable.errors.some((entry) => entry.startsWith("team_members dataset:")));

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
  assert.match(findingById(truncatedHistory, "ZD-13").summary, /The token event inventory was truncated after 2 items \(.+\), so the verdict is limited to the seen population and item-level detail is withheld/);
  assert.match(findingById(truncatedHistory, "ZD-13").summary, /Older tokens may be missing from the unread remainder of the history\./);
  assert.equal(findingById(truncatedHistory, "ZD-13").evidence.token_events_truncated, true);
  assert.equal(findingById(truncatedHistory, "ZD-13").evidence.tokens_outstanding, null, "a zero count over a truncated inventory is not asserted");
  assert.equal(findingById(truncatedHistory, "ZD-13").evidence.outstanding_tokens, null, "item-level detail is withheld while the inventory is incomplete");

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
  assert.ok(results.every((result) => result.errors.some((entry) => entry.startsWith("current_user dataset:"))));

  // Advisory A4: a role that could not be read is not reported as a non-admin role.
  const brands = results.flatMap((result) => result.findings).find((item) => item.id === "ZD-22");
  assert.equal(brands.status, "warn", brands.summary);
  assert.match(brands.summary, /^\d+ brands were visible to a credential whose role could not be read, which may list only the brands the agent belongs to, so cross-brand consistency cannot be confirmed\./);
  assert.doesNotMatch(brands.summary, /non-admin|role unknown/);
  assert.equal(brands.evidence.current_user_role, null);
  const agentBrands = findingById(await assessZendeskIntegrations(healthyClient({ async getCurrentUser() { return { id: 7, email: "agent@example.com", role: "agent" }; } }), { now: () => NOW }), "ZD-22");
  assert.equal(agentBrands.status, "warn", agentBrands.summary);
  assert.match(agentBrands.summary, /brands were visible to a non-admin credential \(role agent\), which only lists brands the agent belongs to, so cross-brand consistency cannot be confirmed\./);
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
  assertNoWindow(rawSettings, FIXTURE_API_TOKEN, "core_data/account_settings.json");

  const second = await exportZendeskAuditBundle(healthyClient(), config, base, { now: () => NOW });
  assert.notEqual(second.outputDir, first.outputDir);
  assert.ok(second.outputDir.endsWith("acme-zendesk-audit-bundle-2"));
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath) && existsSync(second.zipPath));
  assert.equal(readdirSync(base).filter((name) => name.endsWith(".zip")).length, 2);
  assert.equal(readdirSync(base).filter((name) => !name.endsWith(".zip")).length, 2);
});

// Fake credential values Zendesk list endpoints can return verbatim; none may reach a bundle.
// Random-looking alphanumerics (see the window rule above). The Bearer and Basic schemes
// of the header-valued settings are composed where the fixture uses them, since a scheme
// name is legitimate text the scrubbed output keeps; the Slack path keeps the documented
// T.../B.../... shape because the whole path is the secret.
const FAKE_ZENDESK_SECRETS = {
  fullToken: "Mducb0QASQv3Ugw3wqZ21sZXWBc5ITociTOs5dcY",
  tokenPrefix: "Q7l0gnUa1JE",
  refreshToken: "jgf1W64hNNx9ke1OPzMZVU",
  clientSecret: "MHFLILdUP1k7O2mIk7F4QL",
  webhookBearer: "9MrdWdDal0Ldb8OR42Ralm",
  webhookApiKeyValue: "fG8Y1Kg3zFnbHPqBRx6S1j",
  signingSecret: "s1cZ1rG1ghdksri9b59ZD3",
  targetPassword: "7f654gQ0nPLsqTXNMMyqtN",
  targetToken: "jK83AxM1mN8VeQdSsFhvI6",
  appApiKey: "ecLDZ7wK81IOa6WmUeZu25",
  appApiKeyCamel: "DEV0MWVDG3ENLxn9MHYvM3",
  appClientSecretCamel: "LGt33E2k18gewfyCqTGlRi",
  appRefreshTokenCamel: "UdJ9SQ3o7EilvPZTNQt6f5",
  appAccessTokenCamel: "Rs1O7EhdcCddVrl6dqlc4v",
  appAuthorizationBearer: "lPvjw2zeivXec02ucgj0Ax",
  appXApiKeyHeader: "fEOwyslS3SCop1Dnk99SME",
  webhookCustomHeaderBasic: "eyEWii6APMwZCVD2GUSj51",
  webhookCustomHeaderApiKey: "TMeDd3BKQgw6FrtK3HQ94H",
  webhookCustomHeaderPlain: "iXdO3DeUVgMF7msDNb9G6Y",
  // Credentials carried inside URL and free-text string values rather than under a credential key.
  targetUrlQueryToken: "1Ea9sLRnJ4beGrDd6EAyOa",
  webhookUserinfoPassword: "gKmD93ySVYQ0j8YqAVky65",
  redirectUriClientSecret: "pAO1eEu7rf1wU7JgfwroI0",
  slackWebhookPath: "T0K4CKLY1/B0WAF22EB/6swF2tmycU3qGVob6teeP7",
  ownedAppParameterToken: "NtCeeftEa9id8Zaw3Y3yLk",
  ownedAppSecureDefault: "s0nlpo2iHGUIZxhQQ9rW4P",
  jsonEncodedSettingToken: "mjDAS07t0Z1n9lwnyFLaPh",
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
        { id: "wh1", name: "Pager", status: "active", endpoint: "https://hooks.example.com/zendesk", authentication: { type: "bearer_token", add_position: "header", data: { token: FAKE_ZENDESK_SECRETS.webhookBearer } }, custom_headers: { Authorization: `Basic ${FAKE_ZENDESK_SECRETS.webhookCustomHeaderBasic}`, "X-Tenant": FAKE_ZENDESK_SECRETS.webhookCustomHeaderPlain } },
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
            Authorization: `Bearer ${FAKE_ZENDESK_SECRETS.appAuthorizationBearer}`,
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
    assertNoWindow(text, secret, "assessment result");
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
  assertNoSecretWindows(files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assert.ok(zipEntries.has("core_data/oauth_tokens.json"));
  assertNoSecretWindows(zipEntries, secrets, "zip archive");

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
  assert.match(errorLog, /oauth_clients dataset: .*403/);
  assert.match(errorLog, /audit_logs_recent dataset: .*403/);
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

  // Reviewer E finding B: a pair whose name is a credential in the text rules' vocabulary
  // (a header name ending in auth) loses its value whatever the secure flag says. The pairs
  // sit under a neutral container: a headers map is replaced whole by its own rule.
  assert.deepEqual(
    redactCredentialProperties({
      fields: [
        { name: "x-redlock-auth", value: "rvw1RedlockPairValue", secure: false },
        { name: "X-Auth", value: "rvw1XAuthPairValue", secure: false },
        { name: "auth", value: "rvw1AuthPairValue" },
        { name: "Cookie", value: "session=rvw1CookiePairValue", secure: false },
        { name: "X-Trace", value: "trace-rvw-1", secure: false },
        { name: "Content-Type", value: "application/json", secure: false },
      ],
    }),
    {
      fields: [
        { name: "x-redlock-auth", value: "[REDACTED]", secure: false },
        { name: "X-Auth", value: "[REDACTED]", secure: false },
        { name: "auth", value: "[REDACTED]" },
        { name: "Cookie", value: "[REDACTED]", secure: false },
        { name: "X-Trace", value: "trace-rvw-1", secure: false },
        { name: "Content-Type", value: "application/json", secure: false },
      ],
    },
    "an unflagged pair whose name names a credential loses its value; a benign unflagged pair keeps it",
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
  assert.equal(bearer, "upstream said Authorization: Bearer [REDACTED] and Basic [REDACTED] then Cookie: [REDACTED]", "an Authorization value is its scheme word and the one token after it, the rest of the line gets its own carrier treatment, and the marker is not re-scrubbed into a different shape");
  assert.equal(redactErrorText("Authorization: Digest username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", response=\"6629fae49393a05397450978507c4ef1\""), "Authorization: Digest [REDACTED]", "a parameter list after the scheme goes whole");
  assert.equal(redactCredentialValueText("note: key Authorization: Bearer v8cVjqg71d1bQBCQrqEhOQ2Un3jIPVKl end"), "note: key Authorization: Bearer [REDACTED] end", "prose after the one token of an Authorization value stays");
  assert.equal(redactErrorText("Cookie: _zendesk_session=abc123def456; Path=/ was sent"), "Cookie: [REDACTED]");
  assert.equal(redactErrorText("Bearer abcdefghijklmnop rejected"), "Bearer [REDACTED] rejected");
  assert.equal(redactErrorText("Basic dXNlcjpwYXNzd29yZA== rejected"), "Basic [REDACTED] rejected");
  assert.equal(redactErrorText("_zendesk_session=abc123def456 expired"), "_zendesk_session=[REDACTED] expired");
  assert.equal(redactErrorText("see https://api.example.com/v1/x?token=abcd1234 and api_key=zzzz9999 or apiKey: 'qqqq1111'"), "see https://api.example.com/v1/x?token=[REDACTED] and api_key=[REDACTED] or apiKey: '[REDACTED]'");
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

// ---------------------------------------------------------------------------
// Scrub boundary ruling: a name-shaped value bare in prose stays, a carrier loses its value
// whatever its shape, a configured secret is removed in every form whatever its shape, and
// real token shapes are removed bare.
// ---------------------------------------------------------------------------
const NAME_SHAPED_VALUES = ["prod-us-east-2026", "fw-dc1-01", "sess-canary-COOKIE-31415926535897", "my-bucket-prod-2026-logs", "3f2b1c9e-8a7d-4e6f-9b0a-1c2d3e4f5a6b"];

// Every carrier of the ruling with the value in it, and the exact rendering after the scrub.
function carriersOf(value) {
  return [
    [`Authorization: Bearer ${value}`, /^Authorization: (?:Bearer )?\[REDACTED\]$/],
    [`Proxy-Authorization: Basic ${value}`, /^Proxy-Authorization: (?:Basic )?\[REDACTED\]$/],
    [`Cookie: _zendesk_session=${value}; theme=dark`, /^Cookie: \[REDACTED\]$/],
    [`Set-Cookie: _zendesk_session=${value}; Path=/; HttpOnly`, /^Set-Cookie: \[REDACTED\]$/],
    [`X-Api-Key: ${value}`, /^X-Api-Key: \[REDACTED\]$/],
    [`x-auth-token: ${value}`, /^x-auth-token: \[REDACTED\]$/],
    [`<p>X-Api-Key: ${value}</p><p>next</p>`, /^<p>X-Api-Key: \[REDACTED\]<\/p><p>next<\/p>$/],
    // Quoted header values: the value goes with its quotes, whatever the name of the pair
    // that carries it, through the closing quote or to the end of the line; a value that is
    // one quoted string keeps the quotes around the marker; the quote that closes the text
    // the header line was quoted in, and the JSON string it is escaped into, stay intact.
    [`Cookie: sid="${value}"`, /^Cookie: \[REDACTED\]$/],
    [`Cookie: sid='${value}'; theme=dark`, /^Cookie: \[REDACTED\]$/],
    [`Cookie: theme=dark; sid="${value}"; lang=en`, /^Cookie: \[REDACTED\]$/],
    [`Set-Cookie: _zendesk_session="${value}"; Path=/; HttpOnly`, /^Set-Cookie: \[REDACTED\]$/],
    [`Authorization: Bearer "${value}"`, /^Authorization: Bearer "\[REDACTED\]"$/],
    [`Authorization: "Bearer ${value}" was rejected`, /^Authorization: "Bearer \[REDACTED\]" was rejected$/],
    [`X-Api-Key: "${value}"`, /^X-Api-Key: "\[REDACTED\]"$/],
    [`x-auth-token: '${value}'`, /^x-auth-token: '\[REDACTED\]'$/],
    [`{"detail":"upstream rejected Cookie: sid=\\"${value}\\"; path=/","code":401}`, /^\{"detail":"upstream rejected Cookie: \[REDACTED\]","code":401\}$/],
    [`{"cookie": "sid=${value}", "other": "z"}`, /^\{"cookie": "\[REDACTED\]", "other": "z"\}$/],
    [`rejected header "Cookie: sid=${value}" and "X-Other: 1"`, /^rejected header "Cookie: \[REDACTED\]" and "X-Other: 1"$/],
    [`<p>Cookie: sid="${value}"</p><p>next</p>`, /^<p>Cookie: \[REDACTED\]<\/p><p>next<\/p>$/],
    [`<p>Cookie: sid="${value}</p><p>next="1"</p>`, /^<p>Cookie: \[REDACTED\]<\/p><p>next="1"<\/p>$/],
    [`Cookie: sid="${value}"\nX-Other: keep`, /^Cookie: \[REDACTED\]\nX-Other: keep$/],
    // Compound lines: a cookie value, quoted or not, ends before the "Name:" token of the next
    // header on the line, so the following header keeps its name and gets its own carrier
    // treatment, and a Content-Type after the cookie keeps its name and value.
    [`Cookie: sid=${value}; X-Api-Key: "${value}"`, /^Cookie: \[REDACTED\]; X-Api-Key: "\[REDACTED\]"$/],
    [`Cookie: sid="${value}"; X-Api-Key: "${value}"`, /^Cookie: \[REDACTED\]; X-Api-Key: "\[REDACTED\]"$/],
    [`Cookie: _zendesk_session=${value}; theme=dark; X-Api-Key: "${value}"; Content-Type: "application/json"`, /^Cookie: \[REDACTED\]; X-Api-Key: "\[REDACTED\]"; Content-Type: "application\/json"$/],
    [`Cookie: sid="${value}", X-ApiKeys: "${value}", Content-Type: "application/json"`, /^Cookie: \[REDACTED\], X-ApiKeys: "\[REDACTED\]", Content-Type: "application\/json"$/],
    [`Set-Cookie: _zendesk_session=${value}; Path=/; HttpOnly; X-PAN-KEY: "${value}"`, /^Set-Cookie: \[REDACTED\]; X-PAN-KEY: "\[REDACTED\]"$/],
    [`Cookie: sid=${value}; Content-Type: "application/json"; X-Redlock-Auth: ${value}`, /^Cookie: \[REDACTED\]; Content-Type: "application\/json"; X-Redlock-Auth: \[REDACTED\]$/],
    [`X-Api-Key: "${value}"; Cookie: sid=${value}; Content-Type: text/plain`, /^X-Api-Key: "\[REDACTED\]"; Cookie: \[REDACTED\]; Content-Type: text\/plain$/],
    [`{"description":"Cookie: sid=${value}; X-Api-Key: \\"${value}\\"; Content-Type: \\"application/json\\"","error":"InvalidUpstream"}`, /^\{"description":"Cookie: \[REDACTED\]; X-Api-Key: \\"\[REDACTED\]\\"; Content-Type: \\"application\/json\\"","error":"InvalidUpstream"\}$/],
    [`<p>Cookie: sid="${value}"; X-Api-Key: "${value}"; Content-Type: "text/html"</p><p>next</p>`, /^<p>Cookie: \[REDACTED\]; X-Api-Key: "\[REDACTED\]"; Content-Type: "text\/html"<\/p><p>next<\/p>$/],
    [`Cookie: sid=${value}; x-auth-token: "${value}", Accept: text/html`, /^Cookie: \[REDACTED\]; x-auth-token: "\[REDACTED\]", Accept: text\/html$/],
    // The shared end-at-separator rule, edge by edge: a quoted value ends at its closing
    // quote even with "; Name:" inside; cookie attributes before the next header go with the
    // cookie; an unterminated quoted value ends before the next header; Content-Type and
    // Date after a cookie keep their names and values.
    [`Cookie: "sid=${value}; X-Api-Key: ${value}"`, /^Cookie: "\[REDACTED\]"$/],
    [`Set-Cookie: sid=${value}; Path=/; HttpOnly; X-Api-Key: ${value}`, /^Set-Cookie: \[REDACTED\]; X-Api-Key: \[REDACTED\]$/],
    [`Set-Cookie: sid=${value}; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; X-Api-Key: ${value}`, /^Set-Cookie: \[REDACTED\]; X-Api-Key: \[REDACTED\]$/],
    [`Cookie: "sid=${value}; X-Api-Key: ${value}`, /^Cookie: \[REDACTED\]; X-Api-Key: \[REDACTED\]$/],
    [`Cookie: sid=${value}; Content-Type: application/json; Date: Tue, 22 Sep 2026 18:00:00 GMT`, /^Cookie: \[REDACTED\]; Content-Type: application\/json; Date: Tue, 22 Sep 2026 18:00:00 GMT$/],
    // JSON-escaped carriers at any depth: a header pair, a credential pair, an attribute, and
    // an assignment inside a JSON text stringified into a string value (one and two levels
    // down) lose their values and keep their escaped quotes, so the JSON stays well formed.
    [`{"detail":"{\\"Cookie\\": \\"sid=${value}\\", \\"X-Api-Key\\": \\"${value}\\", \\"Content-Type\\": \\"application/json\\"}"}`, /^\{"detail":"\{\\"Cookie\\": \\"\[REDACTED\]\\", \\"X-Api-Key\\": \\"\[REDACTED\]\\", \\"Content-Type\\": \\"application\/json\\"\}"\}$/],
    [`{"o":"{\\"detail\\":\\"{\\\\\\"Cookie\\\\\\": \\\\\\"sid=${value}\\\\\\", \\\\\\"X-Api-Key\\\\\\": \\\\\\"${value}\\\\\\"}\\"}"}`, /^\{"o":"\{\\"detail\\":\\"\{\\\\\\"Cookie\\\\\\": \\\\\\"\[REDACTED\]\\\\\\", \\\\\\"X-Api-Key\\\\\\": \\\\\\"\[REDACTED\]\\\\\\"\}\\"\}"\}$/],
    [`{"detail":"{\\"Authorization\\": \\"Bearer ${value}\\"}"}`, /^\{"detail":"\{\\"Authorization\\": \\"Bearer \[REDACTED\]\\"\}"\}$/],
    [`{"detail":"{'Cookie': 'sid=${value}'}"}`, /^\{"detail":"\{'Cookie': '\[REDACTED\]'\}"\}$/],
    [`{"o":"{\\"detail\\":\\"Cookie: sid=${value}; path=/\\",\\"code\\":401}"}`, /^\{"o":"\{\\"detail\\":\\"Cookie: \[REDACTED\]\\",\\"code\\":401\}"\}$/],
    [`{"detail":"{\\"password\\": \\"${value}\\", \\"user\\": \\"a\\"}"}`, /^\{"detail":"\{\\"password\\": \\"\[REDACTED\]\\", \\"user\\": \\"a\\"\}"\}$/],
    [`{"o":"{\\"detail\\":\\"{\\\\\\"client_secret\\\\\\": \\\\\\"${value}\\\\\\"}\\"}"}`, /^\{"o":"\{\\"detail\\":\\"\{\\\\\\"client_secret\\\\\\": \\\\\\"\[REDACTED\]\\\\\\"\}\\"\}"\}$/],
    [`{"detail":"<entry name=\\"fw1\\" key=\\"${value}\\"/>"}`, /^\{"detail":"<entry name=\\"fw1\\" key=\\"\[REDACTED\]\\"\/>"\}$/],
    [`{"detail":"password: \\"${value}\\" rejected"}`, /^\{"detail":"password: \\"\[REDACTED\]\\" rejected"\}$/],
    [`{"detail":"password=\\"${value}\\" rejected"}`, /^\{"detail":"password=\\"\[REDACTED\]\\" rejected"\}$/],
    [`session=${value}; Path=/`, /^session=\[REDACTED\]; Path=\/$/],
    [`_zendesk_session=${value} expired`, /^_zendesk_session=\[REDACTED\] expired$/],
    [`JSESSIONID=${value}; Path=/`, /^JSESSIONID=\[REDACTED\]; Path=\/$/],
    [`https://svc:${value}@proxy.example.com/x`, /^https:\/\/\[REDACTED\]@proxy\.example\.com\/x$/],
    [`https://hooks.example.com/zendesk?token=${value}&channel=ops`, /^https:\/\/hooks\.example\.com\/zendesk\?token=\[REDACTED\]&channel=ops$/],
    [`https://x.example.com/cb?state=1&api_key=${value}`, /^https:\/\/x\.example\.com\/cb\?state=1&api_key=\[REDACTED\]$/],
    [`GET /login?user=a&pass=${value}`, /^GET \/login\?user=a&pass=\[REDACTED\]$/],
    [`https://x.example.com/cb#access_token=${value}&state=1`, /^https:\/\/x\.example\.com\/cb#access_token=\[REDACTED\]&state=1$/],
    [`https://hooks.slack.com/services/${value}`, /^https:\/\/hooks\.slack\.com\/services\/\[REDACTED\]$/],
    [`Bearer ${value}`, /^Bearer \[REDACTED\]$/],
    [`Basic ${value}`, /^Basic \[REDACTED\]$/],
    [`Token ${value}`, /^Token \[REDACTED\]$/],
    [`ApiKey ${value}`, /^ApiKey \[REDACTED\]$/],
    [`password=${value}`, /^password=\[REDACTED\]$/],
    [`password: ${value}`, /^password: \[REDACTED\]$/],
    [`passphrase: ${value} and more words`, /^passphrase: \[REDACTED\]$/],
    [`client_secret=${value}&grant_type=x`, /^client_secret=\[REDACTED\]&grant_type=x$/],
    [`{"client_secret":"${value}","name":"svc"}`, /^\{"client_secret":"\[REDACTED\]","name":"svc"\}$/],
    [`{"full_token": "${value}", "id": 7}`, /^\{"full_token": "\[REDACTED\]", "id": 7\}$/],
    [`<target name="t1" token="${value}"/>`, /^<target name="t1" token="\[REDACTED\]"\/>$/],
    [`<field name='pw' password='${value}'/>`, /^<field name='pw' password='\[REDACTED\]'\/>$/],
  ];
}

// Reviewer E gap 9: inside a JSON string that was stringified once, a line break or a tab
// arrives as the two characters \n, \r, \t (or the six of \u000a, \u0009), and the header
// name after it has no word boundary in front of it ("\nX-SecurityCenter" reads as one
// word), so the header rule missed it and the pair rule read "nX-SecurityCenter" as a key
// naming nothing. Every credential header the three integrations send, after every escape,
// bare, as a JSON string member, and followed by more escaped text, loses its value in both
// scrubs; the Content-Type and Date on the next escaped line keep their names and values;
// the pair rule reads the key after the escape the same way; the result is a fixed point.
const GAP9_VALUE = "sess-escn-NLINE-27182818284590";
const GAP9_HEADERS = [
  ["X-SecurityCenter", (value) => `X-SecurityCenter: ${value}`],
  ["X-ApiKeys", (value) => `X-ApiKeys: accessKey=${value}; secretKey=${value}`],
  ["X-Cookie", (value) => `X-Cookie: token=${value}`],
  ["X-PAN-KEY", (value) => `X-PAN-KEY: ${value}`],
  ["x-redlock-auth", (value) => `x-redlock-auth: ${value}`],
  ["Authorization Bearer", (value) => `Authorization: Bearer ${value}`],
  ["Authorization Basic", (value) => `Authorization: Basic ${value}`],
  ["Cookie", (value) => `Cookie: sid=${value}`],
  ["Set-Cookie", (value) => `Set-Cookie: session=${value}; Path=/; HttpOnly`],
  ["quoted X-SecurityCenter", (value) => `X-SecurityCenter: "${value}"`],
  ["quoted Cookie", (value) => `Cookie: sid="${value}"; theme=dark`],
];
const GAP9_ESCAPES = ["\\n", "\\r\\n", "\\r", "\\t", "\\b", "\\f", "\\v", "\\u000a", "\\u0009", "\\\""];
const GAP9_FOLLOWING = "\\nContent-Type: application/json\\r\\nDate: Tue, 22 Sep 2026 18:00:00 GMT";
const GAP9_CONTEXTS = [
  ["bare", (escape, line) => `request failed${escape}${line}`],
  ["JSON member", (escape, line) => `{"detail":"request failed${escape}${line}","code":403}`],
  ["followed by escaped text", (escape, line) => `request failed${escape}${line}${GAP9_FOLLOWING}`],
];
const GAP9_PAIRS = [
  (value) => `\\nkey=${value}&x=1`, (value) => `\\nauth: ${value}`, (value) => `\\nsid=${value}; path=/`, (value) => `\\npin=${value}`,
  (value) => `\\u000atoken=${value}`, (value) => `\\tpassword: ${value}`, (value) => `\\r\\nsecret='${value}'`, (value) => `\\nkey="${value}"`,
  (value) => `\\u0009otp=${value}`, (value) => `\\bapi_key=${value}`,
];
const GAP9_CONTROLS = [
  "request failed\\nContent-Type: application/json\\nDate: Tue, 22 Sep 2026 18:00:00 GMT\\nX-Total-Count: 3",
  '{"detail":"request failed\\nContent-Length: 42\\r\\nAccept: text/html\\tX-Request-Id: 7d2f4e6a"}',
  "\\napi_keys: 3\\nkeys=2\\ncookies: 0",
  "The upstream\\nrequested the token inventory\\nand the cookie count is 3",
];

test("reviewer E gap 9: every credential header and pair key after a JSON string escape loses its value in both scrubs, bare, as a JSON member, and followed by more escaped text, while the headers on the next escaped line keep their names", () => {
  let cases = 0;
  for (const scrub of [redactErrorText, redactCredentialValueText]) {
    for (const [name, line] of GAP9_HEADERS) for (const escape of GAP9_ESCAPES) for (const [context, wrap] of GAP9_CONTEXTS) {
      const text = wrap(escape, line(GAP9_VALUE));
      const out = scrub(text);
      const label = `reviewer E gap 9: ${scrub.name} ${name} after ${JSON.stringify(escape)} ${context}`;
      assertNoWindow(out, GAP9_VALUE, label);
      assert.ok(out.includes("[REDACTED]"), `${label}: no marker in ${out}`);
      if (context === "followed by escaped text") assert.ok(out.endsWith(GAP9_FOLLOWING), `${label}: the following headers lost a name or a value: ${out}`);
      if (context === "JSON member") assert.ok(out.endsWith('","code":403}'), `${label}: the JSON member lost its closing text: ${out}`);
      assert.equal(scrub(out), out, `${label}: not idempotent on ${out}`);
      cases += 1;
    }
    for (const pair of GAP9_PAIRS) for (const [context, wrap] of GAP9_CONTEXTS) {
      const text = wrap("", pair(GAP9_VALUE));
      const out = scrub(text);
      const label = `reviewer E gap 9: ${scrub.name} pair ${JSON.stringify(pair(GAP9_VALUE))} ${context}`;
      assertNoWindow(out, GAP9_VALUE, label);
      assert.ok(out.includes("[REDACTED]"), `${label}: no marker in ${out}`);
      if (context === "followed by escaped text") assert.ok(out.endsWith(GAP9_FOLLOWING), `${label}: the following headers lost a name or a value: ${out}`);
      assert.equal(scrub(out), out, `${label}: not idempotent on ${out}`);
      cases += 1;
    }
    for (const text of GAP9_CONTROLS) assert.equal(scrub(text), text, `reviewer E gap 9: ${scrub.name} changed a control: ${text}`);
  }
  assert.equal(cases, 2 * (GAP9_HEADERS.length * GAP9_ESCAPES.length + GAP9_PAIRS.length) * GAP9_CONTEXTS.length);
});

// Reviewer E gap 10: two RFC 6265 token characters let a later cookie pair's value through.
// An apostrophe in a pair name or value (my'pref=value, sid=O'hunter2) was read as the quote
// closing the text the line was quoted in, so the value ended at "my" and the pair after
// the apostrophe stayed; and "&" or "#" in a credential-named pair whose value sat in
// JSON-escaped quotes (my&sid=\"value\") was taken first by the URL query rule with the
// lone backslash as its value, leaving the quoted value behind an orphan quote. Two rules
// now hold in both scrubs of all three modules: a quote closes a value only at the end of a
// token (before whitespace, a delimiter, a bracket, another quote, an escape, or the end),
// never mid-token, in header values, pair values, quoted attributes, and query values; and
// a bare query value never takes a backslash (the escape after it is kept, so a JSON string
// still parses and the text after it is still read), with a recognised header line read
// before the query rule. The controls, the closing quote and following members of an
// enclosing JSON member, escaped controls, and a single-quoted enclosing text survive.
const GAP10_VALUES = ["hunter2", "Tr0ub4dor3", "correct-horse-battery-staple", "abc123", "x7", "9f8e7d6c5b4a3f2e1d0c", "O'Brien42", "p@ss.w0rd", "sess-apos-QUOTE-14142135623730", "dXNlcjpwYXNzd29yZA==", "AKIAIOSFODNN7EXAMPLE", "s3cr3t_2026-09-22T18.00.00Z"];
const GAP10_ROWS = [
  // rule 1: an apostrophe or a raw quote inside a token is content of the value
  [(v) => `Cookie: theme=dark; my'pref=${v}; Content-Type: "text/html; charset=utf-8"`, () => `Cookie: [REDACTED]; Content-Type: "text/html; charset=utf-8"`],
  [(v) => `Cookie: theme=dark; my'pref="${v}"; Date: "Mon, 22 Sep 2026 12:30:00 GMT"`, () => `Cookie: [REDACTED]; Date: "Mon, 22 Sep 2026 12:30:00 GMT"`],
  [(v) => `Cookie: sid=O'${v}; Content-Type: "text/html; charset=utf-8"`, () => `Cookie: [REDACTED]; Content-Type: "text/html; charset=utf-8"`],
  [(v) => `Cookie: theme=dark; my"pref=${v}`, () => `Cookie: [REDACTED]`],
  [(v) => `Cookie: sid="O'${v}"; theme=dark; X-ApiKeys: accessKey=${v}`, () => `Cookie: [REDACTED]; X-ApiKeys: [REDACTED]`],
  [(v) => `Set-Cookie: my'sid=${v}; Path=/; HttpOnly; Date: Mon, 22 Sep 2026 12:30:00 GMT`, () => `Set-Cookie: [REDACTED]; Date: Mon, 22 Sep 2026 12:30:00 GMT`],
  [(v) => `X-Cookie: token=a; my'pref=${v}`, () => `X-Cookie: [REDACTED]`],
  [(v) => `{"detail":"Cookie: theme=dark; my'pref=${v}","code":401}`, () => `{"detail":"Cookie: [REDACTED]","code":401}`],
  [(v) => `{"detail":"Cookie: sid=O'${v}; Content-Type: text/html","code":401}`, () => `{"detail":"Cookie: [REDACTED]; Content-Type: text/html","code":401}`],
  [(v) => `'Cookie: sid=O'${v}'`, () => `'Cookie: [REDACTED]'`],
  [(v) => `sid=O'${v}; path=/`, () => `sid=[REDACTED]; path=/`],
  [(v) => `password: O'${v}`, () => `password: [REDACTED]`],
  [(v) => `password='O'${v}'`, () => `password='[REDACTED]'`],
  [(v) => `{"x":"token=O'${v}"}`, () => `{"x":"token=[REDACTED]"}`],
  [(v) => `?token=O'${v}&x=1`, () => `?token=[REDACTED]&x=1`],
  // rule 2: a bare query value stops before a backslash and the escape is kept
  [(v) => `{"url": "https://h.example.com/p?token=${v}\\"}`, () => `{"url": "https://h.example.com/p?token=[REDACTED]\\"}`],
  [(v) => `{"log": "GET /x?api_key=${v}\\nstatus 502"}`, () => `{"log": "GET /x?api_key=[REDACTED]\\nstatus 502"}`],
  [(v) => `{"hook":"https://hooks.slack.com/services/T000/B000/${v}\\"}`, () => `{"hook":"https://hooks.slack.com/services/[REDACTED]\\"}`],
  [(v) => `{"message": "Cookie: theme=dark; my&sid=\\"${v}\\""}`, () => `{"message": "Cookie: [REDACTED]"}`],
  [(v) => `{"headers":"Set-Cookie: my#sid=\\"${v}\\"; HttpOnly; Content-Type: \\"text/html\\""}`, () => `{"headers":"Set-Cookie: [REDACTED]; Content-Type: \\"text/html\\""}`],
  [(v) => `{"headers":"Cookie: theme=dark; my&sid=\\"${v}\\"; Content-Type: \\"text/html; charset=utf-8\\"; Date: \\"Mon, 22 Sep 2026 12:30:00 GMT\\""}`, () => `{"headers":"Cookie: [REDACTED]; Content-Type: \\"text/html; charset=utf-8\\"; Date: \\"Mon, 22 Sep 2026 12:30:00 GMT\\""}`],
  // boundaries that held before and must keep holding
  [(v) => `Authorization: Bearer ${v}&token=${v}`, () => `Authorization: Bearer [REDACTED]`],
  [(v) => `Cookie: my&sid=${v}`, () => `Cookie: [REDACTED]`],
  [(v) => `Cookie: theme=dark; my#sid=${v}`, () => `Cookie: [REDACTED]`],
  [(v) => `rejected header "Cookie: sid=${v}" and "X-Other: 1"`, () => `rejected header "Cookie: [REDACTED]" and "X-Other: 1"`],
  [(v) => `{"detail":"Cookie: sid=${v}","code":401}`, () => `{"detail":"Cookie: [REDACTED]","code":401}`],
  [(v) => `'Cookie: sid=${v}'`, () => `'Cookie: [REDACTED]'`],
  [(v) => `Cookie: "sid=${v}; X-ApiKeys: ${v}`, () => `Cookie: [REDACTED]; X-ApiKeys: [REDACTED]`],
  [(v) => `X-ApiKeys: accessKey="${v}";secretKey="${v}"; Content-Type: application/json`, () => `X-ApiKeys: [REDACTED]; Content-Type: application/json`],
  [(v) => `{"error":"X-ApiKeys: accessKey=\\"${v}\\";secretKey=\\"${v}\\"","code":403}`, () => `{"error":"X-ApiKeys: [REDACTED]","code":403}`],
  [(v) => `Cookie: sid=${v}"; theme=dark`, () => `Cookie: [REDACTED]"; theme=dark`],
  [(v) => `{"detail":"Authorization: Basic ${v}=","code":401}`, () => `{"detail":"Authorization: Basic [REDACTED]","code":401}`],
  [(v) => `Cookie: sid=${v}=" and "X-Other: 1"`, () => `Cookie: [REDACTED]" and "X-Other: 1"`],
  [(v) => `sid=${v}'; path=/`, () => `sid=[REDACTED]'; path=/`],
  [(v) => `api_key=${v}"}`, () => `api_key=[REDACTED]"}`],
  [(v) => `?token=${v}'}`, () => `?token=[REDACTED]'}`],
];
const GAP10_CONTROLS = [
  `Content-Type: "text/html; charset=utf-8"; Date: "Mon, 22 Sep 2026 12:30:00 GMT"`,
  `{"detail":"it's a fine day","code":200}`,
  `the cookie count is 3 and the token inventory holds 2`,
  `{"names":["O'Brien","D'Angelo"],"cookies":0}`,
  `password=""`,
];

test("reviewer E gap 10: a quote inside a token is content of a cookie, pair, attribute, or query value in both scrubs, a bare query value stops before a backslash and keeps the escape, and a recognised header line is read before the query rule", () => {
  let cases = 0;
  for (const scrub of [redactErrorText, redactCredentialValueText]) {
    for (const [make, expect] of GAP10_ROWS) for (const value of GAP10_VALUES) {
      const input = make(value);
      const out = scrub(input);
      const label = `reviewer E gap 10: ${scrub.name} ${JSON.stringify(input)}`;
      assert.equal(out, expect(value), label);
      assertNoWindow(out, value, label);
      assert.equal(scrub(out), out, `${label}: not idempotent on ${out}`);
      cases += 1;
    }
    for (const text of GAP10_CONTROLS) assert.equal(scrub(text), text, `reviewer E gap 10: ${scrub.name} changed a control: ${text}`);
  }
  assert.equal(cases, 2 * GAP10_ROWS.length * GAP10_VALUES.length);
});

// Reviewer E finding C: an Authorization or Proxy-Authorization value whose first word is not
// a listed scheme word (Bot, GenieKey, Zoho-oauthtoken, Api-Token, SharedKey, LOW, AWS, Key,
// Element, HMAC) goes whole, to the end of the line or to the next header on a compound
// line, in both scrubs: the unknown word may be a scheme with its credentials after it, so
// nothing after it is trusted. A single-token header whose value opens with a listed scheme
// word (X-Auth-Token: Bearer <v>, X-Api-Key: Token <v>) loses the word and the token after it
// under one marker, so the token is never left standing after the marker while prose after
// the token stays. A listed scheme under Authorization keeps its word and loses the one
// token after it. The values are shapes the long-token rule does not catch (a UUID, a dotted
// token, short values) beside one it does; each row is read bare, as a JSON string member,
// and on an escaped line, and the text around the header survives.
const FINDING_C_VALUES = ["eb243592-faa2-4ba2-a551-1afdf565c889", "MTA1MjQ4NDQ2NzI2.GhYz9q.r0tAt3dT0k3nV4lu3", "a1b2c3d4e5f", "hunter2x", "Kq7Zx2Vw9Lm4Tp8Rq3Wn6Yb1Xc5Vd8Fg"];
const FINDING_C_ROWS = [
  // an unlisted first word, or no word at all: the whole value goes
  [(v) => `Authorization: Bot ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: GenieKey ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: Zoho-oauthtoken ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: Zoho-enczapikey ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: Api-Token ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: Key ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: Element ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: HMAC ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: SharedKey account:${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: LOW ${v}:${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: AWS AKIAIOSFODNN7EXAMPLE:${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Proxy-Authorization: Bot ${v}`, () => "Proxy-Authorization: [REDACTED]"],
  [(v) => `Authorization: GenieKey ${v} was rejected`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: ${v} was rejected`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: 12345 ${v}`, () => "Authorization: [REDACTED]"],
  [(v) => `Authorization: GenieKey ${v}, X-Api-Key: ${v}; Date: Tue, 22 Sep 2026 18:00:00 GMT`, () => "Authorization: [REDACTED], X-Api-Key: [REDACTED]; Date: Tue, 22 Sep 2026 18:00:00 GMT"],
  // a single-token header whose value opens with a listed scheme word: the word and the token go together
  [(v) => `X-Auth-Token: Bearer ${v}`, () => "X-Auth-Token: [REDACTED]"],
  [(v) => `X-Api-Key: Token ${v}`, () => "X-Api-Key: [REDACTED]"],
  [(v) => `X-Auth-Token: Bearer ${v} rejected`, () => "X-Auth-Token: [REDACTED] rejected"],
  [(v) => `X-Api-Key: Token ${v} then retry`, () => "X-Api-Key: [REDACTED] then retry"],
  [(v) => `X-Api-Key: ApiKey ${v}; Content-Type: application/json`, () => "X-Api-Key: [REDACTED]; Content-Type: application/json"],
  // controls: a listed scheme under Authorization keeps its word and loses the one token
  // after it, or its whole parameter list; a bare token under a single-token header goes alone
  [(v) => `Authorization: Bearer ${v} was rejected`, () => "Authorization: Bearer [REDACTED] was rejected"],
  [(v) => `Proxy-Authorization: Basic ${v} was rejected`, () => "Proxy-Authorization: Basic [REDACTED] was rejected"],
  [(v) => `Authorization: SSWS ${v}`, () => "Authorization: SSWS [REDACTED]"],
  [(v) => `Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260922/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=${v}`, () => "Authorization: AWS4-HMAC-SHA256 [REDACTED]"],
  [(v) => `X-Auth-Token: ${v} rejected`, () => "X-Auth-Token: [REDACTED] rejected"],
];
const FINDING_C_CONTEXTS = [
  ["bare", (line) => line],
  ["JSON member", (line) => `{"detail":"${line}","code":401}`],
  ["escaped line", (line) => `request failed\\n${line}\\nContent-Type: application/json`],
];
const FINDING_C_CONTROLS = [
  "Proxy-Authorization: [REDACTED]; Content-Type: application/json",
  "X-Auth-Token: [REDACTED] rejected",
  'Authorization: "Bearer [REDACTED]" was rejected',
  "Basic authentication is required; the Bearer token is missing; Content-Type: application/json, Date: Tue, 22 Sep 2026 18:00:00 GMT",
];

test("reviewer E finding C: an Authorization value with an unlisted first word goes whole, a single-token header that opens with a listed scheme word loses the word and the token together, and a listed scheme under Authorization keeps its word, in both scrubs, bare, as a JSON member, and on an escaped line", () => {
  let cases = 0;
  for (const scrub of [redactErrorText, redactCredentialValueText]) {
    for (const [make, expect] of FINDING_C_ROWS) for (const value of FINDING_C_VALUES) for (const [context, wrap] of FINDING_C_CONTEXTS) {
      const input = wrap(make(value));
      const out = scrub(input);
      const label = `reviewer E finding C: ${scrub.name} ${context} ${JSON.stringify(input)}`;
      assert.equal(out, wrap(expect(value)), label);
      assertNoWindow(out, value, label);
      assert.ok(!out.includes("AKIAIOSFODNN7EXAMPLE"), `${label}: the access key id half of a SigV2 value survived in ${out}`);
      assert.equal(scrub(out), out, `${label}: not idempotent on ${out}`);
      cases += 1;
    }
    for (const text of FINDING_C_CONTROLS) assert.equal(scrub(text), text, `reviewer E finding C: ${scrub.name} changed a control: ${text}`);
  }
  assert.equal(cases, 2 * FINDING_C_ROWS.length * FINDING_C_VALUES.length * FINDING_C_CONTEXTS.length);
});

// Reviewer E finding A: inside a JSON string that was stringified once, a tab, form feed,
// backspace, vertical tab, NUL, or their \u0009-style codes arrive as two or six characters,
// and an unquoted pair value in the = spelling, a single-token header value, the token after
// a scheme word, and a --flag value ran through them, so a second credential pair chained
// after the escape lost its key into the first value and kept its own value. Every such
// value now ends at an escaped control as it does at the raw character (a line break, \t,
// \b, \f, \v, \0, \u0000 to \u001f, \u007f, \x09 and the other \xHH controls), so the
// second pair is read on its own and loses its value; a key: value line still ends at a line
// break only, so the second pair after a tab goes with the first value there (nothing
// survives). The escape of a printable character (\u00e9) is content; a raw control ends a
// value the same way; text with no carrier is untouched; the result is a fixed point.
const FINDING_A_FIRST = "hunter2first";
const FINDING_A_SECOND = "correcthorsesecond";
const FINDING_A_FIRST_CARRIERS = [
  ["api_key=", (v) => `api_key=${v}`],
  ["token=", (v) => `token=${v}`],
  ["password: ", (v) => `password: ${v}`],
  ["Authorization: Bearer ", (v) => `Authorization: Bearer ${v}`],
  ["X-Auth-Token: Bearer ", (v) => `X-Auth-Token: Bearer ${v}`],
  ["Cookie: sid=", (v) => `Cookie: sid=${v}`],
  ["X-Api-Key: ", (v) => `X-Api-Key: ${v}`],
  ['"api_key":"', (v) => `"api_key":"${v}"`],
  ["--password ", (v) => `--password ${v}`],
  ["-Dpassword=", (v) => `-Dpassword=${v}`],
];
const FINDING_A_ESCAPES = ["\\t", "\\n", "\\r\\n", "\\u0009", "\\u000a", "\\f", "\\b", "\\v", "\\0", "\\x09", "\\u001f", "\\u007f"];
const FINDING_A_SECOND_CARRIERS = [
  ["password: ", (v) => `password: ${v}`],
  ["password:", (v) => `password:${v}`],
  ["secret=", (v) => `secret=${v}`],
  ["X-Api-Key: ", (v) => `X-Api-Key: ${v}`],
  ["Authorization: Bearer ", (v) => `Authorization: Bearer ${v}`],
  ["Cookie: sid=", (v) => `Cookie: sid=${v}`],
];
const FINDING_A_CONTEXTS = [
  ["bare", (line) => line],
  ["JSON member", (line) => `{"message":"${line}","code":502}`],
  ["prose before", (line) => `login failed: ${line}`],
];
// Exact renderings: the = spelling, the header token, the scheme credentials, and the flag
// value end at the escape, and the chained pair keeps its key and loses its value.
const FINDING_A_EXACT = [
  [(e) => `api_key=${FINDING_A_FIRST}${e}password: ${FINDING_A_SECOND}`, (e) => `api_key=[REDACTED]${e}password: [REDACTED]`],
  [(e) => `token=${FINDING_A_FIRST}${e}secret=${FINDING_A_SECOND}`, (e) => `token=[REDACTED]${e}secret=[REDACTED]`],
  [(e) => `api_key=${FINDING_A_FIRST}${e}X-Api-Key: ${FINDING_A_SECOND}`, (e) => `api_key=[REDACTED]${e}X-Api-Key: [REDACTED]`],
  [(e) => `Authorization: Bearer ${FINDING_A_FIRST}${e}password: ${FINDING_A_SECOND}`, (e) => `Authorization: Bearer [REDACTED]${e}password: [REDACTED]`],
  [(e) => `X-Api-Key: ${FINDING_A_FIRST}${e}X-Api-Key: ${FINDING_A_SECOND}`, (e) => `X-Api-Key: [REDACTED]${e}X-Api-Key: [REDACTED]`],
  [(e) => `X-Auth-Token: Bearer ${FINDING_A_FIRST}${e}Cookie: sid=${FINDING_A_SECOND}`, (e) => `X-Auth-Token: [REDACTED]${e}Cookie: [REDACTED]`],
  [(e) => `--password ${FINDING_A_FIRST}${e}secret=${FINDING_A_SECOND}`, (e) => `--password [REDACTED]${e}secret=[REDACTED]`],
  [(e) => `{"message":"--password ${FINDING_A_FIRST}${e}password: ${FINDING_A_SECOND}","code":502}`, (e) => `{"message":"--password [REDACTED]${e}password: [REDACTED]","code":502}`],
];
const FINDING_A_CONTROLS = [
  "Content-Type: application/json\\tX-Request-Id: 7d2f4e6a\\u0009Date: Tue, 22 Sep 2026 18:00:00 GMT",
  '{"message":"request failed\\tstatus 502\\fretry later\\bdone","code":502}',
  "api_keys: 3\\tkeys=2\\u0009cookies: 0",
  "path C:\\\\temp\\\\file.txt and C:\\\\Users\\\\bob\\\\.kube\\\\config",
  "api_key=[REDACTED]\\tpassword: [REDACTED]",
];

test("reviewer E finding A: an unquoted pair value, a single-token header value, the token after a scheme word, and a flag value end at every escaped control, so a credential pair chained after the escape loses its own value in both scrubs", () => {
  let cases = 0;
  for (const scrub of [redactErrorText, redactCredentialValueText]) {
    for (const [firstName, first] of FINDING_A_FIRST_CARRIERS) for (const escape of FINDING_A_ESCAPES) for (const [secondName, second] of FINDING_A_SECOND_CARRIERS) for (const [context, wrap] of FINDING_A_CONTEXTS) {
      const input = wrap(`${first(FINDING_A_FIRST)}${escape}${second(FINDING_A_SECOND)}`);
      const out = scrub(input);
      const label = `reviewer E finding A: ${scrub.name} [${firstName}] ${JSON.stringify(escape)} [${secondName}] ${context}: ${JSON.stringify(input)} -> ${JSON.stringify(out)}`;
      assertNoWindow(out, FINDING_A_FIRST, label);
      assertNoWindow(out, FINDING_A_SECOND, label);
      if (context === "JSON member") assert.ok(out.endsWith('","code":502}'), `${label}: the JSON member lost its closing text`);
      if (context === "prose before") assert.ok(out.startsWith("login failed: "), `${label}: the prose before the pair was lost`);
      assert.equal(scrub(out), out, `${label}: not idempotent`);
      cases += 1;
    }
    for (const [make, expect] of FINDING_A_EXACT) for (const escape of FINDING_A_ESCAPES) {
      const input = make(escape);
      assert.equal(scrub(input), expect(escape), `reviewer E finding A: ${scrub.name} ${JSON.stringify(input)}`);
    }
    for (const escape of ["\t", "\n", "\f", "\v", "\u001f"]) {
      assert.equal(scrub(`api_key=${FINDING_A_FIRST}${escape}password: ${FINDING_A_SECOND}`), `api_key=[REDACTED]${escape}password: [REDACTED]`, `reviewer E finding A: ${scrub.name} raw control ${JSON.stringify(escape)}`);
    }
    assert.equal(scrub(`api_key=${FINDING_A_FIRST}\\u00e9tail rejected`), "api_key=[REDACTED] rejected", `reviewer E finding A: ${scrub.name} keeps the escape of a printable character inside the value`);
    assert.equal(scrub(`password: ${FINDING_A_FIRST}\\tpassword: ${FINDING_A_SECOND}`), "password: [REDACTED]", `reviewer E finding A: ${scrub.name} a key: value line ends at a line break only`);
    for (const text of FINDING_A_CONTROLS) assert.equal(scrub(text), text, `reviewer E finding A: ${scrub.name} changed a control: ${text}`);
  }
  assert.equal(cases, 2 * FINDING_A_FIRST_CARRIERS.length * FINDING_A_ESCAPES.length * FINDING_A_SECOND_CARRIERS.length * FINDING_A_CONTEXTS.length);
});

// Reviewer E finding D (ruling R5): a colon-terminated credential key that ends a path
// segment is a label whose value is at most one token. A singular label (password, token,
// api_key, secret) takes that token whatever its shape, a random token or a plain word,
// and whatever follows it, so "/etc/app/password: <value> was rejected" renders
// "/etc/app/password: [REDACTED] was rejected"; a plural label (api-tokens, tokens, apikeys,
// passwords, credentials) names a collection, so prose after the token means there was no
// value ("/api/v1/api-tokens: request failed with 403" stays) while a lone token after it is
// one; a count under a plural label stays; an escaped slash before the key is not a path.
const FINDING_D_VALUES = ["hunter2first", "hunter2", "3f9c2b1e-7a4d-4c58-9b0e-2d6f8a1c5e73", "Kq7Zx2Vw9Lm4Tp8RfS1uY3cB6dN0hJ5g", "mfa.Xk9pQ2.rT7vN4wL8s"];
const FINDING_D_SINGULAR_LABELS = ["/etc/app/password: ", "secrets/db/password: ", "vault read secret/app/token: ", "/run/secrets/api_key: ", "GET /api/v2/oauth/token: ", "kv/data/app/secret: ", "# /etc/app/password: ", "https://vault.example.com:8200/v1/secret/app/key: "];
const FINDING_D_PLURAL_LABELS = ["/api/v1/api-tokens: ", "GET /api/v2/oauth/tokens: ", "/api/v1/apikeys: ", "/etc/app/passwords: ", "/v1/credentials: ", "/api/v1/keys: "];
const FINDING_D_TAILS = [" was rejected", " is expired", " has no policy", ""];
const FINDING_D_PROSE = ["request failed with 403", "listing returned 200 items", "read refused for this role"];
const FINDING_D_CONTEXTS = [
  ["bare", (line) => line],
  ["JSON member", (line) => `{"detail":"${line}","code":403}`],
  ["escaped line", (line) => `request failed\\n${line}\\nContent-Type: application/json`],
];
const FINDING_D_CONTROLS = [
  "/api/v1/api-tokens: request failed with 403",
  "GET /api/v2/oauth/tokens: request failed",
  "/api/v2/oauth/tokens: 3",
  "/api/v1/keys: listing returned 200 items",
  "/rest/token failed (403): upstream rejected the request",
  "GET /api/v2/users/me.json: request failed with 403",
  "/etc/app/password:",
  "/etc/app/password: [REDACTED] was rejected",
];

test("reviewer E finding D: a singular credential label at the end of a path segment takes the next token whatever its shape and whatever follows, a plural label followed by prose stays and followed by a lone token loses it, in both scrubs, bare, as a JSON member, and on an escaped line", () => {
  let cases = 0;
  for (const scrub of [redactErrorText, redactCredentialValueText]) {
    for (const value of FINDING_D_VALUES) for (const [context, wrap] of FINDING_D_CONTEXTS) {
      for (const label of FINDING_D_SINGULAR_LABELS) for (const tail of FINDING_D_TAILS) {
        const input = wrap(`${label}${value}${tail}`);
        const out = scrub(input);
        const name = `reviewer E finding D: ${scrub.name} ${context} ${JSON.stringify(input)} -> ${JSON.stringify(out)}`;
        assert.equal(out, wrap(`${label}[REDACTED]${tail}`), name);
        assertNoWindow(out, value, name);
        assert.equal(scrub(out), out, `${name}: not idempotent`);
        cases += 1;
      }
      for (const label of FINDING_D_PLURAL_LABELS) {
        const lone = wrap(`${label}${value}`);
        const out = scrub(lone);
        const name = `reviewer E finding D: ${scrub.name} ${context} ${JSON.stringify(lone)} -> ${JSON.stringify(out)}`;
        assert.equal(out, wrap(`${label}[REDACTED]`), `${name}: a lone token after a plural label is its value`);
        assertNoWindow(out, value, name);
        cases += 1;
      }
    }
    for (const [context, wrap] of FINDING_D_CONTEXTS) for (const label of FINDING_D_PLURAL_LABELS) for (const prose of FINDING_D_PROSE) {
      const input = wrap(`${label}${prose}`);
      assert.equal(scrub(input), input, `reviewer E finding D: ${scrub.name} ${context} changed a plural label followed by prose: ${JSON.stringify(input)}`);
      cases += 1;
    }
    assert.equal(scrub("line\\/password: hunter2first was rejected"), "line\\/password: [REDACTED]", `reviewer E finding D: ${scrub.name} an escaped slash before the key is a line break, not a path, so the key: value line goes to its end`);
    for (const text of FINDING_D_CONTROLS) assert.equal(scrub(text), text, `reviewer E finding D: ${scrub.name} changed a control: ${text}`);
  }
  assert.equal(cases, 2 * (FINDING_D_VALUES.length * FINDING_D_CONTEXTS.length * (FINDING_D_SINGULAR_LABELS.length * FINDING_D_TAILS.length + FINDING_D_PLURAL_LABELS.length) + FINDING_D_CONTEXTS.length * FINDING_D_PLURAL_LABELS.length * FINDING_D_PROSE.length));
});

// CodeRabbit item on #76: the user-and-secret prefix of a URL ends where its authority does, at
// the first "/", "?", or "#", so an "@" inside a query or fragment is never read as userinfo.
// Before the fix https://h?e=a@x.com&token=<v> rendered https://[REDACTED]@x.com&token=[REDACTED]
// (the host "h" and the query lost, "x.com&token=" carried on as the host) and a webhook_url
// with that shape reduced to the fake origin https://x.com&v=<v>/[REDACTED].
const USERINFO_LONG_CANARY = "Qm7Vx2Lk9Rt4Pw8Zs3Yh6Nd1Bc5Fg0Jt";
// [input, expected, the value no window of which may appear in the output]
const USERINFO_URL_ROWS = [
  ["https://h?e=a@x.com&token=s3cr3t", "https://h?e=a@x.com&token=[REDACTED]", "s3cr3t"],
  ["https://h#f@x.com", "https://h#f@x.com", null],
  [`https://h?e=a@x.com&token=${USERINFO_LONG_CANARY}`, "https://h?e=a@x.com&token=[REDACTED]", USERINFO_LONG_CANARY],
  ["https://h?token=s3cr3t@x.com", "https://h?token=[REDACTED]", "s3cr3t"],
  ["https://h/p?e=a@x.com#f@y.com", "https://h/p?e=a@x.com#f@y.com", null],
  // Controls: a real user-and-secret prefix still goes, before a path, a query, or a fragment.
  [`https://svc:${USERINFO_LONG_CANARY}@x.com/path?e=a`, "https://[REDACTED]@x.com/path?e=a", USERINFO_LONG_CANARY],
  [`https://svc:${USERINFO_LONG_CANARY}@x.com?e=a`, "https://[REDACTED]@x.com?e=a", USERINFO_LONG_CANARY],
  [`https://svc:${USERINFO_LONG_CANARY}@x.com#frag`, "https://[REDACTED]@x.com#frag", USERINFO_LONG_CANARY],
];
const USERINFO_WEBHOOK_ROWS = [
  ["webhook_url=https://h?e=a@x.com&v=s3cr3t", "webhook_url=https://h/[REDACTED]", "s3cr3t"],
  ['{"webhook_url":"https://h?e=a@x.com&v=s3cr3t"}', '{"webhook_url":"https://h/[REDACTED]"}', "s3cr3t"],
  ["webhook_url: https://h#f@x.com", "webhook_url: https://h/[REDACTED]", null],
];
const escapeSlashes = (text) => text.replaceAll("/", "\\/");
const USERINFO_CONTEXTS = [
  ["bare", (url) => url],
  ["in a sentence", (url) => `redirect to ${url} denied`],
  ["escaped bare", (url) => escapeSlashes(url)],
  ["escaped JSON member", (url) => `{"detail":"redirect to ${escapeSlashes(url)} denied","code":403}`],
];

test("CodeRabbit #76 userinfo: the user-and-secret prefix of a URL ends at the first /, ?, or #, so an @ inside a query or fragment keeps the host, the query is read pair by pair, and a webhook URL reduces to its true origin, in both scrubs, the walker, and an echoed URL in a Zendesk error string", async () => {
  let cases = 0;
  for (const scrub of [redactErrorText, redactCredentialValueText]) {
    for (const [input, expected, canary] of USERINFO_URL_ROWS) for (const [context, wrap] of USERINFO_CONTEXTS) {
      const text = wrap(input);
      const out = scrub(text);
      const name = `userinfo: ${scrub.name} ${context} ${JSON.stringify(text)} -> ${JSON.stringify(out)}`;
      assert.equal(out, wrap(expected), name);
      if (canary) assertNoWindow(out, canary, name);
      assert.equal(scrub(out), out, `${name}: not idempotent`);
      cases += 1;
    }
    for (const [input, expected, canary] of USERINFO_WEBHOOK_ROWS) {
      const out = scrub(input);
      const name = `userinfo: ${scrub.name} ${JSON.stringify(input)} -> ${JSON.stringify(out)}`;
      assert.equal(out, expected, name);
      if (canary) assertNoWindow(out, canary, name);
      assert.equal(scrub(out), out, `${name}: not idempotent`);
      cases += 1;
    }
  }
  assert.equal(cases, 2 * (USERINFO_URL_ROWS.length * USERINFO_CONTEXTS.length + USERINFO_WEBHOOK_ROWS.length));
  // The walker applies the same rules to every string leaf and reads a webhook_url from the raw value.
  for (const [input, expected, canary] of USERINFO_URL_ROWS) {
    const walked = redactCredentialProperties({ url: input, description: `see ${input} for details`, nested: [{ endpoint: input }] });
    assert.deepEqual(walked, { url: expected, description: `see ${expected} for details`, nested: [{ endpoint: expected }] }, `userinfo: walker ${input}`);
    if (canary) assertNoWindow(JSON.stringify(walked), canary, `userinfo: walker ${input}`);
  }
  assert.deepEqual(redactCredentialProperties({ webhook_url: "https://h?e=a@x.com&v=s3cr3t", other: { webhook_url: "https://h#f@x.com" } }), { webhook_url: "https://h/[REDACTED]", other: { webhook_url: "https://h/[REDACTED]" } }, "userinfo: the walker reduces a webhook_url to its true origin");
  // End to end: a 403 body echoing the URL reaches the operator through the client's error path.
  for (const [url, expected, canary] of USERINFO_URL_ROWS) {
    const client = new ZendeskApiClient(sampleConfig(), {
      fetchImpl: async () => jsonResponse({ error: { title: "Forbidden", message: `redirect to ${url} denied` } }, { status: 403, statusText: "Forbidden" }),
      sleep: async () => {},
    });
    const error = await client.listGroups().catch((thrown) => thrown);
    assert.ok(error instanceof ZendeskApiError, `userinfo: ${url} threw ${String(error)}`);
    assert.ok(error.message.includes(`redirect to ${expected} denied`), `userinfo: echoed URL ${url} -> ${error.message}`);
    if (canary) assertNoWindow(error.message, canary, `userinfo: echoed URL ${url}`);
  }
});

// Harness self-check (frozen revision 3, flag carrier cells): a credential name after "--"
// whose spelling opens with an underscore (the `_zendesk_session` cookie name) was not read as a
// flag, so "psql --_zendesk_session <value> -h db" kept the value when no token rule caught its
// shape. The flag name may now open with a letter or an underscore; the value is still the
// one token after it, never another flag, and a flag glued to a word (x--_password v) or a
// non-credential underscore flag (--_theme dark) stays.
const UNDERSCORE_FLAG_NAME_VALUE = "skvclmtirehs";
const UNDERSCORE_FLAG_LONG_VALUE = "Wn4Kd8Tq2Zr7Vb1Xs9Pm3Lc6Yh0Jf5Gt";
const UNDERSCORE_FLAG_ROWS = [
  [(v) => `psql --_zendesk_session ${v} -h db`, `psql --_zendesk_session [REDACTED] -h db`],
  [(v) => `--_zendesk_session ${v}`, `--_zendesk_session [REDACTED]`],
  [(v) => `psql --_password ${v} -h db`, "psql --_password [REDACTED] -h db"],
  [(v) => `run --__token ${v} --verbose`, "run --__token [REDACTED] --verbose"],
  [(v) => `"cmd --_api_key ${v}"`, '"cmd --_api_key [REDACTED]"'],
  [(v) => `{"message":"psql --_zendesk_session ${v} -h db failed","code":502}`, `{"message":"psql --_zendesk_session [REDACTED] -h db failed","code":502}`],
];
const UNDERSCORE_FLAG_CONTROLS = [
  "--_theme dark",
  "psql --_timeout 30 -h db",
  "--_password --other",
  "--_zendesk_session [REDACTED] -h db",
  "count --_items 3",
];

test("harness self-check: a credential-named flag whose name opens with an underscore (--_zendesk_session <value>) loses its one value argument in both scrubs, while a non-credential underscore flag and a flag glued to a word stay", () => {
  let cases = 0;
  for (const scrub of [redactErrorText, redactCredentialValueText]) {
    for (const [make, expected] of UNDERSCORE_FLAG_ROWS) for (const value of [UNDERSCORE_FLAG_NAME_VALUE, UNDERSCORE_FLAG_LONG_VALUE]) {
      const input = make(value);
      const out = scrub(input);
      const label = `underscore flag: ${scrub.name} ${JSON.stringify(input)} -> ${JSON.stringify(out)}`;
      assert.equal(out, expected, label);
      assertNoWindow(out, value, label);
      assert.equal(scrub(out), out, `${label}: not idempotent`);
      cases += 1;
    }
    for (const text of UNDERSCORE_FLAG_CONTROLS) assert.equal(scrub(text), text, `underscore flag: ${scrub.name} changed a control: ${text}`);
    assert.equal(scrub(`x--_password ${UNDERSCORE_FLAG_NAME_VALUE}`), `x--_password ${UNDERSCORE_FLAG_NAME_VALUE}`, `underscore flag: ${scrub.name} a flag glued to a word is not a flag`);
  }
  assert.equal(cases, 2 * UNDERSCORE_FLAG_ROWS.length * 2);
  assert.equal(isCredentialKey("_zendesk_session"), true);
  assert.equal(isCredentialKey("_theme"), false);
});

// Harness self-check (Codex P1 on #81, query carrier cells): a ";" inside a query value is part
// of the value, as URLSearchParams reads it, so "?token=hunter2;restofsecret" is one value and
// loses the whole of it. The query rule used to end a value at ";" and left ";restofsecret"
// standing in relative, absolute, JSON-escaped, and slash-escaped URLs alike, through both
// scrubs, the error constructor, and the walker. The ";" boundary belongs to the Cookie and
// Set-Cookie header lines, which go whole and are read before the query rule.
const SEMICOLON_QUERY_VALUE = "hunter2;restofsecret";
const SEMICOLON_QUERY_LONG_VALUE = "Rk7Vm2Qx9Tz4;Lw8Hn3Bd6Yp1Cf5";
const SEMICOLON_QUERY_ROWS = [
  [(v) => `GET /api/v2/users?token=${v} failed`, "GET /api/v2/users?token=[REDACTED] failed"],
  [(v) => `GET /api/v2/users?page=2&api_token=${v}&sort=asc`, "GET /api/v2/users?page=2&api_token=[REDACTED]&sort=asc"],
  [(v) => `GET /api/v2/users?token=${v}; retrying`, "GET /api/v2/users?token=[REDACTED] retrying"],
  [(v) => `request to https://acme.zendesk.com/api/v2/users?token=${v} failed`, "request to https://acme.zendesk.com/api/v2/users?token=[REDACTED] failed"],
  [(v) => `request to https://acme.zendesk.com/api/v2/users?token=${v}`, "request to https://acme.zendesk.com/api/v2/users?token=[REDACTED]"],
  [(v) => `{"url":"https://acme.zendesk.com/api/v2/users?token=${v}","status":401}`, '{"url":"https://acme.zendesk.com/api/v2/users?token=[REDACTED]","status":401}'],
  [(v) => `{"error":"request to \\"https://acme.zendesk.com/api/v2/users?token=${v}\\" failed"}`, '{"error":"request to \\"https://acme.zendesk.com/api/v2/users?token=[REDACTED]\\" failed"}'],
  [(v) => `{"error":"GET \\"/api/v2/users?token=${v}\\" failed"}`, '{"error":"GET \\"/api/v2/users?token=[REDACTED]\\" failed"}'],
  [(v) => `{"url":"https:\\/\\/acme.zendesk.com\\/api\\/v2\\/users?token=${v}"}`, '{"url":"https:\\/\\/acme.zendesk.com\\/api\\/v2\\/users?token=[REDACTED]"}'],
  [(v) => `request to https:\\/\\/acme.zendesk.com\\/api\\/v2\\/users?token=${v} failed`, "request to https:\\/\\/acme.zendesk.com\\/api\\/v2\\/users?token=[REDACTED] failed"],
  [(v) => `see https://acme.zendesk.com/oauth#access_token=${v}&type=bearer`, "see https://acme.zendesk.com/oauth#access_token=[REDACTED]&type=bearer"],
];
const SEMICOLON_QUERY_CONTROLS = [
  ["Cookie: &sid=a; pref=b", "Cookie: [REDACTED]"],
  ["Set-Cookie: _zendesk_session=abc123; Path=/; HttpOnly", "Set-Cookie: [REDACTED]"],
  ["GET /api/v2/users?sort=asc;include=roles ok", "GET /api/v2/users?sort=asc;include=roles ok"],
  ["GET /api/v2/users?page=2&per_page=100 ok", "GET /api/v2/users?page=2&per_page=100 ok"],
  ["GET /api/v2/users?token=[REDACTED] failed", "GET /api/v2/users?token=[REDACTED] failed"],
];
const SEMICOLON_QUERY_SINKS = [
  ["redactErrorText", redactErrorText],
  ["redactCredentialValueText", redactCredentialValueText],
  ["redactSecrets", (text) => redactSecrets(text, [])],
  ["ZendeskApiError", (text) => new ZendeskApiError(text, 401).message],
  ["redactCredentialProperties", (text) => redactCredentialProperties({ note: text, items: [{ description: text }] }).note],
];

test("harness self-check: a \";\" inside a query value is part of the value, so ?token=hunter2;restofsecret loses the whole value in relative, absolute, JSON-escaped, and slash-escaped URLs through both scrubs, the error constructor, and the walker, while Cookie: &sid=a; pref=b still goes whole", () => {
  let cases = 0;
  for (const [sinkName, sink] of SEMICOLON_QUERY_SINKS) {
    for (const [make, expected] of SEMICOLON_QUERY_ROWS) for (const value of [SEMICOLON_QUERY_VALUE, SEMICOLON_QUERY_LONG_VALUE]) {
      const input = make(value);
      const out = sink(input);
      const label = `semicolon query value: ${sinkName} ${JSON.stringify(input)} -> ${JSON.stringify(out)}`;
      assert.equal(out, expected, label);
      assertNoWindow(out, value, label);
      assert.equal(sink(out), out, `${label}: not idempotent`);
      cases += 1;
    }
    for (const [text, expected] of SEMICOLON_QUERY_CONTROLS) assert.equal(sink(text), expected, `semicolon query value: ${sinkName} control ${JSON.stringify(text)}`);
  }
  assert.equal(cases, SEMICOLON_QUERY_SINKS.length * SEMICOLON_QUERY_ROWS.length * 2);
});

test("scrub boundary: name-shaped values stay bare in prose, leave every carrier whatever their shape, and go as configured secrets in every form", () => {
  for (const value of NAME_SHAPED_VALUES) {
    for (const prose of [`inventory ${value} was not read`, `${value}`, `webhook ${value} read 12 of 40 destinations`, `path /var/lib/${value}/state`]) {
      assert.equal(redactErrorText(prose), prose, `${value} stays bare in error text`);
      assert.equal(redactCredentialValueText(prose), prose, `${value} stays bare in a data value`);
    }
    for (const [text, expected] of carriersOf(value)) {
      for (const scrub of [redactErrorText, redactCredentialValueText]) {
        const out = scrub(text);
        assert.match(out, expected, `${scrub.name}(${JSON.stringify(text)}) -> ${JSON.stringify(out)}`);
        assertNoWindow(out, value, `${scrub.name} ${text}`);
        assert.equal(scrub(out), out, `${scrub.name} is idempotent on ${out}`);
      }
    }
    // A configured secret goes bare and in every encoded form, however name-shaped it is.
    for (const form of secretForms(value)) {
      assert.equal(redactSecrets(`login rejected for ${form} by upstream`, [value]), "login rejected for [REDACTED] by upstream", `configured ${value} as ${form}`);
      assert.equal(redactConfiguredSecrets(`login rejected for ${form} by upstream`, [value]), "login rejected for [REDACTED] by upstream", `guard 2 alone on ${form}`);
    }
  }
  // The composed Basic credential is its own configured secret: no encoding of the token alone matches it.
  const secrets = configuredZendeskSecrets(sampleConfig());
  assert.deepEqual(secrets, [FIXTURE_API_TOKEN, FIXTURE_BASIC_CREDENTIAL]);
  assert.equal(redactConfiguredSecrets(`sent auditor@example.com/token:${FIXTURE_API_TOKEN} upstream`, secrets), "sent auditor@example.com/token:[REDACTED] upstream", "the plain Basic pair is covered by the token itself; the email is not a secret");
  assert.ok(!secretForms(FIXTURE_API_TOKEN).includes(FIXTURE_BASIC_CREDENTIAL), "the fixture proves the point: the Basic form is not a form of the token");
  assert.equal(redactConfiguredSecrets(`sent Authorization Basic ${FIXTURE_BASIC_CREDENTIAL} upstream`, secrets), "sent Authorization Basic [REDACTED] upstream");
  assert.equal(redactConfiguredSecrets(`sent ${FIXTURE_BASIC_CREDENTIAL} upstream`, [FIXTURE_API_TOKEN]), `sent ${FIXTURE_BASIC_CREDENTIAL} upstream`, "the token alone does not cover the Basic form, so the client registers it");
  assert.deepEqual(configuredZendeskSecrets(sampleConfig({ authMode: "oauth", email: undefined, apiToken: undefined, oauthToken: "oauth-fixture-value-2026" })), ["oauth-fixture-value-2026"]);
  assert.equal(redactConfiguredSecrets("a pin 4711 and pin 47110", ["4711"]), "a pin [REDACTED] and pin 47110", "a short secret is removed as a whole token only");
  assert.equal(redactConfiguredSecrets("too short abc", ["abc"]), "too short abc", "below the minimum length nothing is scrubbed");

  // Real token shapes go bare from error text, and stay in data values where they are identifiers.
  for (const [text, expected] of [
    ["bare Kq7Zx2Vw9Lm4Tp8R token", "bare [REDACTED] token"],
    ["digest 0f9e8d7c6b5a4938 shown", "digest [REDACTED] shown"],
    ["hash 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b shown", "hash [REDACTED] shown"],
    ["jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijk expired", "jwt [REDACTED] expired"],
    ["bare dXNlcjpwYXNzd29yZA== padded", "bare [REDACTED] padded"],
    ["akid AKIAIOSFODNN7EXAMPLE shown", "akid [REDACTED] shown"],
    ["-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----", "[REDACTED]"],
    ["-----BEGIN CERTIFICATE-----\nMIIEfake\n-----END CERTIFICATE-----", "[REDACTED]"],
    ["truncated -----BEGIN PRIVATE KEY-----\nMIIEfake", "truncated [REDACTED]"],
  ]) {
    assert.equal(redactErrorText(text), expected);
    assert.equal(redactErrorText(expected), expected, "idempotent");
  }
  // After a scheme the value goes whatever its shape, a plain lowercase word included,
  // unless it is one of the listed prose words; after the nouns "Token", "OAuth", "Splunk",
  // and "Snowflake" a plain lowercase word shorter than a long token run is prose, and
  // "realm=" or another auth parameter name after any scheme is prose.
  for (const [text, expected] of [
    ["Bearer abcdefghijklmnop rejected", "Bearer [REDACTED] rejected"],
    ["Basic canarybasic rejected", "Basic [REDACTED] rejected"],
    ["ApiKey canaryapikey rejected", "ApiKey [REDACTED] rejected"],
    ["Token abcdefghijklmnopq expired", "Token [REDACTED] expired"],
    ["Token hygiene could not be judged; token inventory read; Token count 3", "Token hygiene could not be judged; token inventory read; Token count 3"],
    ["OAuth clients all declare scopes; an OAuth bearer token; OAuth authentication failed; OAuth abcdefghijklmnop rejected", "OAuth clients all declare scopes; an OAuth bearer token; OAuth authentication failed; OAuth [REDACTED] rejected"],
    ["replayed OAuth Kq7Zx2Vw9Lm4Tp8R upstream; replayed Splunk Kq7Zx2Vw9Lm4Tp8R upstream; replayed Snowflake Kq7Zx2Vw9Lm4Tp8R upstream; replayed AWS4-HMAC-SHA256 Kq7Zx2Vw9Lm4Tp8R upstream", "replayed OAuth [REDACTED] upstream; replayed Splunk [REDACTED] upstream; replayed Snowflake [REDACTED] upstream; replayed AWS4-HMAC-SHA256 [REDACTED] upstream"],
    ["Bearer realm=\"api\"; Bearer token is missing; Digest realm=\"api\", qop=\"auth\"; Splunk search head", "Bearer realm=\"api\"; Bearer token is missing; Digest realm=\"api\", qop=\"auth\"; Splunk search head"],
    ["API token basic auth; Bearer tokens expire; Basic credential; Basic authentication is required", "API token basic auth; Bearer tokens expire; Basic credential; Basic authentication is required"],
    // A Titlecase word makes the scheme name an adjective in a title; a digit, a symbol,
    // token casing, or a run longer than a word still marks a credential.
    ["plans: Basic Support Plan, Bearer Token rotation, Token Hygiene, ApiKey Rotation", "plans: Basic Support Plan, Bearer Token rotation, Token Hygiene, ApiKey Rotation"],
    ["Basic Canary2026 rejected; Basic dXNlcjpwYXNz rejected; Bearer Abcdefghijklmnopqrstu rejected; Basic Canary-Basic rejected", "Basic [REDACTED] rejected; Basic [REDACTED] rejected; Bearer [REDACTED] rejected; Basic [REDACTED] rejected"],
  ]) {
    assert.equal(redactErrorText(text), expected);
    assert.equal(redactCredentialValueText(text), expected);
  }
  // A digit string under a singular credential word is still a credential (a PIN, a numeric token).
  assert.equal(redactErrorText('"pin": 4711, "token": 12345678, otp=123456, "tokens": 2'), '"pin": [REDACTED], "token": [REDACTED], otp=[REDACTED], "tokens": 2');
  assert.equal(redactCredentialValueText("bare Kq7Zx2Vw9Lm4Tp8R id"), "bare Kq7Zx2Vw9Lm4Tp8R id", "an opaque identifier in evidence is not a secret");
  const certificate = "-----BEGIN CERTIFICATE-----\nMIIEfake\n-----END CERTIFICATE-----";
  assert.equal(redactCredentialValueText(certificate), certificate, "a public certificate is evidence");
  assert.equal(redactCredentialValueText("-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----"), "[REDACTED]");
  assert.equal(redactCredentialValueText(`${certificate}\n-----BEGIN EC PRIVATE KEY-----\nMHcC`), `${certificate}\n[REDACTED]`, "a truncated private block after a kept certificate");

  // Names, prose, and this module's own vocabulary survive.
  for (const text of [
    "Zendesk request failed for /users/me (403 Forbidden)",
    "Zendesk request failed for /oauth/tokens (502 Bad Gateway; non-JSON text/html response body (1234 bytes, not echoed))",
    "GET /api/v2/audit_logs?filter[source_type]=apitoken&sort=-created_at&page[size]=100",
    "The OAuth client and token endpoints were readable and returned zero clients and zero tokens, so no third-party OAuth applications are registered on this account.",
    "3 OAuth clients all declare allowed scopes; review 1 public clients, 2 tokens with write or impersonate scope, 0 non-expiring tokens. Token hygiene could not be judged because GET /api/v2/oauth/tokens returned 403 (credential lacks permission).",
    "API token access is disabled (api_token_access=false); manage_api_credentials=true; two_factor_auth=true; password_policy=high",
    "review each outstanding token in Admin Center > Apps and integrations > APIs > API tokens, confirm its owner and purpose, delete unused tokens, and record the OAuth migration plan.",
    "Using Zendesk subdomain acme with API token basic auth.",
    "Unable to read Zendesk config file /etc/zendesk.json (EACCES)",
    "Unable to parse Zendesk config file: invalid JSON in /etc/zendesk.json at line 3",
    "/tmp/grclanker-zendesk-loader-errors-Ab3xY9/nested.yaml",
    "policy 550e8400-e29b-41d4-a716-446655440000 unified_compliance_matrix ENOENT PCI-DSS-4",
    "Basic authentication is required; the Bearer token is missing; token expired, retry later",
    '"pass": 12, "pass_rate": 95, "api_token_access": false, "two_factor_auth": {"enforce": true}, "password": {"min_length": 12}',
    '"api_keys": 3, "secrets": 0, "oauth_tokens": 1, "credentials": 12; keys=3 tokens: 7 cookies: 0',
    "session_timeout_minutes=30 auth_mode=saml credentials_file=/etc/x access_key_id=AKIA client_id=abc",
    "misconfiguration of the Authorization Code flow on misconfigured-support-cluster",
  ]) {
    assert.equal(redactErrorText(text), text, text);
  }
  // Compound header lines with no credential carrier keep every name and value in both
  // scrubs, bare or JSON-escaped.
  for (const text of [
    'Content-Type: "application/json"; Accept: application/json, text/plain; X-Request-Id: 7f3a',
    "Content-Type: text/plain; charset=utf-8, Accept-Encoding: gzip, deflate",
    "Date: Tue, 22 Sep 2026 18:00:00 GMT; Content-Type: application/json",
    "Content-Type: application/json, Date: Tue, 22 Sep 2026 18:00:00 GMT",
    '<p>Content-Type: "text/html"; X-Request-Id: "7f3a"</p><p>next</p>',
    '{"detail":"{\\"Content-Type\\": \\"application/json\\", \\"Date\\": \\"Tue, 22 Sep 2026 18:00:00 GMT\\"}"}',
    '{"detail":"{\\"user\\": \\"auditor@example.com\\", \\"name\\": \\"svc\\", \\"tokens\\": 2}"}',
  ]) {
    assert.equal(redactErrorText(text), text, text);
    assert.equal(redactCredentialValueText(text), text, text);
  }

  for (const [key, expected] of [
    ["key", true], ["token", true], ["full_token", true], ["api_key", true], ["X-Api-Key", true], ["Set-Cookie", true],
    ["_zendesk_session", true], ["session_id", true], ["JSESSIONID", true], ["password1", true], ["authtoken", true],
    ["sharedsecret", true], ["privatekey", true], ["password_hash", true], ["token_value", true], ["authorization_header", true],
    ["client_secret", true], ["signing_secret", true], ["sid", true], ["sig", true],
    ["api_token_access", false], ["public_key", false], ["tokenCount", false], ["scopes", false], ["client_id", false], ["user", false],
    ["login", false], ["max_keys", false], ["auth_mode", false], ["password_policy", false], ["two_factor_auth", true],
    ["pass_rate", false], ["pass", false], ["access_key_id", false], ["monkey", false], ["oauth", false], ["sessions", false],
    ["session_timeout_minutes", false], ["credentials_file", false], ["passwordPolicy", false], ["webhookUrl", false], ["target_url", false],
    ["registration_code", true], ["activation_code", true], ["authorization_code", true], ["recovery_codes", true],
    ["status_code", false], ["error_code", false], ["country_code", false], ["code", false],
  ]) {
    assert.equal(isCredentialKey(key), expected, key);
  }
});

test("no window of a carried or configured canary survives, for every canary length from 6 to 24", () => {
  // A deterministic generator so a failure reproduces; one digit is forced so the value
  // never falls under a prose exception after a scheme.
  let seed = 0x2545f491;
  const next = () => {
    seed = (seed * 1103515245 + 12345) % 0x80000000;
    return seed;
  };
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const canary = (length) => {
    let value = "";
    for (let index = 0; index < length; index += 1) value += alphabet[next() % alphabet.length];
    return `${value.slice(0, -1)}${next() % 10}`;
  };
  for (let length = 6; length <= 24; length += 1) {
    for (let sample = 0; sample < 3; sample += 1) {
      const value = canary(length);
      for (const [text] of carriersOf(value)) {
        for (const scrub of [redactErrorText, redactCredentialValueText]) {
          assertNoWindow(scrub(text), value, `${scrub.name} ${text}`);
        }
      }
      for (const form of secretForms(value)) {
        assertNoWindow(redactSecrets(`upstream echoed ${form} in a ${length}-character reply`, [value]), value, `configured ${value} as ${form}`);
      }
    }
  }
});

test("the healthy bundle is fixed text the scrubs leave untouched, so every marker in a bundle is attributable to a credential or an echo", async () => {
  const bundle = await exportZendeskAuditBundle(healthyClient(), sampleConfig(), createTempBase("grclanker-zendesk-fixed-text-"), { now: () => NOW });
  const files = readBundleFiles(bundle.outputDir);
  assert.ok(files.size >= 20);
  for (const [name, content] of files) {
    assert.equal(redactErrorText(content), content, `${name} is fixed text redactErrorText leaves alone`);
    assert.equal(redactCredentialValueText(content), content, `${name} is fixed text redactCredentialValueText leaves alone`);
    assert.equal(redactConfiguredSecrets(content, configuredZendeskSecrets(sampleConfig())), content, `${name} carries no configured secret`);
    // core_data/ carries the fixture's own webhook and target credentials as markers, and
    // QUICK_REFERENCE.md describes the marker; every other file is marker-free on a healthy tenant.
    if (!name.startsWith("core_data") && name !== "QUICK_REFERENCE.md") assert.ok(!content.includes("[REDACTED]"), `${name} carries no marker on a healthy tenant`);
  }
  const access = await checkZendeskAccess(healthyClient());
  const results = await runAllAssessments(healthyClient());
  for (const [label, text] of [["access check", JSON.stringify(access)], ["assessments", JSON.stringify(results)]]) {
    assert.equal(redactErrorText(text), text, `${label} is fixed text`);
    assert.ok(!text.includes("[REDACTED]"), `${label} carries no marker on a healthy tenant`);
  }
});

// Round 7(a): fixed message text can itself match a credential-pair scrub ("credentials: <path>"
// reads as a pair), so every fixed text this module emits on the unhealthy paths is driven out
// of the module over HTTP and run through the general scrub: the not-collected markers and
// their collection status, the refusal, plan, and could-not-be-read causes, the non-JSON and
// silent-success notes, the manual and capped summaries, and _errors.log must all be the
// identity under redactErrorText. Because the writer scrubs before it writes, a fixed text
// mangled on the way in would surface as a marker, so with nothing planted no file or result
// may carry one (QUICK_REFERENCE.md describes the marker and is exempt).
test("round 7(a): every fixed text emitted on refused, unavailable, failed, and silent-success paths survives the scrubs unchanged", async () => {
  const routes = await healthyHttpRoutes();
  const everyRouteBut = (makeResponse) => new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async (url) => (zendeskRouteKey(url) === "/users/me" ? jsonResponse(routes["/users/me"]) : makeResponse()),
    sleep: async () => {},
  });
  const fixtures = [
    ["every list refused", everyRouteBut(forbiddenJsonResponse)],
    ["every list unavailable on the plan", everyRouteBut(() => jsonResponse({ error: "RecordNotFound", description: "Not found" }, { status: 404, statusText: "Not Found" }))],
    ["every list behind a proxy page", everyRouteBut(() => new Response("<html><body>502 Bad Gateway</body></html>", { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html" } }))],
    ["every list an empty success", everyRouteBut(() => new Response("", { status: 200, statusText: "OK", headers: { "content-type": "application/json" } }))],
  ];
  const corpus = [];
  for (const [label, client] of fixtures) {
    const access = await checkZendeskAccess(client);
    const bundle = await exportZendeskAuditBundle(client, sampleConfig(), createTempBase("grclanker-zendesk-fixed-text-"), { now: () => NOW });
    const rendered = [["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(await runAllAssessments(client))], ...readBundleFiles(bundle.outputDir)];
    assert.ok(rendered.some(([name]) => name === "_errors.log"), `${label}: the failures are logged`);
    for (const [name, text] of rendered) {
      assert.equal(redactErrorText(text), text, `${label}: a fixed text in ${name} is changed by the general scrub`);
      if (name !== "QUICK_REFERENCE.md") assert.ok(!text.includes("[REDACTED]"), `${label}: ${name} carries a marker with nothing planted`);
      corpus.push(text);
    }
  }

  // One surface refused at a time: the capped-at-warn and secondary-inventory wordings.
  for (const surface of Object.keys(routes)) {
    if (surface === "/users/me") continue;
    const client = httpClient(routes, surface, forbiddenJsonResponse);
    for (const [name, text] of [["check_access", JSON.stringify(await checkZendeskAccess(client))], ["assessments", JSON.stringify(await runAllAssessments(client))]]) {
      assert.equal(redactErrorText(text), text, `${surface} refused: a fixed text in ${name} is changed by the general scrub`);
      assert.ok(!text.includes("[REDACTED]"), `${surface} refused: ${name} carries a marker with nothing planted`);
      corpus.push(text);
    }
  }

  // The loader texts, with the fs code and the structured line they carry, are fixed text too.
  const base = createTempBase("grclanker-zendesk-fixed-loader-");
  mkdirSync(join(base, "dir.json"));
  writeFileSync(join(base, "broken.json"), '{\n  "subdomain": "acme"\n  "email": "auditor@example.com"\n}\n');
  for (const file of [join(base, "dir.json"), join(base, "missing.json"), join(base, "broken.json")]) {
    assert.throws(() => resolveZendeskConfiguration({ config_file: file }, {}, base), (error) => {
      assert.equal(redactErrorText(error.message), error.message, `${file}: the loader text survives the scrub`);
      assert.equal(redactCredentialValueText(error.message), error.message, `${file}: the loader text survives the data scrub`);
      corpus.push(error.message);
      return true;
    });
  }

  // Positive controls: the fixtures reach every family of fixed text the rule names.
  const emitted = corpus.join("\n");
  for (const family of [
    /"collected":\s*false/,
    /"dataset_status":\s*"forbidden"/,
    /"dataset_status":\s*"not_found"/,
    /"dataset_status":\s*"error"/,
    // The error line of a dataset named for what it holds keeps its whole message.
    /"oauth_tokens dataset: Zendesk request failed for https:\/\/acme\.zendesk\.com\/api\/v2\/oauth\/tokens\?all=true\S* \(403 Forbidden; Forbidden; You do not have access to this page/,
    /"oauth_tokens dataset: Zendesk request GET \/api\/v2\/oauth\/tokens returned 200 OK with an empty response body/,
    /returned 403 \(credential lacks permission\)\./,
    /returned 404 \(endpoint unavailable on this account or plan\)\./,
    /Unavailable on this account or plan: /,
    / could not be read: /,
    / Manual evidence: /,
    /Verdict capped at warn because a secondary inventory could not be read: /,
    /502 Bad Gateway; non-JSON text\/html response body \(\d+ bytes, not echoed\)/,
    /200 OK with an empty response body where the documented JSON document was expected/,
    /Unable to read Zendesk config file .* \((EISDIR|ENOENT)\)/,
    /Unable to parse Zendesk config file: invalid JSON in .* at line \d+ \(INVALID_JSON\)/,
  ]) {
    assert.match(emitted, family, `the fixtures emit the ${family} family`);
  }
});

test("fixture self-check: planted credentials are alphanumeric and random-looking, share no 6-character window with each other, and no 6-character window of any occurs in the fixtures' legitimate text", async () => {
  const owners = new Map();
  for (const value of PLANTED_CREDENTIALS) {
    assert.ok(value.length >= LEAK_WINDOW_MIN, `${value} is too short to carry a window`);
    if (!SHAPED_CREDENTIALS.has(value)) {
      assert.match(value, /^[A-Za-z0-9]+$/, `${value} is not alphanumeric`);
      assert.ok((value.match(/\d/g) ?? []).length >= 2 && (value.match(/[A-Za-z]/g) ?? []).length >= 4, `${value} does not look random`);
    }
    assert.doesNotMatch(value, /(.)\1\1/, `${value} repeats a character three times`);
    for (const window of sixWindows(value)) {
      const owner = owners.get(window);
      assert.ok(owner === undefined || owner === value, `${value} shares the window ${window} with ${owner}`);
      owners.set(window, value);
    }
  }

  // Legitimate text: everything the healthy fixture renders (the access check, every
  // assessment, and every bundle file), plus everything the secret-bearing fixture renders
  // with the planted values themselves removed, so what remains is the fixture's ordinary
  // vocabulary: names, hosts, URLs, ids, dates, and this module's own wording.
  const corpus = [];
  for (const client of [healthyClient(), secretBearingClient()]) {
    corpus.push(JSON.stringify(await checkZendeskAccess(client)), JSON.stringify(await runAllAssessments(client)));
    const bundle = await exportZendeskAuditBundle(client, sampleConfig(), createTempBase("grclanker-zendesk-self-check-"), { now: () => NOW });
    for (const text of readBundleFiles(bundle.outputDir).values()) corpus.push(text);
  }
  const legitimate = PLANTED_CREDENTIALS.reduce((rest, value) => rest.split(value).join(""), corpus.join("\n"));
  assert.ok(legitimate.length > 10_000, "the legitimate corpus is not empty");
  for (const value of PLANTED_CREDENTIALS) {
    for (const window of sixWindows(value)) assert.ok(!legitimate.includes(window), `window ${window} of ${value} occurs in legitimate fixture text`);
  }
});

test("a documented error field is scrubbed of the configured secrets before it is shortened, so the 200-character cut never leaves a fragment of a secret", async () => {
  const forms = [...secretForms(FIXTURE_API_TOKEN), ...secretForms(FIXTURE_BASIC_CREDENTIAL)];
  for (const form of forms) {
    // The form straddles the 200-character boundary of the shortened field: scrubbing
    // after the cut would leave its head behind.
    const description = `${"x".repeat(200 - Math.floor(form.length / 2))} ${form} was rejected by the upstream identity provider`;
    const fetchImpl = async () => jsonResponse({ error: "Forbidden", description }, { status: 403, statusText: "Forbidden" });
    const client = new ZendeskApiClient(sampleConfig(), { fetchImpl, sleep: async () => {} });
    await assert.rejects(client.getAccountSettings(), (error) => {
      assertNoWindow(error.message, form, `straddling ${form}`);
      assert.match(error.message, /403 Forbidden; Forbidden; x{20,} \[REDACTED\]/, error.message);
      return true;
    });
  }
});

// Canary values that must never survive into any tool result, finding, summary, or bundle
// file: random-looking alphanumerics, no two sharing a 6-character window, so a leaked
// window is attributable (see the window rule above).
const CANARY_BEARER = "2N6iyPTaI1DOHyaG2LG5Rw";
const CANARY_SESSION = "oO3RNP3mUoKn8dhyFj1bw1";
const CANARY_API_KEY = "18F0CMC68hClk3TW4foXVF";
const CANARY_URL_TOKEN = "P3GfdBos2IChWd8L1EAbNz";
// A name-shaped value (the ruling's own example) that only its carrier, a cookie
// assignment, gives away, and a plain lowercase word that only the Bearer scheme does.
const CANARY_NAMED = "sess-canary-COOKIE-31415926535897";
const CANARY_PLAIN = "jdvdnheoejphwk";
// A second name-shaped value that travels in quotes (Cookie: sid="value"): neither its shape
// nor the pair rule removes it, only a header rule that carries a quoted value through its
// closing quote, so its absence proves that rule ran.
const CANARY_QUOTED = "sess-qtdv-QCARRY-16180339887498";
// Reviewer E gap 10: a name-shaped value carried only behind an apostrophe in a cookie pair
// name or value, behind "&" or "#" in a JSON-escaped quoted pair, and before an escaped
// quote or line break in a query pair, so only the mid-token quote rule and the backslash
// boundary remove it.
const CANARY_APOSTROPHE = "sess-apos-QUOTE-14142135623730";
const CANARIES = [CANARY_BEARER, CANARY_SESSION, CANARY_API_KEY, CANARY_URL_TOKEN, CANARY_NAMED, CANARY_PLAIN, CANARY_QUOTED];
const CANARY_URL = `https://api.example.com/v1/x?token=${CANARY_URL_TOKEN}`;
// A value only a refused foreign-origin next link carries, in its query and as its
// password: it proves the link itself is never recorded and never requested.
const CANARY_NEXT_LINK = "Vq7mR2tZk9XcP4nB6wLd3Y";
// The secret of a user-and-secret prefix on a configured base URL (rule 9: a configured URL
// is dropped to scheme, host, and path at configuration and never written).
const CANARY_USERINFO = "Hn3xKw8Rq5TzM2pY7vB4Ld";
// A JSON text stringified into a string value arrives with its quotes escaped (\"): the
// header pairs and the credential pair inside it are carriers one level down, and each
// keeps its escaped quotes around the marker so the text stays well formed.
const CANARY_ESCAPED_NOTE = `upstream body ${JSON.stringify(JSON.stringify({ Cookie: `sid=${CANARY_QUOTED}`, "X-Api-Key": CANARY_QUOTED, password: CANARY_QUOTED }))}`;
const SCRUBBED_ESCAPED_NOTE = 'upstream body "{\\"Cookie\\":\\"[REDACTED]\\",\\"X-Api-Key\\":\\"[REDACTED]\\",\\"password\\":\\"[REDACTED]\\"}"';
// The scrubbed rendering of the JSON canary fields, as every error string must carry it.
const JSON_CANARY_MARKER = new RegExp(`400 Bad Request; InvalidUpstream; Upstream refused Bearer \\[REDACTED\\] at https://api\\.example\\.com/v1/x\\?token=\\[REDACTED\\] mid-sentence; _zendesk_session=\\[REDACTED\\], api_key=\\[REDACTED\\], Bearer \\[REDACTED\\], sid=\\[REDACTED\\] rejected; Cookie: \\[REDACTED\\]; X-Api-Key: "\\[REDACTED\\]"; Content-Type: "application/json"; ${escapeRegExp(SCRUBBED_ESCAPED_NOTE)}`);

function htmlCanaryResponse() {
  const body = `<html><head><title>502 Bad Gateway</title></head><body><p>Authorization: Bearer ${CANARY_BEARER}</p>`
    + `<p>Set-Cookie: _zendesk_session=${CANARY_SESSION}; Path=/</p><p>X-Api-Key: ${CANARY_API_KEY}</p>`
    + `<p>Proxy-Authorization: Bearer ${CANARY_PLAIN}</p><p>Cookie: sid=${CANARY_NAMED}</p>`
    + `<p>Cookie: sid="${CANARY_QUOTED}"; theme=dark; X-Api-Key: "${CANARY_QUOTED}"; Content-Type: "text/html"</p>`
    + `<p>Cookie: sid=${CANARY_SESSION}; x-auth-token: "${CANARY_QUOTED}", Accept: text/html</p>`
    + `<p>The upstream at ${CANARY_URL} did not answer in time, retry later.</p></body></html>`;
  return new Response(body, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

function jsonCanaryResponse() {
  return jsonResponse({
    error: "InvalidUpstream",
    description: `Upstream refused Bearer ${CANARY_BEARER} at ${CANARY_URL} mid-sentence; _zendesk_session=${CANARY_SESSION}, api_key=${CANARY_API_KEY}, Bearer ${CANARY_PLAIN}, sid=${CANARY_NAMED} rejected`,
    // A compound line: the quoted cookie ends at its closing quote, the following quoted
    // X-Api-Key keeps its name and loses its value, and the Content-Type keeps both; then
    // the JSON-escaped carriers one level down.
    message: `Cookie: sid="${CANARY_QUOTED}"; theme=dark; X-Api-Key: "${CANARY_QUOTED}"; Content-Type: "application/json"; ${CANARY_ESCAPED_NOTE}`,
  }, { status: 400, statusText: "Bad Request" });
}

// The configured secrets of the sweep fixture, echoed bare in prose in every encoded form:
// nothing but the configured-secret pass (guard 2) removes a name-shaped token or the
// composed Basic credential, so their absence proves that pass ran at every sink.
const ECHOED_FORMS = [...secretForms(FIXTURE_API_TOKEN), ...secretForms(FIXTURE_BASIC_CREDENTIAL)];
// The plain Basic pair is echoed too; its email half is not a secret and stays.
const ECHOED_MARKER = /credentials(?: \[REDACTED\])+ auditor@example\.com\/token:\[REDACTED\] rejected/;

// Reviewer E gap 10: a 502 whose documented fields carry the apostrophe pair name, the
// apostrophe pair value, the "&"-named pair in JSON-escaped quotes one level down, and a
// query pair before an escaped line break, each followed by a control.
function apostropheCookieResponse() {
  return jsonResponse({
    error: `Cookie: theme=dark; my'pref=${CANARY_APOSTROPHE}; Content-Type: "text/html; charset=utf-8"`,
    description: `Cookie: sid=O'${CANARY_APOSTROPHE}; Date: "Mon, 22 Sep 2026 12:30:00 GMT"`,
    message: `upstream said {"headers":"Cookie: theme=dark; my&sid=\\"${CANARY_APOSTROPHE}\\"; Content-Type: \\"application/json\\""} after GET /x?token=${CANARY_APOSTROPHE}\\nstatus 502`,
  }, { status: 502, statusText: "Bad Gateway" });
}
const APOSTROPHE_MARKER = new RegExp(escapeRegExp(`502 Bad Gateway; Cookie: [REDACTED]; Content-Type: "text/html; charset=utf-8"; Cookie: [REDACTED]; Date: "Mon, 22 Sep 2026 12:30:00 GMT"; upstream said {"headers":"Cookie: [REDACTED]; Content-Type: \\"application/json\\""} after GET /x?token=[REDACTED]\\nstatus 502`));

function echoedSecretsResponse() {
  return jsonResponse({ error: "InvalidUpstream", description: `credentials ${ECHOED_FORMS.join(" ")} auditor@example.com/token:${FIXTURE_API_TOKEN} rejected` }, { status: 400, statusText: "Bad Request" });
}

function assertNoCanary(text, label, canaries = CANARIES) {
  for (const canary of canaries) assertNoWindow(text, canary, label);
}

// Every planted credential of this fixture. The deliberate exceptions to the alphanumeric
// shape are the name-shaped values that prove the configured-secret pass and the carrier
// rules run on their own (hyphenated words with one digit group), the plain lowercase word
// that only the Bearer scheme gives away, and the Slack path (the documented T/B/secret
// shape, the whole path being the secret).
const PLANTED_CREDENTIALS = [...Object.values(LOADER_CANARIES), ...CANARIES, CANARY_NEXT_LINK, CANARY_APOSTROPHE, CANARY_USERINFO, ...Object.values(FAKE_ZENDESK_SECRETS), FIXTURE_API_TOKEN];
const SHAPED_CREDENTIALS = new Set([CANARY_NAMED, CANARY_QUOTED, CANARY_APOSTROPHE, CANARY_PLAIN, FIXTURE_API_TOKEN, FAKE_ZENDESK_SECRETS.slackWebhookPath]);

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

// Body text the notes must never echo, whatever the shape. The JSON canary's compound line
// carries a redacted X-Api-Key by design, so only an X-Api-Key whose value survived counts.
const ECHOED_BODY_TEXT = /<html|Set-Cookie|X-Api-Key: (?!"\[REDACTED\]")|did not answer|Proxy-Authorization/i;

test("error-body canary sweep: every Zendesk surface failing with an HTML 502 or a JSON error body leaks no credential into any tool result, finding, or bundle file", async () => {
  const routes = await healthyHttpRoutes();
  const surfaces = Object.keys(routes);
  assert.equal(surfaces.length, 22, "every endpoint the client reads is enumerated");
  const shapes = [
    { name: "html-502", make: htmlCanaryResponse, marker: /502 Bad Gateway; non-JSON text\/html response body \(\d+ bytes, not echoed\)/, canaries: CANARIES },
    { name: "json-400", make: jsonCanaryResponse, marker: JSON_CANARY_MARKER, canaries: CANARIES },
    { name: "echoed-secrets", make: echoedSecretsResponse, marker: ECHOED_MARKER, canaries: ECHOED_FORMS },
    { name: "json-502-apostrophe-cookie", make: apostropheCookieResponse, marker: APOSTROPHE_MARKER, canaries: [CANARY_APOSTROPHE] },
  ];
  // Fixture self-check: each body carries every canary or form verbatim before the scrubs see it.
  for (const shape of shapes) {
    const body = await shape.make().text();
    for (const canary of shape.canaries) assert.ok(body.includes(canary), `fixture self-check: ${shape.name} carries ${canary}`);
  }
  for (const shape of shapes) {
    for (const surface of surfaces) {
      const label = `${shape.name} on ${surface}`;
      const client = httpClient(routes, surface, shape.make);
      const assertNoCanary = (text, where) => { for (const canary of shape.canaries) assertNoWindow(text, canary, `${where}`); };

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
        assert.doesNotMatch(error, ECHOED_BODY_TEXT, `${label}: body text echoed: ${error}`);
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
      assertNoSecretWindows(files, shape.canaries, `${label} bundle`);
      assertNoSecretWindows(zipEntries, shape.canaries, `${label} zip`);
      for (const [name, content] of files) assertNoCanary(content, `${label} ${name}`);
      const errorLog = files.get("_errors.log");
      assert.ok(errorLog !== undefined, `${label}: _errors.log must exist`);
      assert.match(errorLog, shape.marker, `${label}: _errors.log must carry the note`);
      assert.match(files.get(join("compliance", "executive_summary.md")), /## Partial Collection Warnings/, `${label}: the executive summary names the partial collection`);
    }
  }
});

test("the registered tools scrub error strings end to end over HTTP: access check, every assess tool, and the export", async () => {
  const routes = await healthyHttpRoutes();
  const failing = new Map();
  // Bridges real HTTP requests from the tools onto the same route fixtures the sweep
  // uses, so the tool boundary (runSealed, the text renderers, the export result) is
  // exercised with the real fetch, the real retry sleeps, and the real config resolver.
  const server = createServer((request, response) => {
    const key = zendeskRouteKey(`http://127.0.0.1${request.url}`);
    const upstream = failing.has(key)
      ? failing.get(key)()
      : routes[key] !== undefined
        ? jsonResponse(routes[key])
        : new Response(JSON.stringify({ error: "RecordNotFound", description: `unrouted ${key}` }), { status: 404, headers: { "content-type": "application/json" } });
    upstream.text().then((text) => {
      response.writeHead(upstream.status, Object.fromEntries(upstream.headers));
      response.end(text);
    });
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const { port } = server.address();

  const tools = new Map();
  registerZendeskTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const baseArgs = { subdomain: "acme", email: "auditor@example.com", api_token: FIXTURE_API_TOKEN, base_url: `http://127.0.0.1:${port}/api/v2` };
  const run = async (name, extra = {}) => {
    const tool = tools.get(name);
    return tool.execute("call-tools", tool.prepareArguments({ ...baseArgs, ...extra }));
  };
  const assessTools = ["zendesk_assess_authentication", "zendesk_assess_access_control", "zendesk_assess_data_protection", "zendesk_assess_integrations"];
  // The failing surfaces: team members (read by the access check, the authentication and
  // access-control assessments, and the export) and webhooks (integrations and the export).
  const failingSurfaces = { "/users": "team_members", "/webhooks": "webhooks" };

  try {
    // The 502 shape fails one surface only: the client retries a 5xx twice with real
    // backoff, so every extra failing read costs the test 1.5 seconds.
    for (const shape of [
      { name: "html-502", make: htmlCanaryResponse, marker: /502 Bad Gateway; non-JSON text\/html response body \(\d+ bytes, not echoed\)/, canaries: CANARIES, surfaces: ["/webhooks"] },
      { name: "json-400", make: jsonCanaryResponse, marker: JSON_CANARY_MARKER, canaries: CANARIES, surfaces: ["/users", "/webhooks"] },
      { name: "echoed-secrets", make: echoedSecretsResponse, marker: ECHOED_MARKER, canaries: ECHOED_FORMS, surfaces: ["/users", "/webhooks"] },
    ]) {
      failing.clear();
      for (const surface of shape.surfaces) failing.set(surface, shape.make);
      const noCanary = (text, where) => { for (const canary of shape.canaries) assertNoWindow(text, canary, where); };
      const expectedProbes = shape.surfaces.map((surface) => failingSurfaces[surface]).sort();

      const access = await run("zendesk_check_access");
      noCanary(JSON.stringify(access), `${shape.name} zendesk_check_access`);
      assert.notEqual(access.isError, true, access.content[0].text);
      const failedProbes = access.details.surfaces.filter((probe) => probe.status !== "readable");
      assert.deepEqual(failedProbes.map((probe) => probe.name).sort(), expectedProbes, `${shape.name}: exactly the failing surfaces probe as unreadable`);
      for (const probe of failedProbes) {
        assert.equal(probe.status, "error");
        assert.equal(probe.count, null);
        assert.equal(probe.truncated, null);
        assert.match(probe.error, shape.marker, `${shape.name}: ${probe.name}: ${probe.error}`);
      }
      assert.doesNotMatch(access.content[0].text, ECHOED_BODY_TEXT);
      // The Note column is capped at 90 characters and the request URL fills most of it, so
      // the rendering guarantees the row's status and null count; the full note is in details.
      for (const probe of failedProbes) {
        assert.match(access.content[0].text, new RegExp(`^\\s*${probe.name}\\s+│[^│]*│\\s*error\\s*│\\s*null\\s*│`, "m"), `${shape.name}: the ${probe.name} row renders error and null`);
      }

      const recorded = [];
      for (const name of assessTools) {
        const result = await run(name);
        noCanary(JSON.stringify(result), `${shape.name} ${name}`);
        assert.notEqual(result.isError, true, result.content[0].text);
        assert.equal(result.details.tool, name);
        for (const error of result.details.errors) {
          assert.match(error, shape.marker, `${shape.name} ${name}: ${error}`);
          assert.doesNotMatch(error, ECHOED_BODY_TEXT, error);
          recorded.push(error);
        }
        assert.doesNotMatch(result.content[0].text, ECHOED_BODY_TEXT);
        if (result.details.errors.length > 0) assert.match(result.content[0].text, /Collection warnings:/, `${name}: the rendering names the partial collection`);
        for (const item of result.details.findings) {
          if (/could not be read|502 Bad Gateway|400 Bad Request/.test(item.summary)) {
            assert.notEqual(item.status, "pass", `${shape.name}: ${item.id} passed while naming the failed read`);
          }
        }
      }
      assert.ok(recorded.length >= shape.surfaces.length, `${shape.name}: every failing surface is recorded by the assessment that reads it`);

      const exported = await run("zendesk_export_audit_bundle", { output_dir: createTempBase("grclanker-zendesk-tool-export-") });
      noCanary(JSON.stringify(exported), `${shape.name} zendesk_export_audit_bundle`);
      assert.notEqual(exported.isError, true, exported.content[0].text);
      assert.ok(exported.details.error_count >= shape.surfaces.length, `${shape.name}: the export counts the failed reads`);
      assert.match(exported.content[0].text, new RegExp(`Collection errors: ${exported.details.error_count}$`, "m"));
      const files = readBundleFiles(exported.details.output_dir);
      const zipEntries = readZipEntries(exported.details.zip_path);
      assert.ok(files.size >= 15 && zipEntries.size === files.size, `${shape.name}: bundle and zip were written`);
      for (const [name, text] of files) noCanary(text, `${shape.name} tool bundle ${name}`);
      for (const [name, text] of zipEntries) noCanary(text, `${shape.name} tool zip ${name}`);
      for (const line of files.get("_errors.log").trim().split("\n")) assert.match(line, shape.marker, line);
    }
  } finally {
    server.close();
  }
});

test("ZendeskApiError, transport errors, and the tool catch blocks scrub messages built at the throw site", async () => {
  const constructed = new ZendeskApiError(`Zendesk request failed for /x (500; Bearer ${CANARY_BEARER} at ${CANARY_URL}; Bearer ${CANARY_PLAIN}; sid=${CANARY_NAMED}; Cookie: _zendesk_session=${CANARY_SESSION}; sid="${CANARY_QUOTED}")`, 500);
  assertNoCanary(constructed.message, "constructor");
  // The ";" glued to the query value is part of that value (URLSearchParams semantics), so it goes with it.
  assert.equal(constructed.message, "Zendesk request failed for /x (500; Bearer [REDACTED] at https://api.example.com/v1/x?token=[REDACTED] Bearer [REDACTED]; sid=[REDACTED]; Cookie: [REDACTED]", "the Cookie header line is withheld to the end of the line, quoted values included");
  assert.equal(constructed.status, 500);
  // A quoted header value in a JSON string, in the escaped form the raw body carries it.
  const escaped = new ZendeskApiError(`upstream body {"detail":"rejected Cookie: sid=\\"${CANARY_QUOTED}\\"; path=/","code":401}`, 401);
  assertNoCanary(escaped.message, "constructor, JSON-escaped quotes");
  assert.equal(escaped.message, 'upstream body {"detail":"rejected Cookie: [REDACTED]","code":401}', "the escaped quotes go with the value and the JSON text around it stays intact");

  const transport = new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async () => { throw new Error(`connect ECONNREFUSED via https://svc:${CANARY_SESSION}@proxy.example.com sending Authorization: Bearer ${CANARY_BEARER}`); },
    sleep: async () => {},
  });
  await assert.rejects(transport.getCurrentUser(), (error) => {
    assertNoCanary(error.message, "transport error");
    assert.match(error.message, /https:\/\/\[REDACTED\]@proxy\.example\.com sending Authorization: Bearer \[REDACTED\]/);
    return true;
  });
  const transportResult = await assessZendeskAuthentication(transport, { now: () => NOW });
  assertNoCanary(JSON.stringify(transportResult), "transport error in assessment");
  assert.ok(transportResult.errors.some((entry) => entry.startsWith("current_user dataset: ") && entry.includes("[REDACTED]@proxy.example.com")));

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
  assert.equal(item.evidence.insecure_destinations, null, "advisory A3: with a destination unresolved the insecure count is unknown, not zero");
  assert.equal(item.evidence.insecure_resolved_destinations, 0);
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
  assert.equal(capped.evidence.insecure_destinations, 0, "every destination resolved, so the count is known");

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
  assert.equal(unseen.evidence.insecure_destinations, null);
  assert.match(unseen.summary, /The target or webhook inventory was truncated/);

  // A resolved http destination beside an unresolved one still fails, and the evidence
  // keeps the resolved count while the total stays unknown.
  const mixed = await assessZendeskIntegrations(healthyClient({
    listTargets: forbidden("/targets"),
    async listWebhooks() {
      return list([{ id: "wh9", name: "Legacy", status: "active", endpoint: "http://legacy.example.com/hook", authentication: { type: "basic_auth" } }]);
    },
    async listTriggers() {
      return list([{ id: 9, title: "Post to legacy", active: true, actions: [{ field: "notification_webhook", value: ["wh9", "{{ticket.title}}"] }, { field: "notification_target", value: ["77", "{{ticket.title}}"] }] }]);
    },
  }), { now: () => NOW });
  const mixedItem = findingById(mixed, "ZD-25");
  assert.equal(mixedItem.status, "fail", mixedItem.summary);
  assert.match(mixedItem.summary, /^1\/2 external notification actions deliver ticket data to http:\/\/ destinations\. 1 destination\(s\) could not be resolved/);
  assert.equal(mixedItem.evidence.insecure_destinations, null);
  assert.equal(mixedItem.evidence.insecure_resolved_destinations, 1);
  assert.equal(mixedItem.evidence.unresolved_destinations, 1);
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

test("ZD-02 withholds named principal lists and keeps the counts when the team inventory is truncated", async () => {
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
  assert.equal(item.evidence.without_two_factor_count, 1, "a positive count over a truncated inventory is the observed lower bound");
  assert.equal(item.evidence.two_factor_flag_missing_count, 1);
  assert.equal(item.evidence.without_two_factor, null, "item-level detail is withheld until the inventory is read to completion");
  assert.equal(item.evidence.two_factor_flag_missing, null);
  assert.ok(!("without_two_factor_partial" in item.evidence) && !("two_factor_flag_missing_partial" in item.evidence), "no partial flags accompany withheld detail");
  assert.doesNotMatch(JSON.stringify(item), /user-2@example\.com|user-3@example\.com/, "no principal from the truncated inventory is named");

  const complete = findingById(await assessZendeskAuthentication(healthyClient({
    async listTeamMembers() {
      const member = teamMember({ id: 2, role: "agent", two_factor_auth_enabled: false });
      const unknown = teamMember({ id: 3, role: "agent" });
      delete unknown.two_factor_auth_enabled;
      return list([teamMember({ id: 1, role: "admin" }), member, unknown]);
    },
  }), { now: () => NOW }), "ZD-02");
  assert.equal(complete.evidence.inventory_truncated, false);
  assert.deepEqual(complete.evidence.without_two_factor, ["user-2@example.com"]);
  assert.deepEqual(complete.evidence.two_factor_flag_missing, ["user-3@example.com"]);
  assert.equal(complete.evidence.without_two_factor_count, 1);
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

// ---------------------------------------------------------------------------
// Silent-success class: a 2xx answer without the documented JSON document
// ---------------------------------------------------------------------------

// Wording that must never leave the client: the page itself and V8's parser message,
// which quotes a window of the body.
const NON_DOCUMENT_ECHO = /Captive portal canary page|Unexpected token|is not valid JSON|Unexpected end of JSON/;

// Every body a proxy, captive portal, sign-in page, or misrouted request can serve with
// a 2xx status in place of the documented document, driven through the real client
// parser path (a fixture that throws for a non-protocol body could not see the class).
// The page carries two carried canaries so an echo would show; the last shape carries
// a content type that is not shaped like a media type, which is never quoted.
const SILENT_SUCCESS_SHAPES = [
  {
    name: "200-html",
    make: () => new Response(
      `<html><head><title>Captive portal canary page</title></head><body><p>Authorization: Bearer ${CANARY_BEARER}</p><p>Cookie: sid=${CANARY_NAMED}</p></body></html>`,
      { status: 200, statusText: "OK", headers: { "content-type": "text/html; charset=utf-8" } },
    ),
    note: /200 OK with a non-JSON text\/html response body \(\d+ bytes, not echoed\) where the documented JSON document was expected/,
  },
  {
    name: "200-empty",
    make: () => new Response("", { status: 200, statusText: "OK", headers: { "content-type": "application/json" } }),
    note: /200 OK with an empty response body where the documented JSON document was expected/,
  },
  {
    name: "200-json-array",
    make: () => new Response("[]", { status: 200, statusText: "OK", headers: { "content-type": "application/json" } }),
    note: /200 OK with a JSON array response body \(2 bytes, not echoed\) where the documented JSON document was expected/,
  },
  {
    name: "200-foreign-object",
    make: () => new Response(JSON.stringify({ status: "ok", region: "prod-us-east-2026" }), { status: 200, statusText: "OK", headers: { "content-type": "application/json" } }),
    note: /200 OK with a JSON response body without the documented "[a-z_]+" (?:array|object) \(\d+ bytes, not echoed\)/,
  },
  {
    name: "200-hostile-media-type",
    make: () => new Response("<html>Captive portal canary page</html>", { status: 200, statusText: "OK", headers: { "content-type": `Bearer ${CANARY_BEARER}` } }),
    note: /200 OK with a non-JSON unknown response body \(\d+ bytes, not echoed\) where the documented JSON document was expected/,
  },
];

const OBJECT_PROBE_NAMES = { "/users/me": "current_user", "/account/settings": "account_settings", "/security_settings": "security_settings" };

test("silent-success class: a 2xx answer without the documented JSON document on any surface is an unreadable surface with the observed status, never an empty inventory, a readable probe, a healthy check, or a hard verdict", async () => {
  const routes = await healthyHttpRoutes();
  const surfaces = Object.keys(routes);
  const baseline = statusMap(await runAllAssessments(httpClient(routes)));

  // Positive control: the parser's own message quotes the page, so only the fixed note keeps it out.
  const htmlBody = await SILENT_SUCCESS_SHAPES[0].make().text();
  assert.throws(() => JSON.parse(htmlBody), (error) => /Unexpected token|is not valid JSON/.test(error.message));
  for (const shape of SILENT_SUCCESS_SHAPES) assert.equal(shape.make().status, 200, `${shape.name} is served as a success`);

  for (const surface of surfaces) {
    // A 2xx without the document demotes exactly the verdicts a refusal of the same surface demotes.
    const refused = statusMap(await runAllAssessments(httpClient(routes, surface, forbiddenJsonResponse)));
    const dependents = [...baseline.keys()].filter((id) => refused.get(id) !== baseline.get(id));
    const coreDataName = LIST_CORE_DATA_FILES[surface];
    const probeName = PROBE_NAMES_BY_ROUTE[surface] ?? OBJECT_PROBE_NAMES[surface];

    for (const shape of SILENT_SUCCESS_SHAPES) {
      const label = `${shape.name} on ${surface}`;
      const log = [];
      const client = new ZendeskApiClient(sampleConfig(), { fetchImpl: recordingZendeskFetch(routes, { [surface]: shape.make }, log), sleep: async () => {} });

      const access = await checkZendeskAccess(client);
      const accessText = JSON.stringify(access);
      assertNoCanary(accessText, `${label} access check`);
      assert.doesNotMatch(accessText, NON_DOCUMENT_ECHO, `${label}: the page or the parser message reached the access check`);
      if (probeName) {
        const probe = access.surfaces.find((entry) => entry.name === probeName);
        assert.equal(probe.status, "error", `${label}: the probe does not count the surface as readable`);
        assert.equal(probe.httpStatus, 200, `${label}: the probe carries the status the request observed`);
        assert.equal(probe.count, null, `${label}: nothing was read, so nothing is counted`);
        assert.equal(probe.truncated, null, `${label}: no paging outcome exists`);
        assert.match(probe.error, shape.note, `${label}: ${probe.error}`);
        assert.equal(access.status, "limited", `${label}: a surface that produced no data is not a healthy check`);
        assert.ok(access.notes.some((note) => note.startsWith("Not read (") && note.includes(probeName)), `${label}: the notes name the surface: ${access.notes.join(" | ")}`);
        assert.match(access.recommendedNextStep, /network path/, `${label}: the next step names the network, not the credential`);
        assert.equal(access.surfaces.filter((entry) => entry.status !== "readable").length, 1, `${label}: only the failing surface is unreadable`);
      } else {
        assert.equal(access.status, "healthy", `${label}: the access check does not read this surface`);
      }

      const results = await runAllAssessments(client);
      const resultsText = JSON.stringify(results);
      assertNoCanary(resultsText, `${label} assessments`);
      assert.doesNotMatch(resultsText, NON_DOCUMENT_ECHO, `${label}: the page or the parser message reached an assessment`);
      const errors = results.flatMap((result) => result.errors);
      assert.ok(errors.length > 0, `${label}: the surface is recorded as a collection error`);
      for (const error of errors) assert.match(error, shape.note, `${label}: ${error}`);
      for (const [id, status] of statusMap(results)) {
        assert.equal(status, refused.get(id), `${label}: ${id} renders ${status} where a refused read of the same surface renders ${refused.get(id)}`);
        if (dependents.includes(id)) assert.ok(["warn", "manual"].includes(status), `${label}: dependent ${id} rendered the hard verdict ${status}`);
      }
      for (const code of namedZendeskStatusCodes(`${accessText}\n${resultsText}`)) {
        assert.equal(code, 200, `${label}: status ${code} is named in output but the fixture served only 200`);
      }

      const exported = await exportZendeskAuditBundle(client, sampleConfig(), createTempBase("grclanker-zendesk-silent-success-"), { now: () => NOW });
      const files = readBundleFiles(exported.outputDir);
      for (const [name, content] of files) {
        assertNoCanary(content, `${label} ${name}`);
        assert.doesNotMatch(content, NON_DOCUMENT_ECHO, `${label}: the page or the parser message reached ${name}`);
      }
      assert.match(files.get("_errors.log"), shape.note, `${label}: _errors.log carries the note`);
      if (coreDataName) {
        const marker = JSON.parse(files.get(join("core_data", `${coreDataName}.json`)));
        assert.deepEqual(
          { collected: marker.collected, status: marker.status, dataset_status: marker.dataset_status },
          { collected: false, status: 200, dataset_status: "error" },
          `${label}: the dataset is a marker carrying the observed status, not an empty list`,
        );
        assert.match(marker.error, shape.note, `${label}: the marker carries the note`);
        const entry = collectionEntry(files, coreDataName);
        assert.deepEqual(
          { status: entry.status, http_status: entry.http_status, seen: entry.seen, truncated: entry.truncated },
          { status: "error", http_status: 200, seen: null, truncated: null },
          `${label}: the collection status carries the observed 200 and no counts`,
        );
      }
      assert.ok(log.every((entry) => entry.status === 200), `${label}: every request in the run observed a 2xx`);
    }
  }
});

test("ZendeskApiClient fails a paged read whose later page or single-object read lacks the documented member instead of returning a shorter complete inventory", async () => {
  const usersUrl = (after) => `https://acme.zendesk.com/api/v2/users?page%5Bsize%5D=100&include_boundary_indicators=true&page%5Bafter%5D=${after}&role%5B%5D=agent&role%5B%5D=admin`;
  const scripted = (responses) => {
    let index = 0;
    return new ZendeskApiClient(sampleConfig(), { fetchImpl: async (url) => responses[Math.min(index++, responses.length - 1)](url), sleep: async () => {} });
  };

  await assert.rejects(
    scripted([
      () => jsonResponse({ users: [{ id: 1 }], meta: { has_more: true, after_cursor: "c2" }, links: { next: usersUrl("c2") } }, { statusText: "OK" }),
      () => jsonResponse({ meta: { has_more: false } }, { statusText: "OK" }),
    ]).listTeamMembers(),
    (error) => {
      assert.ok(error instanceof ZendeskApiError);
      assert.equal(error.status, 200);
      assert.equal(error.endpoint, "GET /api/v2/users");
      assert.match(error.message, /^Zendesk request GET \/api\/v2\/users returned 200 OK with a JSON response body without the documented "users" array \(\d+ bytes, not echoed\)$/);
      return true;
    },
  );
  await assert.rejects(
    scripted([() => jsonResponse({ user: [] }, { statusText: "OK" })]).getCurrentUser(),
    /Zendesk request GET \/api\/v2\/users\/me returned 200 OK with a JSON response body without the documented "user" object \(\d+ bytes, not echoed\)$/,
  );
  await assert.rejects(
    scripted([() => jsonResponse({ audit_logs: { id: 1 } }, { statusText: "OK" })]).getOldestAuditLog(),
    /returned 200 OK with a JSON response body without the documented "audit_logs" array/,
  );
  // The documented empty document is still an empty, complete inventory.
  const empty = await scripted([() => jsonResponse({ targets: [], next_page: null, previous_page: null, count: 0 })]).listTargets();
  assert.deepEqual(empty, { items: [], truncated: false, pages: 1 });
  // A 204 is not a documented answer to any read here and carries no document.
  await assert.rejects(
    scripted([() => new Response(null, { status: 204, statusText: "No Content" })]).getAccountSettings(),
    /returned 204 No Content with an empty response body where the documented JSON document was expected/,
  );
});

// ---------------------------------------------------------------------------
// Foreign-origin next link: a server-supplied links.next or next_page is followed only on
// the configured subdomain origin
// ---------------------------------------------------------------------------

// The refused link carries CANARY_NEXT_LINK in its query and (for the userinfo shapes) as
// the password: no request, result, file, or zip entry may carry it or any window of it.
const CONFIGURED_ORIGIN = "https://acme.zendesk.com";
const FOREIGN_HOST_REASON = /^the next link pointed to https:\/\/evil\.example\.com, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed$/;
const FOREIGN_PORT_REASON = /^the next link pointed to https:\/\/acme\.zendesk\.com:8443, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed$/;

// Every shape a foreign next link takes on a paged read of path, with the fixed text the
// refusal records: the rejected origin (for a link carrying user credentials, its origin
// without them) and the configured origin, never the link's path, query, or credentials.
function foreignNextLinks(path) {
  const rest = `${path}?page%5Bafter%5D=${CANARY_NEXT_LINK}&page=2&per_page=100`;
  return [
    ["another host", `https://evil.example.com${rest}`, FOREIGN_HOST_REASON],
    ["a host that merely starts with the configured one", `https://acme.zendesk.com.evil.example.com${rest}`, /^the next link pointed to https:\/\/acme\.zendesk\.com\.evil\.example\.com, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed$/],
    ["another port", `https://acme.zendesk.com:8443${rest}`, FOREIGN_PORT_REASON],
    ["another scheme", `http://acme.zendesk.com${rest}`, /^the next link pointed to http:\/\/acme\.zendesk\.com, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed$/],
    ["the configured host as userinfo before a foreign host", `https://acme.zendesk.com:${CANARY_NEXT_LINK}@evil.example.com${rest}`, /^the next link to https:\/\/evil\.example\.com carried user credentials in the URL and was not followed; only links on the configured origin https:\/\/acme\.zendesk\.com without user credentials are followed$/],
    ["user credentials on the configured host", `https://auditor%40example.com:${CANARY_NEXT_LINK}@acme.zendesk.com${rest}`, /^the next link to https:\/\/acme\.zendesk\.com carried user credentials in the URL and was not followed; only links on the configured origin https:\/\/acme\.zendesk\.com without user credentials are followed$/],
    ["protocol-relative", `//evil.example.com${rest}`, FOREIGN_HOST_REASON],
    ["backslash protocol-relative", `\\\\evil.example.com${rest}`, FOREIGN_HOST_REASON],
    ["a javascript scheme", `javascript:alert('${CANARY_NEXT_LINK}')`, /^the next link used the javascript: scheme, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed$/],
    ["a data scheme", `data:text/plain,${CANARY_NEXT_LINK}`, /^the next link used the data: scheme, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed$/],
    ["a blob scheme", `blob:https://evil.example.com/${CANARY_NEXT_LINK}`, /^the next link used the blob: scheme, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed$/],
    ["a file scheme", `file:///etc/${CANARY_NEXT_LINK}`, /^the next link used the file: scheme, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed$/],
  ];
}

// The two paging loops, each with its first page (carrying the next link under test) and
// its complete second page.
const NEXT_LINK_READS = [
  {
    label: "listCursor",
    path: "/api/v2/users",
    read: (client) => client.listTeamMembers(),
    firstPage: (next) => jsonResponse({ users: [{ id: 1, role: "admin" }], meta: { has_more: true, after_cursor: "c2" }, links: { next } }),
    secondPage: () => jsonResponse({ users: [{ id: 2, role: "agent" }], meta: { has_more: false, after_cursor: null }, links: { next: null } }),
  },
  {
    label: "listOffset",
    path: "/api/v2/targets",
    read: (client) => client.listTargets(),
    firstPage: (next) => jsonResponse({ targets: [{ id: 1 }], next_page: next, previous_page: null, count: 2 }),
    secondPage: () => jsonResponse({ targets: [{ id: 2 }], next_page: null, previous_page: `${CONFIGURED_ORIGIN}/api/v2/targets?page=1`, count: 2 }),
  },
];

function nextLinkClient(link, pages, requests) {
  return new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async (url, init) => {
      requests.push({ url, authorization: headerValue(init.headers, "authorization") });
      return requests.length === 1 ? pages.firstPage(link) : pages.secondPage();
    },
    sleep: async () => {},
  });
}

test("foreign-origin next link: listCursor and listOffset refuse a links.next or next_page outside the configured origin before any request leaves, keep the page already read, and record the inventory truncated with a fixed-text reason", async () => {
  for (const pages of NEXT_LINK_READS) {
    for (const [shape, link, reasonPattern] of foreignNextLinks(pages.path)) {
      const label = `${pages.label} with ${shape}`;
      const requests = [];
      const result = await pages.read(nextLinkClient(link, pages, requests));
      assert.equal(requests.length, 1, `${label}: no request leaves for the refused link`);
      assert.ok(requests[0].url.startsWith(`${CONFIGURED_ORIGIN}${pages.path}?`), `${label}: the only request went to the configured origin (${requests[0].url})`);
      assert.equal(requests[0].authorization, `Basic ${FIXTURE_BASIC_CREDENTIAL}`, `${label}: the credential went to the configured origin only`);
      assert.equal(result.items.length, 1, `${label}: the page already read is kept`);
      assert.equal(result.pages, 1, `${label}: the refused link is not a page`);
      assert.equal(result.truncated, true, `${label}: the inventory is recorded truncated`);
      assert.match(result.truncation_reason, reasonPattern, `${label}: the reason names the rejected origin or host and the configured origin`);
      const rendered = JSON.stringify(result);
      assertNoWindow(rendered, CANARY_NEXT_LINK, `${label}: the link's query and user credentials`);
      assert.ok(!rendered.includes(`${pages.path}?`) && !rendered.includes("page%5Bafter%5D") && !rendered.includes("per_page"), `${label}: the link's path and query are not recorded`);
      assert.ok(!rendered.includes("@"), `${label}: no userinfo is recorded`);
      assert.equal(redactErrorText(result.truncation_reason), result.truncation_reason, `${label}: the reason is fixed text the general scrub leaves alone`);
      assert.equal(redactCredentialValueText(result.truncation_reason), result.truncation_reason, `${label}: the reason is fixed text the data scrub leaves alone`);
    }

    // Same-origin controls: an absolute link on the configured origin (as served, with the
    // default port spelled out, or with the host in another case), a relative path on the
    // base URL, and a protocol-relative link on the configured host are followed with the
    // credential, and the read completes untruncated.
    const relativePath = pages.path.replace(/^\/api\/v2/, "");
    const controls = [
      ["an absolute same-origin link", `${CONFIGURED_ORIGIN}${pages.path}?page=2`, `${CONFIGURED_ORIGIN}${pages.path}?page=2`],
      ["the default port spelled out", `https://acme.zendesk.com:443${pages.path}?page=2`, `${CONFIGURED_ORIGIN}${pages.path}?page=2`],
      ["the host in another case", `https://ACME.Zendesk.com${pages.path}?page=2`, `${CONFIGURED_ORIGIN}${pages.path}?page=2`],
      ["a relative path", `${relativePath}?page=2`, `${CONFIGURED_ORIGIN}${pages.path}?page=2`],
      ["a protocol-relative same-origin link", `//acme.zendesk.com${pages.path}?page=2`, `${CONFIGURED_ORIGIN}${pages.path}?page=2`],
    ];
    for (const [shape, link, followed] of controls) {
      const label = `${pages.label} with ${shape}`;
      const requests = [];
      const result = await pages.read(nextLinkClient(link, pages, requests));
      assert.equal(requests.length, 2, `${label}: the same-origin link is followed`);
      assert.equal(requests[1].url, followed, `${label}: the second request is the link on the configured origin`);
      assert.equal(requests[1].authorization, `Basic ${FIXTURE_BASIC_CREDENTIAL}`, `${label}: the credential goes to the configured origin`);
      assert.deepEqual(result, { items: [{ id: 1, ...(pages.label === "listCursor" ? { role: "admin" } : {}) }, { id: 2, ...(pages.label === "listCursor" ? { role: "agent" } : {}) }], truncated: false, pages: 2 }, `${label}: both pages are merged and the read is complete`);
    }
  }
});

test("foreign-origin next link over HTTP: a refused link demotes the dependent findings, names the reason in the access check, the tool results, core_data, the collection status, _errors.log, and the executive summary, and no request or output carries the link", async () => {
  const routes = await healthyHttpRoutes();
  const foreignUsersLink = `https://evil.example.com/api/v2/users?page%5Bafter%5D=${CANARY_NEXT_LINK}`;
  const foreignTargetsLink = `https://acme.zendesk.com:8443/api/v2/targets?page=2&per_page=${CANARY_NEXT_LINK}`;
  const target = { id: 5, title: "Ops hook", active: true, target_url: "https://hooks.example.com/ops", type: "url_target_v2" };
  const log = [];
  const client = new ZendeskApiClient(sampleConfig(), {
    fetchImpl: async (url, init) => {
      log.push({ url, authorization: headerValue(init.headers, "authorization") });
      const key = zendeskRouteKey(url);
      if (key === "/users") return jsonResponse({ ...routes["/users"], meta: { has_more: true, after_cursor: "c2" }, links: { next: foreignUsersLink } });
      if (key === "/targets") return jsonResponse({ targets: [target], next_page: foreignTargetsLink, previous_page: null, count: 2 });
      const payload = routes[key];
      if (payload === undefined) throw new Error(`unrouted Zendesk request: ${url}`);
      return jsonResponse(payload);
    },
    sleep: async () => {},
  });
  const teamSeen = routes["/users"].users.length;

  const access = await checkZendeskAccess(client);
  const team = access.surfaces.find((surface) => surface.name === "team_members");
  assert.equal(team.status, "readable");
  assert.equal(team.count, teamSeen, "the probe counts the page it read");
  assert.equal(team.truncated, true, "the probe count is a seen count, not the population");
  assert.match(team.truncationReason, FOREIGN_HOST_REASON);
  const targetsSurface = access.surfaces.find((surface) => surface.name === "targets");
  assert.equal(targetsSurface.truncated, true);
  assert.match(targetsSurface.truncationReason, FOREIGN_PORT_REASON);
  assert.equal(access.surfaces.find((surface) => surface.name === "groups").truncated, false, "a list read to completion carries no reason");
  assert.equal(access.surfaces.find((surface) => surface.name === "groups").truncationReason, undefined);
  assert.ok(access.notes.some((note) => /^The team_members probe stopped paging early because the next link pointed to https:\/\/evil\.example\.com, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed\.$/.test(note)), access.notes.join("\n"));
  assert.ok(access.notes.some((note) => /^The targets probe stopped paging early because the next link pointed to https:\/\/acme\.zendesk\.com:8443, outside/.test(note)), access.notes.join("\n"));

  const results = await runAllAssessments(client);
  const accessControl = results.find((result) => result.category === "access-control");
  const admins = findingById(accessControl, "ZD-07");
  assert.equal(admins.status, "warn", `a finding over the truncated team inventory demotes: ${admins.summary}`);
  assert.equal(admins.evidence.inventory_truncated, true);
  assert.match(admins.summary, new RegExp(`The team member inventory was truncated after ${teamSeen} items \\(the next link pointed to https://evil\\.example\\.com, outside the configured origin https://acme\\.zendesk\\.com, and was not followed\\), so the verdict is limited to the seen population and item-level detail is withheld from the evidence until the inventory is read to completion\\.`));
  assert.equal(admins.evidence.admins, null, "admin names are withheld while the team inventory is truncated");
  assert.equal(admins.evidence.dormant_admins_count, null, "a zero count over a truncated inventory is not asserted");
  assert.equal(admins.evidence.seen_admins, 2, "the positive count is the observed lower bound");
  const destinations = findingById(results.find((result) => result.category === "integrations"), "ZD-24");
  assert.equal(destinations.status, "warn", `a finding over the truncated target inventory demotes: ${destinations.summary}`);
  assert.equal(destinations.evidence.inventory_truncated, true);
  assert.equal(destinations.evidence.active_targets, 1, "the seen target is counted");
  assert.match(destinations.summary, /The target inventory was truncated after 1 items \(the next link pointed to https:\/\/acme\.zendesk\.com:8443, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed\)/);
  assert.deepEqual(accessControl.errors, ["team_members dataset: partial inventory, paging stopped early because the next link pointed to https://evil.example.com, outside the configured origin https://acme.zendesk.com, and was not followed"]);
  assert.equal(accessControl.summary.collection.team_members.truncated, true);
  assert.match(accessControl.summary.collection.team_members.truncation_reason, FOREIGN_HOST_REASON);
  assert.equal(accessControl.summary.collection.team_members.seen, teamSeen);
  assert.equal(accessControl.summary.collection.groups.truncation_reason, null, "a list read to completion renders a null reason");

  const exported = await exportZendeskAuditBundle(client, sampleConfig(), createTempBase("grclanker-zendesk-next-link-"), { now: () => NOW });
  const files = readBundleFiles(exported.outputDir);
  const zip = readZipEntries(exported.zipPath);
  const teamData = JSON.parse(files.get(join("core_data", "team_members.json")));
  assert.equal(teamData.truncated, true);
  assert.equal(teamData.items.length, teamSeen, "the page already read is kept in core_data");
  assert.match(teamData.truncation_reason, FOREIGN_HOST_REASON);
  const targetsData = JSON.parse(files.get(join("core_data", "targets.json")));
  assert.deepEqual({ truncated: targetsData.truncated, items: targetsData.items.length, pages: targetsData.pages }, { truncated: true, items: 1, pages: 1 });
  assert.match(targetsData.truncation_reason, FOREIGN_PORT_REASON);
  assert.match(collectionEntry(files, "targets").truncation_reason, FOREIGN_PORT_REASON);
  const errorLog = files.get("_errors.log");
  assert.ok(errorLog !== undefined, "_errors.log records the partial inventories");
  assert.deepEqual(errorLog.trim().split("\n"), [
    "team_members dataset: partial inventory, paging stopped early because the next link pointed to https://evil.example.com, outside the configured origin https://acme.zendesk.com, and was not followed",
    "targets dataset: partial inventory, paging stopped early because the next link pointed to https://acme.zendesk.com:8443, outside the configured origin https://acme.zendesk.com, and was not followed",
  ]);
  assert.equal(JSON.parse(files.get("metadata.json")).error_count, 2);
  assert.match(files.get(join("compliance", "executive_summary.md")), /## Partial Collection Warnings\n\n- team_members dataset: partial inventory, paging stopped early because the next link pointed to https:\/\/evil\.example\.com, outside the configured origin https:\/\/acme\.zendesk\.com, and was not followed\n- targets dataset: partial inventory/);

  // No request left for either refused link: every request of the run went to the
  // configured origin, and only there did the credential go.
  assert.ok(log.length >= 22, `the run made its reads (${log.length})`);
  for (const entry of log) {
    assert.ok(entry.url.startsWith(`${CONFIGURED_ORIGIN}/api/v2/`), `every request went to the configured origin: ${entry.url}`);
    assert.equal(entry.authorization, `Basic ${FIXTURE_BASIC_CREDENTIAL}`);
    assertNoWindow(entry.url, CANARY_NEXT_LINK, "the request log");
  }

  // Every result, file, and zip entry is free of the link's path, query, and credentials,
  // and the reason is fixed text the scrub leaves alone, so no marker appears where none was
  // planted (core_data/ carries the fixture's own webhook and target credentials as markers).
  const outputs = [["check_access", JSON.stringify(access)], ...results.map((result) => [result.category, JSON.stringify(result)]), ...files, ...[...zip].map(([name, text]) => [`zip:${name}`, text])];
  for (const [name, text] of outputs) {
    assertNoWindow(text, CANARY_NEXT_LINK, `${name}: the refused link's query and credentials`);
    assert.ok(!text.includes("evil.example.com/") && !text.includes(":8443/"), `${name}: the refused link's path is not recorded`);
    assert.equal(redactErrorText(text), text, `${name}: the reason is fixed text the general scrub leaves alone`);
    if (!name.includes("core_data") && !name.includes("QUICK_REFERENCE.md")) assert.ok(!text.includes("[REDACTED]"), `${name}: carries no marker with nothing planted`);
  }
});

test("rule 9: a user-and-secret prefix on a configured base URL is dropped at configuration, so no request, the configured origin a refused next link is compared against, no tool result, and no bundle file carries it", async () => {
  const configured = `https://zd-operator:${CANARY_USERINFO}@acme.zendesk.com/api/v2/`;
  // Positive control: the URL parser keeps the prefix, so only the loader can drop it.
  assert.equal(new URL(configured).password, CANARY_USERINFO);
  const config = resolveZendeskConfiguration({ subdomain: "acme", email: "auditor@example.com", api_token: FIXTURE_API_TOKEN, base_url: configured }, {}, createTempBase("grclanker-zendesk-userinfo-home-"));
  assert.equal(config.baseUrl, "https://acme.zendesk.com/api/v2");
  assertNoWindow(JSON.stringify(config), CANARY_USERINFO, "resolved configuration");

  const routes = await healthyHttpRoutes();
  const foreignUsersLink = `https://evil.example.com/api/v2/users?page%5Bafter%5D=${CANARY_NEXT_LINK}`;
  const log = [];
  const client = new ZendeskApiClient(config, {
    fetchImpl: async (url, init) => {
      log.push({ url, authorization: headerValue(init.headers, "authorization") });
      const key = zendeskRouteKey(url);
      if (key === "/users") return jsonResponse({ ...routes["/users"], meta: { has_more: true, after_cursor: "c2" }, links: { next: foreignUsersLink } });
      const payload = routes[key];
      if (payload === undefined) throw new Error(`unrouted Zendesk request: ${url}`);
      return jsonResponse(payload);
    },
    sleep: async () => {},
  });
  const access = await checkZendeskAccess(client);
  const results = await runAllAssessments(client);
  const exported = await exportZendeskAuditBundle(client, config, createTempBase("grclanker-zendesk-userinfo-"), { now: () => NOW });
  const files = readBundleFiles(exported.outputDir);
  const zip = readZipEntries(exported.zipPath);

  assert.ok(log.length >= 22, `the run made its reads (${log.length})`);
  for (const entry of log) {
    assert.ok(entry.url.startsWith(`${CONFIGURED_ORIGIN}/api/v2/`), `every request went to the configured origin without the prefix: ${entry.url}`);
    assert.deepEqual({ username: new URL(entry.url).username, password: new URL(entry.url).password }, { username: "", password: "" }, `request URL carries no credentials: ${entry.url}`);
    assert.equal(entry.authorization, `Basic ${FIXTURE_BASIC_CREDENTIAL}`, "the credential travels in the header, never in the URL");
  }
  // The refusal names the configured origin as scheme and host, never the prefix.
  const team = access.surfaces.find((surface) => surface.name === "team_members");
  assert.match(team.truncationReason, FOREIGN_HOST_REASON);
  const outputs = [["check_access", JSON.stringify(access)], ...results.map((result) => [result.category, JSON.stringify(result)]), ...files, ...[...zip].map(([name, text]) => [`zip:${name}`, text])];
  for (const [name, text] of outputs) {
    assertNoWindow(text, CANARY_USERINFO, `${name}: the configured URL's secret`);
    assert.ok(!text.includes("zd-operator"), `${name}: the configured URL's user is not written either`);
  }
  assert.match(files.get(join("compliance", "executive_summary.md")), /^Subdomain: acme$/m);
});
