import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  LAUNCHDARKLY_CONTROL_CATALOG,
  LaunchdarklyApiClient,
  LaunchdarklyApiError,
  LaunchdarklyConfigFileError,
  assessLaunchdarklyAccessControl,
  assessLaunchdarklyEnvironmentGovernance,
  assessLaunchdarklyFlagHygiene,
  assessLaunchdarklyIdentity,
  assessLaunchdarklyMonitoringIntegrations,
  checkLaunchdarklyAccess,
  exportLaunchdarklyAuditBundle,
  parseSimpleToml,
  resolveLaunchdarklyConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/launchdarkly.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const NOW = Date.parse("2026-09-21T00:00:00Z");
const RECENT = "2026-09-15T00:00:00Z";
const RECENT_MS = Date.parse(RECENT);
const OLD = "2025-01-01T00:00:00Z";
const OLD_MS = Date.parse(OLD);
const FUTURE_MS = NOW + 90 * 24 * 60 * 60 * 1000;
const TEST_TOKEN = "api-11111111-2222-3333-4444-555555555555";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    token: TEST_TOKEN,
    baseUrl: "https://app.launchdarkly.com",
    apiVersion: "20240415",
    timeoutMs: 30000,
    allowedDomains: ["example.com"],
    projectKeys: [],
    configPath: "/nonexistent/config.toml",
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    statusText: options.statusText ?? "OK",
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

/** The error the real client throws for a failed request: the status and request travel as fields, not only as text. */
function apiError(status, statusText, endpoint, detail = "access_denied") {
  return new LaunchdarklyApiError(`LaunchDarkly request failed (${status} ${statusText}) for ${endpoint}: ${detail}`, status, endpoint);
}

function findingStatus(result, id) {
  return result.findings.find((item) => item.id === id)?.status;
}

function finding(result, id) {
  return result.findings.find((item) => item.id === id);
}

function healthyClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getCallerIdentity() {
      return {
        accountId: "acct-123",
        memberId: "m1",
        tokenId: "tok-1",
        tokenName: "grc-audit",
        serviceToken: false,
      };
    },
    async listMembers() {
      return [
        {
          _id: "m1",
          email: "owner@example.com",
          role: "owner",
          mfa: "enabled",
          mfaEnforced: true,
          teams: [{ key: "platform" }],
          _integrationMetadata: { externalId: "idp-1" },
        },
        {
          _id: "m2",
          email: "dev@example.com",
          role: "writer",
          mfa: "enabled",
          teams: [{ key: "platform" }],
        },
        {
          _id: "m3",
          email: "invitee@example.com",
          role: "reader",
          mfa: "disabled",
          _pendingInvite: true,
          teams: [],
        },
      ];
    },
    async listTeams() {
      return [{ key: "platform", name: "Platform" }];
    },
    async listTeamRoles() {
      return [{ key: "release-manager", name: "Release manager" }];
    },
    async listCustomRoles() {
      return [
        {
          key: "release-manager",
          basePermissions: "no_access",
          policy: [
            { effect: "allow", actions: ["updateOn", "updateRules"], resources: ["proj/*:env/production:flag/*"] },
            { effect: "deny", actions: ["updateOn"], resources: ["proj/*:env/*;{critical:true}:flag/*"] },
          ],
        },
      ];
    },
    async listProjects() {
      return [{ key: "web", name: "Web App", tags: [] }];
    },
    async listEnvironments() {
      return [
        {
          key: "production",
          name: "Production",
          critical: true,
          secureMode: true,
          defaultTtl: 5,
          confirmChanges: true,
          requireComments: true,
          approvalSettings: {
            required: true,
            bypassApprovalsForPendingChanges: false,
            canReviewOwnRequest: false,
            minNumApprovals: 1,
          },
          apiKey: "****abcd",
        },
        { key: "staging", name: "Staging", critical: false, secureMode: false, defaultTtl: 0 },
      ];
    },
    async listSdkKeys() {
      return [{ key: "sdk-current", kind: "sdk", _createdAt: RECENT_MS, isDefault: true, value: "****wxyz" }];
    },
    async listFlags() {
      return [
        {
          key: "checkout-v2",
          creationDate: OLD_MS,
          environments: {
            production: { targets: [], contextTargets: [], prerequisites: [{ key: "payments-enabled", variation: 0 }] },
          },
        },
        {
          key: "payments-enabled",
          creationDate: OLD_MS,
          environments: { production: { targets: [], contextTargets: [], prerequisites: [] } },
        },
      ];
    },
    async listFlagStatuses() {
      return [
        { name: "active", lastRequested: RECENT, _links: { parent: { href: "/api/v2/flags/web/checkout-v2" } } },
        { name: "launched", lastRequested: RECENT, _links: { parent: { href: "/api/v2/flags/web/payments-enabled" } } },
      ];
    },
    async listTokens() {
      return [
        {
          _id: "tok-1",
          name: "grc-audit",
          role: "admin",
          serviceToken: false,
          memberId: "m1",
          expiry: FUTURE_MS,
          lastUsed: RECENT_MS,
          creationDate: RECENT_MS,
        },
        {
          _id: "t1",
          name: "ci-service",
          token: "api-xxxxxxxx-1234",
          role: "reader",
          serviceToken: true,
          expiry: FUTURE_MS,
          lastUsed: RECENT_MS,
          creationDate: OLD_MS,
          customRoleIds: ["release-manager"],
        },
        {
          _id: "t2",
          name: "dev-personal",
          role: "writer",
          serviceToken: false,
          memberId: "m2",
          expiry: FUTURE_MS,
          lastUsed: RECENT_MS,
          creationDate: RECENT_MS,
        },
      ];
    },
    async listAuditLogEntries(query = {}) {
      if (query.before !== undefined) {
        return [{ date: OLD_MS, kind: "flag", accesses: [{ action: "updateOn", resource: "proj/web:env/production:flag/x" }] }];
      }
      if (query.spec === "member/*") {
        return [{ date: RECENT_MS, kind: "member", accesses: [{ action: "createMember", resource: "member/m2" }] }];
      }
      if (query.spec === "role/*") {
        return [{ date: RECENT_MS, kind: "role", accesses: [{ action: "updatePolicy", resource: "role/release-manager" }] }];
      }
      if (query.spec === "acct") {
        return [{ date: RECENT_MS, kind: "account", title: "Require SSO enabled", accesses: [{ action: "updateSamlRequireSso", resource: "acct" }] }];
      }
      return [{ date: RECENT_MS, kind: "flag", accesses: [{ action: "updateOn", resource: "proj/web:env/production:flag/checkout-v2" }] }];
    },
    async listWebhooks() {
      return [{ _id: "wh-1", name: "ci-hook", url: "https://hooks.example.com/ld", secret: "[REDACTED]", on: true }];
    },
    async listIntegrationSubscriptions(integrationKey) {
      if (integrationKey !== "datadog") return [];
      return [
        {
          _id: "sub-1",
          name: "datadog-prod",
          on: true,
          statements: [{ effect: "allow", actions: ["updateOn", "updateRules"], resources: ["proj/web:env/production:flag/*"] }],
        },
      ];
    },
    async listRelayProxyConfigs() {
      return [
        {
          _id: "relay-1",
          name: "edge-relay",
          lastModified: RECENT_MS,
          creationDate: OLD_MS,
          policy: [{ effect: "allow", actions: ["*"], resources: ["proj/web:env/production"] }],
        },
      ];
    },
    ...overrides,
  };
}

test("parseSimpleToml reads scalars, arrays, and sections", () => {
  const parsed = parseSimpleToml([
    "# comment",
    'token = "api-file-token" # trailing comment',
    "timeout_seconds = 12",
    'allowed_domains = ["example.com", "example.org"]',
    "",
    "[launchdarkly]",
    'base_url = "https://app.eu.launchdarkly.com"',
    "verbose = true",
  ].join("\n"));

  assert.equal(parsed.token, "api-file-token");
  assert.equal(parsed.timeout_seconds, 12);
  assert.deepEqual(parsed.allowed_domains, ["example.com", "example.org"]);
  assert.equal(parsed["launchdarkly.base_url"], "https://app.eu.launchdarkly.com");
  assert.equal(parsed["launchdarkly.verbose"], true);
});

test("resolveLaunchdarklyConfiguration prefers explicit args over env vars over the config file", () => {
  const home = createTempBase("grclanker-ld-home-");
  const configDir = join(home, ".config", "launchdarkly-sec-inspector");
  mkdirSync(configDir, { recursive: true });
  writeFileSync(join(configDir, "config.toml"), [
    'token = "api-file-token"',
    'base_url = "https://app.eu.launchdarkly.com"',
    'allowed_domains = ["file.example"]',
    'projects = ["file-project"]',
    "timeout_seconds = 45",
  ].join("\n"));

  const fromArgs = resolveLaunchdarklyConfiguration(
    {
      token: "api-arg-token",
      base_url: "https://app.launchdarkly.us/",
      api_version: "beta",
      timeout_seconds: 9,
      allowed_domains: ["Arg.Example"],
      project_keys: ["arg-project"],
    },
    {
      LAUNCHDARKLY_API_TOKEN: "api-env-token",
      LAUNCHDARKLY_BASE_URL: "https://app.launchdarkly.com",
      LAUNCHDARKLY_ALLOWED_DOMAINS: "env.example",
      LAUNCHDARKLY_PROJECTS: "env-project",
    },
    { homeDir: home },
  );
  assert.equal(fromArgs.token, "api-arg-token");
  assert.equal(fromArgs.baseUrl, "https://app.launchdarkly.us");
  assert.equal(fromArgs.apiVersion, "beta");
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.deepEqual(fromArgs.allowedDomains, ["arg.example"]);
  assert.deepEqual(fromArgs.projectKeys, ["arg-project"]);
  assert.ok(fromArgs.sourceChain.includes("arguments-token"));

  const fromEnv = resolveLaunchdarklyConfiguration(
    {},
    {
      LAUNCHDARKLY_API_TOKEN: "api-env-token",
      LAUNCHDARKLY_ALLOWED_DOMAINS: "env.example, @Second.Example",
    },
    { homeDir: home },
  );
  assert.equal(fromEnv.token, "api-env-token");
  assert.equal(fromEnv.baseUrl, "https://app.eu.launchdarkly.com");
  assert.deepEqual(fromEnv.allowedDomains, ["env.example", "second.example"]);
  assert.deepEqual(fromEnv.projectKeys, ["file-project"]);
  assert.equal(fromEnv.timeoutMs, 45000);
  assert.ok(fromEnv.sourceChain.includes("environment-token"));
  assert.ok(fromEnv.sourceChain.includes("config-base-url"));

  const fromFile = resolveLaunchdarklyConfiguration({}, {}, { homeDir: home });
  assert.equal(fromFile.token, "api-file-token");
  assert.equal(fromFile.apiVersion, "20240415");
  assert.deepEqual(fromFile.allowedDomains, ["file.example"]);
  assert.equal(fromFile.configPath, join(configDir, "config.toml"));
  assert.ok(fromFile.sourceChain.includes("config-token"));

  const explicitPath = join(home, "alt.toml");
  writeFileSync(explicitPath, 'token = "api-alt-token"\n');
  const fromExplicitPath = resolveLaunchdarklyConfiguration({}, { LAUNCHDARKLY_CONFIG: explicitPath }, { homeDir: home });
  assert.equal(fromExplicitPath.token, "api-alt-token");

  assert.throws(
    () => resolveLaunchdarklyConfiguration({}, {}, { homeDir: createTempBase("grclanker-ld-empty-") }),
    /LaunchDarkly API access token is required/,
  );
});

test("LaunchdarklyApiClient sends the raw token, LD-API-Version header, and follows _links.next pagination", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      search: url.search,
      auth: headerValue(init.headers, "authorization"),
      version: headerValue(init.headers, "ld-api-version"),
    });
    if (url.searchParams.get("offset") === "1") {
      return jsonResponse({ items: [{ _id: "m2" }], totalCount: 2, _links: { self: { href: url.pathname } } });
    }
    return jsonResponse({
      items: [{ _id: "m1" }],
      totalCount: 2,
      _links: { next: { href: "/api/v2/members?limit=1&offset=1" } },
    });
  };

  const client = new LaunchdarklyApiClient(sampleConfig(), { fetchImpl });
  const members = await client.list("/api/v2/members", {}, { limit: 10, pageSize: 1 });

  assert.deepEqual(members.items.map((member) => member._id), ["m1", "m2"]);
  assert.equal(members.truncated, false);
  assert.equal(members.seen, 2);
  assert.equal(members.total, 2);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].pathname, "/api/v2/members");
  assert.equal(seen[0].auth, TEST_TOKEN);
  assert.equal(seen[0].version, "20240415");
  assert.match(seen[0].search, /limit=1/);
  assert.match(seen[0].search, /offset=0/);
  assert.match(seen[1].search, /offset=1/);
});

test("LaunchdarklyApiClient falls back to offset pagination when _links.next is absent and signals truncation at the limit", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const offset = Number(url.searchParams.get("offset") ?? "0");
    seen.push(offset);
    return jsonResponse({ items: [{ _id: `t${offset}` }, { _id: `t${offset + 1}` }], totalCount: 6 });
  };

  const client = new LaunchdarklyApiClient(sampleConfig(), { fetchImpl });
  const tokens = await client.list("/api/v2/tokens", { showAll: "true" }, { limit: 3, pageSize: 2 });

  assert.equal(tokens.items.length, 3);
  assert.deepEqual(tokens.items.map((token) => token._id), ["t0", "t1", "t2"]);
  assert.equal(tokens.truncated, true);
  assert.equal(tokens.seen, 3);
  assert.equal(tokens.total, 6);
  assert.deepEqual(seen, [0, 2]);
});

test("LaunchdarklyApiClient signals truncation when _links.next remains at the limit and reports complete listings otherwise", async () => {
  const withNext = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ items: [{ _id: "a" }, { _id: "b" }], _links: { next: { href: "/api/v2/members?limit=2&offset=2" } } }),
  });
  const capped = await withNext.list("/api/v2/members", {}, { limit: 2, pageSize: 2 });
  assert.equal(capped.truncated, true);
  assert.equal(capped.seen, 2);
  assert.equal(capped.total, undefined);

  const complete = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ items: [{ _id: "a" }, { _id: "b" }], totalCount: 2 }),
  });
  const all = await complete.list("/api/v2/members", {}, { limit: 2, pageSize: 2 });
  assert.equal(all.truncated, false);
  assert.equal(all.seen, 2);
  assert.equal(all.total, 2);

  const empty = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ items: [], totalCount: 0 }),
  });
  const none = await empty.list("/api/v2/members", {}, { limit: 5 });
  assert.deepEqual(none, { items: [], truncated: false, seen: 0, total: 0, endpoint: "GET /api/v2/members" });
});

test("LaunchdarklyApiClient retries 429 using X-Ratelimit-Reset and retries 5xx responses", async () => {
  let attempt = 0;
  const waits = [];
  const fetchImpl = async () => {
    attempt += 1;
    if (attempt === 1) {
      return jsonResponse({ code: "rate_limited", message: "slow down" }, {
        status: 429,
        statusText: "Too Many Requests",
        headers: { "x-ratelimit-reset": String(Date.now() + 40), "x-ratelimit-route-remaining": "0" },
      });
    }
    if (attempt === 2) {
      return jsonResponse({ message: "upstream" }, { status: 503, statusText: "Service Unavailable" });
    }
    return jsonResponse({ accountId: "acct-123" });
  };

  const client = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl,
    sleep: async (ms) => {
      waits.push(ms);
    },
  });
  const identity = await client.getCallerIdentity();

  assert.equal(identity.accountId, "acct-123");
  assert.equal(attempt, 3);
  assert.ok(waits.length >= 2);
  assert.ok(waits.every((ms) => ms >= 0 && ms <= 30000));
});

test("LaunchdarklyApiClient surfaces LaunchDarkly error details and redacts tokens", async () => {
  const fetchImpl = async () => jsonResponse(
    { code: "unauthorized", message: `Invalid access token ${TEST_TOKEN} for api-99999999-aaaa-bbbb-cccc-dddddddddddd` },
    { status: 401, statusText: "Unauthorized" },
  );
  const client = new LaunchdarklyApiClient(sampleConfig(), { fetchImpl, maxRetries: 0 });

  await assert.rejects(client.listMembers(5), (error) => {
    assert.match(error.message, /401 Unauthorized/);
    assert.match(error.message, /unauthorized: Invalid access token/);
    assert.ok(!error.message.includes(TEST_TOKEN));
    assert.ok(!error.message.includes("api-99999999"));
    assert.match(error.message, /\[REDACTED\]/);
    return true;
  });
});

test("LaunchdarklyApiClient times out and reports the elapsed budget without leaking the token", async () => {
  const fetchImpl = (_input, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => {
      const error = new Error("aborted");
      error.name = "AbortError";
      reject(error);
    });
  });
  const client = new LaunchdarklyApiClient(sampleConfig({ timeoutMs: 20 }), { fetchImpl, maxRetries: 0 });

  await assert.rejects(client.getCallerIdentity(), /timed out after 20ms/);
});

test("LaunchdarklyApiClient uses the beta API version for SDK keys and masks secrets in snapshots", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, version: headerValue(init.headers, "ld-api-version") });
    if (url.pathname.endsWith("/sdk-keys")) {
      return jsonResponse({ items: [{ key: "sdk-1", kind: "sdk", value: "sdk-secret-value-1234" }] });
    }
    if (url.pathname.endsWith("/environments")) {
      return jsonResponse({ items: [{ key: "production", apiKey: "sdk-secret-abcd", mobileKey: "mob-secret-efgh" }] });
    }
    if (url.pathname.endsWith("/webhooks")) {
      return jsonResponse({ items: [{ name: "hook", url: "https://hooks.example.com/services/T0/B0/FAKE_HOOK_TOKEN?token=FAKE_QUERY_TOKEN", secret: "whsec_super_secret", on: true }] });
    }
    if (url.pathname.endsWith("/relay-auto-configs")) {
      return jsonResponse({ items: [{ name: "relay", fullKey: "rel-secret-9999", displayKey: "9999" }] });
    }
    if (url.pathname.endsWith("/tokens")) {
      return jsonResponse({ items: [{ _id: "t1", name: "ci", token: "api-xxxxxxxx-1234", serviceToken: true, role: "reader" }], totalCount: 1 });
    }
    if (url.pathname.endsWith("/integrations/datadog")) {
      return jsonResponse({
        items: [{
          _id: "sub-1",
          name: "datadog-prod",
          on: true,
          apiKey: "dd-api-FAKE",
          config: {
            url: "https://hooks.example.com/services/FAKE_CONFIG_TOKEN",
            endpoint: "hooks.example.com/relative/FAKE_RELATIVE_TOKEN",
            destination: { webhookUrl: "https://example.com/hook?key=FAKE_NESTED_TOKEN", channel: "#audit" },
            headers: [{ name: "Authorization", value: "Bearer FAKE_HEADER_TOKEN" }],
            api_key: "FAKE_SNAKE_KEY",
          },
          statements: [{ effect: "allow", actions: ["updateOn"], resources: ["proj/web:env/production:flag/*"] }],
        }],
      });
    }
    return jsonResponse({ items: [] });
  };

  const client = new LaunchdarklyApiClient(sampleConfig(), { fetchImpl });
  const sdkKeys = await client.listSdkKeys("web", "production");
  const environments = await client.listEnvironments("web");
  const webhooks = await client.listWebhooks();
  const relays = await client.listRelayProxyConfigs();
  const tokens = await client.listTokens();
  const subscriptions = await client.listIntegrationSubscriptions("datadog");

  assert.equal(seen.find((item) => item.pathname.endsWith("/sdk-keys"))?.version, "beta");
  assert.equal(seen.find((item) => item.pathname.endsWith("/environments"))?.version, "20240415");
  assert.equal(sdkKeys.items[0].value, "[REDACTED]");
  assert.equal(sdkKeys.truncated, false);
  assert.equal(environments.items[0].apiKey, "[REDACTED]");
  assert.equal(environments.items[0].mobileKey, "[REDACTED]");
  assert.equal(webhooks.items[0].secret, "[REDACTED]");
  assert.equal(webhooks.items[0].url, "https://hooks.example.com", "the destination is reduced to scheme plus host");
  assert.equal(webhooks.items[0].on, true);
  assert.equal(webhooks.truncated, false);
  assert.equal(relays.items[0].fullKey, "[REDACTED]");
  assert.equal(relays.items[0].displayKey, "9999", "the vendor display key is not a credential");
  assert.equal(tokens.items[0].token, "[REDACTED]");
  assert.equal(tokens.items[0].serviceToken, true, "booleans under credential-shaped keys are kept");
  assert.equal(tokens.items[0].role, "reader");
  const config = subscriptions.items[0].config;
  assert.equal(subscriptions.items[0].apiKey, "[REDACTED]");
  assert.equal(config.url, "https://hooks.example.com");
  assert.equal(config.endpoint, "[REDACTED]", "a host-relative endpoint path is blanked, not echoed");
  assert.equal(config.destination.webhookUrl, "https://example.com");
  assert.equal(config.destination.channel, "#audit");
  assert.deepEqual(config.headers, [{ name: "Authorization", value: "[REDACTED]" }]);
  assert.equal(config.api_key, "[REDACTED]");
  assert.deepEqual(subscriptions.items[0].statements, [{ effect: "allow", actions: ["updateOn"], resources: ["proj/web:env/production:flag/*"] }]);
  const serialized = JSON.stringify({ sdkKeys, environments, webhooks, relays, tokens, subscriptions });
  for (const secret of ["sdk-secret-value-1234", "sdk-secret-abcd", "mob-secret-efgh", "whsec_super_secret", "rel-secret-9999", "api-xxxxxxxx-1234", "dd-api-FAKE", "FAKE_HOOK_TOKEN", "FAKE_QUERY_TOKEN", "FAKE_CONFIG_TOKEN", "FAKE_RELATIVE_TOKEN", "FAKE_NESTED_TOKEN", "FAKE_HEADER_TOKEN", "FAKE_SNAKE_KEY"]) {
    assert.ok(!serialized.includes(secret), `${secret} must not survive collection`);
  }
});

test("LaunchdarklyApiClient reports single-request listings as truncated when the payload advertises a next page", async () => {
  const client = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({
      items: [{ _id: "wh-1", name: "hook", url: "https://hooks.example.com/a", on: true }],
      _links: { next: { href: "/api/v2/webhooks?offset=1" } },
    }),
  });
  const webhooks = await client.listWebhooks();
  assert.equal(webhooks.truncated, true, "a dropped _links.next must be reported as truncation");
  assert.equal(webhooks.seen, 1);

  const byTotal = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ items: [{ name: "relay" }], totalCount: 3 }),
  });
  const relays = await byTotal.listRelayProxyConfigs();
  assert.equal(relays.truncated, true);
  assert.equal(relays.total, 3);
});

test("verdict rule 10: LaunchdarklyApiClient.list reports truncation on an empty page with a next link and on a repeated next href", async () => {
  const emptyWithNext = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      if (url.searchParams.get("offset") === "2") {
        return jsonResponse({ items: [], _links: { next: { href: "/api/v2/members?limit=2&offset=4" } } });
      }
      return jsonResponse({ items: [{ _id: "a" }, { _id: "b" }], _links: { next: { href: "/api/v2/members?limit=2&offset=2" } } });
    },
  });
  const members = await emptyWithNext.list("/api/v2/members", {}, { limit: 10, pageSize: 2 });
  assert.equal(members.seen, 2);
  assert.equal(members.truncated, true, "an empty page that still advertises a next link leaves records behind");

  let calls = 0;
  const repeating = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse({ items: [{ _id: `x${calls}` }], _links: { next: { href: "/api/v2/members?limit=1&offset=1" } } });
    },
  });
  const looped = await repeating.list("/api/v2/members", {}, { limit: 50, pageSize: 1 });
  assert.equal(calls, 2, "the repeated href is fetched once, not until the cap");
  assert.equal(looped.seen, 2);
  assert.equal(looped.truncated, true, "a repeated next href cannot be drained, so the listing is partial");

  const drained = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      if (url.searchParams.get("offset") === "2") return jsonResponse({ items: [] });
      return jsonResponse({ items: [{ _id: "a" }, { _id: "b" }], _links: { next: { href: "/api/v2/members?limit=2&offset=2" } } });
    },
  });
  const complete = await drained.list("/api/v2/members", {}, { limit: 10, pageSize: 2 });
  assert.equal(complete.truncated, false, "a bare empty page drains the listing");
});

test("verdict rule 9: non-JSON error bodies are described, never echoed, into LaunchDarkly error text", async () => {
  const client = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async () => new Response("<html>proxy denied FAKE_REFLECTED_SECRET</html>", {
      status: 403,
      statusText: "Forbidden",
      headers: { "content-type": "text/html" },
    }),
    maxRetries: 0,
  });
  await assert.rejects(client.listMembers(5), (error) => {
    assert.ok(error instanceof LaunchdarklyApiError);
    assert.equal(error.status, 403);
    assert.equal(error.endpoint, "GET /api/v2/members");
    assert.match(error.message, /403 Forbidden: non-JSON body \(text\/html, 47 bytes, not echoed\)/);
    assert.ok(!error.message.includes("FAKE_REFLECTED_SECRET"));
    assert.ok(!error.message.includes("proxy denied"), "the body text is described by length, never echoed");
    return true;
  });
});

test("checkLaunchdarklyAccess reports healthy when every audit surface is readable", async () => {
  const result = await checkLaunchdarklyAccess(healthyClient());

  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.length, 12);
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 12);
  assert.equal(result.callerIdentity.accountId, "acct-123");
  assert.match(result.recommendedNextStep, /launchdarkly_assess_identity/);
  assert.ok(result.notes.some((note) => note.includes("personal token, member m1")));
});

test("checkLaunchdarklyAccess reports limited access and captures per-surface errors", async () => {
  const denied = async () => {
    throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/tokens: access_denied");
  };
  const result = await checkLaunchdarklyAccess(healthyClient({
    listTokens: denied,
    listAuditLogEntries: denied,
    listWebhooks: denied,
    listRelayProxyConfigs: denied,
  }));

  assert.equal(result.status, "limited");
  const tokens = result.surfaces.find((surface) => surface.name === "access_tokens");
  assert.equal(tokens.status, "not_readable");
  assert.match(tokens.error, /403 Forbidden/);
  assert.match(result.recommendedNextStep, /Reader base role/);
});

test("checkLaunchdarklyAccess stays healthy when only optional integration surfaces are unreadable", async () => {
  const denied = async () => {
    throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/webhooks");
  };
  const result = await checkLaunchdarklyAccess(healthyClient({
    listWebhooks: denied,
    listRelayProxyConfigs: denied,
    listIntegrationSubscriptions: denied,
  }));

  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "not_readable").length, 3);
});

test("checkLaunchdarklyAccess marks environment and flag surfaces not_configured when no project is readable", async () => {
  const result = await checkLaunchdarklyAccess(healthyClient({
    async listProjects() {
      return [];
    },
  }));

  assert.equal(result.status, "limited");
  assert.equal(result.surfaces.find((surface) => surface.name === "environments").status, "not_configured");
  assert.equal(result.surfaces.find((surface) => surface.name === "flags").status, "not_configured");
});

test("assessLaunchdarklyIdentity passes healthy identity fixtures and marks SSO enforcement manual", async () => {
  const result = await assessLaunchdarklyIdentity(healthyClient(), { now: NOW });

  assert.equal(findingStatus(result, "LD-01"), "manual");
  assert.match(finding(result, "LD-01").summary, /does not expose the account SSO\/SAML enforcement setting/);
  assert.ok(Array.isArray(finding(result, "LD-01").evidence.manual_evidence));
  assert.equal(findingStatus(result, "LD-02"), "pass");
  assert.equal(findingStatus(result, "LD-03"), "pass");
  assert.equal(findingStatus(result, "LD-06"), "pass");
  assert.equal(findingStatus(result, "LD-07"), "pass");
  assert.equal(findingStatus(result, "LD-24"), "pass");
  assert.deepEqual(result.findings.map((item) => item.control), [1, 2, 3, 6, 7, 24]);
  assert.equal(result.summary.pending_invites, 1);
  assert.deepEqual(finding(result, "LD-01").mappings, [
    "FedRAMP IA-2(1)",
    "CMMC L2 3.5.3",
    "SOC 2 CC6.1",
    "CIS 16.2",
    "PCI-DSS 8.4.1",
    "STIG SRG-APP-000148",
    "IRAP ISM-1546",
    "ISMAP CPS-7.1",
  ]);
  assert.equal(result.errors.length, 0);
});

test("assessLaunchdarklyIdentity flags MFA gaps, owner sprawl, orphans, admin-only teams, and off-domain members", async () => {
  const result = await assessLaunchdarklyIdentity(healthyClient({
    async listMembers() {
      return [
        { _id: "m1", email: "ceo@example.com", role: "owner", mfa: "enabled", teams: [{ key: "ops" }] },
        { _id: "m2", email: "cto@example.com", role: "owner", mfa: "disabled", teams: [{ key: "ops" }] },
        { _id: "m3", email: "contractor@contractor.io", role: "writer", mfa: "disabled", teams: [] },
      ];
    },
    async listTeams() {
      return [{ key: "ops", name: "Ops" }];
    },
    async listTeamRoles() {
      return [];
    },
  }), { now: NOW, maxOwners: 1 });

  assert.equal(findingStatus(result, "LD-02"), "fail");
  assert.deepEqual(finding(result, "LD-02").evidence.members_without_mfa, ["cto@example.com", "contractor@contractor.io"]);
  assert.equal(findingStatus(result, "LD-03"), "fail");
  assert.equal(findingStatus(result, "LD-06"), "fail");
  assert.deepEqual(finding(result, "LD-06").evidence.orphaned_members, ["contractor@contractor.io"]);
  assert.equal(findingStatus(result, "LD-07"), "fail");
  assert.equal(findingStatus(result, "LD-24"), "fail");
  assert.deepEqual(finding(result, "LD-24").evidence.off_domain_members, ["contractor@contractor.io"]);
});

test("assessLaunchdarklyIdentity reports domain policy as manual when no allowed domains are configured", async () => {
  const client = healthyClient({ getResolvedConfig: () => sampleConfig({ allowedDomains: [] }) });
  const result = await assessLaunchdarklyIdentity(client, { now: NOW });

  assert.equal(findingStatus(result, "LD-24"), "manual");
  assert.match(finding(result, "LD-24").summary, /LAUNCHDARKLY_ALLOWED_DOMAINS/);
});

test("assessLaunchdarklyAccessControl passes least-privilege roles and well-managed tokens with an Admin caller", async () => {
  const result = await assessLaunchdarklyAccessControl(healthyClient(), { now: NOW });

  assert.deepEqual(result.findings.map((item) => item.control), [4, 5, 8, 9, 10, 11]);
  for (const id of ["LD-04", "LD-05", "LD-08", "LD-09", "LD-10", "LD-11"]) {
    assert.equal(findingStatus(result, id), "pass", `${id} should pass`);
  }
  assert.equal(result.summary.token_inventory_scope, "full");
  for (const id of ["LD-08", "LD-09", "LD-10", "LD-11"]) {
    const inventory = finding(result, id).evidence.token_inventory;
    assert.equal(inventory.scope, "full", `${id} should record a full inventory`);
    assert.equal(inventory.caller_token_role, "admin");
    assert.equal(inventory.caller_member_role, "owner");
    assert.doesNotMatch(finding(result, id).summary, /Rerun with an Admin or Owner token/);
  }
  assert.equal(result.errors.length, 0);
});

function readerCallerClient(tokens, overrides = {}) {
  return healthyClient({
    async getCallerIdentity() {
      return { accountId: "acct-123", memberId: "m2", tokenId: "reader-1", tokenName: "dev-audit", serviceToken: false };
    },
    async listTokens() {
      return tokens;
    },
    ...overrides,
  });
}

const READER_OWN_TOKENS = [
  { _id: "reader-1", name: "dev-audit", role: "reader", serviceToken: false, memberId: "m2", expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: RECENT_MS },
  { _id: "reader-2", name: "dev-scripts", role: "writer", serviceToken: false, memberId: "m2", expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: RECENT_MS },
];

test("assessLaunchdarklyAccessControl never passes token controls on a Reader caller's partial inventory", async () => {
  const result = await assessLaunchdarklyAccessControl(readerCallerClient(READER_OWN_TOKENS), { now: NOW });

  assert.equal(result.summary.token_inventory_scope, "partial");
  for (const id of ["LD-08", "LD-09", "LD-10", "LD-11"]) {
    assert.equal(findingStatus(result, id), "warn", `${id} must not pass on a partial inventory`);
    assert.match(finding(result, id).summary, /Partial token inventory: The assessment token has the reader base role/);
    assert.match(finding(result, id).summary, /Rerun with an Admin or Owner token for a complete inventory/);
    assert.equal(finding(result, id).evidence.token_inventory.scope, "partial");
    assert.equal(finding(result, id).evidence.token_inventory.caller_token_role, "reader");
  }
  assert.equal(findingStatus(result, "LD-04"), "pass");

  const failing = await assessLaunchdarklyAccessControl(readerCallerClient([
    { ...READER_OWN_TOKENS[0], expiry: undefined, lastUsed: OLD_MS },
  ]), { now: NOW, staleTokenDays: 90 });
  assert.equal(findingStatus(failing, "LD-08"), "fail");
  assert.equal(findingStatus(failing, "LD-09"), "fail");
  assert.match(finding(failing, "LD-08").summary, /Partial token inventory/);

  const customScoped = await assessLaunchdarklyAccessControl(readerCallerClient([
    { ...READER_OWN_TOKENS[0], role: "admin", customRoleIds: ["release-manager"] },
  ]), { now: NOW });
  assert.equal(findingStatus(customScoped, "LD-08"), "warn");
  assert.match(finding(customScoped, "LD-08").summary, /scoped by custom roles or an inline policy/);

  const cappedByMember = await assessLaunchdarklyAccessControl(readerCallerClient([
    { ...READER_OWN_TOKENS[0], role: "admin" },
  ]), { now: NOW });
  assert.equal(findingStatus(cappedByMember, "LD-08"), "warn");
  assert.match(finding(cappedByMember, "LD-08").summary, /member holds the writer role, which caps the token below Admin/);
});

test("assessLaunchdarklyAccessControl infers inventory completeness when the caller token is not listed", async () => {
  const otherMembersVisible = await assessLaunchdarklyAccessControl(healthyClient({
    async getCallerIdentity() {
      return { accountId: "acct-123", memberId: "m1", tokenId: "not-listed", serviceToken: false };
    },
  }), { now: NOW });
  assert.equal(otherMembersVisible.summary.token_inventory_scope, "full");
  assert.match(finding(otherMembersVisible, "LD-08").evidence.token_inventory.reason, /Personal tokens from 1 other members are visible/);
  assert.equal(findingStatus(otherMembersVisible, "LD-08"), "pass");

  const onlyOwnTokens = await assessLaunchdarklyAccessControl(readerCallerClient(READER_OWN_TOKENS, {
    async getCallerIdentity() {
      return { accountId: "acct-123", memberId: "m2", tokenId: "not-listed", serviceToken: false };
    },
  }), { now: NOW });
  assert.equal(onlyOwnTokens.summary.token_inventory_scope, "unknown");
  for (const id of ["LD-08", "LD-09", "LD-10", "LD-11"]) {
    assert.equal(findingStatus(onlyOwnTokens, id), "warn", `${id} must not pass on an unknown inventory`);
    assert.match(finding(onlyOwnTokens, id).summary, /Token inventory completeness is unknown/);
  }

  const identityUnreadable = await assessLaunchdarklyAccessControl(readerCallerClient(READER_OWN_TOKENS, {
    async getCallerIdentity() {
      throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/caller-identity");
    },
  }), { now: NOW });
  assert.equal(identityUnreadable.summary.token_inventory_scope, "unknown");
  assert.equal(findingStatus(identityUnreadable, "LD-08"), "warn");
  assert.match(finding(identityUnreadable, "LD-08").summary, /The caller identity was not readable, so the assessment token's base role and the completeness of the showAll token listing could not be confirmed/);
  assert.match(finding(identityUnreadable, "LD-08").summary, /Unreadable inventory: caller_identity \(GET \/api\/v2\/caller-identity: .*403 Forbidden/);
  assert.ok(identityUnreadable.errors.some((error) => error.startsWith("caller_identity:")));
});

test("assessLaunchdarklyAccessControl never passes LD-10 or LD-11 on an empty permission-limited token listing", async () => {
  const result = await assessLaunchdarklyAccessControl(readerCallerClient([]), { now: NOW });

  assert.equal(result.summary.token_inventory_scope, "unknown");
  assert.equal(result.summary.tokens, 0);
  for (const id of ["LD-08", "LD-09", "LD-10", "LD-11"]) {
    assert.equal(findingStatus(result, id), "warn", `${id} must not pass on an empty listing of unknown scope`);
    assert.match(finding(result, id).summary, /Token inventory completeness is unknown: The token listing was empty/);
    assert.match(finding(result, id).summary, /Rerun with an Admin or Owner token for a complete inventory/);
    assert.equal(finding(result, id).evidence.token_inventory.visible_tokens, 0);
  }
  assert.match(finding(result, "LD-10").summary, /^No service tokens are visible\./);
  assert.match(finding(result, "LD-11").summary, /^No personal tokens are visible\./);
  assert.equal(result.errors.length, 0);
});

test("assessLaunchdarklyAccessControl treats an Admin personal caller with an unresolvable member record as unknown inventory", async () => {
  const membersUnreadable = await assessLaunchdarklyAccessControl(healthyClient({
    async listMembers() {
      throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/members");
    },
  }), { now: NOW });
  assert.equal(membersUnreadable.summary.token_inventory_scope, "unknown");
  for (const id of ["LD-08", "LD-09", "LD-10"]) {
    assert.equal(findingStatus(membersUnreadable, id), "warn", `${id} must not pass when the caller member cannot be resolved`);
    assert.match(finding(membersUnreadable, id).summary, /member inventory was unreadable \(GET \/api\/v2\/members: .*403 Forbidden/);
    assert.equal(finding(membersUnreadable, id).evidence.token_inventory.caller_member_role, null);
  }
  assert.equal(findingStatus(membersUnreadable, "LD-11"), "manual", "personal token ownership cannot be judged without members");
  assert.match(finding(membersUnreadable, "LD-11").summary, /could not be reconciled against members because the member inventory was unreadable/);
  assert.match(finding(membersUnreadable, "LD-11").summary, /Unreadable inventory: members \(GET \/api\/v2\/members/);
  assert.deepEqual(finding(membersUnreadable, "LD-11").evidence.unreadable_inventories.map((gap) => gap.inventory), ["members"]);

  const memberMissing = await assessLaunchdarklyAccessControl(healthyClient({
    async listMembers() {
      return [{ _id: "m2", email: "dev@example.com", role: "writer" }];
    },
  }), { now: NOW });
  assert.equal(memberMissing.summary.token_inventory_scope, "unknown");
  assert.equal(findingStatus(memberMissing, "LD-08"), "warn");

  const serviceCallerWithoutMembers = await assessLaunchdarklyAccessControl(healthyClient({
    async getCallerIdentity() {
      return { accountId: "acct-123", memberId: "m1", tokenId: "svc-audit", tokenName: "grc-audit-service", serviceToken: true };
    },
    async listTokens() {
      return [
        { _id: "svc-audit", name: "grc-audit-service", role: "admin", serviceToken: true, memberId: "m1", expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: RECENT_MS },
      ];
    },
    async listMembers() {
      return [];
    },
  }), { now: NOW });
  assert.equal(serviceCallerWithoutMembers.summary.token_inventory_scope, "full");
  assert.equal(findingStatus(serviceCallerWithoutMembers, "LD-08"), "pass");
});

test("assessLaunchdarklyAccessControl discloses an Admin assessment service token and scopes personal tokens to member roles", async () => {
  const serviceCaller = {
    async getCallerIdentity() {
      return { accountId: "acct-123", memberId: "m1", tokenId: "svc-audit", tokenName: "grc-audit-service", serviceToken: true };
    },
  };
  const auditServiceToken = { _id: "svc-audit", name: "grc-audit-service", role: "admin", serviceToken: true, memberId: "m1", expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: RECENT_MS };
  const devToken = { _id: "dev-1", name: "dev-personal", role: "writer", serviceToken: false, memberId: "m2", expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: RECENT_MS };

  const disclosed = await assessLaunchdarklyAccessControl(healthyClient({
    ...serviceCaller,
    async listTokens() {
      return [auditServiceToken, devToken];
    },
  }), { now: NOW });
  assert.equal(disclosed.summary.token_inventory_scope, "full");
  assert.equal(findingStatus(disclosed, "LD-08"), "pass");
  assert.equal(findingStatus(disclosed, "LD-09"), "pass");
  assert.equal(findingStatus(disclosed, "LD-11"), "pass");
  assert.equal(findingStatus(disclosed, "LD-10"), "warn");
  assert.match(finding(disclosed, "LD-10").summary, /the assessment token grc-audit-service uses the admin base role that LaunchDarkly requires for a complete token inventory/);
  assert.deepEqual(finding(disclosed, "LD-10").evidence.assessment_service_token, { token: "grc-audit-service", role: "admin", over_scoped: true });
  assert.deepEqual(finding(disclosed, "LD-10").evidence.owner_or_admin_service_tokens, []);

  const otherAdminService = await assessLaunchdarklyAccessControl(healthyClient({
    ...serviceCaller,
    async listTokens() {
      return [auditServiceToken, devToken, { _id: "svc-legacy", name: "legacy-deploy", role: "owner", serviceToken: true, expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: RECENT_MS }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(otherAdminService, "LD-10"), "fail");
  assert.deepEqual(finding(otherAdminService, "LD-10").evidence.owner_or_admin_service_tokens, ["legacy-deploy"]);

  const overScopedPersonal = await assessLaunchdarklyAccessControl(healthyClient({
    ...serviceCaller,
    async listTokens() {
      return [auditServiceToken, { ...devToken, role: "admin" }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(overScopedPersonal, "LD-11"), "warn");
  assert.deepEqual(finding(overScopedPersonal, "LD-11").evidence.over_scoped_personal_tokens, [
    { token: "dev-personal", token_role: "admin", member_role: "writer" },
  ]);
});

test("assessLaunchdarklyAccessControl flags wildcard roles, sensitive grants, missing expiry, stale and over-scoped tokens", async () => {
  const result = await assessLaunchdarklyAccessControl(healthyClient({
    async listCustomRoles() {
      return [
        { key: "god-mode", basePermissions: "reader", policy: [{ effect: "allow", actions: ["*"], resources: ["*"] }] },
        { key: "member-admin", basePermissions: "no_access", policy: [{ effect: "allow", actions: ["updateRole"], resources: ["member/*"] }] },
      ];
    },
    async listTokens() {
      return [
        { _id: "t1", name: "legacy-ci", role: "admin", serviceToken: true, lastUsed: OLD_MS, creationDate: OLD_MS },
        { _id: "t2", name: "ghost", role: "owner", serviceToken: false, memberId: "departed", expiry: FUTURE_MS, lastUsed: RECENT_MS },
      ];
    },
    async listMembers() {
      return [{ _id: "m1" }];
    },
  }), { now: NOW, staleTokenDays: 90 });

  assert.equal(findingStatus(result, "LD-04"), "fail");
  assert.deepEqual(finding(result, "LD-04").evidence.wildcard_roles.map((item) => item.role), ["god-mode"]);
  assert.equal(findingStatus(result, "LD-05"), "fail");
  assert.deepEqual(finding(result, "LD-05").evidence.sensitive_roles.map((item) => item.role), ["god-mode", "member-admin"]);
  assert.equal(findingStatus(result, "LD-08"), "fail");
  assert.equal(findingStatus(result, "LD-09"), "fail");
  assert.deepEqual(finding(result, "LD-09").evidence.stale_tokens.map((item) => item.token), ["legacy-ci"]);
  assert.equal(findingStatus(result, "LD-10"), "fail");
  assert.equal(findingStatus(result, "LD-11"), "fail");
});

async function truncatedListing(client, method, seen, total, ...args) {
  const items = await client[method](...args);
  return { items: items.slice(0, seen), truncated: true, seen: Math.min(seen, items.length), total };
}

test("assessLaunchdarklyIdentity never passes member or team controls on truncated listings", async () => {
  const base = healthyClient();
  const truncatedMembers = await assessLaunchdarklyIdentity(healthyClient({
    listMembers: () => truncatedListing(base, "listMembers", 3, 400),
  }), { now: NOW });

  for (const id of ["LD-02", "LD-03", "LD-06", "LD-24"]) {
    assert.equal(findingStatus(truncatedMembers, id), "warn", `${id} must not pass on 3 of 400 members`);
    assert.match(finding(truncatedMembers, id).summary, /Truncated listing: members \(3 of 400 collected\)/);
    assert.match(finding(truncatedMembers, id).summary, /raise member_limit and rerun/);
    assert.deepEqual(finding(truncatedMembers, id).evidence.truncated_collections, [
      { collection: "members", option: "member_limit", seen: 3, total: 400 },
    ]);
  }
  assert.equal(findingStatus(truncatedMembers, "LD-01"), "manual");
  assert.equal(findingStatus(truncatedMembers, "LD-07"), "pass");
  assert.equal(truncatedMembers.summary.truncated_collections, 1);
  assert.equal(truncatedMembers.snapshots.members.truncated, true);
  assert.equal(truncatedMembers.snapshots.members.seen, 3);
  assert.equal(truncatedMembers.snapshots.members.total, 400);
  assert.equal(truncatedMembers.snapshots.members.items.length, 3);
  assert.equal(truncatedMembers.snapshots.teams.truncated, false);

  const truncatedTeams = await assessLaunchdarklyIdentity(healthyClient({
    listTeams: () => truncatedListing(base, "listTeams", 1, 30),
  }), { now: NOW });
  assert.equal(findingStatus(truncatedTeams, "LD-06"), "warn");
  assert.equal(findingStatus(truncatedTeams, "LD-07"), "warn");
  assert.match(finding(truncatedTeams, "LD-07").summary, /teams \(1 of 30 collected\)/);
  assert.match(finding(truncatedTeams, "LD-07").summary, /raise team_limit/);
  assert.equal(findingStatus(truncatedTeams, "LD-02"), "pass");

  const failingAndTruncated = await assessLaunchdarklyIdentity(healthyClient({
    async listMembers() {
      const members = await base.listMembers();
      return { items: [{ ...members[1], mfa: "disabled" }], truncated: true, seen: 1, total: 400 };
    },
  }), { now: NOW });
  assert.equal(findingStatus(failingAndTruncated, "LD-02"), "fail");
  assert.match(finding(failingAndTruncated, "LD-02").summary, /1\/1 active members do not have MFA enabled\. Truncated listing/);
});

test("assessLaunchdarklyAccessControl never passes role or token controls on truncated listings", async () => {
  const base = healthyClient();
  const truncatedRoles = await assessLaunchdarklyAccessControl(healthyClient({
    listCustomRoles: () => truncatedListing(base, "listCustomRoles", 1, 80),
  }), { now: NOW });
  for (const id of ["LD-04", "LD-05"]) {
    assert.equal(findingStatus(truncatedRoles, id), "warn", `${id} must not pass on 1 of 80 roles`);
    assert.match(finding(truncatedRoles, id).summary, /Truncated listing: custom_roles \(1 of 80 collected\)/);
    assert.match(finding(truncatedRoles, id).summary, /raise role_limit/);
    assert.deepEqual(finding(truncatedRoles, id).evidence.truncated_collections, [
      { collection: "custom_roles", option: "role_limit", seen: 1, total: 80 },
    ]);
  }
  assert.equal(findingStatus(truncatedRoles, "LD-08"), "pass");
  assert.equal(truncatedRoles.snapshots.custom_roles.truncated, true);
  assert.equal(truncatedRoles.snapshots.custom_roles.total, 80);

  const truncatedTokens = await assessLaunchdarklyAccessControl(healthyClient({
    listTokens: () => truncatedListing(base, "listTokens", 3, 500),
  }), { now: NOW });
  assert.equal(truncatedTokens.summary.token_inventory_scope, "partial");
  for (const id of ["LD-08", "LD-09", "LD-10", "LD-11"]) {
    assert.equal(findingStatus(truncatedTokens, id), "warn", `${id} must not pass on 3 of 500 tokens`);
    assert.match(finding(truncatedTokens, id).summary, /Partial token inventory: The token listing was truncated at 3 of 500 tokens/);
    assert.match(finding(truncatedTokens, id).summary, /Raise token_limit and rerun/);
    assert.equal(finding(truncatedTokens, id).evidence.token_inventory.total_tokens, 500);
    assert.deepEqual(finding(truncatedTokens, id).evidence.truncated_collections, [
      { collection: "access_tokens", option: "token_limit", seen: 3, total: 500 },
    ]);
  }
  assert.equal(findingStatus(truncatedTokens, "LD-04"), "pass");
  assert.equal(truncatedTokens.snapshots.access_tokens.truncated, true);

  const truncatedMembers = await assessLaunchdarklyAccessControl(healthyClient({
    listMembers: () => truncatedListing(base, "listMembers", 1, 400),
  }), { now: NOW });
  assert.equal(truncatedMembers.summary.token_inventory_scope, "full");
  assert.equal(findingStatus(truncatedMembers, "LD-08"), "pass");
  assert.equal(findingStatus(truncatedMembers, "LD-11"), "warn");
  assert.match(finding(truncatedMembers, "LD-11").summary, /1\/2 visible personal tokens could not be matched to a member in the truncated member listing/);
  assert.match(finding(truncatedMembers, "LD-11").summary, /Truncated listing: members \(1 of 400 collected\)/);
  assert.deepEqual(finding(truncatedMembers, "LD-11").evidence.unverified_personal_tokens, ["dev-personal"]);
  // "No personal token is orphaned" is an absence claim over the member listing, which a truncated read cannot support.
  assert.equal(finding(truncatedMembers, "LD-11").evidence.orphaned_personal_tokens, null);
  assert.equal(truncatedMembers.summary.orphaned_personal_tokens, null);
  assert.deepEqual(finding(truncatedMembers, "LD-11").evidence.truncated_collections, [
    { collection: "members", option: "member_limit", seen: 1, total: 400 },
  ]);
});

test("assessLaunchdarklyAccessControl marks token controls manual instead of passing when tokens cannot be read", async () => {
  const result = await assessLaunchdarklyAccessControl(healthyClient({
    async listTokens() {
      throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/tokens");
    },
  }), { now: NOW });

  for (const id of ["LD-08", "LD-09", "LD-10", "LD-11"]) {
    assert.equal(findingStatus(result, id), "manual", `${id} cannot be judged without the token listing`);
    assert.match(finding(result, id).summary, /^Access tokens could not be read, so this token control could not be evaluated\. Unreadable inventory: access_tokens \(GET \/api\/v2\/tokens\?showAll=true: .*403 Forbidden/);
    assert.equal(finding(result, id).evidence.token_inventory.visible_tokens, null, `${id} renders no token count from a denied listing`);
  }
  assert.equal(result.summary.tokens, null);
  assert.equal(result.summary.tokens_without_expiry, null);
  assert.equal(result.summary.stale_tokens, null);
  assert.equal(result.summary.token_inventory_scope, "unknown");
  assert.ok(result.errors.some((error) => error.startsWith("access_tokens:")));
  assert.deepEqual(
    { collected: result.snapshots.access_tokens.collected, reason: result.snapshots.access_tokens.reason, items: result.snapshots.access_tokens.items },
    { collected: false, reason: "not_readable", items: null },
  );
});

test("assessLaunchdarklyEnvironmentGovernance passes hardened production environments", async () => {
  const result = await assessLaunchdarklyEnvironmentGovernance(healthyClient(), { now: NOW });

  assert.deepEqual(result.findings.map((item) => item.control), [16, 17, 19, 22, 23]);
  for (const id of ["LD-16", "LD-17", "LD-19", "LD-22", "LD-23"]) {
    assert.equal(findingStatus(result, id), "pass", `${id} should pass`);
  }
  assert.equal(result.summary.production_environments, 1);
  assert.equal(result.summary.restricted_production_environments, 1);
  assert.deepEqual(finding(result, "LD-16").evidence.restricted_production_environments, [
    {
      environment: "web/production",
      critical: true,
      restrictions: ["release-manager: deny proj/*:env/*;{critical:true}:flag/*"],
    },
  ]);
});

function governanceClient(roles, environmentOverrides = {}) {
  return healthyClient({
    async listCustomRoles() {
      return roles;
    },
    async listEnvironments() {
      return [
        {
          key: "production",
          name: "Production",
          critical: true,
          secureMode: true,
          defaultTtl: 5,
          confirmChanges: true,
          requireComments: true,
          approvalSettings: { required: true, bypassApprovalsForPendingChanges: false, canReviewOwnRequest: false, minNumApprovals: 1 },
          ...environmentOverrides,
        },
        { key: "staging", name: "Staging", critical: false, secureMode: false, defaultTtl: 0 },
      ];
    },
  });
}

test("assessLaunchdarklyEnvironmentGovernance does not pass LD-16 when critical is the only production qualifier", async () => {
  const result = await assessLaunchdarklyEnvironmentGovernance(governanceClient([
    { key: "dev", basePermissions: "no_access", policy: [{ effect: "allow", actions: ["updateOn"], resources: ["proj/*:env/*:flag/*"] }] },
  ]), { now: NOW });

  assert.notEqual(findingStatus(result, "LD-16"), "pass");
  assert.equal(findingStatus(result, "LD-16"), "warn");
  assert.match(finding(result, "LD-16").summary, /marked critical, which only enables safeguards/);
  assert.deepEqual(finding(result, "LD-16").evidence.critical_only_production_environments, ["web/production"]);
  assert.deepEqual(finding(result, "LD-16").evidence.restricted_production_environments, []);
  assert.equal(result.summary.critical_only_production_environments, 1);

  const noRoles = await assessLaunchdarklyEnvironmentGovernance(governanceClient([]), { now: NOW });
  assert.equal(findingStatus(noRoles, "LD-16"), "warn");
  assert.equal(finding(noRoles, "LD-16").evidence.custom_roles_evaluated, 0);
});

test("assessLaunchdarklyEnvironmentGovernance parses role resource specifiers when matching production restrictions", async () => {
  const restrictionFor = async (roles, environmentOverrides) => {
    const result = await assessLaunchdarklyEnvironmentGovernance(governanceClient(roles, environmentOverrides), { now: NOW });
    return {
      status: findingStatus(result, "LD-16"),
      restrictions: finding(result, "LD-16").evidence.restricted_production_environments.flatMap((entry) => entry.restrictions),
    };
  };
  const denyOn = (resource) => [
    { key: "guard", basePermissions: "no_access", policy: [{ effect: "deny", actions: ["updateOn"], resources: [resource] }] },
  ];

  assert.deepEqual(await restrictionFor(denyOn("proj/*:env/*;{critical:true}:flag/*")), {
    status: "pass",
    restrictions: ["guard: deny proj/*:env/*;{critical:true}:flag/*"],
  });
  assert.deepEqual(await restrictionFor(denyOn("proj/*:env/*;critical:true:flag/*")), {
    status: "pass",
    restrictions: ["guard: deny proj/*:env/*;critical:true:flag/*"],
  });
  assert.deepEqual(await restrictionFor(denyOn("proj/web:env/production:flag/*")), {
    status: "pass",
    restrictions: ["guard: deny proj/web:env/production:flag/*"],
  });
  assert.deepEqual(await restrictionFor(denyOn("proj/*:env/prod*:segment/*")), {
    status: "pass",
    restrictions: ["guard: deny proj/*:env/prod*:segment/*"],
  });
  assert.deepEqual(await restrictionFor(denyOn("proj/*:env/*;tier-1:flag/*"), { tags: ["tier-1", "pci"] }), {
    status: "pass",
    restrictions: ["guard: deny proj/*:env/*;tier-1:flag/*"],
  });

  assert.equal((await restrictionFor(denyOn("proj/*:env/staging:flag/*"))).status, "warn");
  assert.equal((await restrictionFor(denyOn("proj/mobile:env/production:flag/*"))).status, "warn");
  assert.equal((await restrictionFor(denyOn("proj/*:env/*;{critical:false}:flag/*"))).status, "warn");
  assert.equal((await restrictionFor(denyOn("proj/*:env/*;tier-2:flag/*"), { tags: ["tier-1"] })).status, "warn");
  assert.equal((await restrictionFor(denyOn("proj/*"))).status, "warn");

  assert.deepEqual(await restrictionFor([
    { key: "release", basePermissions: "no_access", policy: [{ effect: "allow", actions: ["updateOn"], notResources: ["proj/*:env/*;{critical:true}:flag/*"] }] },
  ]), { status: "pass", restrictions: ["release: allow excludes proj/*:env/*;{critical:true}:flag/*"] });
  assert.deepEqual(await restrictionFor([
    { key: "qa", basePermissions: "no_access", policy: [{ effect: "allow", actions: ["updateOn", "updateRules"], resources: ["proj/*:env/staging:flag/*"] }] },
  ]), { status: "pass", restrictions: ["qa: allow scoped to proj/*:env/staging:flag/*"] });
  assert.equal((await restrictionFor([
    {
      key: "qa-plus",
      basePermissions: "no_access",
      policy: [
        { effect: "allow", actions: ["updateOn"], resources: ["proj/*:env/staging:flag/*"] },
        { effect: "allow", actions: ["updateRules"], resources: ["proj/*:env/*:flag/*"] },
      ],
    },
  ])).status, "warn");

  const unreadable = await assessLaunchdarklyEnvironmentGovernance(healthyClient({
    async listCustomRoles() {
      throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/roles");
    },
  }), { now: NOW });
  assert.equal(findingStatus(unreadable, "LD-16"), "manual");
  assert.match(finding(unreadable, "LD-16").summary, /Custom roles could not be read/);
  assert.match(finding(unreadable, "LD-16").summary, /Unreadable inventory: custom_roles \(GET \/api\/v2\/roles: .*403 Forbidden/);
  assert.equal(finding(unreadable, "LD-16").evidence.unreadable_inventories[0].inventory, "custom_roles");
});

test("assessLaunchdarklyEnvironmentGovernance flags unrestricted production, missing approvals, old SDK keys, and test projects", async () => {
  const result = await assessLaunchdarklyEnvironmentGovernance(healthyClient({
    async listProjects() {
      return [
        { key: "web", name: "Web App", tags: [] },
        { key: "sandbox-demo", name: "Sandbox Demo", tags: ["temp"] },
      ];
    },
    async listEnvironments(projectKey) {
      if (projectKey !== "web") return [];
      return [
        {
          key: "production",
          name: "Production",
          critical: false,
          secureMode: false,
          defaultTtl: 0,
          confirmChanges: false,
          requireComments: false,
          approvalSettings: { required: false },
        },
      ];
    },
    async listSdkKeys() {
      return [{ key: "sdk-old", kind: "sdk", _createdAt: OLD_MS, isDefault: true }];
    },
    async listCustomRoles() {
      return [{ key: "dev", basePermissions: "no_access", policy: [{ effect: "allow", actions: ["*"], resources: ["proj/*"] }] }];
    },
  }), { now: NOW, sdkKeyMaxAgeDays: 365 });

  assert.equal(findingStatus(result, "LD-16"), "fail");
  assert.deepEqual(finding(result, "LD-16").evidence.unrestricted_production_environments, ["web/production"]);
  assert.equal(findingStatus(result, "LD-17"), "fail");
  assert.equal(findingStatus(result, "LD-19"), "fail");
  assert.equal(finding(result, "LD-19").evidence.stale_sdk_keys[0].key, "sdk-old");
  assert.equal(findingStatus(result, "LD-22"), "warn");
  assert.deepEqual(finding(result, "LD-22").evidence.test_like_projects, ["sandbox-demo"]);
  assert.equal(findingStatus(result, "LD-23"), "fail");
});

test("assessLaunchdarklyEnvironmentGovernance marks SDK key rotation manual when the beta endpoint is unavailable", async () => {
  const result = await assessLaunchdarklyEnvironmentGovernance(healthyClient({
    async listSdkKeys(projectKey, environmentKey) {
      throw apiError(404, "Not Found", `GET /api/v2/projects/${projectKey}/environments/${environmentKey}/sdk-keys`, "Not Found");
    },
  }), { now: NOW });

  assert.equal(findingStatus(result, "LD-19"), "manual");
  assert.match(finding(result, "LD-19").summary, /Organization settings > SDK keys/);
  assert.match(finding(result, "LD-19").summary, /Unreadable inventory: sdk_keys for environment web\/production \(GET \/api\/v2\/projects\/web\/environments\/production\/sdk-keys: .*404 Not Found/);
  assert.doesNotMatch(finding(result, "LD-19").summary, /403/, "no status code is named that the run did not observe");
  // The failed reads are recorded, one per environment, and the SDK key snapshot is a marker naming both requests.
  assert.deepEqual(result.errors.map((error) => error.split(":").slice(0, 2).join(":")).sort(), ["sdk_keys:web/production", "sdk_keys:web/staging"]);
  assert.equal(result.summary.stale_sdk_keys, null, "no stale-key count is asserted from unread SDK key listings");
  assert.equal(result.snapshots.sdk_keys.collected, false);
  assert.equal(result.snapshots.sdk_keys.status, 404);
  assert.equal(result.snapshots.sdk_keys.failed_reads.length, 2);
});

test("assessLaunchdarklyEnvironmentGovernance treats tag-scoped approvals and declined-change application as weak approval gates", async () => {
  const roles = await healthyClient().listCustomRoles();
  const approvalSettings = (overrides) => ({
    approvalSettings: {
      required: true,
      bypassApprovalsForPendingChanges: false,
      canReviewOwnRequest: false,
      canApplyDeclinedChanges: false,
      minNumApprovals: 2,
      requiredApprovalTags: [],
      serviceKind: "launchdarkly",
      ...overrides,
    },
  });
  const strictSettings = {
    required: true,
    bypass_approvals_for_pending_changes: false,
    can_review_own_request: false,
    can_apply_declined_changes: false,
    min_num_approvals: 2,
    required_approval_tags: [],
    service_kind: "launchdarkly",
  };

  const strict = await assessLaunchdarklyEnvironmentGovernance(governanceClient(roles, approvalSettings({})), { now: NOW });
  assert.equal(findingStatus(strict, "LD-17"), "pass");
  assert.match(finding(strict, "LD-17").summary, /require approvals on every flag, with no bypass, self review, or declined-change application/);
  assert.deepEqual(finding(strict, "LD-17").evidence.approvals_weak, []);
  assert.deepEqual(finding(strict, "LD-17").evidence.production_environment_settings[0].approval_settings, strictSettings);
  assert.deepEqual(finding(strict, "LD-23").evidence.production_environment_settings[0].approval_settings, strictSettings);
  assert.equal(strict.summary.approvals_weak, 0);

  const tagScoped = await assessLaunchdarklyEnvironmentGovernance(
    governanceClient(roles, approvalSettings({ requiredApprovalTags: ["require-approval"] })),
    { now: NOW },
  );
  assert.equal(findingStatus(tagScoped, "LD-17"), "warn");
  assert.match(finding(tagScoped, "LD-17").summary, /approvals are required only for flags carrying specific tags, so untagged flags skip approval/);
  assert.deepEqual(finding(tagScoped, "LD-17").evidence.approvals_weak, [
    {
      environment: "web/production",
      weaknesses: ["tag_scoped_approvals"],
      settings: { ...strictSettings, required_approval_tags: ["require-approval"] },
    },
  ]);
  assert.deepEqual(
    finding(tagScoped, "LD-17").evidence.production_environment_settings[0].approval_settings.required_approval_tags,
    ["require-approval"],
  );
  assert.equal(tagScoped.summary.approvals_weak, 1);

  const declinedApplicable = await assessLaunchdarklyEnvironmentGovernance(
    governanceClient(roles, approvalSettings({ canApplyDeclinedChanges: true })),
    { now: NOW },
  );
  assert.equal(findingStatus(declinedApplicable, "LD-17"), "warn");
  assert.match(finding(declinedApplicable, "LD-17").summary, /applied after a single approval even when other reviewers declined/);
  assert.deepEqual(finding(declinedApplicable, "LD-17").evidence.approvals_weak[0].weaknesses, ["declined_changes_applicable"]);
  assert.equal(finding(declinedApplicable, "LD-17").evidence.production_environment_settings[0].approval_settings.can_apply_declined_changes, true);

  const everythingWeak = await assessLaunchdarklyEnvironmentGovernance(
    governanceClient(roles, approvalSettings({
      bypassApprovalsForPendingChanges: true,
      canReviewOwnRequest: true,
      canApplyDeclinedChanges: true,
      requiredApprovalTags: ["prod"],
    })),
    { now: NOW },
  );
  assert.equal(findingStatus(everythingWeak, "LD-17"), "warn");
  assert.deepEqual(finding(everythingWeak, "LD-17").evidence.approvals_weak[0].weaknesses, [
    "bypass_pending_changes",
    "self_review",
    "declined_changes_applicable",
    "tag_scoped_approvals",
  ]);
  assert.match(finding(everythingWeak, "LD-17").summary, /pending changes can bypass approval; requesters can approve their own changes; changes can be applied after a single approval/);

  const notRequired = await assessLaunchdarklyEnvironmentGovernance(
    governanceClient(roles, approvalSettings({ required: false, requiredApprovalTags: ["prod"] })),
    { now: NOW },
  );
  assert.equal(findingStatus(notRequired, "LD-17"), "fail");
  assert.deepEqual(finding(notRequired, "LD-17").evidence.approvals_missing, ["web/production"]);
  assert.deepEqual(finding(notRequired, "LD-17").evidence.approvals_weak, []);
  assert.equal(finding(notRequired, "LD-17").evidence.production_environment_settings[0].approvals_required, false);
});

test("assessLaunchdarklyEnvironmentGovernance never passes on truncated project, environment, role, or SDK key listings", async () => {
  const base = healthyClient();
  const truncatedProjects = await assessLaunchdarklyEnvironmentGovernance(healthyClient({
    listProjects: () => truncatedListing(base, "listProjects", 1, 12),
  }), { now: NOW });
  for (const id of ["LD-16", "LD-17", "LD-19", "LD-22", "LD-23"]) {
    assert.equal(findingStatus(truncatedProjects, id), "warn", `${id} must not pass on 1 of 12 projects`);
    assert.match(finding(truncatedProjects, id).summary, /Truncated listing: projects \(1 of 12 collected\)/);
    assert.match(finding(truncatedProjects, id).summary, /raise project_limit/);
    assert.deepEqual(finding(truncatedProjects, id).evidence.truncated_collections, [
      { collection: "projects", option: "project_limit", seen: 1, total: 12 },
    ]);
  }
  assert.equal(truncatedProjects.summary.truncated_collections, 1);
  assert.equal(truncatedProjects.snapshots.projects.truncated, true);
  assert.equal(truncatedProjects.snapshots.projects.total, 12);
  // Environments are snapshotted per project, each entry carrying its own read's flags.
  assert.equal(truncatedProjects.snapshots.environments.length, 1);
  assert.deepEqual(
    { project: truncatedProjects.snapshots.environments[0].project, collected: truncatedProjects.snapshots.environments[0].collected, truncated: truncatedProjects.snapshots.environments[0].truncated },
    { project: "web", collected: true, truncated: false },
  );

  const truncatedEnvironments = await assessLaunchdarklyEnvironmentGovernance(healthyClient({
    listEnvironments: (projectKey) => truncatedListing(base, "listEnvironments", 2, 9, projectKey),
  }), { now: NOW });
  for (const id of ["LD-16", "LD-17", "LD-19", "LD-22", "LD-23"]) {
    assert.equal(findingStatus(truncatedEnvironments, id), "warn", `${id} must not pass on 2 of 9 environments`);
    assert.match(finding(truncatedEnvironments, id).summary, /environments for project web \(2 of 9 collected\)/);
    assert.match(finding(truncatedEnvironments, id).summary, /raise environment_limit/);
    assert.deepEqual(finding(truncatedEnvironments, id).evidence.truncated_collections, [
      { collection: "environments", option: "environment_limit", seen: 2, total: 9, scope: "project web" },
    ]);
  }
  assert.deepEqual(
    truncatedEnvironments.snapshots.environments.map((entry) => ({ project: entry.project, truncated: entry.truncated, seen: entry.seen, total: entry.total, items: entry.items.length })),
    [{ project: "web", truncated: true, seen: 2, total: 9, items: 2 }],
  );

  const truncatedRoles = await assessLaunchdarklyEnvironmentGovernance(healthyClient({
    listCustomRoles: () => truncatedListing(base, "listCustomRoles", 1, 80),
  }), { now: NOW });
  assert.equal(findingStatus(truncatedRoles, "LD-16"), "warn");
  assert.match(finding(truncatedRoles, "LD-16").summary, /All 1 production environments are restricted by custom role statements .* Truncated listing: custom_roles \(1 of 80 collected\)/);
  for (const id of ["LD-17", "LD-19", "LD-22", "LD-23"]) {
    assert.equal(findingStatus(truncatedRoles, id), "pass", `${id} is unaffected by role truncation`);
  }

  const truncatedSdkKeys = await assessLaunchdarklyEnvironmentGovernance(healthyClient({
    listSdkKeys: (projectKey, environmentKey) => truncatedListing(base, "listSdkKeys", 1, 150, projectKey, environmentKey),
  }), { now: NOW });
  assert.equal(findingStatus(truncatedSdkKeys, "LD-19"), "warn");
  assert.match(finding(truncatedSdkKeys, "LD-19").summary, /sdk_keys for environment web\/production \(1 of 150 collected\)/);
  assert.match(finding(truncatedSdkKeys, "LD-19").summary, /review the uncollected items manually/);
  assert.equal(findingStatus(truncatedSdkKeys, "LD-16"), "pass");
  assert.equal(truncatedSdkKeys.snapshots.sdk_keys[0].truncated, true);

  const failingAndTruncated = await assessLaunchdarklyEnvironmentGovernance(healthyClient({
    listProjects: () => truncatedListing(base, "listProjects", 1, 12),
    async listEnvironments() {
      return [{ key: "production", name: "Production", critical: true, secureMode: false, approvalSettings: { required: false } }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(failingAndTruncated, "LD-17"), "fail");
  assert.equal(findingStatus(failingAndTruncated, "LD-23"), "fail");
  assert.match(finding(failingAndTruncated, "LD-23").summary, /do not enable secure mode\. Truncated listing/);
});

test("assessLaunchdarklyFlagHygiene passes clean production flags", async () => {
  const result = await assessLaunchdarklyFlagHygiene(healthyClient(), { now: NOW });

  assert.deepEqual(result.findings.map((item) => item.control), [14, 15, 25]);
  assert.equal(findingStatus(result, "LD-14"), "pass");
  assert.equal(findingStatus(result, "LD-15"), "pass");
  assert.equal(findingStatus(result, "LD-25"), "pass");
  assert.equal(result.summary.evaluated_flags, 2);
  assert.equal(result.summary.evaluated_environments, 1);
});

test("assessLaunchdarklyFlagHygiene flags individual targeting, stale flags, and circular prerequisites", async () => {
  const result = await assessLaunchdarklyFlagHygiene(healthyClient({
    async listFlags() {
      return [
        {
          key: "vip-access",
          creationDate: OLD_MS,
          environments: {
            production: {
              targets: [{ values: ["user-123"], variation: 0 }],
              contextTargets: [{ contextKind: "organization", values: ["org-9"], variation: 0 }],
              prerequisites: [{ key: "beta-gate", variation: 0 }],
            },
          },
        },
        {
          key: "beta-gate",
          creationDate: OLD_MS,
          environments: { production: { prerequisites: [{ key: "vip-access", variation: 0 }] } },
        },
        { key: "old-experiment", creationDate: OLD_MS, environments: { production: {} } },
      ];
    },
    async listFlagStatuses() {
      return [
        { name: "inactive", lastRequested: OLD, _links: { parent: { href: "/api/v2/flags/web/old-experiment" } } },
        { name: "active", lastRequested: RECENT, _links: { parent: { href: "/api/v2/flags/web/vip-access" } } },
        { name: "active", lastRequested: RECENT, _links: { parent: { href: "/api/v2/flags/web/beta-gate" } } },
      ];
    },
  }), { now: NOW, staleFlagDays: 30 });

  assert.equal(findingStatus(result, "LD-14"), "fail");
  const targeted = finding(result, "LD-14").evidence.individually_targeted_flags;
  assert.equal(targeted.length, 1);
  assert.equal(targeted[0].flag, "vip-access");
  assert.equal(targeted[0].targets, 2);
  assert.deepEqual(targeted[0].context_kinds, ["user", "organization"]);
  assert.equal(findingStatus(result, "LD-15"), "warn");
  assert.deepEqual(finding(result, "LD-15").evidence.stale_flags.map((item) => item.flag), ["old-experiment"]);
  assert.equal(findingStatus(result, "LD-25"), "fail");
  const cycle = finding(result, "LD-25").evidence.prerequisite_cycles[0].cycle;
  assert.ok(cycle.includes("vip-access"));
  assert.ok(cycle.includes("beta-gate"));
});

test("assessLaunchdarklyFlagHygiene marks flag controls manual instead of passing when flags cannot be read", async () => {
  const result = await assessLaunchdarklyFlagHygiene(healthyClient({
    async listFlags() {
      throw forbidden("/api/v2/flags/web?env=production");
    },
  }), { now: NOW });

  for (const id of ["LD-14", "LD-15", "LD-25"]) {
    assert.equal(findingStatus(result, id), "manual", `${id} cannot be judged without the flag inventory`);
    assert.match(finding(result, id).summary, /flag listing was unreadable in every one of the 1 evaluated environments/);
    assert.match(finding(result, id).summary, /Unreadable inventory: flags for environment web\/production \(GET \/api\/v2\/flags\/web\?env=production: .*403 Forbidden/);
  }
  assert.ok(result.errors.some((error) => error.startsWith("flags:web/production")));
  assert.equal(result.summary.evaluated_flags, null, "no flag count is rendered from a denied listing");
  assert.equal(result.summary.individually_targeted_flags, null);
  assert.equal(result.summary.stale_flags, null);
  assert.equal(result.summary.prerequisite_cycles, null);
  // With every per-environment flag read denied the snapshot is one marker carrying each failed read, not an empty array.
  assert.ok(!Array.isArray(result.snapshots.flags));
  assert.deepEqual(
    { collected: result.snapshots.flags.collected, status: result.snapshots.flags.status, endpoint: result.snapshots.flags.endpoint, reason: result.snapshots.flags.reason, items: result.snapshots.flags.items },
    { collected: false, status: 403, endpoint: "GET /api/v2/flags/web?env=production", reason: "not_readable", items: null },
  );
  assert.deepEqual(result.snapshots.flags.failed_reads.map((read) => ({ environment: read.environment, status: read.status, collected: read.collected })), [
    { environment: "web/production", status: 403, collected: false },
  ]);
});

test("assessLaunchdarklyFlagHygiene never passes on truncated flag, project, or environment listings", async () => {
  const base = healthyClient();
  const truncatedFlags = await assessLaunchdarklyFlagHygiene(healthyClient({
    listFlags: (projectKey, environmentKey) => truncatedListing(base, "listFlags", 2, 900, projectKey, environmentKey),
  }), { now: NOW });
  for (const id of ["LD-14", "LD-15", "LD-25"]) {
    assert.equal(findingStatus(truncatedFlags, id), "warn", `${id} must not pass on 2 of 900 flags`);
    assert.match(finding(truncatedFlags, id).summary, /Truncated listing: flags for environment web\/production \(2 of 900 collected\)/);
    assert.match(finding(truncatedFlags, id).summary, /raise flag_limit/);
    assert.deepEqual(finding(truncatedFlags, id).evidence.truncated_collections, [
      { collection: "flags", option: "flag_limit", seen: 2, total: 900, scope: "environment web/production" },
    ]);
  }
  assert.equal(truncatedFlags.summary.evaluated_flags, 2);
  assert.equal(truncatedFlags.summary.truncated_collections, 1);
  assert.equal(truncatedFlags.snapshots.flags[0].truncated, true);
  assert.equal(truncatedFlags.snapshots.flags[0].total, 900);
  assert.equal(truncatedFlags.snapshots.flags[0].items.length, 2);

  const truncatedProjects = await assessLaunchdarklyFlagHygiene(healthyClient({
    listProjects: () => truncatedListing(base, "listProjects", 1, 12),
  }), { now: NOW });
  for (const id of ["LD-14", "LD-15", "LD-25"]) {
    assert.equal(findingStatus(truncatedProjects, id), "warn", `${id} must not pass on 1 of 12 projects`);
    assert.match(finding(truncatedProjects, id).summary, /projects \(1 of 12 collected\)/);
  }

  const truncatedEnvironments = await assessLaunchdarklyFlagHygiene(healthyClient({
    listEnvironments: (projectKey) => truncatedListing(base, "listEnvironments", 1, 9, projectKey),
  }), { now: NOW });
  for (const id of ["LD-14", "LD-15", "LD-25"]) {
    assert.equal(findingStatus(truncatedEnvironments, id), "warn", `${id} must not pass on 1 of 9 environments`);
    assert.match(finding(truncatedEnvironments, id).summary, /environments for project web \(1 of 9 collected\)/);
  }

  const failingAndTruncated = await assessLaunchdarklyFlagHygiene(healthyClient({
    async listFlags() {
      return {
        items: [{ key: "vip-access", creationDate: OLD_MS, environments: { production: { targets: [{ values: ["user-123"], variation: 0 }] } } }],
        truncated: true,
        seen: 1,
        total: 900,
      };
    },
  }), { now: NOW });
  assert.equal(findingStatus(failingAndTruncated, "LD-14"), "fail");
  assert.match(finding(failingAndTruncated, "LD-14").summary, /production targeting\. Truncated listing/);
});

test("assessLaunchdarklyMonitoringIntegrations does not pass relay scoping when referenced environments are truncated", async () => {
  const base = healthyClient();
  const result = await assessLaunchdarklyMonitoringIntegrations(healthyClient({
    listEnvironments: (projectKey) => truncatedListing(base, "listEnvironments", 1, 9, projectKey),
  }), { now: NOW });

  assert.equal(findingStatus(result, "LD-18"), "warn");
  assert.match(finding(result, "LD-18").summary, /environments for project web \(1 of 9 collected\)/);
  for (const id of ["LD-12", "LD-13", "LD-20", "LD-21"]) {
    assert.equal(findingStatus(result, id), "pass", `${id} is unaffected by environment truncation`);
  }
});

test("assessLaunchdarklyMonitoringIntegrations passes retained audit logs, scoped relay and integrations, and signed webhooks", async () => {
  const result = await assessLaunchdarklyMonitoringIntegrations(healthyClient(), { now: NOW });

  assert.deepEqual(result.findings.map((item) => item.control), [12, 13, 18, 20, 21]);
  for (const id of ["LD-12", "LD-13", "LD-18", "LD-20", "LD-21"]) {
    assert.equal(findingStatus(result, id), "pass", `${id} should pass`);
  }
  assert.deepEqual(finding(result, "LD-13").evidence.critical_actions_seen, ["createMember", "updatePolicy"]);
});

test("assessLaunchdarklyMonitoringIntegrations fails unreadable audit logs, broad relay and integration scopes, and insecure webhooks", async () => {
  const result = await assessLaunchdarklyMonitoringIntegrations(healthyClient({
    async listAuditLogEntries() {
      throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/auditlog");
    },
    async listRelayProxyConfigs() {
      return [{ name: "wide-open", lastModified: RECENT_MS, policy: [{ effect: "allow", actions: ["*"], resources: ["proj/*:env/*"] }] }];
    },
    async listIntegrationSubscriptions(integrationKey) {
      if (integrationKey !== "splunk") return [];
      return [{ name: "splunk-all", on: true, statements: [{ effect: "allow", actions: ["*"], resources: ["proj/*"] }] }];
    },
    async listWebhooks() {
      return [{ name: "legacy", url: "http://hooks.example.com/ld", on: true }];
    },
  }), { now: NOW });

  assert.equal(findingStatus(result, "LD-12"), "fail");
  assert.equal(findingStatus(result, "LD-13"), "fail");
  assert.equal(findingStatus(result, "LD-18"), "fail");
  assert.deepEqual(finding(result, "LD-18").evidence.broad_relay_configs, ["wide-open"]);
  assert.equal(findingStatus(result, "LD-20"), "fail");
  assert.equal(findingStatus(result, "LD-21"), "fail");
  assert.equal(finding(result, "LD-21").evidence.insecure_enabled_webhooks[0].https, false);
  assert.equal(finding(result, "LD-21").evidence.insecure_enabled_webhooks[0].signed, false);
  assert.equal(result.errors.length, 4);
});

test("assessLaunchdarklyMonitoringIntegrations warns on short retention and marks absent relay or integrations manual", async () => {
  const result = await assessLaunchdarklyMonitoringIntegrations(healthyClient({
    async listAuditLogEntries(query = {}) {
      if (query.before !== undefined) return [];
      return [{ date: RECENT_MS, kind: "flag", accesses: [{ action: "updateOn", resource: "proj/web:env/production:flag/x" }] }];
    },
    async listRelayProxyConfigs() {
      return [];
    },
    async listIntegrationSubscriptions() {
      return [];
    },
    async listWebhooks() {
      return [];
    },
  }), { now: NOW, retentionDays: 90 });

  assert.equal(findingStatus(result, "LD-12"), "warn");
  assert.equal(findingStatus(result, "LD-13"), "warn");
  assert.equal(findingStatus(result, "LD-18"), "manual");
  assert.equal(findingStatus(result, "LD-20"), "manual");
  assert.equal(findingStatus(result, "LD-21"), "pass");
});

function forbidden(endpoint) {
  return apiError(403, "Forbidden", `GET ${endpoint}`);
}

/** Denies the audit log queries `matches` selects, naming the request the way the client would (query parameters included). */
function forbidAuditQuery(base, matches) {
  return {
    async listAuditLogEntries(query = {}) {
      if (matches(query)) {
        const params = new URLSearchParams(Object.entries(query).map(([key, value]) => [key, String(value)]));
        throw forbidden(`/api/v2/auditlog${params.size > 0 ? `?${params}` : ""}`);
      }
      return base.listAuditLogEntries(query);
    },
  };
}

// Every LaunchDarkly finding whose verdict reads two or more collected inventories, with each secondary inventory
// forbidden in turn while the primary stays healthy. Status is what the finding must report; names is the inventory the
// summary must name. LD-08/09/10 also read members and the caller identity through the token inventory scope gate.
const LAUNCHDARKLY_MULTI_INVENTORY_CASES = [
  { id: "LD-01", assess: assessLaunchdarklyIdentity, secondary: "audit_log_account", status: "manual", baseline: "manual", names: /Unreadable inventory: audit_log_account \(GET \/api\/v2\/auditlog\?spec=acct: .*403 Forbidden/, overrides: (base) => forbidAuditQuery(base, (query) => query.spec === "acct") },
  { id: "LD-06", assess: assessLaunchdarklyIdentity, secondary: "teams", status: "manual", names: /Unreadable inventory: teams \(GET \/api\/v2\/teams\?expand=members: .*403 Forbidden/, overrides: () => ({ listTeams: async () => { throw forbidden("/api/v2/teams?expand=members"); } }) },
  { id: "LD-06", assess: assessLaunchdarklyIdentity, secondary: "members", status: "manual", names: /Unreadable inventory: members \(GET \/api\/v2\/members: .*403 Forbidden/, overrides: () => ({ listMembers: async () => { throw forbidden("/api/v2/members"); } }) },
  { id: "LD-07", assess: assessLaunchdarklyIdentity, secondary: "team_roles", status: "manual", names: /Unreadable inventory: team_roles for team platform \(GET \/api\/v2\/teams\/platform\/roles: .*403 Forbidden/, overrides: () => ({ listTeamRoles: async (teamKey) => { throw forbidden(`/api/v2/teams/${teamKey}/roles`); } }) },
  { id: "LD-07", assess: assessLaunchdarklyIdentity, secondary: "teams", status: "manual", names: /Unreadable inventory: teams \(GET \/api\/v2\/teams\?expand=members/, overrides: () => ({ listTeams: async () => { throw forbidden("/api/v2/teams?expand=members"); } }) },
  { id: "LD-08", assess: assessLaunchdarklyAccessControl, secondary: "members", status: "warn", names: /member inventory was unreadable \(GET \/api\/v2\/members: .*403 Forbidden/, overrides: () => ({ listMembers: async () => { throw forbidden("/api/v2/members"); } }) },
  { id: "LD-09", assess: assessLaunchdarklyAccessControl, secondary: "members", status: "warn", names: /member inventory was unreadable \(GET \/api\/v2\/members/, overrides: () => ({ listMembers: async () => { throw forbidden("/api/v2/members"); } }) },
  { id: "LD-10", assess: assessLaunchdarklyAccessControl, secondary: "members", status: "warn", names: /member inventory was unreadable \(GET \/api\/v2\/members/, overrides: () => ({ listMembers: async () => { throw forbidden("/api/v2/members"); } }) },
  { id: "LD-11", assess: assessLaunchdarklyAccessControl, secondary: "members", status: "manual", names: /Unreadable inventory: members \(GET \/api\/v2\/members: .*403 Forbidden/, overrides: () => ({ listMembers: async () => { throw forbidden("/api/v2/members"); } }) },
  { id: "LD-08", assess: assessLaunchdarklyAccessControl, secondary: "caller_identity", status: "warn", names: /The caller identity was not readable, so .* Unreadable inventory: caller_identity \(GET \/api\/v2\/caller-identity: .*403 Forbidden/, overrides: () => ({ getCallerIdentity: async () => { throw forbidden("/api/v2/caller-identity"); } }) },
  { id: "LD-09", assess: assessLaunchdarklyAccessControl, secondary: "caller_identity", status: "warn", names: /Unreadable inventory: caller_identity \(GET \/api\/v2\/caller-identity/, overrides: () => ({ getCallerIdentity: async () => { throw forbidden("/api/v2/caller-identity"); } }) },
  { id: "LD-10", assess: assessLaunchdarklyAccessControl, secondary: "caller_identity", status: "warn", names: /Unreadable inventory: caller_identity \(GET \/api\/v2\/caller-identity/, overrides: () => ({ getCallerIdentity: async () => { throw forbidden("/api/v2/caller-identity"); } }) },
  { id: "LD-11", assess: assessLaunchdarklyAccessControl, secondary: "caller_identity", status: "warn", names: /Unreadable inventory: caller_identity \(GET \/api\/v2\/caller-identity/, overrides: () => ({ getCallerIdentity: async () => { throw forbidden("/api/v2/caller-identity"); } }) },
  { id: "LD-16", assess: assessLaunchdarklyEnvironmentGovernance, secondary: "custom_roles", status: "manual", names: /Unreadable inventory: custom_roles \(GET \/api\/v2\/roles: .*403 Forbidden/, overrides: () => ({ listCustomRoles: async () => { throw forbidden("/api/v2/roles"); } }) },
  { id: "LD-16", assess: assessLaunchdarklyEnvironmentGovernance, secondary: "environments", status: "manual", names: /Unreadable inventory: environments for project web \(GET \/api\/v2\/projects\/web\/environments: .*403 Forbidden/, overrides: () => ({ listEnvironments: async (projectKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments`); } }) },
  { id: "LD-17", assess: assessLaunchdarklyEnvironmentGovernance, secondary: "environments", status: "manual", names: /Unreadable inventory: environments for project web \(GET \/api\/v2\/projects\/web\/environments/, overrides: () => ({ listEnvironments: async (projectKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments`); } }) },
  { id: "LD-19", assess: assessLaunchdarklyEnvironmentGovernance, secondary: "environments", status: "manual", names: /Unreadable inventory: environments for project web \(GET \/api\/v2\/projects\/web\/environments/, overrides: () => ({ listEnvironments: async (projectKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments`); } }) },
  { id: "LD-19", assess: assessLaunchdarklyEnvironmentGovernance, secondary: "sdk_keys", status: "manual", names: /SDK keys endpoint was not readable for any of the 2 environments\. .* Unreadable inventory: sdk_keys for environment web\/production \(GET \/api\/v2\/projects\/web\/environments\/production\/sdk-keys: .*403 Forbidden.*; sdk_keys for environment web\/staging \(GET \/api\/v2\/projects\/web\/environments\/staging\/sdk-keys: .*403 Forbidden/, overrides: () => ({ listSdkKeys: async (projectKey, environmentKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments/${environmentKey}/sdk-keys`); } }) },
  { id: "LD-23", assess: assessLaunchdarklyEnvironmentGovernance, secondary: "environments", status: "manual", names: /Unreadable inventory: environments for project web \(GET \/api\/v2\/projects\/web\/environments/, overrides: () => ({ listEnvironments: async (projectKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments`); } }) },
  { id: "LD-14", assess: assessLaunchdarklyFlagHygiene, secondary: "environments", status: "manual", names: /Unreadable inventory: environments for project web \(GET \/api\/v2\/projects\/web\/environments/, overrides: () => ({ listEnvironments: async (projectKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments`); } }) },
  { id: "LD-14", assess: assessLaunchdarklyFlagHygiene, secondary: "flags", status: "manual", names: /Unreadable inventory: flags for environment web\/production \(GET \/api\/v2\/flags\/web\?env=production: .*403 Forbidden/, overrides: () => ({ listFlags: async (projectKey, environmentKey) => { throw forbidden(`/api/v2/flags/${projectKey}?env=${environmentKey}`); } }) },
  { id: "LD-15", assess: assessLaunchdarklyFlagHygiene, secondary: "flag_statuses", status: "manual", names: /Unreadable inventory: flag_statuses for environment web\/production \(GET \/api\/v2\/flag-statuses\/web\/production: .*403 Forbidden/, overrides: () => ({ listFlagStatuses: async (projectKey, environmentKey) => { throw forbidden(`/api/v2/flag-statuses/${projectKey}/${environmentKey}`); } }) },
  { id: "LD-15", assess: assessLaunchdarklyFlagHygiene, secondary: "flags", status: "manual", names: /Unreadable inventory: flags for environment web\/production \(GET \/api\/v2\/flags\/web\?env=production/, overrides: () => ({ listFlags: async (projectKey, environmentKey) => { throw forbidden(`/api/v2/flags/${projectKey}?env=${environmentKey}`); } }) },
  { id: "LD-15", assess: assessLaunchdarklyFlagHygiene, secondary: "environments", status: "manual", names: /Unreadable inventory: environments for project web \(GET \/api\/v2\/projects\/web\/environments/, overrides: () => ({ listEnvironments: async (projectKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments`); } }) },
  { id: "LD-25", assess: assessLaunchdarklyFlagHygiene, secondary: "environments", status: "manual", names: /Unreadable inventory: environments for project web \(GET \/api\/v2\/projects\/web\/environments/, overrides: () => ({ listEnvironments: async (projectKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments`); } }) },
  { id: "LD-25", assess: assessLaunchdarklyFlagHygiene, secondary: "flags", status: "manual", names: /Unreadable inventory: flags for environment web\/production \(GET \/api\/v2\/flags\/web\?env=production/, overrides: () => ({ listFlags: async (projectKey, environmentKey) => { throw forbidden(`/api/v2/flags/${projectKey}?env=${environmentKey}`); } }) },
  { id: "LD-12", assess: assessLaunchdarklyMonitoringIntegrations, secondary: "audit_log_recent", status: "warn", names: /Unreadable inventory: audit_log_recent \(GET \/api\/v2\/auditlog: .*403 Forbidden/, overrides: (base) => forbidAuditQuery(base, (query) => query.before === undefined && query.spec === undefined) },
  { id: "LD-12", assess: assessLaunchdarklyMonitoringIntegrations, secondary: "audit_log_retention_probe", status: "manual", names: /Unreadable inventory: audit_log_retention_probe \(GET \/api\/v2\/auditlog\?before=\d{13}: .*403 Forbidden/, overrides: (base) => forbidAuditQuery(base, (query) => query.before !== undefined) },
  { id: "LD-13", assess: assessLaunchdarklyMonitoringIntegrations, secondary: "audit_log_members", status: "warn", names: /Unreadable inventory: audit_log_members \(GET \/api\/v2\/auditlog\?spec=member%2F\*: .*403 Forbidden/, overrides: (base) => forbidAuditQuery(base, (query) => query.spec === "member/*") },
  { id: "LD-13", assess: assessLaunchdarklyMonitoringIntegrations, secondary: "audit_log_roles", status: "warn", names: /Unreadable inventory: audit_log_roles \(GET \/api\/v2\/auditlog\?spec=role%2F\*: .*403 Forbidden/, overrides: (base) => forbidAuditQuery(base, (query) => query.spec === "role/*") },
  { id: "LD-18", assess: assessLaunchdarklyMonitoringIntegrations, secondary: "environments", status: "warn", names: /Unreadable inventory: environments for project web \(GET \/api\/v2\/projects\/web\/environments: .*403 Forbidden.*\), so secure mode on the production environments the Relay Proxy serves was not checked/, overrides: () => ({ listEnvironments: async (projectKey) => { throw forbidden(`/api/v2/projects/${projectKey}/environments`); } }) },
  { id: "LD-18", assess: assessLaunchdarklyMonitoringIntegrations, secondary: "projects", status: "warn", names: /Unreadable inventory: projects \(GET \/api\/v2\/projects\?filter=keys%3Aweb: .*403 Forbidden/, overrides: () => ({ listProjects: async (limit, projectKeys = []) => { throw forbidden(`/api/v2/projects${projectKeys.length > 0 ? `?filter=keys%3A${projectKeys.join("%7C")}` : ""}`); } }) },
  { id: "LD-18", assess: assessLaunchdarklyMonitoringIntegrations, secondary: "relay_proxy_configs", status: "manual", names: /Unreadable inventory: relay_proxy_configs \(GET \/api\/v2\/account\/relay-auto-configs: .*403 Forbidden/, overrides: () => ({ listRelayProxyConfigs: async () => { throw forbidden("/api/v2/account/relay-auto-configs"); } }) },
  { id: "LD-20", assess: assessLaunchdarklyMonitoringIntegrations, secondary: "integration_subscriptions:splunk", status: "warn", names: /Unreadable inventory: integration_subscriptions for splunk \(GET \/api\/v2\/integrations\/splunk: .*403 Forbidden.*\), so splunk audit log subscriptions were not checked/, overrides: (base) => ({ async listIntegrationSubscriptions(key) { if (key === "splunk") throw forbidden(`/api/v2/integrations/${key}`); return base.listIntegrationSubscriptions(key); } }) },
];

test("verdict rule 1 corollary: LaunchDarkly findings that read several inventories never pass while a secondary inventory is forbidden", async () => {
  const baselines = new Map();
  for (const item of LAUNCHDARKLY_MULTI_INVENTORY_CASES) {
    if (!baselines.has(item.assess)) baselines.set(item.assess, await item.assess(healthyClient(), { now: NOW }));
    const baseline = baselines.get(item.assess);
    assert.equal(findingStatus(baseline, item.id), item.baseline ?? "pass", `${item.id} baseline on the healthy fixture`);

    const base = healthyClient();
    const result = await item.assess(healthyClient(item.overrides(base)), { now: NOW });
    const found = finding(result, item.id);
    const label = `${item.id} with ${item.secondary} forbidden`;
    assert.notEqual(found.status, "pass", `${label} must not pass`);
    assert.equal(found.status, item.status, `${label} status`);
    assert.match(found.summary, item.names, `${label} must name the unreadable inventory`);
    assert.match(found.summary, /403 Forbidden/, `${label} must carry the HTTP error`);
    if (/Unreadable inventory:/.test(found.summary)) {
      assert.match(found.summary, /Collect manually: /, `${label} must tell the human what to collect`);
      assert.ok(Array.isArray(found.evidence.unreadable_inventories) && found.evidence.unreadable_inventories.length > 0, `${label} evidence lists the gap`);
      assert.ok(found.evidence.manual_evidence.length > 0, `${label} evidence names manual evidence`);
    }
  }
});

test("verdict rule 1 corollary: LaunchDarkly findings keep judging readable inventories and fail when the readable half fails", async () => {
  const base = healthyClient();
  const partialTeams = await assessLaunchdarklyIdentity(healthyClient({
    async listTeams() {
      return [{ key: "platform", name: "Platform" }, { key: "data", name: "Data" }];
    },
    async listTeamRoles(teamKey) {
      if (teamKey === "data") throw forbidden("/api/v2/teams/data/roles");
      return base.listTeamRoles(teamKey);
    },
  }), { now: NOW });
  assert.equal(findingStatus(partialTeams, "LD-07"), "warn", "one unreadable team role listing demotes but does not fail");
  assert.match(finding(partialTeams, "LD-07").summary, /All 1 sampled teams with readable roles have at least one custom role assigned/);
  assert.match(finding(partialTeams, "LD-07").summary, /team_roles for team data/);
  assert.deepEqual(finding(partialTeams, "LD-07").evidence.teams_with_unreadable_roles, ["data"]);
  // An unreadable role listing is neither counted as zero roles nor used to assert that every team has one.
  assert.equal(finding(partialTeams, "LD-07").evidence.teams_without_custom_roles, null);
  assert.equal(partialTeams.summary.teams_without_custom_roles, null);

  const failingAndGapped = await assessLaunchdarklyMonitoringIntegrations(healthyClient({
    ...forbidAuditQuery(base, (query) => query.spec === "role/*"),
    async listWebhooks() {
      return [{ name: "legacy", url: "http://hooks.example.com/ld", on: true }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(failingAndGapped, "LD-13"), "warn");
  assert.match(finding(failingAndGapped, "LD-13").summary, /^Audit log entries for member resources are present with critical actions \(createMember\)\. Unreadable inventory: audit_log_roles/);
  assert.equal(findingStatus(failingAndGapped, "LD-21"), "fail", "a readable insecure webhook still fails");
  assert.equal(findingStatus(failingAndGapped, "LD-12"), "pass", "LD-12 does not read the role audit query");

  const allAudit = await assessLaunchdarklyMonitoringIntegrations(healthyClient({
    async listAuditLogEntries() {
      throw forbidden("/api/v2/auditlog");
    },
  }), { now: NOW });
  assert.equal(findingStatus(allAudit, "LD-12"), "fail", "a wholly unreadable audit log remains a fail");
  assert.equal(findingStatus(allAudit, "LD-13"), "fail");
});

const LAUNCHDARKLY_FAKE_SECRETS = [
  "FAKE_WEBHOOK_PATH_TOKEN_1",
  "FAKE_WEBHOOK_QUERY_TOKEN_2",
  "FAKE_INTEGRATION_URL_TOKEN_3",
  "FAKE_INTEGRATION_HEADER_TOKEN_4",
  "FAKE_INTEGRATION_NESTED_KEY_5",
  "FAKE_FLAG_VARIATION_SECRET_6",
  "FAKE_ACCESS_TOKEN_VALUE_7",
  "FAKE_RELAY_FULL_KEY_8",
  "FAKE_PROJECT_ENV_API_KEY_9",
  "sdk-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
];

function secretBearingLaunchdarklyClient() {
  const base = healthyClient();
  return healthyClient({
    async listWebhooks() {
      return [{ _id: "wh-1", name: "ci-hook", url: `https://hooks.example.com/services/T0/B0/${LAUNCHDARKLY_FAKE_SECRETS[0]}?token=${LAUNCHDARKLY_FAKE_SECRETS[1]}`, secret: "whsec_FAKE", on: true }];
    },
    async listIntegrationSubscriptions(integrationKey) {
      if (integrationKey !== "datadog") return [];
      return [{
        _id: "sub-1",
        name: "datadog-prod",
        on: true,
        config: {
          url: `https://hooks.example.com/services/${LAUNCHDARKLY_FAKE_SECRETS[2]}`,
          headers: [{ name: "Authorization", value: `Bearer ${LAUNCHDARKLY_FAKE_SECRETS[3]}` }],
          destination: { credentials: { apiKey: LAUNCHDARKLY_FAKE_SECRETS[4] } },
        },
        statements: [{ effect: "allow", actions: ["updateOn", "updateRules"], resources: ["proj/web:env/production:flag/*"] }],
      }];
    },
    async listFlags(...args) {
      const flags = await base.listFlags(...args);
      return flags.map((flag) => ({
        ...flag,
        variations: [{ value: { apiSecret: LAUNCHDARKLY_FAKE_SECRETS[5] }, name: "on" }, { value: false, name: "off" }],
        environments: { production: { ...flag.environments.production, on: true, rules: [{ clauses: [{ attribute: "email", op: "in", values: [LAUNCHDARKLY_FAKE_SECRETS[5]] }] }] } },
      }));
    },
    async listTokens() {
      const tokens = await base.listTokens();
      return tokens.map((token) => ({ ...token, token: LAUNCHDARKLY_FAKE_SECRETS[6] }));
    },
    async listRelayProxyConfigs() {
      const relays = await base.listRelayProxyConfigs();
      return relays.map((relay) => ({ ...relay, fullKey: LAUNCHDARKLY_FAKE_SECRETS[7], displayKey: "y-8" }));
    },
    async listProjects() {
      return [{ key: "web", name: "Web App", tags: [], environments: [{ key: "production", apiKey: LAUNCHDARKLY_FAKE_SECRETS[8], mobileKey: "mob-FAKE" }] }];
    },
    async listSdkKeys() {
      return [{ key: LAUNCHDARKLY_FAKE_SECRETS[9], kind: "sdk", _createdAt: RECENT_MS, isDefault: true, value: LAUNCHDARKLY_FAKE_SECRETS[9] }];
    },
  });
}

test("verdict rule 9: the LaunchDarkly bundle and its zip never carry credential-shaped values or token-bearing URLs from any collected object", async () => {
  const base = createTempBase("grclanker-ld-secrets-");
  const result = await exportLaunchdarklyAuditBundle(secretBearingLaunchdarklyClient(), sampleConfig(), base, { now: NOW });

  assert.equal(result.findingCount, 25);
  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size >= 30, "the bundle directory was written");
  assert.ok(entries.size >= 30, "the zip archive carries the bundle files");
  assertSecretsAbsent(assert, files, [...LAUNCHDARKLY_FAKE_SECRETS, TEST_TOKEN], "bundle file");
  assertSecretsAbsent(assert, entries, [...LAUNCHDARKLY_FAKE_SECRETS, TEST_TOKEN], "zip entry");

  const webhooks = JSON.parse(files.get(join("core_data", "webhooks.json")));
  assert.equal(webhooks.items[0].url, "https://hooks.example.com", "the webhook destination is reduced to scheme plus host");
  assert.equal(webhooks.items[0].secret, "[REDACTED]");
  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  const webhookFinding = findings.find((item) => item.id === "LD-21");
  assert.equal(webhookFinding.status, "pass", "an HTTPS signed webhook still passes on the reduced URL");
  const subscriptions = JSON.parse(files.get(join("core_data", "integration_subscriptions.json")));
  const config = subscriptions[0].items[0].config;
  assert.equal(config.url, "https://hooks.example.com");
  assert.deepEqual(config.headers, [{ name: "Authorization", value: "[REDACTED]" }]);
  assert.equal(config.destination.credentials.apiKey, "[REDACTED]");
  const flags = JSON.parse(files.get(join("core_data", "flags.json")));
  assert.equal(flags[0].items[0].variations, 2, "flag variations are projected to a count");
  assert.equal(flags[0].items[0].environments.production.rules, 1, "rule clauses are projected to a count");
  assert.equal(flags[0].items[0].key, "checkout-v2");
  const tokens = JSON.parse(files.get(join("core_data", "access_tokens.json")));
  assert.ok(tokens.items.every((token) => token.token === "[REDACTED]"));
  const relays = JSON.parse(files.get(join("core_data", "relay_proxy_configs.json")));
  assert.equal(relays.items[0].fullKey, "[REDACTED]");
  assert.equal(relays.items[0].displayKey, "y-8");
  const projects = JSON.parse(files.get(join("core_data", "projects.json")));
  assert.equal(projects.items[0].environments[0].apiKey, "[REDACTED]", "environments embedded in the project rep are redacted");
  const sdkKeys = JSON.parse(files.get(join("core_data", "sdk_keys.json")));
  assert.equal(sdkKeys[0].items[0].value, "[REDACTED]");
  assert.equal(sdkKeys[0].items[0].key, "[REDACTED]", "an SDK-key-shaped key field is scrubbed");
});

test("LAUNCHDARKLY_CONTROL_CATALOG covers all 25 spec controls with every framework mapping", () => {
  const controls = Object.keys(LAUNCHDARKLY_CONTROL_CATALOG).map(Number).sort((left, right) => left - right);
  assert.deepEqual(controls, Array.from({ length: 25 }, (_value, index) => index + 1));
  for (const definition of Object.values(LAUNCHDARKLY_CONTROL_CATALOG)) {
    assert.deepEqual(Object.keys(definition.frameworks).sort(), ["cis", "cmmc", "fedramp", "irap", "ismap", "pci_dss", "soc2", "stig"]);
    assert.ok(Object.values(definition.frameworks).every((mapping) => typeof mapping === "string" && mapping.length > 0));
  }
  assert.equal(LAUNCHDARKLY_CONTROL_CATALOG[18].frameworks.stig, "SRG-APP-000439");
  assert.equal(LAUNCHDARKLY_CONTROL_CATALOG[25].frameworks.ismap, "CPS-10.5");
});

function listFilesRecursively(root) {
  const files = [];
  for (const entry of readdirSync(root)) {
    const pathname = join(root, entry);
    if (statSync(pathname).isDirectory()) {
      files.push(...listFilesRecursively(pathname));
    } else {
      files.push(pathname);
    }
  }
  return files;
}

test("exportLaunchdarklyAuditBundle writes core data, analysis, compliance reports, quick reference, and zip", async () => {
  const base = createTempBase("grclanker-ld-export-");
  const result = await exportLaunchdarklyAuditBundle(healthyClient(), sampleConfig(), base, { now: NOW });

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.match(result.zipPath, /app\.launchdarkly\.com-acct-123-audit-bundle\.zip$/);
  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 30);

  const expected = [
    "metadata.json",
    "QUICK_REFERENCE.md",
    join("core_data", "access_check.json"),
    join("core_data", "members.json"),
    join("core_data", "teams.json"),
    join("core_data", "custom_roles.json"),
    join("core_data", "access_tokens.json"),
    join("core_data", "projects.json"),
    join("core_data", "environments.json"),
    join("core_data", "sdk_keys.json"),
    join("core_data", "flags.json"),
    join("core_data", "flag_statuses.json"),
    join("core_data", "audit_log_recent.json"),
    join("core_data", "relay_proxy_configs.json"),
    join("core_data", "integration_subscriptions.json"),
    join("core_data", "webhooks.json"),
    join("analysis", "findings.json"),
    join("analysis", "summary.md"),
    join("analysis", "identity.json"),
    join("analysis", "access_control.json"),
    join("analysis", "environment_governance.json"),
    join("analysis", "flag_hygiene.json"),
    join("analysis", "monitoring_integrations.json"),
    join("compliance", "executive_summary.md"),
    join("compliance", "unified_compliance_matrix.md"),
    join("compliance", "fedramp", "fedramp_compliance_report.md"),
    join("compliance", "cmmc", "cmmc_compliance_report.md"),
    join("compliance", "soc2", "soc2_compliance_report.md"),
    join("compliance", "cis", "cis_controls_report.md"),
    join("compliance", "pci_dss", "pci_dss_compliance_report.md"),
    join("compliance", "disa_stig", "stig_compliance_checklist.md"),
    join("compliance", "irap", "irap_compliance_report.md"),
    join("compliance", "ismap", "ismap_compliance_report.md"),
  ];
  for (const relativePath of expected) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `${relativePath} should exist`);
  }
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.account_id, "acct-123");
  assert.equal(metadata.controls_evaluated, 25);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  const ids = findings.map((item) => item.id).sort();
  assert.deepEqual(ids, Array.from({ length: 25 }, (_value, index) => `LD-${String(index + 1).padStart(2, "0")}`));
  assert.ok(findings.every((item) => item.mappings.length === 8));

  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /\| Control \| Title \| Status \| Severity \| FedRAMP \| CMMC \| SOC 2 \| CIS \| PCI-DSS \| STIG \| IRAP \| ISMAP \|/);
  assert.match(matrix, /LD-25/);

  const executive = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executive, /25 of 25 spec controls evaluated/);
  assert.match(executive, /Manual Verification Required/);

  for (const file of listFilesRecursively(result.outputDir)) {
    assert.ok(!readFileSync(file, "utf8").includes(TEST_TOKEN), `${file} must not contain the access token`);
  }
  assert.equal(statSync(result.zipPath).mode & 0o077, 0);
});

test("exportLaunchdarklyAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("grclanker-ld-export-errors-");
  const client = healthyClient({
    async listWebhooks() {
      throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/webhooks: access_denied");
    },
  });
  const result = await exportLaunchdarklyAuditBundle(client, sampleConfig(), base, { now: NOW });

  assert.equal(result.findingCount, 25);
  assert.ok(result.errorCount >= 1);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /webhooks/);
  assert.match(errorLog, /403 Forbidden/);
  const executive = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executive, /Partial Collection Warnings/);
});

test("exportLaunchdarklyAuditBundle records truncated listings in core data snapshots and the executive summary", async () => {
  const base = createTempBase("grclanker-ld-export-truncated-");
  const reference = healthyClient();
  const result = await exportLaunchdarklyAuditBundle(healthyClient({
    listMembers: () => truncatedListing(reference, "listMembers", 3, 400),
  }), sampleConfig(), base, { now: NOW });

  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 0);
  const members = JSON.parse(readFileSync(join(result.outputDir, "core_data", "members.json"), "utf8"));
  assert.equal(members.truncated, true);
  assert.equal(members.seen, 3);
  assert.equal(members.total, 400);
  assert.equal(members.items.length, 3);
  const roles = JSON.parse(readFileSync(join(result.outputDir, "core_data", "custom_roles.json"), "utf8"));
  assert.equal(roles.truncated, false);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  const mfa = findings.find((item) => item.id === "LD-02");
  assert.equal(mfa.status, "warn");
  assert.deepEqual(mfa.evidence.truncated_collections, [{ collection: "members", option: "member_limit", seen: 3, total: 400 }]);

  const executive = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executive, /## Truncated Listings/);
  assert.match(executive, /- members: 3 of 400 collected; raise member_limit/);
  assert.doesNotMatch(executive, /Partial Collection Warnings/);
});

test("exportLaunchdarklyAuditBundle keeps directory and zip paired across repeated exports", async () => {
  const base = createTempBase("grclanker-ld-export-dupe-");
  const first = await exportLaunchdarklyAuditBundle(healthyClient(), sampleConfig(), base, { now: NOW });
  const firstZipSize = statSync(first.zipPath).size;
  const second = await exportLaunchdarklyAuditBundle(healthyClient(), sampleConfig(), base, { now: NOW });

  assert.notEqual(first.outputDir, second.outputDir);
  assert.match(second.outputDir, /-audit-bundle-2$/);
  assert.notEqual(first.zipPath, second.zipPath);
  assert.match(first.zipPath, /app\.launchdarkly\.com-acct-123-audit-bundle\.zip$/);
  assert.match(second.zipPath, /app\.launchdarkly\.com-acct-123-audit-bundle-2\.zip$/);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
  assert.equal(statSync(first.zipPath).size, firstZipSize);

  rmSync(second.outputDir, { recursive: true, force: true });
  const third = await exportLaunchdarklyAuditBundle(healthyClient(), sampleConfig(), base, { now: NOW });
  assert.match(third.outputDir, /-audit-bundle-3$/);
  assert.equal(third.zipPath, `${third.outputDir}.zip`);
  assert.ok(existsSync(second.zipPath));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-ld-path-");
  const outside = createTempBase("grclanker-ld-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, join("..", "..", "etc", "passwd")), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("compliance", "safe.md"));
  assert.match(safe, /compliance\/safe\.md$/);
});

test("LaunchDarkly tools are registered in the tool catalog under the LaunchDarkly group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("launchdarkly_"));
  const names = tools.map((tool) => tool.name).sort();

  assert.deepEqual(names, [
    "launchdarkly_assess_access_control",
    "launchdarkly_assess_environment_governance",
    "launchdarkly_assess_flag_hygiene",
    "launchdarkly_assess_identity",
    "launchdarkly_assess_monitoring_integrations",
    "launchdarkly_check_access",
    "launchdarkly_export_audit_bundle",
  ]);
  assert.ok(tools.every((tool) => tool.group === "LaunchDarkly"));
  assert.ok(tools.every((tool) => tool.kind === "domain"));
  assert.ok(tools.every((tool) => tool.parameterSummaries.some((parameter) => parameter.name === "token")));
  const exportTool = tools.find((tool) => tool.name === "launchdarkly_export_audit_bundle");
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "output_dir"));
  assert.ok(tools.every((tool) => !tool.description.includes("\u2014")));
});
