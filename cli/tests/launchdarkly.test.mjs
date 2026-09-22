import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
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
  registerLaunchdarklyTools,
  resolveLaunchdarklyConfiguration,
  resolveSecureOutputPath,
  scrubErrorText,
} from "../dist/extensions/grc-tools/launchdarkly.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import { assertCanaryFixture, assertCanaryWindowsAbsent } from "./helpers/canary-windows.mjs";

const NOW = Date.parse("2026-09-21T00:00:00Z");
const RECENT = "2026-09-15T00:00:00Z";
const RECENT_MS = Date.parse(RECENT);
const OLD = "2025-01-01T00:00:00Z";
const OLD_MS = Date.parse(OLD);
const FUTURE_MS = NOW + 90 * 24 * 60 * 60 * 1000;
// The configured token is itself a planted credential: alphanumeric and random-looking so every 6-to-24-character
// window of it can be asserted absent from every output (see helpers/canary-windows.mjs).
const TEST_TOKEN = "U7ktAa5zEHKELrac4CfrjWJF3zBQuiEx";

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

// Credential values planted in collected objects. Alphanumeric and random-looking so that every 6-to-24-character window
// can be asserted absent; the SDK key keeps LaunchDarkly's sdk-<uuid> shape around a random hex body.
const LD_SDK_KEY_HEX = "e83bd5a5f00659aed175191b7953c460";
const LD_SDK_KEY_CANARY = `sdk-${LD_SDK_KEY_HEX.slice(0, 8)}-${LD_SDK_KEY_HEX.slice(8, 12)}-${LD_SDK_KEY_HEX.slice(12, 16)}-${LD_SDK_KEY_HEX.slice(16, 20)}-${LD_SDK_KEY_HEX.slice(20)}`;
const LAUNCHDARKLY_FAKE_SECRETS = {
  webhookPath: "pPXDbR3TsHbMajWLVZ4nDenRJ5eXtCZY",
  webhookQuery: "wfT9kKT8uFCLktEKb9jXg3hnVJebXMNZ",
  integrationUrl: "b2aNgSfKeEHwSMN33X77Bof3JZStQBGg",
  integrationHeader: "HEi8h3UJAs8Zn8CFUV6vkBT684NbuKY4",
  integrationNestedKey: "4idBU9tWqjTjawfBTxvH68aXvkfESBG3",
  flagVariation: "YJLeRkSTZCiKDoe8ZvaSi3NYxMZ4UHTa",
  accessTokenValue: "WB3FfAGQCKmcpSbk7MGRBT5tshEK3rrL",
  relayFullKey: "uCANkAy4FHeqgLEqUbRo93C8P7NAJbBf",
  projectEnvApiKey: "BYAE7HSiWwjvHTvPPwjGYcJbPxHBW7tY",
  sdkKey: LD_SDK_KEY_CANARY,
};

function secretBearingLaunchdarklyClient() {
  const base = healthyClient();
  const secrets = LAUNCHDARKLY_FAKE_SECRETS;
  return healthyClient({
    async listWebhooks() {
      return [{ _id: "wh-1", name: "ci-hook", url: `https://hooks.example.com/services/T0/B0/${secrets.webhookPath}?token=${secrets.webhookQuery}`, secret: "whsec_FAKE", on: true }];
    },
    async listIntegrationSubscriptions(integrationKey) {
      if (integrationKey !== "datadog") return [];
      return [{
        _id: "sub-1",
        name: "datadog-prod",
        on: true,
        config: {
          url: `https://hooks.example.com/services/${secrets.integrationUrl}`,
          headers: [{ name: "Authorization", value: `Bearer ${secrets.integrationHeader}` }],
          destination: { credentials: { apiKey: secrets.integrationNestedKey } },
        },
        statements: [{ effect: "allow", actions: ["updateOn", "updateRules"], resources: ["proj/web:env/production:flag/*"] }],
      }];
    },
    async listFlags(...args) {
      const flags = await base.listFlags(...args);
      return flags.map((flag) => ({
        ...flag,
        variations: [{ value: { apiSecret: secrets.flagVariation }, name: "on" }, { value: false, name: "off" }],
        environments: { production: { ...flag.environments.production, on: true, rules: [{ clauses: [{ attribute: "email", op: "in", values: [secrets.flagVariation] }] }] } },
      }));
    },
    async listTokens() {
      const tokens = await base.listTokens();
      return tokens.map((token) => ({ ...token, token: secrets.accessTokenValue }));
    },
    async listRelayProxyConfigs() {
      const relays = await base.listRelayProxyConfigs();
      return relays.map((relay) => ({ ...relay, fullKey: secrets.relayFullKey, displayKey: "y-8" }));
    },
    async listProjects() {
      return [{ key: "web", name: "Web App", tags: [], environments: [{ key: "production", apiKey: secrets.projectEnvApiKey, mobileKey: "mob-FAKE" }] }];
    },
    async listSdkKeys() {
      return [{ key: secrets.sdkKey, kind: "sdk", _createdAt: RECENT_MS, isDefault: true, value: secrets.sdkKey }];
    },
  });
}

test("verdict rule 9: the LaunchDarkly bundle and its zip never carry credential-shaped values or token-bearing URLs from any collected object", async () => {
  const base = createTempBase("grclanker-ld-secrets-");
  // Self-check: the planted values share no 6-character window with each other or with the healthy fixture's own output.
  const baseline = await exportLaunchdarklyAuditBundle(healthyClient(), sampleConfig({ token: "not-a-canary" }), createTempBase("grclanker-ld-secrets-baseline-"), { now: NOW });
  const plantedAlphanumeric = [...Object.values(LAUNCHDARKLY_FAKE_SECRETS).filter((value) => value !== LD_SDK_KEY_CANARY), LD_SDK_KEY_HEX, TEST_TOKEN];
  assertCanaryFixture(assert, plantedAlphanumeric, readBundleFiles(baseline.outputDir), "collected-object canaries");

  const result = await exportLaunchdarklyAuditBundle(secretBearingLaunchdarklyClient(), sampleConfig(), base, { now: NOW });

  assert.equal(result.findingCount, 25);
  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size >= 30, "the bundle directory was written");
  assert.ok(entries.size >= 30, "the zip archive carries the bundle files");
  const planted = [...Object.values(LAUNCHDARKLY_FAKE_SECRETS), TEST_TOKEN];
  assertCanaryWindowsAbsent(assert, files, planted, "bundle file");
  assertCanaryWindowsAbsent(assert, entries, planted, "zip entry");

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

// ---------------------------------------------------------------------------------------------------------------
// Addenda 2 to 7: the real client over an HTTP router that records every request the run makes.
// ---------------------------------------------------------------------------------------------------------------

// Every planted credential is alphanumeric and random-looking; helpers/canary-windows.mjs asserts every 6-to-24-character
// window of each one absent, and the fixture self-check below proves no window occurs in the fixture's own values.
const LD_CANARIES = {
  bearer: "aMF3WGwJ9UKifFXjxkPA8WexoDtcP4ZT",
  cookie: "wDLfuP8P7gnn3JsU2DT3XrCUrQwJLnZ7",
  apiKey: "QJGjPixxDSCkGNoArXMeL2USsBcdGfdd",
  urlToken: "PCWXTXXWpLrVFgXp2SPm7YQKZgcAgWUx",
  jwtHeader: "aNrGBaN7JZ6Gfs4wQKAgRchyWs4dGuV2",
  jwtPayload: "9uZpMZQPRAt8TdXJ6H77iwUnT5TzR6H3",
  jwtSignature: "YQex5tM7P4nUAJd5oXvRWDYC72r5sFqQ",
};
const LD_JWT_CANARY = `eyJ${LD_CANARIES.jwtHeader}.${LD_CANARIES.jwtPayload}.${LD_CANARIES.jwtSignature}`;

const LD_HTML_ERROR_BODY = `<html><body><h1>502 Bad Gateway</h1><p>upstream sent Authorization: Bearer ${LD_CANARIES.bearer}; Set-Cookie: session=${LD_CANARIES.cookie}; api_key=${LD_CANARIES.apiKey}; retry at https://api.example.com/v1/x?token=${LD_CANARIES.urlToken} later; jwt ${LD_JWT_CANARY}</p></body></html>`;

/** A proxy error page: non-JSON, carrying every credential class in its body. */
function ldHtmlGateway() {
  return () => new Response(LD_HTML_ERROR_BODY, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

/** LaunchDarkly's documented JSON error shape whose message embeds a URL with a credential in its query string. */
function ldJsonForbiddenWithUrl() {
  return () => jsonResponse({ code: "forbidden", message: `Forbidden; see https://api.example.com/v1/x?token=${LD_CANARIES.urlToken} for details` }, { status: 403, statusText: "Forbidden" });
}

/** A JSON 401 whose long message places the configured token across the 300-character cut of the quoted message. */
function ldJsonUnauthorizedWithSplitToken() {
  const padding = "The request was rejected by the account policy engine. ".repeat(5);
  return () => jsonResponse({ code: "unauthorized", message: `${padding.slice(0, 288)}${TEST_TOKEN} is not an active token` }, { status: 401, statusText: "Unauthorized" });
}

function ldNotFound() {
  return () => jsonResponse({ code: "not_found", message: "Not Found" }, { status: 404, statusText: "Not Found" });
}

/** The all-readable data the router serves: the same records healthyClient() returns, as plain data keyed by scope. */
function ldFixture() {
  const production = { key: "production", name: "Production", critical: true, secureMode: true, defaultTtl: 5, confirmChanges: true, requireComments: true, approvalSettings: { required: true, bypassApprovalsForPendingChanges: false, canReviewOwnRequest: false, minNumApprovals: 1 }, apiKey: "****abcd" };
  const staging = { key: "staging", name: "Staging", critical: false, secureMode: false, defaultTtl: 0 };
  return {
    identity: { accountId: "acct-123", memberId: "m1", tokenId: "tok-1", tokenName: "grc-audit", serviceToken: false },
    members: [
      { _id: "m1", email: "owner@example.com", role: "owner", mfa: "enabled", mfaEnforced: true, teams: [{ key: "platform" }], _integrationMetadata: { externalId: "idp-1" } },
      { _id: "m2", email: "dev@example.com", role: "writer", mfa: "enabled", teams: [{ key: "platform" }] },
      { _id: "m3", email: "invitee@example.com", role: "reader", mfa: "disabled", _pendingInvite: true, teams: [] },
    ],
    teams: [{ key: "platform", name: "Platform" }],
    teamRoles: { platform: [{ key: "release-manager", name: "Release manager" }] },
    customRoles: [{ key: "release-manager", basePermissions: "no_access", policy: [
      { effect: "allow", actions: ["updateOn", "updateRules"], resources: ["proj/*:env/production:flag/*"] },
      { effect: "deny", actions: ["updateOn"], resources: ["proj/*:env/*;{critical:true}:flag/*"] },
    ] }],
    projects: [{ key: "web", name: "Web App", tags: [] }],
    environments: { web: [production, staging] },
    sdkKeys: { "web/production": [{ key: "sdk-current", kind: "sdk", _createdAt: RECENT_MS, isDefault: true, value: "****wxyz" }], "web/staging": [{ key: "sdk-staging", kind: "sdk", _createdAt: RECENT_MS, isDefault: true, value: "****stag" }] },
    flags: { web: [
      { key: "checkout-v2", creationDate: OLD_MS, environments: { production: { targets: [], contextTargets: [], prerequisites: [{ key: "payments-enabled", variation: 0 }] } } },
      { key: "payments-enabled", creationDate: OLD_MS, environments: { production: { targets: [], contextTargets: [], prerequisites: [] } } },
    ] },
    flagStatuses: { "web/production": [
      { name: "active", lastRequested: RECENT, _links: { parent: { href: "/api/v2/flags/web/checkout-v2" } } },
      { name: "launched", lastRequested: RECENT, _links: { parent: { href: "/api/v2/flags/web/payments-enabled" } } },
    ] },
    auditLog: {
      recent: [{ date: RECENT_MS, kind: "flag", accesses: [{ action: "updateOn", resource: "proj/web:env/production:flag/checkout-v2" }] }],
      retention: [{ date: OLD_MS, kind: "flag", accesses: [{ action: "updateOn", resource: "proj/web:env/production:flag/x" }] }],
      members: [{ date: RECENT_MS, kind: "member", accesses: [{ action: "createMember", resource: "member/m2" }] }],
      roles: [{ date: RECENT_MS, kind: "role", accesses: [{ action: "updatePolicy", resource: "role/release-manager" }] }],
      account: [{ date: RECENT_MS, kind: "account", title: "Require SSO enabled", accesses: [{ action: "updateSamlRequireSso", resource: "acct" }] }],
    },
    tokens: [
      { _id: "tok-1", name: "grc-audit", role: "admin", serviceToken: false, memberId: "m1", expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: RECENT_MS },
      { _id: "t1", name: "ci-service", token: "api-xxxxxxxx-1234", role: "reader", serviceToken: true, expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: OLD_MS, customRoleIds: ["release-manager"] },
      { _id: "t2", name: "dev-personal", role: "writer", serviceToken: false, memberId: "m2", expiry: FUTURE_MS, lastUsed: RECENT_MS, creationDate: RECENT_MS },
    ],
    webhooks: [{ _id: "wh-1", name: "ci-hook", url: "https://hooks.example.com/ld", secret: "[REDACTED]", on: true }],
    integrations: { datadog: [{ _id: "sub-1", name: "datadog-prod", on: true, statements: [{ effect: "allow", actions: ["updateOn", "updateRules"], resources: ["proj/web:env/production:flag/*"] }] }] },
    relayConfigs: [{ _id: "relay-1", name: "edge-relay", lastModified: RECENT_MS, creationDate: OLD_MS, policy: [{ effect: "allow", actions: ["*"], resources: ["proj/web:env/production"] }] }],
  };
}

/** One page of a LaunchDarkly collection: items, totalCount, and a _links.next href while more remain. */
function ldPage(items, url) {
  const limit = Number(url.searchParams.get("limit") ?? "20");
  const offset = Number(url.searchParams.get("offset") ?? "0");
  const page = items.slice(offset, offset + limit);
  const links = { self: { href: `${url.pathname}${url.search}` } };
  if (offset + page.length < items.length) {
    const next = new URLSearchParams(url.searchParams);
    next.set("offset", String(offset + page.length));
    links.next = { href: `${url.pathname}?${next}` };
  }
  return jsonResponse({ items: page, totalCount: items.length, _links: links });
}

const LD_ROUTE_TEMPLATES = [
  ["GET /api/v2/caller-identity", /^\/api\/v2\/caller-identity$/],
  ["GET /api/v2/members", /^\/api\/v2\/members$/],
  ["GET /api/v2/teams", /^\/api\/v2\/teams$/],
  ["GET /api/v2/teams/{team}/roles", /^\/api\/v2\/teams\/([^/]+)\/roles$/],
  ["GET /api/v2/roles", /^\/api\/v2\/roles$/],
  ["GET /api/v2/projects", /^\/api\/v2\/projects$/],
  ["GET /api/v2/projects/{project}/environments", /^\/api\/v2\/projects\/([^/]+)\/environments$/],
  ["GET /api/v2/projects/{project}/environments/{environment}/sdk-keys", /^\/api\/v2\/projects\/([^/]+)\/environments\/([^/]+)\/sdk-keys$/],
  ["GET /api/v2/flags/{project}", /^\/api\/v2\/flags\/([^/]+)$/],
  ["GET /api/v2/flag-statuses/{project}/{environment}", /^\/api\/v2\/flag-statuses\/([^/]+)\/([^/]+)$/],
  ["GET /api/v2/auditlog", /^\/api\/v2\/auditlog$/],
  ["GET /api/v2/tokens", /^\/api\/v2\/tokens$/],
  ["GET /api/v2/webhooks", /^\/api\/v2\/webhooks$/],
  ["GET /api/v2/integrations/{integration}", /^\/api\/v2\/integrations\/([^/]+)$/],
  ["GET /api/v2/account/relay-auto-configs", /^\/api\/v2\/account\/relay-auto-configs$/],
];

/** One handler per LaunchDarkly surface; handlers receive the URL and the decoded path parameters. */
function ldRoutes(fixture) {
  return {
    "GET /api/v2/caller-identity": () => jsonResponse(fixture.identity),
    "GET /api/v2/members": (url) => ldPage(fixture.members, url),
    "GET /api/v2/teams": (url) => ldPage(fixture.teams, url),
    "GET /api/v2/teams/{team}/roles": (url, [team]) => ldPage(fixture.teamRoles[team] ?? [], url),
    "GET /api/v2/roles": (url) => ldPage(fixture.customRoles, url),
    "GET /api/v2/projects": (url) => {
      const filter = url.searchParams.get("filter");
      const keys = filter?.startsWith("keys:") ? new Set(filter.slice(5).split("|")) : null;
      return ldPage(fixture.projects.filter((project) => keys === null || keys.has(project.key)), url);
    },
    "GET /api/v2/projects/{project}/environments": (url, [project]) => ldPage(fixture.environments[project] ?? [], url),
    "GET /api/v2/projects/{project}/environments/{environment}/sdk-keys": (url, [project, environment]) => ldPage(fixture.sdkKeys[`${project}/${environment}`] ?? [], url),
    "GET /api/v2/flags/{project}": (url, [project]) => ldPage(fixture.flags[project] ?? [], url),
    "GET /api/v2/flag-statuses/{project}/{environment}": (url, [project, environment]) => jsonResponse({ items: fixture.flagStatuses[`${project}/${environment}`] ?? [] }),
    "GET /api/v2/auditlog": (url) => {
      const spec = url.searchParams.get("spec");
      const entries = url.searchParams.has("before")
        ? fixture.auditLog.retention
        : spec === "member/*" ? fixture.auditLog.members : spec === "role/*" ? fixture.auditLog.roles : spec === "acct" ? fixture.auditLog.account : fixture.auditLog.recent;
      return ldPage(entries, url);
    },
    "GET /api/v2/tokens": (url) => ldPage(fixture.tokens, url),
    "GET /api/v2/webhooks": () => jsonResponse({ items: fixture.webhooks, totalCount: fixture.webhooks.length }),
    "GET /api/v2/integrations/{integration}": (url, [integration]) => jsonResponse({ items: fixture.integrations[integration] ?? [] }),
    "GET /api/v2/account/relay-auto-configs": () => jsonResponse({ items: fixture.relayConfigs, totalCount: fixture.relayConfigs.length }),
  };
}

/** The real LaunchdarklyApiClient over a fetch router that records the method, path, URL, and status of every request served. */
function httpLaunchdarkly(fixture, options = {}) {
  const routes = { ...ldRoutes(fixture), ...(options.routes ?? {}) };
  const log = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    const method = (init.method ?? "GET").toUpperCase();
    let response;
    const template = LD_ROUTE_TEMPLATES.find(([, pattern]) => pattern.test(url.pathname));
    if (template) {
      const params = [...url.pathname.match(template[1])].slice(1).map(decodeURIComponent);
      response = await routes[template[0]](url, params, init);
    } else {
      response = jsonResponse({ code: "not_found", message: "Not Found" }, { status: 404, statusText: "Not Found" });
    }
    log.push({ method, path: url.pathname, url: url.toString(), host: url.host, status: response.status, authorization: headerValue(init.headers, "authorization") });
    return response;
  };
  const config = sampleConfig(options.config ?? {});
  const client = new LaunchdarklyApiClient(config, { fetchImpl, sleep: async () => {}, maxRetries: 0 });
  return { client, config, log, routes, fetchImpl };
}

/** Runs a registered LaunchDarkly tool against the router by standing in for global fetch for the duration of the call. */
async function runLaunchdarklyTool(toolName, fetchImpl, args) {
  const registered = [];
  registerLaunchdarklyTools({ registerTool: (tool) => registered.push(tool) });
  const tool = registered.find((candidate) => candidate.name === toolName);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await tool.execute(`call-${toolName}`, tool.prepareArguments(args));
  } finally {
    globalThis.fetch = originalFetch;
  }
}

const LD_AREAS = [
  ["identity", assessLaunchdarklyIdentity],
  ["access_control", assessLaunchdarklyAccessControl],
  ["environment_governance", assessLaunchdarklyEnvironmentGovernance],
  ["flag_hygiene", assessLaunchdarklyFlagHygiene],
  ["monitoring_integrations", assessLaunchdarklyMonitoringIntegrations],
];

/** What the five assess tools return, assessed with the default options. */
async function runAllLaunchdarklyAssessments(client) {
  const results = [];
  for (const [, assess] of LD_AREAS) results.push(await assess(client, { now: NOW }));
  return results;
}

/** Request labels the way the run writes them: method, path, and the query without the pagination parameters. */
function ldRequestLabel(entry) {
  const url = new URL(entry.url);
  url.searchParams.delete("limit");
  url.searchParams.delete("offset");
  const query = url.searchParams.toString();
  return `${entry.method} ${url.pathname}${query.length > 0 ? `?${query}` : ""}`;
}

function ldMentionedEndpoints(text) {
  return [...text.matchAll(/\b(GET|POST|PUT|PATCH|DELETE)\s+(\/api\/v2\/[A-Za-z0-9_.\/?=&%*{}|-]+)/g)]
    .map((match) => `${match[1]} ${match[2].replace(/[.,;:)]+$/, "")}`);
}

function ldMentionedStatusCodes(text) {
  const codes = new Set();
  for (const match of text.matchAll(/\b([1-5]\d\d) (?:OK|Forbidden|Unauthorized|Bad Request|Not Found|Too Many Requests|Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout|Error)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/request failed \(([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/"(?:http_)?status":\s*([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/\bHTTP ([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  return [...codes];
}

/** Asserts every request label and status code named anywhere in `outputs` was requested and observed according to `log`. */
function assertLdOutputMatchesRequestLog(outputs, log, label) {
  const requested = new Set(log.map(ldRequestLabel));
  const statuses = new Set(log.map((entry) => entry.status));
  let endpointMentions = 0;
  let statusMentions = 0;
  for (const [name, text] of outputs) {
    for (const endpoint of ldMentionedEndpoints(text)) {
      endpointMentions += 1;
      assert.ok(requested.has(endpoint), `${label}: ${name} names ${endpoint} but the run never requested it; requested: ${[...requested].sort().join(", ")}`);
    }
    for (const code of ldMentionedStatusCodes(text)) {
      statusMentions += 1;
      assert.ok(statuses.has(code), `${label}: ${name} names HTTP ${code} but no request observed it; observed: ${[...statuses]}`);
    }
  }
  return { endpointMentions, statusMentions };
}

function ldLeafEntries(value, path = "", output = []) {
  if (Array.isArray(value)) {
    if (value.length === 0) output.push([path, "[]"]);
    value.forEach((entry, index) => ldLeafEntries(entry, path ? `${path}.${index}` : String(index), output));
  } else if (value !== null && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 0) output.push([path, "{}"]);
    for (const key of keys) ldLeafEntries(value[key], path ? `${path}.${key}` : key, output);
  } else {
    output.push([path, value]);
  }
  return output;
}

function ldPluck(value, path) {
  return path.split(".").reduce((cursor, key) => (cursor === null || cursor === undefined ? undefined : cursor[key]), value);
}

/** Every string a LaunchDarkly run records: access check errors and notes, assessment errors, finding text, evidence strings, and the errors log. */
function ldRecordedStrings(access, assessments, files) {
  const strings = [];
  for (const surface of access.surfaces) if (typeof surface.error === "string") strings.push(surface.error);
  strings.push(...access.notes);
  for (const assessment of assessments) {
    strings.push(...(assessment.errors ?? []));
    for (const finding of assessment.findings) {
      strings.push(finding.summary);
      for (const [, value] of ldLeafEntries(finding.evidence ?? {})) if (typeof value === "string") strings.push(value);
    }
  }
  const errorsLog = files.get("_errors.log");
  if (errorsLog) strings.push(...errorsLog.split("\n"));
  return strings;
}

test("canary fixture self-check: every planted LaunchDarkly credential is alphanumeric, random-looking, and shares no 6-character window with the fixture's legitimate values", async () => {
  const { client, config } = httpLaunchdarkly(ldFixture());
  const access = await checkLaunchdarklyAccess(client);
  const assessments = await runAllLaunchdarklyAssessments(client);
  const exported = await exportLaunchdarklyAuditBundle(client, config, createTempBase("grclanker-ld-self-check-"), { now: NOW });
  const legitimate = new Map([
    ...readBundleFiles(exported.outputDir),
    ["fixture", JSON.stringify(ldFixture())],
    ["principal fixture", JSON.stringify(ldPrincipalFixture())],
    ["check_access", JSON.stringify(access)],
    ["assessments", JSON.stringify(assessments)],
    ["config", JSON.stringify({ ...config, token: null })],
  ]);
  assertCanaryFixture(assert, [...Object.values(LD_CANARIES), TEST_TOKEN, ...Object.values(LD_CONFIG_CANARIES), LD_PARSER_SNIPPET_CANARY], legitimate, "LaunchDarkly canaries");
});

test("verdict rule 9 / addendum 2: the LaunchDarkly bundle, its zip, every assess payload, and the access check never carry any window of a canary from an error body, and errors carry the status-and-length note", async () => {
  const { client, config, log } = httpLaunchdarkly(ldFixture(), {
    routes: {
      "GET /api/v2/teams": ldHtmlGateway(),
      "GET /api/v2/roles": ldJsonForbiddenWithUrl(),
      "GET /api/v2/webhooks": ldJsonUnauthorizedWithSplitToken(),
    },
  });

  const access = await checkLaunchdarklyAccess(client);
  const result = await exportLaunchdarklyAuditBundle(client, config, createTempBase("grclanker-ld-canary-"), { now: NOW });
  const assessments = await runAllLaunchdarklyAssessments(client);

  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size >= 30 && entries.size === files.size, `expected the zip to mirror ${files.size} files, got ${entries.size}`);
  const planted = [...Object.values(LD_CANARIES), LD_JWT_CANARY, config.token];
  assertCanaryWindowsAbsent(assert, files, planted, "bundle file");
  assertCanaryWindowsAbsent(assert, entries, planted, "zip entry");
  assertCanaryWindowsAbsent(assert, new Map([["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), planted, "tool payload");
  assert.ok(log.some((entry) => entry.status === 502) && log.some((entry) => entry.status === 403) && log.some((entry) => entry.status === 401), "the three failing surfaces were requested");

  // The non-JSON body is described by status and length; the JSON error is quoted with its URL query scrubbed; the token
  // that straddled the 300-character cut of the quoted message is redacted before the cut, so no fragment survives.
  const errors = files.get("_errors.log");
  assert.match(errors, /^identity: teams: LaunchDarkly request failed \(502 Bad Gateway\) for GET \/api\/v2\/teams\?expand=members: 502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)$/m);
  assert.match(errors, /^access_control: custom_roles: LaunchDarkly request failed \(403 Forbidden\) for GET \/api\/v2\/roles: forbidden: Forbidden; see https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for details$/m);
  assert.match(errors, /^monitoring_integrations: webhooks: LaunchDarkly request failed \(401 Unauthorized\) for GET \/api\/v2\/webhooks: unauthorized: The request was rejected by the account policy engine\. .*\[REDACTED\]/m);
  assert.doesNotMatch(errors, /<html|upstream sent|Set-Cookie/);

  // The observed status flows into the marker, the finding, the access surface, and the collection status; no "403" is
  // invented for the 502 path and no endpoint is named from a constant.
  const teams = JSON.parse(files.get("core_data/teams.json"));
  assert.deepEqual(
    { collected: teams.collected, status: teams.status, endpoint: teams.endpoint, reason: teams.reason, items: teams.items, seen: teams.seen, truncated: teams.truncated },
    { collected: false, status: 502, endpoint: "GET /api/v2/teams?expand=members", reason: "not_readable", items: null, seen: null, truncated: null },
  );
  assert.match(teams.error, /non-JSON body \(text\/html/);
  const roles = JSON.parse(files.get("core_data/custom_roles.json"));
  assert.deepEqual({ collected: roles.collected, status: roles.status, endpoint: roles.endpoint }, { collected: false, status: 403, endpoint: "GET /api/v2/roles" });
  const teamRoles = JSON.parse(files.get("core_data/team_roles.json"));
  assert.deepEqual({ collected: teamRoles.collected, status: teamRoles.status, reason: teamRoles.reason, endpoint: teamRoles.endpoint }, { collected: false, status: "not-collected", reason: "not_requested", endpoint: null }, "no per-team role listing is requested when the team listing failed");

  const identity = assessments[0];
  const teamsFinding = finding(identity, "LD-06");
  assert.equal(teamsFinding.status, "manual");
  assert.match(teamsFinding.summary, /Unreadable inventory: teams \(GET \/api\/v2\/teams\?expand=members: LaunchDarkly request failed \(502 Bad Gateway\) for GET \/api\/v2\/teams\?expand=members: 502 Bad Gateway: non-JSON body/);
  assert.doesNotMatch(teamsFinding.summary, /403/);
  assert.equal(teamsFinding.evidence.unreadable_inventories[0].http_status, 502);
  const wildcard = finding(assessments[1], "LD-04");
  assert.equal(wildcard.status, "manual");
  assert.match(wildcard.summary, /Unreadable inventory: custom_roles \(GET \/api\/v2\/roles: LaunchDarkly request failed \(403 Forbidden\).*\[REDACTED\]/);

  const teamsProbe = access.surfaces.find((surface) => surface.name === "teams");
  assert.deepEqual(
    { status: teamsProbe.status, collected: teamsProbe.collected, http_status: teamsProbe.http_status, count: teamsProbe.count, endpoint: teamsProbe.endpoint },
    { status: "not_readable", collected: false, http_status: 502, count: null, endpoint: "GET /api/v2/teams?expand=members" },
  );
  assert.match(teamsProbe.error, /502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/);
  const webhooksProbe = access.surfaces.find((surface) => surface.name === "webhooks");
  assert.deepEqual({ status: webhooksProbe.status, http_status: webhooksProbe.http_status }, { status: "not_readable", http_status: 401 });

  const status = JSON.parse(files.get("core_data/collection_status.json"));
  const teamsRow = status.inventories.find((row) => row.inventory === "teams");
  assert.deepEqual(
    { status: teamsRow.status, collected: teamsRow.collected, http_status: teamsRow.http_status, complete: teamsRow.complete, truncated: teamsRow.truncated, seen: teamsRow.seen, total: teamsRow.total, endpoint: teamsRow.endpoint },
    { status: "not_readable", collected: false, http_status: 502, complete: null, truncated: null, seen: null, total: null, endpoint: "GET /api/v2/teams?expand=members" },
  );
  const teamRolesRow = status.inventories.find((row) => row.inventory === "team_roles");
  assert.deepEqual({ status: teamRolesRow.status, collected: teamRolesRow.collected, http_status: teamRolesRow.http_status, complete: teamRolesRow.complete, truncated: teamRolesRow.truncated }, { status: "not_requested", collected: false, http_status: null, complete: null, truncated: null });
  assert.equal(status.totals.not_readable, 3);
  assert.equal(status.totals.not_requested, 1);
  assert.equal(status.totals.truncation_unknown, 4);
  assert.equal(identity.summary.teams, null, "an unread inventory renders null, never 0");
  assert.equal(identity.summary.orphaned_members, null);
  assert.equal(assessments[1].summary.custom_roles, null);
  assert.equal(assessments[1].summary.wildcard_roles, null);
});

test("addendum 5: every request label and status code named in LaunchDarkly output corresponds to a request the run made and observed", async () => {
  const fixture = ldFixture();
  const base = ldRoutes(fixture);
  const { client, config, log, fetchImpl } = httpLaunchdarkly(fixture, {
    routes: {
      "GET /api/v2/teams": ldHtmlGateway(),
      "GET /api/v2/roles": ldJsonForbiddenWithUrl(),
      "GET /api/v2/account/relay-auto-configs": ldNotFound(),
      // Only the staging SDK key read is denied; the production read succeeds.
      "GET /api/v2/projects/{project}/environments/{environment}/sdk-keys": (url, params, init) => (params[1] === "staging" ? ldJsonForbiddenWithUrl()() : base["GET /api/v2/projects/{project}/environments/{environment}/sdk-keys"](url, params, init)),
    },
  });

  const access = await checkLaunchdarklyAccess(client);
  const result = await exportLaunchdarklyAuditBundle(client, config, createTempBase("grclanker-ld-request-log-"), { now: NOW });
  const assessments = await runAllLaunchdarklyAssessments(client);
  // The human-readable access check table (Request and Note columns) is produced through the registered tool.
  const accessTool = await runLaunchdarklyTool("launchdarkly_check_access", fetchImpl, { token: TEST_TOKEN, allowed_domains: ["example.com"] });
  assert.notEqual(accessTool.isError, true, accessTool.content[0].text);
  const outputs = [...readBundleFiles(result.outputDir), ["check_access", JSON.stringify(access)], ["check_access_text", accessTool.content[0].text], ["assessments", JSON.stringify(assessments)]];

  assert.deepEqual([...new Set(log.map((entry) => entry.status))].sort(), [200, 403, 404, 502], "the fixture served 200, 403, 404, and 502");
  assert.ok(log.some((entry) => entry.path === "/api/v2/projects/web/environments/staging/sdk-keys" && entry.status === 403), "the per-environment SDK key request was made and denied");
  const { endpointMentions, statusMentions } = assertLdOutputMatchesRequestLog(outputs, log, "mixed denials");
  assert.ok(endpointMentions > 60, `expected request labels across the bundle, got ${endpointMentions}`);
  assert.ok(statusMentions > 8, `expected status mentions across the bundle, got ${statusMentions}`);
  assert.ok(!JSON.stringify(outputs).includes("{project}") && !JSON.stringify(outputs).includes("{environment}"), "no templated endpoint reaches the output");

  // The per-environment gap names the request the run made and the status it observed, beside the environment that did load.
  const governance = assessments[2];
  const rotation = finding(governance, "LD-19");
  assert.notEqual(rotation.status, "pass");
  assert.match(rotation.summary, /Unreadable inventory: sdk_keys for environment web\/staging \(GET \/api\/v2\/projects\/web\/environments\/staging\/sdk-keys: LaunchDarkly request failed \(403 Forbidden\) for GET \/api\/v2\/projects\/web\/environments\/staging\/sdk-keys: forbidden: Forbidden; see https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for details\)/);
  const sdkKeys = JSON.parse(readFileSync(join(result.outputDir, "core_data", "sdk_keys.json"), "utf8"));
  const failed = sdkKeys.find((entry) => entry.collected === false);
  assert.deepEqual({ environment: failed.environment, status: failed.status, endpoint: failed.endpoint, reason: failed.reason, items: failed.items }, { environment: "web/staging", status: 403, endpoint: "GET /api/v2/projects/web/environments/staging/sdk-keys", reason: "not_readable", items: null });
  assert.equal(sdkKeys.filter((entry) => entry.collected === true).length, 1, "the production key listing keeps its records");
  const relays = JSON.parse(readFileSync(join(result.outputDir, "core_data", "relay_proxy_configs.json"), "utf8"));
  assert.deepEqual({ collected: relays.collected, status: relays.status, endpoint: relays.endpoint }, { collected: false, status: 404, endpoint: "GET /api/v2/account/relay-auto-configs" });
  const relayFinding = finding(assessments[4], "LD-18");
  assert.match(relayFinding.summary, /relay_proxy_configs \(GET \/api\/v2\/account\/relay-auto-configs: LaunchDarkly request failed \(404 Not Found\)/);
  assert.doesNotMatch(relayFinding.summary, /403/);
});

/** Every list dataset written to core_data, the route (and, for the audit log, the query) that fills it, and its file. */
const LD_CORE_DATA_DATASETS = [
  { inventory: "members", route: "GET /api/v2/members", file: "core_data/members.json" },
  { inventory: "teams", route: "GET /api/v2/teams", file: "core_data/teams.json" },
  { inventory: "team_roles", route: "GET /api/v2/teams/{team}/roles", file: "core_data/team_roles.json", scoped: true },
  { inventory: "audit_log_account", route: "GET /api/v2/auditlog", file: "core_data/audit_log_account.json", query: (url) => url.searchParams.get("spec") === "acct" },
  { inventory: "custom_roles", route: "GET /api/v2/roles", file: "core_data/custom_roles.json" },
  { inventory: "access_tokens", route: "GET /api/v2/tokens", file: "core_data/access_tokens.json" },
  { inventory: "projects", route: "GET /api/v2/projects", file: "core_data/projects.json" },
  { inventory: "environments", route: "GET /api/v2/projects/{project}/environments", file: "core_data/environments.json", scoped: true },
  { inventory: "sdk_keys", route: "GET /api/v2/projects/{project}/environments/{environment}/sdk-keys", file: "core_data/sdk_keys.json", scoped: true },
  { inventory: "flags", route: "GET /api/v2/flags/{project}", file: "core_data/flags.json", scoped: true },
  { inventory: "flag_statuses", route: "GET /api/v2/flag-statuses/{project}/{environment}", file: "core_data/flag_statuses.json", scoped: true },
  { inventory: "audit_log_recent", route: "GET /api/v2/auditlog", file: "core_data/audit_log_recent.json", query: (url) => !url.searchParams.has("spec") && !url.searchParams.has("before") },
  { inventory: "audit_log_retention_probe", route: "GET /api/v2/auditlog", file: "core_data/audit_log_retention_probe.json", query: (url) => url.searchParams.has("before") },
  { inventory: "audit_log_members", route: "GET /api/v2/auditlog", file: "core_data/audit_log_members.json", query: (url) => url.searchParams.get("spec") === "member/*" },
  { inventory: "audit_log_roles", route: "GET /api/v2/auditlog", file: "core_data/audit_log_roles.json", query: (url) => url.searchParams.get("spec") === "role/*" },
  { inventory: "relay_proxy_configs", route: "GET /api/v2/account/relay-auto-configs", file: "core_data/relay_proxy_configs.json" },
  { inventory: "integration_subscriptions", route: "GET /api/v2/integrations/{integration}", file: "core_data/integration_subscriptions.json", scoped: true },
  { inventory: "webhooks", route: "GET /api/v2/webhooks", file: "core_data/webhooks.json" },
];

/** Denies one dataset; audit log datasets share a route and are told apart by their query. */
function ldDenyDataset(base, denial) {
  const forbidden = ldJsonForbiddenWithUrl();
  if (denial.query === undefined) return forbidden;
  return (url, params, init) => (denial.query(url) ? forbidden() : base[denial.route](url, params, init));
}

/** The healthy fixture with the webhook and Relay Proxy listings legitimately empty, so a readable-but-empty read sits beside every denial. */
function ldSparseFixture() {
  return { ...ldFixture(), webhooks: [], relayConfigs: [] };
}

test("addendum 5: under each single-inventory denial the denied LaunchDarkly dataset's core_data file is a not-collected marker while readable-but-empty datasets keep items []", async () => {
  for (const denial of LD_CORE_DATA_DATASETS) {
    const fixture = ldSparseFixture();
    const { client, config, log } = httpLaunchdarkly(fixture, { routes: { [denial.route]: ldDenyDataset(ldRoutes(fixture), denial) } });
    const result = await exportLaunchdarklyAuditBundle(client, config, createTempBase("grclanker-ld-marker-"), { now: NOW });
    const files = readBundleFiles(result.outputDir);
    const label = `${denial.inventory} denied`;

    const denied = JSON.parse(files.get(denial.file));
    assert.ok(!Array.isArray(denied), `${label}: ${denial.file} must be a marker object, not an array`);
    assert.equal(denied.collected, false, label);
    assert.equal(denied.status, 403, `${label}: the marker carries the observed status`);
    assert.equal(denied.reason, "not_readable", label);
    assert.equal(denied.items, null, `${label}: a denied list carries items: null, never []`);
    assert.deepEqual([denied.truncated, denied.seen, denied.total], [null, null, null], `${label}: no collection-status flag defaults on a read that never completed`);
    assert.match(denied.error, /LaunchDarkly request failed \(403 Forbidden\)/, label);
    assertCanaryWindowsAbsent(assert, JSON.stringify(denied), [LD_CANARIES.urlToken], `${label} marker`);
    const deniedRequests = new Set(log.filter((entry) => entry.status === 403).map(ldRequestLabel));
    for (const endpoint of denied.endpoint.split(", ")) {
      assert.ok(deniedRequests.has(endpoint), `${label}: marker names ${endpoint}, which was not the denied request (${[...deniedRequests].join(", ")})`);
    }
    if (denial.scoped) {
      // Several assessments may repeat the same scoped read; the marker carries one failed read per distinct request.
      const deniedReads = deniedRequests.size;
      assert.ok(Array.isArray(denied.failed_reads) && deniedReads > 0 && denied.failed_reads.length === deniedReads, `${label}: one failed read per scope (${deniedReads} denied requests, ${denied.failed_reads?.length} failed reads)`);
      assert.ok(denied.failed_reads.every((read) => read.collected === false && read.status === 403 && deniedRequests.has(read.endpoint) && read.items === null), label);
    }
    if (denial.inventory === "teams") {
      const teamRoles = JSON.parse(files.get("core_data/team_roles.json"));
      assert.deepEqual({ collected: teamRoles.collected, status: teamRoles.status, endpoint: teamRoles.endpoint, reason: teamRoles.reason }, { collected: false, status: "not-collected", endpoint: null, reason: "not_requested" }, "no per-team role read is attempted when the team listing is denied");
    }
    if (denial.inventory === "projects") {
      for (const file of ["core_data/environments.json", "core_data/sdk_keys.json", "core_data/flags.json", "core_data/flag_statuses.json"]) {
        const dependent = JSON.parse(files.get(file));
        assert.deepEqual({ collected: dependent.collected, status: dependent.status, endpoint: dependent.endpoint, reason: dependent.reason }, { collected: false, status: "not-collected", endpoint: null, reason: "not_requested" }, `${file}: nothing below a denied project listing is requested`);
      }
    }

    const emptyFile = denial.inventory === "webhooks" ? "core_data/relay_proxy_configs.json" : "core_data/webhooks.json";
    const empty = JSON.parse(files.get(emptyFile));
    assert.deepEqual({ collected: empty.collected, items: empty.items, truncated: empty.truncated, seen: empty.seen }, { collected: true, items: [], truncated: false, seen: 0 }, `${label}: a readable-but-empty dataset keeps items []`);
    const status = JSON.parse(files.get("core_data/collection_status.json"));
    const row = status.inventories.find((entry) => entry.inventory === denial.inventory);
    assert.deepEqual({ status: row.status, collected: row.collected, http_status: row.http_status, complete: row.complete, truncated: row.truncated, seen: row.seen, total: row.total }, { status: "not_readable", collected: false, http_status: 403, complete: null, truncated: null, seen: null, total: null }, label);
    const emptyRow = status.inventories.find((entry) => entry.inventory === (denial.inventory === "webhooks" ? "relay_proxy_configs" : "webhooks"));
    assert.deepEqual({ status: emptyRow.status, complete: emptyRow.complete, truncated: emptyRow.truncated, seen: emptyRow.seen }, { status: "readable", complete: true, truncated: false, seen: 0 }, `${label}: the empty inventory is a complete, untruncated read of zero records`);
  }
});

/**
 * Principals that only one inventory (or one combination of inventories) can name. Each is asserted present in the
 * all-readable baseline and absent from every assess payload and derived bundle file when any listed inventory is denied.
 */
const LD_PRINCIPAL_CANARIES = [
  { canary: "nomfa.canaryqz@example.com", inventories: ["members"] },
  { canary: "canary-empty-team-zq", inventories: ["teams"] },
  // The team is legitimately named by the readable team listing and by the gap that names its denied role request; what
  // may not be claimed from the denied role listing is that it has no custom role.
  { canary: "canary-empty-team-zq", inventories: ["team_roles"], field: "teams_without_custom_roles" },
  { canary: "canary-wildcard-role-zq", inventories: ["custom_roles"] },
  { canary: "canary-noexpiry-token-zq", inventories: ["access_tokens"] },
  { canary: "canary-sandbox-project-zq", inventories: ["projects"] },
  { canary: "canary-open-prod-zq", inventories: ["projects", "environments"] },
  { canary: "CanaryStaleSdkKeyZq", inventories: ["projects", "environments", "sdk_keys"] },
  { canary: "canary-targeted-flag-zq", inventories: ["projects", "environments", "flags"] },
  { canary: "canary-stale-flag-zq", inventories: ["projects", "environments", "flags", "flag_statuses"] },
  { canary: "canary-insecure-hook-zq", inventories: ["webhooks"] },
  { canary: "canary-broad-relay-zq", inventories: ["relay_proxy_configs"] },
  { canary: "canary-broad-subscription-zq", inventories: ["integration_subscriptions"] },
  { canary: "CanaryRequireSsoChangeZq", inventories: ["audit_log_account"] },
  { canary: "canaryaccountzq", inventories: ["caller_identity"] },
];

/** The healthy fixture with one principal per inventory that no other inventory carries. */
function ldPrincipalFixture() {
  const fixture = ldFixture();
  fixture.identity = { ...fixture.identity, accountId: "canaryaccountzq" };
  fixture.members.push({ _id: "m9", email: "nomfa.canaryqz@example.com", role: "writer", mfa: "disabled", teams: [{ key: "platform" }] });
  fixture.teams.push({ key: "canary-empty-team-zq", name: "Canary Empty Team" });
  fixture.teamRoles["canary-empty-team-zq"] = [];
  fixture.customRoles.push({ key: "canary-wildcard-role-zq", basePermissions: "no_access", policy: [{ effect: "allow", actions: ["*"], resources: ["proj/*"] }] });
  fixture.tokens.push({ _id: "t9", name: "canary-noexpiry-token-zq", role: "reader", serviceToken: true, lastUsed: RECENT_MS, creationDate: RECENT_MS });
  fixture.projects.push({ key: "canary-sandbox-project-zq", name: "Canary Sandbox", tags: [] });
  fixture.environments["canary-sandbox-project-zq"] = [];
  fixture.environments.web.push({ key: "canary-open-prod-zq", name: "Canary Open Prod", critical: true, secureMode: false, defaultTtl: 0 });
  fixture.sdkKeys["web/canary-open-prod-zq"] = [{ key: "sdk-open", name: "CanaryStaleSdkKeyZq", kind: "sdk", _createdAt: OLD_MS, isDefault: true, value: "****open" }];
  fixture.flags.web.push(
    { key: "canary-targeted-flag-zq", creationDate: OLD_MS, environments: { production: { targets: [{ values: ["user-1"], variation: 0 }], contextTargets: [], prerequisites: [] } } },
    { key: "canary-stale-flag-zq", creationDate: OLD_MS, environments: { production: { targets: [], contextTargets: [], prerequisites: [] } } },
  );
  fixture.flagStatuses["web/production"].push(
    { name: "active", lastRequested: RECENT, _links: { parent: { href: "/api/v2/flags/web/canary-targeted-flag-zq" } } },
    { name: "inactive", lastRequested: OLD, _links: { parent: { href: "/api/v2/flags/web/canary-stale-flag-zq" } } },
  );
  fixture.webhooks.push({ _id: "wh-9", name: "canary-insecure-hook-zq", url: "http://hooks.example.com/legacy", on: true });
  fixture.relayConfigs.push({ _id: "relay-9", name: "canary-broad-relay-zq", lastModified: RECENT_MS, creationDate: RECENT_MS, policy: [{ effect: "allow", actions: ["*"], resources: ["proj/*:env/*"] }] });
  fixture.integrations.datadog.push({ _id: "sub-9", name: "canary-broad-subscription-zq", on: true, statements: [{ effect: "allow", actions: ["*"], resources: ["proj/*:env/*"] }] });
  fixture.auditLog.account.push({ date: RECENT_MS, kind: "account", title: "CanaryRequireSsoChangeZq", accesses: [{ action: "updateSamlRequireSso", resource: "acct" }] });
  return fixture;
}

const LD_SINGLE_INVENTORY_DENIALS = LD_CORE_DATA_DATASETS.concat([{ inventory: "caller_identity", route: "GET /api/v2/caller-identity", file: null }]);

const LD_FALLBACK_VALUES = new Set([0, false, "none", "[]", "{}"]);

/** Fields that describe the read itself (read-state flags, inventory states, gaps, caveats) and legitimately flip under a denial. */
const LD_READ_STATE_PATHS = [
  /(^|\.)[a-z_]*(complete|readable|observed|loaded|read|sampled|available|requested|collected)$/,
  /^inventories(\.|$)/,
  /^unreadable_inventories(\.|$)/,
  /^truncated_collections(\.|$)/,
  /^unreadable_(environments|projects)$/,
  /^teams_with_unreadable_roles$/,
  /^token_inventory_scope$/,
  /^truncation_unknown$/,
  /^(pass|warn|fail|manual)$/,
];

/** True when a denied-run value is a zero, false, or empty fallback where the all-readable baseline held real data. */
function isLdFallback(path, value, baselineValue) {
  if (!LD_FALLBACK_VALUES.has(value)) return false;
  if (baselineValue === undefined || baselineValue === null || LD_FALLBACK_VALUES.has(baselineValue)) return false;
  if (Array.isArray(baselineValue) && baselineValue.length === 0) return false;
  if (typeof baselineValue === "object" && !Array.isArray(baselineValue) && Object.keys(baselineValue).length === 0) return false;
  return !LD_READ_STATE_PATHS.some((pattern) => pattern.test(path));
}

test("addendum 3: under every single-inventory denial no LaunchDarkly finding, summary, or tool payload falls back to a zero, false, or empty value, and no principal is named from the denied inventory", async () => {
  const baselineRun = httpLaunchdarkly(ldPrincipalFixture());
  const baseline = await runAllLaunchdarklyAssessments(baselineRun.client);
  const baselineExport = await exportLaunchdarklyAuditBundle(baselineRun.client, baselineRun.config, createTempBase("grclanker-ld-principal-baseline-"), { now: NOW });
  const baselineFiles = readBundleFiles(baselineExport.outputDir);
  const baselineText = JSON.stringify(baseline) + [...baselineFiles].filter(([name]) => !name.startsWith("core_data/")).map(([, text]) => text).join("\n");
  for (const { canary } of LD_PRINCIPAL_CANARIES) {
    assert.ok(baselineText.includes(canary), `${canary} must be named by an all-readable assess payload or derived bundle file for its gating check to mean anything`);
  }

  const offenders = [];
  let comparedLeaves = 0;
  for (const denial of LD_SINGLE_INVENTORY_DENIALS) {
    const fixture = ldPrincipalFixture();
    const { client, config } = httpLaunchdarkly(fixture, { routes: { [denial.route]: ldDenyDataset(ldRoutes(fixture), denial) } });
    const denied = await runAllLaunchdarklyAssessments(client);
    const exported = await exportLaunchdarklyAuditBundle(client, config, createTempBase("grclanker-ld-principal-"), { now: NOW });
    const files = readBundleFiles(exported.outputDir);
    const label = `${denial.inventory} denied`;
    // Raw core_data records and the snapshots an assess payload carries are the readable inventories themselves; the gating
    // rule covers what the run asserts about principals, so findings, summaries, errors, and the analysis, compliance,
    // metadata, and quick-reference files are scanned.
    const withoutSnapshots = (text) => {
      const { snapshots: _snapshots, ...rest } = JSON.parse(text);
      return JSON.stringify(rest);
    };
    const derived = [...files]
      .filter(([name]) => !name.startsWith("core_data/"))
      .map(([name, text]) => [name, /^analysis\/[a-z_]+\.json$/.test(name) && name !== "analysis/findings.json" ? withoutSnapshots(text) : text]);
    const asserted = denied.map(({ snapshots: _snapshots, ...rest }) => rest);
    const deniedText = JSON.stringify(asserted) + derived.map(([, text]) => text).join("\n");
    for (const { canary, inventories, field } of LD_PRINCIPAL_CANARIES) {
      if (!inventories.includes(denial.inventory)) continue;
      if (field !== undefined) {
        for (const item of denied.flatMap((result) => result.findings)) {
          if (!(item.evidence && field in item.evidence)) continue;
          assert.ok(!JSON.stringify(item.evidence[field]).includes(canary), `${label}: ${item.id} evidence.${field} still names ${canary} from the denied inventory: ${JSON.stringify(item.evidence[field])}`);
        }
        for (const result of denied) {
          if (field in result.summary) assert.ok(!JSON.stringify(result.summary[field]).includes(canary), `${label}: ${result.category} summary.${field} still names ${canary}`);
        }
        continue;
      }
      const where = [
        ...ldLeafEntries(asserted).filter(([, value]) => typeof value === "string" && value.includes(canary)).map(([path]) => `assessments.${path}`),
        ...derived.filter(([, text]) => text.includes(canary)).map(([name]) => name),
      ];
      assert.ok(!deniedText.includes(canary), `${label}: ${canary} is still named from the denied inventory at ${where.join(", ")}`);
    }
    for (const [areaIndex, result] of denied.entries()) {
      const baselineResult = baseline[areaIndex];
      for (const [path, value] of ldLeafEntries(result.summary)) {
        comparedLeaves += 1;
        const baselineValue = ldPluck(baselineResult.summary, path);
        if (isLdFallback(path, value, baselineValue)) offenders.push(`${label}: ${result.category} summary.${path} = ${JSON.stringify(value)} (baseline ${JSON.stringify(baselineValue)})`);
      }
      for (const item of result.findings) {
        const baselineFinding = finding(baselineResult, item.id);
        for (const [path, value] of ldLeafEntries(item.evidence ?? {})) {
          comparedLeaves += 1;
          const baselineValue = ldPluck(baselineFinding.evidence ?? {}, path);
          if (isLdFallback(path, value, baselineValue)) offenders.push(`${label}: ${item.id} evidence.${path} = ${JSON.stringify(value)} (baseline ${JSON.stringify(baselineValue)})`);
        }
      }
    }
    // The bundle's assessment-level summaries get the same treatment as the tool payloads.
    for (const [, area] of LD_AREAS.map(([category]) => [category, `analysis/${category}.json`])) {
      if (!files.has(area)) continue;
      const summary = JSON.parse(files.get(area)).summary ?? {};
      const baselineSummary = JSON.parse(baselineFiles.get(area)).summary ?? {};
      for (const [path, value] of ldLeafEntries(summary)) {
        comparedLeaves += 1;
        if (isLdFallback(path, value, ldPluck(baselineSummary, path))) offenders.push(`${label}: ${area} summary.${path} = ${JSON.stringify(value)}`);
      }
    }
    if (denial.inventory === "caller_identity") {
      const metadata = JSON.parse(files.get("metadata.json"));
      assert.equal(metadata.account_id, null, "the account id is unknown when the caller identity was not readable");
    }
  }
  assert.ok(comparedLeaves > 3000, `expected the sweep to compare thousands of leaves, got ${comparedLeaves}`);
  assert.deepEqual(offenders, [], `values that fell back to zero, false, or empty under a denial:\n${offenders.join("\n")}`);
});

// ---------------------------------------------------------------------------------------------------------------
// Addendum 4: every surface fails in turn with a 502 HTML page and a JSON error carrying canaries.
// ---------------------------------------------------------------------------------------------------------------

/** How each route template is named in an error string, so the strings about a failing surface can be picked out. */
function ldSurfacePattern(template) {
  const escaped = template.replace(/[/?]/g, (character) => `\\${character}`).replace(/\{[a-z]+\}/g, "[^/?:\\s]+");
  return new RegExp(escaped);
}

test("addendum 4: a 502 HTML page or a JSON error message carrying credentials on any LaunchDarkly surface never reaches the access check, an assess payload, or the bundle, and every recorded error carries the status-and-length note", async () => {
  const surfaces = Object.keys(ldRoutes(ldFixture()));
  assert.equal(surfaces.length, 15, "every collector and access probe route");
  const variants = [
    { name: "html502", handler: ldHtmlGateway, note: /502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/ },
    { name: "json403", handler: ldJsonForbiddenWithUrl, note: /\(403 Forbidden\)/ },
  ];
  let notedSurfaces = 0;
  for (const surface of surfaces) {
    for (const variant of variants) {
      const { client, config } = httpLaunchdarkly(ldFixture(), { routes: { [surface]: variant.handler() } });
      const label = `${surface} ${variant.name}`;
      const planted = [...Object.values(LD_CANARIES), LD_JWT_CANARY, config.token];

      const access = await checkLaunchdarklyAccess(client);
      const assessments = await runAllLaunchdarklyAssessments(client);
      const result = await exportLaunchdarklyAuditBundle(client, config, createTempBase("grclanker-ld-surface-canary-"), { now: NOW });
      const files = readBundleFiles(result.outputDir);
      const entries = readZipEntries(result.zipPath);

      assertCanaryWindowsAbsent(assert, files, planted, `${label} bundle file`);
      assertCanaryWindowsAbsent(assert, entries, planted, `${label} zip entry`);
      assertCanaryWindowsAbsent(assert, new Map([["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), planted, `${label} tool payload`);

      const pattern = ldSurfacePattern(surface);
      const aboutSurface = ldRecordedStrings(access, assessments, files).filter((text) => pattern.test(text) && /request failed|timed out/.test(text));
      assert.ok(aboutSurface.length > 0, `${label}: the failure is recorded somewhere`);
      notedSurfaces += 1;
      for (const text of aboutSurface) {
        assert.match(text, variant.note, `${label}: error string lacks the status note: ${text}`);
        assert.ok(!/<html|Bad Gateway<\/|upstream sent/.test(text), `${label}: error string echoes the body: ${text}`);
        if (variant.name === "json403") assert.ok(!text.includes("token=") || text.includes("?[REDACTED]"), `${label}: URL token survives in ${text}`);
      }
    }
  }
  assert.equal(notedSurfaces, surfaces.length * variants.length);
});

// ---------------------------------------------------------------------------------------------------------------
// Addenda 6 and 6b: config loader errors are fixed text carrying only the path, a validated code, and a line.
// ---------------------------------------------------------------------------------------------------------------

const LD_CONFIG_CANARIES = {
  tomlLine: "ZV8owUdYUiDGBtsFcAnAHaYCAnCEEK8g",
  jsonValue: "BPt5mgDrRZ5YyLTHaQPepJUYQbGYRCjG",
  unreadable: "tLeWcrtPjZyf6J7YmrvbbFCbduuypKkb",
};
const LD_PARSER_SNIPPET_CANARY = "nSRVHATViWUGzQZKaE9NdiBW4nUZeRsL";

const LD_LIBRARY_WORDING = ["expected a comment", "Invalid TOML", "is not valid JSON", "Unexpected token", "illegal operation", "permission denied", "no such file"];

/** Asserts a message carries neither any window of a canary nor the parser's or filesystem's own wording. */
function assertLdFixedTextOnly(message, canaries, label) {
  assertCanaryWindowsAbsent(assert, message, canaries, label);
  for (const wording of LD_LIBRARY_WORDING) assert.ok(!message.includes(wording), `${label}: carries library wording "${wording}": ${message}`);
}

test("config loader errors: a LaunchDarkly config file that cannot be read or parsed yields fixed text with only the path, a validated code, and the parser's line, from the resolver and from check_access", async () => {
  const registered = [];
  registerLaunchdarklyTools({ registerTool: (tool) => registered.push(tool) });
  const checkTool = registered.find((tool) => tool.name === "launchdarkly_check_access");
  const exportTool = registered.find((tool) => tool.name === "launchdarkly_export_audit_bundle");
  const canaries = Object.values(LD_CONFIG_CANARIES);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("no request may be made while the config file is unreadable"); };
  try {
    const base = createTempBase("grclanker-ld-config-errors-");
    const cases = [];

    // A YAML-style line in the TOML file: the in-house parser rejects the line by number and quotes nothing from it.
    const yamlStyle = join(base, "yaml-style.toml");
    writeFileSync(yamlStyle, `# LaunchDarkly\ntoken: Bearer ${LD_CONFIG_CANARIES.tomlLine}\n`, "utf8");
    assert.throws(() => parseSimpleToml(readFileSync(yamlStyle, "utf8")), (error) => error.name === "LaunchdarklyTomlSyntaxError" && error.line === 2 && !error.message.includes(LD_CONFIG_CANARIES.tomlLine), "positive control: the parser rejects line 2 without quoting it");
    cases.push({ name: "toml yaml-style line", path: yamlStyle, code: "INVALID_TOML", line: 2, message: `Unable to parse LaunchDarkly config file: invalid TOML in ${yamlStyle} at line 2` });

    // A JSON document where TOML was expected: the first line has no key = value pair.
    const jsonFile = join(base, "config.json.toml");
    writeFileSync(jsonFile, `{"token":"${LD_CONFIG_CANARIES.jsonValue}"}`, "utf8");
    assert.throws(() => JSON.parse(`{"token":${LD_CONFIG_CANARIES.jsonValue}}`), (error) => error instanceof SyntaxError && error.message.includes(LD_CONFIG_CANARIES.jsonValue.slice(0, 6)), "positive control: JSON.parse quotes the source window");
    cases.push({ name: "json in toml", path: jsonFile, code: "INVALID_TOML", line: 1, message: `Unable to parse LaunchDarkly config file: invalid TOML in ${jsonFile} at line 1` });

    // EISDIR: a directory at the path is a read failure, not a parse failure.
    const directory = join(base, "config-dir");
    mkdirSync(directory);
    assert.throws(() => readFileSync(directory, "utf8"), (error) => error.code === "EISDIR" && /illegal operation/.test(error.message), "positive control: the filesystem message carries its own wording");
    cases.push({ name: "EISDIR", path: directory, code: "EISDIR", line: undefined, message: `Unable to read LaunchDarkly config file ${directory} (EISDIR)` });

    // EACCES: an unreadable file (root reads everything, so the case is skipped when running as root).
    if (typeof process.getuid === "function" && process.getuid() !== 0) {
      const unreadable = join(base, "unreadable.toml");
      writeFileSync(unreadable, `token = "${LD_CONFIG_CANARIES.unreadable}"\n`, "utf8");
      chmodSync(unreadable, 0o000);
      assert.throws(() => readFileSync(unreadable, "utf8"), (error) => error.code === "EACCES" && /permission denied/.test(error.message), "positive control");
      cases.push({ name: "EACCES", path: unreadable, code: "EACCES", line: undefined, message: `Unable to read LaunchDarkly config file ${unreadable} (EACCES)` });
    }

    // ENOENT on an explicit path: a missing file named by argument or environment is an error, not a silent default.
    const missing = join(base, "missing.toml");
    cases.push({ name: "ENOENT", path: missing, code: "ENOENT", line: undefined, message: `Unable to read LaunchDarkly config file ${missing} (ENOENT)` });

    for (const item of cases) {
      let thrown;
      try {
        resolveLaunchdarklyConfiguration({ config_path: item.path }, {}, { homeDir: base });
      } catch (error) {
        thrown = error;
      }
      assert.ok(thrown, `${item.name}: the resolver must reject the file`);
      assert.equal(thrown.name, "LaunchdarklyConfigFileError", item.name);
      assert.ok(thrown instanceof LaunchdarklyConfigFileError, item.name);
      assert.equal(thrown.message, item.message, `${item.name}: fixed text only`);
      assert.equal(thrown.code, item.code, item.name);
      assert.equal(thrown.line, item.line, item.name);
      assert.equal(thrown.path, item.path, item.name);
      assertLdFixedTextOnly(thrown.message, canaries, `${item.name} resolver`);

      const access = await checkTool.execute("call-config", checkTool.prepareArguments({ config_path: item.path }));
      assert.equal(access.isError, true, item.name);
      assert.equal(access.content[0].text, `LaunchDarkly access check failed: ${item.message}`, item.name);
      assertLdFixedTextOnly(JSON.stringify(access), canaries, `${item.name} check_access`);

      const outputDir = join(base, `export-${item.code}-${item.name.replace(/[^a-z]+/g, "-")}`);
      const exported = await exportTool.execute("call-config-export", exportTool.prepareArguments({ config_path: item.path, output_dir: outputDir }));
      assert.equal(exported.isError, true, item.name);
      assert.equal(exported.content[0].text, `LaunchDarkly audit bundle export failed: ${item.message}`, item.name);
      assert.equal(existsSync(outputDir), false, `${item.name}: nothing is written when the config file is unreadable`);
    }

    // The environment variable is an explicit path too, and a missing default file is still simply absent.
    assert.throws(() => resolveLaunchdarklyConfiguration({ token: TEST_TOKEN }, { LAUNCHDARKLY_CONFIG: missing }, { homeDir: base }), { message: `Unable to read LaunchDarkly config file ${missing} (ENOENT)` });
    assert.equal(resolveLaunchdarklyConfiguration({ token: TEST_TOKEN }, {}, { homeDir: base }).token, TEST_TOKEN);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("config loader errors: a SyntaxError raised by the transport is recorded by name only, never by the parser's message that quotes the body", async () => {
  const snippet = `<html>${LD_PARSER_SNIPPET_CANARY}</html>`;
  const client = new LaunchdarklyApiClient(sampleConfig(), {
    fetchImpl: async () => { throw new SyntaxError(`Unexpected token '<', "${snippet}"... is not valid JSON`); },
    maxRetries: 0,
  });
  await assert.rejects(() => client.getCallerIdentity(), (error) => {
    assert.ok(error instanceof LaunchdarklyApiError);
    assert.equal(error.message, "LaunchDarkly request failed for GET /api/v2/caller-identity: SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body");
    assert.equal(error.status, null);
    return true;
  });
  const access = await checkLaunchdarklyAccess(client);
  assertCanaryWindowsAbsent(assert, JSON.stringify(access), [LD_PARSER_SNIPPET_CANARY], "check_access");
  assert.ok(access.surfaces.every((surface) => surface.status !== "readable"));
  const identity = await assessLaunchdarklyIdentity(client, { now: NOW });
  assert.ok(identity.errors.length > 0 && identity.errors.every((text) => text.includes("SyntaxError: response could not be parsed as JSON")), identity.errors.join("\n"));
  assertCanaryWindowsAbsent(assert, JSON.stringify(identity), [LD_PARSER_SNIPPET_CANARY], "assess payload");
});

// ---------------------------------------------------------------------------------------------------------------
// Round 7: fixed message text survives the scrubber, and argument overlays never erase env-provided credentials.
// ---------------------------------------------------------------------------------------------------------------

/** Every fixed-text message the LaunchDarkly integration emits that a fixture run does not already produce. */
const LD_FIXED_TEXT_MESSAGES = [
  "Unable to read LaunchDarkly config file /home/auditor/.config/launchdarkly-sec-inspector/config.toml (ENOENT)",
  "Unable to read LaunchDarkly config file /home/auditor/.config/launchdarkly-sec-inspector/config.toml (EACCES)",
  "Unable to parse LaunchDarkly config file: invalid TOML in /home/auditor/.config/launchdarkly-sec-inspector/config.toml at line 3",
  "Unable to parse LaunchDarkly config file: invalid TOML in /home/auditor/.config/launchdarkly-sec-inspector/config.toml",
  "Invalid TOML at line 3: expected a comment, a [table] header, or a key = value pair",
  "LaunchDarkly API access token is required. Pass token, set LAUNCHDARKLY_API_TOKEN, or add token to /home/auditor/.config/launchdarkly-sec-inspector/config.toml.",
  "Unsupported LaunchDarkly base URL protocol: ftp:",
  "502 Bad Gateway: non-JSON body (text/html, 5120 bytes, not echoed)",
  "403 Forbidden: JSON body without a documented error field (64 bytes, not echoed)",
  "LaunchDarkly request failed (502 Bad Gateway) for GET /api/v2/tokens?showAll=true: 502 Bad Gateway: non-JSON body (text/html, 5120 bytes, not echoed)",
  "LaunchDarkly response for GET /api/v2/members was not valid JSON (200 OK: non-JSON body (text/html, 1024 bytes, not echoed)).",
  "LaunchDarkly request failed for GET /api/v2/caller-identity: timed out after 30000ms",
  "LaunchDarkly request failed for GET /api/v2/caller-identity: SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
  "LaunchDarkly request failed (403 Forbidden) for GET /api/v2/auditlog?spec=member%2F*: forbidden: You do not have permission to view the audit log",
  "The caller identity was not readable (HTTP 403), so the token name, token kind, and member are unknown.",
  "No project was readable, so no environment listing was requested.",
  "Using LaunchDarkly instance https://app.launchdarkly.com with API version 20240415.",
  "Config precedence resolved from: environment-token -> config-base-url -> config-file-present.",
  "Authorization > Access tokens: name, role or custom role, owner, expiry, and last used date of every token (showAll as an Owner or Admin)",
  "Authorization > Access tokens: the role of the token used for this assessment",
  "Organization settings > Security > SAML: Enable SSO and Require SSO are checked",
  "Account settings > Security: multi-factor authentication requirement and the members who have not enrolled",
  "Unknown LaunchDarkly control 99",
  JSON.stringify({ collected: false, status: "not-collected", endpoint: null, error: null, reason: "not_requested", truncated: null, seen: null, total: null, items: null }),
  JSON.stringify({ collected: false, status: 403, endpoint: "GET /api/v2/tokens?showAll=true", error: "LaunchDarkly request failed (403 Forbidden) for GET /api/v2/tokens?showAll=true: forbidden: access_denied", reason: "not_readable", truncated: null, seen: null, total: null, items: null }),
];

test("round 7a: every fixed-text message the LaunchDarkly integration emits survives its own scrubber unchanged, including every string a healthy or partially denied run records", async () => {
  for (const message of LD_FIXED_TEXT_MESSAGES) {
    assert.equal(scrubErrorText(message), message, `fixed text was altered by the scrubber: ${message}`);
  }

  // Every string a run writes about legitimate data is fixed text from the run's point of view: the scrubber must not
  // rewrite a finding summary, a manual-evidence instruction, an inventory gap, or a bundle document.
  const runs = [httpLaunchdarkly(ldPrincipalFixture())];
  for (const denial of LD_SINGLE_INVENTORY_DENIALS) {
    const fixture = ldPrincipalFixture();
    runs.push(httpLaunchdarkly(fixture, { routes: { [denial.route]: ldDenyDataset(ldRoutes(fixture), denial) } }));
  }
  let checked = 0;
  const altered = [];
  for (const { client, config } of runs) {
    const access = await checkLaunchdarklyAccess(client);
    const assessments = await runAllLaunchdarklyAssessments(client);
    const exported = await exportLaunchdarklyAuditBundle(client, config, createTempBase("grclanker-ld-fixed-text-"), { now: NOW });
    const files = readBundleFiles(exported.outputDir);
    const texts = [
      ...ldRecordedStrings(access, assessments, files),
      ...[...files].filter(([name]) => !name.startsWith("core_data/")).map(([, text]) => text),
      ...ldLeafEntries(assessments).map(([, value]) => value).filter((value) => typeof value === "string"),
    ];
    for (const text of texts) {
      checked += 1;
      const scrubbed = scrubErrorText(text);
      if (scrubbed !== text) altered.push(`${text.slice(0, 160)} -> ${scrubbed.slice(0, 160)}`);
    }
  }
  assert.ok(checked > 2000, `expected thousands of recorded strings, got ${checked}`);
  assert.deepEqual([...new Set(altered)], [], `legitimate run text altered by the scrubber:\n${[...new Set(altered)].join("\n")}`);
});

test("round 7b: resolveLaunchdarklyConfiguration keeps env-provided credentials and config path when an unrelated argument is passed, and the tool sends the env token", async () => {
  const registered = [];
  registerLaunchdarklyTools({ registerTool: (tool) => registered.push(tool) });
  const checkTool = registered.find((tool) => tool.name === "launchdarkly_check_access");
  const home = createTempBase("grclanker-ld-env-overlay-");
  const configPath = join(home, "canary.toml");
  writeFileSync(configPath, 'base_url = "https://app.eu.launchdarkly.com"\nallowed_domains = ["file.example"]\n', "utf8");
  const env = { LAUNCHDARKLY_API_TOKEN: TEST_TOKEN, LAUNCHDARKLY_CONFIG: configPath };

  // The tool's prepareArguments emits every auth key (undefined when not passed); that shape must not erase env values.
  const prepared = checkTool.prepareArguments({ timeout_seconds: 45 });
  assert.ok(Object.prototype.hasOwnProperty.call(prepared, "token") && prepared.token === undefined, "the overlay carries an undefined token key");
  const resolved = resolveLaunchdarklyConfiguration(prepared, env, { homeDir: home });
  assert.equal(resolved.token, TEST_TOKEN, "the env token survives an unrelated argument");
  assert.equal(resolved.configPath, configPath, "the env config path survives an unrelated argument");
  assert.equal(resolved.baseUrl, "https://app.eu.launchdarkly.com", "the file the env path names is still read");
  assert.deepEqual(resolved.allowedDomains, ["file.example"]);
  assert.equal(resolved.timeoutMs, 45000, "the unrelated argument still applies");
  assert.ok(resolved.sourceChain.includes("environment-token"), `source chain names env for the token: ${resolved.sourceChain.join(" -> ")}`);
  assert.ok(resolved.sourceChain.includes("config-base-url"), resolved.sourceChain.join(" -> "));

  // Through the registered tool with the environment set: every request carries the env token to the env-named instance.
  const saved = { LAUNCHDARKLY_API_TOKEN: process.env.LAUNCHDARKLY_API_TOKEN, LAUNCHDARKLY_CONFIG: process.env.LAUNCHDARKLY_CONFIG, LAUNCHDARKLY_BASE_URL: process.env.LAUNCHDARKLY_BASE_URL };
  const { log, fetchImpl } = httpLaunchdarkly(ldFixture());
  try {
    process.env.LAUNCHDARKLY_API_TOKEN = TEST_TOKEN;
    process.env.LAUNCHDARKLY_CONFIG = configPath;
    delete process.env.LAUNCHDARKLY_BASE_URL;
    const result = await runLaunchdarklyTool("launchdarkly_check_access", fetchImpl, { timeout_seconds: 45 });
    assert.notEqual(result.isError, true, result.content[0].text);
    assert.ok(log.length > 0, "requests were made");
    assert.ok(log.every((entry) => entry.authorization === TEST_TOKEN), "every request carries the env token");
    assert.ok(log.every((entry) => entry.host === "app.eu.launchdarkly.com"), "the base URL from the env-named config file is used");
    assert.match(result.content[0].text, /environment-token/);
    assertCanaryWindowsAbsent(assert, JSON.stringify(result), [TEST_TOKEN], "check_access result");
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
