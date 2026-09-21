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

  assert.deepEqual(members.map((member) => member._id), ["m1", "m2"]);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].pathname, "/api/v2/members");
  assert.equal(seen[0].auth, TEST_TOKEN);
  assert.equal(seen[0].version, "20240415");
  assert.match(seen[0].search, /limit=1/);
  assert.match(seen[0].search, /offset=0/);
  assert.match(seen[1].search, /offset=1/);
});

test("LaunchdarklyApiClient falls back to offset pagination when _links.next is absent and stops at the limit", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const offset = Number(url.searchParams.get("offset") ?? "0");
    seen.push(offset);
    return jsonResponse({ items: [{ _id: `t${offset}` }, { _id: `t${offset + 1}` }], totalCount: 6 });
  };

  const client = new LaunchdarklyApiClient(sampleConfig(), { fetchImpl });
  const tokens = await client.list("/api/v2/tokens", { showAll: "true" }, { limit: 3, pageSize: 2 });

  assert.equal(tokens.length, 3);
  assert.deepEqual(seen, [0, 2]);
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
      return jsonResponse({ items: [{ name: "hook", url: "https://example.com", secret: "whsec_super_secret" }] });
    }
    if (url.pathname.endsWith("/relay-auto-configs")) {
      return jsonResponse({ items: [{ name: "relay", fullKey: "rel-secret-9999" }] });
    }
    return jsonResponse({ items: [] });
  };

  const client = new LaunchdarklyApiClient(sampleConfig(), { fetchImpl });
  const sdkKeys = await client.listSdkKeys("web", "production");
  const environments = await client.listEnvironments("web");
  const webhooks = await client.listWebhooks();
  const relays = await client.listRelayProxyConfigs();

  assert.equal(seen.find((item) => item.pathname.endsWith("/sdk-keys"))?.version, "beta");
  assert.equal(seen.find((item) => item.pathname.endsWith("/environments"))?.version, "20240415");
  assert.equal(sdkKeys[0].value, "****1234");
  assert.equal(environments[0].apiKey, "****abcd");
  assert.equal(environments[0].mobileKey, "****efgh");
  assert.equal(webhooks[0].secret, "[REDACTED]");
  assert.equal(relays[0].fullKey, "****9999");
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
  assert.match(finding(identityUnreadable, "LD-08").summary, /caller identity could not be read/);
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
  for (const id of ["LD-08", "LD-09", "LD-10", "LD-11"]) {
    assert.equal(findingStatus(membersUnreadable, id), "warn", `${id} must not pass when the caller member cannot be resolved`);
    assert.match(finding(membersUnreadable, id).summary, /member record could not be resolved from the member listing/);
    assert.equal(finding(membersUnreadable, id).evidence.token_inventory.caller_member_role, null);
  }

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

test("assessLaunchdarklyAccessControl warns instead of passing when tokens cannot be read", async () => {
  const result = await assessLaunchdarklyAccessControl(healthyClient({
    async listTokens() {
      throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/tokens");
    },
  }), { now: NOW });

  for (const id of ["LD-08", "LD-09", "LD-10", "LD-11"]) {
    assert.equal(findingStatus(result, id), "warn", `${id} should warn`);
  }
  assert.ok(result.errors.some((error) => error.startsWith("access_tokens:")));
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
  assert.equal(findingStatus(unreadable, "LD-16"), "warn");
  assert.match(finding(unreadable, "LD-16").summary, /Custom roles could not be read/);
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
    async listSdkKeys() {
      throw new Error("LaunchDarkly request failed (404 Not Found) for GET /api/v2/projects/web/environments/production/sdk-keys");
    },
  }), { now: NOW });

  assert.equal(findingStatus(result, "LD-19"), "manual");
  assert.match(finding(result, "LD-19").summary, /Organization settings > SDK keys/);
  assert.equal(result.errors.length, 0);
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

test("assessLaunchdarklyFlagHygiene warns instead of passing when flags cannot be read", async () => {
  const result = await assessLaunchdarklyFlagHygiene(healthyClient({
    async listFlags() {
      throw new Error("LaunchDarkly request failed (403 Forbidden) for GET /api/v2/flags/web");
    },
  }), { now: NOW });

  assert.equal(findingStatus(result, "LD-14"), "warn");
  assert.equal(findingStatus(result, "LD-15"), "warn");
  assert.equal(findingStatus(result, "LD-25"), "warn");
  assert.ok(result.errors.some((error) => error.startsWith("flags:web/production")));
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
