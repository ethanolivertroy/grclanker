import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  DatadogApiClient,
  DatadogApiError,
  DATADOG_CONTROL_CATALOG,
  assessDatadogAccessControls,
  assessDatadogDataProtection,
  assessDatadogIdentity,
  assessDatadogSecurityMonitoring,
  checkDatadogAccess,
  datadogBaseUrlForSite,
  exportDatadogAuditBundle,
  normalizeDatadogSite,
  resolveDatadogConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/datadog.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const NOW = new Date("2026-09-21T00:00:00.000Z");

function daysAgo(days) {
  return new Date(NOW.getTime() - days * 86_400_000).toISOString();
}

function hoursAgo(hours) {
  return new Date(NOW.getTime() - hours * 3_600_000).toISOString();
}

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    apiKey: "api-key-0123456789abcdef",
    appKey: "app-key-0123456789abcdef",
    site: "datadoghq.com",
    baseUrl: "https://api.datadoghq.com",
    timeoutMs: 30_000,
    maxRetries: 3,
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

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function forbidden(path) {
  return new DatadogApiError(`Datadog request failed (403 Forbidden) GET ${path}: Forbidden`, 403, path);
}

function user(id, overrides = {}) {
  return {
    id,
    type: "users",
    attributes: {
      handle: `${id}@acme.example`,
      email: `${id}@acme.example`,
      name: id,
      status: "Active",
      disabled: false,
      mfa_enabled: true,
      service_account: false,
      created_at: daysAgo(400),
      last_login_time: daysAgo(2),
      ...overrides,
    },
  };
}

function role(id, name, userCount) {
  return { id, type: "roles", attributes: { name, user_count: userCount } };
}

function detectionRule(id, tags, overrides = {}) {
  return {
    id,
    name: `Rule ${id}`,
    type: "log_detection",
    isEnabled: true,
    isDefault: true,
    tags,
    ...overrides,
  };
}

function complianceRule(id, framework, overrides = {}) {
  return {
    id,
    name: `Compliance ${id}`,
    type: "cloud_configuration",
    isEnabled: true,
    isDefault: true,
    tags: [`framework:${framework}`, "cloud_provider:aws"],
    ...overrides,
  };
}

function healthyOrganization() {
  return {
    name: "Acme",
    public_id: "abc123",
    settings: {
      saml: { enabled: true },
      saml_strict_mode: { enabled: true },
      saml_idp_initiated_login: { enabled: true },
      saml_idp_metadata_uploaded: true,
      private_widget_share: false,
      saml_autocreate_users_domains: { enabled: true, domains: ["acme.example"] },
    },
  };
}

function healthyApplicationKeys() {
  return {
    data: [
      {
        id: "ak-1",
        type: "application_keys",
        attributes: {
          name: "ci-deploy",
          last4: "abcd",
          created_at: daysAgo(10),
          last_used_at: daysAgo(1),
          scopes: ["dashboards_read"],
        },
        relationships: { owned_by: { data: { id: "svc-terraform", type: "users" } } },
      },
    ],
    included: [user("svc-terraform", { service_account: true, last_login_time: undefined })],
  };
}

function healthySensitiveDataScanner() {
  return {
    data: { type: "sensitive_data_scanner_configuration", id: "cfg-1" },
    included: [
      {
        id: "group-1",
        type: "sensitive_data_scanner_group",
        attributes: { name: "PCI", is_enabled: true, product_list: ["logs", "apm", "rum", "events"] },
      },
      {
        id: "rule-1",
        type: "sensitive_data_scanner_rule",
        attributes: { name: "Credit Card Number", is_enabled: true, tags: ["pci"] },
        relationships: { standard_pattern: { data: { id: "std-1", type: "sensitive_data_scanner_standard_pattern" } } },
      },
    ],
  };
}

function healthyClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async validateApiKey() {
      return { valid: true };
    },
    async validateKeyPair() {
      return { status: "ok" };
    },
    async getOrganization() {
      return healthyOrganization();
    },
    async listOrgConfigs() {
      return [{ id: "monitor_timezone", type: "org_configs", attributes: { name: "monitor_timezone", value: "UTC" } }];
    },
    async listOrgConnections() {
      return [];
    },
    async listUsers() {
      return [
        user("alice"),
        user("bob"),
        user("svc-terraform", { service_account: true, last_login_time: undefined }),
      ];
    },
    async listRoles() {
      return [
        role("role-admin", "Datadog Admin Role", 2),
        role("role-standard", "Datadog Standard Role", 10),
        role("role-readonly", "Datadog Read Only Role", 5),
        role("role-auditor", "Auditor", 1),
      ];
    },
    async listRolePermissions() {
      return [{ id: "perm-1", type: "permissions", attributes: { name: "dashboards_read" } }];
    },
    async listApiKeys() {
      return [
        { id: "key-1", type: "api_keys", attributes: { name: "prod-agent", last4: "1234", created_at: daysAgo(10), date_last_used: daysAgo(1) } },
      ];
    },
    async listApplicationKeys() {
      return healthyApplicationKeys();
    },
    async listAuditEvents(options = {}) {
      if (options.sort === "timestamp") {
        return [{ id: "evt-old", type: "audit", attributes: { timestamp: daysAgo(100), service: "audit" } }];
      }
      return [
        { id: "evt-1", type: "audit", attributes: { timestamp: hoursAgo(2) } },
        { id: "evt-2", type: "audit", attributes: { timestamp: hoursAgo(20) } },
      ];
    },
    async listSecurityRules() {
      return [
        detectionRule("auth", ["tactic:TA0006-credential-access", "technique:T1110-brute-force"]),
        detectionRule("privesc", ["tactic:TA0004-privilege-escalation"]),
        detectionRule("exfil", ["tactic:TA0010-exfiltration"]),
        complianceRule("cis", "cis-aws-1.5.0"),
        complianceRule("pci", "pci-dss-4.0"),
        complianceRule("soc2", "soc-2"),
        complianceRule("hipaa", "hipaa"),
      ];
    },
    async listSecuritySignals() {
      return [];
    },
    async listPostureFindings(options = {}) {
      return options.evaluation === "fail"
        ? { data: [], total_filtered_count: 10 }
        : { data: [], total_filtered_count: 90 };
    },
    async getIpAllowlist() {
      return {
        data: {
          type: "ip_allowlist",
          id: "ip-1",
          attributes: {
            enabled: true,
            entries: [{ data: { type: "ip_allowlist_entry", id: "e1", attributes: { cidr_block: "203.0.113.0/24", note: "office" } } }],
          },
        },
      };
    },
    async getSensitiveDataScannerConfig() {
      return healthySensitiveDataScanner();
    },
    async listLogPipelines() {
      return [{ id: "p1", name: "cloudtrail", is_enabled: true, filter: { query: "source:cloudtrail" }, processors: [] }];
    },
    async listLogIndexes() {
      return [
        {
          name: "main",
          num_retention_days: 30,
          exclusion_filters: [{ name: "debug noise", is_enabled: true, filter: { query: "status:debug service:web", sample_rate: 1 } }],
        },
      ];
    },
    async listLogArchives() {
      return [{ id: "a1", type: "archives", attributes: { name: "s3-archive", state: "WORKING", destination: { type: "s3" } } }];
    },
    async listDashboards() {
      return [];
    },
    async listMonitors() {
      return [
        { id: 1, name: "Security: root login detected", tags: ["team:security"], priority: 1, message: "Root login detected @pagerduty-security @slack-sec-alerts" },
        { id: 2, name: "Web latency", tags: ["team:web"], message: "Latency high @slack-web" },
      ];
    },
    async listAwsIntegrations() {
      return [{ account_id: "123456789012", role_name: "DatadogIntegrationRole", cspm_resource_collection_enabled: true }];
    },
    async listGcpIntegrations() {
      return [];
    },
    async listAzureIntegrations() {
      return [];
    },
    ...overrides,
  };
}

function findingStatus(result, id) {
  return result.findings.find((item) => item.id === id)?.status;
}

function findingById(result, id) {
  return result.findings.find((item) => item.id === id);
}

const READ_METHODS = [
  "getOrganization",
  "listOrgConfigs",
  "listOrgConnections",
  "listUsers",
  "listRoles",
  "listRolePermissions",
  "listApiKeys",
  "listApplicationKeys",
  "listAuditEvents",
  "listSecurityRules",
  "listSecuritySignals",
  "listPostureFindings",
  "getIpAllowlist",
  "getSensitiveDataScannerConfig",
  "listLogPipelines",
  "listLogIndexes",
  "listLogArchives",
  "listDashboards",
  "listMonitors",
  "listAwsIntegrations",
  "listGcpIntegrations",
  "listAzureIntegrations",
];

function forbiddenClient() {
  const overrides = {};
  for (const method of READ_METHODS) {
    overrides[method] = async () => {
      throw forbidden(`/${method}`);
    };
  }
  return healthyClient(overrides);
}

function emptyClient(overrides = {}) {
  return healthyClient({
    async getOrganization() {
      return { name: "Empty", public_id: "empty", settings: {} };
    },
    async listOrgConfigs() {
      return [];
    },
    async listOrgConnections() {
      return [];
    },
    async listUsers() {
      return [];
    },
    async listRoles() {
      return [];
    },
    async listRolePermissions() {
      return [];
    },
    async listApiKeys() {
      return [];
    },
    async listApplicationKeys() {
      return { data: [], included: [] };
    },
    async listAuditEvents() {
      return [];
    },
    async listSecurityRules() {
      return [];
    },
    async listSecuritySignals() {
      return [];
    },
    async listPostureFindings() {
      return { data: [], total_filtered_count: null, truncated: false };
    },
    async getIpAllowlist() {
      return { data: { type: "ip_allowlist", id: "ip-1", attributes: {} } };
    },
    async getSensitiveDataScannerConfig() {
      return { data: {}, included: [] };
    },
    async listLogPipelines() {
      return [];
    },
    async listLogIndexes() {
      return [];
    },
    async listLogArchives() {
      return [];
    },
    async listDashboards() {
      return [];
    },
    async listMonitors() {
      return [];
    },
    async listAwsIntegrations() {
      return [];
    },
    async listGcpIntegrations() {
      return [];
    },
    async listAzureIntegrations() {
      return [];
    },
    ...overrides,
  });
}

function fill(count, factory) {
  return Array.from({ length: count }, (_, index) => factory(index));
}

// Fixture (c): every inventory is either truncated (the mock returns exactly the probe limit,
// which is limit + 1), permission-limited on a secondary surface, or missing a flag the
// verdict depends on. No control should pass on this view.
function partialClient(overrides = {}) {
  return healthyClient({
    async getOrganization() {
      return { name: "Partial", public_id: "partial", settings: { saml: { enabled: true }, private_widget_share: false } };
    },
    async listOrgConnections() {
      throw forbidden("/api/v2/org_connections");
    },
    async listUsers(limit) {
      return fill(limit, (index) => user(`u${index}`, index === 0 ? { handle: "svc-terraform@acme.example", service_account: true, last_login_time: undefined } : {}));
    },
    async listRoles(limit) {
      return fill(limit, (index) => role(`r${index}`, index === 0 ? "Datadog Admin Role" : `Custom ${index}`, 1));
    },
    async listRolePermissions() {
      throw forbidden("/api/v2/roles/r1/permissions");
    },
    async listApiKeys(limit) {
      return fill(limit, (index) => ({ id: `k${index}`, type: "api_keys", attributes: { name: `prod-agent-${index}`, last4: "0000", created_at: daysAgo(10), date_last_used: daysAgo(1) } }));
    },
    async listApplicationKeys(limit) {
      return {
        data: fill(limit, (index) => ({
          id: `ak${index}`,
          type: "application_keys",
          attributes: { name: `deploy-${index}`, last4: "1111", created_at: daysAgo(10), last_used_at: daysAgo(1), scopes: ["dashboards_read"] },
          relationships: { owned_by: { data: { id: "u1", type: "users" } } },
        })),
        included: [],
      };
    },
    async listAuditEvents(options = {}) {
      if (options.sort === "timestamp") {
        return [{ id: "evt-old", type: "audit", attributes: { timestamp: daysAgo(100) } }];
      }
      throw forbidden("/api/v2/audit/events");
    },
    async listSecurityRules(limit) {
      return fill(limit, (index) => (index % 2 === 0
        ? detectionRule(`det-${index}`, ["tactic:TA0006-credential-access", "tactic:TA0004-privilege-escalation", "tactic:TA0010-exfiltration"])
        : complianceRule(`cmp-${index}`, ["cis", "pci", "soc2", "hipaa"][Math.floor(index / 2) % 4])));
    },
    async listSecuritySignals(options = {}) {
      return fill(options.limit ?? 200, (index) => ({
        id: `sig-${index}`,
        type: "signal",
        attributes: { timestamp: hoursAgo(1), message: "Brute force", attributes: { status: "high", workflow: { triage: { state: "archived" } } } },
      }));
    },
    async listPostureFindings(options = {}) {
      return { data: fill(options.limit ?? 100, (index) => ({ id: `f${index}` })), total_filtered_count: null, truncated: true };
    },
    async getIpAllowlist() {
      return { data: { type: "ip_allowlist", id: "ip-1", attributes: { enabled: true } } };
    },
    async getSensitiveDataScannerConfig() {
      const configuration = healthySensitiveDataScanner();
      configuration.data.relationships = { groups: { data: [{ id: "group-1", type: "sensitive_data_scanner_group" }, { id: "group-2", type: "sensitive_data_scanner_group" }] } };
      return configuration;
    },
    async listLogArchives() {
      throw forbidden("/api/v2/logs/config/archives");
    },
    async listDashboards(options = {}) {
      return fill(options.limit ?? 100, (index) => ({ id: `dash-${index}`, title: `Shared ${index}` }));
    },
    async listMonitors(limit) {
      return fill(limit, (index) => ({ id: index, name: `Security monitor ${index}`, tags: ["team:security"], message: "@pagerduty-security" }));
    },
    ...overrides,
  });
}

async function assessAll(client) {
  const results = await Promise.all([
    assessDatadogIdentity(client, { now: NOW }),
    assessDatadogAccessControls(client, { now: NOW }),
    assessDatadogSecurityMonitoring(client, { now: NOW }),
    assessDatadogDataProtection(client, { now: NOW }),
  ]);
  const findings = new Map();
  for (const item of results.flatMap((result) => result.findings)) {
    findings.set(item.id, item);
  }
  return findings;
}

function statusMap(findings) {
  return Object.fromEntries([...findings.entries()].map(([id, item]) => [id, item.status]).sort(([a], [b]) => a.localeCompare(b)));
}

test("resolveDatadogConfiguration prefers explicit args over environment values", () => {
  const resolved = resolveDatadogConfiguration(
    {
      api_key: "arg-api-key-0123456789",
      app_key: "arg-app-key-0123456789",
      site: "us5.datadoghq.com",
      timeout_seconds: 9,
      max_retries: 1,
    },
    {
      DD_API_KEY: "env-api-key-0123456789",
      DD_APP_KEY: "env-app-key-0123456789",
      DD_SITE: "datadoghq.eu",
    },
    "/nonexistent-home",
  );

  assert.equal(resolved.apiKey, "arg-api-key-0123456789");
  assert.equal(resolved.appKey, "arg-app-key-0123456789");
  assert.equal(resolved.site, "us5.datadoghq.com");
  assert.equal(resolved.baseUrl, "https://api.us5.datadoghq.com");
  assert.equal(resolved.timeoutMs, 9000);
  assert.equal(resolved.maxRetries, 1);
  assert.ok(resolved.sourceChain.includes("arguments-api-key"));
  assert.ok(resolved.sourceChain.includes("arguments-site"));
});

test("resolveDatadogConfiguration falls back from environment to ~/.dogrc and maps DD_SITE to the API base URL", () => {
  const home = createTempBase("grclanker-datadog-home-");
  writeFileSync(join(home, ".dogrc"), [
    "[Connection]",
    "apikey = file-api-key-0123456789",
    "appkey = file-app-key-0123456789",
    "",
  ].join("\n"));

  const fromFile = resolveDatadogConfiguration({}, {}, home);
  assert.equal(fromFile.apiKey, "file-api-key-0123456789");
  assert.equal(fromFile.appKey, "file-app-key-0123456789");
  assert.equal(fromFile.site, "datadoghq.com");
  assert.equal(fromFile.baseUrl, "https://api.datadoghq.com");
  assert.ok(fromFile.sourceChain.includes("config-file-api-key"));

  const fromEnv = resolveDatadogConfiguration({}, {
    DD_API_KEY: "env-api-key-0123456789",
    DD_APPLICATION_KEY: "env-app-key-0123456789",
    DD_SITE: "ddog-gov.com",
  }, home);
  assert.equal(fromEnv.apiKey, "env-api-key-0123456789");
  assert.equal(fromEnv.appKey, "env-app-key-0123456789");
  assert.equal(fromEnv.baseUrl, "https://api.ddog-gov.com");
  assert.ok(fromEnv.sourceChain.includes("environment-site"));

  const explicitHost = resolveDatadogConfiguration({}, {
    DD_API_KEY: "env-api-key-0123456789",
    DD_APP_KEY: "env-app-key-0123456789",
    DD_SITE: "us3",
    DD_HOST: "https://api.us3.datadoghq.com/",
  }, home);
  assert.equal(explicitHost.site, "us3.datadoghq.com");
  assert.equal(explicitHost.baseUrl, "https://api.us3.datadoghq.com");

  assert.throws(() => resolveDatadogConfiguration({}, {}, "/nonexistent-home"), /DD_API_KEY/);
  assert.throws(() => resolveDatadogConfiguration({}, { DD_API_KEY: "only-api-key-0123456789" }, "/nonexistent-home"), /DD_APP_KEY/);
});

test("normalizeDatadogSite accepts every documented site, aliases, and hostnames", () => {
  assert.equal(normalizeDatadogSite(undefined), "datadoghq.com");
  assert.equal(normalizeDatadogSite("datadoghq.eu"), "datadoghq.eu");
  assert.equal(normalizeDatadogSite("us3.datadoghq.com"), "us3.datadoghq.com");
  assert.equal(normalizeDatadogSite("us5.datadoghq.com"), "us5.datadoghq.com");
  assert.equal(normalizeDatadogSite("ap1.datadoghq.com"), "ap1.datadoghq.com");
  assert.equal(normalizeDatadogSite("ap2.datadoghq.com"), "ap2.datadoghq.com");
  assert.equal(normalizeDatadogSite("ddog-gov.com"), "ddog-gov.com");
  assert.equal(normalizeDatadogSite("us2.ddog-gov.com"), "us2.ddog-gov.com");
  assert.equal(normalizeDatadogSite("app.datadoghq.eu"), "datadoghq.eu");
  assert.equal(normalizeDatadogSite("https://api.ddog-gov.com"), "ddog-gov.com");
  assert.equal(normalizeDatadogSite("eu"), "datadoghq.eu");
  assert.equal(normalizeDatadogSite("gov"), "ddog-gov.com");
  assert.equal(normalizeDatadogSite("us1-fed"), "ddog-gov.com");
  assert.equal(normalizeDatadogSite("US2-FED"), "us2.ddog-gov.com");
  assert.equal(datadogBaseUrlForSite("us2-fed"), "https://api.us2.ddog-gov.com");
  assert.equal(datadogBaseUrlForSite("ap1"), "https://api.ap1.datadoghq.com");
  assert.throws(() => normalizeDatadogSite("not a site"), /Unrecognized Datadog site/);
});

test("DatadogApiClient sends both key headers and paginates users with page[size] and page[number]", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      page: url.searchParams.get("page[number]"),
      size: url.searchParams.get("page[size]"),
      apiKey: headerValue(init.headers, "DD-API-KEY"),
      appKey: headerValue(init.headers, "DD-APPLICATION-KEY"),
      method: init.method,
    });
    const page = Number(url.searchParams.get("page[number]"));
    const size = Number(url.searchParams.get("page[size]"));
    const total = 150;
    const start = page * size;
    const ids = Array.from({ length: Math.max(0, Math.min(size, total - start)) }, (_, index) => `u${start + index + 1}`);
    return jsonResponse({
      data: ids.map((id) => user(id)),
      meta: { page: { total_count: total, total_filtered_count: total } },
    });
  };

  const client = new DatadogApiClient(sampleConfig(), { fetchImpl });
  const users = await client.listUsers(150);

  assert.equal(users.length, 150);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].pathname, "/api/v2/users");
  assert.equal(seen[0].method, "GET");
  assert.equal(seen[0].apiKey, "api-key-0123456789abcdef");
  assert.equal(seen[0].appKey, "app-key-0123456789abcdef");
  assert.deepEqual(seen.map((item) => item.page), ["0", "1"]);
  assert.equal(seen[0].size, "100");
  assert.equal(users[0].id, "u1");
  assert.equal(users[149].id, "u150");
});

test("DatadogApiClient follows meta.page.after cursors and page/page_size monitor paging", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(url);
    if (url.pathname === "/api/v2/audit/events") {
      if (!url.searchParams.get("page[cursor]")) {
        return jsonResponse({ data: [{ id: "e1", attributes: {} }], meta: { page: { after: "cursor-2" } } });
      }
      return jsonResponse({ data: [{ id: "e2", attributes: {} }], meta: { page: {} } });
    }
    if (url.pathname === "/api/v1/monitor") {
      const page = Number(url.searchParams.get("page"));
      return jsonResponse(page === 0 ? [{ id: 1 }, { id: 2 }] : [{ id: 3 }]);
    }
    if (url.pathname === "/api/v2/org_connections") {
      return jsonResponse({ data: [{ id: "c1", attributes: { connection_types: ["logs"] } }], meta: { page: { total_count: 1 } } });
    }
    throw new Error(`unexpected ${url.pathname}`);
  };

  const client = new DatadogApiClient(sampleConfig(), { fetchImpl });
  const events = await client.listAuditEvents({ from: "now-1d", to: "now", query: "@action:login", limit: 10 });
  assert.deepEqual(events.map((event) => event.id), ["e1", "e2"]);
  const auditCalls = seen.filter((url) => url.pathname === "/api/v2/audit/events");
  assert.equal(auditCalls[0].searchParams.get("filter[query]"), "@action:login");
  assert.equal(auditCalls[0].searchParams.get("filter[from]"), "now-1d");
  assert.equal(auditCalls[0].searchParams.get("page[limit]"), "10");
  assert.equal(auditCalls[1].searchParams.get("page[cursor]"), "cursor-2");

  const monitors = await client.listMonitors(2);
  assert.equal(monitors.length, 2);
  const monitorCalls = seen.filter((url) => url.pathname === "/api/v1/monitor");
  assert.equal(monitorCalls.length, 1);
  assert.equal(monitorCalls[0].searchParams.get("page_size"), "2");

  const connections = await client.listOrgConnections(25);
  assert.equal(connections.length, 1);
  const connectionCalls = seen.filter((url) => url.pathname === "/api/v2/org_connections");
  assert.equal(connectionCalls[0].searchParams.get("limit"), "25");
  assert.equal(connectionCalls[0].searchParams.get("offset"), "0");
  assert.equal(connectionCalls[0].searchParams.has("page[limit]"), false);
});

test("DatadogApiClient retries 429 honoring X-RateLimit-Reset and retries 5xx with backoff", async () => {
  const sleeps = [];
  let attempts = 0;
  const fetchImpl = async () => {
    attempts += 1;
    if (attempts === 1) {
      return jsonResponse({ errors: ["rate limited"] }, { status: 429, headers: { "X-RateLimit-Reset": "2" } });
    }
    if (attempts === 2) {
      return jsonResponse({ errors: ["upstream"] }, { status: 503 });
    }
    return jsonResponse({ valid: true });
  };

  const client = new DatadogApiClient(sampleConfig(), { fetchImpl, sleepImpl: async (ms) => { sleeps.push(ms); } });
  const result = await client.validateApiKey();
  assert.equal(result.valid, true);
  assert.equal(attempts, 3);
  assert.deepEqual(sleeps, [2000, 1000]);
});

test("DatadogApiClient surfaces exhausted retries, redacts keys, and reports timeouts", async () => {
  const config = sampleConfig({ maxRetries: 1 });
  const failing = new DatadogApiClient(config, {
    fetchImpl: async () => jsonResponse({ errors: [`bad key ${config.apiKey}`] }, { status: 500 }),
    sleepImpl: async () => {},
  });
  await assert.rejects(() => failing.validateApiKey(), (error) => {
    assert.ok(error instanceof DatadogApiError);
    assert.equal(error.status, 500);
    assert.doesNotMatch(error.message, /api-key-0123456789abcdef/);
    assert.match(error.message, /\[REDACTED\]/);
    return true;
  });

  const denied = new DatadogApiClient(config, {
    fetchImpl: async () => jsonResponse({ errors: ["Forbidden"] }, { status: 403 }),
  });
  await assert.rejects(() => denied.listUsers(1), (error) => {
    assert.ok(error instanceof DatadogApiError);
    assert.equal(error.status, 403);
    assert.equal(error.path, "/api/v2/users");
    return true;
  });

  const slow = new DatadogApiClient(sampleConfig({ timeoutMs: 20, maxRetries: 0 }), {
    fetchImpl: (_input, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new Error("aborted")));
    }),
  });
  await assert.rejects(() => slow.validateApiKey(), /timed out after 20ms/);
});

test("DatadogApiClient validates the key pair with GET /api/v2/validate_keys", async () => {
  const seen = [];
  const client = new DatadogApiClient(sampleConfig(), {
    fetchImpl: async (input, init = {}) => {
      seen.push({ url: new URL(typeof input === "string" ? input : input.toString()), init });
      return jsonResponse({ status: "ok" });
    },
  });
  const result = await client.validateKeyPair();
  assert.deepEqual(result, { status: "ok" });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url.pathname, "/api/v2/validate_keys");
  assert.equal(seen[0].init.method, "GET");
  assert.equal(headerValue(seen[0].init.headers, "DD-API-KEY"), "api-key-0123456789abcdef");
  assert.equal(headerValue(seen[0].init.headers, "DD-APPLICATION-KEY"), "app-key-0123456789abcdef");
});

test("DatadogApiClient pages org connections with limit and offset until the total is reached", async () => {
  const seen = [];
  const total = 2300;
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(url);
    const offset = Number(url.searchParams.get("offset"));
    const limit = Number(url.searchParams.get("limit"));
    const count = Math.max(0, Math.min(limit, total - offset));
    return jsonResponse({
      data: fill(count, (index) => ({ id: `c${offset + index}`, type: "org_connection", attributes: { connection_types: ["logs"] } })),
      meta: { page: { total_count: total, total_filtered_count: total } },
    });
  };
  const client = new DatadogApiClient(sampleConfig(), { fetchImpl });
  const connections = await client.listOrgConnections();
  assert.equal(connections.length, total);
  assert.equal(connections[total - 1].id, `c${total - 1}`);
  assert.deepEqual(seen.map((url) => url.searchParams.get("offset")), ["0", "1000", "2000"]);
  assert.ok(seen.every((url) => url.searchParams.get("limit") === "1000"));
  assert.ok(seen.every((url) => !url.searchParams.has("page[limit]")));

  const capped = await new DatadogApiClient(sampleConfig(), { fetchImpl }).listOrgConnections(1500);
  assert.equal(capped.length, 1500);
});

test("DatadogApiClient pages dashboards with count and start instead of relying on the default count of 100", async () => {
  const seen = [];
  const total = 250;
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(url);
    const start = Number(url.searchParams.get("start"));
    const count = Number(url.searchParams.get("count"));
    return jsonResponse({ dashboards: fill(Math.max(0, Math.min(count, total - start)), (index) => ({ id: `dash-${start + index}`, title: `Dashboard ${start + index}` })) });
  };
  const client = new DatadogApiClient(sampleConfig(), { fetchImpl });
  const dashboards = await client.listDashboards({ shared: true });
  assert.equal(dashboards.length, total);
  assert.deepEqual(seen.map((url) => url.searchParams.get("start")), ["0", "100", "200"]);
  assert.ok(seen.every((url) => url.searchParams.get("count") === "100"));
  assert.ok(seen.every((url) => url.searchParams.get("filter[shared]") === "true"));

  seen.length = 0;
  const probe = await client.listDashboards({ shared: true, limit: 1 });
  assert.equal(probe.length, 1);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].searchParams.get("count"), "1");
});

test("DatadogApiClient pages posture findings by cursor when total_filtered_count is absent and flags truncation", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(url);
    const pageLimit = Number(url.searchParams.get("page[limit]"));
    const cursor = url.searchParams.get("page[cursor]");
    const pageIndex = cursor ? Number(cursor.replace("cursor-", "")) : 0;
    const isLast = pageIndex === 2;
    return jsonResponse({
      data: fill(isLast ? 5 : pageLimit, (index) => ({ id: `f${pageIndex}-${index}`, type: "finding" })),
      meta: { page: isLast ? {} : { cursor: `cursor-${pageIndex + 1}` } },
    });
  };
  const client = new DatadogApiClient(sampleConfig(), { fetchImpl });

  const complete = await client.listPostureFindings({ evaluation: "fail", limit: 5000 });
  assert.equal(complete.data.length, 2005);
  assert.equal(complete.total_filtered_count, null);
  assert.equal(complete.truncated, false);
  assert.equal(seen.length, 3);
  assert.equal(seen[0].searchParams.get("filter[evaluation]"), "fail");
  assert.equal(seen[0].searchParams.get("page[limit]"), "1000");
  assert.equal(seen[0].searchParams.has("page[cursor]"), false);
  assert.equal(seen[1].searchParams.get("page[cursor]"), "cursor-1");
  assert.equal(seen[2].searchParams.get("page[cursor]"), "cursor-2");

  seen.length = 0;
  const truncated = await client.listPostureFindings({ evaluation: "fail", limit: 1500 });
  assert.equal(truncated.data.length, 1500);
  assert.equal(truncated.truncated, true);
  assert.equal(seen.length, 2);

  seen.length = 0;
  const counted = new DatadogApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      seen.push(new URL(typeof input === "string" ? input : input.toString()));
      return jsonResponse({ data: [{ id: "f1" }], meta: { page: { total_filtered_count: 4321, cursor: "more" } } });
    },
  });
  const result = await counted.listPostureFindings({ evaluation: "pass" });
  assert.equal(result.total_filtered_count, 4321);
  assert.equal(result.truncated, false);
  assert.equal(seen.length, 1);
});

test("checkDatadogAccess reports healthy access when every surface is readable", async () => {
  const result = await checkDatadogAccess(healthyClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.apiKeyValid, true);
  assert.equal(result.keyPairValid, true);
  assert.equal(result.surfaces.length, 22);
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 22);
  assert.equal(result.surfaces.find((surface) => surface.name === "validate_keys")?.endpoint, "/api/v2/validate_keys");
  assert.equal(result.surfaces.find((surface) => surface.name === "org_connections")?.permission, "org_connections_read");
  assert.deepEqual(result.missingPermissions, []);
  assert.match(result.recommendedNextStep, /datadog_assess_identity/);
});

test("checkDatadogAccess reports limited access and missing permissions on 403s", async () => {
  const result = await checkDatadogAccess(healthyClient({
    async listUsers() {
      throw forbidden("/api/v2/users");
    },
    async listSecurityRules() {
      throw forbidden("/api/v2/security_monitoring/rules");
    },
    async getIpAllowlist() {
      throw new Error("socket hang up");
    },
  }));
  assert.equal(result.status, "limited");
  assert.deepEqual(result.missingPermissions, ["user_access_read", "security_monitoring_rules_read"]);
  assert.equal(result.surfaces.find((surface) => surface.name === "users")?.status, "forbidden");
  assert.equal(result.surfaces.find((surface) => surface.name === "ip_allowlist")?.status, "not_readable");
  assert.match(result.recommendedNextStep, /missing read permissions/);

  const failed = await checkDatadogAccess(healthyClient({
    async validateApiKey() {
      throw forbidden("/api/v1/validate");
    },
  }));
  assert.equal(failed.status, "failed");
  assert.equal(failed.apiKeyValid, false);
});

test("checkDatadogAccess reports an invalid key pair, 401 denials, and the org connections probe", async () => {
  const pairInvalid = await checkDatadogAccess(healthyClient({
    async validateKeyPair() {
      throw forbidden("/api/v2/validate_keys");
    },
  }));
  assert.equal(pairInvalid.status, "limited");
  assert.equal(pairInvalid.apiKeyValid, true);
  assert.equal(pairInvalid.keyPairValid, false);
  assert.deepEqual(pairInvalid.missingPermissions, []);
  assert.ok(pairInvalid.notes.some((note) => /did not validate \(GET \/api\/v2\/validate_keys\)/.test(note)));

  const unauthorized = await checkDatadogAccess(healthyClient({
    async listOrgConnections() {
      throw new DatadogApiError("Datadog request failed (401 Unauthorized) GET /api/v2/org_connections", 401, "/api/v2/org_connections");
    },
  }));
  assert.equal(unauthorized.status, "limited");
  assert.equal(unauthorized.surfaces.find((surface) => surface.name === "org_connections")?.status, "forbidden");
  assert.deepEqual(unauthorized.missingPermissions, ["org_connections_read"]);

  const nothingReadable = await checkDatadogAccess(forbiddenClient());
  assert.equal(nothingReadable.status, "failed");
  assert.equal(nothingReadable.apiKeyValid, true);
  assert.equal(nothingReadable.surfaces.filter((surface) => surface.status === "forbidden").length, 20);
});

test("assessDatadogIdentity passes on a hardened tenant and marks session timeout as manual", async () => {
  const result = await assessDatadogIdentity(healthyClient(), { now: NOW });
  assert.equal(result.findings.length, 6);
  assert.equal(findingStatus(result, "DD-01"), "pass");
  assert.equal(findingStatus(result, "DD-02"), "pass");
  assert.equal(findingStatus(result, "DD-03"), "pass");
  assert.equal(findingStatus(result, "DD-04"), "pass");
  assert.equal(findingStatus(result, "DD-16"), "manual");
  assert.equal(findingStatus(result, "DD-19"), "pass");
  assert.match(result.findings.find((item) => item.id === "DD-16").summary, /Manual evidence required/);
  assert.deepEqual(result.errors, []);
  const saml = result.findings.find((item) => item.id === "DD-01");
  assert.ok(saml.mappings.includes("FedRAMP IA-2"));
  assert.ok(saml.mappings.includes("CMMC AC.L2-3.1.1"));
  assert.ok(saml.mappings.includes("ISMAP CPS-9.1"));
});

test("assessDatadogIdentity fails weak SSO, MFA, RBAC, access review, and service account posture", async () => {
  const result = await assessDatadogIdentity(healthyClient({
    async getOrganization() {
      return { settings: { saml: { enabled: false }, saml_strict_mode: { enabled: false } } };
    },
    async listUsers() {
      return [
        user("alice", { mfa_enabled: false }),
        user("bob", { last_login_time: daysAgo(200) }),
        user("carol", { status: "Pending", created_at: daysAgo(60) }),
        user("terraform", { service_account: true, last_login_time: daysAgo(3) }),
      ];
    },
    async listRoles() {
      return [role("role-admin", "Datadog Admin Role", 20), role("role-power", "Power Users", 4)];
    },
    async listRolePermissions() {
      return [{ attributes: { name: "org_management" } }, { attributes: { name: "dashboards_read" } }];
    },
    async listApplicationKeys() {
      return {
        data: [{
          id: "ak-old",
          attributes: { name: "legacy", last4: "zzzz", created_at: daysAgo(400), scopes: [] },
          relationships: { owned_by: { data: { id: "terraform", type: "users" } } },
        }],
        included: [],
      };
    },
  }), { now: NOW });

  assert.equal(findingStatus(result, "DD-01"), "fail");
  assert.equal(findingStatus(result, "DD-02"), "fail");
  assert.equal(findingStatus(result, "DD-03"), "fail");
  assert.equal(findingStatus(result, "DD-04"), "fail");
  assert.equal(findingStatus(result, "DD-19"), "fail");
  const rbac = result.findings.find((item) => item.id === "DD-03");
  assert.deepEqual(rbac.evidence.custom_roles_with_admin_equivalent_permissions, [{ role: "Power Users", permissions: ["org_management"] }]);
});

test("assessDatadogIdentity converts unreadable surfaces into manual findings", async () => {
  const result = await assessDatadogIdentity(healthyClient({
    async getOrganization() {
      throw forbidden("/api/v1/org");
    },
    async listUsers() {
      throw forbidden("/api/v2/users");
    },
  }), { now: NOW });
  assert.equal(findingStatus(result, "DD-01"), "manual");
  assert.equal(findingStatus(result, "DD-02"), "manual");
  assert.equal(findingStatus(result, "DD-04"), "manual");
  assert.match(result.findings.find((item) => item.id === "DD-01").summary, /403/);
  assert.equal(result.errors.length, 2);
});

test("DD-02 treats SAML strict mode without native MFA as manual with IdP evidence, never pass", async () => {
  const strict = await assessDatadogIdentity(healthyClient({
    async listUsers() {
      return [user("alice", { mfa_enabled: false }), user("bob")];
    },
  }), { now: NOW });
  const mfa = findingById(strict, "DD-02");
  assert.equal(mfa.status, "manual");
  assert.match(mfa.summary, /1\/2 active users lack Datadog-native MFA/);
  assert.match(mfa.summary, /does not expose whether the identity provider enforces a second factor/);
  assert.match(mfa.summary, /Okta authentication policy or Entra ID conditional access policy/);
  assert.equal(mfa.evidence.saml_strict_mode, true);
  assert.equal(mfa.evidence.users_without_native_mfa, 1);
  assert.deepEqual(mfa.evidence.users_without_native_mfa_sample, ["alice@acme.example"]);

  const passwordLogin = await assessDatadogIdentity(healthyClient({
    async getOrganization() {
      return { settings: { saml: { enabled: true }, saml_strict_mode: { enabled: false } } };
    },
    async listUsers() {
      return [user("alice", { mfa_enabled: false }), user("bob")];
    },
  }), { now: NOW });
  assert.equal(findingStatus(passwordLogin, "DD-02"), "fail");

  const missingFlag = await assessDatadogIdentity(healthyClient({
    async listUsers() {
      return [user("alice", { mfa_enabled: undefined })];
    },
  }), { now: NOW });
  assert.equal(findingStatus(missingFlag, "DD-02"), "manual");
  assert.equal(findingById(missingFlag, "DD-02").evidence.users_without_native_mfa, 1);
});

test("DD-03 is manual, never pass, when custom role permissions cannot be read", async () => {
  const unreadable = await assessDatadogIdentity(healthyClient({
    async listRolePermissions() {
      throw forbidden("/api/v2/roles/role-auditor/permissions");
    },
  }), { now: NOW });
  const rbac = findingById(unreadable, "DD-03");
  assert.equal(rbac.status, "manual");
  assert.match(rbac.summary, /1\/1 custom roles could not have their permissions read/);
  assert.match(rbac.summary, /Auditor/);
  assert.equal(rbac.evidence.custom_roles_without_permission_detail, 1);
  assert.match(rbac.evidence.custom_roles_without_permission_detail_sample[0].error, /403/);
  assert.ok(unreadable.errors.some((error) => /role_permissions\(Auditor\)/.test(error)));

  const mixed = await assessDatadogIdentity(healthyClient({
    async listRoles() {
      return [role("role-admin", "Datadog Admin Role", 2), role("role-power", "Power Users", 4), role("role-auditor", "Auditor", 1)];
    },
    async listRolePermissions(roleId) {
      if (roleId === "role-power") return [{ attributes: { name: "org_management" } }];
      throw forbidden(`/api/v2/roles/${roleId}/permissions`);
    },
  }), { now: NOW });
  const mixedRbac = findingById(mixed, "DD-03");
  assert.equal(mixedRbac.status, "fail");
  assert.deepEqual(mixedRbac.evidence.verdict_caveats, ["1 custom roles could not have their permissions read."]);

  const noAdminCount = await assessDatadogIdentity(healthyClient({
    async listRoles() {
      return [{ id: "role-admin", attributes: { name: "Datadog Admin Role" } }, role("role-auditor", "Auditor", 1)];
    },
  }), { now: NOW });
  assert.equal(findingStatus(noAdminCount, "DD-03"), "warn");
  assert.match(findingById(noAdminCount, "DD-03").summary, /user_count\) was not returned/);
});

test("identity findings never pass on empty user or role inventories", async () => {
  const result = await assessDatadogIdentity(healthyClient({
    async listUsers() {
      return [];
    },
    async listRoles() {
      return [];
    },
  }), { now: NOW });
  for (const id of ["DD-02", "DD-03", "DD-04", "DD-19"]) {
    assert.equal(findingStatus(result, id), "manual", `${id} should be manual on an empty inventory`);
    assert.match(findingById(result, id).summary, /treated as (unverifiable|not applicable) rather than compliant/);
  }
  assert.match(findingById(result, "DD-03").summary, /three managed Datadog roles/);

  const noServiceAccounts = await assessDatadogIdentity(healthyClient({
    async listUsers() {
      return [user("alice"), user("bob")];
    },
  }), { now: NOW });
  assert.equal(findingStatus(noServiceAccounts, "DD-19"), "manual");
  assert.match(findingById(noServiceAccounts, "DD-19").summary, /treated as not applicable rather than compliant/);
});

test("identity findings bucket undated users and keys and cap the verdict at warn", async () => {
  const result = await assessDatadogIdentity(healthyClient({
    async listUsers() {
      return [
        user("alice"),
        user("dana", { last_login_time: undefined, created_at: undefined }),
        user("svc-terraform", { service_account: true, last_login_time: undefined }),
      ];
    },
    async listApplicationKeys() {
      return {
        data: [{
          id: "ak-undated",
          attributes: { name: "ci-deploy", last4: "abcd", scopes: ["dashboards_read"] },
          relationships: { owned_by: { data: { id: "svc-terraform", type: "users" } } },
        }],
        included: [user("svc-terraform", { service_account: true, last_login_time: undefined })],
      };
    },
  }), { now: NOW });
  const access = findingById(result, "DD-04");
  assert.equal(access.status, "warn");
  assert.match(access.summary, /Downgraded to warn: .*neither last_login_time nor created_at/);
  assert.deepEqual(access.evidence.active_users_without_login_or_creation_date, ["dana@acme.example"]);
  const serviceAccounts = findingById(result, "DD-19");
  assert.equal(serviceAccounts.status, "warn");
  assert.match(serviceAccounts.summary, /have no created_at and were not counted as rotated/);
});

test("identity findings flag truncated user and role inventories instead of passing", async () => {
  const result = await assessDatadogIdentity(healthyClient({
    async listUsers(limit) {
      return fill(limit, (index) => user(`u${index}`));
    },
    async listRoles(limit) {
      return fill(limit, (index) => role(`r${index}`, index === 0 ? "Datadog Admin Role" : `Custom ${index}`, 1));
    },
  }), { now: NOW, userLimit: 50, roleLimit: 10 });
  for (const id of ["DD-02", "DD-03", "DD-04"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "warn", `${id} should warn on a truncated inventory`);
    assert.match(item.summary, /inventory is truncated at (50|10) items \(raise (user_limit|role_limit)\)/);
  }
  assert.equal(findingById(result, "DD-02").evidence.users_inventory_truncated, true);
  assert.equal(findingById(result, "DD-02").evidence.active_human_users, 50);
  assert.equal(findingById(result, "DD-03").evidence.roles_inventory_truncated, true);
  assert.equal(result.summary.users, 50);
  assert.ok(result.errors.some((error) => /users: inventory truncated at 50 items/.test(error)));
  assert.ok(result.errors.some((error) => /roles: inventory truncated at 10 items/.test(error)));
});

test("assessDatadogAccessControls passes on rotated keys, closed sharing, and a scoped allowlist", async () => {
  const result = await assessDatadogAccessControls(healthyClient(), { now: NOW });
  assert.equal(result.findings.length, 5);
  assert.equal(findingStatus(result, "DD-05"), "pass");
  assert.equal(findingStatus(result, "DD-06"), "pass");
  assert.equal(findingStatus(result, "DD-14"), "pass");
  assert.equal(findingStatus(result, "DD-15"), "pass");
  assert.equal(findingStatus(result, "DD-18"), "manual");
  assert.deepEqual(result.findings.find((item) => item.id === "DD-18").evidence.manual_evidence.length, 3);
});

test("assessDatadogAccessControls fails stale keys, orphaned keys, public sharing, and a disabled allowlist", async () => {
  const result = await assessDatadogAccessControls(healthyClient({
    async getOrganization() {
      return { settings: { private_widget_share: true } };
    },
    async listApiKeys() {
      return [
        { id: "k1", attributes: { name: "prod-agent", last4: "1111", created_at: daysAgo(200), date_last_used: daysAgo(1) } },
        { id: "k2", attributes: { name: "test", last4: "2222", created_at: daysAgo(5) } },
      ];
    },
    async listApplicationKeys() {
      return {
        data: [{
          id: "ak-1",
          attributes: { name: "old-script", last4: "9999", created_at: daysAgo(300), scopes: [] },
          relationships: { owned_by: { data: { id: "gone", type: "users" } } },
        }],
        included: [user("gone", { status: "Disabled", disabled: true })],
      };
    },
    async listDashboards() {
      return [{ id: "dash-1", title: "Ops overview" }];
    },
    async getIpAllowlist() {
      return { data: { attributes: { enabled: false, entries: [{ data: { attributes: { cidr_block: "0.0.0.0/0" } } }] } } };
    },
    async listAwsIntegrations() {
      return [{ account_id: "999999999999", access_key_id: "AKIAEXAMPLE" }];
    },
  }), { now: NOW });

  assert.equal(findingStatus(result, "DD-05"), "fail");
  assert.equal(findingStatus(result, "DD-06"), "fail");
  assert.equal(findingStatus(result, "DD-14"), "fail");
  assert.equal(findingStatus(result, "DD-15"), "fail");
  assert.equal(findingStatus(result, "DD-18"), "manual");
  assert.match(result.findings.find((item) => item.id === "DD-18").summary, /static access keys/);

  const broad = await assessDatadogAccessControls(healthyClient({
    async getIpAllowlist() {
      return { data: { attributes: { enabled: true, entries: [{ data: { attributes: { cidr_block: "10.0.0.0/8" } } }] } } };
    },
  }), { now: NOW });
  assert.equal(findingStatus(broad, "DD-15"), "fail");
  assert.match(broad.findings.find((item) => item.id === "DD-15").summary, /overly broad/);
});

test("DD-14 is manual, never pass, when org settings are unreadable or omit private_widget_share", async () => {
  const orgForbidden = await assessDatadogAccessControls(healthyClient({
    async getOrganization() {
      throw forbidden("/api/v1/org");
    },
  }), { now: NOW });
  const sharing = findingById(orgForbidden, "DD-14");
  assert.equal(sharing.status, "manual");
  assert.match(sharing.summary, /organization settings \(org_management\).*403/);
  assert.match(sharing.summary, /private_widget_share setting was therefore never read/);
  assert.equal(sharing.evidence.private_widget_share, null);
  assert.equal(sharing.evidence.organization_settings_readable, false);
  assert.ok(sharing.evidence.manual_evidence.some((step) => /private_widget_share/.test(step)));

  const settingMissing = await assessDatadogAccessControls(healthyClient({
    async getOrganization() {
      return { name: "Acme", settings: { saml: { enabled: true } } };
    },
  }), { now: NOW });
  assert.equal(findingStatus(settingMissing, "DD-14"), "manual");
  assert.match(findingById(settingMissing, "DD-14").summary, /did not include the private_widget_share setting/);

  const dashboardsForbidden = await assessDatadogAccessControls(healthyClient({
    async listDashboards() {
      throw forbidden("/api/v1/dashboard");
    },
  }), { now: NOW });
  assert.equal(findingStatus(dashboardsForbidden, "DD-14"), "manual");
  assert.match(findingById(dashboardsForbidden, "DD-14").summary, /dashboards \(dashboards_read\)/);
});

test("access control findings never pass on empty key inventories or an allowlist without its enabled flag", async () => {
  const result = await assessDatadogAccessControls(healthyClient({
    async listApiKeys() {
      return [];
    },
    async listApplicationKeys() {
      return { data: [], included: [] };
    },
    async getIpAllowlist() {
      return { data: { type: "ip_allowlist", id: "ip-1", attributes: { entries: [] } } };
    },
  }), { now: NOW });
  assert.equal(findingStatus(result, "DD-05"), "manual");
  assert.match(findingById(result, "DD-05").summary, /API key used for this request must exist.*unverifiable rather than compliant/);
  assert.equal(findingStatus(result, "DD-06"), "manual");
  assert.match(findingById(result, "DD-06").summary, /application key used for this request must exist/);
  assert.equal(findingStatus(result, "DD-15"), "manual");
  assert.match(findingById(result, "DD-15").summary, /did not include the enabled flag/);
  assert.equal(findingById(result, "DD-15").evidence.enabled, null);

  const noEntries = await assessDatadogAccessControls(healthyClient({
    async getIpAllowlist() {
      return { data: { type: "ip_allowlist", id: "ip-1", attributes: { enabled: true } } };
    },
  }), { now: NOW });
  assert.equal(findingStatus(noEntries, "DD-15"), "warn");
  assert.match(findingById(noEntries, "DD-15").summary, /returned no CIDR entries/);
});

test("access control findings bucket undated keys and unresolved owners and cap the verdict at warn", async () => {
  const result = await assessDatadogAccessControls(healthyClient({
    async listApiKeys() {
      return [
        { id: "k1", type: "api_keys", attributes: { name: "prod-agent", last4: "1111", created_at: daysAgo(10), date_last_used: daysAgo(1) } },
        { id: "k2", type: "api_keys", attributes: { name: "legacy-collector", last4: "2222", date_last_used: daysAgo(1) } },
      ];
    },
    async listApplicationKeys() {
      return {
        data: [
          {
            id: "ak-1",
            type: "application_keys",
            attributes: { name: "ci-deploy", last4: "abcd", scopes: ["dashboards_read"] },
            relationships: { owned_by: { data: { id: "missing-owner", type: "users" } } },
          },
        ],
        included: [],
      };
    },
  }), { now: NOW });
  const apiKeys = findingById(result, "DD-05");
  assert.equal(apiKeys.status, "warn");
  assert.match(apiKeys.summary, /Downgraded to warn: 1 API keys have no created_at and were not counted as rotated/);
  assert.equal(apiKeys.evidence.keys_without_created_at_count, 1);
  const appKeys = findingById(result, "DD-06");
  assert.equal(appKeys.status, "warn");
  assert.match(appKeys.summary, /1 application keys have no owner record in the response/);
  assert.match(appKeys.summary, /neither last_used_at nor created_at/);
  assert.equal(appKeys.evidence.keys_without_resolved_owner, 1);
  assert.deepEqual(appKeys.evidence.keys_without_any_date, ["ci-deploy (...abcd)"]);
});

test("access control findings flag truncated key and shared dashboard inventories instead of passing", async () => {
  const result = await assessDatadogAccessControls(healthyClient({
    async listApiKeys(limit) {
      return fill(limit, (index) => ({ id: `k${index}`, type: "api_keys", attributes: { name: `prod-agent-${index}`, last4: "0000", created_at: daysAgo(10), date_last_used: daysAgo(1) } }));
    },
    async listApplicationKeys(limit) {
      return {
        data: fill(limit, (index) => ({
          id: `ak${index}`,
          type: "application_keys",
          attributes: { name: `deploy-${index}`, last4: "1111", created_at: daysAgo(10), last_used_at: daysAgo(1), scopes: ["dashboards_read"] },
          relationships: { owned_by: { data: { id: "svc-terraform", type: "users" } } },
        })),
        included: [user("svc-terraform", { service_account: true })],
      };
    },
    async listDashboards(options = {}) {
      return fill(options.limit ?? 100, (index) => ({ id: `dash-${index}`, title: `Shared ${index}` }));
    },
  }), { now: NOW, keyLimit: 20 });
  for (const id of ["DD-05", "DD-06"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "warn", `${id} should warn on a truncated inventory`);
    assert.match(item.summary, /inventory is truncated at 20 items \(raise key_limit\)/);
  }
  assert.equal(findingById(result, "DD-05").evidence.api_keys_inventory_truncated, true);
  assert.equal(findingById(result, "DD-06").evidence.application_keys_inventory_truncated, true);
  const sharing = findingById(result, "DD-14");
  assert.equal(sharing.status, "warn");
  assert.equal(sharing.evidence.shared_dashboards_inventory_truncated, true);
  assert.equal(sharing.evidence.shared_dashboards, 2000);
  assert.deepEqual(sharing.evidence.verdict_caveats, ["shared_dashboards inventory is truncated at 2000 items (raise the dashboard limit), so the verdict covers a partial view."]);
  assert.ok(result.errors.some((error) => /shared_dashboards: inventory truncated at 2000 items/.test(error)));
});

test("assessDatadogSecurityMonitoring passes with enabled rules, clean signals, CSPM, coverage, and routed monitors", async () => {
  const result = await assessDatadogSecurityMonitoring(healthyClient(), { now: NOW });
  assert.equal(result.findings.length, 5);
  assert.equal(findingStatus(result, "DD-08"), "pass");
  assert.equal(findingStatus(result, "DD-09"), "pass");
  assert.equal(findingStatus(result, "DD-12"), "pass");
  assert.equal(findingStatus(result, "DD-13"), "pass");
  assert.equal(findingStatus(result, "DD-17"), "pass");
  assert.equal(result.findings.find((item) => item.id === "DD-12").evidence.posture_pass_rate, 0.9);
});

test("assessDatadogSecurityMonitoring fails disabled rules, overdue signals, missing CSPM, coverage gaps, and silent monitors", async () => {
  const result = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecurityRules() {
      return [detectionRule("auth", ["tactic:TA0006-credential-access"], { isEnabled: false })];
    },
    async listSecuritySignals() {
      return [
        {
          id: "sig-1",
          type: "signal",
          attributes: {
            timestamp: hoursAgo(200),
            message: "Brute force",
            attributes: { status: "critical", workflow: { triage: { state: "open" } } },
          },
        },
        {
          id: "sig-2",
          type: "signal",
          attributes: {
            timestamp: hoursAgo(1),
            attributes: { status: "high", workflow: { triage: { state: "archived" } } },
          },
        },
      ];
    },
    async listPostureFindings() {
      throw forbidden("/api/v2/posture_management/findings");
    },
    async listMonitors() {
      return [{ id: 7, name: "Security audit failure", tags: ["security"], message: "Investigate" }];
    },
    async listAwsIntegrations() {
      return [{ account_id: "123456789012", role_name: "DatadogIntegrationRole", cspm_resource_collection_enabled: false }];
    },
  }), { now: NOW, signalSlaHours: 72 });

  assert.equal(findingStatus(result, "DD-08"), "fail");
  assert.equal(findingStatus(result, "DD-09"), "fail");
  assert.equal(findingStatus(result, "DD-12"), "fail");
  assert.equal(findingStatus(result, "DD-13"), "fail");
  assert.equal(findingStatus(result, "DD-17"), "fail");
  const signals = result.findings.find((item) => item.id === "DD-09");
  assert.equal(signals.evidence.overdue_signals, 1);
  assert.equal(signals.evidence.unresolved_high_or_critical_signals, 1);

  const emailOnly = await assessDatadogSecurityMonitoring(healthyClient({
    async listMonitors() {
      return [{ id: 8, name: "IAM policy change", tags: ["team:security"], message: "Notify @analyst@acme.example" }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(emailOnly, "DD-17"), "warn");
});

test("DD-12 is manual when either the rules or the posture findings source is unreadable", async () => {
  const rulesForbidden = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecurityRules() {
      throw forbidden("/api/v2/security_monitoring/rules");
    },
  }), { now: NOW });
  const cspm = findingById(rulesForbidden, "DD-12");
  assert.equal(cspm.status, "manual");
  assert.match(cspm.summary, /security_rules \(security_monitoring_rules_read\) \(403 forbidden\)/);
  assert.doesNotMatch(cspm.summary, /is not active/);
  assert.equal(cspm.evidence.rules_readable, false);
  assert.equal(cspm.evidence.posture_findings_readable, true);

  const postureForbidden = await assessDatadogSecurityMonitoring(healthyClient({
    async listPostureFindings(options = {}) {
      if (options.evaluation === "pass") throw forbidden("/api/v2/posture_management/findings");
      return { data: [], total_filtered_count: 10 };
    },
  }), { now: NOW });
  assert.equal(findingStatus(postureForbidden, "DD-12"), "manual");
  assert.match(findingById(postureForbidden, "DD-12").summary, /CSPM appears active.*posture_findings_pass/);

  const integrationsForbidden = await assessDatadogSecurityMonitoring(healthyClient({
    async listGcpIntegrations() {
      throw forbidden("/api/v1/integration/gcp");
    },
  }), { now: NOW });
  assert.equal(findingStatus(integrationsForbidden, "DD-12"), "manual");
  assert.match(findingById(integrationsForbidden, "DD-12").summary, /gcp_integrations \(gcp_configuration_read\)/);
});

test("DD-12 downgrades to warn when posture counts are truncated instead of reporting a fixed rate", async () => {
  const truncated = await assessDatadogSecurityMonitoring(healthyClient({
    async listPostureFindings(options = {}) {
      return { data: fill(options.limit ?? 100, (index) => ({ id: `f${index}` })), total_filtered_count: null, truncated: true };
    },
  }), { now: NOW, findingLimit: 100 });
  const cspm = findingById(truncated, "DD-12");
  assert.equal(cspm.status, "warn");
  assert.match(cspm.summary, /carried no total_filtered_count and the paged counts hit the finding_limit/);
  assert.equal(cspm.evidence.posture_counts_truncated, true);
  assert.equal(cspm.evidence.posture_count_source, "paged_data");

  const pagedToCompletion = await assessDatadogSecurityMonitoring(healthyClient({
    async listPostureFindings(options = {}) {
      return {
        data: fill(options.evaluation === "fail" ? 5 : 95, (index) => ({ id: `${options.evaluation}-${index}` })),
        total_filtered_count: null,
        truncated: false,
      };
    },
  }), { now: NOW });
  const complete = findingById(pagedToCompletion, "DD-12");
  assert.equal(complete.status, "pass");
  assert.equal(complete.evidence.posture_pass_rate, 0.95);
  assert.match(complete.summary, /counted from paged findings/);

  const noFindings = await assessDatadogSecurityMonitoring(healthyClient({
    async listPostureFindings() {
      return { data: [], total_filtered_count: null, truncated: false };
    },
  }), { now: NOW });
  assert.equal(findingStatus(noFindings, "DD-12"), "warn");
  assert.match(findingById(noFindings, "DD-12").summary, /no posture findings were returned yet/);
});

test("security monitoring findings never pass on empty rule, signal, or monitor inventories", async () => {
  const result = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecurityRules() {
      return [];
    },
    async listSecuritySignals() {
      return [];
    },
    async listMonitors() {
      return [];
    },
  }), { now: NOW });
  assert.equal(findingStatus(result, "DD-08"), "fail");
  assert.match(findingById(result, "DD-08").summary, /empty rule inventory is treated as fail/);
  assert.equal(findingStatus(result, "DD-09"), "manual");
  assert.match(findingById(result, "DD-09").summary, /no detection rules are enabled.*unverifiable rather than compliant/);
  assert.equal(findingStatus(result, "DD-13"), "fail");
  assert.match(findingById(result, "DD-13").summary, /empty compliance rule set is treated as fail/);
  assert.equal(findingStatus(result, "DD-17"), "manual");
  assert.match(findingById(result, "DD-17").summary, /empty inventory is treated as unverifiable/);

  const rulesUnreadable = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecurityRules() {
      throw forbidden("/api/v2/security_monitoring/rules");
    },
  }), { now: NOW });
  assert.equal(findingStatus(rulesUnreadable, "DD-09"), "manual");
  assert.match(findingById(rulesUnreadable, "DD-09").summary, /detection rule inventory was not readable/);

  const noIntegrations = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecurityRules() {
      return [detectionRule("auth", ["tactic:TA0006-credential-access"])];
    },
    async listAwsIntegrations() {
      return [];
    },
  }), { now: NOW });
  assert.equal(findingStatus(noIntegrations, "DD-12"), "manual");
  assert.match(findingById(noIntegrations, "DD-12").summary, /no cloud footprint.*not applicable rather than compliant/);
});

test("security monitoring findings flag truncated rule, signal, and monitor inventories instead of passing", async () => {
  const result = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecurityRules(limit) {
      return fill(limit, (index) => (index % 2 === 0
        ? detectionRule(`det-${index}`, ["tactic:TA0006-credential-access", "tactic:TA0004-privilege-escalation", "tactic:TA0010-exfiltration"])
        : complianceRule(`cmp-${index}`, ["cis", "pci", "soc2", "hipaa"][Math.floor(index / 2) % 4])));
    },
    async listSecuritySignals(options = {}) {
      return fill(options.limit ?? 200, (index) => ({
        id: `sig-${index}`,
        type: "signal",
        attributes: { timestamp: hoursAgo(1), attributes: { status: "high", workflow: { triage: { state: "archived" } } } },
      }));
    },
    async listMonitors(limit) {
      return fill(limit, (index) => ({ id: index, name: `Security monitor ${index}`, tags: ["team:security"], message: "@pagerduty-security" }));
    },
  }), { now: NOW, ruleLimit: 40, signalLimit: 10, monitorLimit: 30 });
  for (const [id, limit, argument] of [["DD-08", 40, "rule_limit"], ["DD-13", 40, "rule_limit"], ["DD-17", 30, "monitor_limit"]]) {
    const item = findingById(result, id);
    assert.equal(item.status, "warn", `${id} should warn on a truncated inventory`);
    assert.match(item.summary, new RegExp(`inventory is truncated at ${limit} items \\(raise ${argument}\\)`));
  }
  assert.equal(findingById(result, "DD-08").evidence.rules_inventory_truncated, true);
  assert.equal(findingById(result, "DD-12").evidence.rules_inventory_truncated, true);
  assert.equal(findingById(result, "DD-17").evidence.monitors_inventory_truncated, true);
  const signals = findingById(result, "DD-09");
  assert.equal(signals.status, "warn");
  assert.equal(signals.evidence.signals_inventory_truncated, true);
  assert.equal(signals.evidence.unresolved_high_or_critical_signals, 0);
  assert.match(signals.summary, /truncated list of 10 items that were all archived/);

  const openSignals = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecuritySignals(options = {}) {
      return fill(options.limit ?? 200, (index) => ({
        id: `sig-${index}`,
        type: "signal",
        attributes: { timestamp: index === 0 ? undefined : hoursAgo(1), attributes: { status: "high", workflow: { triage: { state: "open" } } } },
      }));
    },
  }), { now: NOW, signalLimit: 5 });
  const open = findingById(openSignals, "DD-09");
  assert.equal(open.status, "warn");
  assert.equal(open.evidence.signals_without_timestamp, 1);
  assert.match(open.summary, /1 signals have no timestamp and could not be aged/);
  assert.match(open.summary, /truncated at 5 items \(raise signal_limit\)/);
});

test("assessDatadogDataProtection passes with an active audit trail, safe indexes, archives, scanner coverage, and closed org settings", async () => {
  const result = await assessDatadogDataProtection(healthyClient(), { now: NOW });
  assert.equal(result.findings.length, 4);
  assert.equal(findingStatus(result, "DD-07"), "pass");
  assert.equal(findingStatus(result, "DD-10"), "pass");
  assert.equal(findingStatus(result, "DD-11"), "pass");
  assert.equal(findingStatus(result, "DD-20"), "pass");
  assert.equal(result.findings.find((item) => item.id === "DD-07").evidence.oldest_event_age_days, 100);
});

test("assessDatadogDataProtection fails a silent audit trail, dropped security logs, an idle scanner, and open sharing", async () => {
  const result = await assessDatadogDataProtection(healthyClient({
    async getOrganization() {
      return { settings: { private_widget_share: true } };
    },
    async listAuditEvents() {
      return [];
    },
    async listLogIndexes() {
      return [{
        name: "main",
        num_retention_days: 7,
        exclusion_filters: [{ name: "drop cloudtrail", is_enabled: true, filter: { query: "source:cloudtrail", sample_rate: 1 } }],
      }];
    },
    async listLogArchives() {
      return [];
    },
    async getSensitiveDataScannerConfig() {
      return { data: {}, included: [{ id: "g", type: "sensitive_data_scanner_group", attributes: { is_enabled: false, product_list: ["logs"] } }] };
    },
  }), { now: NOW });

  assert.equal(findingStatus(result, "DD-07"), "fail");
  assert.equal(findingStatus(result, "DD-10"), "fail");
  assert.equal(findingStatus(result, "DD-11"), "fail");
  assert.equal(findingStatus(result, "DD-20"), "fail");

  const shortRetention = await assessDatadogDataProtection(healthyClient({
    async listAuditEvents(options = {}) {
      return options.sort === "timestamp"
        ? [{ id: "evt", attributes: { timestamp: daysAgo(20) } }]
        : [{ id: "evt", attributes: { timestamp: hoursAgo(1) } }];
    },
    async listLogArchives() {
      return [];
    },
  }), { now: NOW, minAuditRetentionDays: 90 });
  assert.equal(findingStatus(shortRetention, "DD-07"), "warn");
  assert.equal(findingStatus(shortRetention, "DD-10"), "warn");
});

test("DD-20 is manual, never pass, when org connections or org settings are unreadable", async () => {
  const connectionsForbidden = await assessDatadogDataProtection(healthyClient({
    async listOrgConnections() {
      throw forbidden("/api/v2/org_connections");
    },
  }), { now: NOW });
  const orgSettings = findingById(connectionsForbidden, "DD-20");
  assert.equal(orgSettings.status, "manual");
  assert.match(orgSettings.summary, /org_connections \(org_connections_read\) \(403 forbidden\)/);
  assert.equal(orgSettings.evidence.org_connections, null);
  assert.equal(orgSettings.evidence.org_connections_readable, false);
  assert.ok(orgSettings.evidence.manual_evidence.some((step) => /Org Connections/.test(step)));

  const orgForbidden = await assessDatadogDataProtection(healthyClient({
    async getOrganization() {
      throw forbidden("/api/v1/org");
    },
  }), { now: NOW });
  assert.equal(findingStatus(orgForbidden, "DD-20"), "manual");
  assert.match(findingById(orgForbidden, "DD-20").summary, /organization settings \(org_management\) \(403 forbidden\)/);

  const settingMissing = await assessDatadogDataProtection(healthyClient({
    async getOrganization() {
      return { name: "Acme", settings: {} };
    },
  }), { now: NOW });
  assert.equal(findingStatus(settingMissing, "DD-20"), "manual");
  assert.match(findingById(settingMissing, "DD-20").summary, /did not include the private_widget_share setting/);

  const indexesForbidden = await assessDatadogDataProtection(healthyClient({
    async listLogIndexes() {
      throw forbidden("/api/v1/logs/config/indexes");
    },
  }), { now: NOW });
  assert.equal(findingStatus(indexesForbidden, "DD-20"), "manual");
  assert.equal(findingStatus(indexesForbidden, "DD-10"), "manual");
});

test("DD-20 warns on indexes without a retention value and flags truncated org connections", async () => {
  const unknownRetention = await assessDatadogDataProtection(healthyClient({
    async listLogIndexes() {
      return [{ name: "main", num_retention_days: 30, exclusion_filters: [] }, { name: "legacy", exclusion_filters: [] }];
    },
  }), { now: NOW });
  const finding = findingById(unknownRetention, "DD-20");
  assert.equal(finding.status, "warn");
  assert.match(finding.summary, /1 indexes did not report num_retention_days/);
  assert.deepEqual(finding.evidence.indexes_without_retention_value, ["legacy"]);

  const truncated = await assessDatadogDataProtection(healthyClient({
    async listOrgConnections(limit) {
      return fill(limit, (index) => ({ id: `c${index}`, type: "org_connection", attributes: { connection_types: ["logs"] }, relationships: { sink_org: { data: { id: `org-${index}` } } } }));
    },
  }), { now: NOW });
  const connections = findingById(truncated, "DD-20");
  assert.equal(connections.status, "warn");
  assert.equal(connections.evidence.org_connections_inventory_truncated, true);
  assert.equal(connections.evidence.org_connections, 10000);
  assert.match(connections.evidence.verdict_caveats[0], /org_connections inventory is truncated at 10000 items/);
  assert.ok(truncated.errors.some((error) => /org_connections: inventory truncated at 10000 items/.test(error)));
});

test("DD-07 and DD-10 are manual when one of their surfaces is unreadable and warn on undated events", async () => {
  const recentForbidden = await assessDatadogDataProtection(healthyClient({
    async listAuditEvents(options = {}) {
      if (options.sort === "timestamp") {
        return [{ id: "evt-old", type: "audit", attributes: { timestamp: daysAgo(100) } }];
      }
      throw forbidden("/api/v2/audit/events");
    },
    async listLogArchives() {
      throw forbidden("/api/v2/logs/config/archives");
    },
  }), { now: NOW });
  const audit = findingById(recentForbidden, "DD-07");
  assert.equal(audit.status, "manual");
  assert.match(audit.summary, /audit_events_recent \(audit_logs_read\) \(403 forbidden\)/);
  assert.equal(audit.evidence.oldest_events_readable, true);
  assert.equal(audit.evidence.recent_events_readable, false);
  const logs = findingById(recentForbidden, "DD-10");
  assert.equal(logs.status, "manual");
  assert.match(logs.summary, /log_archives \(logs_read_archives\) \(403 forbidden\)/);
  assert.equal(logs.evidence.surfaces_readable.archives, false);

  const undatedOldest = await assessDatadogDataProtection(healthyClient({
    async listAuditEvents(options = {}) {
      if (options.sort === "timestamp") {
        return [{ id: "evt-old", type: "audit", attributes: {} }];
      }
      return [{ id: "evt-1", type: "audit", attributes: { timestamp: hoursAgo(2) } }];
    },
  }), { now: NOW });
  const undated = findingById(undatedOldest, "DD-07");
  assert.equal(undated.status, "warn");
  assert.match(undated.summary, /oldest returned event has no timestamp/);
  assert.equal(undated.evidence.oldest_event_has_timestamp, false);

  const noRecent = await assessDatadogDataProtection(healthyClient({
    async listAuditEvents(options = {}) {
      return options.sort === "timestamp" ? [{ id: "evt-old", type: "audit", attributes: { timestamp: daysAgo(100) } }] : [];
    },
  }), { now: NOW });
  assert.equal(findingStatus(noRecent, "DD-07"), "warn");
  assert.match(findingById(noRecent, "DD-07").summary, /returned none in the last 7 days/);

  const noIndexes = await assessDatadogDataProtection(healthyClient({
    async listLogIndexes() {
      return [];
    },
  }), { now: NOW });
  assert.equal(findingStatus(noIndexes, "DD-10"), "manual");
  assert.match(findingById(noIndexes, "DD-10").summary, /returned no indexes.*unverifiable rather than compliant/);
});

test("DD-11 treats a partial or flagless scanning group inventory as unverifiable, never pass", async () => {
  const referencedButMissing = await assessDatadogDataProtection(healthyClient({
    async getSensitiveDataScannerConfig() {
      const configuration = healthySensitiveDataScanner();
      configuration.data.relationships = { groups: { data: [{ id: "group-1", type: "sensitive_data_scanner_group" }, { id: "group-2", type: "sensitive_data_scanner_group" }] } };
      return configuration;
    },
  }), { now: NOW });
  const partial = findingById(referencedButMissing, "DD-11");
  assert.equal(partial.status, "warn");
  assert.match(partial.summary, /Downgraded to warn: 1\/2 scanning groups referenced by the configuration were not returned/);
  assert.equal(partial.evidence.scanning_groups_referenced_by_configuration, 2);
  assert.deepEqual(partial.evidence.scanning_groups_missing_from_included, ["group-2"]);

  const flagless = await assessDatadogDataProtection(healthyClient({
    async getSensitiveDataScannerConfig() {
      return {
        data: { type: "sensitive_data_scanner_configuration", id: "cfg-1" },
        included: [{ id: "group-1", type: "sensitive_data_scanner_group", attributes: { name: "PCI", product_list: ["logs", "apm", "rum", "events"] } }],
      };
    },
  }), { now: NOW });
  const unknown = findingById(flagless, "DD-11");
  assert.equal(unknown.status, "manual");
  assert.match(unknown.summary, /1 scanning groups did not report is_enabled/);
  assert.match(unknown.summary, /unverifiable rather than compliant/);
  assert.deepEqual(unknown.evidence.scanning_groups_without_is_enabled, ["PCI"]);

  const empty = await assessDatadogDataProtection(healthyClient({
    async getSensitiveDataScannerConfig() {
      return { data: { type: "sensitive_data_scanner_configuration", id: "cfg-1" }, included: [] };
    },
  }), { now: NOW });
  assert.equal(findingStatus(empty, "DD-11"), "fail");
  assert.match(findingById(empty, "DD-11").summary, /empty configuration is treated as fail/);
});

test("every one of the 20 spec controls is covered exactly once across the assessments", async () => {
  const client = healthyClient();
  const results = await Promise.all([
    assessDatadogIdentity(client, { now: NOW }),
    assessDatadogAccessControls(client, { now: NOW }),
    assessDatadogSecurityMonitoring(client, { now: NOW }),
    assessDatadogDataProtection(client, { now: NOW }),
  ]);
  const ids = results.flatMap((result) => result.findings.map((item) => item.id)).sort();
  const expected = Object.keys(DATADOG_CONTROL_CATALOG).map((number) => `DD-${String(number).padStart(2, "0")}`).sort();
  assert.deepEqual(ids, expected);
  assert.equal(ids.length, 20);
  for (const item of results.flatMap((result) => result.findings)) {
    assert.ok(item.mappings.length >= 8, `${item.id} should map to every framework`);
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
  }
});

test("false-pass self-check (a): every endpoint returning 403 yields 20 manual findings and no pass", async () => {
  const findings = await assessAll(forbiddenClient());
  assert.equal(findings.size, 20);
  const statuses = statusMap(findings);
  assert.deepEqual(Object.values(statuses), Array.from({ length: 20 }, () => "manual"));
  for (const [id, item] of findings) {
    assert.ok(Array.isArray(item.evidence.manual_evidence) && item.evidence.manual_evidence.length > 0, `${id} must name the evidence to collect`);
    if (id === "DD-16") {
      assert.match(item.summary, /does not expose the organization session timeout/);
    } else if (id === "DD-18") {
      assert.match(item.summary, /not visible through the Datadog API/);
    } else {
      assert.match(item.summary, /403/, `${id} must cite the 403 cause`);
    }
  }
});

test("false-pass self-check (b): every list empty yields no pass and states per control whether emptiness is fail or manual", async () => {
  const findings = await assessAll(emptyClient());
  assert.equal(findings.size, 20);
  assert.deepEqual(statusMap(findings), {
    "DD-01": "manual",
    "DD-02": "manual",
    "DD-03": "manual",
    "DD-04": "manual",
    "DD-05": "manual",
    "DD-06": "manual",
    "DD-07": "fail",
    "DD-08": "fail",
    "DD-09": "manual",
    "DD-10": "manual",
    "DD-11": "fail",
    "DD-12": "manual",
    "DD-13": "fail",
    "DD-14": "manual",
    "DD-15": "manual",
    "DD-16": "manual",
    "DD-17": "manual",
    "DD-18": "manual",
    "DD-19": "manual",
    "DD-20": "manual",
  });
  for (const id of ["DD-07", "DD-08", "DD-11", "DD-13"]) {
    assert.match(findings.get(id).summary, /treated as fail/, `${id} must state that emptiness is fail`);
  }
  for (const id of ["DD-02", "DD-03", "DD-04", "DD-05", "DD-06", "DD-09", "DD-10", "DD-12", "DD-17", "DD-19"]) {
    assert.match(findings.get(id).summary, /treated as (unverifiable|not applicable) rather than compliant/, `${id} must state that emptiness is manual`);
  }
});

test("false-pass self-check (b) exceptions: emptiness passes only where the control's intent makes it compliant", async () => {
  const signals = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecuritySignals() {
      return [];
    },
  }), { now: NOW });
  const noOpenSignals = findingById(signals, "DD-09");
  assert.equal(noOpenSignals.status, "pass");
  assert.match(noOpenSignals.summary, /empty result is treated as compliant because 3 enabled detection rules are active/);

  const sharing = await assessDatadogAccessControls(healthyClient({
    async listDashboards() {
      return [];
    },
  }), { now: NOW });
  const noSharedDashboards = findingById(sharing, "DD-14");
  assert.equal(noSharedDashboards.status, "pass");
  assert.match(noSharedDashboards.summary, /No dashboards are shared through public links and widget sharing outside the org is disabled \(private_widget_share read as false\)/);

  const dataProtection = await assessDatadogDataProtection(healthyClient({
    async listOrgConnections() {
      return [];
    },
  }), { now: NOW });
  const noConnections = findingById(dataProtection, "DD-20");
  assert.equal(noConnections.status, "pass");
  assert.match(noConnections.summary, /org connections list was read and is empty/);
});

test("false-pass self-check (c): a partial inventory never passes on any of the 20 controls", async () => {
  const findings = await assessAll(partialClient());
  assert.equal(findings.size, 20);
  const statuses = statusMap(findings);
  assert.deepEqual(Object.values(statuses).filter((status) => status === "pass"), []);
  assert.deepEqual(statuses, {
    "DD-01": "manual",
    "DD-02": "warn",
    "DD-03": "manual",
    "DD-04": "warn",
    "DD-05": "warn",
    "DD-06": "warn",
    "DD-07": "manual",
    "DD-08": "warn",
    "DD-09": "warn",
    "DD-10": "manual",
    "DD-11": "warn",
    "DD-12": "warn",
    "DD-13": "warn",
    "DD-14": "warn",
    "DD-15": "warn",
    "DD-16": "manual",
    "DD-17": "warn",
    "DD-18": "manual",
    "DD-19": "warn",
    "DD-20": "manual",
  });
  assert.match(findings.get("DD-01").summary, /did not include the saml_strict_mode setting/);
  assert.match(findings.get("DD-02").summary, /users inventory is truncated/);
  assert.match(findings.get("DD-03").summary, /could not have their permissions read/);
  assert.match(findings.get("DD-05").summary, /api_keys inventory is truncated/);
  assert.match(findings.get("DD-06").summary, /application_keys inventory is truncated/);
  assert.match(findings.get("DD-07").summary, /audit_events_recent/);
  assert.match(findings.get("DD-09").summary, /truncated list/);
  assert.match(findings.get("DD-10").summary, /log_archives/);
  assert.match(findings.get("DD-11").summary, /were not returned in the included payload/);
  assert.match(findings.get("DD-12").summary, /paged counts hit the finding_limit/);
  assert.match(findings.get("DD-14").summary, /confirm each uses invite-only sharing/);
  assert.equal(findings.get("DD-14").evidence.shared_dashboards_inventory_truncated, true);
  assert.match(findings.get("DD-15").summary, /returned no CIDR entries/);
  assert.match(findings.get("DD-17").summary, /monitors inventory is truncated/);
  assert.match(findings.get("DD-20").summary, /org_connections \(org_connections_read\)/);
});

test("exportDatadogAuditBundle writes core data, analysis, compliance reports, quick reference, and archive", async () => {
  const base = createTempBase("grclanker-datadog-export-");
  const result = await exportDatadogAuditBundle(healthyClient(), sampleConfig(), base, { now: NOW });

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.findingCount, 20);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 35);

  for (const relativePath of [
    "README.md",
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "core_data/organization.json",
    "core_data/users.json",
    "core_data/roles.json",
    "core_data/api_keys.json",
    "core_data/application_keys.json",
    "core_data/security_rules.json",
    "core_data/security_signals.json",
    "core_data/posture_findings.json",
    "core_data/audit_events.json",
    "core_data/log_indexes.json",
    "core_data/log_archives.json",
    "core_data/sensitive_data_scanner.json",
    "core_data/ip_allowlist.json",
    "core_data/monitors.json",
    "core_data/cloud_integrations.json",
    "analysis/findings.json",
    "analysis/identity.json",
    "analysis/access-controls.json",
    "analysis/security-monitoring.json",
    "analysis/data-protection.json",
    "analysis/summary.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/frameworks/fedramp.md",
    "compliance/frameworks/cmmc.md",
    "compliance/frameworks/soc2.md",
    "compliance/frameworks/cis.md",
    "compliance/frameworks/pci-dss.md",
    "compliance/frameworks/disa-stig.md",
    "compliance/frameworks/irap.md",
    "compliance/frameworks/ismap.md",
  ]) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `${relativePath} should exist`);
  }
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.site, "datadoghq.com");
  assert.equal(metadata.controls_assessed, 20);
  assert.equal(metadata.manual, 2);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 20);
  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /DD-01 \| SAML SSO Enforcement \| pass/);
  assert.match(matrix, /SRG-APP-000023/);
  const bundleText = readFileSync(join(result.outputDir, "core_data", "api_keys.json"), "utf8");
  assert.doesNotMatch(bundleText, /api-key-0123456789abcdef/);
});

test("exportDatadogAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("grclanker-datadog-export-errors-");
  const result = await exportDatadogAuditBundle(healthyClient({
    async getIpAllowlist() {
      throw forbidden("/api/v2/ip_allowlist");
    },
    async listLogArchives() {
      throw new Error("upstream unavailable");
    },
  }), sampleConfig(), base, { now: NOW });

  assert.equal(result.findingCount, 20);
  assert.ok(result.errorCount >= 2);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /ip_allowlist/);
  assert.match(errorLog, /log_archives/);
  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /Collection Warnings/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "DD-15").status, "manual");
});

test("exportDatadogAuditBundle reruns allocate a new directory and zip without overwriting the prior bundle", async () => {
  const base = createTempBase("grclanker-datadog-export-rerun-");
  const first = await exportDatadogAuditBundle(healthyClient(), sampleConfig(), base, { now: NOW });
  const firstZipStat = statSync(first.zipPath);
  const firstReadme = readFileSync(join(first.outputDir, "README.md"), "utf8");

  const second = await exportDatadogAuditBundle(healthyClient(), sampleConfig(), base, { now: NOW });
  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.equal(basename(first.zipPath), `${basename(first.outputDir)}.zip`);
  assert.equal(basename(second.zipPath), `${basename(second.outputDir)}.zip`);
  assert.match(basename(second.outputDir), /-audit-bundle-2$/);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
  assert.equal(statSync(first.zipPath).size, firstZipStat.size);
  assert.equal(statSync(first.zipPath).mtimeMs, firstZipStat.mtimeMs);
  assert.equal(readFileSync(join(first.outputDir, "README.md"), "utf8"), firstReadme);

  rmSync(second.outputDir, { recursive: true, force: true });
  const third = await exportDatadogAuditBundle(healthyClient(), sampleConfig(), base, { now: NOW });
  assert.notEqual(third.zipPath, second.zipPath, "a leftover zip must block reuse of its directory name");
  assert.match(basename(third.outputDir), /-audit-bundle-3$/);
  assert.ok(existsSync(second.zipPath));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-datadog-path-");
  const outside = createTempBase("grclanker-datadog-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("compliance", "safe.md"));
  assert.match(safe, /compliance\/safe\.md$/);
});

test("Datadog tools are registered in the tool catalog under the Datadog group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("datadog_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "datadog_assess_access_controls",
    "datadog_assess_data_protection",
    "datadog_assess_identity",
    "datadog_assess_security_monitoring",
    "datadog_check_access",
    "datadog_export_audit_bundle",
  ]);
  for (const tool of tools) {
    assert.equal(tool.group, "Datadog");
    assert.equal(tool.kind, "domain");
    assert.ok(tool.parameterSummaries.some((parameter) => parameter.name === "site"));
  }
});
