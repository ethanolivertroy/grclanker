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
  isCredentialKey,
  normalizeDatadogSite,
  projectAuditEvent,
  projectCloudIntegration,
  projectDashboard,
  projectKeyRecord,
  projectMonitor,
  projectPostureFinding,
  projectSecuritySignal,
  redactCredentialValues,
  reduceUrl,
  registerDatadogTools,
  resolveDatadogConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/datadog.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

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
    ...(options.statusText ? { statusText: options.statusText } : {}),
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
  const listing = await client.listUsers(150);
  const users = listing.items;

  assert.equal(users.length, 150);
  assert.equal(listing.truncated, false);
  assert.equal(listing.total, 150);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].pathname, "/api/v2/users");
  assert.equal(seen[0].method, "GET");
  assert.equal(seen[0].apiKey, "api-key-0123456789abcdef");
  assert.equal(seen[0].appKey, "app-key-0123456789abcdef");
  assert.deepEqual(seen.map((item) => item.page), ["0", "1"]);
  assert.equal(seen[0].size, "100");
  assert.equal(users[0].id, "u1");
  assert.equal(users[149].id, "u150");

  // A cap below the server total is reported as truncated with the total the server disclosed.
  const capped = await client.listUsers(120);
  assert.equal(capped.items.length, 120);
  assert.equal(capped.truncated, true);
  assert.equal(capped.total, 150);
  assert.match(capped.truncationReason, /item cap of 120 was reached/);
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
  assert.deepEqual(events.items.map((event) => event.id), ["e1", "e2"]);
  assert.equal(events.truncated, false);
  const auditCalls = seen.filter((url) => url.pathname === "/api/v2/audit/events");
  assert.equal(auditCalls[0].searchParams.get("filter[query]"), "@action:login");
  assert.equal(auditCalls[0].searchParams.get("filter[from]"), "now-1d");
  assert.equal(auditCalls[0].searchParams.get("page[limit]"), "10");
  assert.equal(auditCalls[1].searchParams.get("page[cursor]"), "cursor-2");

  const monitors = await client.listMonitors(2);
  assert.equal(monitors.items.length, 2);
  // The cap stopped the loop while the page was still full, so the client cannot claim the list is complete.
  assert.equal(monitors.truncated, true);
  const monitorCalls = seen.filter((url) => url.pathname === "/api/v1/monitor");
  assert.equal(monitorCalls.length, 1);
  assert.equal(monitorCalls[0].searchParams.get("page_size"), "2");

  const connections = await client.listOrgConnections(25);
  assert.equal(connections.items.length, 1);
  assert.equal(connections.truncated, false);
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
  const listing = await client.listOrgConnections();
  const connections = listing.items;
  assert.equal(connections.length, total);
  assert.equal(listing.truncated, false);
  assert.equal(listing.total, total);
  assert.equal(connections[total - 1].id, `c${total - 1}`);
  assert.deepEqual(seen.map((url) => url.searchParams.get("offset")), ["0", "1000", "2000"]);
  assert.ok(seen.every((url) => url.searchParams.get("limit") === "1000"));
  assert.ok(seen.every((url) => !url.searchParams.has("page[limit]")));

  const capped = await new DatadogApiClient(sampleConfig(), { fetchImpl }).listOrgConnections(1500);
  assert.equal(capped.items.length, 1500);
  assert.equal(capped.truncated, true);
  assert.equal(capped.total, total);
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
  assert.equal(dashboards.items.length, total);
  assert.equal(dashboards.truncated, false);
  assert.deepEqual(seen.map((url) => url.searchParams.get("start")), ["0", "100", "200"]);
  assert.ok(seen.every((url) => url.searchParams.get("count") === "100"));
  assert.ok(seen.every((url) => url.searchParams.get("filter[shared]") === "true"));

  seen.length = 0;
  const probe = await client.listDashboards({ shared: true, limit: 1 });
  assert.equal(probe.items.length, 1);
  // The dashboard endpoint has no total, so a full single page under the cap is reported as truncated, not complete.
  assert.equal(probe.truncated, true);
  assert.equal(probe.total, undefined);
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
  assert.match(mfa.summary, /1\/2 active human users lack Datadog-native MFA/);
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
    assert.match(item.summary, /inventory is truncated at (50|10) items \((50|10) of an unknown total loaded; raise (user_limit|role_limit)\)/);
  }
  // Population counts derived from a truncated inventory render null; only the number of records read is stated.
  const mfa = findingById(result, "DD-02");
  assert.equal(mfa.evidence.users_inventory_truncated, true);
  assert.equal(mfa.evidence.users_returned, 50);
  assert.equal(mfa.evidence.active_human_users, null);
  assert.equal(mfa.evidence.users_without_native_mfa, null);
  assert.equal(mfa.evidence.users_without_native_mfa_sample, null);
  assert.deepEqual([mfa.evidence.inventory.read, mfa.evidence.inventory.complete, mfa.evidence.inventory.seen, mfa.evidence.inventory.total], [true, false, 50, null]);
  assert.equal(findingById(result, "DD-03").evidence.roles_inventory_truncated, true);
  assert.equal(result.summary.users, null);
  assert.equal(result.summary.users_seen, 50);
  assert.equal(result.summary.users_complete, false);
  assert.equal(result.summary.roles, null);
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
  assert.match(sharing.summary, /Unreadable inventory: organization settings \(GET \/api\/v1\/org, org_management: .*403 Forbidden/);
  assert.match(sharing.summary, /whether widget sharing outside the organization \(private_widget_share\) is disabled was not checked/);
  assert.equal(sharing.evidence.private_widget_share, null);
  assert.equal(sharing.evidence.organization_settings_readable, false);
  assert.equal(sharing.evidence.unreadable_inventories[0].inventory, "organization settings");
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
  assert.match(findingById(dashboardsForbidden, "DD-14").summary, /Unreadable inventory: shared_dashboards \(GET \/api\/v1\/dashboard\?filter\[shared\]=true, dashboards_read: .*403 Forbidden/);
  assert.match(findingById(dashboardsForbidden, "DD-14").summary, /Collect manually: Dashboards > Shared Dashboards/);
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
    assert.match(item.summary, /inventory is truncated at 20 items \(20 of an unknown total loaded; raise key_limit\)/);
  }
  const apiKeys = findingById(result, "DD-05");
  assert.equal(apiKeys.evidence.api_keys_inventory_truncated, true);
  assert.equal(apiKeys.evidence.keys_returned, 20);
  assert.equal(apiKeys.evidence.api_keys, null);
  assert.equal(apiKeys.evidence.keys_older_than_rotation_window, null);
  const appKeys = findingById(result, "DD-06");
  assert.equal(appKeys.evidence.application_keys_inventory_truncated, true);
  assert.equal(appKeys.evidence.application_keys, null);
  assert.equal(appKeys.evidence.orphaned_keys, null);
  const sharing = findingById(result, "DD-14");
  assert.equal(sharing.status, "warn");
  assert.match(sharing.summary, /^an uncounted number of dashboards read are shared through public links/);
  assert.equal(sharing.evidence.shared_dashboards_inventory_truncated, true);
  // Counts and dashboard titles derived from the truncated list are unknown; only the records read are counted.
  assert.equal(sharing.evidence.shared_dashboards, null);
  assert.equal(sharing.evidence.shared_dashboards_seen, 2000);
  assert.equal(sharing.evidence.shared_dashboard_titles, null);
  assert.deepEqual(sharing.evidence.verdict_caveats, ["shared_dashboards inventory is truncated at 2000 items (2000 of an unknown total loaded; raise the dashboard limit), so the verdict covers a partial view and violators from it are neither counted nor named."]);
  assert.equal(result.summary.api_keys, null);
  assert.equal(result.summary.api_keys_seen, 20);
  assert.equal(result.summary.shared_dashboards, null);
  assert.equal(result.summary.shared_dashboards_seen, 2000);
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
  assert.match(cspm.summary, /Unreadable inventory: security_rules \(GET \/api\/v2\/security_monitoring\/rules, security_monitoring_rules_read: .*403 Forbidden/);
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
  assert.match(findingById(integrationsForbidden, "DD-12").summary, /Unreadable inventory: gcp_integrations \(GET \/api\/v1\/integration\/gcp, gcp_configuration_read: .*403 Forbidden/);
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
    assert.match(item.summary, new RegExp(`inventory is truncated at ${limit} items \\(${limit} of an unknown total loaded; raise ${argument}\\)`));
  }
  // Population counts and the names of rules or monitors derived from a truncated list are unknown; the `_read`
  // counts describe the records that were read.
  const rules = findingById(result, "DD-08");
  assert.equal(rules.evidence.rules_inventory_truncated, true);
  assert.equal(rules.evidence.rules_returned, 40);
  assert.equal(rules.evidence.total_rules, null);
  assert.equal(rules.evidence.enabled_detection_rules, null);
  assert.equal(rules.evidence.enabled_detection_rules_read, 20);
  assert.equal(rules.evidence.disabled_default_rule_sample, null);
  assert.equal(rules.evidence.critical_category_coverage, null);
  assert.equal(findingById(result, "DD-12").evidence.rules_inventory_truncated, true);
  assert.equal(findingById(result, "DD-12").evidence.cloud_configuration_rules, null);
  assert.equal(findingById(result, "DD-13").evidence.coverage, null);
  const monitors = findingById(result, "DD-17");
  assert.equal(monitors.evidence.monitors_inventory_truncated, true);
  assert.equal(monitors.evidence.monitors, null);
  assert.equal(monitors.evidence.monitors_returned, 30);
  assert.equal(monitors.evidence.security_monitors_without_notifications, null);
  const signals = findingById(result, "DD-09");
  assert.equal(signals.status, "warn");
  assert.equal(signals.evidence.signals_inventory_truncated, true);
  assert.equal(signals.evidence.unresolved_high_or_critical_signals, null);
  assert.equal(signals.evidence.unresolved_high_or_critical_signals_read, 0);
  assert.equal(signals.evidence.overdue_signal_sample, null);
  assert.match(signals.summary, /truncated list of 10 items that were all archived/);
  assert.equal(result.summary.rules, null);
  assert.equal(result.summary.rules_seen, 40);
  assert.equal(result.summary.monitors, null);
  assert.equal(result.summary.monitors_seen, 30);
  assert.equal(result.summary.unresolved_high_or_critical_signals, null);

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
  assert.equal(open.evidence.signals_without_timestamp, null);
  assert.equal(open.evidence.signals_without_timestamp_sample, null);
  assert.match(open.summary, /^an uncounted number of unresolved high or critical signals read are open within/);
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
  assert.match(orgSettings.summary, /Unreadable inventory: org_connections \(GET \/api\/v2\/org_connections, org_connections_read: .*403 Forbidden.*\), so whether any cross-org connection shares data with another organization was not checked\. Collect manually: Organization Settings > Org Connections/);
  assert.equal(orgSettings.evidence.org_connections, null);
  assert.equal(orgSettings.evidence.org_connections_readable, false);
  assert.ok(orgSettings.evidence.manual_evidence.some((step) => /Org Connections/.test(step)));

  const orgForbidden = await assessDatadogDataProtection(healthyClient({
    async getOrganization() {
      throw forbidden("/api/v1/org");
    },
  }), { now: NOW });
  assert.equal(findingStatus(orgForbidden, "DD-20"), "manual");
  assert.match(findingById(orgForbidden, "DD-20").summary, /Unreadable inventory: organization settings \(GET \/api\/v1\/org, org_management: .*403 Forbidden/);

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
  // The population count and the sink org ids come from a truncated list, so they are unknown; only the read count is stated.
  assert.equal(connections.evidence.org_connections, null);
  assert.equal(connections.evidence.org_connections_seen, 10000);
  assert.equal(connections.evidence.org_connection_sample, null);
  assert.match(connections.summary, /an uncounted number of cross-org connections read share data with other orgs/);
  assert.equal(truncated.summary.org_connections, null);
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
  assert.match(audit.summary, /Unreadable inventory: audit_events_recent \(GET \/api\/v2\/audit\/events \(last 7 days\), audit_logs_read: .*403 Forbidden.*\), so whether Audit Trail recorded any event in the last 7 days was not checked/);
  assert.equal(audit.evidence.oldest_events_readable, true);
  assert.equal(audit.evidence.recent_events_readable, false);
  const logs = findingById(recentForbidden, "DD-10");
  assert.equal(logs.status, "manual");
  assert.match(logs.summary, /Unreadable inventory: log_archives \(GET \/api\/v2\/logs\/config\/archives, logs_read_archives: .*403 Forbidden.*\), so whether a healthy archive destination exists for long-term retention was not checked/);
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
  assert.match(findings.get("DD-20").summary, /Unreadable inventory: org_connections \(GET \/api\/v2\/org_connections, org_connections_read: /);
});

// Every Datadog finding whose verdict reads two or more collected inventories, with each secondary inventory forbidden
// in turn while the primary stays healthy. `label` is the inventory name the summary and the evidence gap must carry,
// `errorPrefix` the prefix of the single collection error the failure must produce, and `status` the verdict required.
// Single-inventory controls (DD-01, DD-04, DD-05, DD-06, DD-08, DD-11, DD-13, DD-15, DD-17) and the always-manual
// DD-16 are covered by the false-pass self-checks above.
const DATADOG_MULTI_INVENTORY_CASES = [
  // DD-02 reads users (primary) plus the organization's SAML strict-mode setting; native MFA still judges the users.
  { control: "DD-02", area: "identity", label: "organization settings", errorPrefix: "organization:", failure: { method: "getOrganization", path: "/api/v1/org" }, status: "warn", names: /All 2 active human users have Datadog MFA enabled.*Unreadable inventory: organization settings \(GET \/api\/v1\/org, org_management: .*403 Forbidden.*\), so whether SAML strict mode disables password login for the users below was not checked\. Collect manually: Organization Settings > Login Methods/ },
  // DD-03 reads roles (primary) plus each custom role's permission list.
  { control: "DD-03", area: "identity", label: "role_permissions", errorPrefix: "role_permissions(Auditor):", failure: { method: "listRolePermissions", path: "/api/v2/roles/role-auditor/permissions" }, status: "manual", names: /1\/1 custom roles could not have their permissions read.*Unreadable inventory: role_permissions \(GET \/api\/v2\/roles\/role-auditor\/permissions, user_access_read: Auditor: .*403 Forbidden.*\), so admin-equivalent grants in 1 custom roles could not be ruled out\. Collect manually: the permission list of each custom role/ },
  // DD-19 reads users (primary) plus application keys for rotation; naming and interactive logins still judge the users.
  { control: "DD-19", area: "identity", label: "application_keys", errorPrefix: "application_keys:", failure: { method: "listApplicationKeys", path: "/api/v2/application_keys" }, status: "warn", names: /1 service accounts follow the naming convention and have no interactive logins\. Unreadable inventory: application_keys \(GET \/api\/v2\/application_keys, org_app_keys_read: .*403 Forbidden.*\), so whether the application keys owned by these service accounts were rotated within 90 days was not checked\. Collect manually: Organization Settings > Application Keys/ },
  // DD-14 reads organization settings plus shared dashboards; both are essential.
  { control: "DD-14", area: "access", label: "organization settings", errorPrefix: "organization:", failure: { method: "getOrganization", path: "/api/v1/org" }, status: "manual", names: /^Unreadable inventory: organization settings \(GET \/api\/v1\/org, org_management: .*403 Forbidden.*\), so whether widget sharing outside the organization \(private_widget_share\) is disabled was not checked/ },
  { control: "DD-14", area: "access", label: "shared_dashboards", errorPrefix: "shared_dashboards:", failure: { method: "listDashboards", path: "/api/v1/dashboard" }, status: "manual", names: /^Unreadable inventory: shared_dashboards \(GET \/api\/v1\/dashboard\?filter\[shared\]=true, dashboards_read: .*403 Forbidden.*\), so whether any dashboard is shared through a public link was not checked/ },
  // DD-18 reads the AWS, GCP, and Azure integration lists; it is always manual but must still name what it could not inventory.
  { control: "DD-18", area: "access", label: "aws_integrations", errorPrefix: "aws_integrations:", failure: { method: "listAwsIntegrations", path: "/api/v1/integration/aws" }, status: "manual", names: /0 GCP, 0 Azure integrations were inventoried.*Unreadable inventory: aws_integrations \(GET \/api\/v1\/integration\/aws, aws_configuration_read: .*403 Forbidden.*\), so AWS accounts and their authentication method were not inventoried/ },
  { control: "DD-18", area: "access", label: "gcp_integrations", errorPrefix: "gcp_integrations:", failure: { method: "listGcpIntegrations", path: "/api/v1/integration/gcp" }, status: "manual", names: /1 AWS, 0 Azure integrations were inventoried.*Unreadable inventory: gcp_integrations \(GET \/api\/v1\/integration\/gcp, gcp_configuration_read: .*403 Forbidden.*\), so GCP projects were not inventoried/ },
  { control: "DD-18", area: "access", label: "azure_integrations", errorPrefix: "azure_integrations:", failure: { method: "listAzureIntegrations", path: "/api/v1/integration/azure" }, status: "manual", names: /1 AWS, 0 GCP integrations were inventoried.*Unreadable inventory: azure_integrations \(GET \/api\/v1\/integration\/azure, azure_configuration_read: .*403 Forbidden.*\), so Azure tenants were not inventoried/ },
  // DD-09 reads signals (primary) plus the rule inventory that makes an empty signal list meaningful.
  { control: "DD-09", area: "monitoring", label: "security_rules", errorPrefix: "security_rules:", failure: { method: "listSecurityRules", path: "/api/v2/security_monitoring/rules" }, status: "manual", names: /detection rule inventory was not readable.*Unreadable inventory: security_rules \(GET \/api\/v2\/security_monitoring\/rules, security_monitoring_rules_read: .*403 Forbidden.*\), so whether any detection rule is enabled to generate signals was not checked\. Collect manually: Security > Cloud SIEM > Detection Rules/ },
  // DD-12 reads rules (primary) plus the three cloud integration lists and the failing and passing posture counts.
  { control: "DD-12", area: "monitoring", label: "aws_integrations", errorPrefix: "aws_integrations:", failure: { method: "listAwsIntegrations", path: "/api/v1/integration/aws" }, status: "manual", names: /^Unreadable inventory: aws_integrations \(GET \/api\/v1\/integration\/aws, aws_configuration_read: .*403 Forbidden.*\), so whether AWS accounts have CSPM resource collection enabled was not checked/ },
  { control: "DD-12", area: "monitoring", label: "gcp_integrations", errorPrefix: "gcp_integrations:", failure: { method: "listGcpIntegrations", path: "/api/v1/integration/gcp" }, status: "manual", names: /^Unreadable inventory: gcp_integrations .*so whether GCP projects have CSPM resource collection enabled was not checked/ },
  { control: "DD-12", area: "monitoring", label: "azure_integrations", errorPrefix: "azure_integrations:", failure: { method: "listAzureIntegrations", path: "/api/v1/integration/azure" }, status: "manual", names: /^Unreadable inventory: azure_integrations .*so whether Azure tenants have CSPM resource collection enabled was not checked/ },
  { control: "DD-12", area: "monitoring", label: "posture_findings_fail", errorPrefix: "posture_findings_fail:", failure: { method: "listPostureFindings", path: "/api/v2/posture_management/findings", when: (options = {}) => options.evaluation === "fail" }, status: "manual", names: /CSPM appears active.*passing rate could not be measured\. Unreadable inventory: posture_findings_fail \(GET \/api\/v2\/posture_management\/findings\?filter\[evaluation\]=fail, security_monitoring_findings_read: .*403 Forbidden.*\), so the failing posture finding count behind the passing rate was not read/ },
  { control: "DD-12", area: "monitoring", label: "posture_findings_pass", errorPrefix: "posture_findings_pass:", failure: { method: "listPostureFindings", path: "/api/v2/posture_management/findings", when: (options = {}) => options.evaluation === "pass" }, status: "manual", names: /CSPM appears active.*Unreadable inventory: posture_findings_pass \(GET \/api\/v2\/posture_management\/findings\?filter\[evaluation\]=pass, security_monitoring_findings_read: .*403 Forbidden.*\), so the passing posture finding count behind the passing rate was not read/ },
  // DD-07 reads the oldest retained audit event and the last seven days of events; both are essential.
  { control: "DD-07", area: "data", label: "audit_events_oldest", errorPrefix: "audit_events_oldest:", failure: { method: "listAuditEvents", path: "/api/v2/audit/events", when: (options = {}) => options.sort === "timestamp" }, status: "manual", names: /^Unreadable inventory: audit_events_oldest \(GET \/api\/v2\/audit\/events \(oldest event in the retention window\), audit_logs_read: .*403 Forbidden.*\), so whether events at least 83 days old are still retained was not checked\. Collect manually: Organization Settings > Audit Trail showing the retention setting/ },
  { control: "DD-07", area: "data", label: "audit_events_recent", errorPrefix: "audit_events_recent:", failure: { method: "listAuditEvents", path: "/api/v2/audit/events", when: (options = {}) => options.sort === "-timestamp" }, status: "manual", names: /^Unreadable inventory: audit_events_recent \(GET \/api\/v2\/audit\/events \(last 7 days\), audit_logs_read: .*403 Forbidden.*\), so whether Audit Trail recorded any event in the last 7 days was not checked/ },
  // DD-10 reads indexes (primary) plus pipelines and archives.
  { control: "DD-10", area: "data", label: "log_pipelines", errorPrefix: "log_pipelines:", failure: { method: "listLogPipelines", path: "/api/v1/logs/config/pipelines" }, status: "manual", names: /^Unreadable inventory: log_pipelines \(GET \/api\/v1\/logs\/config\/pipelines, logs_read_config: .*403 Forbidden.*\), so whether processing pipelines are configured for security sources was not checked\. Collect manually: Logs > Configuration > Pipelines/ },
  { control: "DD-10", area: "data", label: "log_archives", errorPrefix: "log_archives:", failure: { method: "listLogArchives", path: "/api/v2/logs/config/archives" }, status: "manual", names: /^Unreadable inventory: log_archives \(GET \/api\/v2\/logs\/config\/archives, logs_read_archives: .*403 Forbidden.*\), so whether a healthy archive destination exists for long-term retention was not checked/ },
  // DD-20 reads organization settings (primary) plus log indexes and org connections.
  { control: "DD-20", area: "data", label: "log_indexes", errorPrefix: "log_indexes:", failure: { method: "listLogIndexes", path: "/api/v1/logs/config/indexes" }, status: "manual", names: /^Unreadable inventory: log_indexes \(GET \/api\/v1\/logs\/config\/indexes, logs_read_config: .*403 Forbidden.*\), so whether every log index retains data for at least 30 days was not checked\. Collect manually: Logs > Configuration > Indexes/ },
  { control: "DD-20", area: "data", label: "org_connections", errorPrefix: "org_connections:", failure: { method: "listOrgConnections", path: "/api/v2/org_connections" }, status: "manual", names: /^Unreadable inventory: org_connections \(GET \/api\/v2\/org_connections, org_connections_read: .*403 Forbidden.*\), so whether any cross-org connection shares data with another organization was not checked\. Collect manually: Organization Settings > Org Connections/ },
];

const DATADOG_ASSESS_BY_AREA = {
  identity: assessDatadogIdentity,
  access: assessDatadogAccessControls,
  monitoring: assessDatadogSecurityMonitoring,
  data: assessDatadogDataProtection,
};

function clientWithForbiddenSecondary(failure) {
  const base = healthyClient();
  return healthyClient({
    async [failure.method](...args) {
      if (failure.when && !failure.when(...args)) return base[failure.method](...args);
      throw forbidden(failure.path);
    },
  });
}

test("verdict rule 1 corollary: Datadog findings that read several inventories never pass while a secondary inventory is forbidden", async () => {
  const baselines = new Map();
  for (const item of DATADOG_MULTI_INVENTORY_CASES) {
    const assess = DATADOG_ASSESS_BY_AREA[item.area];
    if (!baselines.has(item.area)) baselines.set(item.area, await assess(healthyClient(), { now: NOW }));
    const baseline = findingById(baselines.get(item.area), item.control);
    assert.equal(baseline.status, item.control === "DD-18" ? "manual" : "pass", `${item.control} baseline on the healthy fixture`);
    assert.equal(baseline.evidence.unreadable_inventories, undefined, `${item.control} baseline records no inventory gap`);

    const label = `${item.control} with ${item.label} forbidden`;
    const result = await assess(clientWithForbiddenSecondary(item.failure), { now: NOW });
    assert.equal(result.errors.length, 1, `${label}: only the secondary inventory failed (${result.errors.join(" | ")})`);
    assert.ok(result.errors[0].startsWith(item.errorPrefix), `${label}: the collection error names the inventory (${result.errors[0]})`);

    const found = findingById(result, item.control);
    assert.notEqual(found.status, "pass", `${label} must not pass`);
    assert.equal(found.status, item.status, `${label} status`);
    assert.match(found.summary, item.names, `${label} must name the unreadable inventory`);
    assert.match(found.summary, /403 Forbidden/, `${label} must carry the HTTP error`);
    assert.match(found.summary, /Collect manually: /, `${label} must tell the human what to collect`);
    const gaps = found.evidence.unreadable_inventories;
    assert.ok(Array.isArray(gaps) && gaps.some((gap) => gap.inventory === item.label), `${label} evidence lists the gap`);
    assert.ok(gaps.every((gap) => gap.endpoint && gap.permission && gap.error && gap.not_checked && gap.collect_manually), `${label} gap entries are complete`);
    assert.equal(gaps.filter((gap) => gap.inventory === item.label).length, 1, `${label} records the gap once`);
    if (item.status === "manual") {
      assert.ok(Array.isArray(found.evidence.manual_evidence) && found.evidence.manual_evidence.length > 0, `${label} lists manual evidence`);
      assert.match(found.summary, /Manual evidence required: /, `${label} states the manual evidence`);
    }
  }
});

test("verdict rule 1 corollary: Datadog findings keep judging the readable inventories and still fail on them", async () => {
  // DD-02: users without native MFA and no organization settings cannot be called fail (strict SAML may block passwords) or pass.
  const mfaUnknown = await assessDatadogIdentity(healthyClient({
    async getOrganization() {
      throw forbidden("/api/v1/org");
    },
    async listUsers() {
      return [user("alice", { mfa_enabled: false }), user("bob")];
    },
  }), { now: NOW });
  const mfa = findingById(mfaUnknown, "DD-02");
  assert.equal(mfa.status, "manual");
  assert.match(mfa.summary, /1\/2 active human users lack Datadog-native MFA, and whether SAML strict mode blocks their password login is unknown/);
  assert.match(mfa.summary, /Unreadable inventory: organization settings/);
  assert.equal(mfa.evidence.saml_strict_mode, null);
  assert.deepEqual(mfa.evidence.manual_evidence.length, 2);

  // DD-19: an interactive service account still fails even though its application keys could not be read.
  const interactive = await assessDatadogIdentity(healthyClient({
    async listApplicationKeys() {
      throw forbidden("/api/v2/application_keys");
    },
    async listUsers() {
      return [user("alice"), user("svc-terraform", { service_account: true, last_login_time: daysAgo(1) })];
    },
  }), { now: NOW });
  const serviceAccounts = findingById(interactive, "DD-19");
  assert.equal(serviceAccounts.status, "fail");
  assert.match(serviceAccounts.summary, /1 service accounts show interactive login history.*Unreadable inventory: application_keys/);

  // DD-09: overdue signals fail regardless of the unreadable rule inventory, and the summary still names the gap.
  const overdue = await assessDatadogSecurityMonitoring(healthyClient({
    async listSecurityRules() {
      throw forbidden("/api/v2/security_monitoring/rules");
    },
    async listSecuritySignals() {
      return [{ id: "sig-1", type: "signal", attributes: { timestamp: hoursAgo(80), message: "Brute force", attributes: { status: "critical", workflow: { triage: { state: "open" } } } } }];
    },
  }), { now: NOW });
  const signals = findingById(overdue, "DD-09");
  assert.equal(signals.status, "fail");
  assert.match(signals.summary, /1\/1 unresolved high or critical signals are older than the 72-hour SLA\. Unreadable inventory: security_rules/);

  // DD-14 and DD-20: an enabled private_widget_share fails even when the dashboard list or org connections are unreadable.
  const openSharing = await assessDatadogAccessControls(healthyClient({
    async getOrganization() {
      return { settings: { private_widget_share: true } };
    },
    async listDashboards() {
      throw forbidden("/api/v1/dashboard");
    },
  }), { now: NOW });
  assert.equal(findingStatus(openSharing, "DD-14"), "fail");
  assert.match(findingById(openSharing, "DD-14").summary, /private_widget_share enabled.*Unreadable inventory: shared_dashboards/);
  const openOrg = await assessDatadogDataProtection(healthyClient({
    async getOrganization() {
      return { settings: { private_widget_share: true } };
    },
    async listOrgConnections() {
      throw forbidden("/api/v2/org_connections");
    },
  }), { now: NOW });
  assert.equal(findingStatus(openOrg, "DD-20"), "fail");
  assert.match(findingById(openOrg, "DD-20").summary, /Widget sharing outside the organization is enabled.*Unreadable inventory: org_connections/);

  // DD-10: an exclusion filter dropping security sources fails even when archives are unreadable.
  const dropping = await assessDatadogDataProtection(healthyClient({
    async listLogIndexes() {
      return [{ name: "main", num_retention_days: 30, exclusion_filters: [{ name: "drop cloudtrail", is_enabled: true, filter: { query: "source:cloudtrail", sample_rate: 1 } }] }];
    },
    async listLogArchives() {
      throw forbidden("/api/v2/logs/config/archives");
    },
  }), { now: NOW });
  assert.equal(findingStatus(dropping, "DD-10"), "fail");
  assert.match(findingById(dropping, "DD-10").summary, /drop security-relevant log sources\. Unreadable inventory: log_archives/);
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

test("isCredentialKey, reduceUrl, and redactCredentialValues cover nested, plural, camelCase, key-id, pair, and URL-shaped credential fields", () => {
  for (const name of ["apiKey", "api_keys", "appKey", "secrets", "clientSecret", "client_secret", "access_key_id", "private_key_id", "privateKey", "authorization", "password", "passphrase", "signing_secret", "sessionToken", "bearer"]) {
    assert.equal(isCredentialKey(name), true, `${name} is credential-shaped`);
  }
  for (const name of ["handle", "public_id", "monitor_id", "key_id", "keys_without_created_at", "stale_service_account_keys", "cspm_resource_collection_enabled", "authentication", "credential_fields_dropped", "last4"]) {
    assert.equal(isCredentialKey(name), false, `${name} is not credential-shaped`);
  }

  assert.equal(reduceUrl("https://hooks.example.com/services/T000/B000/secret?token=abc"), "https://hooks.example.com");
  assert.equal(reduceUrl("https://user:pw@idp.example.com:8443/sso"), "https://idp.example.com:8443");
  assert.equal(reduceUrl("/api/v1/hook?api_key=abc"), "[REDACTED]");
  assert.equal(reduceUrl("/api/v1/hook?page=2"), "/api/v1/hook?page=2");
  assert.equal(reduceUrl("http://[bad"), "[REDACTED]");

  const redacted = redactCredentialValues({
    secrets: { nested: "value" },
    tokens: ["t1", "t2"],
    apiKey: "plain",
    accessKeyId: "AKIA0000",
    nested: { clientSecret: "s", name: "ok", count: 3, enabled: true, empty: null },
    pairs: [{ name: "api_token", value: "v" }, { name: "region", value: "us" }, { name: "password", value: { inner: "x" } }],
    webhook_url: "https://hooks.example.com/x?token=abc",
    link: "/relative?api_key=abc",
    endpoint: "GET /api/v1/org",
    plain: "/relative/path?query=1",
  });
  assert.deepEqual(redacted, {
    secrets: "[REDACTED]",
    tokens: "[REDACTED]",
    apiKey: "[REDACTED]",
    accessKeyId: "[REDACTED]",
    nested: { clientSecret: "[REDACTED]", name: "ok", count: 3, enabled: true, empty: null },
    pairs: [{ name: "api_token", value: "[REDACTED]" }, { name: "region", value: "us" }, { name: "password", value: "[REDACTED]" }],
    webhook_url: "https://hooks.example.com",
    link: "[REDACTED]",
    endpoint: "GET /api/v1/org",
    plain: "/relative/path?query=1",
  });

  // Booleans, numbers, and nulls under credential keys pass through: they cannot carry a secret and often mean "is set".
  assert.deepEqual(redactCredentialValues({ api_key: null, has_secret: true, token: 4 }), { api_key: null, has_secret: true, token: 4 });

  let deep = { leaf: "value" };
  for (let depth = 0; depth < 80; depth += 1) deep = { level: deep };
  let cursor = redactCredentialValues(deep);
  let steps = 0;
  while (cursor && typeof cursor === "object") {
    cursor = cursor.level;
    steps += 1;
  }
  assert.equal(cursor, "[REDACTED]", "nesting beyond the depth cap collapses to [REDACTED]");
  assert.ok(steps <= 66 && steps >= 60, `redaction recursed ${steps} levels before capping`);
});

test("projection helpers keep only assessment fields and drop key values, cloud credentials, signal payloads, and configuration bodies", () => {
  const apiKey = projectKeyRecord({ id: "k1", type: "api_keys", attributes: { name: "agent", key: "dd-api-key-value-FAKE0001", last4: "0001", created_at: daysAgo(1) } });
  assert.equal(apiKey.attributes.key, undefined);
  assert.equal(apiKey.attributes.last4, "0001");
  assert.equal(apiKey.attributes.name, "agent");

  const aws = projectCloudIntegration("aws", {
    account_id: "123456789012",
    access_key_id: "AKIAFAKEACCESSKEY0003",
    secret_access_key: "aws-secret-access-key-FAKE0004",
    cspm_resource_collection_enabled: true,
    host_tags: ["env:prod"],
  });
  assert.deepEqual(aws, {
    account_id: "123456789012",
    cspm_resource_collection_enabled: true,
    host_tags: ["env:prod"],
    authentication: "access_key",
    credential_fields_dropped: ["access_key_id", "secret_access_key"],
  });
  assert.equal(projectCloudIntegration("aws", { account_id: "1", role_name: "DatadogRole" }).authentication, "role_delegation");
  assert.equal(projectCloudIntegration("aws", { account_id: "1" }).authentication, "unknown");
  const gcp = projectCloudIntegration("gcp", { project_id: "p1", client_email: "dd@p1.iam.gserviceaccount.com", private_key: "gcp-private-key-FAKE0005", private_key_id: "kid", is_cspm_enabled: true });
  assert.deepEqual(gcp, { project_id: "p1", client_email: "dd@p1.iam.gserviceaccount.com", is_cspm_enabled: true, credential_fields_dropped: ["private_key", "private_key_id"] });
  const azure = projectCloudIntegration("azure", { tenant_name: "t1", client_id: "cid", client_secret: "azure-client-secret-FAKE0006", cspm_enabled: false });
  assert.deepEqual(azure, { tenant_name: "t1", client_id: "cid", cspm_enabled: false, credential_fields_dropped: ["client_secret"] });

  const signal = projectSecuritySignal({
    id: "sig-1",
    type: "signal",
    attributes: {
      timestamp: hoursAgo(1),
      message: "Brute force from 203.0.113.9",
      status: "high",
      tags: ["source:okta"],
      attributes: {
        status: "high",
        workflow: { triage: { state: "open", assignee: { handle: "alice" } }, rule: { id: "r1", name: "Okta brute force", query: "source:okta" } },
        custom: { request: { headers: { authorization: "signal-authorization-header-FAKE0007" } } },
        samples: [{ message: "raw log line with password=hunter2" }],
      },
    },
  });
  assert.deepEqual(signal, {
    id: "sig-1",
    type: "signal",
    attributes: {
      timestamp: signal.attributes.timestamp,
      message: "Brute force from 203.0.113.9",
      status: "high",
      tags: ["source:okta"],
      attributes: { status: "high", workflow: { triage: { state: "open" }, rule: { id: "r1", name: "Okta brute force" } } },
    },
  });

  const event = projectAuditEvent({
    id: "evt-1",
    type: "audit",
    attributes: {
      timestamp: hoursAgo(2),
      service: "audit",
      attributes: { action: "user_login", asset: { type: "user", id: "u1" }, http: { request: { headers: { cookie: "audit-request-header-FAKE0008" } } }, usr: { email: "alice@acme.example" } },
    },
  });
  assert.deepEqual(event, { id: "evt-1", type: "audit", attributes: { timestamp: event.attributes.timestamp, service: "audit", action: "user_login", asset_type: "user" } });
  assert.equal(projectAuditEvent({ id: "evt-2", attributes: { attributes: { evt: { name: "logout" } } } }).attributes.action, "logout");

  assert.deepEqual(
    projectMonitor({ id: 1, name: "Security", type: "log alert", tags: ["team:security"], priority: 1, message: "@pagerduty-security", overall_state: "OK", query: "logs(\"token:monitor-query-secret-FAKE0014\")", options: { notify_audit: true }, creator: { email: "alice@acme.example" } }),
    { id: 1, name: "Security", type: "log alert", tags: ["team:security"], priority: 1, message: "@pagerduty-security", overall_state: "OK" },
  );
  assert.deepEqual(
    projectDashboard({ id: "d1", title: "Shared", layout_type: "ordered", is_read_only: false, url: "https://app.datadoghq.com/dashboard/d1?token=dashboard-url-secret-FAKE0015", author_handle: "alice@acme.example" }),
    { id: "d1", title: "Shared", layout_type: "ordered", is_read_only: false },
  );
  assert.deepEqual(
    projectPostureFinding({ id: "f1", type: "finding", attributes: { evaluation: "fail", status: "critical", resource_type: "aws_s3_bucket", resource: "arn:aws:s3:::bucket", rule: { id: "r1", name: "S3 public", description: "long text" }, resource_configuration: { policy: "posture-resource-secret-FAKE0016" } } }),
    { id: "f1", type: "finding", attributes: { evaluation: "fail", status: "critical", resource_type: "aws_s3_bucket", resource: "arn:aws:s3:::bucket", rule: { id: "r1", name: "S3 public" } } },
  );
});

test("DatadogApiClient withholds non-JSON error bodies, caps JSON error detail, and strips userinfo from explicit base URLs", async () => {
  const htmlDenied = new DatadogApiClient(sampleConfig({ maxRetries: 0 }), {
    fetchImpl: async () => new Response("<html><body>Forbidden for token SECRET-IN-HTML-FAKE</body></html>", { status: 403, statusText: "Forbidden", headers: { "content-type": "text/html; charset=utf-8" } }),
  });
  await assert.rejects(() => htmlDenied.listUsers(1), (error) => {
    assert.ok(error instanceof DatadogApiError);
    assert.doesNotMatch(error.message, /SECRET-IN-HTML-FAKE/);
    // The body is replaced with a status-and-length note rather than sliced into the message.
    assert.match(error.message, /403 Forbidden: non-JSON body \(text\/html, \d+ bytes, not echoed\)/);
    return true;
  });

  const longDetail = new DatadogApiClient(sampleConfig({ maxRetries: 0 }), {
    fetchImpl: async () => jsonResponse({ errors: [`Bad request ${"x".repeat(600)} TAIL-FAKE`] }, { status: 400 }),
  });
  await assert.rejects(() => longDetail.listUsers(1), (error) => {
    assert.match(error.message, /\.\.\. \(truncated\)$/);
    assert.doesNotMatch(error.message, /TAIL-FAKE/);
    assert.ok(error.message.length < 400, `error message is capped (${error.message.length} characters)`);
    return true;
  });

  const emptyJson = new DatadogApiClient(sampleConfig({ maxRetries: 0 }), {
    fetchImpl: async () => jsonResponse({ unexpected: "shape" }, { status: 400 }),
  });
  await assert.rejects(() => emptyJson.listUsers(1), /Datadog request failed \(400\) GET \/api\/v2\/users: 400: JSON body without a documented error field \(application\/json, \d+ bytes, not echoed\)/);

  const resolved = resolveDatadogConfiguration(
    { api_key: "arg-api-key-0123456789", app_key: "arg-app-key-0123456789", base_url: "https://svc:hunter2@api.datadoghq.eu/?token=abc#frag" },
    {},
    "/nonexistent-home",
  );
  assert.equal(resolved.baseUrl, "https://api.datadoghq.eu");
});

test("DatadogApiClient stops on a repeated cursor or repeated empty pages and reports why the listing is incomplete", async () => {
  let stuckCalls = 0;
  const stuck = new DatadogApiClient(sampleConfig(), {
    fetchImpl: async () => {
      stuckCalls += 1;
      return jsonResponse({ data: [{ id: `sig-${stuckCalls}`, attributes: {} }], meta: { page: { after: "same-cursor" } } });
    },
  });
  const repeated = await stuck.listSecuritySignals({ from: "now-7d", to: "now", limit: 50 });
  assert.equal(repeated.items.length, 2);
  assert.equal(repeated.truncated, true);
  assert.match(repeated.truncationReason, /repeated the same page cursor/);
  assert.equal(stuckCalls, 2, "the client stops as soon as the cursor repeats");

  let emptyCalls = 0;
  const empty = new DatadogApiClient(sampleConfig(), {
    fetchImpl: async () => {
      emptyCalls += 1;
      return jsonResponse({ data: [], meta: { page: { after: `cursor-${emptyCalls}` } } });
    },
  });
  const spun = await empty.listAuditEvents({ from: "now-7d", to: "now", limit: 50 });
  assert.equal(spun.items.length, 0);
  assert.equal(spun.truncated, true);
  assert.match(spun.truncationReason, /5 consecutive empty pages arrived with a next-page cursor/);
  assert.equal(emptyCalls, 5, "the client gives up after the configured number of empty pages");

  let sparseCalls = 0;
  const sparse = new DatadogApiClient(sampleConfig(), {
    fetchImpl: async () => {
      sparseCalls += 1;
      if (sparseCalls === 2) return jsonResponse({ data: [], meta: { page: { after: "cursor-2" } } });
      if (sparseCalls === 3) return jsonResponse({ data: [{ id: "e3", attributes: {} }], meta: { page: {} } });
      return jsonResponse({ data: [{ id: "e1", attributes: {} }], meta: { page: { after: "cursor-1" } } });
    },
  });
  const tolerated = await sparse.listAuditEvents({ from: "now-7d", to: "now", limit: 50 });
  assert.deepEqual(tolerated.items.map((item) => item.id), ["e1", "e3"]);
  assert.equal(tolerated.truncated, false, "a single empty page between two populated pages is followed, not treated as the end");

  let postureCalls = 0;
  const posture = new DatadogApiClient(sampleConfig(), {
    fetchImpl: async () => {
      postureCalls += 1;
      return jsonResponse({ data: [{ id: `f${postureCalls}` }], meta: { page: { cursor: "same-cursor" } } });
    },
  });
  const findings = await posture.listPostureFindings({ evaluation: "fail", limit: 100 });
  assert.equal(findings.truncated, true);
  assert.equal(findings.seen, 2);
  assert.equal(findings.total_filtered_count, null);
  assert.match(findings.truncation_reason, /repeated the same page cursor/);

  let emptyPostureCalls = 0;
  const emptyPosture = new DatadogApiClient(sampleConfig(), {
    fetchImpl: async () => {
      emptyPostureCalls += 1;
      return jsonResponse({ data: [], meta: { page: { cursor: `cursor-${emptyPostureCalls}` } } });
    },
  });
  const spunPosture = await emptyPosture.listPostureFindings({ evaluation: "pass", limit: 100 });
  assert.equal(spunPosture.truncated, true);
  assert.match(spunPosture.truncation_reason, /5 consecutive empty pages/);
  assert.equal(emptyPostureCalls, 5);

  const seen = [];
  const keys = new DatadogApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      seen.push(url);
      const page = Number(url.searchParams.get("page[number]"));
      const size = Number(url.searchParams.get("page[size]"));
      return jsonResponse({ data: fill(size, (index) => ({ id: `ak-${page * size + index}`, attributes: { last4: "0000" } })) });
    },
  });
  const currentUserKeys = await keys.listCurrentUserApplicationKeys(250);
  assert.equal(currentUserKeys.items.length, 250);
  assert.equal(currentUserKeys.truncated, true, "a full last page under the cap without a total is reported as truncated");
  assert.deepEqual(seen.map((url) => url.pathname), Array(3).fill("/api/v2/current_user/application_keys"));
  assert.deepEqual(seen.map((url) => url.searchParams.get("page[number]")), ["0", "1", "2"]);
});

// Fake credential material planted in every collected surface. Each value must be absent from every bundle file and
// zip entry: keys through the key projection, cloud credentials through the integration projection, signal, audit,
// monitor, dashboard, and posture payloads through their projections, and the verbatim configuration exports
// (organization, org configs, pipelines, archives, scanner, rules) through the credential-key redactor.
const DATADOG_FAKE_SECRETS = [
  "dd-api-key-value-FAKE0001",
  "dd-app-key-value-FAKE0002",
  "AKIAFAKEACCESSKEY0003",
  "aws-secret-access-key-FAKE0004",
  "gcp-private-key-FAKE0005",
  "azure-client-secret-FAKE0006",
  "signal-authorization-header-FAKE0007",
  "audit-request-header-FAKE0008",
  "org-setting-token-FAKE0009",
  "pipeline-processor-token-FAKE0010",
  "archive-secret-FAKE0011",
  "scanner-api-key-FAKE0012",
  "org-config-value-FAKE0013",
  "monitor-query-secret-FAKE0014",
  "dashboard-url-secret-FAKE0015",
  "posture-resource-secret-FAKE0016",
  "rule-signing-secret-FAKE0017",
  "index-webhook-secret-FAKE0018",
];

function leakyClient() {
  const organization = healthyOrganization();
  organization.settings.saml_idp_endpoint = "https://idp.example.com/sso?token=org-setting-token-FAKE0009";
  const scanner = healthySensitiveDataScanner();
  scanner.included[0].attributes.api_key = "scanner-api-key-FAKE0012";
  return healthyClient({
    async getOrganization() {
      return organization;
    },
    async listOrgConfigs() {
      return [
        { id: "monitor_timezone", type: "org_configs", attributes: { name: "monitor_timezone", value: "UTC" } },
        { id: "api_token", type: "org_configs", attributes: { name: "api_token", value: "org-config-value-FAKE0013" } },
      ];
    },
    async listApiKeys() {
      return [{ id: "key-1", type: "api_keys", attributes: { name: "prod-agent", key: "dd-api-key-value-FAKE0001", last4: "0001", created_at: daysAgo(10), date_last_used: daysAgo(1) } }];
    },
    async listApplicationKeys() {
      const keys = healthyApplicationKeys();
      keys.data[0].attributes.key = "dd-app-key-value-FAKE0002";
      return keys;
    },
    async listAwsIntegrations() {
      return [{ account_id: "123456789012", access_key_id: "AKIAFAKEACCESSKEY0003", secret_access_key: "aws-secret-access-key-FAKE0004", cspm_resource_collection_enabled: true }];
    },
    async listGcpIntegrations() {
      return [{ project_id: "p1", client_email: "dd@p1.iam.gserviceaccount.com", private_key: "gcp-private-key-FAKE0005", is_cspm_enabled: true }];
    },
    async listAzureIntegrations() {
      return [{ tenant_name: "t1", client_id: "cid", client_secret: "azure-client-secret-FAKE0006", cspm_enabled: true }];
    },
    async listSecurityRules() {
      const rules = await healthyClient().listSecurityRules();
      rules[0].options = { signing_secret: "rule-signing-secret-FAKE0017", evaluationWindow: 300 };
      return rules;
    },
    async listSecuritySignals() {
      return [{
        id: "sig-1",
        type: "signal",
        attributes: {
          timestamp: hoursAgo(1),
          message: "Brute force",
          attributes: { status: "high", workflow: { triage: { state: "open" } }, custom: { request: { headers: { authorization: "signal-authorization-header-FAKE0007" } } } },
        },
      }];
    },
    async listPostureFindings(options = {}) {
      return {
        data: [{ id: "f1", attributes: { evaluation: options.evaluation, resource_configuration: { policy: "posture-resource-secret-FAKE0016" } } }],
        total_filtered_count: options.evaluation === "fail" ? 10 : 90,
      };
    },
    async listAuditEvents(options = {}) {
      const headers = { cookie: "audit-request-header-FAKE0008" };
      if (options.sort === "timestamp") {
        return [{ id: "evt-old", type: "audit", attributes: { timestamp: daysAgo(100), service: "audit", attributes: { http: { request: { headers } } } } }];
      }
      return [{ id: "evt-1", type: "audit", attributes: { timestamp: hoursAgo(2), attributes: { http: { request: { headers } } } } }];
    },
    async listLogPipelines() {
      return [{ id: "p1", name: "cloudtrail", is_enabled: true, filter: { query: "source:cloudtrail" }, processors: [{ type: "lookup-processor", api_token: "pipeline-processor-token-FAKE0010" }] }];
    },
    async listLogIndexes() {
      return [{ name: "main", num_retention_days: 30, exclusion_filters: [], daily_limit_reset: { webhook_secret: "index-webhook-secret-FAKE0018" } }];
    },
    async listLogArchives() {
      return [{ id: "a1", type: "archives", attributes: { name: "s3-archive", state: "WORKING", destination: { type: "s3", integration: { account_id: "123456789012", secret_access_key: "archive-secret-FAKE0011" } } } }];
    },
    async getSensitiveDataScannerConfig() {
      return scanner;
    },
    async listDashboards() {
      return [{ id: "d1", title: "Shared", url: "https://app.datadoghq.com/dashboard/d1?token=dashboard-url-secret-FAKE0015", author_handle: "alice@acme.example" }];
    },
    async listMonitors() {
      return [{ id: 1, name: "Security: root login", tags: ["team:security"], priority: 1, message: "@pagerduty-security", query: "logs(\"monitor-query-secret-FAKE0014\")" }];
    },
  });
}

test("exportDatadogAuditBundle never writes credential material from any collected surface into the bundle or its zip", async () => {
  const base = createTempBase("grclanker-datadog-export-secrets-");
  const config = sampleConfig();
  const result = await exportDatadogAuditBundle(leakyClient(), config, base, { now: NOW });
  assert.equal(result.findingCount, 20);

  const files = readBundleFiles(result.outputDir);
  assert.ok(files.size >= 35, `bundle has ${files.size} files`);
  const entries = readZipEntries(result.zipPath);
  assert.ok(entries.size >= 35, `zip has ${entries.size} entries`);
  const secrets = [...DATADOG_FAKE_SECRETS, config.apiKey, config.appKey];
  assertSecretsAbsent(assert, files, secrets, "bundle file");
  assertSecretsAbsent(assert, entries, secrets, "zip entry");

  const apiKeys = JSON.parse(files.get("core_data/api_keys.json"));
  assert.equal(apiKeys[0].attributes.key, undefined);
  assert.equal(apiKeys[0].attributes.last4, "0001");
  const cloud = JSON.parse(files.get("core_data/cloud_integrations.json"));
  assert.equal(cloud.aws[0].authentication, "access_key");
  assert.deepEqual(cloud.aws[0].credential_fields_dropped, ["access_key_id", "secret_access_key"]);
  assert.deepEqual(cloud.gcp[0].credential_fields_dropped, ["private_key"]);
  assert.deepEqual(cloud.azure[0].credential_fields_dropped, ["client_secret"]);
  const signals = JSON.parse(files.get("core_data/security_signals.json"));
  assert.equal(signals[0].attributes.attributes.custom, undefined);
  assert.equal(signals[0].attributes.attributes.workflow.triage.state, "open");
  const organization = JSON.parse(files.get("core_data/organization.json"));
  assert.equal(organization.settings.saml_idp_endpoint, "https://idp.example.com");
  const orgConfigs = JSON.parse(files.get("core_data/org_configs.json"));
  assert.equal(orgConfigs[1].attributes.value, "[REDACTED]");
  assert.equal(orgConfigs[0].attributes.value, "UTC");
  const rules = JSON.parse(files.get("core_data/security_rules.json"));
  assert.equal(rules[0].options.signing_secret, "[REDACTED]");
  assert.equal(rules[0].options.evaluationWindow, 300);
  const findings = JSON.parse(files.get("analysis/findings.json"));
  const integrations = findings.find((item) => item.id === "DD-18");
  assert.deepEqual(integrations.evidence.aws_accounts_with_static_key_authentication, ["123456789012"]);
  assert.match(integrations.summary, /1 AWS integrations authenticate with static access keys/);
  assert.equal(findings.find((item) => item.id === "DD-12").status, "pass");
});

test("exportDatadogAuditBundle writes collection_status.json with readable, complete, seen, and total for every inventory", async () => {
  const base = createTempBase("grclanker-datadog-export-status-");
  const result = await exportDatadogAuditBundle(healthyClient({
    async listUsers(limit) {
      return fill(limit, (index) => user(`u${index}`));
    },
    async listOrgConnections(limit) {
      // The client stopped under the probe limit on its own (a stuck cursor, say) and reported the server total.
      return { items: fill(Math.min(limit, 10000), (index) => ({ id: `c${index}`, attributes: { connection_types: ["logs"] } })), truncated: true, total: 12000 };
    },
    async getIpAllowlist() {
      throw forbidden("/api/v2/ip_allowlist");
    },
    async listPostureFindings(options = {}) {
      return options.evaluation === "fail"
        ? { data: fill(3, (index) => ({ id: `f${index}` })), total_filtered_count: null, truncated: true, truncation_reason: "the server repeated the same page cursor", seen: 3 }
        : { data: [], total_filtered_count: 90 };
    },
  }), sampleConfig(), base, { now: NOW, userLimit: 50 });

  const status = JSON.parse(readFileSync(join(result.outputDir, "core_data", "collection_status.json"), "utf8"));
  const byInventory = new Map(status.inventories.map((row) => [row.inventory, row]));
  assert.equal(byInventory.size, 23);
  assert.ok([...byInventory.values()].every((row) => typeof row.readable === "boolean" && row.collected === row.readable && row.endpoint && row.permission));
  // Flags are booleans only for inventories that were read; a denied inventory renders them null.
  assert.ok([...byInventory.values()].every((row) => (row.readable ? typeof row.complete === "boolean" && typeof row.truncated === "boolean" : row.complete === null && row.truncated === null)));

  const users = byInventory.get("users");
  assert.equal(users.status, "readable");
  assert.equal(users.readable, true);
  assert.equal(users.complete, false);
  assert.equal(users.truncated, true);
  assert.equal(users.seen, 50);
  assert.equal(users.total, null);
  assert.equal(users.limit, 50);
  assert.equal(users.http_status, null);
  assert.match(users.truncation_reason, /more than 50 items exist/);

  const connections = byInventory.get("org_connections");
  assert.equal(connections.complete, false);
  assert.equal(connections.seen, 10000);
  assert.equal(connections.total, 12000);

  const allowlist = byInventory.get("ip_allowlist");
  assert.equal(allowlist.status, "forbidden");
  assert.equal(allowlist.collected, false);
  assert.equal(allowlist.readable, false);
  assert.equal(allowlist.http_status, 403);
  assert.deepEqual([allowlist.complete, allowlist.truncated, allowlist.seen, allowlist.total, allowlist.truncation_reason], [null, null, null, null, null]);
  assert.match(allowlist.error, /403 Forbidden/);

  // Totals count only what was observed: the denied inventory is neither complete nor truncated.
  assert.equal(status.totals.inventories, 23);
  assert.equal(status.totals.readable, 22);
  assert.equal(status.totals.forbidden, 1);
  assert.equal(status.totals.not_readable, 0);
  assert.equal(status.totals.truncated, 3);
  assert.equal(status.totals.complete, 19);
  assert.equal(status.totals.truncation_unknown, 1);

  const failing = byInventory.get("posture_findings_fail");
  assert.equal(failing.complete, false);
  assert.equal(failing.seen, 3);
  assert.equal(failing.total, null);
  assert.match(failing.truncation_reason, /repeated the same page cursor/);
  const passing = byInventory.get("posture_findings_pass");
  assert.equal(passing.complete, true);
  assert.equal(passing.total, 90);

  const roles = byInventory.get("roles");
  assert.deepEqual([roles.readable, roles.complete, roles.seen, roles.total], [true, true, 4, 4]);

  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /users: inventory truncated at 50 items \(50 of an unknown total loaded; more than 50 items exist\); raise user_limit to inspect the full list/);
  assert.match(errorLog, /org_connections: inventory truncated at 10000 items \(10000 of 12000 loaded; the listing stopped early\); raise the org connection limit/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "DD-12").status, "warn");
  assert.match(findings.find((item) => item.id === "DD-12").summary, /paged counts hit the finding_limit/);
  const orgSettings = findings.find((item) => item.id === "DD-20");
  assert.equal(orgSettings.status, "warn");
  // DD-20 already warns on the readable inventories, so the truncation caveat is recorded in evidence rather than re-demoting the verdict.
  assert.match(orgSettings.evidence.verdict_caveats.join(" "), /org_connections inventory is truncated at 10000 items \(10000 of 12000 loaded; raise the org connection limit\)/);
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

// ---------------------------------------------------------------------------------------------------------------
// Addenda 2, 3, and 5. The fixtures below drive the real DatadogApiClient through an HTTP router that records every
// request it served, so the status codes and endpoints named in the output can be checked against the requests the
// run actually made, and a principal fixture plants names that only ever appear in one inventory so their absence
// under that inventory's denial proves gating.
// ---------------------------------------------------------------------------------------------------------------

const DD_CANARIES = {
  bearer: "BEARER_CANARY_9f8e7d6c5b4a3210",
  cookie: "SESSION_CANARY_0123456789abcdef",
  apiKey: "APIKEY_CANARY_fedcba9876543210",
  urlToken: "URLTOKEN_CANARY_1122334455667788",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKV1RfQ0FOQVJZX2FiY2RlZjAxMjM0NTY3ODkifQ.JWT_CANARY_SIGNATURE_abcdef0123456789",
};

function ddCanaryValues() {
  return Object.values(DD_CANARIES);
}

const DD_HTML_ERROR_BODY = `<html><body><h1>502 Bad Gateway</h1><p>upstream sent Authorization: Bearer ${DD_CANARIES.bearer}; Set-Cookie: session=${DD_CANARIES.cookie}; api_key=${DD_CANARIES.apiKey}; retry at https://api.example.com/v1/x?token=${DD_CANARIES.urlToken} later; jwt ${DD_CANARIES.jwt}</p></body></html>`;

/** A proxy error page: non-JSON, carrying every credential class in its body. */
function htmlGateway() {
  return () => new Response(DD_HTML_ERROR_BODY, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

/** Datadog's documented JSON error shape whose message embeds a URL with a credential in its query string. */
function jsonForbiddenWithUrl() {
  return () => jsonResponse({ errors: [`Forbidden; see https://api.example.com/v1/x?token=${DD_CANARIES.urlToken} for details`] }, { status: 403, statusText: "Forbidden" });
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function listingItems(value) {
  return Array.isArray(value) ? value : asArray(value?.items ?? value?.data);
}

function numberedPage(url, list) {
  const size = Number(url.searchParams.get("page[size]"));
  const page = Number(url.searchParams.get("page[number]") ?? 0);
  return { data: list.slice(page * size, (page + 1) * size), meta: { page: { total_count: list.length } } };
}

/**
 * Serves a method-level fixture client over HTTP in the envelopes the Datadog API uses (v2 `data`/`meta.page`
 * paging, v1 arrays, `orgs`, `indexes`, `dashboards`, `accounts`), so the real DatadogApiClient can be exercised
 * against the same fixtures the assess tests use.
 */
function routesFromClient(client) {
  return {
    "GET /api/v1/validate": async () => jsonResponse(await client.validateApiKey()),
    "GET /api/v2/validate_keys": async () => jsonResponse(await client.validateKeyPair()),
    "GET /api/v1/org": async () => jsonResponse({ orgs: [await client.getOrganization()] }),
    "GET /api/v2/org_configs": async () => jsonResponse({ data: await client.listOrgConfigs() }),
    "GET /api/v2/org_connections": async (url) => {
      const list = listingItems(await client.listOrgConnections(100000));
      const size = Number(url.searchParams.get("limit"));
      const offset = Number(url.searchParams.get("offset") ?? 0);
      return jsonResponse({ data: list.slice(offset, offset + size), meta: { page: { total_count: list.length } } });
    },
    "GET /api/v2/users": async (url) => jsonResponse(numberedPage(url, listingItems(await client.listUsers(100000)))),
    "GET /api/v2/roles": async (url) => jsonResponse(numberedPage(url, listingItems(await client.listRoles(100000)))),
    "GET /api/v2/roles/{id}/permissions": async (url) => jsonResponse({ data: await client.listRolePermissions(decodeURIComponent(url.pathname.split("/")[4])) }),
    "GET /api/v2/api_keys": async (url) => jsonResponse(numberedPage(url, listingItems(await client.listApiKeys(100000)))),
    "GET /api/v2/application_keys": async (url) => {
      const keys = await client.listApplicationKeys(100000);
      return jsonResponse({ ...numberedPage(url, asArray(keys.data)), included: asArray(keys.included) });
    },
    "GET /api/v2/audit/events": async (url) => jsonResponse({
      data: listingItems(await client.listAuditEvents({ sort: url.searchParams.get("sort") })).slice(0, Number(url.searchParams.get("page[limit]"))),
      meta: { page: {} },
    }),
    "GET /api/v2/security_monitoring/rules": async (url) => jsonResponse(numberedPage(url, listingItems(await client.listSecurityRules(100000)))),
    "GET /api/v2/security_monitoring/signals": async (url) => jsonResponse({
      data: listingItems(await client.listSecuritySignals({ limit: 100000 })).slice(0, Number(url.searchParams.get("page[limit]"))),
      meta: { page: {} },
    }),
    "GET /api/v2/posture_management/findings": async (url) => {
      const result = await client.listPostureFindings({ evaluation: url.searchParams.get("filter[evaluation]") ?? undefined, limit: 100000 });
      return jsonResponse({
        data: asArray(result.data).slice(0, Number(url.searchParams.get("page[limit]"))),
        meta: { page: { total_filtered_count: result.total_filtered_count ?? undefined } },
      });
    },
    "GET /api/v2/ip_allowlist": async () => jsonResponse(await client.getIpAllowlist()),
    "GET /api/v2/sensitive-data-scanner/config": async () => jsonResponse(await client.getSensitiveDataScannerConfig()),
    "GET /api/v1/logs/config/pipelines": async () => jsonResponse(await client.listLogPipelines()),
    "GET /api/v1/logs/config/indexes": async () => jsonResponse({ indexes: await client.listLogIndexes() }),
    "GET /api/v2/logs/config/archives": async () => jsonResponse({ data: await client.listLogArchives() }),
    "GET /api/v1/dashboard": async (url) => {
      const list = url.searchParams.get("filter[shared]") === "true" ? listingItems(await client.listDashboards({ shared: true, limit: 100000 })) : [];
      const count = Number(url.searchParams.get("count"));
      const start = Number(url.searchParams.get("start") ?? 0);
      return jsonResponse({ dashboards: list.slice(start, start + count) });
    },
    "GET /api/v1/monitor": async (url) => {
      const list = listingItems(await client.listMonitors(100000));
      const size = Number(url.searchParams.get("page_size"));
      const page = Number(url.searchParams.get("page") ?? 0);
      return jsonResponse(list.slice(page * size, (page + 1) * size));
    },
    "GET /api/v1/integration/aws": async () => jsonResponse({ accounts: await client.listAwsIntegrations() }),
    "GET /api/v1/integration/gcp": async () => jsonResponse(await client.listGcpIntegrations()),
    "GET /api/v1/integration/azure": async () => jsonResponse(await client.listAzureIntegrations()),
  };
}

/** Fetch replacement that routes by method and path and records the status of every response it served. */
function createDatadogRouter(routes, log = []) {
  return async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const method = init.method ?? "GET";
    const handler = routes[`${method} ${url.pathname.replace(/^\/api\/v2\/roles\/[^/]+\/permissions$/, "/api/v2/roles/{id}/permissions")}`];
    if (!handler) throw new Error(`no fixture route for ${method} ${url.pathname}`);
    const response = await handler(url, init);
    log.push({ method, url: url.toString(), path: url.pathname, status: response.status });
    return response;
  };
}

function httpClient(routes, log, configOverrides = {}) {
  const config = sampleConfig({ maxRetries: 0, ...configOverrides });
  return { config, client: new DatadogApiClient(config, { fetchImpl: createDatadogRouter(routes, log) }) };
}

function ddMentionedEndpoints(text) {
  return [...text.matchAll(/\b(GET|POST|PUT|PATCH|DELETE)\s+(\/[A-Za-z0-9_./?=&{}[\]-]+)/g)]
    .map((match) => ({ method: match[1], path: match[2].split("?")[0].replace(/[.,;:)]+$/, "") }));
}

function ddMentionedStatusCodes(text) {
  const codes = new Set();
  for (const match of text.matchAll(/\b([1-5]\d\d) (?:OK|Forbidden|Unauthorized|Bad Request|Not Found|Too Many Requests|Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout|Error)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/request failed \(([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/"(?:http_)?status":\s*([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/\bHTTP ([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  return [...codes];
}

/** Asserts every endpoint and status code named anywhere in `outputs` was requested and observed according to `log`. */
function assertOutputMatchesRequestLog(outputs, log, label) {
  const requested = new Set(log.map((entry) => `${entry.method} ${entry.path}`));
  const statuses = new Set(log.map((entry) => entry.status));
  let endpointMentions = 0;
  let statusMentions = 0;
  for (const [name, text] of outputs) {
    for (const { method, path } of ddMentionedEndpoints(text)) {
      endpointMentions += 1;
      assert.ok(requested.has(`${method} ${path}`), `${label}: ${name} names ${method} ${path} but the run never requested it; requested: ${[...requested].sort().join(", ")}`);
    }
    for (const code of ddMentionedStatusCodes(text)) {
      statusMentions += 1;
      assert.ok(statuses.has(code), `${label}: ${name} names HTTP ${code} but no request observed it; observed: ${[...statuses]}`);
    }
  }
  return { endpointMentions, statusMentions };
}

async function runAllAssessments(client) {
  return Promise.all([
    assessDatadogIdentity(client, { now: NOW }),
    assessDatadogAccessControls(client, { now: NOW }),
    assessDatadogSecurityMonitoring(client, { now: NOW }),
    assessDatadogDataProtection(client, { now: NOW }),
  ]);
}

test("verdict rule 9 / addendum 2: the Datadog bundle, its zip, every assess payload, and the access check never carry canaries from error bodies, and errors carry the status-and-length note", async () => {
  const routes = routesFromClient(leakyClient());
  routes["GET /api/v2/ip_allowlist"] = htmlGateway();
  routes["GET /api/v2/logs/config/archives"] = jsonForbiddenWithUrl();
  const log = [];
  const { client, config } = httpClient(routes, log);

  const access = await checkDatadogAccess(client);
  const result = await exportDatadogAuditBundle(client, config, createTempBase("grclanker-datadog-canary-"), { now: NOW });
  const assessments = await runAllAssessments(client);

  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size >= 35 && entries.size === files.size, `expected the zip to mirror ${files.size} files, got ${entries.size}`);
  const secrets = [...ddCanaryValues(), ...DATADOG_FAKE_SECRETS, config.apiKey, config.appKey];
  assertSecretsAbsent(assert, files, secrets, "bundle file");
  assertSecretsAbsent(assert, entries, secrets, "zip entry");
  assertSecretsAbsent(assert, new Map([["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), secrets, "tool payload");
  assert.equal(result.errorCount, 2, `only the two failing surfaces are recorded: ${files.get("_errors.log")}`);

  // The non-JSON body is described by status and length; the JSON error is echoed with its URL query scrubbed.
  const errors = files.get("_errors.log");
  assert.match(errors, /^ip_allowlist: Datadog request failed \(502 Bad Gateway\) GET \/api\/v2\/ip_allowlist: 502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)$/m);
  assert.match(errors, /^log_archives: Datadog request failed \(403 Forbidden\) GET \/api\/v2\/logs\/config\/archives: Forbidden; see https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for details$/m);

  // The observed status flows into the marker, the finding, the access surface, and the collection status; no "403" is
  // invented for the 502 path.
  const allowlist = JSON.parse(files.get("core_data/ip_allowlist.json"));
  assert.deepEqual(
    { collected: allowlist.collected, status: allowlist.status, endpoint: allowlist.endpoint, permission: allowlist.permission, reason: allowlist.reason },
    { collected: false, status: 502, endpoint: "GET /api/v2/ip_allowlist", permission: "org_management", reason: "not_readable" },
  );
  assert.match(allowlist.error, /non-JSON body \(text\/html/);
  const findings = JSON.parse(files.get("analysis/findings.json"));
  const ipAllowlist = findings.find((item) => item.id === "DD-15");
  assert.equal(ipAllowlist.status, "manual");
  assert.match(ipAllowlist.summary, /^The IP allowlist \(org_management\) surface was not readable \(Datadog request failed \(502 Bad Gateway\) GET \/api\/v2\/ip_allowlist: 502 Bad Gateway: non-JSON body/);
  assert.doesNotMatch(ipAllowlist.summary, /403/);
  assert.deepEqual([ipAllowlist.evidence.enabled, ipAllowlist.evidence.entries, ipAllowlist.evidence.inventory.http_status, ipAllowlist.evidence.inventory.read], [null, null, 502, false]);
  const archives = findings.find((item) => item.id === "DD-10");
  assert.equal(archives.status, "manual");
  assert.match(archives.summary, /Unreadable inventory: log_archives \(GET \/api\/v2\/logs\/config\/archives, logs_read_archives: Datadog request failed \(403 Forbidden\).*\[REDACTED\]/);
  assert.equal(archives.evidence.archives, null);
  assert.equal(archives.evidence.archive_destinations, null);
  assert.equal(archives.evidence.failing_archives, null);

  const allowlistProbe = access.surfaces.find((surface) => surface.name === "ip_allowlist");
  assert.deepEqual(
    { status: allowlistProbe.status, collected: allowlistProbe.collected, http_status: allowlistProbe.http_status, count: allowlistProbe.count },
    { status: "not_readable", collected: false, http_status: 502, count: null },
  );
  assert.match(allowlistProbe.error, /502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/);
  const archiveProbe = access.surfaces.find((surface) => surface.name === "log_archives");
  assert.deepEqual({ status: archiveProbe.status, collected: archiveProbe.collected, http_status: archiveProbe.http_status, count: archiveProbe.count }, { status: "forbidden", collected: false, http_status: 403, count: null });
  assert.deepEqual(access.missingPermissions, ["logs_read_archives"]);
  assert.deepEqual(access.permissionStateUnknown, ["ip_allowlist"]);
  assert.equal(access.status, "limited");
  assert.ok(access.notes.some((note) => /Permission state unknown for ip_allowlist: the probe failed without a permission denial/.test(note)), access.notes.join("\n"));

  const status = JSON.parse(files.get("core_data/collection_status.json"));
  const allowlistRow = status.inventories.find((row) => row.inventory === "ip_allowlist");
  assert.deepEqual(
    { status: allowlistRow.status, collected: allowlistRow.collected, http_status: allowlistRow.http_status, complete: allowlistRow.complete, truncated: allowlistRow.truncated, seen: allowlistRow.seen, total: allowlistRow.total },
    { status: "not_readable", collected: false, http_status: 502, complete: null, truncated: null, seen: null, total: null },
  );
  assert.equal(status.totals.not_readable, 1);
  assert.equal(status.totals.forbidden, 1);
  assert.equal(status.totals.truncation_unknown, 2);

  // The assess tools see the same denials with the same statuses.
  const accessControls = assessments[1];
  assert.equal(findingById(accessControls, "DD-15").status, "manual");
  assert.match(findingById(accessControls, "DD-15").summary, /502 Bad Gateway/);
  assert.equal(accessControls.summary.ip_allowlist_enabled, null);
  assert.equal(assessments[3].summary.archives, null);
});

test("addendum 5: every endpoint and status code named in Datadog output corresponds to a request the run made and observed", async () => {
  const routes = routesFromClient(healthyClient());
  routes["GET /api/v2/ip_allowlist"] = htmlGateway();
  routes["GET /api/v2/logs/config/archives"] = jsonForbiddenWithUrl();
  routes["GET /api/v1/integration/gcp"] = () => jsonResponse({ errors: ["Forbidden"] }, { status: 403, statusText: "Forbidden" });
  routes["GET /api/v2/roles/{id}/permissions"] = () => jsonResponse({ errors: ["Forbidden"] }, { status: 403, statusText: "Forbidden" });
  const log = [];
  const { client, config } = httpClient(routes, log);

  const access = await checkDatadogAccess(client);
  const result = await exportDatadogAuditBundle(client, config, createTempBase("grclanker-datadog-request-log-"), { now: NOW });
  const assessments = await runAllAssessments(client);
  const outputs = [...readBundleFiles(result.outputDir), ["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]];

  const statuses = new Set(log.map((entry) => entry.status));
  assert.deepEqual([...statuses].sort(), [200, 403, 502], `fixture served 200, 403, and 502; got ${[...statuses]}`);
  assert.ok(log.some((entry) => entry.path === "/api/v2/roles/role-auditor/permissions" && entry.status === 403), "the per-role permission request was made and denied");
  const { endpointMentions, statusMentions } = assertOutputMatchesRequestLog(outputs, log, "mixed denials");
  assert.ok(endpointMentions > 40, `expected endpoint mentions across the bundle, got ${endpointMentions}`);
  assert.ok(statusMentions > 5, `expected status mentions across the bundle, got ${statusMentions}`);

  // The per-role gap names the request the run made, not the descriptor template.
  const rbac = findingById(assessments[0], "DD-03");
  assert.equal(rbac.status, "manual");
  assert.match(rbac.summary, /Unreadable inventory: role_permissions \(GET \/api\/v2\/roles\/role-auditor\/permissions, user_access_read: Auditor: Datadog request failed \(403 Forbidden\) GET \/api\/v2\/roles\/role-auditor\/permissions: Forbidden\)/);
  assert.ok(!JSON.stringify(outputs).includes("{id}"), "no templated endpoint reaches the output");
  const roles = JSON.parse(readFileSync(join(result.outputDir, "core_data", "roles.json"), "utf8"));
  assert.deepEqual(
    { collected: roles.permissions_by_role["role-auditor"].collected, status: roles.permissions_by_role["role-auditor"].status, endpoint: roles.permissions_by_role["role-auditor"].endpoint },
    { collected: false, status: 403, endpoint: "GET /api/v2/roles/role-auditor/permissions" },
  );
});

/**
 * Every list dataset written to core_data, the route that fills it, and the shape a readable-but-empty read leaves
 * behind (`[]` for a bare list, a `data: []` envelope for application keys and posture findings).
 */
const DD_CORE_DATA_DATASETS = [
  { route: "GET /api/v2/users", datasets: [["users", "core_data/users.json", (json) => json, "array"]] },
  { route: "GET /api/v2/roles", datasets: [["roles", "core_data/roles.json", (json) => json.roles, "array"]] },
  { route: "GET /api/v2/org_configs", datasets: [["org_configs", "core_data/org_configs.json", (json) => json, "array"]] },
  { route: "GET /api/v2/api_keys", datasets: [["api_keys", "core_data/api_keys.json", (json) => json, "array"]] },
  { route: "GET /api/v2/application_keys", datasets: [["application_keys", "core_data/application_keys.json", (json) => json, "envelope"]] },
  { route: "GET /api/v1/dashboard", datasets: [["shared_dashboards", "core_data/shared_dashboards.json", (json) => json, "array"]] },
  { route: "GET /api/v1/integration/aws", datasets: [["aws_integrations", "core_data/cloud_integrations.json", (json) => json.aws, "array"]] },
  { route: "GET /api/v1/integration/gcp", datasets: [["gcp_integrations", "core_data/cloud_integrations.json", (json) => json.gcp, "array"]] },
  { route: "GET /api/v1/integration/azure", datasets: [["azure_integrations", "core_data/cloud_integrations.json", (json) => json.azure, "array"]] },
  { route: "GET /api/v2/security_monitoring/rules", datasets: [["security_rules", "core_data/security_rules.json", (json) => json, "array"]] },
  { route: "GET /api/v2/security_monitoring/signals", datasets: [["security_signals", "core_data/security_signals.json", (json) => json, "array"]] },
  {
    route: "GET /api/v2/posture_management/findings",
    datasets: [
      ["posture_findings_fail", "core_data/posture_findings.json", (json) => json.failing, "envelope"],
      ["posture_findings_pass", "core_data/posture_findings.json", (json) => json.passing, "envelope"],
    ],
  },
  { route: "GET /api/v1/monitor", datasets: [["monitors", "core_data/monitors.json", (json) => json, "array"]] },
  {
    route: "GET /api/v2/audit/events",
    datasets: [
      ["audit_events_oldest", "core_data/audit_events.json", (json) => json.oldest, "array"],
      ["audit_events_recent", "core_data/audit_events.json", (json) => json.recent, "array"],
    ],
  },
  { route: "GET /api/v1/logs/config/pipelines", datasets: [["log_pipelines", "core_data/log_pipelines.json", (json) => json, "array"]] },
  { route: "GET /api/v1/logs/config/indexes", datasets: [["log_indexes", "core_data/log_indexes.json", (json) => json, "array"]] },
  { route: "GET /api/v2/logs/config/archives", datasets: [["log_archives", "core_data/log_archives.json", (json) => json, "array"]] },
  { route: "GET /api/v2/org_connections", datasets: [["org_connections", "core_data/org_connections.json", (json) => json, "array"]] },
];

function isEmptyReadShape(value, shape) {
  if (shape === "array") return Array.isArray(value) && value.length === 0;
  return !Array.isArray(value) && value !== null && typeof value === "object" && Array.isArray(value.data) && value.data.length === 0 && value.collected === undefined;
}

test("addendum 5: under each single-inventory denial the denied dataset's core_data file is a not-collected marker while readable-but-empty datasets stay []", async () => {
  for (const denial of DD_CORE_DATA_DATASETS) {
    const routes = routesFromClient(emptyClient());
    routes[denial.route] = jsonForbiddenWithUrl();
    const log = [];
    const { client, config } = httpClient(routes, log);
    const result = await exportDatadogAuditBundle(client, config, createTempBase("grclanker-datadog-marker-"), { now: NOW });
    const files = readBundleFiles(result.outputDir);
    const label = `${denial.route} denied`;

    for (const [inventory, file, select] of denial.datasets) {
      const marker = select(JSON.parse(files.get(file)));
      assert.ok(!Array.isArray(marker), `${label}: ${inventory} must be a marker object, never []`);
      assert.equal(marker.collected, false, `${label}: ${inventory} marker carries collected: false`);
      assert.equal(marker.status, 403, `${label}: ${inventory} marker carries the observed HTTP status`);
      assert.equal(marker.endpoint.split(/[ ?]/).slice(0, 2).join(" "), denial.route, `${label}: ${inventory} marker names the endpoint that was requested`);
      assert.equal(marker.reason, "not_readable");
      assert.match(marker.error, /Datadog request failed \(403 Forbidden\)/);
      assert.match(marker.error, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/, `${label}: the marker error is scrubbed`);
      assert.equal(typeof marker.permission, "string");

      const row = JSON.parse(files.get("core_data/collection_status.json")).inventories.find((item) => item.inventory === inventory);
      assert.deepEqual(
        { status: row.status, collected: row.collected, http_status: row.http_status, complete: row.complete, truncated: row.truncated, seen: row.seen, total: row.total, truncation_reason: row.truncation_reason },
        { status: "forbidden", collected: false, http_status: 403, complete: null, truncated: null, seen: null, total: null, truncation_reason: null },
        `${label}: collection_status row for ${inventory}`,
      );
    }
    for (const other of DD_CORE_DATA_DATASETS) {
      if (other === denial) continue;
      for (const [inventory, file, select, shape] of other.datasets) {
        const value = select(JSON.parse(files.get(file)));
        assert.ok(isEmptyReadShape(value, shape), `${label}: readable-but-empty ${inventory} stays ${shape === "array" ? "[]" : "{ data: [] }"}, got ${JSON.stringify(value)}`);
      }
    }
    if (denial.route === "GET /api/v2/roles") {
      // No per-role permission request can be made without the role list, so that dataset is marked not attempted
      // and names no endpoint or status.
      const permissions = JSON.parse(files.get("core_data/roles.json")).permissions_by_role;
      assert.deepEqual(
        { collected: permissions.collected, status: permissions.status, endpoint: permissions.endpoint, reason: permissions.reason },
        { collected: false, status: "not-collected", endpoint: null, reason: "not_attempted" },
      );
    }

    const status = JSON.parse(files.get("core_data/collection_status.json"));
    assert.equal(status.totals.forbidden, denial.datasets.length, `${label}: totals count the denied inventories as forbidden`);
    assert.equal(status.totals.truncation_unknown, denial.datasets.length, `${label}: a denied inventory is neither complete nor truncated`);
    assert.equal(status.totals.readable + status.totals.forbidden, status.totals.inventories);
    assert.match(files.get("_errors.log"), new RegExp(`^${denial.datasets[0][0]}: Datadog request failed \\(403 Forbidden\\)`, "m"));
    assertSecretsAbsent(assert, files, ddCanaryValues(), `marker bundle for ${label}`);
    assertOutputMatchesRequestLog([...files], log, label);
  }
});

// ---------------------------------------------------------------------------------------------------------------
// Addendum 3: single-inventory denial sweep over every finding, assessment summary, and tool payload.
// ---------------------------------------------------------------------------------------------------------------

/** Names that only ever appear in one fixture inventory; the all-readable baseline names each one, so its absence under that inventory's denial proves gating. */
const DD_PRINCIPAL_CANARIES = {
  getOrganization: ["canary-autocreate.example"],
  listOrgConfigs: ["canary_session_pref"],
  listOrgConnections: ["sink-canary-org"],
  listUsers: ["usr-canary-nomfa", "usr-canary-idle", "svc-canary-interactive"],
  listRoles: ["Role Canary Broad"],
  listApiKeys: ["apikey-canary-stale"],
  listApplicationKeys: ["appkey-canary-stale"],
  listSecurityRules: ["Rule canary-disabled-default"],
  listSecuritySignals: ["sig-canary-overdue"],
  getIpAllowlist: ["198.51.100.77/32"],
  getSensitiveDataScannerConfig: ["Canary Scanner Rule"],
  listLogIndexes: ["canary-short-index", "drop canary cloudtrail"],
  listLogArchives: ["canary-archive-failing"],
  listDashboards: ["Dashboard Canary Public"],
  listMonitors: ["Security canary silent"],
  listAwsIntegrations: ["999988887777"],
};

function principalClient(overrides = {}) {
  const base = healthyClient();
  const organization = healthyOrganization();
  organization.settings.saml_autocreate_users_domains = { enabled: true, domains: ["canary-autocreate.example"] };
  const scanner = healthySensitiveDataScanner();
  scanner.included.push({
    id: "rule-canary",
    type: "sensitive_data_scanner_rule",
    attributes: { name: "Canary Scanner Rule", is_enabled: true, tags: ["pii"] },
    relationships: { standard_pattern: { data: { id: "std-2", type: "sensitive_data_scanner_standard_pattern" } } },
  });
  return healthyClient({
    async getOrganization() {
      return organization;
    },
    async listOrgConfigs() {
      return [...(await base.listOrgConfigs()), { id: "canary_session_pref", type: "org_configs", attributes: { name: "canary_session_pref", value: "1" } }];
    },
    async listOrgConnections() {
      return [{ id: "c-canary", type: "org_connection", attributes: { connection_types: ["logs"] }, relationships: { sink_org: { data: { id: "sink-canary-org", type: "orgs" } } } }];
    },
    async listUsers() {
      return [
        ...(await base.listUsers()),
        user("usr-canary-nomfa", { mfa_enabled: false }),
        user("usr-canary-idle", { last_login_time: daysAgo(200) }),
        user("svc-canary-interactive", { service_account: true, last_login_time: daysAgo(1) }),
      ];
    },
    async listRoles() {
      return [...(await base.listRoles()), role("role-canary-broad", "Role Canary Broad", 1)];
    },
    async listRolePermissions(roleId) {
      return roleId === "role-canary-broad"
        ? [{ id: "perm-9", type: "permissions", attributes: { name: "user_access_manage" } }]
        : base.listRolePermissions(roleId);
    },
    async listApiKeys() {
      return [...(await base.listApiKeys()), { id: "key-canary", type: "api_keys", attributes: { name: "apikey-canary-stale", last4: "9999", created_at: daysAgo(400), date_last_used: daysAgo(300) } }];
    },
    async listApplicationKeys() {
      const keys = healthyApplicationKeys();
      keys.data.push({
        id: "ak-canary",
        type: "application_keys",
        attributes: { name: "appkey-canary-stale", last4: "8888", created_at: daysAgo(400), last_used_at: daysAgo(1), scopes: ["dashboards_read"] },
        relationships: { owned_by: { data: { id: "svc-terraform", type: "users" } } },
      });
      return keys;
    },
    async listSecurityRules() {
      return [...(await base.listSecurityRules()), detectionRule("canary-disabled", ["tactic:TA0006-credential-access"], { name: "Rule canary-disabled-default", isEnabled: false })];
    },
    async listSecuritySignals() {
      return [{ id: "sig-canary-overdue", type: "signal", attributes: { timestamp: hoursAgo(80), message: "Canary brute force", attributes: { status: "critical", workflow: { triage: { state: "open" } } } } }];
    },
    async getIpAllowlist() {
      const allowlist = await base.getIpAllowlist();
      allowlist.data.attributes.entries.push({ data: { type: "ip_allowlist_entry", id: "e-canary", attributes: { cidr_block: "198.51.100.77/32", note: "canary" } } });
      return allowlist;
    },
    async getSensitiveDataScannerConfig() {
      return scanner;
    },
    async listLogIndexes() {
      return [
        ...(await base.listLogIndexes()),
        { name: "canary-short-index", num_retention_days: 3, exclusion_filters: [{ name: "drop canary cloudtrail", is_enabled: true, filter: { query: "source:cloudtrail", sample_rate: 1 } }] },
      ];
    },
    async listLogArchives() {
      return [...(await base.listLogArchives()), { id: "a-canary", type: "archives", attributes: { name: "canary-archive-failing", state: "FAILING", destination: { type: "s3" } } }];
    },
    async listDashboards() {
      return [{ id: "dash-canary", title: "Dashboard Canary Public" }];
    },
    async listMonitors() {
      return [...(await base.listMonitors()), { id: 77, name: "Security canary silent", tags: ["team:security"], priority: 1, message: "no handles" }];
    },
    async listAwsIntegrations() {
      return [...(await base.listAwsIntegrations()), { account_id: "999988887777", access_key_id: "AKIACANARY0000000000", cspm_resource_collection_enabled: false }];
    },
    ...overrides,
  });
}

/** One entry per client read; `controls` are the findings that read the inventory and therefore may not pass while it is denied. */
const DD_SINGLE_INVENTORY_DENIALS = [
  { method: "getOrganization", inventory: "organization", path: "/api/v1/org", controls: ["DD-01", "DD-02", "DD-14", "DD-20"] },
  { method: "listOrgConfigs", inventory: "org_configs", path: "/api/v2/org_configs", controls: ["DD-16"] },
  { method: "listOrgConnections", inventory: "org_connections", path: "/api/v2/org_connections", controls: ["DD-20"] },
  { method: "listUsers", inventory: "users", path: "/api/v2/users", controls: ["DD-02", "DD-04", "DD-19"] },
  { method: "listRoles", inventory: "roles", path: "/api/v2/roles", controls: ["DD-03"] },
  { method: "listRolePermissions", inventory: "role_permissions", path: "/api/v2/roles/role-auditor/permissions", controls: ["DD-03"] },
  { method: "listApiKeys", inventory: "api_keys", path: "/api/v2/api_keys", controls: ["DD-05"] },
  { method: "listApplicationKeys", inventory: "application_keys", path: "/api/v2/application_keys", controls: ["DD-06", "DD-19"] },
  { method: "listAuditEvents", inventory: "audit_events", path: "/api/v2/audit/events", controls: ["DD-07"] },
  { method: "listSecurityRules", inventory: "security_rules", path: "/api/v2/security_monitoring/rules", controls: ["DD-08", "DD-09", "DD-12", "DD-13"] },
  { method: "listSecuritySignals", inventory: "security_signals", path: "/api/v2/security_monitoring/signals", controls: ["DD-09"] },
  { method: "listPostureFindings", inventory: "posture_findings", path: "/api/v2/posture_management/findings", controls: ["DD-12"] },
  { method: "getIpAllowlist", inventory: "ip_allowlist", path: "/api/v2/ip_allowlist", controls: ["DD-15"] },
  { method: "getSensitiveDataScannerConfig", inventory: "sensitive_data_scanner", path: "/api/v2/sensitive-data-scanner/config", controls: ["DD-11"] },
  { method: "listLogPipelines", inventory: "log_pipelines", path: "/api/v1/logs/config/pipelines", controls: ["DD-10"] },
  { method: "listLogIndexes", inventory: "log_indexes", path: "/api/v1/logs/config/indexes", controls: ["DD-10", "DD-20"] },
  { method: "listLogArchives", inventory: "log_archives", path: "/api/v2/logs/config/archives", controls: ["DD-10"] },
  { method: "listDashboards", inventory: "shared_dashboards", path: "/api/v1/dashboard", controls: ["DD-14"] },
  { method: "listMonitors", inventory: "monitors", path: "/api/v1/monitor", controls: ["DD-17"] },
  { method: "listAwsIntegrations", inventory: "aws_integrations", path: "/api/v1/integration/aws", controls: ["DD-12", "DD-18"] },
  { method: "listGcpIntegrations", inventory: "gcp_integrations", path: "/api/v1/integration/gcp", controls: ["DD-12", "DD-18"] },
  { method: "listAzureIntegrations", inventory: "azure_integrations", path: "/api/v1/integration/azure", controls: ["DD-12", "DD-18"] },
];

/** Every leaf of a JSON value with its dotted path; empty arrays and objects are leaves so a `[]` fallback is visible. */
function leafEntries(value, path = "", output = []) {
  if (Array.isArray(value)) {
    if (value.length === 0) output.push([path, "[]"]);
    value.forEach((entry, index) => leafEntries(entry, path ? `${path}.${index}` : String(index), output));
  } else if (value !== null && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 0) output.push([path, "{}"]);
    for (const key of keys) leafEntries(value[key], path ? `${path}.${key}` : key, output);
  } else {
    output.push([path, value]);
  }
  return output;
}

function pluckPath(value, path) {
  return path.split(".").reduce((cursor, key) => (cursor === null || cursor === undefined ? undefined : cursor[key]), value);
}

const DD_FALLBACK_VALUES = new Set([0, false, "none", "[]", "{}"]);

/** Fields that describe the read itself (readable flags, inventory states, gaps, caveats, status counts) and legitimately flip under a denial. */
const DD_READ_STATE_PATHS = [/(^|\.)[a-z_]*readable(\.|$)/, /^inventor(y|ies)(\.|$)/, /^unreadable_inventories(\.|$)/, /^manual_evidence(\.|$)/, /^verdict_caveats(\.|$)/, /^users_complete$/, /^(pass|warn|fail|manual)$/];

/** True when a denied-run value is a zero, false, or empty fallback where the all-readable baseline held real data. */
function isFallback(path, value, baselineValue) {
  if (!DD_FALLBACK_VALUES.has(value)) return false;
  if (baselineValue === undefined || baselineValue === null || DD_FALLBACK_VALUES.has(baselineValue)) return false;
  if (Array.isArray(baselineValue) && baselineValue.length === 0) return false;
  if (typeof baselineValue === "object" && !Array.isArray(baselineValue) && Object.keys(baselineValue).length === 0) return false;
  return !DD_READ_STATE_PATHS.some((pattern) => pattern.test(path));
}

test("addendum 3: under every single-inventory denial no Datadog finding, summary, or tool payload falls back to a zero, false, or empty value, and no principal is named from the denied inventory", async () => {
  const baseline = await runAllAssessments(principalClient());
  const baselineText = JSON.stringify(baseline);
  for (const [method, canaries] of Object.entries(DD_PRINCIPAL_CANARIES)) {
    for (const canary of canaries) assert.ok(baselineText.includes(canary), `${canary} (${method}) must be named by the all-readable baseline for its gating check to mean anything`);
  }

  const offenders = [];
  let comparedLeaves = 0;
  for (const denial of DD_SINGLE_INVENTORY_DENIALS) {
    const denied = await runAllAssessments(principalClient({
      async [denial.method]() {
        throw forbidden(denial.path);
      },
    }));
    const label = `${denial.inventory} denied`;
    const deniedText = JSON.stringify(denied);
    for (const canary of DD_PRINCIPAL_CANARIES[denial.method] ?? []) {
      assert.ok(!deniedText.includes(canary), `${label}: ${canary} is still named from the denied inventory`);
    }
    for (const control of denial.controls) {
      const item = denied.flatMap((result) => result.findings).find((candidate) => candidate.id === control);
      assert.notEqual(item.status, "pass", `${label}: ${control} must not pass (${item.summary})`);
      assert.match(item.summary, /403 Forbidden/, `${label}: ${control} carries the observed error (${item.summary})`);
    }
    for (const [areaIndex, result] of denied.entries()) {
      const baselineResult = baseline[areaIndex];
      for (const [path, value] of leafEntries(result.summary)) {
        comparedLeaves += 1;
        const baselineValue = pluckPath(baselineResult.summary, path);
        if (isFallback(path, value, baselineValue)) offenders.push(`${label}: ${result.category} summary.${path} = ${JSON.stringify(value)} (baseline ${JSON.stringify(baselineValue)})`);
      }
      for (const item of result.findings) {
        const baselineFinding = findingById(baselineResult, item.id);
        for (const [path, value] of leafEntries(item.evidence ?? {})) {
          comparedLeaves += 1;
          const baselineValue = pluckPath(baselineFinding.evidence ?? {}, path);
          if (isFallback(path, value, baselineValue)) offenders.push(`${label}: ${item.id} evidence.${path} = ${JSON.stringify(value)} (baseline ${JSON.stringify(baselineValue)})`);
        }
      }
    }
  }
  assert.ok(comparedLeaves > 3000, `expected the sweep to compare thousands of leaves, got ${comparedLeaves}`);
  assert.deepEqual(offenders, [], `values that fell back to zero, false, or empty under a denial:\n${offenders.join("\n")}`);
});

// ---------------------------------------------------------------------------------------------------------------
// Addendum 4: every surface fails in turn with a 502 HTML page and a JSON error carrying canaries.
// ---------------------------------------------------------------------------------------------------------------

/** Every error string a Datadog run can record, gathered from the access check, the assess payloads, and the bundle. */
function ddRecordedErrorStrings(access, assessments, files) {
  const strings = [];
  for (const surface of access.surfaces) if (typeof surface.error === "string") strings.push(surface.error);
  strings.push(...access.notes);
  for (const assessment of assessments) {
    strings.push(...(assessment.errors ?? []));
    for (const finding of assessment.findings) {
      strings.push(finding.summary);
      for (const [, value] of leafEntries(finding.evidence ?? {})) if (typeof value === "string") strings.push(value);
    }
  }
  const errorsLog = files.get("_errors.log");
  if (errorsLog) strings.push(...errorsLog.split("\n"));
  return strings;
}

test("addendum 4: a 502 HTML page or a JSON error message carrying credentials on any Datadog surface never reaches the access check, an assess payload, or the bundle, and every recorded error carries the status-and-length note", async () => {
  const surfaces = Object.keys(routesFromClient(leakyClient()));
  assert.ok(surfaces.length >= 24, `expected every collector and access probe route, got ${surfaces.length}`);
  const variants = [
    { name: "html502", handler: htmlGateway, note: /502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/ },
    { name: "json403", handler: jsonForbiddenWithUrl, note: /\(403 Forbidden\)/ },
  ];
  let notedSurfaces = 0;
  for (const surface of surfaces) {
    for (const variant of variants) {
      const routes = routesFromClient(leakyClient());
      routes[surface] = variant.handler();
      const { client, config } = httpClient(routes, []);
      const label = `${surface} ${variant.name}`;
      const secrets = [...ddCanaryValues(), ...DATADOG_FAKE_SECRETS, config.apiKey, config.appKey];

      const access = await checkDatadogAccess(client);
      const assessments = await runAllAssessments(client);
      const result = await exportDatadogAuditBundle(client, config, createTempBase("grclanker-datadog-surface-canary-"), { now: NOW });
      const files = readBundleFiles(result.outputDir);
      const entries = readZipEntries(result.zipPath);

      assertSecretsAbsent(assert, files, secrets, `${label} bundle file`);
      assertSecretsAbsent(assert, entries, secrets, `${label} zip entry`);
      assertSecretsAbsent(assert, new Map([["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), secrets, `${label} tool payload`);

      const [method, path] = surface.split(" ");
      const aboutSurface = ddRecordedErrorStrings(access, assessments, files).filter((text) => text.includes(`${method} ${path}`) && /request failed|timed out/.test(text));
      if (aboutSurface.length === 0) continue;
      notedSurfaces += 1;
      for (const text of aboutSurface) {
        assert.match(text, variant.note, `${label}: error string lacks the status note: ${text}`);
        assert.ok(!/<html|Bad Gateway<\/|upstream sent/.test(text), `${label}: error string echoes the body: ${text}`);
        if (variant.name === "json403") assert.ok(!text.includes(`token=${DD_CANARIES.urlToken}`), `${label}: URL token survives in ${text}`);
      }
    }
  }
  assert.ok(notedSurfaces >= surfaces.length, `every surface should record its failure at least once across the variants, got ${notedSurfaces} of ${surfaces.length * variants.length}`);
});

// ---------------------------------------------------------------------------------------------------------------
// Addendum 6: config loader errors never quote the file.
// ---------------------------------------------------------------------------------------------------------------

const DOGRC_CANARY = "DOGRC_CANARY_7d8e9f0a1b2c3d4e";

/** Malformed dogshell INI shapes with the canary on the bad line; the parser skips or keeps the line but never quotes it. */
const MALFORMED_DOGRC_FILES = [
  { name: "unterminated quote", content: `[Connection]\napikey = "${DOGRC_CANARY}\nappkey = app-key-0123456789\n` },
  { name: "bad indent", content: `[Connection]\n    apikey = ${DOGRC_CANARY}\n\tappkey = app-key-0123456789\n` },
  { name: "duplicate key", content: `[Connection]\napikey = first-key-0123456789\napikey = ${DOGRC_CANARY}\nappkey = app-key-0123456789\n` },
  { name: "trailing comma", content: `[Connection]\napikey = ${DOGRC_CANARY},\nappkey = app-key-0123456789,\n` },
  { name: "missing separator", content: `[Connection]\napikey ${DOGRC_CANARY}\nappkey app-key-0123456789\n` },
  { name: "unterminated section header", content: `[Connection\napikey = ${DOGRC_CANARY}\nappkey = app-key-0123456789\n` },
];

test("rule 9 / addendum 6: a malformed .dogrc whose bad line carries a credential never reaches the resolver error, the check_access payload, or a bundle, and a filesystem failure names only the path and errno code", async () => {
  const registered = [];
  registerDatadogTools({ registerTool: (tool) => registered.push(tool) });
  const checkTool = registered.find((tool) => tool.name === "datadog_check_access");
  const exportTool = registered.find((tool) => tool.name === "datadog_export_audit_bundle");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new TypeError("fetch failed"); };
  try {
    for (const shape of MALFORMED_DOGRC_FILES) {
      const base = createTempBase("grclanker-dogrc-malformed-");
      const configPath = join(base, "dogrc");
      writeFileSync(configPath, shape.content, "utf8");
      const outputDir = join(base, "export");

      let resolverMessage;
      try {
        resolveDatadogConfiguration({ config_file: configPath }, {}, base);
      } catch (error) {
        resolverMessage = error.message;
      }
      if (resolverMessage !== undefined) {
        assert.match(resolverMessage, /DD_API_KEY|DD_APP_KEY/, `${shape.name}: a skipped line surfaces as the missing-key message`);
        assert.ok(!resolverMessage.includes(DOGRC_CANARY), `${shape.name}: the resolver message quotes the credential: ${resolverMessage}`);
      }

      const access = await checkTool.execute("call-dogrc", checkTool.prepareArguments({ config_file: configPath }));
      assert.ok(!JSON.stringify(access).includes(DOGRC_CANARY), `${shape.name}: the check_access payload quotes the credential: ${access.content[0].text}`);
      // The export records unreachable surfaces as collection errors rather than failing, so whatever it wrote is scanned.
      const exported = await exportTool.execute("call-dogrc-export", exportTool.prepareArguments({ config_file: configPath, output_dir: outputDir }));
      assert.ok(!JSON.stringify(exported).includes(DOGRC_CANARY), `${shape.name}: the export payload quotes the credential`);
      if (existsSync(outputDir)) {
        for (const entry of readdirSync(outputDir)) {
          if (entry.endsWith(".zip")) continue;
          assertSecretsAbsent(assert, readBundleFiles(join(outputDir, entry)), [DOGRC_CANARY], `${shape.name} bundle file`);
        }
      }
    }

    const directoryAsFile = createTempBase("grclanker-dogrc-dir-");
    let fsError;
    try {
      resolveDatadogConfiguration({ config_file: directoryAsFile }, {}, directoryAsFile);
    } catch (error) {
      fsError = error;
    }
    assert.equal(fsError.name, "DatadogConfigFileError");
    assert.equal(fsError.code, "EISDIR");
    assert.equal(fsError.message, `Unable to read Datadog config file ${directoryAsFile} (EISDIR)`);
    const access = await checkTool.execute("call-dogrc-dir", checkTool.prepareArguments({ config_file: directoryAsFile }));
    assert.equal(access.isError, true);
    assert.equal(access.content[0].text, `Datadog access check failed: Unable to read Datadog config file ${directoryAsFile} (EISDIR)`);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ---------------------------------------------------------------------------------------------------------------
// Addendum 6b: the .dogrc loader takes the read-failure rule (fixed text, validated errno code) and the
// catch-everything rule; the dogshell INI parser has no structured position, so no line is ever reported.
// ---------------------------------------------------------------------------------------------------------------

const DOGRC_READ_CANARY = "CFGD5w6x7y8z9a0b1c2";
const FS_WORDING = ["illegal operation", "permission denied", "no such file", "Nested mappings", "is not valid JSON", "Unresolved alias"];

function eightCharacterWindows(text) {
  const windows = [];
  for (let index = 0; index + 8 <= text.length; index += 1) windows.push(text.slice(index, index + 8));
  return windows;
}

/** Asserts a message carries neither the canary, nor any 8-character fragment of it, nor the filesystem's own wording. */
function assertFixedTextOnly(message, label) {
  assert.ok(!message.includes(DOGRC_READ_CANARY), `${label}: carries the canary: ${message}`);
  for (const fragment of eightCharacterWindows(DOGRC_READ_CANARY)) assert.ok(!message.includes(fragment), `${label}: carries the fragment ${fragment}: ${message}`);
  for (const wording of FS_WORDING) assert.ok(!message.includes(wording), `${label}: carries library wording "${wording}": ${message}`);
}

test("config loader errors: a .dogrc that cannot be read yields fixed text with only the path and a validated errno code, from the resolver and from check_access, and an explicit missing path is an error", async () => {
  assert.equal(new Set(eightCharacterWindows(DOGRC_READ_CANARY)).size, eightCharacterWindows(DOGRC_READ_CANARY).length, "canary windows are distinct");
  const registered = [];
  registerDatadogTools({ registerTool: (tool) => registered.push(tool) });
  const checkTool = registered.find((tool) => tool.name === "datadog_check_access");
  const exportTool = registered.find((tool) => tool.name === "datadog_export_audit_bundle");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("no request may be made while the config file is unreadable"); };
  try {
    const base = createTempBase("grclanker-dogrc-read-errors-");
    const cases = [];

    // EISDIR: a directory at the path is a read failure with the filesystem's wording withheld.
    const directory = join(base, "dogrc-dir");
    mkdirSync(directory);
    assert.throws(() => readFileSync(directory, "utf8"), (error) => error.code === "EISDIR" && /illegal operation/.test(error.message), "positive control: the filesystem message carries its own wording");
    cases.push({ name: "EISDIR", path: directory, code: "EISDIR", message: `Unable to read Datadog config file ${directory} (EISDIR)` });

    // EACCES: an unreadable file whose contents carry the canary (root reads everything, so skipped as root).
    if (typeof process.getuid === "function" && process.getuid() !== 0) {
      const unreadable = join(base, "unreadable.dogrc");
      writeFileSync(unreadable, `[Connection]\napikey = ${DOGRC_READ_CANARY}\n`, "utf8");
      chmodSync(unreadable, 0o000);
      assert.throws(() => readFileSync(unreadable, "utf8"), (error) => error.code === "EACCES" && /permission denied/.test(error.message), "positive control");
      cases.push({ name: "EACCES", path: unreadable, code: "EACCES", message: `Unable to read Datadog config file ${unreadable} (EACCES)` });
    }

    // ENOENT on an explicit path: a missing file named by argument or environment is an error, not a silent default.
    const missing = join(base, "missing.dogrc");
    cases.push({ name: "ENOENT", path: missing, code: "ENOENT", message: `Unable to read Datadog config file ${missing} (ENOENT)` });

    for (const item of cases) {
      let thrown;
      try {
        resolveDatadogConfiguration({ config_file: item.path }, {}, base);
      } catch (error) {
        thrown = error;
      }
      assert.ok(thrown, `${item.name}: the resolver must reject the file`);
      assert.equal(thrown.name, "DatadogConfigFileError", item.name);
      assert.equal(thrown.message, item.message, `${item.name}: fixed text only`);
      assert.equal(thrown.code, item.code, item.name);
      assert.equal(thrown.line, undefined, item.name);
      assert.equal(thrown.path, item.path, item.name);
      assertFixedTextOnly(thrown.message, `${item.name} resolver`);

      const access = await checkTool.execute("call-dogrc-read", checkTool.prepareArguments({ config_file: item.path }));
      assert.equal(access.isError, true, item.name);
      assert.equal(access.content[0].text, `Datadog access check failed: ${item.message}`, item.name);
      assertFixedTextOnly(JSON.stringify(access), `${item.name} check_access`);

      const outputDir = join(base, `export-${item.code}`);
      const exported = await exportTool.execute("call-dogrc-read-export", exportTool.prepareArguments({ config_file: item.path, output_dir: outputDir }));
      assert.equal(exported.isError, true, item.name);
      assert.equal(exported.content[0].text, `Datadog audit bundle export failed: ${item.message}`, item.name);
      assert.equal(existsSync(outputDir), false, `${item.name}: nothing is written when the config file is unreadable`);
    }

    // The environment variables are explicit paths too, and a missing default ~/.dogrc is still simply absent.
    for (const variable of ["DD_CONFIG_FILE", "DATADOG_CONFIG_FILE"]) {
      assert.throws(
        () => resolveDatadogConfiguration({ api_key: "k".repeat(32), app_key: "a".repeat(40) }, { [variable]: missing }, base),
        { message: `Unable to read Datadog config file ${missing} (ENOENT)` },
        variable,
      );
    }
    assert.equal(resolveDatadogConfiguration({ api_key: "k".repeat(32), app_key: "a".repeat(40) }, {}, base).apiKey, "k".repeat(32));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
