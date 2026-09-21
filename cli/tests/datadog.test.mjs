import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
