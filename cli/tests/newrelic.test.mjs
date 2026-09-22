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
import { join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";

import {
  API_KEY_DOCUMENTED_ONLY_NOTE,
  NEWRELIC_CLIENT_SURFACE_METHODS,
  NEWRELIC_CONTROL_CATALOG,
  NEWRELIC_NERDGRAPH_SELECTIONS,
  NEWRELIC_STORED_RECORD_SHAPES,
  NewrelicApiClient,
  NewrelicNoAccountsError,
  assessNewrelicAccessControl,
  assessNewrelicAlerting,
  assessNewrelicDataGovernance,
  assessNewrelicIdentity,
  checkNewrelicAccess,
  compactCause,
  exportNewrelicAuditBundle,
  projectRecord,
  resolveNewrelicConfiguration,
  resolveSecureOutputPath,
  scrubErrorText,
} from "../dist/extensions/grc-tools/newrelic.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const TEST_KEY = "NRAK-TESTKEY1234567890ABCDEF";
const NOW = Date.UTC(2026, 8, 21, 12, 0, 0);
const DAY_SECONDS = 86_400;

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function secondsAgo(days) {
  return Math.floor(NOW / 1000) - days * DAY_SECONDS;
}

function sampleConfig(overrides = {}) {
  return {
    apiKey: TEST_KEY,
    accountIds: [111, 222],
    region: "US",
    nerdgraphUrl: "https://api.newrelic.com/graphql",
    restBaseUrl: "https://api.newrelic.com",
    timeoutMs: 30_000,
    auditWindowDays: 30,
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

function findingStatus(result, id) {
  return result.findings.find((item) => item.id === id)?.status;
}

function findingById(result, id) {
  return result.findings.find((item) => item.id === id);
}

function user(id, options = {}) {
  return {
    id,
    email: options.email ?? `${id}@example.com`,
    name: options.name ?? id,
    lastActive: options.lastActive === null ? null : secondsAgo(options.lastActiveDaysAgo ?? 3),
    type: { id: options.type ?? "BASIC", displayName: options.type ?? "Basic" },
    groups: { groups: (options.groups ?? []).map((groupId) => ({ id: groupId, displayName: groupId })) },
  };
}

function orgManagerGroup(id = "g-admin") {
  return {
    id,
    displayName: "Organization admins",
    roles: [
      { id: "grant-1", name: "Organization manager", displayName: "Organization manager", type: "STANDARD", organizationId: "org-1" },
    ],
  };
}

function accountGroup(id, accountIds, roleName = "Read only", roleType = "STANDARD") {
  return {
    id,
    displayName: id,
    roles: accountIds.map((accountId) => ({
      id: `grant-${id}-${accountId}`,
      name: roleName,
      displayName: roleName,
      type: roleType,
      accountId,
    })),
  };
}

function standardRoles() {
  return [
    { id: "1", name: "Organization manager", scope: "organization", type: "STANDARD" },
    { id: "2", name: "Read only", scope: "account", type: "STANDARD" },
  ];
}

function requireOrganizationId(organizationId) {
  assert.equal(organizationId, "org-1", "listRoles must be filtered by the organization id from actor.organization");
}

function identityClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getOrganization() {
      return { id: "org-1", name: "Example Org" };
    },
    async listAuthenticationDomains() {
      return [{ id: "domain-1", name: "Corporate SSO", provisioningType: "SCIM" }];
    },
    async listOrganizationAuthenticationDomains() {
      return [{ id: "domain-1", name: "Corporate SSO", organizationId: "org-1", provisioningType: "SCIM", authenticationType: "SAML_SSO" }];
    },
    async listDomainUsers() {
      return [
        user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }),
        user("bob", { type: "BASIC", groups: ["g-dev"] }),
        user("carol", { type: "CORE", groups: ["g-dev"] }),
      ];
    },
    async listDomainGroupGrants() {
      return [orgManagerGroup(), accountGroup("g-dev", [222])];
    },
    async listRoles(organizationId) {
      requireOrganizationId(organizationId);
      return standardRoles();
    },
    ...overrides,
  };
}

function accessControlClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getOrganization() {
      return { id: "org-1", name: "Example Org" };
    },
    async resolveAccountIds() {
      return [111, 222];
    },
    async listAccounts() {
      return [{ id: 111, name: "Payments Production" }, { id: 222, name: "Payments Development" }];
    },
    async listAuthenticationDomains() {
      return [{ id: "domain-1", name: "Corporate SSO", provisioningType: "SCIM" }];
    },
    async listDomainUsers() {
      return [
        user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }),
        user("bob", { type: "BASIC", groups: ["g-dev"] }),
      ];
    },
    async listDomainGroupGrants() {
      return [orgManagerGroup(), accountGroup("g-dev", [222])];
    },
    async listRoles(organizationId) {
      requireOrganizationId(organizationId);
      return standardRoles();
    },
    async listApiKeys() {
      return [
        { id: "key-1", name: "ci-deploy", type: "USER", createdAt: secondsAgo(10), userId: "bob", accountId: 111 },
        { id: "key-2", name: "license-prod", type: "INGEST", ingestType: "LICENSE", createdAt: secondsAgo(20), accountId: 111 },
        { id: "key-3", name: "browser-prod", type: "INGEST", ingestType: "BROWSER", createdAt: secondsAgo(20), accountId: 111 },
      ];
    },
    async runNrql(_accountId, nrql) {
      if (nrql.includes("actorType = 'api_key'")) {
        return [{ actorAPIKey: "abc123", actorType: "api_key", actionIdentifier: "alerts.policy.create", timestamp: NOW }];
      }
      return [];
    },
    ...overrides,
  };
}

function alertingClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig({ accountIds: [111] }),
    async resolveAccountIds() {
      return [111];
    },
    async getCurrentUser() {
      return { id: "u-1", email: "auditor@example.com", name: "Auditor" };
    },
    async listAlertPolicies() {
      return [{ id: "policy-1", name: "Production", incidentPreference: "PER_CONDITION_AND_TARGET", accountId: 111 }];
    },
    async listNrqlConditions() {
      return [{ id: "cond-1", name: "Error rate", type: "STATIC", enabled: true, policyId: "policy-1", nrql: { query: "SELECT count(*) FROM TransactionError" } }];
    },
    async listNotificationDestinations() {
      return [
        {
          id: "dest-1",
          name: "Ops distribution list",
          type: "EMAIL",
          properties: [{ key: "email", value: "ops@example.com" }],
        },
      ];
    },
    async listNotificationChannels() {
      return [{ id: "chan-1", name: "Ops email", type: "EMAIL", destinationId: "dest-1" }];
    },
    async listWorkflows() {
      return [
        {
          id: "wf-1",
          name: "Production issues",
          workflowEnabled: true,
          enrichmentsEnabled: false,
          destinationsEnabled: true,
          destinationConfigurations: [{ channelId: "chan-1", name: "Ops email", type: "EMAIL" }],
          enrichments: [],
        },
      ];
    },
    async searchEntities(query) {
      if (query.includes("WORKLOAD")) {
        return [{ guid: "wl-1", name: "Checkout", domain: "NR1", type: "WORKLOAD", workloadStatus: { statusValue: "OPERATIONAL" } }];
      }
      return [
        { guid: "app-1", name: "checkout-api", domain: "APM", type: "APPLICATION", entityType: "APM_APPLICATION_ENTITY", reporting: true, alertSeverity: "NOT_ALERTING" },
        { guid: "host-1", name: "ip-10-0-0-1", domain: "INFRA", type: "HOST", entityType: "INFRASTRUCTURE_HOST_ENTITY", reporting: true, alertSeverity: "WARNING" },
      ];
    },
    ...overrides,
  };
}

function dataGovernanceClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig({ accountIds: [111] }),
    async resolveAccountIds() {
      return [111];
    },
    async listEventRetentionRules() {
      return [
        { id: "rule-1", namespace: "Log", retentionInDays: 90, createdAt: secondsAgo(100), deletedAt: null },
        { id: "rule-2", namespace: "Transaction", retentionInDays: 120, createdAt: secondsAgo(100), deletedAt: null },
      ];
    },
    async listRetentionNamespaces() {
      return [{ namespace: "Log" }, { namespace: "Transaction" }];
    },
    async listObfuscationRules() {
      return [
        {
          id: "obf-1",
          name: "Mask credentials and PII",
          description: "Hash passwords, tokens, and email addresses",
          filter: "SELECT * FROM Log",
          enabled: true,
          actions: [{ attributes: ["message"], method: "HASH_SHA256", expression: { id: "expr-1", name: "password token" } }],
        },
      ];
    },
    async listObfuscationExpressions() {
      return [
        { id: "expr-1", name: "password token api_key", regex: "(password|token|api_key)=\\S+", description: "Credential values" },
        { id: "expr-2", name: "email addresses", regex: "[a-z]+@[a-z]+\\.[a-z]+", description: "PII email" },
      ];
    },
    async listPipelineCloudRules() {
      return [{ id: "rule-guid-1", name: "Drop card numbers", type: "PIPELINE_CLOUD_RULE", nrql: "DELETE cardNumber FROM Log", enabled: true }];
    },
    async listNrqlDropRules() {
      return [];
    },
    async searchEntities(query) {
      if (query.includes("DASHBOARD")) {
        return [{ guid: "dash-1", name: "Ops overview", domain: "VIZ", type: "DASHBOARD", permissions: "PUBLIC_READ_ONLY", accountId: 111 }];
      }
      if (query.includes("SECURE_CRED")) {
        return [{ guid: "cred-1", name: "LOGIN_PASSWORD", domain: "SYNTH", type: "SECURE_CRED", accountId: 111 }];
      }
      if (query.includes("MONITOR")) {
        return [{ guid: "mon-1", name: "Login flow", domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_BROWSER", accountId: 111 }];
      }
      return [];
    },
    async countEntities() {
      return 4;
    },
    async getSyntheticScript() {
      return "const password = $secure.LOGIN_PASSWORD;\n$browser.get('https://example.com/login');";
    },
    async listDashboardLiveUrls() {
      return [];
    },
    async runNrql(_accountId, nrql) {
      if (nrql.includes("RLIKE")) return [{ matchCount: 0 }];
      if (nrql.includes("FROM Log")) return [{ logCount: 12_000 }];
      if (nrql.includes("SystemSample")) return [{ agentVersion: "1.60.1", hosts: 4 }];
      return [];
    },
    ...overrides,
  };
}

function bundleClient(overrides = {}) {
  return {
    ...identityClient(),
    ...accessControlClient(),
    ...alertingClient(),
    ...dataGovernanceClient(),
    getResolvedConfig: () => sampleConfig({ accountIds: [111] }),
    async resolveAccountIds() {
      return [111];
    },
    async listAccounts() {
      return [{ id: 111, name: "Payments Production" }];
    },
    async getCurrentUser() {
      return { id: "u-1", email: "auditor@example.com", name: "Auditor" };
    },
    async runNrql(accountId, nrql) {
      if (nrql.includes("NrAuditEvent")) return accessControlClient().runNrql(accountId, nrql);
      return dataGovernanceClient().runNrql(accountId, nrql);
    },
    async searchEntities(query) {
      if (query.includes("alertSeverity") || query.includes("WORKLOAD")) return alertingClient().searchEntities(query);
      return dataGovernanceClient().searchEntities(query);
    },
    ...overrides,
  };
}

test("New Relic control catalog covers all 20 spec controls with eight framework mappings each", () => {
  assert.equal(NEWRELIC_CONTROL_CATALOG.length, 20);
  assert.deepEqual(
    NEWRELIC_CONTROL_CATALOG.map((control) => control.number),
    Array.from({ length: 20 }, (_, index) => index + 1),
  );
  for (const control of NEWRELIC_CONTROL_CATALOG) {
    assert.match(control.id, /^NR-\d{2}-[A-Z-]+$/);
    assert.equal(control.mappings.length, 8);
    for (const prefix of ["FedRAMP ", "CMMC ", "SOC 2 ", "CIS ", "PCI-DSS ", "STIG ", "IRAP ", "ISMAP "]) {
      assert.ok(control.mappings.some((mapping) => mapping.startsWith(prefix)), `${control.id} lacks ${prefix.trim()} mapping`);
    }
  }
  assert.deepEqual(
    NEWRELIC_CONTROL_CATALOG.find((control) => control.number === 1).mappings,
    ["FedRAMP IA-2", "CMMC AC.L2-3.1.1", "SOC 2 CC6.1", "CIS 1.1", "PCI-DSS 8.3.1", "STIG SRG-APP-000148", "IRAP ISM-1557", "ISMAP CPS-04"],
  );
});

test("resolveNewrelicConfiguration prefers explicit args, then env vars, then the config file", () => {
  const home = createTempBase("grclanker-newrelic-home-");
  mkdirSync(join(home, ".newrelic-sec-inspector"), { recursive: true });
  writeFileSync(
    join(home, ".newrelic-sec-inspector", "config.yaml"),
    "api_key: NRAK-FILEKEY000000000000000000\naccount_ids:\n  - 333\nregion: EU\ntimeout_seconds: 12\naudit_window_days: 45\n",
  );
  const env = { NEW_RELIC_API_KEY: "NRAK-ENVKEY0000000000000000000", NEW_RELIC_ACCOUNT_ID: "444, 555", NEW_RELIC_REGION: "eu" };

  const fromArgs = resolveNewrelicConfiguration(
    { api_key: TEST_KEY, account_id: "111,222", region: "us", timeout_seconds: 9, audit_window_days: 7 },
    env,
    home,
  );
  assert.equal(fromArgs.apiKey, TEST_KEY);
  assert.deepEqual(fromArgs.accountIds, [111, 222]);
  assert.equal(fromArgs.region, "US");
  assert.equal(fromArgs.nerdgraphUrl, "https://api.newrelic.com/graphql");
  assert.equal(fromArgs.restBaseUrl, "https://api.newrelic.com");
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.equal(fromArgs.auditWindowDays, 7);
  assert.ok(fromArgs.sourceChain.includes("arguments:api_key"));
  assert.ok(fromArgs.sourceChain.includes("arguments:account_id"));
  assert.ok(fromArgs.sourceChain.includes("arguments:region"));

  const fromEnv = resolveNewrelicConfiguration({}, env, home);
  assert.equal(fromEnv.apiKey, "NRAK-ENVKEY0000000000000000000");
  assert.deepEqual(fromEnv.accountIds, [444, 555]);
  assert.equal(fromEnv.region, "EU");
  assert.equal(fromEnv.nerdgraphUrl, "https://api.eu.newrelic.com/graphql");
  assert.equal(fromEnv.restBaseUrl, "https://api.eu.newrelic.com");
  assert.equal(fromEnv.timeoutMs, 12_000);
  assert.ok(fromEnv.sourceChain.includes("environment:NEW_RELIC_API_KEY"));
  assert.ok(fromEnv.sourceChain.includes("environment:NEW_RELIC_ACCOUNT_ID"));
  assert.ok(fromEnv.sourceChain.includes("environment:NEW_RELIC_REGION"));

  const fromFile = resolveNewrelicConfiguration({}, {}, home);
  assert.equal(fromFile.apiKey, "NRAK-FILEKEY000000000000000000");
  assert.deepEqual(fromFile.accountIds, [333]);
  assert.equal(fromFile.region, "EU");
  assert.equal(fromFile.auditWindowDays, 45);
  assert.ok(fromFile.sourceChain.some((entry) => entry.startsWith("config:")));
});

test("resolveNewrelicConfiguration honors explicit config paths, defaults to US, and rejects bad input", () => {
  const home = createTempBase("grclanker-newrelic-home-empty-");
  const configDir = createTempBase("grclanker-newrelic-config-");
  const explicitPath = join(configDir, "inspector.yaml");
  writeFileSync(explicitPath, "api_key: NRAK-EXPLICIT00000000000000000\naccount_id: 777\n");

  const explicit = resolveNewrelicConfiguration({ config_file: explicitPath }, {}, home);
  assert.equal(explicit.apiKey, "NRAK-EXPLICIT00000000000000000");
  assert.deepEqual(explicit.accountIds, [777]);
  assert.equal(explicit.region, "US");
  assert.ok(explicit.sourceChain.includes("default:region-us"));

  const viaEnvPath = resolveNewrelicConfiguration({}, { NEW_RELIC_SEC_INSPECTOR_CONFIG: explicitPath }, home);
  assert.equal(viaEnvPath.apiKey, "NRAK-EXPLICIT00000000000000000");

  const discovery = resolveNewrelicConfiguration({ api_key: TEST_KEY }, {}, home);
  assert.deepEqual(discovery.accountIds, []);
  assert.ok(discovery.sourceChain.includes("discovery:actor.accounts"));

  assert.throws(() => resolveNewrelicConfiguration({ api_key: TEST_KEY, region: "APAC" }, {}, home), /Unsupported New Relic region/);
  assert.throws(() => resolveNewrelicConfiguration({}, {}, home), /NEW_RELIC_API_KEY/);
});

test("NewrelicApiClient posts NerdGraph queries with the Api-Key header and follows nextCursor pagination", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const body = JSON.parse(init.body);
    seen.push({
      url: typeof input === "string" ? input : input.toString(),
      method: init.method,
      apiKey: headerValue(init.headers, "api-key"),
      contentType: headerValue(init.headers, "content-type"),
      body,
      signal: init.signal,
    });
    const page = body.variables.cursor
      ? { nextCursor: null, totalCount: 2, authenticationDomains: [{ id: "domain-2", name: "Contractors", provisioningType: "MANUAL" }] }
      : { nextCursor: "page-2", totalCount: 2, authenticationDomains: [{ id: "domain-1", name: "Corporate", provisioningType: "SCIM" }] };
    return jsonResponse({ data: { actor: { organization: { userManagement: { authenticationDomains: page } } } } });
  };

  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });
  const domains = await client.listAuthenticationDomains();

  assert.deepEqual(domains.items.map((domain) => domain.id), ["domain-1", "domain-2"]);
  assert.equal(domains.complete, true);
  assert.equal(domains.totalCount, 2);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].url, "https://api.newrelic.com/graphql");
  assert.equal(seen[0].method, "POST");
  assert.equal(seen[0].apiKey, TEST_KEY);
  assert.equal(seen[0].contentType, "application/json");
  assert.match(seen[0].body.query, /authenticationDomains\(cursor: \$cursor\)/);
  assert.equal(seen[0].body.variables.cursor, undefined);
  assert.equal(seen[1].body.variables.cursor, "page-2");
  assert.ok(seen[0].signal instanceof AbortSignal);
});

test("NewrelicApiClient uses the EU endpoint and account-scoped NRQL variables", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    seen.push({ url: input.toString(), body: JSON.parse(init.body) });
    return jsonResponse({ data: { actor: { account: { nrql: { results: [{ count: 3 }] } } } } });
  };
  const config = resolveNewrelicConfiguration({ api_key: TEST_KEY, account_id: "999", region: "EU" }, {}, createTempBase("grclanker-newrelic-eu-"));
  const client = new NewrelicApiClient(config, { fetchImpl });
  const rows = await client.runNrql(999, "SELECT count(*) FROM NrAuditEvent SINCE 1 day ago");

  assert.deepEqual(rows, [{ count: 3 }]);
  assert.equal(seen[0].url, "https://api.eu.newrelic.com/graphql");
  assert.deepEqual(seen[0].body.variables, { accountId: 999, nrql: "SELECT count(*) FROM NrAuditEvent SINCE 1 day ago" });
});

test("NewrelicApiClient retries 429 and 5xx responses using Retry-After and exponential backoff", async () => {
  let calls = 0;
  const sleeps = [];
  const fetchImpl = async () => {
    calls += 1;
    if (calls === 1) return new Response("rate limited", { status: 429, headers: { "retry-after": "2" } });
    if (calls === 2) return new Response("upstream unavailable", { status: 503 });
    return jsonResponse({ data: { actor: { user: { id: "u-1", email: "auditor@example.com", name: "Auditor" } } } });
  };

  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl, sleep: async (ms) => { sleeps.push(ms); } });
  const currentUser = await client.getCurrentUser();

  assert.equal(currentUser.email, "auditor@example.com");
  assert.equal(calls, 3);
  assert.deepEqual(sleeps, [2000, 1000]);
});

test("NewrelicApiClient stops retrying after the retry budget and reports the status", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return new Response("still failing", { status: 502, statusText: "Bad Gateway" });
  };
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl, sleep: async () => {}, maxRetries: 1 });

  await assert.rejects(client.getOrganization(), /NerdGraph request failed \(502 Bad Gateway\)/);
  assert.equal(calls, 2);
});

test("NewrelicApiClient redacts the API key from NerdGraph and transport errors", async () => {
  const secret = "NRAK-SUPERSECRETVALUE0000001";
  const graphqlErrors = async () => jsonResponse({
    errors: [{ message: `Not authorized to view users with key ${secret}`, path: ["actor", "user"] }],
    data: null,
  });
  const graphqlClient = new NewrelicApiClient(sampleConfig({ apiKey: secret }), { fetchImpl: graphqlErrors });
  await assert.rejects(graphqlClient.getCurrentUser(), (error) => {
    assert.match(error.message, /NerdGraph returned errors/);
    assert.match(error.message, /at actor\.user/);
    assert.doesNotMatch(error.message, /SUPERSECRETVALUE/);
    assert.match(error.message, /\[REDACTED\]/);
    return true;
  });

  const transportFailure = async () => {
    throw new Error(`connect ECONNREFUSED while sending Api-Key: ${secret}`);
  };
  const transportClient = new NewrelicApiClient(sampleConfig({ apiKey: secret }), { fetchImpl: transportFailure });
  await assert.rejects(transportClient.getCurrentUser(), (error) => {
    assert.match(error.message, /New Relic request failed/);
    assert.doesNotMatch(error.message, /SUPERSECRETVALUE/);
    return true;
  });
});

const ENTITY_GUID = Buffer.from("123456|APM|APPLICATION|1234567").toString("base64");

// Every credential shape rule 9 names, as [label, input, canary, expected output]. The expected text pins the
// rule that fires (a header keeps its name, a URL keeps its origin and path, a name-value pair keeps its name).
const SCRUB_SHAPES = [
  ["configured credential by exact match", "rejected key NRAK-SUPERSECRETVALUE0000001 for tenant 111", "SUPERSECRETVALUE", "rejected key [REDACTED] for tenant 111"],
  ["NRAK user key", "api key NRAK-CANARYAPIKEY7F3A9C1D0000000 rejected", "CANARYAPIKEY7F3A9C1D", "api key NRAK-[REDACTED] rejected"],
  ["NRII ingest license key", "ingest key NRII-CANARYINGEST7f3a9c1d rejected", "CANARYINGEST7f3a9c1d", "ingest key NRII-[REDACTED] rejected"],
  ["NRJS browser key", "browser key NRJS-canary7f3a9c1d rejected", "canary7f3a9c1d", "browser key NRJS-[REDACTED] rejected"],
  ["NRBR browser key", "browser key NRBR-canary7f3a9c1d rejected", "canary7f3a9c1d", "browser key NRBR-[REDACTED] rejected"],
  ["40 character hex license key in a header", "X-License-Key: cafe7f3a9c1dcafe7f3a9c1dcafe7f3a9c1dcafe", "cafe7f3a9c1dcafe7f3a9c1dcafe7f3a9c1dcafe", "X-License-Key: [REDACTED]"],
  ["40 character hex run in free text", "license cafe7f3a9c1dcafe7f3a9c1dcafe7f3a9c1dcafe rejected", "cafe7f3a9c1dcafe7f3a9c1dcafe7f3a9c1dcafe", "license [REDACTED] rejected"],
  ["Authorization Bearer header", "Authorization: Bearer CANARYBEARER7f3a9c1dAAAAAAAAAAAAAAAAAAAA", "CANARYBEARER7f3a9c1d", "Authorization: Bearer [REDACTED]"],
  ["bare Bearer value", "sent Bearer CANARYBEARER7f3a9c1dAAAA upstream", "CANARYBEARER7f3a9c1dAAAA", "sent Bearer [REDACTED] upstream"],
  ["Authorization Basic header", "Authorization: Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQtN2YzYTljMWQ=", "Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQtN2YzYTljMWQ=", "Authorization: Basic [REDACTED]"],
  ["Cookie header", "Cookie: NRSESSION=CANARYSESSION7f3a9c1d; theme=dark", "CANARYSESSION7f3a9c1d", "Cookie: [REDACTED]"],
  ["Set-Cookie header", "Set-Cookie: NRSESSION=CANARYSESSION7f3a9c1d; Path=/; HttpOnly", "CANARYSESSION7f3a9c1d", "Set-Cookie: [REDACTED]"],
  ["quoted api key pair", 'api_key="CANARYAPIKEY7f3a9c1d"', "CANARYAPIKEY7f3a9c1d", 'api_key="[REDACTED]"'],
  ["api key pair with a space", "api key: CANARYAPIKEY7f3a9c1d", "CANARYAPIKEY7f3a9c1d", "api key: [REDACTED]"],
  ["license key pair", "license key: CANARYLICENSE7f3a9c1d", "CANARYLICENSE7f3a9c1d", "license key: [REDACTED]"],
  ["session id pair", "session_id=CANARYSESSION7f3a9c1d", "CANARYSESSION7f3a9c1d", "session_id=[REDACTED]"],
  ["session pair", "session: CANARYSESSION7f3a9c1d", "CANARYSESSION7f3a9c1d", "session: [REDACTED]"],
  ["access token pair", "access_token=CANARYACCESS7f3a9c1d", "CANARYACCESS7f3a9c1d", "access_token=[REDACTED]"],
  ["refresh token pair", "refresh_token: CANARYREFRESH7f3a9c1d", "CANARYREFRESH7f3a9c1d", "refresh_token: [REDACTED]"],
  ["quoted id token pair", '"id_token": "CANARYIDTOKEN7f3a9c1d"', "CANARYIDTOKEN7f3a9c1d", '"id_token": "[REDACTED]"'],
  ["quoted client secret pair", '{"client_secret": "CANARYSECRET7f3a9c1d"}', "CANARYSECRET7f3a9c1d", '{"client_secret": "[REDACTED]"}'],
  ["password pair", "password: hunter22seven", "hunter22seven", "password: [REDACTED]"],
  ["single-quoted password pair", "password='hunter22seven'", "hunter22seven", "password='[REDACTED]'"],
  ["embedded URL userinfo", "https://user:CANARYPASS7f3a@api.newrelic.com/graphql", "CANARYPASS7f3a", "https://[REDACTED]@api.newrelic.com/graphql"],
  ["embedded URL query", "retry at https://login.newrelic.com/callback?access_token=CANARYURLTOKEN7f3a9c1d&state=x", "CANARYURLTOKEN7f3a9c1d", "retry at https://login.newrelic.com/callback?[REDACTED]"],
  ["embedded URL fragment", "see https://one.newrelic.com/#access_token=CANARYURLTOKEN7f3a9c1d&token_type=bearer", "CANARYURLTOKEN7f3a9c1d", "see https://one.newrelic.com/#[REDACTED]"],
  ["long token with digits in free text", "Upstream rejected request CANARYLONGTOKEN7f3a9c1dZZZZ for tenant", "CANARYLONGTOKEN7f3a9c1dZZZZ", "Upstream rejected request [REDACTED] for tenant"],
  ["long mixed-case token in free text", "Upstream rejected request CANARYmixedTOKENxyzABC for tenant", "CANARYmixedTOKENxyzABC", "Upstream rejected request [REDACTED] for tenant"],
];

// Text that carries no credential and must come back byte for byte: query paths and statuses, account, policy, and
// entity ids, NRQL without secrets, schema names, finding ids, timestamps, enum codes, and `token: user`.
const SCRUB_BENIGN = [
  "alerts.policiesSearch: account 111, account 222: NerdGraph returned errors: Not authorized (at actor.account.alerts.policiesSearch)",
  "authorizationManagement.groups: authentication domains were not readable (userManagement.authenticationDomains: NerdGraph returned errors: Not authorized (at actor.organization.userManagement.authenticationDomains))",
  "nrqlDropRules.list: account 4343: NerdGraph returned errors: Not authorized [SERVER_ERROR] (at actor.account.nrqlDropRules.list)",
  "logConfigurations.obfuscationExpressions: account 111: NerdGraph request failed (502 Bad Gateway) at POST /graphql: non-JSON error body (text/html; 412 bytes)",
  "REST API v2 request failed for GET /v2/users.json (403 Forbidden): The API key provided is invalid",
  'Cannot query field "nextCursor" on type "ApiAccessKeySearchResult"',
  `entity ${ENTITY_GUID} in account 1234567 (policy 98765432101)`,
  "SELECT actorAPIKey, actorId, actorEmail, actionIdentifier, targetType, targetId, timestamp FROM NrAuditEvent WHERE actorType = 'api_key' SINCE 30 days ago LIMIT MAX",
  "SELECT count(*) AS matchCount FROM Log WHERE message RLIKE r'(?i).*(password\\s*[:=]|passwd\\s*[:=]|secret\\s*[:=]|api[_-]?key\\s*[:=]|authorization:\\s*bearer|NRAK-[A-Z0-9]{27}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY).*' SINCE 1 day ago",
  "SELECT count(*) AS logCount FROM Log SINCE 1 day ago",
  "token: user",
  "New Relic request timed out after 30s: https://api.newrelic.com/graphql",
  "NR-04-API-KEY-GOVERNANCE",
  "2026-09-21T12:00:00.000Z",
  "PIPELINE_CLOUD_RULE HASH_SHA256 MASK SCRIPT_BROWSER",
  "Basic users: 3, Full platform users: 12, Core users: 4",
  "token=[a-z0-9]+ and secret=(.*) and password=\\w+",
  "keySearch rejected the cursor argument, so only the first page was read (12 of 40 keys)",
  "arguments:api_key environment:NEW_RELIC_API_KEY config:/home/auditor/.newrelic-sec-inspector/config.yaml",
];

test("scrubErrorText removes every credential shape and leaves query paths, ids, guids, and NRQL untouched", () => {
  const configured = ["NRAK-SUPERSECRETVALUE0000001"];
  for (const [label, input, canary, expected] of SCRUB_SHAPES) {
    assert.ok(input.includes(canary), `${label}: the fixture must carry its canary`);
    const output = scrubErrorText(input, configured);
    assert.equal(output, expected, label);
    assert.equal(output.includes(canary), false, `${label}: the canary survived`);
    assert.equal(scrubErrorText(output, configured), output, `${label}: a second scrub changed the text`);
  }
  for (const text of SCRUB_BENIGN) {
    assert.equal(scrubErrorText(text, configured), text, `benign text changed: ${text}`);
    assert.equal(scrubErrorText(text, configured, { longTokens: false }), text, `benign text changed in data mode: ${text}`);
  }

  // The long-token heuristic is the only rule the data mode turns off: opaque ids survive as evidence there, while
  // every named shape is still removed.
  const opaqueIds = `user-q2hCJZ7bT5C-lk1NXVApFA policy 98765432101 ${ENTITY_GUID}`;
  assert.equal(scrubErrorText(opaqueIds, [], { longTokens: false }), opaqueIds);
  assert.equal(scrubErrorText(opaqueIds), `[REDACTED] policy 98765432101 ${ENTITY_GUID}`);
  for (const [label, input, canary] of SCRUB_SHAPES.filter(([name]) => !name.startsWith("long"))) {
    assert.equal(scrubErrorText(input, configured, { longTokens: false }).includes(canary), false, `${label}: the canary survived the data mode`);
  }
  // A configured credential shorter than eight characters is never used as a scrub key (it would match everywhere).
  assert.equal(scrubErrorText("the word key appears here", ["key"]), "the word key appears here");
});

test("NewrelicApiClient aborts requests that exceed the configured timeout", async () => {
  const fetchImpl = (_input, init = {}) => new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => reject(new Error("The operation was aborted")));
  });
  const client = new NewrelicApiClient(sampleConfig({ timeoutMs: 20 }), { fetchImpl });

  await assert.rejects(client.getCurrentUser(), /timed out after 0s/);
});

test("NewrelicApiClient follows REST API v2 Link headers with the Api-Key header", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input.toString());
    seen.push({ pathname: url.pathname, page: url.searchParams.get("page"), method: init.method, apiKey: headerValue(init.headers, "api-key") });
    if (!url.searchParams.get("page")) {
      return jsonResponse(
        { users: [{ id: 1, email: "one@example.com" }] },
        { headers: { link: '<https://api.newrelic.com/v2/users.json?page=2>; rel="next", <https://api.newrelic.com/v2/users.json?page=2>; rel="last"' } },
      );
    }
    return jsonResponse({ users: [{ id: 2, email: "two@example.com" }] });
  };

  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });
  const users = await client.listRestUsers();

  assert.deepEqual(users.items.map((item) => item.id), [1, 2]);
  assert.equal(users.complete, true);
  assert.equal(seen[0].pathname, "/v2/users.json");
  assert.equal(seen[0].method, "GET");
  assert.equal(seen[0].apiKey, TEST_KEY);
  assert.equal(seen[1].page, "2");
});

test("NewrelicApiClient paginates keySearch with a cursor and scopes it to account IDs", async () => {
  const seen = [];
  const fetchImpl = async (_input, init = {}) => {
    const body = JSON.parse(init.body);
    seen.push(body);
    const page = body.variables.cursor
      ? { nextCursor: null, count: 2, keys: [{ id: "key-2", name: "ingest", type: "INGEST", ingestType: "LICENSE", accountId: 111 }] }
      : { nextCursor: "keys-2", count: 2, keys: [{ id: "key-1", name: "user", type: "USER", userId: 5, accountId: 111 }] };
    return jsonResponse({ data: { actor: { apiAccess: { keySearch: page } } } });
  };
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });
  const keys = await client.listApiKeys(["USER", "INGEST"], [111]);

  assert.deepEqual(keys.items.map((key) => key.id), ["key-1", "key-2"]);
  assert.equal(keys.complete, true);
  assert.equal(keys.totalCount, 2);
  assert.equal(keys.note, undefined);
  assert.deepEqual(seen[0].variables.query, { types: ["USER", "INGEST"], scope: { accountIds: [111] } });
  assert.match(seen[0].query, /keySearch\(query: \$query, cursor: \$cursor\)/);
  assert.equal(seen[1].variables.cursor, "keys-2");
});

test("NewrelicApiClient falls back to a single-page keySearch when the cursor argument is rejected", async () => {
  const seen = [];
  const fetchImpl = async (_input, init = {}) => {
    const body = JSON.parse(init.body);
    seen.push(body.query);
    if (body.query.includes("cursor: $cursor")) {
      return jsonResponse({ errors: [{ message: 'Unknown argument "cursor" on field "ApiAccessActorStitchedFields.keySearch".' }] });
    }
    return jsonResponse({ data: { actor: { apiAccess: { keySearch: { count: 3, keys: [{ id: "key-1", name: "user", type: "USER" }] } } } } });
  };
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });
  const keys = await client.listApiKeys(["USER"]);

  assert.deepEqual(keys.items.map((key) => key.id), ["key-1"]);
  assert.equal(keys.complete, false);
  assert.equal(keys.totalCount, 3);
  assert.match(keys.note, /rejected the cursor argument.*1 of 3 keys/);
  assert.equal(seen.length, 2);
  assert.doesNotMatch(seen[1], /cursor/);
  assert.match(seen[1], /createdAt/);
});

test("NewrelicApiClient falls back to the documented keySearch fields when schema-cited fields are rejected", async () => {
  const seen = [];
  const fetchImpl = async (_input, init = {}) => {
    const body = JSON.parse(init.body);
    seen.push(body.query);
    if (body.query.includes("cursor: $cursor")) {
      return jsonResponse({ errors: [{ message: 'Cannot query field "nextCursor" on type "ApiAccessKeySearchResult".' }] });
    }
    if (body.query.includes("createdAt")) {
      return jsonResponse({ errors: [{ message: 'Cannot query field "createdAt" on type "ApiAccessKey". Did you mean "created"?' }] });
    }
    return jsonResponse({
      data: {
        actor: {
          apiAccess: {
            keySearch: {
              keys: [
                { id: "key-1", name: "user", type: "USER" },
                { id: "key-2", name: "license", type: "INGEST", ingestType: "LICENSE" },
              ],
            },
          },
        },
      },
    });
  };
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });
  const keys = await client.listApiKeys(["USER", "INGEST"], [111]);

  assert.equal(seen.length, 3);
  assert.match(seen[0], /nextCursor count/);
  assert.match(seen[1], /count\s+keys \{\s+id name type createdAt/);
  assert.match(seen[2], /keySearch\(query: \$query\) \{\s+keys \{\s+id name type\s+\.\.\. on ApiAccessIngestKey \{ ingestType \}\s+\}/);
  assert.doesNotMatch(seen[2], /createdAt|userId|accountId|notes|nextCursor|count|cursor|\bkey\b/);
  assert.deepEqual(keys.items.map((key) => key.id), ["key-1", "key-2"]);
  assert.equal(keys.complete, false);
  assert.equal(keys.totalCount, undefined);
  assert.match(keys.note, /only the documented fields \(id, name, type, ingestType\) were read on a single page; createdAt, userId, accountId, and pagination are unavailable and completeness is unknown \(2 keys read\)/);

  const unauthorized = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ errors: [{ message: "Not authorized", path: ["actor", "apiAccess", "keySearch"] }] }),
  });
  await assert.rejects(unauthorized.listApiKeys(["USER"]), /Not authorized/);
});

test("NewrelicApiClient treats every NerdGraph schema validation wording as a schema mismatch", async () => {
  const wordings = [
    'Cannot query field "nextCursor" on type "ApiAccessKeySearchResult".',
    'Unknown argument "cursor" on field "ApiAccessActorStitchedFields.keySearch".',
    'Unknown field "count" on type "ApiAccessKeySearchResult".',
    'Argument "query" has invalid value {types: [USER]}.',
    'Field "createdAt" is not defined by type "ApiAccessKey".',
    'Field "keySearch" does not accept argument "cursor".',
    'Field "userId" doesn\'t exist on type "ApiAccessKey".',
  ];
  for (const wording of wordings) {
    let calls = 0;
    const client = new NewrelicApiClient(sampleConfig(), {
      fetchImpl: async (_input, init = {}) => {
        calls += 1;
        const body = JSON.parse(init.body);
        if (body.query.includes("cursor: $cursor")) return jsonResponse({ errors: [{ message: wording }] });
        return jsonResponse({ data: { actor: { apiAccess: { keySearch: { count: 1, keys: [{ id: "key-1", name: "user", type: "USER", createdAt: 1 }] } } } } });
      },
    });
    const keys = await client.listApiKeys(["USER"]);
    assert.equal(calls, 2, `expected a fallback after: ${wording}`);
    assert.deepEqual(keys.items.map((key) => key.id), ["key-1"]);
  }

  for (const wording of ["Not authorized", "Forbidden: this key cannot read keySearch", "Internal server error"]) {
    const client = new NewrelicApiClient(sampleConfig(), {
      fetchImpl: async () => jsonResponse({ errors: [{ message: wording }] }),
    });
    await assert.rejects(client.listApiKeys(["USER"]), new RegExp(wording.split(":")[0]));
  }
});

test("NewrelicApiClient reads the role catalog from customerAdministration.roles with the documented fields and cursor", async () => {
  const seen = [];
  const fetchImpl = async (_input, init = {}) => {
    const body = JSON.parse(init.body);
    seen.push(body.query);
    const page = body.query.includes("cursor:")
      ? { items: [{ id: "2", name: "Read only", scope: "account", type: "STANDARD" }], nextCursor: null, totalCount: 2 }
      : { items: [{ id: "1", name: "Organization manager", scope: "organization", type: "STANDARD" }], nextCursor: "roles-2", totalCount: 2 };
    return jsonResponse({ data: { customerAdministration: { roles: page } } });
  };
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });
  const roles = await client.listRoles("org-1");

  assert.deepEqual(roles.items.map((role) => role.id), ["1", "2"]);
  assert.equal(roles.complete, true);
  assert.equal(roles.totalCount, 2);
  assert.equal(seen.length, 2);
  assert.match(seen[0], /customerAdministration \{ roles\(filter: \{ organizationId: \{ eq: "org-1" \} \}\) \{ items \{ id name scope type \} nextCursor totalCount \} \}/);
  assert.doesNotMatch(seen[0], /cursor:|authorizationManagement|displayName/);
  assert.match(seen[1], /roles\(filter: \{ organizationId: \{ eq: "org-1" \} \}, cursor: "roles-2"\)/);

  const rejectingCursor = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async (_input, init = {}) => {
      const body = JSON.parse(init.body);
      if (body.query.includes("cursor:")) {
        return jsonResponse({ errors: [{ message: 'Unknown argument "cursor" on field "CustomerAdministration.roles".' }] });
      }
      return jsonResponse({ data: { customerAdministration: { roles: { items: [{ id: "1", name: "Organization manager", scope: "organization", type: "STANDARD" }], nextCursor: "roles-2", totalCount: 2 } } } });
    },
  });
  const firstPage = await rejectingCursor.listRoles("org-1");
  assert.equal(firstPage.complete, false);
  assert.equal(firstPage.items.length, 1);
  assert.match(firstPage.note, /customerAdministration\.roles rejected the cursor argument.*1 of 2 items/);

  const unauthorized = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ errors: [{ message: "Not authorized", path: ["customerAdministration", "roles"] }] }),
  });
  await assert.rejects(unauthorized.listRoles("org-1"), /Not authorized/);

  const domains = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async (_input, init = {}) => {
      const body = JSON.parse(init.body);
      assert.match(body.query, /authenticationDomains\(filter: \{ organizationId: \{ eq: "org-1" \} \}\) \{ items \{ id name organizationId provisioningType authenticationType \} nextCursor \}/);
      return jsonResponse({ data: { customerAdministration: { authenticationDomains: { items: [{ id: "domain-1", provisioningType: "SCIM", authenticationType: "SAML_SSO" }], nextCursor: null } } } });
    },
  });
  assert.deepEqual(await domains.listOrganizationAuthenticationDomains("org-1"), {
    items: [{ id: "domain-1", provisioningType: "SCIM", authenticationType: "SAML_SSO" }],
    complete: true,
    totalCount: undefined,
  });
});

test("NewrelicApiClient surfaces dashboard live URL errors and omits link values", async () => {
  const fetchImpl = async (_input, init = {}) => {
    const body = JSON.parse(init.body);
    assert.doesNotMatch(body.query, /\burl\b|uuid/);
    return jsonResponse({ data: { actor: { dashboard: { liveUrls: { liveUrls: [{ title: "Ops", type: "DASHBOARD", createdAt: NOW }], errors: null } } } } });
  };
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });
  assert.deepEqual(await client.listDashboardLiveUrls(), { items: [{ title: "Ops", type: "DASHBOARD", createdAt: NOW }], complete: true });

  const failing = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ data: { actor: { dashboard: { liveUrls: { liveUrls: [], errors: [{ description: "Live URL listing is not permitted" }] } } } } }),
  });
  await assert.rejects(failing.listDashboardLiveUrls(), /Live URL listing is not permitted/);

  const missingContainer = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ data: { actor: { dashboard: { liveUrls: null } } } }),
  });
  await assert.rejects(missingContainer.listDashboardLiveUrls(), /did not include actor\.dashboard\.liveUrls\./);

  const missingList = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ data: { actor: { dashboard: { liveUrls: { errors: null } } } } }),
  });
  await assert.rejects(missingList.listDashboardLiveUrls(), /did not include actor\.dashboard\.liveUrls\.liveUrls/);
});

test("NewrelicApiClient parses the documented live URL sample response and control 14 fails on public links", async () => {
  const seen = [];
  const client = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async (_input, init = {}) => {
      seen.push(JSON.parse(init.body).query);
      return jsonResponse({
        data: {
          actor: {
            dashboard: {
              liveUrls: {
                errors: null,
                liveUrls: [
                  { createdAt: 1753000000346, title: "", type: "WIDGET", url: "https://chart-embed.example.newrelic.com/herald/9ac583f4" },
                  { createdAt: 1753000000572, title: "", type: "WIDGET", url: "https://chart-embed.example.newrelic.com/herald/5d81451a" },
                  { createdAt: 1728900000694, title: "Ops overview", type: "DASHBOARD", uuid: "c1eac5ac-4a93-42d4-8b25-36078ecc8d79" },
                ],
              },
            },
          },
        },
      });
    },
  });
  const liveUrls = await client.listDashboardLiveUrls();
  assert.equal(liveUrls.complete, true);
  assert.equal(liveUrls.items.length, 3);
  assert.match(seen[0], /actor \{ dashboard \{ liveUrls \{ liveUrls \{ title type createdAt \} errors \{ description \} \} \} \}/);
  assert.doesNotMatch(seen[0], /filter|\burl\b|uuid/);

  const result = await assessNewrelicDataGovernance(dataGovernanceClient({
    async listDashboardLiveUrls() {
      return liveUrls;
    },
  }), { now: NOW });
  const exposure = findingById(result, "NR-14-DASHBOARD-PERMISSIONS");
  assert.equal(exposure.status, "fail");
  assert.match(exposure.summary, /1 dashboards and 2 widgets are shared through public live URLs/);
  assert.equal(exposure.evidence.public_live_urls, 3);
  assert.deepEqual(exposure.evidence.public_dashboard_live_urls, ["Ops overview"]);
  assert.equal(exposure.evidence.public_widget_live_urls, 2);
  const snapshots = result.coreData["core_data/dashboard_live_urls.json"];
  assert.deepEqual(snapshots[2], { title: "Ops overview", type: "DASHBOARD", createdAt: 1728900000694 });
  assert.ok(!JSON.stringify(snapshots).includes("chart-embed"));
  assert.ok(!JSON.stringify(snapshots).includes("c1eac5ac"));
});

test("NewrelicApiClient discovers account IDs from actor.accounts when none are configured", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return jsonResponse({ data: { actor: { accounts: [{ id: 111, name: "One" }, { id: 222, name: "Two" }] } } });
  };
  const client = new NewrelicApiClient(sampleConfig({ accountIds: [] }), { fetchImpl });

  assert.deepEqual(await client.resolveAccountIds(), [111, 222]);
  assert.deepEqual(await client.resolveAccountIds(), [111, 222]);
  assert.equal(calls, 1);
});

test("checkNewrelicAccess reports healthy when every required surface is readable", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getCurrentUser() {
      return { id: "u-1", email: "auditor@example.com" };
    },
    async getOrganization() {
      return { id: "org-1", name: "Example Org" };
    },
    async listAccounts() {
      return [{ id: 111, name: "Production" }, { id: 222, name: "Development" }];
    },
    async resolveAccountIds() {
      return [111, 222];
    },
    async listAuthenticationDomains() {
      return [{ id: "domain-1" }];
    },
    async listRoles(organizationId) {
      requireOrganizationId(organizationId);
      return standardRoles();
    },
    async listApiKeys() {
      return [{ id: "key-1", type: "USER" }];
    },
    async runNrql() {
      return [{ count: 5 }];
    },
    async searchEntities() {
      return [{ guid: "dash-1" }];
    },
    async listAlertPolicies() {
      return [{ id: "policy-1" }];
    },
    async listEventRetentionRules() {
      return [];
    },
    async listObfuscationRules() {
      return [];
    },
    async listRestUsers() {
      return [{ id: 1 }];
    },
  };

  const result = await checkNewrelicAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.region, "US");
  assert.deepEqual(result.accountIds, [111, 222]);
  assert.equal(result.surfaces.length, 12);
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 12);
  assert.equal(result.surfaces.filter((surface) => surface.required).length, 6);
  assert.ok(result.surfaces.some((surface) => surface.name === "nrql" && surface.required));
  const roleCatalog = result.surfaces.find((surface) => surface.name === "role_catalog");
  assert.equal(roleCatalog.required, false);
  assert.match(roleCatalog.endpoint, /customerAdministration\.roles/);
  assert.ok(result.notes.some((note) => note.includes("auditor@example.com")));
  assert.match(result.recommendedNextStep, /newrelic_assess_identity/);
});

test("checkNewrelicAccess stays healthy when the entitlement-gated role catalog is not served", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig(),
    async getCurrentUser() {
      return { id: "u-1", email: "auditor@example.com" };
    },
    async getOrganization() {
      return { id: "org-1", name: "Example Org" };
    },
    async listAccounts() {
      return [{ id: 111, name: "Production" }];
    },
    async resolveAccountIds() {
      return [111];
    },
    async listAuthenticationDomains() {
      return [{ id: "domain-1" }];
    },
    async listRoles() {
      throw new Error("NerdGraph returned errors: Not authorized (at customerAdministration.roles)");
    },
    async listApiKeys() {
      return [{ id: "key-1", type: "USER" }];
    },
    async runNrql() {
      return [{ count: 5 }];
    },
    async searchEntities() {
      return [{ guid: "dash-1" }];
    },
    async listAlertPolicies() {
      return [{ id: "policy-1" }];
    },
    async listEventRetentionRules() {
      return [];
    },
    async listObfuscationRules() {
      return [];
    },
    async listRestUsers() {
      return [{ id: 1 }];
    },
  };

  const result = await checkNewrelicAccess(client);
  assert.equal(result.status, "healthy");
  const roleCatalog = result.surfaces.find((surface) => surface.name === "role_catalog");
  assert.equal(roleCatalog.status, "not_readable");
  assert.equal(roleCatalog.required, false);
  assert.match(roleCatalog.error, /Not authorized/);
  assert.ok(result.notes.some((note) => /multi-tenancy entitlement/.test(note) && /control 20 renders manual/.test(note)));
  assert.ok(!result.surfaces.some((surface) => /authorizationManagement\.roles/.test(surface.endpoint)));
});

test("checkNewrelicAccess reports limited access when required surfaces fail", async () => {
  const client = {
    getResolvedConfig: () => sampleConfig({ accountIds: [] }),
    async getCurrentUser() {
      return { id: "u-1", email: "viewer@example.com" };
    },
    async getOrganization() {
      return { id: "org-1" };
    },
    async listAccounts() {
      return [{ id: 111 }];
    },
    async resolveAccountIds() {
      return [111];
    },
    async listAuthenticationDomains() {
      throw new Error("NerdGraph returned errors: Not authorized (at actor.organization.userManagement)");
    },
    async listRoles() {
      throw new Error("NerdGraph returned errors: Not authorized (at customerAdministration.roles)");
    },
    async listApiKeys() {
      return [];
    },
    async runNrql() {
      return [{ count: 0 }];
    },
    async searchEntities() {
      return [];
    },
    async listAlertPolicies() {
      return [];
    },
    async listEventRetentionRules() {
      return [];
    },
    async listObfuscationRules() {
      return [];
    },
    async listRestUsers() {
      throw new Error("REST API v2 request failed for /v2/users.json (403 Forbidden)");
    },
  };

  const result = await checkNewrelicAccess(client);
  assert.equal(result.status, "limited");
  const userManagement = result.surfaces.find((surface) => surface.name === "user_management");
  assert.equal(userManagement.status, "not_readable");
  assert.match(userManagement.error, /Not authorized/);
  assert.equal(result.surfaces.find((surface) => surface.name === "rest_v2_users").required, false);
  assert.match(result.recommendedNextStep, /Organization manager/);
});

test("assessNewrelicIdentity passes a SCIM-provisioned SSO domain with active, minimal admins", async () => {
  const result = await assessNewrelicIdentity(identityClient(), { now: NOW });

  assert.equal(result.category, "identity");
  assert.deepEqual(result.findings.map((item) => item.control), [1, 2, 3, 18, 19]);
  assert.equal(findingStatus(result, "NR-01-SSO-ENFORCEMENT"), "pass");
  assert.equal(findingStatus(result, "NR-02-USER-TYPE-LEAST-PRIVILEGE"), "pass");
  assert.equal(findingStatus(result, "NR-03-ADMIN-MINIMIZATION"), "pass");
  assert.equal(findingStatus(result, "NR-18-AUTH-DOMAIN-CONFIGURATION"), "manual");
  assert.match(findingById(result, "NR-18-AUTH-DOMAIN-CONFIGURATION").summary, /provision users through SCIM .*Session duration and user upgrade approval settings are not exposed/);
  assert.equal(findingStatus(result, "NR-19-INACTIVE-USER-ACCOUNTS"), "pass");
  assert.equal(result.errors.length, 0);
  assert.deepEqual(result.coverage, []);
  assert.equal(result.summary.users, 3);
  assert.equal(result.summary.admin_users, 1);
  assert.ok(result.findings.every((item) => item.mappings.length === 8));
  assert.ok(Object.keys(result.coreData).includes("core_data/users.json"));
});

test("assessNewrelicIdentity fails password authentication, admin sprawl, inactive users, and manual provisioning", async () => {
  const client = identityClient({
    async listAuthenticationDomains() {
      return [{ id: "domain-1", name: "Legacy", provisioningType: "MANUAL" }];
    },
    async listOrganizationAuthenticationDomains() {
      return [{ id: "domain-1", name: "Legacy", organizationId: "org-1", provisioningType: "MANUAL", authenticationType: "PASSWORD" }];
    },
    async listDomainUsers() {
      return [
        user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }),
        user("bob", { type: "FULL_PLATFORM", groups: ["g-admin"] }),
        user("carol", { type: "FULL_PLATFORM", groups: ["g-admin"], lastActiveDaysAgo: 200 }),
        user("dave", { type: "BASIC", groups: ["g-dev"], lastActive: null }),
      ];
    },
  });

  const result = await assessNewrelicIdentity(client, { now: NOW, maxAdmins: 2 });

  assert.equal(findingStatus(result, "NR-01-SSO-ENFORCEMENT"), "fail");
  assert.match(findingById(result, "NR-01-SSO-ENFORCEMENT").summary, /New Relic passwords/);
  assert.equal(findingStatus(result, "NR-02-USER-TYPE-LEAST-PRIVILEGE"), "fail");
  assert.equal(findingStatus(result, "NR-03-ADMIN-MINIMIZATION"), "fail");
  assert.equal(findingById(result, "NR-03-ADMIN-MINIMIZATION").evidence.admin_users, 3);
  assert.equal(findingStatus(result, "NR-18-AUTH-DOMAIN-CONFIGURATION"), "warn");
  assert.equal(findingStatus(result, "NR-19-INACTIVE-USER-ACCOUNTS"), "fail");
  assert.deepEqual(findingById(result, "NR-19-INACTIVE-USER-ACCOUNTS").evidence.inactive_user_sample, ["carol@example.com"]);
});

test("assessNewrelicIdentity turns unreadable authentication types into manual evidence requests", async () => {
  const client = identityClient({
    async listOrganizationAuthenticationDomains() {
      throw new Error("NerdGraph returned errors: customerAdministration is not available for this organization");
    },
  });

  const result = await assessNewrelicIdentity(client, { now: NOW });
  const sso = findingById(result, "NR-01-SSO-ENFORCEMENT");

  assert.equal(sso.status, "manual");
  assert.match(sso.summary, /Administration > Access Management > Authentication domains/);
  assert.match(sso.evidence.manual_evidence, /SAML SSO or OIDC SSO/);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /customerAdministration\.authenticationDomains/);
});

test("assessNewrelicAccessControl passes a clean key inventory with scoped account access", async () => {
  const result = await assessNewrelicAccessControl(accessControlClient(), { now: NOW });

  assert.equal(result.category, "access_control");
  assert.deepEqual(result.findings.map((item) => item.control), [4, 5, 6, 7, 8, 20]);
  assert.equal(findingStatus(result, "NR-04-API-KEY-INVENTORY"), "pass");
  assert.equal(findingStatus(result, "NR-05-API-KEY-AGE"), "pass");
  assert.equal(findingStatus(result, "NR-06-UNUSED-API-KEYS"), "manual");
  assert.match(findingById(result, "NR-06-UNUSED-API-KEYS").summary, /1 distinct API keys performed configuration changes/);
  assert.equal(findingStatus(result, "NR-07-ACCOUNT-ACCESS-CONTROLS"), "pass");
  assert.equal(findingStatus(result, "NR-08-CROSS-ACCOUNT-RESTRICTIONS"), "pass");
  assert.equal(findingStatus(result, "NR-20-CUSTOM-ROLE-PERMISSIONS"), "pass");
  assert.equal(result.summary.keys_total, 3);
  assert.equal(result.summary.user_keys, 1);
  assert.equal(result.errors.length, 0);
});

test("assessNewrelicAccessControl flags unnamed and aged keys, orphaned owners, broad access, and custom roles", async () => {
  const client = accessControlClient({
    async listAccounts() {
      return [
        { id: 111, name: "Payments Production" },
        { id: 222, name: "Payments Development" },
        { id: 333, name: "Shared Staging" },
        { id: 444, name: "Data QA" },
        { id: 555, name: "Sandbox" },
        { id: 666, name: "Demo" },
        { id: 777, name: "UAT" },
      ];
    },
    async listDomainUsers() {
      return [
        user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }),
        user("bob", { type: "BASIC", groups: ["g-dev", "g-prod"] }),
        user("carol", { type: "CORE", groups: ["g-everything"] }),
      ];
    },
    async listDomainGroupGrants() {
      return [
        orgManagerGroup(),
        accountGroup("g-dev", [222]),
        accountGroup("g-prod", [111]),
        accountGroup("g-everything", [222, 333, 444, 555, 666, 777]),
      ];
    },
    async listRoles(organizationId) {
      requireOrganizationId(organizationId);
      return [...standardRoles(), { id: "9", name: "Deploy operators", scope: "account", type: "CUSTOM" }];
    },
    async listApiKeys() {
      return [
        { id: "key-1", name: null, type: "USER", createdAt: secondsAgo(400), userId: "ghost", accountId: 111 },
        { id: "key-2", name: "admin-automation", type: "USER", createdAt: secondsAgo(5), userId: "alice", accountId: 111 },
        { id: "key-3", name: "license-prod", type: "INGEST", ingestType: "LICENSE", createdAt: secondsAgo(500), accountId: 111 },
      ];
    },
  });

  const result = await assessNewrelicAccessControl(client, { now: NOW });

  assert.equal(findingStatus(result, "NR-04-API-KEY-INVENTORY"), "warn");
  assert.deepEqual(findingById(result, "NR-04-API-KEY-INVENTORY").evidence.admin_owned_user_keys, ["admin-automation"]);
  assert.equal(findingStatus(result, "NR-05-API-KEY-AGE"), "fail");
  assert.match(findingById(result, "NR-05-API-KEY-AGE").summary, /1\/2 user keys are older than 90 days/);
  assert.equal(findingStatus(result, "NR-06-UNUSED-API-KEYS"), "warn");
  assert.deepEqual(findingById(result, "NR-06-UNUSED-API-KEYS").evidence.orphaned_user_keys, ["key-1"]);
  assert.equal(findingStatus(result, "NR-07-ACCOUNT-ACCESS-CONTROLS"), "warn");
  assert.match(findingById(result, "NR-07-ACCOUNT-ACCESS-CONTROLS").evidence.broad_access_users[0], /carol@example.com \(6 accounts\)/);
  assert.equal(findingStatus(result, "NR-08-CROSS-ACCOUNT-RESTRICTIONS"), "warn");
  assert.deepEqual(findingById(result, "NR-08-CROSS-ACCOUNT-RESTRICTIONS").evidence.cross_environment_users, ["bob@example.com"]);
  assert.equal(findingById(result, "NR-08-CROSS-ACCOUNT-RESTRICTIONS").evidence.admin_users_excluded, 1);
  assert.equal(findingStatus(result, "NR-20-CUSTOM-ROLE-PERMISSIONS"), "manual");
  assert.match(findingById(result, "NR-20-CUSTOM-ROLE-PERMISSIONS").summary, /1 custom roles exist \(Deploy operators\).*Administration > Access Management > Roles/);
  assert.deepEqual(findingById(result, "NR-20-CUSTOM-ROLE-PERMISSIONS").evidence.custom_roles, [
    { id: "9", name: "Deploy operators", scope: "account", type: "CUSTOM" },
  ]);
});

test("controls 4, 5 and 6 render manual when keySearch only exposes the documented key fields", async () => {
  const documentedOnly = accessControlClient({
    async listApiKeys() {
      return {
        items: [
          { id: "key-1", name: "ci-deploy", type: "USER" },
          { id: "key-2", name: "license-prod", type: "INGEST", ingestType: "LICENSE" },
        ],
        complete: false,
        note: `${API_KEY_DOCUMENTED_ONLY_NOTE} (2 keys read)`,
      };
    },
  });
  const result = await assessNewrelicAccessControl(documentedOnly, { now: NOW });

  const inventory = findingById(result, "NR-04-API-KEY-INVENTORY");
  assert.equal(inventory.status, "manual");
  assert.match(inventory.summary, /none of the 1 user keys exposed a userId \(the schema-cited ApiAccessUserKey\.userId field was not returned\)/);
  assert.match(inventory.summary, /key owners cannot be matched to admin group members/);
  assert.match(inventory.summary, /Partial view: .*keySearch rejected the schema-cited fields, so only the documented fields/);
  assert.equal(inventory.evidence.user_keys_without_user_id, 1);
  assert.equal(inventory.evidence.key_listing_complete, false);

  const age = findingById(result, "NR-05-API-KEY-AGE");
  assert.equal(age.status, "manual");
  assert.match(age.summary, /createdAt \(the schema-cited ApiAccessUserKey\.createdAt and ApiAccessIngestKey\.createdAt fields\) was not exposed for any of the 2 keys/);
  assert.match(age.summary, /key age cannot be evaluated through the API/);
  assert.equal(age.evidence.keys_without_created_at_total, 2);

  const unused = findingById(result, "NR-06-UNUSED-API-KEYS");
  assert.equal(unused.status, "manual");
  assert.match(unused.summary, /none of the 1 user keys exposed a userId/);
  assert.match(unused.summary, /orphaned and inactive-owner keys cannot be identified through the API/);
  assert.equal(unused.evidence.user_keys_without_user_id, 1);

  const partialOwners = await assessNewrelicAccessControl(accessControlClient({
    async listApiKeys() {
      return [
        { id: "key-1", name: "ci-deploy", type: "USER", createdAt: secondsAgo(10), userId: "bob", accountId: 111 },
        { id: "key-4", name: "legacy-user-key", type: "USER", createdAt: secondsAgo(10) },
        { id: "key-2", name: "license-prod", type: "INGEST", ingestType: "LICENSE", createdAt: secondsAgo(20), accountId: 111 },
      ];
    },
  }), { now: NOW });
  const partialInventory = findingById(partialOwners, "NR-04-API-KEY-INVENTORY");
  assert.equal(partialInventory.status, "warn");
  assert.match(partialInventory.summary, /1 user keys expose no userId, so admin-owned user keys may be undercounted/);
  assert.equal(findingStatus(partialOwners, "NR-06-UNUSED-API-KEYS"), "manual");
  assert.match(findingById(partialOwners, "NR-06-UNUSED-API-KEYS").summary, /\(1 user keys expose no userId\)/);

  const clean = await assessNewrelicAccessControl(accessControlClient(), { now: NOW });
  assert.equal(findingStatus(clean, "NR-04-API-KEY-INVENTORY"), "pass");
  assert.match(findingById(clean, "NR-04-API-KEY-INVENTORY").summary, /every one exposing a userId/);
});

test("control 20 reads the role catalog from customerAdministration.roles and classifies by the CUSTOM/STANDARD enum", async () => {
  const calls = [];
  const catalog = accessControlClient({
    async listRoles(organizationId) {
      calls.push(organizationId);
      return [
        { id: "1", name: "Organization manager", scope: "organization", type: "STANDARD" },
        { id: "2", name: "Read only", scope: "account", type: "standard" },
      ];
    },
  });
  const passing = await assessNewrelicAccessControl(catalog, { now: NOW });
  assert.deepEqual(calls, ["org-1"]);
  assert.equal(findingStatus(passing, "NR-20-CUSTOM-ROLE-PERMISSIONS"), "pass");
  assert.match(findingById(passing, "NR-20-CUSTOM-ROLE-PERMISSIONS").summary, /customerAdministration\.roles query was readable and complete.*2 STANDARD roles/);
  assert.equal(findingById(passing, "NR-20-CUSTOM-ROLE-PERMISSIONS").evidence.role_catalog_source, "customerAdministration.roles");

  const unknownType = await assessNewrelicAccessControl(accessControlClient({
    async listRoles() {
      return [...standardRoles(), { id: "3", name: "Mystery", scope: "account", type: "SYSTEM" }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(unknownType, "NR-20-CUSTOM-ROLE-PERMISSIONS"), "manual");
  assert.match(findingById(unknownType, "NR-20-CUSTOM-ROLE-PERMISSIONS").summary, /1\/3 roles exposed a type other than CUSTOM or STANDARD \(the MultiTenantAuthorizationRoleTypeEnum values\)/);

  const noOrganizationId = await assessNewrelicAccessControl(accessControlClient({
    async getOrganization() {
      return { name: "Example Org" };
    },
    async listRoles() {
      throw new Error("listRoles must not be called without an organization id");
    },
  }), { now: NOW });
  assert.equal(findingStatus(noOrganizationId, "NR-20-CUSTOM-ROLE-PERMISSIONS"), "manual");
  assert.match(findingById(noOrganizationId, "NR-20-CUSTOM-ROLE-PERMISSIONS").summary, /role catalog \(customerAdministration\.roles\) was not collected \(customerAdministration\.roles was not queried for any organization: actor\.organization returned no id\)/);
});

test("control 20 renders manual with custom roles from group grants when the role catalog is entitlement-gated", async () => {
  const result = await assessNewrelicAccessControl(accessControlClient({
    async listDomainGroupGrants() {
      return [orgManagerGroup(), accountGroup("g-dev", [222]), accountGroup("g-deploy", [111], "Deploy operators", "CUSTOM")];
    },
    async listRoles() {
      throw new Error("NerdGraph returned errors: Not authorized (at customerAdministration.roles)");
    },
  }), { now: NOW });

  const finding = findingById(result, "NR-20-CUSTOM-ROLE-PERMISSIONS");
  assert.equal(finding.status, "manual");
  assert.match(finding.summary, /role catalog \(customerAdministration\.roles\) was unreadable \(customerAdministration\.roles: .*Not authorized \(at customerAdministration\.roles\)\)/);
  assert.match(finding.summary, /only served to organizations with the multi-tenancy entitlement/);
  assert.match(finding.summary, /Group grants expose 1 custom roles in use \(Deploy operators\)/);
  assert.equal(finding.evidence.role_catalog_readable, false);
  assert.deepEqual(finding.evidence.custom_roles_in_group_grants, ["Deploy operators"]);
  assert.deepEqual(finding.evidence.groups_granted_custom_roles, ["g-deploy"]);
  assert.ok(result.errors.some((error) => /customerAdministration\.roles: .*Not authorized/.test(error)));
  assert.equal(findingStatus(result, "NR-04-API-KEY-INVENTORY"), "pass");
  assert.equal(findingStatus(result, "NR-07-ACCOUNT-ACCESS-CONTROLS"), "pass");

  const identity = await assessNewrelicIdentity(identityClient({
    async listRoles() {
      throw new Error("NerdGraph returned errors: Not authorized (at customerAdministration.roles)");
    },
  }), { now: NOW });
  assert.equal(findingStatus(identity, "NR-01-SSO-ENFORCEMENT"), "pass");
  assert.equal(findingStatus(identity, "NR-03-ADMIN-MINIMIZATION"), "pass");
  assert.ok(identity.errors.some((error) => /customerAdministration\.roles: .*Not authorized/.test(error)));
});

test("assessNewrelicAccessControl marks controls manual when API keys and grants are not readable", async () => {
  const client = accessControlClient({
    async listApiKeys() {
      throw new Error("NerdGraph returned errors: Not authorized (at actor.apiAccess.keySearch)");
    },
    async listDomainGroupGrants() {
      throw new Error("NerdGraph returned errors: Not authorized (at actor.organization.authorizationManagement)");
    },
  });

  const result = await assessNewrelicAccessControl(client, { now: NOW });

  assert.equal(findingStatus(result, "NR-04-API-KEY-INVENTORY"), "manual");
  assert.equal(findingStatus(result, "NR-05-API-KEY-AGE"), "manual");
  assert.equal(findingStatus(result, "NR-06-UNUSED-API-KEYS"), "manual");
  assert.equal(findingStatus(result, "NR-07-ACCOUNT-ACCESS-CONTROLS"), "manual");
  assert.equal(findingStatus(result, "NR-08-CROSS-ACCOUNT-RESTRICTIONS"), "manual");
  assert.equal(result.errors.length, 2);
});

test("assessNewrelicAlerting passes covered entities routed to corporate destinations", async () => {
  const result = await assessNewrelicAlerting(alertingClient());

  assert.equal(result.category, "alerting");
  assert.deepEqual(result.findings.map((item) => item.control), [9, 10, 17]);
  assert.equal(findingStatus(result, "NR-09-ALERT-POLICY-COVERAGE"), "pass");
  assert.equal(findingStatus(result, "NR-10-ALERT-NOTIFICATION-CHANNELS"), "pass");
  assert.equal(findingStatus(result, "NR-17-APPLIED-INTELLIGENCE-SENSITIVITY"), "manual");
  assert.match(findingById(result, "NR-17-APPLIED-INTELLIGENCE-SENSITIVITY").summary, /Correlation decisions/);
  const channels = findingById(result, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.deepEqual(channels.evidence.approved_email_domains, ["example.com"]);
  assert.match(channels.summary, /1 destinations across 1 types receive 1 enabled workflows \(1 destinations resolved through channels\)/);
  assert.match(channels.summary, /every workflow exposed workflowEnabled/);
  assert.match(channels.summary, /Destination active state is not among the documented aiNotifications\.destinations fields and is not read; enablement is verified through the documented workflowEnabled flag/);
  assert.doesNotMatch(channels.summary, /active state, and/);
  assert.equal(channels.evidence.destinations_routed_by_enabled_workflows, 1);
  assert.equal(channels.evidence.destination_active_state, "not read: not among the documented aiNotifications.destinations fields");
  assert.equal(result.summary.reporting_alertable_entities, 2);
  assert.equal(result.errors.length, 0);
});

test("control 10 renders manual when enabled workflows cannot be resolved to inventoried destinations", async () => {
  const unresolved = await assessNewrelicAlerting(alertingClient({
    async listNotificationChannels() {
      return [{ id: "chan-1", name: "Ops email", type: "EMAIL" }];
    },
  }));
  const channels = findingById(unresolved, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.equal(channels.status, "manual");
  assert.match(channels.summary, /1 enabled workflows exist, but none of their destination configurations resolved to an inventoried destination through channels/);
  assert.equal(channels.evidence.destinations_routed_by_enabled_workflows, 0);

  const partlyResolved = await assessNewrelicAlerting(alertingClient({
    async listWorkflows() {
      return [
        { id: "wf-1", name: "Production issues", workflowEnabled: true, destinationConfigurations: [{ channelId: "chan-1", name: "Ops email", type: "EMAIL" }], enrichments: [] },
        { id: "wf-2", name: "Dangling", workflowEnabled: true, destinationConfigurations: [{ channelId: "chan-missing", name: "Old", type: "EMAIL" }], enrichments: [] },
      ];
    },
  }));
  const partly = findingById(partlyResolved, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.equal(partly.status, "warn");
  assert.match(partly.summary, /2 enabled workflows route to 1 of them/);
  assert.match(partly.summary, /1 enabled workflows resolve to no inventoried destination/);
  assert.deepEqual(partly.evidence.enabled_workflows_without_resolved_destination, ["Dangling"]);

  const stripped = await assessNewrelicAlerting(alertingClient({
    async listNotificationDestinations() {
      return [{ id: "dest-1", name: "Ops distribution list", type: "EMAIL", active: false, status: "ERROR", properties: [{ key: "email", value: "ops@example.com" }] }];
    },
  }));
  const ignoresUndocumented = findingById(stripped, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.equal(ignoresUndocumented.status, "pass");
  assert.equal(ignoresUndocumented.evidence.inactive_destinations, undefined);
  assert.equal(ignoresUndocumented.evidence.destinations_without_active_flag, undefined);
});

test("NewrelicApiClient treats a documented aiNotifications error object as an unreadable account", async () => {
  const seen = [];
  const client = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async (_input, init = {}) => {
      const body = JSON.parse(init.body);
      seen.push(body.query);
      if (body.query.includes("destinations(")) {
        return jsonResponse({ data: { actor: { account: { aiNotifications: { destinations: { nextCursor: null, totalCount: 0, entities: [], error: { details: "Account 111 is not entitled to notifications" } } } } } } });
      }
      return jsonResponse({ data: { actor: { account: { aiNotifications: { channels: { nextCursor: null, totalCount: 1, entities: [{ id: "chan-1", name: "Ops", type: "EMAIL", destinationId: "dest-1" }], error: null } } } } } });
    },
  });

  await assert.rejects(client.listNotificationDestinations(111), /aiNotifications\.destinations returned an error: Account 111 is not entitled to notifications/);
  const channels = await client.listNotificationChannels(111);
  assert.deepEqual(channels.items.map((channel) => channel.id), ["chan-1"]);
  assert.equal(channels.complete, true);
  assert.match(seen[0], /destinations\(cursor: \$cursor\) \{\s+nextCursor totalCount\s+entities \{ id name type properties \{ key value \} \}\s+error \{ details \}/);
  assert.doesNotMatch(seen[0], /active|status|isUserAuthenticated|lastSent|displayValue|createdAt|updatedAt/);
  assert.match(seen[1], /channels\(cursor: \$cursor\) \{\s+nextCursor totalCount\s+entities \{ id name type destinationId \}\s+error \{ details \}/);
  assert.doesNotMatch(seen[1], /active|status|product/);

  const alerting = await assessNewrelicAlerting(alertingClient({
    async listNotificationDestinations() {
      throw new Error("actor.account.aiNotifications.destinations returned an error: Account 111 is not entitled to notifications");
    },
  }));
  const finding = findingById(alerting, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.equal(finding.status, "manual");
  assert.match(finding.summary, /Notification destinations \(aiNotifications\.destinations\) could not be read \(.*not entitled to notifications\)/);
});

test("NewrelicApiClient falls back to a single workflows page when the cursor argument is rejected", async () => {
  const seen = [];
  const client = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async (_input, init = {}) => {
      const body = JSON.parse(init.body);
      seen.push(body.query);
      if (body.query.includes("cursor: $cursor")) {
        return jsonResponse({ errors: [{ message: 'Unknown argument "cursor" on field "AiWorkflowsAccountStitchedFields.workflows".' }] });
      }
      return jsonResponse({ data: { actor: { account: { aiWorkflows: { workflows: { nextCursor: null, totalCount: 1, entities: [{ id: "wf-1", name: "Production", workflowEnabled: true, destinationConfigurations: [], enrichments: [] }] } } } } } });
    },
  });
  const workflows = await client.listWorkflows(111);
  assert.deepEqual(workflows.items.map((workflow) => workflow.id), ["wf-1"]);
  assert.equal(workflows.complete, true);
  assert.equal(seen.length, 2);
  assert.match(seen[1], /workflows\(filters: \{\}\) \{/);
  assert.doesNotMatch(seen[1], /cursor/);
  assert.match(seen[1], /enrichments \{ id name configurations/);
  assert.doesNotMatch(seen[1], /enrichments \{ id name type/);

  const truncated = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async (_input, init = {}) => {
      const body = JSON.parse(init.body);
      if (body.query.includes("cursor: $cursor")) {
        return jsonResponse({ errors: [{ message: 'Unknown argument "cursor" on field "AiWorkflowsAccountStitchedFields.workflows".' }] });
      }
      return jsonResponse({ data: { actor: { account: { aiWorkflows: { workflows: { nextCursor: "more", totalCount: 5, entities: [{ id: "wf-1", name: "Production", workflowEnabled: true }] } } } } } });
    },
  });
  const firstPage = await truncated.listWorkflows(111);
  assert.equal(firstPage.complete, false);
  assert.match(firstPage.note, /aiWorkflows\.workflows rejected the cursor argument, so only the first page was read \(1 of 5 workflows\)/);
});

// Every identifier that may appear in a NerdGraph selection. Each entry is traceable to the docs.newrelic.com page or
// the schema type cited above the matching QUERY_* constant in newrelic.ts; anything else fails the allowlist.
const DOCUMENTED_SELECTION_TOKENS = new Set([
  "actor", "on", "query", "user", "organization", "accounts", "id", "name", "email",
  "userManagement", "authorizationManagement", "authenticationDomains", "nextCursor", "totalCount", "count",
  "provisioningType", "authenticationType", "organizationId", "users", "lastActive", "type", "displayName", "groups",
  "roles", "accountId", "scope",
  "apiAccess", "keySearch", "keys", "createdAt", "ApiAccessIngestKey", "ingestType", "ApiAccessUserKey", "userId",
  "account", "nrql", "results",
  "entitySearch", "entities", "guid", "entityType", "domain", "reporting", "tags", "key", "values",
  "AlertableEntityOutline", "alertSeverity", "DashboardEntityOutline", "permissions", "SyntheticMonitorEntityOutline",
  "monitorType", "WorkloadEntityOutline", "workloadStatus", "statusValue",
  "alerts", "policiesSearch", "policies", "incidentPreference", "nrqlConditionsSearch", "nrqlConditions", "enabled",
  "policyId",
  "aiNotifications", "destinations", "properties", "value", "error", "details", "channels", "destinationId",
  "aiWorkflows", "workflows", "workflowEnabled", "enrichmentsEnabled", "destinationsEnabled",
  "destinationConfigurations", "channelId", "notificationTriggers", "enrichments", "configurations",
  "AiWorkflowsNrqlConfiguration",
  "dataManagement", "eventRetentionRules", "namespace", "retentionInDays", "createdById", "deletedAt", "deletedById",
  "customizableRetention", "eventNamespaces",
  "logConfigurations", "obfuscationRules", "description", "filter", "updatedAt", "actions", "attributes", "method",
  "expression", "obfuscationExpressions", "regex",
  "entityManagement", "EntityManagementPipelineCloudRuleEntity",
  "nrqlDropRules", "list", "rules", "action", "createdBy", "reason",
  "synthetics", "script", "text",
  "dashboard", "liveUrls", "title", "errors",
]);

// Fields the compliance review found in no public New Relic documentation; they must never be requested again.
const UNDOCUMENTED_FIELDS = [
  "emailVerificationState", "timeZone", "dashboardParentGuid", "owner", "monitoredUrl", "period", "monitorId",
  "secureCredentialId", "SecureCredentialEntityOutline", "notes", "active", "status", "isUserAuthenticated", "lastSent",
  "displayValue", "product", "url", "uuid", "roleId",
];

function selectionTokens(selection) {
  const withoutArguments = selection.replace(/\([^()]*\)/g, " ");
  return withoutArguments.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
}

test("every NerdGraph selection stays on the documented field allowlist", () => {
  assert.ok(Object.keys(NEWRELIC_NERDGRAPH_SELECTIONS).length >= 28);
  for (const [purpose, selection] of Object.entries(NEWRELIC_NERDGRAPH_SELECTIONS)) {
    const unexpected = [...new Set(selectionTokens(selection))].filter((token) => !DOCUMENTED_SELECTION_TOKENS.has(token));
    assert.deepEqual(unexpected, [], `${purpose} selects undocumented identifiers: ${unexpected.join(", ")}`);
    for (const field of UNDOCUMENTED_FIELDS) {
      assert.doesNotMatch(selection, new RegExp(`\\b${field}\\b`), `${purpose} still requests ${field}`);
    }
  }
  assert.match(NEWRELIC_NERDGRAPH_SELECTIONS.entitySearch, /\.\.\. on DashboardEntityOutline \{ permissions \}/);
  assert.match(NEWRELIC_NERDGRAPH_SELECTIONS.entitySearch, /\.\.\. on SyntheticMonitorEntityOutline \{ monitorType \}/);
  assert.match(NEWRELIC_NERDGRAPH_SELECTIONS.domainUsers, /users \{\s+id name email lastActive\s+type \{ id displayName \}/);
  assert.match(NEWRELIC_NERDGRAPH_SELECTIONS.alertPolicies, /policies \{ id name incidentPreference \}/);
  assert.match(NEWRELIC_NERDGRAPH_SELECTIONS.obfuscationRules, /expression \{ name \}/);
  assert.match(NEWRELIC_NERDGRAPH_SELECTIONS.pipelineCloudRules, /entities \{\s+id type\s+\.\.\. on EntityManagementPipelineCloudRuleEntity \{ id name nrql description enabled \}/);
  assert.doesNotMatch(NEWRELIC_NERDGRAPH_SELECTIONS.domainGroupGrants, /authorizationManagement \{\s*roles/);
});

// Fields this module attaches to stored records itself; they never come from NerdGraph.
const SYNTHESIZED_RECORD_FIELDS = new Set([
  "queriedAccountId", "authenticationDomainId", "authenticationDomainName", "provisioningType", "rolesReadable",
]);

// NRQL result rows and rows this module builds are keyed by the SELECT clause or by the builder, not by a NerdGraph selection.
const NON_NERDGRAPH_SHAPES = new Set([
  "apiKeyActorEvents", "apiKeyChangeEvents", "syntheticScriptScan", "logVolume", "logSecretMatches", "infraHostCounts", "infraAgentVersions",
]);

const SHAPE_SELECTION_SOURCES = {
  organization: ["organization"],
  currentUser: ["currentUser"],
  accounts: ["accounts"],
  authenticationDomains: ["authenticationDomains"],
  organizationAuthenticationDomains: ["organizationAuthenticationDomainFields"],
  users: ["domainUsers"],
  groupGrants: ["domainGroupGrants"],
  roles: ["roleCatalogFields"],
  apiKeys: ["apiKeys"],
  alertPolicies: ["alertPolicies"],
  nrqlConditions: ["nrqlConditions"],
  destinations: ["destinations"],
  channels: ["channels"],
  workflows: ["workflows"],
  entities: ["entitySearch"],
  retentionRules: ["retentionRules"],
  retentionNamespaces: ["retentionNamespaces"],
  obfuscationRules: ["obfuscationRules"],
  obfuscationExpressions: ["obfuscationExpressions"],
  pipelineCloudRules: ["pipelineCloudRules"],
  nrqlDropRules: ["nrqlDropRules"],
  dashboardLiveUrls: ["dashboardLiveUrls"],
};

function shapeFieldNames(shape) {
  return Object.entries(shape).flatMap(([field, fieldShape]) =>
    typeof fieldShape === "object" ? [field, ...shapeFieldNames(fieldShape)] : [field],
  );
}

test("bundle secret hygiene: every stored record shape names only fields its NerdGraph selection requests", () => {
  const shapeNames = Object.keys(NEWRELIC_STORED_RECORD_SHAPES);
  assert.deepEqual(
    shapeNames.filter((name) => !NON_NERDGRAPH_SHAPES.has(name)).sort(),
    Object.keys(SHAPE_SELECTION_SOURCES).sort(),
    "every NerdGraph-backed shape must map to the selection it stores",
  );
  for (const [shapeName, selectionKeys] of Object.entries(SHAPE_SELECTION_SOURCES)) {
    const selected = new Set(selectionKeys.flatMap((key) => selectionTokens(NEWRELIC_NERDGRAPH_SELECTIONS[key])));
    const stray = shapeFieldNames(NEWRELIC_STORED_RECORD_SHAPES[shapeName]).filter(
      (field) => !selected.has(field) && !SYNTHESIZED_RECORD_FIELDS.has(field),
    );
    assert.deepEqual(stray, [], `${shapeName} stores fields its selection never requests: ${stray.join(", ")}`);
  }
  for (const shapeName of NON_NERDGRAPH_SHAPES) {
    assert.ok(NEWRELIC_STORED_RECORD_SHAPES[shapeName], `${shapeName} shape is missing`);
  }
  for (const field of UNDOCUMENTED_FIELDS) {
    for (const [shapeName, shape] of Object.entries(NEWRELIC_STORED_RECORD_SHAPES)) {
      assert.equal(shapeFieldNames(shape).includes(field), false, `${shapeName} would store the undocumented field ${field}`);
    }
  }
  assert.equal(shapeFieldNames(NEWRELIC_STORED_RECORD_SHAPES.apiKeys).includes("key"), false);
  assert.equal(shapeFieldNames(NEWRELIC_STORED_RECORD_SHAPES.users).includes("passwordHash"), false);
  assert.equal(typeof NEWRELIC_STORED_RECORD_SHAPES.destinations.properties, "function");
  assert.equal("properties" in NEWRELIC_STORED_RECORD_SHAPES.channels, false);
});

test("bundle secret hygiene: projectRecord keeps selected fields and drops everything the API volunteers", () => {
  const projected = projectRecord(
    {
      id: "wf-1",
      name: "Production",
      workflowEnabled: true,
      apiToken: "PLANTED-VOLUNTEERED-TOKEN",
      destinationConfigurations: [
        { channelId: "chan-1", type: "EMAIL", notificationTriggers: ["ACTIVATED", { nested: "object" }], secret: "PLANTED" },
        "not an object",
      ],
      enrichments: null,
      queriedAccountId: 111,
      nested: { deep: "PLANTED" },
    },
    NEWRELIC_STORED_RECORD_SHAPES.workflows,
  );
  assert.deepEqual(projected, {
    id: "wf-1",
    name: "Production",
    workflowEnabled: true,
    destinationConfigurations: [{ channelId: "chan-1", type: "EMAIL", notificationTriggers: ["ACTIVATED"] }],
    enrichments: null,
    queriedAccountId: 111,
  });

  assert.deepEqual(projectRecord({ id: "u-1", lastActive: null, type: "not an object", groups: { groups: "not a list" } }, NEWRELIC_STORED_RECORD_SHAPES.users), {
    id: "u-1",
    lastActive: null,
    groups: {},
  });

  const destination = projectRecord(
    {
      id: "dest-1",
      name: "Hooks",
      type: "WEBHOOK",
      properties: [
        { key: "url", value: "https://hooks.example.com/PLANTED-TOKEN" },
        { key: "Email", value: "ops@example.com, sre@example.com" },
        { key: "headers", value: { Authorization: "Bearer PLANTED" } },
        { value: "PLANTED-KEYLESS" },
        "not an object",
      ],
    },
    NEWRELIC_STORED_RECORD_SHAPES.destinations,
  );
  assert.deepEqual(destination, {
    id: "dest-1",
    name: "Hooks",
    type: "WEBHOOK",
    properties: [{ key: "url" }, { key: "Email", value: "ops@example.com, sre@example.com" }, { key: "headers" }],
  });
});

test("NewrelicApiClient falls back to the documented group grant shape when the domain filter or cursor is rejected", async () => {
  const seen = [];
  const documentedShape = {
    data: {
      actor: {
        organization: {
          authorizationManagement: {
            authenticationDomains: {
              authenticationDomains: [
                { id: "domain-1", groups: { groups: [{ id: "g-admin", displayName: "Admins", roles: { roles: [{ id: "grant-1", name: "Organization manager", displayName: "Organization manager", type: "STANDARD", organizationId: "org-1" }] } }] } },
                { id: "domain-2", groups: { groups: [{ id: "g-read", displayName: "Readers", roles: { roles: [] } }] } },
              ],
            },
          },
        },
      },
    },
  };
  const client = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async (_input, init = {}) => {
      const body = JSON.parse(init.body);
      seen.push(body.query);
      if (body.query.includes("id: $domainId")) {
        return jsonResponse({ errors: [{ message: 'Unknown argument "id" on field "AuthorizationManagementOrganizationStitchedFields.authenticationDomains".' }] });
      }
      return jsonResponse(documentedShape);
    },
  });

  const grants = await client.listDomainGroupGrants("domain-1");
  assert.equal(seen.length, 2);
  assert.doesNotMatch(seen[1], /cursor|\$domainId|nextCursor|totalCount/);
  assert.match(seen[1], /authenticationDomains \{ authenticationDomains \{\s+id\s+groups \{\s+groups \{\s+id displayName\s+roles \{ roles \{ id name displayName type accountId organizationId \} \}/);
  assert.deepEqual(grants.items.map((group) => group.id), ["g-admin"]);
  assert.deepEqual(grants.items[0].roles.map((role) => role.name), ["Organization manager"]);
  assert.equal(grants.items[0].rolesReadable, true);
  assert.equal(grants.complete, false);
  assert.match(grants.note, /documented unpaginated shape was read \(1 groups on one page, completeness unknown\)/);

  const missing = await client.listDomainGroupGrants("domain-9");
  assert.deepEqual(missing.items, []);
  assert.equal(missing.complete, false);
  assert.match(missing.note, /did not include domain domain-9 \(2 domains returned\)/);

  const denied = new NewrelicApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ errors: [{ message: "Not authorized to query authorizationManagement" }] }),
  });
  await assert.rejects(() => denied.listDomainGroupGrants("domain-1"), /Not authorized/);
});

test("assessNewrelicAlerting fails uncovered critical entities and personal email destinations, and warns on enriched external workflows", async () => {
  const client = alertingClient({
    async searchEntities(query) {
      if (query.includes("WORKLOAD")) {
        return [{ guid: "wl-1", name: "Checkout", domain: "NR1", type: "WORKLOAD", workloadStatus: { statusValue: "DISRUPTED" } }];
      }
      return [
        { guid: "app-1", name: "checkout-api", domain: "APM", type: "APPLICATION", reporting: true, alertSeverity: "NOT_CONFIGURED" },
        { guid: "host-1", name: "ip-10-0-0-1", domain: "INFRA", type: "HOST", reporting: true, alertSeverity: "NOT_CONFIGURED" },
        { guid: "old-1", name: "retired", domain: "APM", type: "APPLICATION", reporting: false, alertSeverity: "NOT_CONFIGURED" },
      ];
    },
    async listNotificationDestinations() {
      return [
        { id: "dest-1", name: "Personal inbox", type: "EMAIL", properties: [{ key: "email", value: "oncall.person@gmail.com" }] },
        { id: "dest-2", name: "Ops Slack", type: "SLACK", properties: [] },
      ];
    },
    async listNotificationChannels() {
      return [
        { id: "chan-1", name: "Personal", type: "EMAIL", destinationId: "dest-1" },
        { id: "chan-2", name: "Ops Slack", type: "SLACK", destinationId: "dest-2" },
      ];
    },
    async listWorkflows() {
      return [
        {
          id: "wf-1",
          name: "Enriched Slack",
          workflowEnabled: true,
          enrichmentsEnabled: true,
          destinationConfigurations: [{ channelId: "chan-2", name: "Ops Slack", type: "SLACK" }],
          enrichments: [{ id: "en-1", name: "Recent errors", type: "NRQL", configurations: [{ query: "SELECT * FROM Log WHERE level = 'error'" }] }],
        },
      ];
    },
  });

  const result = await assessNewrelicAlerting(client);

  assert.equal(findingStatus(result, "NR-09-ALERT-POLICY-COVERAGE"), "fail");
  assert.equal(findingById(result, "NR-09-ALERT-POLICY-COVERAGE").evidence.uncovered_entities, 2);
  assert.deepEqual(findingById(result, "NR-09-ALERT-POLICY-COVERAGE").evidence.disrupted_workloads, ["Checkout"]);
  assert.equal(findingStatus(result, "NR-10-ALERT-NOTIFICATION-CHANNELS"), "fail");
  assert.deepEqual(findingById(result, "NR-10-ALERT-NOTIFICATION-CHANNELS").evidence.personal_email_destinations, ["Personal inbox"]);
  assert.equal(findingStatus(result, "NR-17-APPLIED-INTELLIGENCE-SENSITIVITY"), "warn");
  assert.deepEqual(findingById(result, "NR-17-APPLIED-INTELLIGENCE-SENSITIVITY").evidence.enriched_external_workflows, ["Enriched Slack"]);
});

test("assessNewrelicAlerting warns on unapproved email domains and missing workflows", async () => {
  const client = alertingClient({
    async listNotificationDestinations() {
      return [{ id: "dest-1", name: "Vendor inbox", type: "EMAIL", properties: [{ key: "email", value: "noc@vendor.example.net" }] }];
    },
    async listWorkflows() {
      return [];
    },
  });

  const result = await assessNewrelicAlerting(client, { approvedEmailDomains: ["example.com"] });
  const channels = findingById(result, "NR-10-ALERT-NOTIFICATION-CHANNELS");

  assert.equal(channels.status, "warn");
  assert.deepEqual(channels.evidence.unapproved_email_destinations, ["Vendor inbox"]);
  assert.equal(findingStatus(result, "NR-09-ALERT-POLICY-COVERAGE"), "pass");
});

test("assessNewrelicDataGovernance passes retention, obfuscation, synthetics, dashboards, and log hygiene checks", async () => {
  const result = await assessNewrelicDataGovernance(dataGovernanceClient());

  assert.equal(result.category, "data_governance");
  assert.deepEqual(result.findings.map((item) => item.control), [11, 12, 13, 14, 15, 16]);
  assert.equal(findingStatus(result, "NR-11-DATA-RETENTION"), "pass");
  assert.equal(findingStatus(result, "NR-12-LOG-OBFUSCATION"), "pass");
  assert.equal(findingStatus(result, "NR-13-SYNTHETIC-MONITOR-SECURITY"), "pass");
  assert.equal(findingById(result, "NR-13-SYNTHETIC-MONITOR-SECURITY").evidence.scripts_using_secure_credentials, 1);
  assert.equal(findingStatus(result, "NR-14-DASHBOARD-PERMISSIONS"), "pass");
  assert.equal(findingStatus(result, "NR-15-LOGS-IN-CONTEXT-SECURITY"), "pass");
  assert.equal(findingStatus(result, "NR-16-INFRA-AGENT-CONFIGURATION"), "manual");
  assert.match(findingById(result, "NR-16-INFRA-AGENT-CONFIGURATION").summary, /newrelic-infra\.yml/);
  assert.equal(findingById(result, "NR-16-INFRA-AGENT-CONFIGURATION").evidence.reporting_hosts, 4);
  assert.equal(result.errors.length, 0);
});

test("assessNewrelicDataGovernance fails short retention, missing obfuscation, hardcoded secrets, public dashboards, and leaked log secrets", async () => {
  const client = dataGovernanceClient({
    async listEventRetentionRules() {
      return [
        { id: "rule-1", namespace: "Log", retentionInDays: 7, deletedAt: null },
        { id: "rule-2", namespace: "Metric", retentionInDays: 3, deletedAt: secondsAgo(1) },
      ];
    },
    async listObfuscationRules() {
      return [];
    },
    async listObfuscationExpressions() {
      return [];
    },
    async getSyntheticScript() {
      return "const password = \"hunter2hunter2\";\nconst token = 'NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ';";
    },
    async searchEntities(query) {
      if (query.includes("DASHBOARD")) {
        return [
          { guid: "dash-1", name: "Everyone edits", domain: "VIZ", type: "DASHBOARD", permissions: "PUBLIC_READ_WRITE", accountId: 111 },
          { guid: "dash-2", name: "Private", domain: "VIZ", type: "DASHBOARD", permissions: "PRIVATE", accountId: 111 },
        ];
      }
      if (query.includes("SECURE_CRED")) return [];
      if (query.includes("MONITOR")) {
        return [{ guid: "mon-1", name: "Login flow", domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_API", accountId: 111 }];
      }
      return [];
    },
    async listDashboardLiveUrls() {
      return [
        { title: "Everyone edits", type: "DASHBOARD", createdAt: NOW },
        { title: "", type: "WIDGET", createdAt: NOW },
      ];
    },
    async runNrql(_accountId, nrql) {
      if (nrql.includes("RLIKE")) return [{ matchCount: 6 }];
      if (nrql.includes("FROM Log")) return [{ logCount: 5000 }];
      return [];
    },
    async countEntities() {
      return 0;
    },
  });

  const result = await assessNewrelicDataGovernance(client, { minRetentionDays: 30 });

  assert.equal(findingStatus(result, "NR-11-DATA-RETENTION"), "fail");
  assert.deepEqual(findingById(result, "NR-11-DATA-RETENTION").evidence.short_retention_rules, ["Log: 7 days"]);
  assert.equal(findingStatus(result, "NR-12-LOG-OBFUSCATION"), "fail");
  assert.equal(findingStatus(result, "NR-13-SYNTHETIC-MONITOR-SECURITY"), "fail");
  assert.match(findingById(result, "NR-13-SYNTHETIC-MONITOR-SECURITY").summary, /credential assignment, New Relic user key/);
  assert.equal(findingStatus(result, "NR-14-DASHBOARD-PERMISSIONS"), "fail");
  assert.equal(findingById(result, "NR-14-DASHBOARD-PERMISSIONS").evidence.public_live_urls, 2);
  assert.deepEqual(findingById(result, "NR-14-DASHBOARD-PERMISSIONS").evidence.public_dashboard_live_urls, ["Everyone edits"]);
  assert.equal(findingById(result, "NR-14-DASHBOARD-PERMISSIONS").evidence.public_widget_live_urls, 1);
  assert.match(findingById(result, "NR-14-DASHBOARD-PERMISSIONS").summary, /1 dashboards and 1 widgets are shared through public live URLs/);
  assert.deepEqual(findingById(result, "NR-14-DASHBOARD-PERMISSIONS").evidence.public_read_write_dashboards, ["Everyone edits"]);
  assert.equal(findingStatus(result, "NR-15-LOGS-IN-CONTEXT-SECURITY"), "fail");
  assert.equal(findingById(result, "NR-15-LOGS-IN-CONTEXT-SECURITY").evidence.secret_pattern_matches, 6);
  assert.equal(findingStatus(result, "NR-16-INFRA-AGENT-CONFIGURATION"), "manual");
  assert.match(findingById(result, "NR-16-INFRA-AGENT-CONFIGURATION").summary, /No reporting infrastructure hosts/);
});

test("assessNewrelicDataGovernance marks unreadable scripts and log queries as manual and records errors", async () => {
  const client = dataGovernanceClient({
    async getSyntheticScript() {
      throw new Error("NerdGraph returned errors: Not authorized (at actor.account.synthetics.script)");
    },
    async runNrql(_accountId, nrql) {
      if (nrql.includes("RLIKE")) throw new Error("NerdGraph returned errors: NRQL Syntax Error");
      if (nrql.includes("FROM Log")) return [{ logCount: 10 }];
      return [];
    },
  });

  const result = await assessNewrelicDataGovernance(client);

  assert.equal(findingStatus(result, "NR-13-SYNTHETIC-MONITOR-SECURITY"), "manual");
  assert.match(findingById(result, "NR-13-SYNTHETIC-MONITOR-SECURITY").summary, /\$secure\.NAME/);
  assert.equal(findingStatus(result, "NR-15-LOGS-IN-CONTEXT-SECURITY"), "manual");
  assert.equal(result.errors.length, 2);
  assert.ok(result.errors.some((error) => error.startsWith("synthetics.script:")));
  assert.ok(result.errors.some((error) => error.startsWith("nrql.Log.secret_patterns:")));
});

function forbiddenClient(overrides = {}) {
  const fetchImpl = async (_input, init = {}) => {
    if ((init.method ?? "GET").toUpperCase() === "POST") {
      return jsonResponse({ data: null, errors: [{ message: "Not authorized", path: ["actor"], extensions: { errorClass: "SERVER_ERROR" } }] });
    }
    return new Response(JSON.stringify({ error: { title: "Forbidden" } }), {
      status: 403,
      statusText: "Forbidden",
      headers: { "content-type": "application/json" },
    });
  };
  return new NewrelicApiClient(sampleConfig(overrides), { fetchImpl });
}

function emptyClient(overrides = {}) {
  const empty = async () => [];
  return {
    getResolvedConfig: () => sampleConfig({ accountIds: [111] }),
    async resolveAccountIds() {
      return [111];
    },
    async getCurrentUser() {
      return { id: "u-1", email: "auditor@example.com", name: "Auditor" };
    },
    async getOrganization() {
      return { id: "org-1", name: "Example Org" };
    },
    listAccounts: empty,
    listAuthenticationDomains: empty,
    listOrganizationAuthenticationDomains: empty,
    listDomainUsers: empty,
    listDomainGroupGrants: empty,
    listRoles: empty,
    listApiKeys: empty,
    listAlertPolicies: empty,
    listNrqlConditions: empty,
    listNotificationDestinations: empty,
    listNotificationChannels: empty,
    listWorkflows: empty,
    searchEntities: empty,
    async countEntities() {
      return 0;
    },
    listEventRetentionRules: empty,
    listRetentionNamespaces: empty,
    listObfuscationRules: empty,
    listObfuscationExpressions: empty,
    listPipelineCloudRules: empty,
    listNrqlDropRules: empty,
    listDashboardLiveUrls: empty,
    async getSyntheticScript() {
      return "";
    },
    async runNrql() {
      return [];
    },
    ...overrides,
  };
}

function forbidden(scope) {
  return new Error(`NerdGraph returned errors: Not authorized (at ${scope})`);
}

function twoDomains() {
  return [
    { id: "domain-1", name: "Corporate SSO", provisioningType: "SCIM" },
    { id: "domain-2", name: "Contractors", provisioningType: "SCIM" },
  ];
}

function onlyDomainOne(load) {
  return async (domainId, ...rest) => {
    if (domainId !== "domain-1") throw forbidden("actor.organization.userManagement.authenticationDomains");
    return load(domainId, ...rest);
  };
}

function onlyAccount111(load) {
  return async (accountId, ...rest) => {
    if (accountId !== 111) throw forbidden("actor.account");
    return load(accountId, ...rest);
  };
}

async function assessAll(clients, options = {}) {
  const results = [
    await assessNewrelicIdentity(clients.identity, { now: NOW, ...options.identity }),
    await assessNewrelicAccessControl(clients.accessControl, { now: NOW, ...options.accessControl }),
    await assessNewrelicAlerting(clients.alerting, options.alerting),
    await assessNewrelicDataGovernance(clients.dataGovernance, options.dataGovernance),
  ];
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  assert.deepEqual([...new Set(findings.map((item) => item.control))].sort((a, b) => a - b), Array.from({ length: 20 }, (_, index) => index + 1));
  return { results, findings };
}

function passing(findings) {
  return findings.filter((item) => item.status === "pass").map((item) => item.id);
}

test("verdict safety rule 1: NerdGraph errors alongside partial data are treated as failures, not data", async () => {
  const fetchImpl = async () => jsonResponse({
    data: { actor: { user: { id: "u-1", email: "auditor@example.com" }, organization: null } },
    errors: [{ message: "Not authorized", path: ["actor", "organization"] }],
  });
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });

  await assert.rejects(client.getCurrentUser(), /NerdGraph returned errors: Not authorized \(at actor\.organization\)/);
  await assert.rejects(client.getOrganization(), /NerdGraph returned errors/);
});

test("verdict safety rule 1 and self-check (a): forbidden NerdGraph and REST surfaces yield manual verdicts that name the cause and the evidence", async () => {
  const client = forbiddenClient();
  const { results, findings } = await assessAll({ identity: client, accessControl: client, alerting: client, dataGovernance: client });

  assert.deepEqual(passing(findings), []);
  assert.deepEqual([...new Set(findings.map((item) => item.status))], ["manual"]);
  for (const item of findings) {
    assert.match(item.summary, /Not authorized/, `${item.id} does not name the cause: ${item.summary}`);
    assert.match(item.summary, /[Cc]ollect|[Rr]ecord|[Cc]onfirm|[Rr]eview/, `${item.id} does not name the evidence: ${item.summary}`);
  }
  assert.ok(results.every((result) => result.errors.length > 0));
  assert.ok(results.every((result) => result.errors.every((error) => /Not authorized|403 Forbidden/.test(error))));

  const access = await checkNewrelicAccess(client);
  assert.equal(access.status, "limited");
  assert.ok(access.surfaces.filter((surface) => surface.required).every((surface) => surface.status === "not_readable"));
  const restUsers = access.surfaces.find((surface) => surface.name === "rest_v2_users");
  assert.equal(restUsers.status, "not_readable");
  assert.match(restUsers.error, /403 Forbidden/);
});

test("verdict safety rule 2 and self-check (b): empty inventories never pass and each summary says emptiness is unknown", async () => {
  const client = emptyClient();
  const { results, findings } = await assessAll({ identity: client, accessControl: client, alerting: client, dataGovernance: client });

  assert.deepEqual(passing(findings), []);
  assert.deepEqual(findings.filter((item) => item.status === "fail").map((item) => item.id), []);
  // Nothing failed, so the errors array carries only the disclosure of the domain-scoped queries that were skipped
  // because the domain listing returned zero domains (they surface in _errors.log the same way).
  const skippedQueryPattern = /^(userManagement\.users|authorizationManagement\.groups) was not queried for any authentication domain: userManagement\.authenticationDomains returned zero domains$/;
  assert.ok(results.every((result) => result.errors.every((error) => skippedQueryPattern.test(error))), JSON.stringify(results.map((result) => result.errors)));
  assert.deepEqual(results.map((result) => result.errors.length), [2, 2, 0, 0]);
  const emptinessControls = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 19, 20];
  for (const control of emptinessControls) {
    const item = findings.find((entry) => entry.control === control);
    assert.equal(item.status, "manual", `${item.id}: ${item.summary}`);
    assert.match(item.summary, /unknown rather than compliant|zero|No |no /, `${item.id} does not explain emptiness: ${item.summary}`);
  }
  assert.match(findings.find((item) => item.control === 12).summary, /not applicable through the API while logging stays disabled/);
  assert.match(findings.find((item) => item.control === 13).summary, /Not applicable through the API/);
  // Zero authentication domains leave the group and user queries with nothing to query, so the domain-scoped
  // inventories are not collected and the summary names the upstream query that returned nothing.
  const separation = findings.find((item) => item.control === 8);
  assert.match(separation.summary, /could not be collected \(authorizationManagement\.groups was not queried for any authentication domain: userManagement\.authenticationDomains returned zero domains\)/);
  assert.equal(separation.evidence.cross_environment_users, null);
  assert.match(separation.evidence.cross_environment_users_status, /^not collected \(userManagement\.users was not queried for any authentication domain: .*; authorizationManagement\.groups was not queried/);
  assert.match(findings.find((item) => item.control === 2).summary, /Users could not be collected \(userManagement\.users was not queried for any authentication domain: userManagement\.authenticationDomains returned zero domains\)/);
});

test("verdict safety rule 2: control 6 never passes on zero keys because a complete key listing cannot be empty", async () => {
  const clean = await assessNewrelicAccessControl(accessControlClient({ async listApiKeys() { return []; } }), { now: NOW });
  const unused = findingById(clean, "NR-06-UNUSED-API-KEYS");
  assert.equal(unused.status, "manual");
  assert.match(unused.summary, /returned zero keys for 2 accounts in scope \(111, 222\)/);
  assert.match(unused.summary, /query includes INGEST keys and every account has at least its original license key, so a complete listing cannot be empty/);
  assert.match(unused.summary, /the key cannot see the keys and is unknown rather than compliant/);
  assert.doesNotMatch(unused.summary, /Both conditions/);
  assert.equal(findingStatus(clean, "NR-04-API-KEY-INVENTORY"), "manual");
  assert.match(findingById(clean, "NR-04-API-KEY-INVENTORY").summary, /empty inventory means the key cannot see them/);
  assert.equal(findingStatus(clean, "NR-05-API-KEY-AGE"), "manual");

  const hiddenAccount = await assessNewrelicAccessControl(accessControlClient({
    async listApiKeys() { return []; },
    async listAccounts() { return [{ id: 111, name: "Payments Production" }]; },
  }), { now: NOW });
  assert.equal(findingStatus(hiddenAccount, "NR-06-UNUSED-API-KEYS"), "manual");
  assert.match(findingById(hiddenAccount, "NR-06-UNUSED-API-KEYS").summary, /Accounts 222 are also not visible to this key/);
  assert.deepEqual(findingById(hiddenAccount, "NR-06-UNUSED-API-KEYS").evidence.accounts_in_scope_not_visible, [222]);

  const fallback = await assessNewrelicAccessControl(accessControlClient({
    async listApiKeys() {
      return { items: [], complete: false, totalCount: undefined, note: "keySearch rejected the cursor argument, so only the first page was read (0 keys)" };
    },
  }), { now: NOW });
  assert.equal(findingStatus(fallback, "NR-06-UNUSED-API-KEYS"), "manual");
  assert.match(findingById(fallback, "NR-06-UNUSED-API-KEYS").summary, /listing was also incomplete/);

  const accountsUnreadable = await assessNewrelicAccessControl(accessControlClient({
    async listApiKeys() { return []; },
    async listAccounts() { throw forbidden("actor.accounts"); },
  }), { now: NOW });
  assert.equal(findingStatus(accountsUnreadable, "NR-06-UNUSED-API-KEYS"), "manual");
  assert.match(findingById(accountsUnreadable, "NR-06-UNUSED-API-KEYS").summary, /Not authorized/);
});

test("verdict safety rule 2: control 20 passes on zero custom roles only when the role listing is readable, complete, and lists standard roles", async () => {
  const clean = await assessNewrelicAccessControl(accessControlClient(), { now: NOW });
  const roles = findingById(clean, "NR-20-CUSTOM-ROLE-PERMISSIONS");
  assert.equal(roles.status, "pass");
  assert.match(roles.summary, /Both conditions for accepting this hold/);
  assert.match(roles.summary, /readable and complete/);
  assert.match(roles.summary, /returned 2 STANDARD roles/);

  const noRoles = await assessNewrelicAccessControl(accessControlClient({ async listRoles() { return []; } }), { now: NOW });
  assert.equal(findingStatus(noRoles, "NR-20-CUSTOM-ROLE-PERMISSIONS"), "manual");
  assert.match(findingById(noRoles, "NR-20-CUSTOM-ROLE-PERMISSIONS").summary, /zero roles.*unknown rather than compliant/);

  const untyped = await assessNewrelicAccessControl(accessControlClient({
    async listRoles() { return [{ id: "role-1", name: "Organization manager" }]; },
  }), { now: NOW });
  assert.equal(findingStatus(untyped, "NR-20-CUSTOM-ROLE-PERMISSIONS"), "manual");
  assert.match(findingById(untyped, "NR-20-CUSTOM-ROLE-PERMISSIONS").summary, /exposed a type other than CUSTOM or STANDARD/);

  const truncated = await assessNewrelicAccessControl(accessControlClient({
    async listRoles() { return { items: standardRoles(), complete: false, note: "stopped after 2 items with more pages available" }; },
  }), { now: NOW });
  assert.equal(findingStatus(truncated, "NR-20-CUSTOM-ROLE-PERMISSIONS"), "warn");
  assert.match(findingById(truncated, "NR-20-CUSTOM-ROLE-PERMISSIONS").summary, /role listing was incomplete/);
  assert.equal(findingById(truncated, "NR-20-CUSTOM-ROLE-PERMISSIONS").evidence.role_listing_complete, false);
});

test("verdict safety rule 3: scoped-out or not-applicable controls render as manual, never pass", async () => {
  const singleTenant = await assessNewrelicIdentity(identityClient({
    async listOrganizationAuthenticationDomains() {
      throw forbidden("customerAdministration.authenticationDomains");
    },
  }), { now: NOW });
  const sso = findingById(singleTenant, "NR-01-SSO-ENFORCEMENT");
  assert.equal(sso.status, "manual");
  assert.match(sso.summary, /scoped out of the API check and not applicable to automated verification/);
  assert.equal(sso.evidence.authentication_type_readable, false);

  const singleAccount = await assessNewrelicAccessControl(accessControlClient({
    async resolveAccountIds() { return [111]; },
    async listAccounts() { return [{ id: 111, name: "Payments Production" }]; },
  }), { now: NOW });
  assert.equal(findingStatus(singleAccount, "NR-08-CROSS-ACCOUNT-RESTRICTIONS"), "manual");
  assert.match(findingById(singleAccount, "NR-08-CROSS-ACCOUNT-RESTRICTIONS").summary, /Not applicable through the API: only one account/);

  const noPipelineControl = await assessNewrelicDataGovernance(dataGovernanceClient({
    async listPipelineCloudRules() { throw forbidden("actor.entityManagement"); },
    async searchEntities(query) {
      if (query.includes("MONITOR")) return [{ guid: "mon-1", name: "Ping", domain: "SYNTH", type: "MONITOR", monitorType: "SIMPLE", accountId: 111 }];
      if (query.includes("DASHBOARD")) return [{ guid: "dash-1", name: "Ops", domain: "VIZ", type: "DASHBOARD", permissions: "PRIVATE", accountId: 111 }];
      return [];
    },
  }));
  const obfuscation = findingById(noPipelineControl, "NR-12-LOG-OBFUSCATION");
  assert.equal(obfuscation.status, "warn");
  assert.match(obfuscation.summary, /attribute drop coverage is unverified because Pipeline Control cloud rules \(entityManagement\.pipelineCloudRules\) were not readable/);
  assert.match(obfuscation.summary, /^Partial view: Pipeline Control cloud rules: unreadable \(entityManagement\.pipelineCloudRules: NerdGraph returned errors: Not authorized \(at actor\.entityManagement\)\)\. A dataset this finding depends on was unreadable, so the verdict is limited to warn instead of pass\. Within the readable data: /);
  assert.match(obfuscation.evidence.pipeline_cloud_rules_status, /^unreadable \(entityManagement\.pipelineCloudRules: /);
  assert.equal(obfuscation.evidence.pipeline_cloud_rules, null);
  assert.equal(obfuscation.evidence.attribute_drop_rules, null);
  assert.match(obfuscation.evidence.attribute_drop_rules_status, /^unreadable \(entityManagement\.pipelineCloudRules: /);
  const synthetics = findingById(noPipelineControl, "NR-13-SYNTHETIC-MONITOR-SECURITY");
  assert.equal(synthetics.status, "manual");
  assert.match(synthetics.summary, /Not applicable through the API: none of the 1 synthetic monitors is scripted/);
  assert.equal(findingStatus(noPipelineControl, "NR-16-INFRA-AGENT-CONFIGURATION"), "manual");
  assert.equal(findingStatus(noPipelineControl, "NR-14-DASHBOARD-PERMISSIONS"), "pass");
});

test("verdict safety rule 4: items without dates are bucketed separately and cap the verdict at warn", async () => {
  const identity = await assessNewrelicIdentity(identityClient({
    async listDomainUsers() {
      return [
        user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"], lastActive: null }),
        user("bob", { type: "BASIC", groups: ["g-dev"], lastActive: null }),
      ];
    },
  }), { now: NOW });
  const userTypes = findingById(identity, "NR-02-USER-TYPE-LEAST-PRIVILEGE");
  assert.equal(userTypes.status, "warn");
  assert.match(userTypes.summary, /1 of them have no lastActive value/);
  assert.deepEqual(userTypes.evidence.undated_full_platform_users, ["alice@example.com"]);
  const inactive = findingById(identity, "NR-19-INACTIVE-USER-ACCOUNTS");
  assert.equal(inactive.status, "warn");
  assert.match(inactive.summary, /2 users have no lastActive value and cannot be counted as active/);
  assert.deepEqual(inactive.evidence.never_active_users, ["alice@example.com", "bob@example.com"]);
  assert.equal(inactive.evidence.inactive_users, 0);

  const someUndated = await assessNewrelicAccessControl(accessControlClient({
    async listApiKeys() {
      return [
        { id: "key-1", name: "ci-deploy", type: "USER", createdAt: secondsAgo(10), userId: "bob", accountId: 111 },
        { id: "key-2", name: "legacy", type: "USER", createdAt: null, userId: "bob", accountId: 111 },
      ];
    },
  }), { now: NOW });
  const age = findingById(someUndated, "NR-05-API-KEY-AGE");
  assert.equal(age.status, "warn");
  assert.match(age.summary, /1\/2 keys have no createdAt value and cannot be counted as rotated/);
  assert.deepEqual(age.evidence.keys_without_created_at, ["legacy"]);

  const allUndated = await assessNewrelicAccessControl(accessControlClient({
    async listApiKeys() {
      return [{ id: "key-1", name: "ci-deploy", type: "USER", userId: "bob", accountId: 111 }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(allUndated, "NR-05-API-KEY-AGE"), "manual");
  assert.match(findingById(allUndated, "NR-05-API-KEY-AGE").summary, /createdAt \(.*\) was not exposed for any of the 1 keys/);

  const undatedOwner = await assessNewrelicAccessControl(accessControlClient({
    async listDomainUsers() {
      return [user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }), user("bob", { type: "BASIC", groups: ["g-dev"], lastActive: null })];
    },
  }), { now: NOW });
  const unused = findingById(undatedOwner, "NR-06-UNUSED-API-KEYS");
  assert.equal(unused.status, "warn");
  assert.match(unused.summary, /1 belong to users with no lastActive value/);
  assert.deepEqual(unused.evidence.undated_owner_user_keys, ["ci-deploy"]);
});

test("verdict safety rule 5: the keySearch single-page fallback downgrades every key-hygiene verdict to warn", async () => {
  const result = await assessNewrelicAccessControl(accessControlClient({
    async listApiKeys() {
      return {
        items: [
          { id: "key-1", name: "ci-deploy", type: "USER", createdAt: secondsAgo(10), userId: "bob", accountId: 111 },
          { id: "key-2", name: "license-prod", type: "INGEST", ingestType: "LICENSE", createdAt: secondsAgo(20), accountId: 111 },
        ],
        complete: false,
        totalCount: 7,
        note: "keySearch rejected the cursor argument, so only the first page was read (2 of 7 keys)",
      };
    },
  }), { now: NOW });

  for (const id of ["NR-04-API-KEY-INVENTORY", "NR-05-API-KEY-AGE"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "warn", `${id}: ${item.summary}`);
    assert.match(item.summary, /limited to warn instead of pass/);
    assert.match(item.summary, /Partial view: API keys: 2 of 7 seen before pagination stopped; apiAccess\.keySearch: keySearch rejected the cursor argument/);
    assert.equal(item.evidence.key_listing_complete, false);
  }
  assert.equal(findingById(result, "NR-04-API-KEY-INVENTORY").evidence.keys_reported_total, 7);
  assert.equal(findingStatus(result, "NR-06-UNUSED-API-KEYS"), "manual");
  assert.match(findingById(result, "NR-06-UNUSED-API-KEYS").summary, /Partial view: API keys: 2 of 7 seen/);
  assert.ok(result.coverage.some((note) => /keySearch rejected the cursor argument/.test(note)));
});

test("verdict safety rule 5: sampled scripts at the limit, truncated entitySearch, and a hidden in-scope account flag partial views", async () => {
  const sampled = await assessNewrelicDataGovernance(dataGovernanceClient({
    async searchEntities(query) {
      if (query.includes("SECURE_CRED")) return [{ guid: "cred-1", name: "LOGIN_PASSWORD", domain: "SYNTH", type: "SECURE_CRED", accountId: 111 }];
      if (query.includes("MONITOR")) {
        return [
          { guid: "mon-1", name: "Login flow", domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_BROWSER", accountId: 111 },
          { guid: "mon-2", name: "Checkout flow", domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_API", accountId: 111 },
        ];
      }
      if (query.includes("DASHBOARD")) return [{ guid: "dash-1", name: "Ops", domain: "VIZ", type: "DASHBOARD", permissions: "PRIVATE", accountId: 111 }];
      return [];
    },
  }), { scriptSampleLimit: 1 });
  const synthetics = findingById(sampled, "NR-13-SYNTHETIC-MONITOR-SECURITY");
  assert.equal(synthetics.status, "warn");
  assert.match(synthetics.summary, /1 of 2 scripted monitors were sampled/);
  assert.match(synthetics.summary, /only 1 of 2 scripted monitors were sampled \(script_sample_limit 1\)/);
  assert.equal(synthetics.evidence.scripts_sample_complete, false);
  assert.equal(synthetics.evidence.scripts_sampled, 1);

  const truncated = await assessNewrelicAlerting(alertingClient({
    async searchEntities(query) {
      if (query.includes("WORKLOAD")) return [];
      return {
        items: [{ guid: "app-1", name: "checkout-api", domain: "APM", type: "APPLICATION", reporting: true, alertSeverity: "NOT_ALERTING" }],
        complete: false,
        totalCount: 340,
        note: "stopped after 1 items with more pages available",
      };
    },
  }));
  const coverage = findingById(truncated, "NR-09-ALERT-POLICY-COVERAGE");
  assert.equal(coverage.status, "warn");
  assert.match(coverage.summary, /Partial view: alertable entities: 1 of 340 seen before pagination stopped/);
  assert.equal(coverage.evidence.alertable_entities_reported_total, 340);

  const hidden = await assessNewrelicAccessControl(accessControlClient({
    async listAccounts() { return [{ id: 111, name: "Payments Production" }]; },
  }), { now: NOW });
  for (const id of ["NR-04-API-KEY-INVENTORY", "NR-05-API-KEY-AGE", "NR-07-ACCOUNT-ACCESS-CONTROLS"]) {
    const item = findingById(hidden, id);
    assert.notEqual(item.status, "pass", `${id}: ${item.summary}`);
    assert.match(item.summary, /accounts in scope not visible to this key: 222/, `${id}: ${item.summary}`);
  }
  assert.equal(findingStatus(hidden, "NR-08-CROSS-ACCOUNT-RESTRICTIONS"), "manual");
});

test("verdict safety rule 6: verdicts read every enabling flag and treat absent flags as not enabled", async () => {
  const alerting = await assessNewrelicAlerting(alertingClient({
    async listNrqlConditions() {
      return [{ id: "cond-1", name: "Error rate", type: "STATIC", policyId: "policy-1", nrql: { query: "SELECT count(*) FROM TransactionError" } }];
    },
  }));
  const policyCoverage = findingById(alerting, "NR-09-ALERT-POLICY-COVERAGE");
  assert.equal(policyCoverage.status, "fail");
  assert.match(policyCoverage.summary, /none has a NRQL condition with enabled = true \(1 conditions returned, 1 without an enabled flag\)/);
  assert.equal(policyCoverage.evidence.conditions_without_enabled_flag, 1);

  const disabledCondition = await assessNewrelicAlerting(alertingClient({
    async listNrqlConditions() {
      return [{ id: "cond-1", name: "Error rate", type: "STATIC", enabled: false, policyId: "policy-1", nrql: { query: "SELECT count(*) FROM TransactionError" } }];
    },
  }));
  assert.equal(findingStatus(disabledCondition, "NR-09-ALERT-POLICY-COVERAGE"), "fail");

  const unflaggedWorkflow = await assessNewrelicAlerting(alertingClient({
    async listWorkflows() {
      return [{ id: "wf-1", name: "Production issues", destinationConfigurations: [{ channelId: "chan-1", name: "Ops email", type: "EMAIL" }], enrichments: [] }];
    },
  }));
  const channels = findingById(unflaggedWorkflow, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.equal(channels.status, "manual");
  assert.match(channels.summary, /none of the 1 workflows exposed the documented workflowEnabled flag, so enablement cannot be verified through the API/);

  const mixedWorkflowFlags = await assessNewrelicAlerting(alertingClient({
    async listWorkflows() {
      return [
        { id: "wf-1", name: "Production issues", workflowEnabled: true, destinationConfigurations: [{ channelId: "chan-1", name: "Ops email", type: "EMAIL" }], enrichments: [] },
        { id: "wf-2", name: "Legacy", destinationConfigurations: [{ channelId: "chan-1", name: "Ops email", type: "EMAIL" }], enrichments: [] },
      ];
    },
  }));
  const mixed = findingById(mixedWorkflowFlags, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.equal(mixed.status, "warn");
  assert.match(mixed.summary, /1 workflows expose no enabled flag/);

  const untypedDestination = await assessNewrelicAlerting(alertingClient({
    async listNotificationDestinations() {
      return [{ id: "dest-1", name: "Ops distribution list", properties: [{ key: "email", value: "ops@example.com" }] }];
    },
  }));
  const destinations = findingById(untypedDestination, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.equal(destinations.status, "warn");
  assert.match(destinations.summary, /1 destinations expose no type/);

  const disabledObfuscation = await assessNewrelicDataGovernance(dataGovernanceClient({
    async listObfuscationRules() {
      return [
        { id: "obf-1", name: "Mask credentials", enabled: false, actions: [] },
        { id: "obf-2", name: "Mask PII", actions: [] },
      ];
    },
  }));
  const obfuscation = findingById(disabledObfuscation, "NR-12-LOG-OBFUSCATION");
  assert.equal(obfuscation.status, "fail");
  assert.match(obfuscation.summary, /No obfuscation rule with enabled = true exists .*\(2 rules returned, 1 without an enabled flag\)/);

  const retention = await assessNewrelicDataGovernance(dataGovernanceClient({
    async listEventRetentionRules() {
      return [
        { id: "rule-1", namespace: "Log", retentionInDays: 90, deletedAt: null },
        { id: "rule-2", namespace: "Transaction", deletedAt: null },
      ];
    },
  }));
  const retentionFinding = findingById(retention, "NR-11-DATA-RETENTION");
  assert.equal(retentionFinding.status, "warn");
  assert.match(retentionFinding.summary, /1\/2 active retention rules expose no retentionInDays value/);

  const defaults = await assessNewrelicDataGovernance(dataGovernanceClient({
    async listEventRetentionRules() {
      return [{ id: "rule-1", namespace: "Log", retentionInDays: 90, deletedAt: null }];
    },
  }));
  assert.equal(findingStatus(defaults, "NR-11-DATA-RETENTION"), "warn");
  assert.match(findingById(defaults, "NR-11-DATA-RETENTION").summary, /1\/2 customizable namespaces have no rule and rely on New Relic defaults that the API does not expose \(Transaction\)/);

  const untypedUsers = await assessNewrelicIdentity(identityClient({
    async listDomainUsers() {
      return [{ id: "alice", email: "alice@example.com", lastActive: secondsAgo(1), groups: { groups: [{ id: "g-admin" }] } }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(untypedUsers, "NR-02-USER-TYPE-LEAST-PRIVILEGE"), "warn");
  assert.match(findingById(untypedUsers, "NR-02-USER-TYPE-LEAST-PRIVILEGE").summary, /1 users expose no user type/);

  const noGroupData = await assessNewrelicIdentity(identityClient({
    async listDomainUsers() {
      return [{ id: "alice", email: "alice@example.com", lastActive: secondsAgo(1), type: { id: "FULL_PLATFORM" } }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(noGroupData, "NR-03-ADMIN-MINIMIZATION"), "manual");
  assert.match(findingById(noGroupData, "NR-03-ADMIN-MINIMIZATION").summary, /Group membership was not exposed for any of the 1 users/);

  const noRoleData = await assessNewrelicIdentity(identityClient({
    async listDomainGroupGrants() {
      return [{ id: "g-admin", displayName: "Organization admins", roles: [], rolesReadable: false }, { id: "g-dev", displayName: "g-dev", roles: [], rolesReadable: false }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(noRoleData, "NR-03-ADMIN-MINIMIZATION"), "manual");
  assert.match(findingById(noRoleData, "NR-03-ADMIN-MINIMIZATION").summary, /Role grants were not exposed for any of the 2 groups/);

  const noAuthType = await assessNewrelicIdentity(identityClient({
    async listOrganizationAuthenticationDomains() {
      return [{ id: "domain-1", name: "Corporate SSO", organizationId: "org-1", provisioningType: "SCIM" }];
    },
  }), { now: NOW });
  assert.equal(findingStatus(noAuthType, "NR-01-SSO-ENFORCEMENT"), "manual");
  assert.match(findingById(noAuthType, "NR-01-SSO-ENFORCEMENT").summary, /unrecognized authenticationType \(Corporate SSO: UNKNOWN\)/);

  const grantsUnreadable = await assessNewrelicAccessControl(accessControlClient({
    async listDomainGroupGrants() { throw forbidden("actor.organization.authorizationManagement"); },
  }), { now: NOW });
  assert.equal(findingStatus(grantsUnreadable, "NR-04-API-KEY-INVENTORY"), "manual");
  assert.match(findingById(grantsUnreadable, "NR-04-API-KEY-INVENTORY").summary, /group role grants were unreadable \(authorizationManagement\.groups: /);
});

test("verdict safety rule 7: the client records truncation when it stops before nextCursor is exhausted", async () => {
  let calls = 0;
  const fetchImpl = async (_input, init = {}) => {
    calls += 1;
    const body = JSON.parse(init.body);
    const page = {
      nextCursor: `page-${calls + 1}`,
      totalCount: 10,
      users: [{ id: `user-${calls}`, email: `user-${calls}@example.com` }],
    };
    assert.deepEqual(body.variables.domainId, ["domain-1"]);
    return jsonResponse({ data: { actor: { organization: { userManagement: { authenticationDomains: { authenticationDomains: [{ users: page }] } } } } } });
  };
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });

  const users = await client.listDomainUsers("domain-1", 2);

  assert.equal(users.items.length, 2);
  assert.equal(users.complete, false);
  assert.equal(users.totalCount, 10);
  assert.match(users.note, /stopped after 2 of 10 items with more pages available \(2 item limit\)/);
  assert.equal(calls, 2);
});

function nestedData(path, leaf) {
  let value = leaf;
  for (let index = path.length - 1; index >= 0; index -= 1) {
    const segment = path[index];
    value = typeof segment === "number" ? [value] : { [segment]: value };
  }
  return value;
}

function setNested(target, path, value) {
  let current = target;
  for (const segment of path.slice(0, -1)) current = current[segment];
  current[path[path.length - 1]] = value;
}

const CURSOR_SURFACES = [
  {
    name: "userManagement.users",
    call: (client) => client.listDomainUsers("domain-1"),
    path: ["actor", "organization", "userManagement", "authenticationDomains", "authenticationDomains", 0, "users"],
    itemsKey: "users",
    item: (n) => ({ id: `user-${n}`, email: `user-${n}@example.com` }),
  },
  {
    name: "authorizationManagement.groups",
    call: (client) => client.listDomainGroupGrants("domain-1"),
    path: ["actor", "organization", "authorizationManagement", "authenticationDomains", "authenticationDomains", 0, "groups"],
    itemsKey: "groups",
    item: (n) => ({ id: `group-${n}`, displayName: `Group ${n}`, roles: { roles: [] } }),
  },
  {
    name: "apiAccess.keySearch",
    call: (client) => client.listApiKeys(["USER", "INGEST"]),
    path: ["actor", "apiAccess", "keySearch"],
    itemsKey: "keys",
    totalKey: "count",
    item: (n) => ({ id: `key-${n}`, name: `key-${n}`, type: "USER", userId: n, accountId: 111 }),
  },
  {
    name: "entitySearch",
    call: (client) => client.searchEntities("type = 'DASHBOARD'"),
    path: ["actor", "entitySearch", "results"],
    itemsKey: "entities",
    totalPath: ["actor", "entitySearch", "count"],
    item: (n) => ({ guid: `entity-${n}`, name: `entity-${n}` }),
  },
  {
    name: "alerts.policiesSearch",
    call: (client) => client.listAlertPolicies(111),
    path: ["actor", "account", "alerts", "policiesSearch"],
    itemsKey: "policies",
    item: (n) => ({ id: `policy-${n}`, name: `Policy ${n}` }),
  },
  {
    name: "alerts.nrqlConditionsSearch",
    call: (client) => client.listNrqlConditions(111),
    path: ["actor", "account", "alerts", "nrqlConditionsSearch"],
    itemsKey: "nrqlConditions",
    item: (n) => ({ id: `cond-${n}`, name: `Condition ${n}`, enabled: true, policyId: "policy-1" }),
  },
  {
    name: "aiNotifications.destinations",
    call: (client) => client.listNotificationDestinations(111),
    path: ["actor", "account", "aiNotifications", "destinations"],
    itemsKey: "entities",
    item: (n) => ({ id: `dest-${n}`, name: `Destination ${n}`, type: "EMAIL", properties: [] }),
  },
  {
    name: "aiNotifications.channels",
    call: (client) => client.listNotificationChannels(111),
    path: ["actor", "account", "aiNotifications", "channels"],
    itemsKey: "entities",
    item: (n) => ({ id: `chan-${n}`, name: `Channel ${n}`, type: "EMAIL", destinationId: `dest-${n}` }),
  },
  {
    name: "aiWorkflows.workflows",
    call: (client) => client.listWorkflows(111),
    path: ["actor", "account", "aiWorkflows", "workflows"],
    itemsKey: "entities",
    item: (n) => ({ id: `wf-${n}`, name: `Workflow ${n}`, workflowEnabled: true }),
  },
  {
    name: "customerAdministration.authenticationDomains",
    call: (client) => client.listOrganizationAuthenticationDomains("org-1"),
    path: ["customerAdministration", "authenticationDomains"],
    itemsKey: "items",
    item: (n) => ({ id: `domain-${n}`, name: `Domain ${n}` }),
  },
  {
    name: "customerAdministration.roles",
    call: (client) => client.listRoles("org-1"),
    path: ["customerAdministration", "roles"],
    itemsKey: "items",
    item: (n) => ({ id: `role-${n}`, name: `Role ${n}`, scope: "account", type: "STANDARD" }),
  },
];

function cursorSurfaceClient(surface, pages) {
  let calls = 0;
  const fetchImpl = async () => {
    const page = pages[Math.min(calls, pages.length - 1)];
    calls += 1;
    const pageObject = { nextCursor: page.nextCursor ?? null, [surface.itemsKey]: page.items };
    if (surface.totalPath === undefined) pageObject[surface.totalKey ?? "totalCount"] = page.total;
    const data = nestedData(surface.path, pageObject);
    if (surface.totalPath !== undefined) setNested(data, surface.totalPath, page.total);
    return jsonResponse({ data });
  };
  return { client: new NewrelicApiClient(sampleConfig(), { fetchImpl }), calls: () => calls };
}

test("verdict safety rule 10: a cursor that stops advancing is reported as truncated on every paginated surface", async () => {
  for (const surface of CURSOR_SURFACES) {
    const { client, calls } = cursorSurfaceClient(surface, [
      { items: [surface.item(1), surface.item(2)], nextCursor: "page-2", total: 10 },
      { items: [surface.item(3), surface.item(4)], nextCursor: "page-2", total: 10 },
    ]);
    const result = await surface.call(client);
    assert.equal(calls(), 2, `${surface.name}: the walk must stop once the cursor repeats`);
    assert.equal(result.items.length, 4, surface.name);
    assert.equal(result.complete, false, `${surface.name} reported complete on a stalled cursor`);
    assert.equal(result.totalCount, 10, surface.name);
    assert.match(result.note, /stopped after 4 of 10 items because the next cursor did not advance/, surface.name);
  }
});

test("verdict safety rule 10: an empty page beside a next cursor is reported as truncated on every paginated surface", async () => {
  for (const surface of CURSOR_SURFACES) {
    const { client, calls } = cursorSurfaceClient(surface, [
      { items: [surface.item(1), surface.item(2)], nextCursor: "page-2", total: 10 },
      { items: [], nextCursor: "page-3", total: 10 },
    ]);
    const result = await surface.call(client);
    assert.equal(calls(), 2, surface.name);
    assert.equal(result.items.length, 2, surface.name);
    assert.equal(result.complete, false, `${surface.name} reported complete on an empty page with a next cursor`);
    assert.match(result.note, /stopped after 2 of 10 items because a page returned no items while a next cursor was reported/, surface.name);
  }
});

test("verdict safety rule 10: a listing that ends short of its reported total is truncated on every paginated surface", async () => {
  for (const surface of CURSOR_SURFACES) {
    const { client, calls } = cursorSurfaceClient(surface, [{ items: [surface.item(1)], nextCursor: null, total: 40 }]);
    const result = await surface.call(client);
    assert.equal(calls(), 1, surface.name);
    assert.equal(result.items.length, 1, surface.name);
    assert.equal(result.complete, false, `${surface.name} reported complete with 1 of 40 items`);
    assert.equal(result.totalCount, 40, surface.name);
    assert.match(result.note, /1 of 40 items seen before the listing ended without a next cursor/, surface.name);

    const consistent = cursorSurfaceClient(surface, [{ items: [surface.item(1)], nextCursor: null, total: 1 }]);
    const complete = await surface.call(consistent.client);
    assert.equal(complete.complete, true, `${surface.name} must stay complete when the total matches`);
    assert.equal(complete.note, undefined, surface.name);
  }
});

test("verdict safety rule 10: a page larger than the item limit is truncated even without a next cursor", async () => {
  const fetchImpl = async () => jsonResponse({
    data: nestedData(["actor", "account", "alerts", "policiesSearch"], {
      nextCursor: null,
      totalCount: 3,
      policies: [{ id: "policy-1", name: "A" }, { id: "policy-2", name: "B" }, { id: "policy-3", name: "C" }],
    }),
  });
  const client = new NewrelicApiClient(sampleConfig(), { fetchImpl });

  const policies = await client.listAlertPolicies(111, 2);

  assert.equal(policies.items.length, 2);
  assert.equal(policies.complete, false);
  assert.match(policies.note, /stopped after 2 of 3 items with more pages available \(2 item limit\)/);

  const restFetch = async () => jsonResponse({ users: [{ id: 1 }, { id: 2 }, { id: 3 }] });
  const restClient = new NewrelicApiClient(sampleConfig(), { fetchImpl: restFetch });
  const restUsers = await restClient.listRestUsers(2);
  assert.equal(restUsers.items.length, 2);
  assert.equal(restUsers.complete, false);
  assert.match(restUsers.note, /stopped after 2 items at the 2 item limit with more items available/);
});

test("verdict safety rule 10: destinations behind a repeating cursor limit control 10 to warn", async () => {
  const destination = (n) => ({ id: `dest-${n}`, name: `Ops ${n}`, type: "EMAIL", properties: [{ key: "email", value: "ops@example.com" }] });
  const destinationsClient = (pages) => {
    let calls = 0;
    const fetchImpl = async () => {
      const page = pages[Math.min(calls, pages.length - 1)];
      calls += 1;
      return jsonResponse({
        data: nestedData(["actor", "account", "aiNotifications", "destinations"], {
          nextCursor: page.nextCursor,
          totalCount: page.total,
          entities: page.items,
          error: null,
        }),
      });
    };
    return new NewrelicApiClient(sampleConfig({ accountIds: [111] }), { fetchImpl });
  };

  const consistent = destinationsClient([
    { items: [destination(1), destination(2)], nextCursor: "page-2", total: 4 },
    { items: [destination(3), destination(4)], nextCursor: null, total: 4 },
  ]);
  const baseline = await assessNewrelicAlerting(alertingClient({
    listNotificationDestinations: (accountId) => consistent.listNotificationDestinations(accountId),
  }));
  assert.equal(findingStatus(baseline, "NR-10-ALERT-NOTIFICATION-CHANNELS"), "pass");

  const stalled = destinationsClient([
    { items: [destination(1), destination(2)], nextCursor: "page-2", total: 10 },
    { items: [destination(3), destination(4)], nextCursor: "page-2", total: 10 },
  ]);
  const result = await assessNewrelicAlerting(alertingClient({
    listNotificationDestinations: (accountId) => stalled.listNotificationDestinations(accountId),
  }));
  const channels = findingById(result, "NR-10-ALERT-NOTIFICATION-CHANNELS");
  assert.equal(channels.status, "warn");
  assert.match(channels.summary, /Partial view: destinations: 4 of 10 seen before pagination stopped/);
  assert.match(channels.summary, /account 111: stopped after 4 of 10 items because the next cursor did not advance/);
  assert.equal(result.summary.destinations, 4);
});

test("verdict safety rule 10: policiesSearch returning fewer policies than its total limits control 9 to warn", async () => {
  const policiesClient = (total) => new NewrelicApiClient(sampleConfig({ accountIds: [111] }), {
    fetchImpl: async () => jsonResponse({
      data: nestedData(["actor", "account", "alerts", "policiesSearch"], {
        nextCursor: null,
        totalCount: total,
        policies: [{ id: "policy-1", name: "Production", incidentPreference: "PER_CONDITION_AND_TARGET" }],
      }),
    }),
  });

  const consistent = policiesClient(1);
  const baseline = await assessNewrelicAlerting(alertingClient({ listAlertPolicies: (accountId) => consistent.listAlertPolicies(accountId) }));
  assert.equal(findingStatus(baseline, "NR-09-ALERT-POLICY-COVERAGE"), "pass");

  const short = policiesClient(40);
  const result = await assessNewrelicAlerting(alertingClient({ listAlertPolicies: (accountId) => short.listAlertPolicies(accountId) }));
  const coverage = findingById(result, "NR-09-ALERT-POLICY-COVERAGE");
  assert.equal(coverage.status, "warn");
  assert.match(coverage.summary, /Partial view: alert policies: 1 of 40 seen before pagination stopped/);
  assert.match(coverage.summary, /1 of 40 items seen before the listing ended without a next cursor/);
});

test("verdict safety rule 7: a truncated user or entity population downgrades passing verdicts to warn", async () => {
  const identity = await assessNewrelicIdentity(identityClient({
    async listDomainUsers() {
      return {
        items: [user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }), user("bob", { type: "BASIC", groups: ["g-dev"] })],
        complete: false,
        totalCount: 250,
        note: "stopped after 2 items with more pages available",
      };
    },
  }), { now: NOW });

  for (const id of ["NR-02-USER-TYPE-LEAST-PRIVILEGE", "NR-03-ADMIN-MINIMIZATION", "NR-19-INACTIVE-USER-ACCOUNTS"]) {
    const item = findingById(identity, id);
    assert.equal(item.status, "warn", `${id}: ${item.summary}`);
    assert.match(item.summary, /Partial view: users: 2 of 250 seen before pagination stopped/);
  }
  assert.equal(findingStatus(identity, "NR-01-SSO-ENFORCEMENT"), "pass");
  assert.deepEqual(identity.coverage, ["users: 2 of 250 seen before pagination stopped; userManagement.users: authentication domain Corporate SSO: stopped after 2 items with more pages available"]);
  assert.equal(identity.summary.coverage_limitations, 1);

  const dashboards = await assessNewrelicDataGovernance(dataGovernanceClient({
    async searchEntities(query) {
      if (query.includes("DASHBOARD")) {
        return { items: [{ guid: "dash-1", name: "Ops", domain: "VIZ", type: "DASHBOARD", permissions: "PRIVATE", accountId: 111 }], complete: false, totalCount: 90, note: "stopped after 1 items with more pages available" };
      }
      if (query.includes("SECURE_CRED")) return [{ guid: "cred-1", name: "LOGIN_PASSWORD", domain: "SYNTH", type: "SECURE_CRED", accountId: 111 }];
      if (query.includes("MONITOR")) return [{ guid: "mon-1", name: "Login flow", domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_BROWSER", accountId: 111 }];
      return [];
    },
  }));
  const permissions = findingById(dashboards, "NR-14-DASHBOARD-PERMISSIONS");
  assert.equal(permissions.status, "warn");
  assert.match(permissions.summary, /Partial view: dashboards: 1 of 90 seen before pagination stopped/);
  assert.equal(permissions.evidence.dashboards_reported_total, 90);
});

test("false-pass self-check (c): a partial inventory never yields pass in any assess tool", async () => {
  const identity = identityClient({
    async listAuthenticationDomains() {
      return twoDomains();
    },
    async listOrganizationAuthenticationDomains() {
      return {
        items: [
          { id: "domain-1", name: "Corporate SSO", organizationId: "org-1", provisioningType: "SCIM", authenticationType: "SAML_SSO" },
          { id: "domain-2", name: "Contractors", organizationId: "org-1", provisioningType: "SCIM", authenticationType: "SAML_SSO" },
        ],
        complete: false,
        note: "customerAdministration.authenticationDomains returned more pages than were read",
      };
    },
    listDomainUsers: onlyDomainOne(async () => [user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }), user("bob", { type: "BASIC", groups: ["g-dev"] })]),
    listDomainGroupGrants: onlyDomainOne(async () => [orgManagerGroup(), accountGroup("g-dev", [222])]),
  });
  const accessControl = accessControlClient({
    async listAuthenticationDomains() {
      return twoDomains();
    },
    async listAccounts() {
      return [{ id: 111, name: "Payments Production" }];
    },
    listDomainUsers: onlyDomainOne(async () => [user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }), user("bob", { type: "BASIC", groups: ["g-dev"] })]),
    listDomainGroupGrants: onlyDomainOne(async () => [orgManagerGroup(), accountGroup("g-dev", [222])]),
    async listApiKeys() {
      return {
        items: [{ id: "key-1", name: "ci-deploy", type: "USER", createdAt: secondsAgo(10), userId: "bob", accountId: 111 }],
        complete: false,
        totalCount: 4,
        note: "keySearch rejected the cursor argument, so only the first page was read (1 of 4 keys)",
      };
    },
    async listRoles() {
      return { items: standardRoles(), complete: false, note: "stopped after 2 items with more pages available" };
    },
  });
  const baseAlerting = alertingClient();
  const alerting = alertingClient({
    getResolvedConfig: () => sampleConfig({ accountIds: [111, 222] }),
    async resolveAccountIds() {
      return [111, 222];
    },
    listAlertPolicies: onlyAccount111(baseAlerting.listAlertPolicies),
    listNrqlConditions: onlyAccount111(baseAlerting.listNrqlConditions),
    listNotificationDestinations: onlyAccount111(baseAlerting.listNotificationDestinations),
    listNotificationChannels: onlyAccount111(baseAlerting.listNotificationChannels),
    listWorkflows: onlyAccount111(baseAlerting.listWorkflows),
    async searchEntities(query) {
      if (query.includes("accountId = 222")) throw forbidden("actor.entitySearch");
      if (query.includes("WORKLOAD")) return [];
      return {
        items: [{ guid: "app-1", name: "checkout-api", domain: "APM", type: "APPLICATION", reporting: true, alertSeverity: "NOT_ALERTING" }],
        complete: false,
        totalCount: 120,
        note: "stopped after 1 items with more pages available",
      };
    },
  });
  const baseGovernance = dataGovernanceClient();
  const dataGovernance = dataGovernanceClient({
    getResolvedConfig: () => sampleConfig({ accountIds: [111, 222] }),
    async resolveAccountIds() {
      return [111, 222];
    },
    listEventRetentionRules: onlyAccount111(baseGovernance.listEventRetentionRules),
    listRetentionNamespaces: onlyAccount111(baseGovernance.listRetentionNamespaces),
    listObfuscationRules: onlyAccount111(baseGovernance.listObfuscationRules),
    listObfuscationExpressions: onlyAccount111(baseGovernance.listObfuscationExpressions),
    listNrqlDropRules: onlyAccount111(baseGovernance.listNrqlDropRules),
    async searchEntities(query) {
      if (query.includes("accountId = 222")) throw forbidden("actor.entitySearch");
      if (query.includes("MONITOR")) {
        return [
          { guid: "mon-1", name: "Login flow", domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_BROWSER", accountId: 111 },
          { guid: "mon-2", name: "Checkout flow", domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_API", accountId: 111 },
        ];
      }
      return baseGovernance.searchEntities(query);
    },
    async countEntities(query) {
      if (query.includes("accountId = 222")) throw forbidden("actor.entitySearch");
      return 4;
    },
    async runNrql(accountId, nrql) {
      if (accountId !== 111) throw forbidden("actor.account.nrql");
      return baseGovernance.runNrql(accountId, nrql);
    },
  });

  const { results, findings } = await assessAll(
    { identity, accessControl, alerting, dataGovernance },
    { dataGovernance: { scriptSampleLimit: 1 } },
  );

  assert.deepEqual(passing(findings), []);
  assert.deepEqual(findings.filter((item) => item.status === "fail").map((item) => item.id), []);
  const partialControls = [1, 2, 3, 4, 5, 7, 9, 10, 11, 12, 14, 15];
  for (const control of partialControls) {
    const item = findings.find((entry) => entry.control === control);
    assert.equal(item.status, "warn", `${item.id}: ${item.summary}`);
    assert.match(item.summary, /Partial view: /, `${item.id}: ${item.summary}`);
  }
  assert.match(findings.find((item) => item.control === 2).summary, /Partial view: users: 1 scope unreadable \(userManagement\.users: authentication domain Contractors: NerdGraph returned errors: Not authorized/);
  assert.match(findings.find((item) => item.control === 4).summary, /keySearch rejected the cursor argument/);
  assert.match(findings.find((item) => item.control === 4).summary, /accounts in scope not visible to this key: 222/);
  assert.match(findings.find((item) => item.control === 9).summary, /alertable entities: 1 seen before pagination stopped; 1 scope unreadable/);
  assert.match(findings.find((item) => item.control === 9).summary, /account 111: stopped after 1 items with more pages available/);
  assert.match(findings.find((item) => item.control === 9).summary, /account 222: NerdGraph returned errors: Not authorized/);
  assert.match(findings.find((item) => item.control === 13).summary, /1 of 2 scripted monitors were sampled/);
  assert.equal(findings.find((item) => item.control === 20).status, "warn");
  assert.ok(results.every((result) => result.coverage.length > 0));
  assert.ok(results.every((result) => result.errors.length > 0));
});

// Rule 1 corollary fixtures: two accounts (111 production, 222 development), two SCIM/SAML authentication domains
// (Corporate SSO and Contractors), one scripted monitor per account, and every pass-capable finding passing at
// baseline. Denials throw the same pathed NerdGraph error the client raises for a null field beside an errors entry.
const COROLLARY_ACCOUNT_IDS = [111, 222];
const COROLLARY_DOMAIN_USERS = {
  "domain-1": () => [user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }), user("bob", { type: "BASIC", groups: ["g-dev"] })],
  "domain-2": () => [user("dave", { type: "BASIC", groups: ["g-contractors"] })],
};
const COROLLARY_DOMAIN_GROUPS = {
  "domain-1": () => [orgManagerGroup(), accountGroup("g-dev", [222])],
  "domain-2": () => [accountGroup("g-contractors", [222])],
};
const SECURE_SCRIPT = "const password = $secure.LOGIN_PASSWORD;\n$browser.get('https://example.com/login');";

function corollaryClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig({ accountIds: COROLLARY_ACCOUNT_IDS }),
    async resolveAccountIds() {
      return COROLLARY_ACCOUNT_IDS;
    },
    async getCurrentUser() {
      return { id: "u-1", email: "auditor@example.com", name: "Auditor" };
    },
    async getOrganization() {
      return { id: "org-1", name: "Example Org" };
    },
    async listAccounts() {
      return [{ id: 111, name: "Payments Production" }, { id: 222, name: "Payments Development" }];
    },
    async listAuthenticationDomains() {
      return twoDomains();
    },
    async listOrganizationAuthenticationDomains() {
      return twoDomains().map((domain) => ({ ...domain, organizationId: "org-1", authenticationType: "SAML_SSO" }));
    },
    async listDomainUsers(domainId) {
      return COROLLARY_DOMAIN_USERS[domainId]?.() ?? [];
    },
    async listDomainGroupGrants(domainId) {
      return COROLLARY_DOMAIN_GROUPS[domainId]?.() ?? [];
    },
    async listRoles(organizationId) {
      requireOrganizationId(organizationId);
      return standardRoles();
    },
    async listApiKeys() {
      return [
        { id: "key-1", name: "ci-deploy", type: "USER", createdAt: secondsAgo(10), userId: "bob", accountId: 111 },
        { id: "key-2", name: "license-prod", type: "INGEST", ingestType: "LICENSE", createdAt: secondsAgo(20), accountId: 111 },
        { id: "key-3", name: "license-dev", type: "INGEST", ingestType: "LICENSE", createdAt: secondsAgo(20), accountId: 222 },
      ];
    },
    async listAlertPolicies(accountId) {
      return [{ id: `policy-${accountId}`, name: `Policy ${accountId}`, incidentPreference: "PER_CONDITION_AND_TARGET", accountId }];
    },
    async listNrqlConditions(accountId) {
      return [{ id: `cond-${accountId}`, name: "Error rate", type: "STATIC", enabled: true, policyId: `policy-${accountId}`, nrql: { query: "SELECT count(*) FROM TransactionError" } }];
    },
    async listNotificationDestinations(accountId) {
      return [{ id: `dest-${accountId}`, name: `Ops ${accountId}`, type: "EMAIL", properties: [{ key: "email", value: "ops@example.com" }] }];
    },
    async listNotificationChannels(accountId) {
      return [{ id: `chan-${accountId}`, name: "Ops email", type: "EMAIL", destinationId: `dest-${accountId}` }];
    },
    async listWorkflows(accountId) {
      return [{
        id: `wf-${accountId}`,
        name: `Issues ${accountId}`,
        workflowEnabled: true,
        enrichmentsEnabled: false,
        destinationsEnabled: true,
        destinationConfigurations: [{ channelId: `chan-${accountId}`, name: "Ops email", type: "EMAIL" }],
        enrichments: [],
      }];
    },
    async searchEntities(query) {
      const accountId = Number(/accountId = (\d+)/.exec(query)?.[1]);
      if (query.includes("WORKLOAD")) {
        return [{ guid: `wl-${accountId}`, name: `Checkout ${accountId}`, domain: "NR1", type: "WORKLOAD", workloadStatus: { statusValue: "OPERATIONAL" }, accountId }];
      }
      if (query.includes("alertSeverity")) {
        return [{ guid: `app-${accountId}`, name: `checkout-api-${accountId}`, domain: "APM", type: "APPLICATION", entityType: "APM_APPLICATION_ENTITY", reporting: true, alertSeverity: "NOT_ALERTING", accountId }];
      }
      if (query.includes("DASHBOARD")) return [{ guid: `dash-${accountId}`, name: `Ops ${accountId}`, domain: "VIZ", type: "DASHBOARD", permissions: "PRIVATE", accountId }];
      if (query.includes("SECURE_CRED")) return [{ guid: `cred-${accountId}`, name: "LOGIN_PASSWORD", domain: "SYNTH", type: "SECURE_CRED", accountId }];
      if (query.includes("MONITOR")) return [{ guid: `mon-${accountId}`, name: `Login flow ${accountId}`, domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_BROWSER", accountId }];
      return [];
    },
    async countEntities() {
      return 2;
    },
    async getSyntheticScript() {
      return SECURE_SCRIPT;
    },
    async listEventRetentionRules(accountId) {
      return [
        { id: `rule-log-${accountId}`, namespace: "Log", retentionInDays: 90, createdAt: secondsAgo(100), deletedAt: null },
        { id: `rule-txn-${accountId}`, namespace: "Transaction", retentionInDays: 120, createdAt: secondsAgo(100), deletedAt: null },
      ];
    },
    async listRetentionNamespaces() {
      return [{ namespace: "Log" }, { namespace: "Transaction" }];
    },
    async listObfuscationRules(accountId) {
      return [{
        id: `obf-${accountId}`,
        name: "Mask credentials and PII",
        description: "Hash passwords, tokens, and email addresses",
        filter: "SELECT * FROM Log",
        enabled: true,
        actions: [{ attributes: ["message"], method: "HASH_SHA256", expression: { id: "expr-1", name: "password token" } }],
      }];
    },
    async listObfuscationExpressions() {
      return [
        { id: "expr-1", name: "password token api_key", regex: "(password|token|api_key)=\\S+", description: "Credential values" },
        { id: "expr-2", name: "email addresses", regex: "[a-z]+@[a-z]+\\.[a-z]+", description: "PII email" },
      ];
    },
    async listPipelineCloudRules() {
      return [{ id: "rule-guid-1", name: "Drop card numbers", type: "PIPELINE_CLOUD_RULE", nrql: "DELETE cardNumber FROM Log", enabled: true }];
    },
    async listNrqlDropRules(accountId) {
      return [{ id: `drop-${accountId}`, action: "DROP_ATTRIBUTES", nrql: "SELECT ssn FROM Log", accountId }];
    },
    async listDashboardLiveUrls() {
      return [];
    },
    async runNrql(_accountId, nrql) {
      if (nrql.includes("actorType = 'api_key'")) return [{ actorAPIKey: "abc123", actorType: "api_key", actionIdentifier: "alerts.policy.create", timestamp: NOW }];
      if (nrql.includes("RLIKE")) return [{ matchCount: 0 }];
      if (nrql.includes("AS logCount FROM Log")) return [{ logCount: 12_000 }];
      if (nrql.includes("SystemSample")) return [{ agentVersion: "1.60.1", hosts: 2 }];
      return [];
    },
    ...overrides,
  };
}

function controlId(number) {
  return NEWRELIC_CONTROL_CATALOG.find((control) => control.number === number).id;
}

const COROLLARY_BASELINE_PASS = [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 19, 20].map(controlId);
const NRQL_LOG_VOLUME = (nrql) => nrql.includes("AS logCount FROM Log");
const NRQL_API_KEY_ACTORS = (nrql) => nrql.includes("actorType = 'api_key'");

// Every NerdGraph query and NRQL the four collectors run, the client method that carries it, the `source` the
// collector records for it (the name every `*_status` field and coverage note uses), its scoping (per account, per
// authentication domain, or per monitor), the query path a denial reports, and the pass-capable findings that read
// it. `match` narrows shared methods (runNrql, searchEntities) to one inventory.
const COROLLARY_INVENTORIES = [
  { inventory: "actor.user", method: "getCurrentUser", source: "actor.user", path: "actor.user", dependents: [10] },
  { inventory: "actor.organization", method: "getOrganization", source: "actor.organization", path: "actor.organization", dependents: [1, 20] },
  { inventory: "actor.accounts", method: "listAccounts", source: "actor.accounts", path: "actor.accounts", dependents: [4, 5, 7, 8] },
  { inventory: "userManagement.authenticationDomains", method: "listAuthenticationDomains", source: "userManagement.authenticationDomains", path: "actor.organization.userManagement.authenticationDomains", dependents: [1, 2, 3, 4, 7, 8, 19, 20] },
  { inventory: "customerAdministration.authenticationDomains", method: "listOrganizationAuthenticationDomains", source: "customerAdministration.authenticationDomains", path: "customerAdministration.authenticationDomains", dependents: [1] },
  { inventory: "userManagement.users", method: "listDomainUsers", source: "userManagement.users", scope: "domain", path: "actor.organization.userManagement.authenticationDomains.users", dependents: [2, 3, 4, 7, 8, 19] },
  { inventory: "authorizationManagement.groups", method: "listDomainGroupGrants", source: "authorizationManagement.groups", scope: "domain", path: "actor.organization.authorizationManagement.authenticationDomains.groups", dependents: [3, 4, 7, 8, 20] },
  { inventory: "customerAdministration.roles", method: "listRoles", source: "customerAdministration.roles", path: "customerAdministration.roles", dependents: [20] },
  { inventory: "apiAccess.keySearch", method: "listApiKeys", source: "apiAccess.keySearch", path: "actor.apiAccess.keySearch", dependents: [4, 5] },
  { inventory: "NRQL NrAuditEvent actorType api_key", method: "runNrql", source: "nrql.NrAuditEvent.api_key_actor", scope: "account", match: NRQL_API_KEY_ACTORS, path: "actor.account.nrql", dependents: [] },
  { inventory: "NRQL NrAuditEvent api_key changes", method: "runNrql", source: "nrql.NrAuditEvent.api_key_changes", scope: "account", match: (nrql) => nrql.includes("actionIdentifier LIKE 'api_key%'"), path: "actor.account.nrql", dependents: [] },
  { inventory: "alerts.policiesSearch", method: "listAlertPolicies", source: "alerts.policiesSearch", scope: "account", path: "actor.account.alerts.policiesSearch", dependents: [9, 10] },
  { inventory: "alerts.nrqlConditionsSearch", method: "listNrqlConditions", source: "alerts.nrqlConditionsSearch", scope: "account", path: "actor.account.alerts.nrqlConditionsSearch", dependents: [9] },
  { inventory: "aiNotifications.destinations", method: "listNotificationDestinations", source: "aiNotifications.destinations", scope: "account", path: "actor.account.aiNotifications.destinations", dependents: [10] },
  { inventory: "aiNotifications.channels", method: "listNotificationChannels", source: "aiNotifications.channels", scope: "account", path: "actor.account.aiNotifications.channels", dependents: [10] },
  { inventory: "aiWorkflows.workflows", method: "listWorkflows", source: "aiWorkflows.workflows", scope: "account", path: "actor.account.aiWorkflows.workflows", dependents: [10] },
  { inventory: "entitySearch alertable entities", method: "searchEntities", source: "entitySearch.alertable", scope: "account", match: (query) => query.includes("alertSeverity"), path: "actor.entitySearch", dependents: [9] },
  { inventory: "entitySearch workloads", method: "searchEntities", source: "entitySearch.workloads", scope: "account", match: (query) => query.includes("WORKLOAD"), path: "actor.entitySearch", dependents: [9] },
  { inventory: "dataManagement.eventRetentionRules", method: "listEventRetentionRules", source: "dataManagement.eventRetentionRules", scope: "account", path: "actor.account.dataManagement.eventRetentionRules", dependents: [11] },
  { inventory: "dataManagement.customizableRetention", method: "listRetentionNamespaces", source: "dataManagement.customizableRetention", scope: "account", path: "actor.account.dataManagement.customizableRetention", dependents: [11] },
  { inventory: "logConfigurations.obfuscationRules", method: "listObfuscationRules", source: "logConfigurations.obfuscationRules", scope: "account", path: "actor.account.logConfigurations.obfuscationRules", dependents: [12] },
  { inventory: "logConfigurations.obfuscationExpressions", method: "listObfuscationExpressions", source: "logConfigurations.obfuscationExpressions", scope: "account", path: "actor.account.logConfigurations.obfuscationExpressions", dependents: [12] },
  { inventory: "entityManagement.pipelineCloudRules", method: "listPipelineCloudRules", source: "entityManagement.pipelineCloudRules", path: "actor.entityManagement.entitySearch", dependents: [12] },
  { inventory: "nrqlDropRules.list", method: "listNrqlDropRules", source: "nrqlDropRules.list", scope: "account", path: "actor.account.nrqlDropRules.list", dependents: [12] },
  { inventory: "entitySearch dashboards", method: "searchEntities", source: "entitySearch.dashboards", scope: "account", match: (query) => query.includes("DASHBOARD"), path: "actor.entitySearch", dependents: [14] },
  { inventory: "dashboard.liveUrls", method: "listDashboardLiveUrls", source: "dashboard.liveUrls", path: "actor.dashboard.liveUrls", dependents: [14] },
  { inventory: "entitySearch synthetic monitors", method: "searchEntities", source: "entitySearch.syntheticMonitors", scope: "account", match: (query) => query.includes("MONITOR"), path: "actor.entitySearch", dependents: [13] },
  { inventory: "entitySearch secure credentials", method: "searchEntities", source: "entitySearch.secureCredentials", scope: "account", match: (query) => query.includes("SECURE_CRED"), path: "actor.entitySearch", dependents: [13] },
  { inventory: "synthetics.script", method: "getSyntheticScript", source: "synthetics.script", scope: "monitor", path: "actor.account.synthetics.script", dependents: [13] },
  { inventory: "NRQL Log volume", method: "runNrql", source: "nrql.Log.volume", scope: "account", match: NRQL_LOG_VOLUME, path: "actor.account.nrql", dependents: [12, 15] },
  { inventory: "NRQL Log secret patterns", method: "runNrql", source: "nrql.Log.secret_patterns", scope: "account", match: (nrql) => nrql.includes("RLIKE"), path: "actor.account.nrql", dependents: [15] },
  { inventory: "entitySearch infra hosts", method: "countEntities", source: "entitySearch.infraHosts", scope: "account", path: "actor.entitySearch.count", dependents: [] },
  { inventory: "NRQL SystemSample agent versions", method: "runNrql", source: "nrql.SystemSample.agentVersion", scope: "account", match: (nrql) => nrql.includes("SystemSample"), path: "actor.account.nrql", dependents: [] },
];

const COROLLARY_SECOND_SCOPE = { account: "222", domain: "domain-2", monitor: "222" };
const COROLLARY_SCOPE_LABEL = { account: "account 222", domain: "authentication domain Contractors", monitor: "Login flow 222" };

function inventoryScopeId(row, args) {
  if (row.method === "searchEntities" || row.method === "countEntities") return /accountId = (\d+)/.exec(String(args[0]))?.[1];
  return String(args[0]);
}

/** Denies one inventory on the client: every scope (`full`) or the second account, domain, or monitor only (`partial`). */
function denyInventory(client, row, mode) {
  const base = client[row.method];
  return {
    ...client,
    async [row.method](...args) {
      const text = String(row.method === "runNrql" ? args[1] : args[0]);
      const matches = !row.match || row.match(text);
      const inScope = mode === "full" || !row.scope || inventoryScopeId(row, args) === COROLLARY_SECOND_SCOPE[row.scope];
      if (matches && inScope) throw forbidden(row.path);
      return base.apply(client, args);
    },
  };
}

function denyInventories(client, denials) {
  return denials.reduce((current, [inventory, mode]) => {
    const row = COROLLARY_INVENTORIES.find((entry) => entry.inventory === inventory);
    assert.ok(row, `unknown inventory ${inventory}`);
    return denyInventory(current, row, mode);
  }, client);
}

async function assessCorollary(denials = []) {
  const client = denyInventories(corollaryClient(), denials);
  return assessAll({ identity: client, accessControl: client, alerting: client, dataGovernance: client });
}

function belowPass(item, context) {
  assert.ok(item.status === "warn" || item.status === "manual", `${item.id} is ${item.status} ${context}: ${item.summary}`);
}

/** Wraps a fixture client so every query it receives is recorded as the collector `source` it carries. */
function recordingClient(client) {
  const requested = new Set();
  const recorded = {};
  for (const method of NEWRELIC_CLIENT_SURFACE_METHODS) {
    if (typeof client[method] !== "function") continue;
    recorded[method] = (...args) => {
      // resolveAccountIds discovers accounts through actor.accounts when none are configured.
      if (method === "resolveAccountIds") requested.add("actor.accounts");
      const text = String(method === "runNrql" ? args[1] : args[0]);
      for (const row of COROLLARY_INVENTORIES) {
        if (row.method === method && (!row.match || row.match(text))) requested.add(row.source);
      }
      return client[method](...args);
    };
  }
  return { client: recorded, requested };
}

const UNAVAILABLE_STATUS = /^(unreadable|not collected|unknown)\b/;
const NULL_COMPANION_STATUS = /^(unreadable|not collected|unknown|partial)\b/;
const COLLECTED_STATUS = /^(complete|partial|truncated)\b/;
const SOURCE_MENTION = new RegExp(
  `(?<![\\w.])(?:${[...new Set(COROLLARY_INVENTORIES.map((row) => row.source))]
    .sort((a, b) => b.length - a.length)
    .map((source) => source.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|")})(?![\\w.])`,
  "g",
);

function isFabricatedPlaceholder(value) {
  return value === 0
    || value === false
    || (Array.isArray(value) && value.length === 0)
    || (value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0);
}

/**
 * No count, list, map, or flag renders 0, [], {}, or false beside a status that says the data was unreadable, not
 * collected, unknown, or only partly readable: the companion of such a `*_status` is null, and the siblings of a
 * nested `status` marker (core_data files, summary sub-objects) carry no placeholder value.
 */
function assertNoFabricatedValues(value, label, path = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoFabricatedValues(item, label, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    assert.notEqual(entry, "unknown", `${label}: ${path}.${key} is the "unknown" placeholder`);
    if (typeof entry === "string" && key.endsWith("_status") && NULL_COMPANION_STATUS.test(entry)) {
      const base = key.slice(0, -"_status".length);
      if (base in value) assert.equal(value[base], null, `${label}: ${path}.${base} must be null beside status "${entry}"`);
    }
    if (key === "status" && typeof entry === "string" && UNAVAILABLE_STATUS.test(entry)) {
      for (const [sibling, siblingValue] of Object.entries(value)) {
        assert.ok(!isFabricatedPlaceholder(siblingValue), `${label}: ${path}.${sibling} renders ${JSON.stringify(siblingValue)} beside status "${entry}"`);
      }
    }
    assertNoFabricatedValues(entry, label, `${path}.${key}`);
  }
}

/** A status that says complete, partial, or truncated may only name queries the client actually received. */
function assertStatusesMatchRequests(value, requested, label, path = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertStatusesMatchRequests(item, requested, label, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string" && (key.endsWith("_status") || key === "status") && COLLECTED_STATUS.test(entry)) {
      for (const mention of entry.match(SOURCE_MENTION) ?? []) {
        assert.ok(requested.has(mention), `${label}: ${path}.${key} says "${entry}" but ${mention} was never requested`);
      }
    }
    assertStatusesMatchRequests(entry, requested, label, `${path}.${key}`);
  }
}

/**
 * Runs the four assessors, each on its own recording client, and checks every evidence, summary, and core_data value
 * with both guards. The request record is scoped per assessor, so a status may only name a query the assessor that
 * rendered it issued itself, not one another assessor happened to run in the same test. `requested` is the union.
 */
async function assessGuarded(client, label) {
  const recorders = [recordingClient(client), recordingClient(client), recordingClient(client), recordingClient(client)];
  const [identity, accessControl, alerting, dataGovernance] = recorders.map((recorder) => recorder.client);
  const { results, findings } = await assessAll({ identity, accessControl, alerting, dataGovernance });
  const requested = new Set();
  results.forEach((result, index) => {
    const scoped = {
      summary: result.summary,
      evidence: result.findings.map((item) => item.evidence ?? null),
      coreData: result.coreData,
    };
    assertNoFabricatedValues(scoped, `${label} (${result.category})`);
    assertStatusesMatchRequests(scoped, recorders[index].requested, `${label} (${result.category})`);
    for (const source of recorders[index].requested) requested.add(source);
  });
  const rendered = {
    summaries: results.map((result) => result.summary),
    evidence: findings.map((item) => item.evidence ?? null),
    coreData: results.map((result) => result.coreData),
  };
  return { results, findings, requested, rendered };
}

test("rule 1 corollary: the corollary baseline passes every pass-capable finding with no collection errors", async () => {
  const { results, findings, requested } = await assessGuarded(corollaryClient(), "corollary baseline");
  assert.deepEqual(passing(findings).sort(), [...COROLLARY_BASELINE_PASS].sort());
  assert.deepEqual(findings.filter((item) => item.status === "manual").map((item) => item.control).sort((a, b) => a - b), [6, 16, 17, 18]);
  assert.ok(results.every((result) => result.errors.length === 0 && result.coverage.length === 0), JSON.stringify(results.map((result) => [result.errors, result.coverage])));
  // The baseline issues every inventory in the table, so every `complete` status names a query that ran.
  assert.deepEqual([...requested].sort(), [...new Set(COROLLARY_INVENTORIES.map((row) => row.source))].sort());

  // The other compliant fixtures render no placeholder either, and the all-empty fixture's statuses only name issued queries.
  await assessGuarded(bundleClient(), "bundle baseline");
  await assessGuarded(emptyClient(), "empty fixture");
});

test("rule 1 corollary table: the per-inventory table covers exactly the collectors' client methods", () => {
  // getResolvedConfig reads local configuration and resolveAccountIds resolves the account scope through
  // actor.accounts, which the table carries under listAccounts. listRestUsers is the REST v2 probe that only
  // check_access issues, so no finding depends on it and it is excluded from the denial sweep.
  const nonQueryMethods = ["getResolvedConfig", "resolveAccountIds", "listRestUsers"];
  const collectorMethods = NEWRELIC_CLIENT_SURFACE_METHODS.filter((method) => !nonQueryMethods.includes(method));
  assert.deepEqual([...new Set(COROLLARY_INVENTORIES.map((row) => row.method))].sort(), [...collectorMethods].sort());
  assert.equal(new Set(COROLLARY_INVENTORIES.map((row) => row.source)).size, COROLLARY_INVENTORIES.length, "every row records a distinct collector source");
  for (const method of collectorMethods) assert.equal(typeof corollaryClient()[method], "function", `${method} is stubbed by the corollary fixture`);
});

test("rule 1 corollary root cause: a fully denied secondary dataset produces a coverage note and caps the verdict at warn", async () => {
  const { findings } = await assessCorollary([["alerts.policiesSearch", "full"]]);
  const channels = findings.find((item) => item.control === 10);
  assert.equal(channels.status, "warn");
  assert.match(channels.summary, /A dataset this finding depends on was unreadable, so the verdict is limited to warn instead of pass/);
  assert.match(channels.summary, /Partial view: alert policies: unreadable \(alerts\.policiesSearch: account 111, account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.alerts\.policiesSearch\)\)/);
  const coverage = findings.find((item) => item.control === 9);
  assert.equal(coverage.status, "manual", "the primary inventory of NR-09 stays manual, not warn");
  assert.match(coverage.summary, /Alert policies \(alerts\.policiesSearch\) could not be read/);
});

test("rule 1 corollary wording: compactCause keeps the dataset, status, and query path of every scope inside the 200 character budget", () => {
  const chained = "authorizationManagement.groups: authentication domains were not readable (userManagement.authenticationDomains: NerdGraph returned errors: Not authorized (at actor.organization.userManagement.authenticationDomains))";
  assert.ok(chained.length > 200);
  const compact = compactCause(chained);
  assert.ok(compact.length <= 200, `${compact.length}: ${compact}`);
  assert.match(compact, /^authorizationManagement\.groups: authentication domains were not readable \(userManagement\.authenticationDomains: /);
  assert.match(compact, /\.\.\.Not authorized \(at actor\.organization\.userManagement\.authenticationDomains\)\)$/);
  assert.match(compact, / \.\.\.Not authorized/, `the head is cut at a word boundary, not mid-token: ${compact}`);

  const twoDomainsMerged = `authorizationManagement.groups: ${["Corporate SSO", "Contractors"].map((name) => `authentication domain ${name}: NerdGraph returned errors: Not authorized (at actor.organization.authorizationManagement.authenticationDomains.groups)`).join("; ")}`;
  const mergedDomains = compactCause(twoDomainsMerged);
  assert.ok(mergedDomains.length <= 200, `${mergedDomains.length}: ${mergedDomains}`);
  assert.match(mergedDomains, /^authorizationManagement\.groups: authentication domain Corporate SSO, authentication domain Contractors: \.\.\.Not authorized \(at actor\.organization\.authorizationManagement\.authenticationDomains\.groups\)$/);

  const twoAccounts = `alerts.policiesSearch: ${[111, 222].map((id) => `account ${id}: NerdGraph returned errors: Not authorized (at actor.account.alerts.policiesSearch)`).join("; ")}`;
  assert.ok(twoAccounts.length > 200);
  assert.equal(compactCause(twoAccounts), "alerts.policiesSearch: account 111, account 222: NerdGraph returned errors: Not authorized (at actor.account.alerts.policiesSearch)");

  const manyMessages = `nrql.Log.volume: ${[1, 2, 3, 4, 5].map((id) => `account ${id}: NerdGraph returned errors: Query ${id} timed out after 60s (at actor.account.nrql)`).join("; ")}`;
  const merged = compactCause(manyMessages);
  assert.ok(merged.length <= 200, `${merged.length}: ${merged}`);
  assert.match(merged, /^nrql\.Log\.volume: account 1: NerdGraph returned errors: Query 1 timed out after 60s \(at actor\.account\.nrql\)/);
  assert.match(merged, /; \d more scopes failed and are listed in the errors array$/);
  assert.doesNotMatch(merged, /actor\.account\.n\.\.\./);

  assert.equal(compactCause("short"), "short");
  const noPath = `apiAccess.keySearch: NerdGraph request failed (403 Forbidden): ${"x".repeat(300)}`;
  const cut = compactCause(noPath);
  assert.ok(cut.length <= 200);
  assert.match(cut, /^apiAccess\.keySearch: NerdGraph request failed \(403 Forbidden\): x+\.\.\.$/);
});

test("rule 1 corollary hit 1: NR-04 never concludes no admin-owned keys on a partial or unreadable group roster", async () => {
  const partial = await assessCorollary([["authorizationManagement.groups", "partial"]]);
  const inventory = partial.findings.find((item) => item.control === 4);
  assert.equal(inventory.status, "warn");
  assert.match(inventory.summary, /the admin roster \(userManagement\.users joined to authorizationManagement\.groups\) is incomplete, so the absence of admin-owned keys is not concluded/);
  assert.match(inventory.summary, /Partial view: groups: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: NerdGraph returned errors: Not authorized \(at actor\.organization\.authorizationManagement\.authenticationDomains\.groups\)\)/);
  assert.equal(inventory.evidence.admin_owned_user_keys, null);
  assert.equal(inventory.evidence.admin_roster_complete, false);
  assert.match(inventory.evidence.admin_roster_status, /^partial: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: .*\(at actor\.organization\.authorizationManagement\.authenticationDomains\.groups\)\); complete \(userManagement\.users\)$/);
  assert.match(inventory.evidence.admin_owned_user_keys_status, /^partial: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: .*\); complete \(apiAccess\.keySearch, userManagement\.users\)$/);
  assert.equal(inventory.evidence.key_listing_complete, true);

  const full = await assessCorollary([["authorizationManagement.groups", "full"]]);
  const unreadable = full.findings.find((item) => item.control === 4);
  assert.equal(unreadable.status, "manual");
  assert.match(unreadable.summary, /group role grants were unreadable \(authorizationManagement\.groups: authentication domain Corporate SSO, authentication domain Contractors: .*Not authorized \(at actor\.organization\.authorizationManagement\.authenticationDomains\.groups\)\)/);
  assert.equal(unreadable.evidence.admin_owned_user_keys, null);
  assert.match(unreadable.evidence.admin_roster_status, /^unreadable \(authorizationManagement\.groups: /);

  const flagged = await assessNewrelicAccessControl(denyInventories(corollaryClient({
    async listApiKeys() {
      return [
        { id: "key-admin", name: "alice-cli", type: "USER", createdAt: secondsAgo(10), userId: "alice", accountId: 111 },
        { id: "key-2", name: "license-prod", type: "INGEST", ingestType: "LICENSE", createdAt: secondsAgo(20), accountId: 111 },
      ];
    },
  }), [["authorizationManagement.groups", "partial"]]), { now: NOW });
  const adminOwned = findingById(flagged, "NR-04-API-KEY-INVENTORY");
  assert.equal(adminOwned.status, "warn");
  assert.match(adminOwned.summary, /^Partial view: groups: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: /);
  assert.match(adminOwned.summary, /1 user keys \(alice-cli\) inherit admin-level permissions from their owners identified from the readable domains/, "admins visible in the readable domains are still named");
  assert.equal(adminOwned.evidence.admin_owned_user_keys, null, "the list is a lower bound from part of the domains, so the evidence field is null beside its partial status");
  assert.match(adminOwned.evidence.admin_owned_user_keys_status, /^partial: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: /);
});

test("rule 1 corollary hit 2: the NrAuditEvent api_key actor rows are owned by NR-06 and render null with a status when unreadable", async () => {
  for (const mode of ["full", "partial"]) {
    const { findings } = await assessCorollary([["NRQL NrAuditEvent actorType api_key", mode]]);
    const inventory = findings.find((item) => item.control === 4);
    assert.equal(inventory.status, "pass", `NR-04 no longer lists the audit rows (${mode}): ${inventory.summary}`);
    assert.equal("audit_events_by_api_keys" in inventory.evidence, false);
    assert.equal("audit_readable" in inventory.evidence, false);
    const unused = findings.find((item) => item.control === 6);
    assert.equal(unused.status, "manual");
    assert.match(unused.summary, /nrql\.NrAuditEvent\.api_key_actor/);
    assert.match(unused.summary, /\(at actor\.account\.nrql\)/);
    if (mode === "full") {
      assert.equal(unused.evidence.audit_events_by_api_keys, null);
      assert.equal(unused.evidence.distinct_api_keys_in_audit, null);
      assert.equal(unused.evidence.audit_readable, false);
      assert.match(unused.evidence.audit_status, /^unreadable \(nrql\.NrAuditEvent\.api_key_actor: account 111: NerdGraph returned errors: Not authorized \(at actor\.account\.nrql\); account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.nrql\)\)$/);
      assert.match(unused.summary, /API key change activity is unknown \(NrAuditEvent api_key actors unreadable \(nrql\.NrAuditEvent\.api_key_actor: account 111: .*; account 222: .*\(at actor\.account\.nrql\)\)\)/);
      assert.doesNotMatch(unused.summary, /0 distinct API keys/, "no zero count stands in for the unreadable audit rows");
    } else {
      assert.equal(unused.evidence.audit_events_by_api_keys, null, "a count from the readable account only is not a count");
      assert.equal(unused.evidence.distinct_api_keys_in_audit, null);
      assert.equal(unused.evidence.audit_readable, true);
      assert.match(unused.evidence.audit_status, /^partial: 1 scope unreadable \(nrql\.NrAuditEvent\.api_key_actor: account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.nrql\)\)$/);
      assert.match(unused.summary, /^Partial view: NrAuditEvent api_key actors: 1 scope unreadable \(nrql\.NrAuditEvent\.api_key_actor: account 222: /);
      assert.match(unused.summary, /1 distinct API keys performed configuration changes in the last \d+ days in the readable accounts/);
    }
  }
});

test("rule 1 corollary hit 3: NR-09 renders workloads as null with a status and is limited to warn when the workload listing is unreadable", async () => {
  const full = await assessCorollary([["entitySearch workloads", "full"]]);
  const coverage = full.findings.find((item) => item.control === 9);
  assert.equal(coverage.status, "warn");
  assert.match(coverage.summary, /^Partial view: workloads: unreadable \(entitySearch\.workloads: account 111: NerdGraph returned errors: Not authorized \(at actor\.entitySearch\); account 222: NerdGraph returned errors: Not authorized \(at actor\.entitySearch\)\)\. A dataset this finding depends on was unreadable, so the verdict is limited to warn instead of pass\. Within the readable data: 2 policies with 2 enabled NRQL conditions cover all 2 reporting alertable entities\.$/);
  assert.equal(coverage.evidence.workloads, null);
  assert.equal(coverage.evidence.disrupted_workloads, null);
  assert.match(coverage.evidence.workloads_status, /^unreadable \(entitySearch\.workloads: account 111: .*; account 222: /);
  assert.equal(coverage.evidence.reporting_alertable_entities, 2);

  const partial = await assessCorollary([["entitySearch workloads", "partial"]]);
  const partly = partial.findings.find((item) => item.control === 9);
  assert.equal(partly.status, "warn");
  assert.match(partly.summary, /^Partial view: workloads: 1 scope unreadable \(entitySearch\.workloads: account 222: NerdGraph returned errors: Not authorized \(at actor\.entitySearch\)\)\. The inventory was incomplete and the counts that follow cover the readable scopes only, so the verdict is limited to warn instead of pass\. Within the readable data: /);
  assert.equal(partly.evidence.workloads, null, "the guide promises null for a denial affecting any one account");
  assert.equal(partly.evidence.disrupted_workloads, null);
  assert.match(partly.evidence.workloads_status, /^partial: 1 scope unreadable \(entitySearch\.workloads: account 222: .*\(at actor\.entitySearch\)\)$/);
  assert.equal(partly.evidence.reporting_alertable_entities, 2, "inventories with every scope readable keep their counts");
});

test("rule 1 corollary hit 4: NR-10 is limited to warn naming alerts.policiesSearch when the policy listing is unreadable on the pass path", async () => {
  for (const mode of ["full", "partial"]) {
    const { findings } = await assessCorollary([["alerts.policiesSearch", mode]]);
    const channels = findings.find((item) => item.control === 10);
    assert.equal(channels.status, "warn", `${mode}: ${channels.summary}`);
    assert.match(channels.summary, /^Partial view: alert policies: /);
    assert.match(channels.summary, /Within the readable data: 2 destinations across 1 types receive 2 enabled workflows/);
    assert.match(channels.summary, /alerts\.policiesSearch/);
    assert.match(channels.summary, /\(at actor\.account\.alerts\.policiesSearch\)/);
    if (mode === "full") {
      assert.equal(channels.evidence.alert_policies, null);
      assert.match(channels.evidence.alert_policies_status, /^unreadable \(alerts\.policiesSearch: account 111, account 222: /);
    } else {
      assert.equal(channels.evidence.alert_policies, null);
      assert.match(channels.evidence.alert_policies_status, /^partial: 1 scope unreadable \(alerts\.policiesSearch: account 222: /);
      assert.match(channels.summary, /^Partial view: alert policies: 1 scope unreadable \(alerts\.policiesSearch: account 222: /);
    }
    assert.equal(channels.evidence.destinations, 2);
    assert.equal(channels.evidence.destinations_status, "complete (aiNotifications.destinations)");
  }
});

test("rule 1 corollary hit 5: NR-12 is limited to warn naming entityManagement.pipelineCloudRules when Pipeline Control is unreadable", async () => {
  const { findings } = await assessCorollary([["entityManagement.pipelineCloudRules", "full"]]);
  const obfuscation = findings.find((item) => item.control === 12);
  assert.equal(obfuscation.status, "warn");
  assert.match(obfuscation.summary, /^Partial view: Pipeline Control cloud rules: unreadable \(entityManagement\.pipelineCloudRules: NerdGraph returned errors: Not authorized \(at actor\.entityManagement\.entitySearch\)\)\. A dataset this finding depends on was unreadable, so the verdict is limited to warn instead of pass\. Within the readable data: 2 enabled obfuscation rules and 4 expressions cover credential and PII patterns; attribute drop coverage is unverified because Pipeline Control cloud rules \(entityManagement\.pipelineCloudRules\) were not readable\.$/);
  assert.equal(obfuscation.evidence.pipeline_cloud_rules, null);
  assert.equal(obfuscation.evidence.attribute_drop_rules, null);
  assert.equal(obfuscation.evidence.legacy_drop_rules, 2, "the readable drop rules keep their count");
  assert.equal(obfuscation.evidence.legacy_drop_rules_status, "complete (nrqlDropRules.list)");
  assert.match(obfuscation.evidence.pipeline_cloud_rules_status, /^unreadable \(entityManagement\.pipelineCloudRules: /);
  assert.match(obfuscation.evidence.attribute_drop_rules_status, /^unreadable \(entityManagement\.pipelineCloudRules: .*\(at actor\.entityManagement\.entitySearch\)\)$/, "the derived total carries a status of its own");
  assert.doesNotMatch(obfuscation.summary, /\d+ pipeline or drop rules also drop sensitive attributes/);
});

test("rule 1 corollary hit 6: NR-12 is limited to warn naming nrqlDropRules.list and the account when drop rules are unreadable", async () => {
  const full = await assessCorollary([["nrqlDropRules.list", "full"]]);
  const obfuscation = full.findings.find((item) => item.control === 12);
  assert.equal(obfuscation.status, "warn");
  assert.match(obfuscation.summary, /attribute drop coverage is unverified because NRQL drop rules \(nrqlDropRules\.list\) were not readable/);
  assert.match(obfuscation.summary, /Partial view: NRQL drop rules: unreadable \(nrqlDropRules\.list: account 111, account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.nrqlDropRules\.list\)\)/);
  assert.equal(obfuscation.evidence.legacy_drop_rules, null);
  assert.equal(obfuscation.evidence.attribute_drop_rules, null);
  assert.equal(obfuscation.evidence.pipeline_cloud_rules, 1);
  assert.match(obfuscation.evidence.legacy_drop_rules_status, /^unreadable \(nrqlDropRules\.list: account 111, account 222: /);
  assert.match(obfuscation.evidence.attribute_drop_rules_status, /^unreadable \(nrqlDropRules\.list: account 111, account 222: /);

  const partial = await assessCorollary([["nrqlDropRules.list", "partial"]]);
  const partly = partial.findings.find((item) => item.control === 12);
  assert.equal(partly.status, "warn");
  assert.match(partly.summary, /^Partial view: NRQL drop rules: 1 scope unreadable \(nrqlDropRules\.list: account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.nrqlDropRules\.list\)\)\. The inventory was incomplete and the counts that follow cover the readable scopes only, so the verdict is limited to warn instead of pass\. Within the readable data: 2 enabled obfuscation rules and 4 expressions cover credential and PII patterns; 2 pipeline or drop rules also drop sensitive attributes \(1 Pipeline Control cloud rules, 1 NRQL drop rules in the readable accounts\)\.$/);
  assert.equal(partly.evidence.legacy_drop_rules, null, "a count from the readable account only is not a count");
  assert.match(partly.evidence.legacy_drop_rules_status, /^partial: 1 scope unreadable \(nrqlDropRules\.list: account 222: .*\(at actor\.account\.nrqlDropRules\.list\)\)$/);
  assert.equal(partly.evidence.attribute_drop_rules, null, "a derived total inherits the partial state of either input");
  assert.match(partly.evidence.attribute_drop_rules_status, /^partial: 1 scope unreadable \(nrqlDropRules\.list: account 222: .*\); complete \(entityManagement\.pipelineCloudRules\)$/);
  assert.equal(partly.evidence.pipeline_cloud_rules, 1);

  const both = await assessCorollary([["nrqlDropRules.list", "full"], ["entityManagement.pipelineCloudRules", "full"]]);
  assert.match(both.findings.find((item) => item.control === 12).summary, /unverified because Pipeline Control cloud rules \(entityManagement\.pipelineCloudRules\) and NRQL drop rules \(nrqlDropRules\.list\) were not readable/);
});

test("rule 1 corollary hit 7: NR-12 renders log volume as null with a status and is limited to warn when the Log count NRQL is unreadable", async () => {
  const full = await assessCorollary([["NRQL Log volume", "full"]]);
  const obfuscation = full.findings.find((item) => item.control === 12);
  assert.equal(obfuscation.status, "warn");
  assert.match(obfuscation.summary, /Partial view: log volume: unreadable \(nrql\.Log\.volume: account 111: NerdGraph returned errors: Not authorized \(at actor\.account\.nrql\); account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.nrql\)\)/);
  assert.equal(obfuscation.evidence.log_events_last_day, null);
  assert.match(obfuscation.evidence.log_events_last_day_status, /^unreadable \(nrql\.Log\.volume: account 111: .*; account 222: /);
  const logs = full.findings.find((item) => item.control === 15);
  assert.equal(logs.status, "manual");
  assert.match(logs.summary, /the log volume query failed \(nrql\.Log\.volume: account 111: NerdGraph returned errors: Not authorized \(at actor\.account\.nrql\); account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.nrql\)\)/);
  assert.equal(logs.evidence.log_events_last_day, null);

  const partial = await assessCorollary([["NRQL Log volume", "partial"]]);
  const partly = partial.findings.find((item) => item.control === 12);
  assert.equal(partly.status, "warn");
  assert.match(partly.summary, /^Partial view: log volume: 1 scope unreadable \(nrql\.Log\.volume: account 222: /);
  assert.equal(partly.evidence.log_events_last_day, null, "a volume from the readable account only is not a volume");
  assert.match(partly.evidence.log_events_last_day_status, /^partial: 1 scope unreadable \(nrql\.Log\.volume: account 222: .*\(at actor\.account\.nrql\)\)$/);
  const partlyLogs = partial.findings.find((item) => item.control === 15);
  assert.equal(partlyLogs.status, "warn");
  assert.match(partlyLogs.summary, /^Partial view: log volume: 1 scope unreadable \(nrql\.Log\.volume: account 222: .*Within the readable data: 12000 log events in the last day/);
  assert.equal(partlyLogs.evidence.log_events_last_day, null);
  assert.equal(partlyLogs.evidence.log_volume_readable, true);
});

test("rule 1 corollary hit 8: NR-20 is limited to warn naming the path when group grants are not fully readable", async () => {
  const full = await assessCorollary([["authorizationManagement.groups", "full"]]);
  const roles = full.findings.find((item) => item.control === 20);
  assert.equal(roles.status, "warn");
  // The gap leads; the catalog's zero count follows it so it is not read as a confirmed absence of custom roles.
  assert.match(roles.summary, /^Group grants \(authorizationManagement\.groups\) were unreadable \(authorizationManagement\.groups: authentication domain Corporate SSO, authentication domain Contractors: .*Not authorized \(at actor\.organization\.authorizationManagement\.authenticationDomains\.groups\)\), so the roles in use were not cross-checked against the catalog; the catalog itself lists no custom roles \(the customerAdministration\.roles query was readable and complete, and it returned 2 STANDARD roles\)\.$/);
  assert.equal(roles.evidence.custom_roles_in_group_grants, null);
  assert.equal(roles.evidence.groups_granted_custom_roles, null);
  assert.match(roles.evidence.group_grants_status, /^unreadable \(authorizationManagement\.groups: /);
  assert.deepEqual(roles.evidence.custom_roles, []);

  const partial = await assessCorollary([["authorizationManagement.groups", "partial"]]);
  const partly = partial.findings.find((item) => item.control === 20);
  assert.equal(partly.status, "warn");
  assert.match(partly.summary, /^Partial view: groups: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: NerdGraph returned errors: Not authorized \(at actor\.organization\.authorizationManagement\.authenticationDomains\.groups\)\)\. The group grant listing \(authorizationManagement\.groups\) is incomplete, so the roles in use were only partly cross-checked against the catalog; no custom role appears in the readable group grants and the catalog itself lists none \(the customerAdministration\.roles query was readable and complete, and it returned 2 STANDARD roles\)\.$/);
  assert.equal(partly.evidence.custom_roles_in_group_grants, null, "an empty list from the readable domain only is not a list");
  assert.equal(partly.evidence.groups_granted_custom_roles, null);
  assert.match(partly.evidence.group_grants_status, /^partial: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: /);
  assert.match(partly.evidence.custom_roles_in_group_grants_status, /^partial: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: /);

  const chained = await assessCorollary([["userManagement.authenticationDomains", "full"]]);
  const viaDomains = chained.findings.find((item) => item.control === 20);
  assert.equal(viaDomains.status, "warn");
  // The group query is never issued when the domain listing it iterates is unreadable, so the grants are not
  // collected (not unreadable) and the status names the upstream query, its failure status, and its path. The
  // compacted cause keeps the status and path and elides the boilerplate between them.
  assert.match(viaDomains.summary, /^Group grants \(authorizationManagement\.groups\) were not collected \(authorizationManagement\.groups was not queried for any authentication domain: userManagement\.authenticationDomains was .*Not authorized \(at actor\.organization\.userManagement\.authenticationDomains\)\)\), so the roles in use were not cross-checked against the catalog; the catalog itself lists no custom roles/);
  assert.equal(viaDomains.evidence.custom_roles_in_group_grants, null);
  assert.equal(viaDomains.evidence.groups_granted_custom_roles, null);
  assert.match(viaDomains.evidence.group_grants_status, /^not collected \(authorizationManagement\.groups was not queried for any authentication domain: userManagement\.authenticationDomains was .*Not authorized \(at actor\.organization\.userManagement\.authenticationDomains\)\)\)$/);
});

test("rule 1 corollary sweep: denying any one inventory demotes exactly the findings that read it, fully and per scope", async () => {
  for (const row of COROLLARY_INVENTORIES) {
    for (const mode of row.scope ? ["full", "partial"] : ["full"]) {
      const context = `with ${row.inventory} denied (${mode})`;
      // Both generic guards run over every finding's evidence, every category summary, and every core_data value.
      const { results, findings } = await assessGuarded(denyInventories(corollaryClient(), [[row.inventory, mode]]), context);
      const expectedDemoted = row.dependents.map(controlId);
      const expectedPass = COROLLARY_BASELINE_PASS.filter((id) => !expectedDemoted.includes(id));
      assert.deepEqual(passing(findings).sort(), expectedPass.sort(), `pass set ${context}`);
      assert.deepEqual(findings.filter((item) => item.status === "fail").map((item) => item.id), [], `no false fail ${context}`);
      assert.ok(results.some((result) => result.errors.some((error) => error.includes(row.path))), `the denial is disclosed in an errors array ${context}`);
      for (const id of expectedDemoted) {
        const item = findingById({ findings }, id);
        belowPass(item, context);
        assert.ok(item.summary.includes(row.path), `${id} does not name the query path ${row.path} ${context}: ${item.summary}`);
        if (mode === "partial") {
          assert.ok(item.summary.includes(COROLLARY_SCOPE_LABEL[row.scope]), `${id} does not name the denied scope ${context}: ${item.summary}`);
          // Counts from the readable scopes only never lead: the Partial view clause states the gap first.
          assert.ok(item.summary.startsWith("Partial view: "), `${id} states a readable-scope count ahead of the gap ${context}: ${item.summary}`);
        }
      }
    }
  }
});

test("rule 1 corollary bundle check: findings.json never carries NR-04, 09, 10, 12, 20 as pass when their secondary inventories are denied", async () => {
  const base = createTempBase("grclanker-newrelic-corollary-");
  const client = denyInventories(corollaryClient(), [
    ["nrqlDropRules.list", "partial"],
    ["entitySearch workloads", "full"],
    ["authorizationManagement.groups", "partial"],
    ["alerts.policiesSearch", "partial"],
  ]);

  const result = await exportNewrelicAuditBundle(client, sampleConfig({ accountIds: COROLLARY_ACCOUNT_IDS }), base, { now: NOW });

  assert.equal(result.findingCount, 20);
  assert.equal(result.errorCount, 4);
  const errorsLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorsLog, /^nrqlDropRules\.list: account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.nrqlDropRules\.list\)$/m);
  assert.match(errorsLog, /^entitySearch\.workloads: account 111: .*; account 222: .*\(at actor\.entitySearch\)$/m);
  assert.match(errorsLog, /^authorizationManagement\.groups: authentication domain Contractors: .*\(at actor\.organization\.authorizationManagement\.authenticationDomains\.groups\)$/m);
  assert.match(errorsLog, /^alerts\.policiesSearch: account 222: .*\(at actor\.account\.alerts\.policiesSearch\)$/m);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 20);
  const byControl = (control) => findings.find((item) => item.control === control);
  for (const [control, dataset] of [[4, "authorizationManagement.groups"], [9, "entitySearch.workloads"], [10, "alerts.policiesSearch"], [12, "nrqlDropRules.list"], [20, "authorizationManagement.groups"]]) {
    const item = byControl(control);
    assert.equal(item.status, "warn", `${item.id}: ${item.summary}`);
    assert.ok(item.summary.includes(dataset), `${item.id} does not name ${dataset}: ${item.summary}`);
  }
  assert.equal(byControl(4).evidence.admin_owned_user_keys, null);
  assert.equal(byControl(9).evidence.workloads, null);
  assert.equal(byControl(9).evidence.disrupted_workloads, null);
  assert.match(byControl(9).summary, /alerts\.policiesSearch: account 222/);
  assert.equal(byControl(10).evidence.alert_policies, null);
  assert.match(byControl(10).evidence.alert_policies_status, /^partial: 1 scope unreadable \(alerts\.policiesSearch: account 222: /);
  assert.equal(byControl(12).evidence.legacy_drop_rules, null);
  assert.match(byControl(12).evidence.legacy_drop_rules_status, /^partial: 1 scope unreadable \(nrqlDropRules\.list: account 222: /);
  assert.equal(byControl(20).evidence.custom_roles_in_group_grants, null);
  assert.deepEqual(
    findings.filter((item) => item.status === "pass").map((item) => item.control).sort((a, b) => a - b),
    [1, 2, 5, 11, 13, 14, 15, 19],
  );
  assert.deepEqual(findings.filter((item) => item.status === "fail"), []);

  const summaryJson = JSON.parse(readFileSync(join(result.outputDir, "analysis", "alerting.json"), "utf8"));
  assert.equal(summaryJson.summary.workloads, null);
  assert.match(summaryJson.summary.workloads_status, /^unreadable \(entitySearch\.workloads: /);
  assert.equal(summaryJson.summary.policies, null);
  assert.match(summaryJson.summary.policies_status, /^partial: 1 scope unreadable \(alerts\.policiesSearch: account 222: /);
  assert.ok(summaryJson.coverage.some((note) => note.startsWith("workloads: unreadable (entitySearch.workloads: ")));
  const governance = JSON.parse(readFileSync(join(result.outputDir, "analysis", "data_governance.json"), "utf8"));
  assert.equal(governance.summary.legacy_drop_rules, null);
  assert.match(governance.summary.legacy_drop_rules_status, /^partial: 1 scope unreadable \(nrqlDropRules\.list: account 222: /);
  assert.equal(governance.summary.attribute_drop_rules, null);
  assert.match(governance.summary.attribute_drop_rules_status, /^partial: 1 scope unreadable \(nrqlDropRules\.list: account 222: .*; complete \(entityManagement\.pipelineCloudRules\)$/);
  assert.ok(governance.coverage.some((note) => note.startsWith("NRQL drop rules: 1 scope unreadable (nrqlDropRules.list: account 222: ")));
  const dropRulesFile = JSON.parse(readFileSync(join(result.outputDir, "core_data", "nrql_drop_rules.json"), "utf8"));
  assert.match(dropRulesFile.status, /^partial: 1 scope unreadable \(nrqlDropRules\.list: account 222: /);
  assert.equal(dropRulesFile.records.length, 1, "the readable account's rows are kept beside the marker");
  const workloadsFile = JSON.parse(readFileSync(join(result.outputDir, "core_data", "workloads.json"), "utf8"));
  assert.match(workloadsFile.status, /^unreadable \(entitySearch\.workloads: /);
  assert.equal(workloadsFile.records, null);
});

// Round 5: a zero-scope collection is not collected. With actor.accounts unreadable (or answering zero accounts) and
// no account_ids configured, no account-scoped query runs, so every account-scoped inventory is recorded as not
// collected naming actor.accounts and the skipped query, never as a complete empty listing that 0 and [] fall out of.
const ACCOUNT_SCOPED_SOURCES = COROLLARY_INVENTORIES.filter((row) => row.scope === "account" || row.scope === "monitor").map((row) => row.source);
const ACCOUNT_SCOPED_FINDINGS = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17].map(controlId);
const ZERO_SCOPE_PASS = [1, 2, 3, 19, 20].map(controlId);
const OLD_ZERO_SCOPE_NOTE = "no scopes were available to query";
// The two governance surfaces that are not account scoped: they answer even when no account resolved.
const GLOBAL_GOVERNANCE_FILES = ["core_data/pipeline_cloud_rules.json", "core_data/dashboard_live_urls.json"];

/** The corollary tenant with no configured account_ids and actor.accounts unreadable (`denied`) or answering zero accounts (`empty`). */
function zeroScopeClient(mode) {
  return corollaryClient({
    getResolvedConfig: () => sampleConfig({ accountIds: [] }),
    async resolveAccountIds() {
      if (mode === "empty") throw new NewrelicNoAccountsError("No New Relic accounts were visible to the API key. Set NEW_RELIC_ACCOUNT_ID explicitly.");
      throw forbidden("actor.accounts");
    },
    async listAccounts() {
      if (mode === "empty") return [];
      throw forbidden("actor.accounts");
    },
  });
}

/** Every never-collected core_data value is a marker with null records; nested markers (composite files) are checked the same way. */
function assertNotCollectedMarkers(coreData, label, allowedArrays = []) {
  for (const [file, value] of Object.entries(coreData)) {
    if (Array.isArray(value)) {
      assert.ok(allowedArrays.includes(file), `${label}: ${file} is written as an array (${value.length} rows) although its query never ran`);
      continue;
    }
    const markers = "status" in value ? [value] : Object.values(value);
    for (const marker of markers) {
      // The script scan is derived twice over (monitor listing, then accounts), so its compacted cause keeps the path only.
      assert.match(marker.status, /^not collected \(\S+ was not queried for any (account|monitor): .*actor\.accounts/, `${label}: ${file}`);
      assert.equal(marker.records, null, `${label}: ${file} carries records beside a not-collected status`);
    }
  }
}

test("round 5 zero scope: with actor.accounts unreadable and no account_ids, account-scoped inventories are not collected and no account-scoped finding passes or fails", async () => {
  for (const mode of ["denied", "empty"]) {
    const label = `zero scope (${mode})`;
    const { results, findings, requested, rendered } = await assessGuarded(zeroScopeClient(mode), label);
    const cause = mode === "denied"
      ? "actor\\.accounts was unreadable \\(NerdGraph returned errors: Not authorized \\(at actor\\.accounts\\)\\) and no account_ids were configured"
      : "actor\\.accounts returned zero accounts and no account_ids were configured";

    // actor.accounts was asked; nothing account or monitor scoped was.
    assert.ok(requested.has("actor.accounts"), label);
    assert.deepEqual(ACCOUNT_SCOPED_SOURCES.filter((source) => requested.has(source)), [], `${label}: account-scoped queries were issued without an account`);
    assert.ok(!JSON.stringify(rendered).includes(OLD_ZERO_SCOPE_NOTE), `${label}: a zero-scope collection is still rendered as complete`);

    // Only the findings that never read account-scoped data keep their verdicts; the rest are manual or warn, never fail.
    assert.deepEqual(passing(findings).sort(), [...ZERO_SCOPE_PASS].sort(), `${label}: pass set`);
    assert.deepEqual(findings.filter((item) => item.status === "fail").map((item) => item.id), [], `${label}: a verdict failed on never-collected data`);
    for (const id of ACCOUNT_SCOPED_FINDINGS) {
      const item = findingById({ findings }, id);
      belowPass(item, label);
      assert.ok(item.summary.includes("actor.accounts"), `${id} does not name actor.accounts ${label}: ${item.summary}`);
    }

    // NR-12 was the false HIGH FAIL: its primary inventory was never collected, so it is manual and names both queries.
    const obfuscation = findingById({ findings }, controlId(12));
    assert.equal(obfuscation.status, "manual", `${label}: ${obfuscation.summary}`);
    assert.match(obfuscation.summary, /logConfigurations\.obfuscationRules/);
    assert.doesNotMatch(obfuscation.summary, /across 0 accounts|No obfuscation rule with enabled = true exists/);
    assert.equal(obfuscation.evidence.obfuscation_rules, null);
    assert.match(obfuscation.evidence.obfuscation_rules_status, new RegExp(`^not collected \\(logConfigurations\\.obfuscationRules was not queried for any account: ${cause}\\)$`));
    assert.equal(obfuscation.evidence.enabled_obfuscation_rules, null);
    assert.equal(obfuscation.evidence.legacy_drop_rules, null);
    assert.equal(obfuscation.evidence.log_events_last_day, null);
    assert.equal(obfuscation.evidence.attribute_drop_rules, null, "the derived total is null when one of its inputs was never collected");
    assert.match(obfuscation.evidence.attribute_drop_rules_status, /^not collected \(nrqlDropRules\.list was not queried for any account: actor\.accounts /);
    assert.equal(obfuscation.evidence.pipeline_cloud_rules, 1, "the organization-wide cloud rule query ran and keeps its count");
    assert.equal(obfuscation.evidence.pipeline_cloud_rules_status, "complete (entityManagement.pipelineCloudRules)");

    // Every account-scoped category says the account scope is unknown and why.
    for (const result of results.slice(1)) {
      assert.equal(result.summary.accounts_in_scope, null, `${result.category} ${label}`);
      assert.match(result.summary.accounts_in_scope_status, new RegExp(`^unknown \\(${cause}\\)$`), `${result.category} ${label}`);
      assert.ok(result.errors.some((error) => error.includes("actor.accounts")), `${result.category} discloses actor.accounts in its errors ${label}`);
    }
    const [, accessControl, alerting, governance] = results;
    assert.equal(alerting.summary.policies, null);
    assert.match(alerting.summary.policies_status, /^not collected \(alerts\.policiesSearch was not queried for any account: actor\.accounts /);
    assert.equal(governance.summary.enabled_obfuscation_rules, null);
    assert.equal(governance.summary.log_events_last_day, null);
    assert.equal(accessControl.summary.api_key_audit_events, null);
    assert.match(accessControl.summary.api_key_audit_events_status, /^not collected \(nrql\.NrAuditEvent\.api_key_actor was not queried for any account: actor\.accounts /);

    // core_data files for never-collected surfaces are markers, not [].
    assertNotCollectedMarkers(alerting.coreData, `alerting ${label}`);
    assertNotCollectedMarkers(governance.coreData, `data_governance ${label}`, GLOBAL_GOVERNANCE_FILES);
    assert.equal(Object.keys(alerting.coreData).length, 7);
    assert.equal(Object.keys(governance.coreData).length, 13);
    assert.equal(governance.coreData["core_data/pipeline_cloud_rules.json"].length, 1);
  }

  // The exported bundle carries the same shape and the executive summary headlines no fail built on never-collected data.
  const base = createTempBase("grclanker-newrelic-zero-scope-");
  const result = await exportNewrelicAuditBundle(zeroScopeClient("denied"), sampleConfig({ accountIds: [] }), base, { now: NOW });
  assert.equal(result.findingCount, 20);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  const byControl = (control) => findings.find((item) => item.control === control);
  assert.equal(byControl(12).status, "manual", byControl(12).summary);
  assert.deepEqual(findings.filter((item) => item.status === "fail"), []);
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.control).sort((a, b) => a - b), [1, 2, 3, 19, 20]);
  const executive = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executive, /^- Failed controls: 0$/m);
  assert.match(executive, /^Accounts: none resolved$/m);
  assert.doesNotMatch(executive, /across 0 accounts|No obfuscation rule with enabled = true exists|FAIL\)/);
  assert.match(executive, /^- NR-12-LOG-OBFUSCATION: Partial view: .*logConfigurations\.obfuscationRules/m);
  const obfuscationFile = JSON.parse(readFileSync(join(result.outputDir, "core_data", "obfuscation_rules.json"), "utf8"));
  assert.match(obfuscationFile.status, /^not collected \(logConfigurations\.obfuscationRules was not queried for any account: actor\.accounts was unreadable/);
  assert.equal(obfuscationFile.records, null);
  const governanceJson = JSON.parse(readFileSync(join(result.outputDir, "analysis", "data_governance.json"), "utf8"));
  assert.equal(governanceJson.summary.accounts_in_scope, null);
  assert.equal(governanceJson.summary.enabled_obfuscation_rules, null);
  const errorsLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorsLog, /^actor\.accounts: NerdGraph returned errors: Not authorized \(at actor\.accounts\)$/m);
  assert.match(errorsLog, /^logConfigurations\.obfuscationRules was not queried for any account: actor\.accounts was unreadable/m);
  assert.ok(!errorsLog.includes(OLD_ZERO_SCOPE_NOTE));
});

test("round 5 script scan: the synthetic script scan takes its status from the monitor listing it is computed from", async () => {
  // Monitor search unreadable everywhere: no script was fetched, so the scan is not collected and every scan value is null.
  const denied = await assessGuarded(denyInventories(corollaryClient(), [["entitySearch synthetic monitors", "full"]]), "monitor search denied");
  assert.ok(!denied.requested.has("synthetics.script"), "no script query was issued without a monitor listing");
  const monitorsDenied = findingById(denied, controlId(13));
  assert.equal(monitorsDenied.status, "manual", monitorsDenied.summary);
  assert.equal(monitorsDenied.evidence.monitors, null);
  assert.equal(monitorsDenied.evidence.scripts_sampled, null);
  assert.equal(monitorsDenied.evidence.scripts_sample_complete, null);
  assert.equal(monitorsDenied.evidence.scripts_with_secret_indicators, null);
  assert.equal(monitorsDenied.evidence.scripts_using_secure_credentials, null);
  // Both accounts' monitor searches failed, so the compacted cause keeps the first path and counts the other scope.
  assert.match(
    monitorsDenied.evidence.scripts_status,
    /^not collected \(synthetics\.script was not queried for any monitor: entitySearch\.syntheticMonitors was unreadable .*\(at actor\.entitySearch\); 1 more scope failed and is listed in the errors array\)$/,
  );
  assert.equal(monitorsDenied.evidence.scripts_sampled_status, monitorsDenied.evidence.scripts_status);
  const governanceDenied = denied.results[3];
  assert.equal(governanceDenied.summary.scripts_with_secret_indicators, null);
  assert.equal(governanceDenied.summary.scripts_with_secret_indicators_status, monitorsDenied.evidence.scripts_status);
  assert.deepEqual(governanceDenied.coreData["core_data/synthetic_script_scan.json"], { status: monitorsDenied.evidence.scripts_status, records: null });
  assert.ok(governanceDenied.coverage.some((note) => note.startsWith("synthetic scripts: not collected (synthetics.script was not queried for any monitor: ")), JSON.stringify(governanceDenied.coverage));

  // One account's monitor search unreadable: the scan over the readable monitors is partial, named after the denied scope.
  const partial = await assessGuarded(denyInventories(corollaryClient(), [["entitySearch synthetic monitors", "partial"]]), "monitor search denied for one account");
  const monitorsPartial = findingById(partial, controlId(13));
  belowPass(monitorsPartial, "with one account's monitor search denied");
  assert.equal(monitorsPartial.evidence.scripts_sampled, null);
  assert.equal(monitorsPartial.evidence.scripts_sample_complete, null);
  assert.match(monitorsPartial.evidence.scripts_status, /^partial: derived from entitySearch\.syntheticMonitors: 1 scope unreadable \(entitySearch\.syntheticMonitors: account 222: /);
  assert.match(monitorsPartial.summary, /^Partial view: /);

  // A complete listing without a scripted monitor: no script query is needed, and the status says what the empty scan rests on.
  const baseClient = corollaryClient();
  const unscripted = await assessGuarded({
    ...baseClient,
    async searchEntities(query) {
      if (query.includes("MONITOR")) return [{ guid: "mon-111", name: "Ping 111", domain: "SYNTH", type: "MONITOR", monitorType: "SIMPLE", accountId: 111 }];
      return baseClient.searchEntities(query);
    },
  }, "no scripted monitors");
  assert.ok(!unscripted.requested.has("synthetics.script"));
  const noScripts = findingById(unscripted, controlId(13));
  assert.equal(noScripts.status, "manual", noScripts.summary);
  assert.equal(noScripts.evidence.scripted_monitors, 0);
  assert.equal(noScripts.evidence.scripts_sampled, 0);
  assert.equal(noScripts.evidence.scripts_status, "complete (entitySearch.syntheticMonitors listed no scripted monitor, so no script was fetched)");
});

test("round 5 derived totals and option-derived lists carry their own status and render null when an input is unavailable", async () => {
  const baseline = await assessGuarded(corollaryClient(), "derived totals baseline");
  const obfuscation = findingById(baseline, controlId(12));
  // One cloud rule deleting an attribute plus one DROP_ATTRIBUTES drop rule per account.
  assert.equal(obfuscation.evidence.attribute_drop_rules, 3);
  assert.equal(obfuscation.evidence.attribute_drop_rules_status, "complete (entityManagement.pipelineCloudRules, nrqlDropRules.list)");
  assert.equal(baseline.results[3].summary.attribute_drop_rules, 3);
  assert.equal(baseline.results[3].summary.attribute_drop_rules_status, obfuscation.evidence.attribute_drop_rules_status);
  const channels = findingById(baseline, controlId(10));
  assert.deepEqual(channels.evidence.approved_email_domains, ["example.com"]);
  assert.equal(channels.evidence.approved_email_domains_status, "complete (actor.user)");
  // Every count, list, map, or flag in the alerting and data governance summaries carries a status (region and the
  // run's own error and limitation counts are not inventory values).
  for (const result of baseline.results.slice(2)) {
    for (const [key, value] of Object.entries(result.summary)) {
      if (key.endsWith("_status") || ["region", "collection_errors", "coverage_limitations"].includes(key)) continue;
      assert.ok(`${key}_status` in result.summary, `${result.category}.${key} (${JSON.stringify(value)}) has no status`);
    }
  }

  // The cloud rule query denied: the derived total is null with a status naming the unreadable input, the drop rule count stays.
  const cloudDenied = await assessGuarded(denyInventories(corollaryClient(), [["entityManagement.pipelineCloudRules", "full"]]), "cloud rules denied");
  const cloudObfuscation = findingById(cloudDenied, controlId(12));
  assert.equal(cloudObfuscation.status, "warn", cloudObfuscation.summary);
  assert.equal(cloudObfuscation.evidence.attribute_drop_rules, null);
  assert.match(cloudObfuscation.evidence.attribute_drop_rules_status, /^unreadable \(entityManagement\.pipelineCloudRules: .*\(at actor\.entityManagement\.entitySearch\)\)$/);
  assert.equal(cloudObfuscation.evidence.legacy_drop_rules, 2);
  assert.equal(cloudDenied.results[3].summary.attribute_drop_rules, null);

  // actor.user denied: the approved domain list derived from it is null with its status, and NR-10 is limited naming the path.
  const userDenied = await assessGuarded(denyInventories(corollaryClient(), [["actor.user", "full"]]), "actor.user denied");
  const userChannels = findingById(userDenied, controlId(10));
  assert.equal(userChannels.status, "warn", userChannels.summary);
  assert.match(userChannels.summary, /actor\.user/);
  assert.equal(userChannels.evidence.approved_email_domains, null);
  assert.match(userChannels.evidence.approved_email_domains_status, /^unreadable \(actor\.user: .*\(at actor\.user\)\)$/);
  assert.equal(userChannels.evidence.current_user_status, userChannels.evidence.approved_email_domains_status);
  // Passing the option makes the list independent of actor.user.
  const client = denyInventories(corollaryClient(), [["actor.user", "full"]]);
  const withOption = await assessNewrelicAlerting(client, { approvedEmailDomains: ["example.com"] });
  const optionChannels = findingById(withOption, controlId(10));
  assert.deepEqual(optionChannels.evidence.approved_email_domains, ["example.com"]);
  assert.equal(optionChannels.evidence.approved_email_domains_status, "complete (approved_email_domains option)");
});

test("round 5 partial denials: a partly readable inventory renders null beside a partial status naming the scope and path, and the gap leads the summary", async () => {
  const cases = [
    ["alerts.policiesSearch", 10, "alert_policies", /^partial: 1 scope unreadable \(alerts\.policiesSearch: account 222: NerdGraph returned errors: Not authorized \(at actor\.account\.alerts\.policiesSearch\)\)$/],
    ["logConfigurations.obfuscationRules", 12, "enabled_obfuscation_rules", /^partial: 1 scope unreadable \(logConfigurations\.obfuscationRules: account 222: .*\(at actor\.account\.logConfigurations\.obfuscationRules\)\)$/],
    ["entitySearch alertable entities", 9, "uncovered_entities", /^partial: 1 scope unreadable \(entitySearch\.alertable: account 222: .*\(at actor\.entitySearch\)\)$/],
    ["userManagement.users", 19, "inactive_users", /^partial: 1 scope unreadable \(userManagement\.users: authentication domain Contractors: .*\(at actor\.organization\.userManagement\.authenticationDomains\.users\)\)$/],
    ["dataManagement.eventRetentionRules", 11, "short_retention_rules", /^partial: 1 scope unreadable \(dataManagement\.eventRetentionRules: account 222: .*\(at actor\.account\.dataManagement\.eventRetentionRules\)\)$/],
  ];
  for (const [inventory, control, field, status] of cases) {
    const context = `with ${inventory} denied for one scope`;
    const { findings } = await assessGuarded(denyInventories(corollaryClient(), [[inventory, "partial"]]), context);
    const item = findingById({ findings }, controlId(control));
    belowPass(item, context);
    assert.equal(item.evidence[field], null, `${item.id}.${field} renders a readable-scope value ${context}`);
    assert.match(item.evidence[`${field}_status`], status, `${item.id}.${field}_status ${context}`);
    // The incompleteness note comes first; no count from the readable scopes precedes it.
    assert.match(item.summary, /^Partial view: [^.]*1 scope unreadable/, `${item.id} ${context}: ${item.summary}`);
    assert.ok(item.summary.indexOf("Partial view") < item.summary.search(/\b\d+ /), `${item.id} states a count before the gap ${context}: ${item.summary}`);
  }
});

test("exportNewrelicAuditBundle writes core data, analysis, compliance reports, and a zip archive", async () => {
  const base = createTempBase("grclanker-newrelic-export-");
  const config = sampleConfig({ accountIds: [111] });

  const result = await exportNewrelicAuditBundle(bundleClient(), config, base, { now: NOW });

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.match(result.zipPath, /newrelic-111-audit-bundle\.zip$/);
  assert.equal(result.findingCount, 20);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 40, `expected at least 40 files, saw ${result.fileCount}`);
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);

  const expectedFiles = [
    "metadata.json",
    "QUICK_REFERENCE.md",
    "analysis/findings.json",
    "analysis/identity.json",
    "analysis/access_control.json",
    "analysis/alerting.json",
    "analysis/data_governance.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
    "core_data/organization.json",
    "core_data/authentication_domains.json",
    "core_data/users.json",
    "core_data/group_role_grants.json",
    "core_data/roles.json",
    "core_data/api_keys.json",
    "core_data/audit_api_key_actor_events.json",
    "core_data/alert_policies.json",
    "core_data/notification_destinations.json",
    "core_data/workflows.json",
    "core_data/retention_rules.json",
    "core_data/obfuscation_rules.json",
    "core_data/dashboards.json",
    "core_data/synthetic_script_scan.json",
    "core_data/log_secret_scan.json",
  ];
  for (const relativePath of expectedFiles) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.region, "US");
  assert.deepEqual(metadata.account_ids, [111]);
  assert.equal(JSON.stringify(metadata).includes(TEST_KEY), false);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 20);
  assert.deepEqual([...new Set(findings.map((item) => item.control))].sort((a, b) => a - b), Array.from({ length: 20 }, (_, index) => index + 1));
  assert.ok(findings.every((item) => Array.isArray(item.mappings) && item.mappings.length === 8));
  assert.ok(findings.every((item) => ["pass", "warn", "fail", "manual"].includes(item.status)));

  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /NR-01-SSO-ENFORCEMENT/);
  assert.match(matrix, /FedRAMP IA-2/);
  const fedramp = readFileSync(join(result.outputDir, "compliance", "fedramp", "fedramp_compliance_report.md"), "utf8");
  assert.match(fedramp, /## IA-2: SSO\/SAML enforcement/);
  const executive = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executive, /## Manual Evidence Required/);
  assert.match(executive, /NR-16-INFRA-AGENT-CONFIGURATION/);

  const scriptScan = JSON.parse(readFileSync(join(result.outputDir, "core_data", "synthetic_script_scan.json"), "utf8"));
  assert.equal(scriptScan[0].usesSecureCredentials, true);
  assert.equal("text" in scriptScan[0], false);
});

function listFilesRecursively(root, dir = root) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const pathname = join(dir, entry.name);
    return entry.isDirectory() ? listFilesRecursively(root, pathname) : [relative(root, pathname)];
  });
}

// Minimal reader for the archives archiver writes: walks the central directory and inflates each entry.
function readZipEntries(buffer) {
  let endOfCentralDirectory = -1;
  for (let offset = buffer.length - 22; offset >= 0; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      endOfCentralDirectory = offset;
      break;
    }
  }
  assert.notEqual(endOfCentralDirectory, -1, "zip end of central directory record not found");
  const entryCount = buffer.readUInt16LE(endOfCentralDirectory + 10);
  let offset = buffer.readUInt32LE(endOfCentralDirectory + 16);
  const entries = new Map();
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, "central directory header expected");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
    assert.equal(buffer.readUInt32LE(localHeaderOffset), 0x04034b50, `local header expected for ${name}`);
    const dataStart = localHeaderOffset + 30 + buffer.readUInt16LE(localHeaderOffset + 26) + buffer.readUInt16LE(localHeaderOffset + 28);
    const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
    if (method === 8) entries.set(name, inflateRawSync(compressed).toString("utf8"));
    else if (method === 0) entries.set(name, compressed.toString("utf8"));
    else assert.fail(`unsupported zip compression method ${method} for ${name}`);
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

const PLANTED_SECRETS = {
  webhookUrlToken: "https://hooks.example.com/services/PLANTED-WEBHOOK-TOKEN-7f3a",
  webhookSecurityCode: "PLANTED-SECURITY-CODE-91b2",
  slackAccessToken: "xoxb-PLANTED-SLACK-TOKEN-4c8d",
  authorizationHeader: "Bearer PLANTED-AUTHORIZATION-HEADER-2e6f",
  destinationVolunteeredField: "PLANTED-DESTINATION-AUTH-3b0a",
  channelPropertySecret: "PLANTED-CHANNEL-PROPERTY-SECRET-5a1c",
  userKeyValue: "NRAK-PLANTEDUSERKEYVALUE0123456789",
  ingestKeyValue: "PLANTED-LICENSE-KEY-VALUE-NRAL-8d2b",
  passwordHash: "$2b$12$PLANTED-PASSWORD-HASH-3f9e",
  liveUrlToken: "https://onenr.io/PLANTED-LIVE-URL-TOKEN-6c4a",
  liveUrlUuid: "PLANTED-LIVE-URL-UUID-1b7d",
  secureCredentialValue: "PLANTED-SECURE-CREDENTIAL-VALUE-9a0e",
  scriptInlineSecret: "PLANTED-SCRIPT-INLINE-SECRET-2d5c",
  logMessage: "PLANTED-LOG-MESSAGE-SECRET-7e1f",
  volunteeredField: "PLANTED-VOLUNTEERED-FIELD-0c9d",
};

function plantedBundleClient() {
  const planted = { volunteered: PLANTED_SECRETS.volunteeredField };
  return bundleClient({
    async getOrganization() {
      return { id: "org-1", name: "Example Org", ...planted };
    },
    async getCurrentUser() {
      return { id: "u-1", email: "auditor@example.com", name: "Auditor", ...planted };
    },
    async listAccounts() {
      return [{ id: 111, name: "Payments Production", ...planted }];
    },
    async listAuthenticationDomains() {
      return [{ id: "domain-1", name: "Corporate SSO", provisioningType: "SCIM", ...planted }];
    },
    async listOrganizationAuthenticationDomains() {
      return [{ id: "domain-1", name: "Corporate SSO", organizationId: "org-1", provisioningType: "SCIM", authenticationType: "SAML_SSO", ...planted }];
    },
    async listDomainUsers() {
      return [
        { ...user("alice", { type: "FULL_PLATFORM", groups: ["g-admin"] }), passwordHash: PLANTED_SECRETS.passwordHash },
        { ...user("bob", { type: "BASIC", groups: ["g-dev"] }), passwordHash: PLANTED_SECRETS.passwordHash, ...planted },
      ];
    },
    async listDomainGroupGrants() {
      return [{ ...orgManagerGroup(), ...planted }, { ...accountGroup("g-dev", [111]), ...planted }];
    },
    async listRoles(organizationId) {
      requireOrganizationId(organizationId);
      return standardRoles().map((role) => ({ ...role, ...planted }));
    },
    async listApiKeys() {
      return [
        { id: "key-1", name: "ci-deploy", type: "USER", key: PLANTED_SECRETS.userKeyValue, createdAt: secondsAgo(10), userId: "bob", accountId: 111, ...planted },
        { id: "key-2", name: "license-prod", type: "INGEST", key: PLANTED_SECRETS.ingestKeyValue, ingestType: "LICENSE", createdAt: secondsAgo(20), accountId: 111 },
      ];
    },
    async listAlertPolicies() {
      return [{ id: "policy-1", name: "Production", incidentPreference: "PER_CONDITION_AND_TARGET", ...planted }];
    },
    async listNrqlConditions() {
      return [{ id: "cond-1", name: "Error rate", type: "STATIC", enabled: true, policyId: "policy-1", nrql: { query: "SELECT count(*) FROM TransactionError" }, ...planted }];
    },
    async listNotificationDestinations() {
      return [
        {
          id: "dest-1",
          name: "Ops distribution list",
          type: "EMAIL",
          properties: [{ key: "email", value: "ops@example.com" }],
          auth: { token: PLANTED_SECRETS.destinationVolunteeredField },
        },
        {
          id: "dest-2",
          name: "Pager webhook",
          type: "WEBHOOK",
          properties: [
            { key: "url", value: PLANTED_SECRETS.webhookUrlToken },
            { key: "securityCode", value: PLANTED_SECRETS.webhookSecurityCode },
            { key: "headers", value: PLANTED_SECRETS.authorizationHeader },
          ],
        },
        {
          id: "dest-3",
          name: "Ops Slack",
          type: "SLACK",
          properties: [{ key: "accessToken", value: PLANTED_SECRETS.slackAccessToken }, { key: "teamName", value: "example" }],
        },
      ];
    },
    async listNotificationChannels() {
      return [
        { id: "chan-1", name: "Ops email", type: "EMAIL", destinationId: "dest-1", properties: [{ key: "payload", value: PLANTED_SECRETS.channelPropertySecret }] },
        { id: "chan-2", name: "Pager", type: "WEBHOOK", destinationId: "dest-2", properties: [{ key: "headers", value: PLANTED_SECRETS.authorizationHeader }] },
      ];
    },
    async listWorkflows() {
      return [
        {
          id: "wf-1",
          name: "Production issues",
          workflowEnabled: true,
          enrichmentsEnabled: false,
          destinationsEnabled: true,
          destinationConfigurations: [{ channelId: "chan-1", name: "Ops email", type: "EMAIL", ...planted }],
          enrichments: [],
          ...planted,
        },
      ];
    },
    async searchEntities(query) {
      if (query.includes("alertSeverity") || query.includes("WORKLOAD")) return alertingClient().searchEntities(query);
      if (query.includes("DASHBOARD")) {
        return [{ guid: "dash-1", name: "Ops overview", domain: "VIZ", type: "DASHBOARD", permissions: "PUBLIC_READ_ONLY", accountId: 111, ...planted }];
      }
      if (query.includes("SECURE_CRED")) {
        return [{ guid: "cred-1", name: "LOGIN_PASSWORD", domain: "SYNTH", type: "SECURE_CRED", accountId: 111, value: PLANTED_SECRETS.secureCredentialValue }];
      }
      if (query.includes("MONITOR")) {
        return [{ guid: "mon-1", name: "Login flow", domain: "SYNTH", type: "MONITOR", monitorType: "SCRIPT_BROWSER", accountId: 111, ...planted }];
      }
      return [];
    },
    async getSyntheticScript() {
      return `const password = $secure.LOGIN_PASSWORD;\nconst inline = "${PLANTED_SECRETS.scriptInlineSecret}";\n$browser.get('https://example.com/login');`;
    },
    async listDashboardLiveUrls() {
      return [{ title: "Ops overview", type: "DASHBOARD", createdAt: secondsAgo(5), url: PLANTED_SECRETS.liveUrlToken, uuid: PLANTED_SECRETS.liveUrlUuid }];
    },
    async listEventRetentionRules() {
      return [{ id: "rule-1", namespace: "Log", retentionInDays: 90, createdAt: secondsAgo(100), deletedAt: null, ...planted }];
    },
    async listObfuscationRules() {
      return dataGovernanceClient().listObfuscationRules().then((rules) => rules.map((rule) => ({ ...rule, ...planted })));
    },
    async listPipelineCloudRules() {
      return [{ id: "rule-guid-1", name: "Drop card numbers", type: "PIPELINE_CLOUD_RULE", nrql: "DELETE cardNumber FROM Log", enabled: true, ...planted }];
    },
    async runNrql(accountId, nrql) {
      if (nrql.includes("NrAuditEvent")) {
        const rows = await accessControlClient().runNrql(accountId, nrql);
        return rows.map((row) => ({ ...row, ...planted }));
      }
      if (nrql.includes("RLIKE")) return [{ matchCount: 1, message: PLANTED_SECRETS.logMessage }];
      return dataGovernanceClient().runNrql(accountId, nrql);
    },
  });
}

test("bundle secret hygiene: planted credentials never reach any bundle file or zip entry", async () => {
  const base = createTempBase("grclanker-newrelic-export-secrets-");
  const result = await exportNewrelicAuditBundle(plantedBundleClient(), sampleConfig({ accountIds: [111] }), base, { now: NOW });
  assert.equal(result.findingCount, 20);

  const files = listFilesRecursively(result.outputDir);
  assert.ok(files.length >= 40, `expected at least 40 files, saw ${files.length}`);
  const fileContents = new Map(files.map((file) => [file, readFileSync(join(result.outputDir, file), "utf8")]));
  const zipEntries = readZipEntries(readFileSync(result.zipPath));
  assert.deepEqual([...zipEntries.keys()].filter((name) => !name.endsWith("/")).sort(), files.sort(), "the zip must contain exactly the bundle files");

  for (const [label, secret] of Object.entries(PLANTED_SECRETS)) {
    for (const [file, content] of fileContents) {
      assert.equal(content.includes(secret), false, `${label} leaked into ${file}`);
    }
    for (const [entry, content] of zipEntries) {
      assert.equal(content.includes(secret), false, `${label} leaked into zip entry ${entry}`);
    }
  }
  for (const [file, content] of fileContents) {
    assert.equal(content.includes(TEST_KEY), false, `caller API key leaked into ${file}`);
    assert.equal(content.includes("PLANTED"), false, `a planted marker leaked into ${file}`);
  }

  const destinations = JSON.parse(fileContents.get("core_data/notification_destinations.json"));
  assert.deepEqual(destinations.map((destination) => destination.properties), [
    [{ key: "email", value: "ops@example.com" }],
    [{ key: "url" }, { key: "securityCode" }, { key: "headers" }],
    [{ key: "accessToken" }, { key: "teamName" }],
  ]);
  assert.ok(destinations.every((destination) => !("auth" in destination) && !("volunteered" in destination)));
  const channels = JSON.parse(fileContents.get("core_data/notification_channels.json"));
  assert.ok(channels.every((channel) => !("properties" in channel)));
  assert.deepEqual(Object.keys(channels[0]).sort(), ["destinationId", "id", "name", "queriedAccountId", "type"]);
  const keys = JSON.parse(fileContents.get("core_data/api_keys.json"));
  assert.ok(keys.every((key) => !("key" in key) && !("volunteered" in key)));
  const users = JSON.parse(fileContents.get("core_data/users.json"));
  assert.ok(users.every((entry) => !("passwordHash" in entry)));
  assert.deepEqual(JSON.parse(fileContents.get("core_data/dashboard_live_urls.json")), [{ title: "Ops overview", type: "DASHBOARD", createdAt: secondsAgo(5) }]);
  const scriptScan = JSON.parse(fileContents.get("core_data/synthetic_script_scan.json"));
  assert.equal(scriptScan[0].usesSecureCredentials, true);
  assert.equal("text" in scriptScan[0], false);
  const logScan = JSON.parse(fileContents.get("core_data/log_secret_scan.json"));
  assert.deepEqual(logScan.matches, [{ matchCount: 1, queriedAccountId: 111 }]);

  const alerting = JSON.parse(fileContents.get("analysis/alerting.json"));
  assert.equal(alerting.findings.find((item) => item.control === 10).status, "pass");
});

// Rule 9, error-body class. Canaries planted in upstream error responses: the three credential shapes of a proxy
// error page, a plain-word marker that no pattern rule can recognise (only a body that is never echoed keeps it
// out), a tokenised URL and a long free-text token inside documented GraphQL and REST error fields, and values in
// undocumented REST body fields.
const ERROR_BODY_CANARIES = {
  bearer: "CANARYBEARER7f3a9c1dAAAAAAAAAAAAAAAAAAAA",
  session: "CANARYSESSION7f3a9c1dbbbbbbbbbbbbbbbbbbbb",
  licenseKey: "cafe7f3a9c1dcafe7f3a9c1dcafe7f3a9c1dcafe",
  htmlMarker: "canary-html-body-marker",
  urlToken: "CANARYURLTOKEN7f3a9c1d",
  longToken: "CANARYLONGTOKEN7f3a9c1dZZZZ",
  tenantId: "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
  restDetail: "CANARYRESTDETAIL7f3a9c1d",
};

const HTML_502_BODY = [
  `<html><body><h1>502 Bad Gateway</h1><p>${ERROR_BODY_CANARIES.htmlMarker}</p>`,
  `<p>Authorization: Bearer ${ERROR_BODY_CANARIES.bearer}</p>`,
  `<p>Set-Cookie: NRSESSION=${ERROR_BODY_CANARIES.session}; Path=/; HttpOnly</p>`,
  `<p>X-License-Key: ${ERROR_BODY_CANARIES.licenseKey}</p></body></html>`,
].join("\n");
const HTML_502_BYTES = Buffer.byteLength(HTML_502_BODY, "utf8");
const TOKENISED_URL = `https://login.newrelic.com/callback?access_token=${ERROR_BODY_CANARIES.urlToken}&state=x`;

function htmlResponse(body, status, statusText) {
  return new Response(body, { status, statusText, headers: { "content-type": "text/html; charset=utf-8" } });
}

function restForbidden(body) {
  return new Response(JSON.stringify(body), { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json; charset=utf-8" } });
}

// The three upstream failure shapes of the walk. `respond` answers every request the client sends (NerdGraph POSTs
// and REST GETs); `nerdgraph` and `rest` are the whole disclosed message each consumer must carry: status, path,
// and either the body's content type and length or the documented fields, scrubbed.
const ERROR_BODY_SHAPES = [
  {
    shape: "502 text/html with bearer, session, and license key canaries",
    respond: async () => htmlResponse(HTML_502_BODY, 502, "Bad Gateway"),
    nerdgraph: `NerdGraph request failed (502 Bad Gateway) at POST /graphql: non-JSON error body (text/html; ${HTML_502_BYTES} bytes)`,
    rest: `REST API v2 request failed for GET /v2/users.json (502 Bad Gateway): non-JSON error body (text/html; ${HTML_502_BYTES} bytes)`,
  },
  {
    shape: "GraphQL errors[] whose message embeds a tokenised URL",
    respond: async (_input, init = {}) => ((init.method ?? "GET").toUpperCase() === "POST"
      ? jsonResponse({
        data: null,
        errors: [{ message: `Upstream rejected the request; retry at ${TOKENISED_URL}`, path: ["actor", "account", "alerts"], extensions: { errorClass: "SERVER_ERROR" } }],
      })
      : restForbidden({ error: { title: `Forbidden; see ${TOKENISED_URL}` } })),
    nerdgraph: "NerdGraph returned errors: Upstream rejected the request; retry at https://login.newrelic.com/callback?[REDACTED] [SERVER_ERROR] (at actor.account.alerts)",
    rest: "REST API v2 request failed for GET /v2/users.json (403 Forbidden): Forbidden; see https://login.newrelic.com/callback?[REDACTED]",
  },
  {
    shape: "free-text errors[].message with a long token",
    respond: async (_input, init = {}) => ((init.method ?? "GET").toUpperCase() === "POST"
      ? jsonResponse({
        data: null,
        errors: [{ message: `Request ${ERROR_BODY_CANARIES.longToken} was rejected for tenant ${ERROR_BODY_CANARIES.tenantId}`, path: ["actor"] }],
      })
      : restForbidden({ error: { title: `Request ${ERROR_BODY_CANARIES.longToken} was rejected for tenant ${ERROR_BODY_CANARIES.tenantId}` } })),
    nerdgraph: "NerdGraph returned errors: Request [REDACTED] was rejected for tenant [REDACTED] (at actor)",
    rest: "REST API v2 request failed for GET /v2/users.json (403 Forbidden): Request [REDACTED] was rejected for tenant [REDACTED]",
  },
];

// getResolvedConfig is the only surface method that sends nothing; every other one is walked.
const WALKED_SURFACE_METHODS = NEWRELIC_CLIENT_SURFACE_METHODS.filter((method) => method !== "getResolvedConfig");

/**
 * The corollary fixture with one method routed through a real NewrelicApiClient whose every request receives the
 * shape's response, so the failure the collectors, check_access, and the bundle see is the one the client's own
 * constructors built. Every error the real method throws is recorded for the thrown-error assertion.
 */
function errorBodyWalkClient(method, shape) {
  // resolveAccountIds only queries actor.accounts when no account ids are configured.
  const config = sampleConfig({ accountIds: method === "resolveAccountIds" ? [] : COROLLARY_ACCOUNT_IDS });
  const real = new NewrelicApiClient(config, { fetchImpl: shape.respond, maxRetries: 0 });
  const thrown = [];
  const client = {
    ...corollaryClient(),
    getResolvedConfig: () => config,
    async listRestUsers() {
      return [{ id: 1 }];
    },
    async [method](...args) {
      try {
        return await real[method](...args);
      } catch (error) {
        thrown.push(error);
        throw error;
      }
    },
  };
  return { client, thrown };
}

function assertNoCanary(text, label) {
  for (const [name, canary] of Object.entries(ERROR_BODY_CANARIES)) {
    assert.equal(text.includes(canary), false, `${name} canary reached ${label}`);
  }
}

test("rule 9 error-body walk: no upstream error body reaches any finding, summary, coverage note, errors array, bundle file, zip entry, or thrown error", async () => {
  const base = createTempBase("grclanker-newrelic-error-body-walk-");
  for (const method of WALKED_SURFACE_METHODS) {
    for (const shape of ERROR_BODY_SHAPES) {
      const label = `${method} with ${shape.shape}`;
      const { client, thrown } = errorBodyWalkClient(method, shape);
      const { results } = await assessAll({ identity: client, accessControl: client, alerting: client, dataGovernance: client });
      const access = await checkNewrelicAccess(client);
      const outputRoot = join(base, `${method}-${ERROR_BODY_SHAPES.indexOf(shape)}`);
      mkdirSync(outputRoot, { mode: 0o700 });
      const exported = await exportNewrelicAuditBundle(client, client.getResolvedConfig(), outputRoot, { now: NOW });
      const files = listFilesRecursively(exported.outputDir).map((file) => [file, readFileSync(join(exported.outputDir, file), "utf8")]);
      const zipEntries = [...readZipEntries(readFileSync(exported.zipPath))];

      // No canary anywhere: thrown errors, then in memory (findings, summaries, coverage notes, and errors arrays of
      // all four assessors, and check_access), then every bundle file and zip entry.
      assert.ok(thrown.length > 0, `${label}: the walk never exercised ${method}`);
      for (const error of thrown) assertNoCanary(error.message, `${label}: thrown error`);
      assertNoCanary(JSON.stringify(results), `${label}: assessment results`);
      assertNoCanary(JSON.stringify(access), `${label}: check_access result`);
      for (const [file, content] of files) assertNoCanary(content, `${label}: bundle file ${file}`);
      for (const [entry, content] of zipEntries) assertNoCanary(content, `${label}: zip entry ${entry}`);

      // Every error the client raised is the disclosed form and nothing else.
      const expected = method === "listRestUsers" ? shape.rest : shape.nerdgraph;
      for (const error of thrown) {
        assert.equal(error.message, expected, `${label}: thrown error`);
      }

      // The failure is disclosed, whole, where the consumer records errors.
      const disclosed = [
        ...results.flatMap((result) => result.errors),
        ...access.surfaces.map((surface) => surface.error).filter(Boolean),
      ];
      assert.ok(disclosed.some((text) => text.includes(expected)), `${label}: no errors entry or surface discloses "${expected}"; saw ${JSON.stringify(disclosed)}`);
      if (method !== "listRestUsers") {
        const errorsLog = files.find(([file]) => file === "_errors.log");
        assert.ok(errorsLog && errorsLog[1].includes(expected), `${label}: _errors.log does not disclose the failure`);
      }
    }
  }
});

test("rule 9 REST 403 body: checkNewrelicAccess echoes only the documented error.title and describes any other body", async () => {
  const cases = [
    {
      label: "documented title beside undocumented fields",
      respond: async () => restForbidden({
        error: { title: "The API key provided is invalid", detail: `session ${ERROR_BODY_CANARIES.session}` },
        debug: { authorization: `Bearer ${ERROR_BODY_CANARIES.bearer}`, license: ERROR_BODY_CANARIES.licenseKey, note: ERROR_BODY_CANARIES.restDetail },
      }),
      expected: "REST API v2 request failed for GET /v2/users.json (403 Forbidden): The API key provided is invalid",
    },
    {
      label: "documented title carrying a tokenised URL",
      respond: async () => restForbidden({ error: { title: `Forbidden; retry at ${TOKENISED_URL}` } }),
      expected: "REST API v2 request failed for GET /v2/users.json (403 Forbidden): Forbidden; retry at https://login.newrelic.com/callback?[REDACTED]",
    },
    {
      label: "JSON body without the documented title",
      respond: async () => restForbidden({ message: `denied ${ERROR_BODY_CANARIES.restDetail}`, session: ERROR_BODY_CANARIES.session }),
      expected: (bytes) => `REST API v2 request failed for GET /v2/users.json (403 Forbidden): JSON error body without a documented error.title (application/json; ${bytes} bytes)`,
      body: JSON.stringify({ message: `denied ${ERROR_BODY_CANARIES.restDetail}`, session: ERROR_BODY_CANARIES.session }),
    },
    {
      label: "text/html body",
      respond: async () => htmlResponse(HTML_502_BODY, 403, "Forbidden"),
      expected: `REST API v2 request failed for GET /v2/users.json (403 Forbidden): non-JSON error body (text/html; ${HTML_502_BYTES} bytes)`,
    },
  ];
  for (const testCase of cases) {
    const real = new NewrelicApiClient(sampleConfig({ accountIds: COROLLARY_ACCOUNT_IDS }), { fetchImpl: testCase.respond, maxRetries: 0 });
    const client = { ...corollaryClient(), listRestUsers: (...args) => real.listRestUsers(...args) };
    const result = await checkNewrelicAccess(client);
    const surface = result.surfaces.find((entry) => entry.name === "rest_v2_users");
    const expected = typeof testCase.expected === "function" ? testCase.expected(Buffer.byteLength(testCase.body, "utf8")) : testCase.expected;
    assert.equal(surface.status, "not_readable", testCase.label);
    assert.equal(surface.error, expected, testCase.label);
    assertNoCanary(JSON.stringify(result), `${testCase.label}: check_access result`);
    assert.equal(result.status, "healthy", `${testCase.label}: the optional REST surface does not limit access`);
  }
});

test("null standard: NR-10 unapproved_email_destinations carries the approved-domain inventory and renders null without a basis", async () => {
  const baseline = await assessGuarded(corollaryClient(), "unapproved destinations baseline");
  const baselineChannels = findingById(baseline, controlId(10));
  assert.deepEqual(baselineChannels.evidence.unapproved_email_destinations, []);
  assert.equal(baselineChannels.evidence.unapproved_email_destinations_status, "complete (aiNotifications.destinations, actor.user)");

  // actor.user denied: the comparison has no approved set, so the list is null beside a status naming actor.user.
  const userDenied = await assessGuarded(denyInventories(corollaryClient(), [["actor.user", "full"]]), "actor.user denied");
  const deniedChannels = findingById(userDenied, controlId(10));
  assert.equal(deniedChannels.status, "warn", deniedChannels.summary);
  assert.equal(deniedChannels.evidence.unapproved_email_destinations, null);
  assert.match(deniedChannels.evidence.unapproved_email_destinations_status, /^unreadable \(actor\.user: NerdGraph returned errors: Not authorized \(at actor\.user\)\)$/);

  // actor.user readable but without an email domain and no option passed: the comparison never ran.
  const noEmail = await assessGuarded(corollaryClient({
    async getCurrentUser() {
      return { id: "u-1", email: null, name: "Auditor" };
    },
  }), "actor.user without an email");
  const noEmailChannels = findingById(noEmail, controlId(10));
  assert.equal(noEmailChannels.evidence.approved_email_domains, null);
  assert.equal(noEmailChannels.evidence.unapproved_email_destinations, null);
  const undetermined = "unknown (not compared against an approved domain list: actor.user returned no email domain and approved_email_domains was not passed; inputs complete (aiNotifications.destinations, actor.user))";
  assert.equal(noEmailChannels.evidence.unapproved_email_destinations_status, undetermined);
  assert.equal(noEmailChannels.evidence.approved_email_domains_status, "unknown (not compared against an approved domain list: actor.user returned no email domain and approved_email_domains was not passed; inputs complete (actor.user))");

  // The option supplies the basis: the comparison runs on the destination listing alone, even with actor.user denied.
  const withOption = await assessNewrelicAlerting(denyInventories(corollaryClient(), [["actor.user", "full"]]), { approvedEmailDomains: ["example.com"] });
  const optionChannels = findingById(withOption, controlId(10));
  assert.deepEqual(optionChannels.evidence.unapproved_email_destinations, []);
  assert.equal(optionChannels.evidence.unapproved_email_destinations_status, "complete (aiNotifications.destinations)");

  // A destination outside the derived domain is listed when the basis exists.
  const unapproved = await assessGuarded(corollaryClient({
    async listNotificationDestinations(accountId) {
      return [{ id: `dest-${accountId}`, name: `Contractor pager ${accountId}`, type: "EMAIL", properties: [{ key: "email", value: "oncall@contractor.example.net" }] }];
    },
  }), "unapproved destination");
  const unapprovedChannels = findingById(unapproved, controlId(10));
  assert.deepEqual(unapprovedChannels.evidence.unapproved_email_destinations, ["Contractor pager 111", "Contractor pager 222"]);
  assert.equal(unapprovedChannels.evidence.unapproved_email_destinations_status, "complete (aiNotifications.destinations, actor.user)");
  assert.equal(unapprovedChannels.status, "warn", unapprovedChannels.summary);
});

test("null standard: NR-08 cross_environment_users renders null with an unknown status when accounts cannot be classified", async () => {
  const baseline = await assessGuarded(corollaryClient(), "cross environment baseline");
  const baselineAccounts = findingById(baseline, controlId(8));
  assert.deepEqual(baselineAccounts.evidence.cross_environment_users, []);
  assert.match(baselineAccounts.evidence.cross_environment_users_status, /^complete \(.*actor\.accounts\)$/);
  assert.equal(baseline.results[1].summary.cross_environment_users, 0);

  // Names on neither side of the production boundary: the comparison never ran, so no empty list or zero stands in.
  const unclassifiable = await assessGuarded(corollaryClient({
    async listAccounts() {
      return [{ id: 111, name: "Payments Alpha" }, { id: 222, name: "Payments Beta" }];
    },
  }), "unclassifiable accounts");
  const unclassifiableAccounts = findingById(unclassifiable, controlId(8));
  assert.equal(unclassifiableAccounts.status, "manual", unclassifiableAccounts.summary);
  assert.equal(unclassifiableAccounts.evidence.cross_environment_users, null);
  const gap = "unknown (not compared: account names did not match both the production pattern /prod/ and the non-production pattern /dev|test|stag|sandbox|qa|nonprod|non-prod|uat|demo/ (0 production, 0 non-production, 2 unclassified of 2 accounts); inputs complete (userManagement.users, authorizationManagement.groups, actor.accounts))";
  assert.equal(unclassifiableAccounts.evidence.cross_environment_users_status, gap);
  assert.deepEqual(unclassifiableAccounts.evidence.unclassified_accounts, ["Payments Alpha", "Payments Beta"]);
  assert.equal(unclassifiable.results[1].summary.cross_environment_users, null);
  assert.equal(unclassifiable.results[1].summary.cross_environment_users_status, gap);

  // Every account on one side: still no comparison.
  const productionOnly = await assessGuarded(corollaryClient({
    async listAccounts() {
      return [{ id: 111, name: "Payments Production" }, { id: 222, name: "Payments Production EU" }];
    },
  }), "production-only accounts");
  const productionAccounts = findingById(productionOnly, controlId(8));
  assert.equal(productionAccounts.evidence.cross_environment_users, null);
  assert.match(productionAccounts.evidence.cross_environment_users_status, /^unknown \(not compared: .*\(2 production, 0 non-production, 0 unclassified of 2 accounts\); inputs complete \(/);

  // An unreadable input outranks the classification gap: the status stays partial and names the scope and path.
  const partialAndUnclassifiable = await assessGuarded(denyInventories(corollaryClient({
    async listAccounts() {
      return [{ id: 111, name: "Payments Alpha" }, { id: 222, name: "Payments Beta" }];
    },
  }), [["authorizationManagement.groups", "partial"]]), "unclassifiable accounts with groups denied for one domain");
  const partialAccounts = findingById(partialAndUnclassifiable, controlId(8));
  assert.equal(partialAccounts.evidence.cross_environment_users, null);
  assert.match(partialAccounts.evidence.cross_environment_users_status, /^partial: 1 scope unreadable \(authorizationManagement\.groups: authentication domain Contractors: .*\(at actor\.organization\.authorizationManagement\.authenticationDomains\.groups\)\)/);
});

test("exportNewrelicAuditBundle allocates a fresh directory and zip on repeated runs", async () => {
  const base = createTempBase("grclanker-newrelic-export-repeat-");
  const config = sampleConfig({ accountIds: [111] });

  const first = await exportNewrelicAuditBundle(bundleClient(), config, base, { now: NOW });
  const second = await exportNewrelicAuditBundle(bundleClient(), config, base, { now: NOW });

  assert.notEqual(first.outputDir, second.outputDir);
  assert.notEqual(first.zipPath, second.zipPath);
  assert.match(second.outputDir, /newrelic-111-audit-bundle-2$/);
  assert.match(second.zipPath, /newrelic-111-audit-bundle-2\.zip$/);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.notEqual(readFileSync(first.zipPath).length, 0);
  assert.notEqual(readFileSync(second.zipPath).length, 0);
});

test("verdict safety rule 8: an export never overwrites a stale zip whose directory was removed", async () => {
  const base = createTempBase("grclanker-newrelic-export-stale-zip-");
  const staleZip = join(base, "newrelic-111-audit-bundle.zip");
  writeFileSync(staleZip, "stale archive from a prior run");

  const result = await exportNewrelicAuditBundle(bundleClient(), sampleConfig({ accountIds: [111] }), base, { now: NOW });

  assert.match(result.outputDir, /newrelic-111-audit-bundle-2$/);
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(readFileSync(staleZip, "utf8"), "stale archive from a prior run");
  assert.ok(existsSync(result.zipPath));
  assert.deepEqual(
    readdirSync(base).sort(),
    ["newrelic-111-audit-bundle-2", "newrelic-111-audit-bundle-2.zip", "newrelic-111-audit-bundle.zip"],
  );
});

test("exportNewrelicAuditBundle writes _errors.log when collection partially fails", async () => {
  const base = createTempBase("grclanker-newrelic-export-errors-");
  const client = bundleClient({
    async listObfuscationRules() {
      throw new Error("NerdGraph returned errors: Not authorized (at actor.account.logConfigurations)");
    },
    async listApiKeys() {
      throw new Error("NerdGraph returned errors: Not authorized (at actor.apiAccess.keySearch)");
    },
  });

  const result = await exportNewrelicAuditBundle(client, sampleConfig({ accountIds: [111] }), base, { now: NOW });

  assert.equal(result.findingCount, 20);
  assert.equal(result.errorCount, 2);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /logConfigurations\.obfuscationRules: /);
  assert.match(errorLog, /apiAccess\.keySearch: /);
  const executive = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executive, /## Partial Collection Warnings/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "NR-12-LOG-OBFUSCATION").status, "manual");
  assert.equal(findings.find((item) => item.id === "NR-04-API-KEY-INVENTORY").status, "manual");
  assert.ok(existsSync(result.zipPath));
});

test("exportNewrelicAuditBundle refuses to follow a symlink planted at the bundle path", async () => {
  const base = createTempBase("grclanker-newrelic-export-symlink-");
  const outside = createTempBase("grclanker-newrelic-export-outside-");
  symlinkSync(outside, join(base, "newrelic-111-audit-bundle"), "dir");

  await assert.rejects(
    exportNewrelicAuditBundle(bundleClient(), sampleConfig({ accountIds: [111] }), base, { now: NOW }),
    /symlinked parent directory/,
  );
  assert.deepEqual(readdirSync(outside), []);
});

test("resolveSecureOutputPath rejects traversal and symlinked parents", () => {
  const base = createTempBase("grclanker-newrelic-path-");
  const outside = createTempBase("grclanker-newrelic-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  assert.throws(() => resolveSecureOutputPath(base, "/etc/passwd"), /Refusing to write outside/);

  const safe = resolveSecureOutputPath(base, join("compliance", "safe.md"));
  assert.match(safe, /compliance\/safe\.md$/);
});

test("New Relic tools are registered in the tool catalog under the New Relic group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("newrelic_"));
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    [
      "newrelic_assess_access_control",
      "newrelic_assess_alerting",
      "newrelic_assess_data_governance",
      "newrelic_assess_identity",
      "newrelic_check_access",
      "newrelic_export_audit_bundle",
    ],
  );
  assert.ok(tools.every((tool) => tool.group === "New Relic"));
  assert.ok(tools.every((tool) => tool.kind === "domain"));
  const exportTool = tools.find((tool) => tool.name === "newrelic_export_audit_bundle");
  assert.match(exportTool.description, /20 spec controls/);
});
