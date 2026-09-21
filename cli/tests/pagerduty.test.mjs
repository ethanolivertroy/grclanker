import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PAGERDUTY_CONTROLS,
  PagerdutyApiClient,
  assessPagerdutyAccessControl,
  assessPagerdutyAuditLogging,
  assessPagerdutyIncidentResponse,
  assessPagerdutyIntegrationSecurity,
  assessPagerdutyOncallCoverage,
  checkPagerdutyAccess,
  collectionOf,
  exportPagerdutyAuditBundle,
  findingId,
  resolvePagerdutyConfiguration,
  resolveSecureOutputPath,
  runPagerdutyAccessControlAssessment,
  runPagerdutyAuditLoggingAssessment,
  runPagerdutyIncidentResponseAssessment,
  runPagerdutyIntegrationSecurityAssessment,
  runPagerdutyOncallCoverageAssessment,
  scheduleCoverageGaps,
} from "../dist/extensions/grc-tools/pagerduty.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const NOW = new Date("2026-09-21T00:00:00.000Z");
const EMPTY_ENV = { PAGERDUTY_CONFIG_FILE: "/nonexistent/pagerduty.json" };
const DAY_MS = 24 * 60 * 60 * 1000;
const COVERAGE_UNTIL = new Date(NOW.getTime() + 30 * DAY_MS);
const COVERAGE_WINDOW = { since: NOW.toISOString(), until: COVERAGE_UNTIL.toISOString(), days: 30 };
const AUDIT_WINDOWS = {
  recent: { since: "2026-08-22T00:00:00.000Z", until: NOW.toISOString() },
  retention: { since: "2025-09-21T00:00:00.000Z", until: "2025-10-21T00:00:00.000Z" },
};
const CHANGE_WINDOW = { since: "2026-08-22T00:00:00.000Z", until: NOW.toISOString() };
const ALL_CONTROLS = PAGERDUTY_CONTROLS.map((item) => item.control);

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    authMode: "api_token",
    apiToken: "pd-secret-token",
    region: "us",
    baseUrl: "https://api.pagerduty.com",
    identityTokenUrl: "https://identity.pagerduty.com/oauth/token",
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

function snapshot(data, error) {
  return error ? { data, error } : { data };
}

function list(items, error) {
  return snapshot(collectionOf(items), error);
}

function partialList(items, total = 2500) {
  return snapshot(collectionOf(items, {
    complete: false,
    total,
    truncation: `stopped at the requested limit of ${items.length} with more results available`,
  }));
}

function accountScope() {
  return snapshot({ kind: "account", fullVisibility: true, note: "account-level REST API key" });
}

function userScope(role = "user") {
  return snapshot({
    kind: "user",
    userId: "me-1",
    email: "me@example.com",
    role,
    fullVisibility: role === "owner" || role === "admin",
    note: role === "owner" || role === "admin"
      ? `user-level credential for me@example.com with role ${role}`
      : `user-level credential for me@example.com with role ${role} only returns the objects that user can see`,
  });
}

function findingById(result, controlNumber) {
  return result.findings.find((item) => item.id === findingId(controlNumber));
}

function assertStatuses(result, expected) {
  for (const [controlNumber, status] of Object.entries(expected)) {
    const item = findingById(result, Number(controlNumber));
    assert.ok(item, `finding ${findingId(Number(controlNumber))} missing`);
    assert.equal(item.status, status, `${item.id} expected ${status} but was ${item.status}: ${item.summary}`);
  }
}

function assertNoPass(findings, label) {
  const passing = findings.filter((item) => item.status === "pass").map((item) => `${item.id}: ${item.summary}`);
  assert.deepEqual(passing, [], `${label} must not produce pass verdicts`);
}

function user(id, overrides = {}) {
  return {
    id,
    email: `${id}@example.com`,
    role: "user",
    created_via_sso: true,
    teams: [{ id: "team-1" }],
    contact_methods: [
      { id: `${id}-email`, type: "email_contact_method", enabled: true },
      { id: `${id}-phone`, type: "phone_contact_method", enabled: true, blacklisted: false },
    ],
    notification_rules: [
      { id: `${id}-rule-high`, urgency: "high", contact_method: { id: `${id}-phone` } },
      { id: `${id}-rule-low`, urgency: "low", contact_method: { id: `${id}-email` } },
    ],
    ...overrides,
  };
}

function service(id, overrides = {}) {
  return {
    id,
    name: `Service ${id}`,
    summary: `Service ${id}`,
    status: "active",
    escalation_policy: { id: "ep-1" },
    incident_urgency_rule: { type: "use_support_hours", during_support_hours: { urgency: "high" }, outside_support_hours: { urgency: "low" } },
    acknowledgement_timeout: 1800,
    auto_resolve_timeout: 14400,
    integrations: [{ id: `${id}-int`, summary: "Events API v2", type: "events_api_v2_inbound_integration" }],
    ...overrides,
  };
}

function escalationPolicy(id, overrides = {}) {
  return {
    id,
    name: `Policy ${id}`,
    summary: `Policy ${id}`,
    num_loops: 2,
    services: [{ id: "svc-1" }],
    escalation_rules: [
      { escalation_delay_in_minutes: 30, targets: [{ id: "sched-1", type: "schedule_reference" }] },
      { escalation_delay_in_minutes: 30, targets: [{ id: "user-2", type: "user_reference" }] },
    ],
    ...overrides,
  };
}

function coveredSchedule(id, overrides = {}) {
  return {
    id,
    name: `Schedule ${id}`,
    summary: `Schedule ${id}`,
    escalation_policies: [{ id: "ep-1" }],
    users: [{ id: "user-1" }, { id: "user-2" }],
    schedule_layers: [{ users: [{ user: { id: "user-1" } }, { user: { id: "user-2" } }] }],
    final_schedule: {
      rendered_coverage_percentage: 100,
      rendered_schedule_entries: [
        { start: NOW.toISOString(), end: COVERAGE_UNTIL.toISOString(), user: { id: "user-1" } },
      ],
    },
    ...overrides,
  };
}

function auditRecord(id, executionTime, overrides = {}) {
  return {
    id,
    execution_time: executionTime,
    method: { type: "api_token", truncated_token: "abcd" },
    actors: [{ id: "owner-1", type: "user_reference" }],
    ...overrides,
  };
}

function healthyFixtures() {
  return {
    abilities: ["sso", "teams", "advanced_analytics", "audit_trail"],
    users: [user("owner-1", { role: "owner" }), user("admin-1", { role: "admin" }), user("user-1"), user("user-2")],
    teams: [{ id: "team-1", name: "Platform", summary: "Platform" }],
    teamMembers: [{ user: { id: "owner-1" }, role: "manager" }, { user: { id: "user-1" }, role: "responder" }],
    services: [service("svc-1"), service("svc-2", { incident_urgency_rule: { type: "constant", urgency: "high" } })],
    escalationPolicies: [escalationPolicy("ep-1")],
    schedules: [{ id: "sched-1", name: "Primary", summary: "Primary" }],
    oncalls: [{ user: { id: "user-1" }, schedule: { id: "sched-1" }, escalation_level: 1 }],
    extensions: [{ id: "ext-1", summary: "Slack", endpoint_url: "https://hooks.example.com/slack", extension_schema: { summary: "Slack V2" } }],
    webhookSubscriptions: [{ id: "wh-1", description: "SIEM", active: true, delivery_method: { type: "http_delivery_method", url: "https://siem.example.com/pd" } }],
    businessServices: [{ id: "bs-1", name: "Checkout", summary: "Checkout" }],
    businessServiceDependencies: [{ supporting_service: { id: "svc-1", type: "technical_service_reference" } }],
    priorities: [{ id: "p1", name: "P1", summary: "P1" }, { id: "p2", name: "P2", summary: "P2" }],
    incidentWorkflows: [{ id: "wf-1", name: "Page leadership", is_enabled: true }],
    incidentWorkflowTriggers: [{ id: "trig-1", trigger_type: "conditional_trigger", services: [{ id: "svc-1" }] }],
    changeEvents: [{ id: "chg-1", summary: "deploy 1.2.3", timestamp: new Date(NOW.getTime() - DAY_MS).toISOString(), services: [{ id: "svc-1" }] }],
  };
}

function healthyClient(overrides = {}, wrap = (items) => collectionOf(items)) {
  const fixtures = healthyFixtures();
  return {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => NOW,
    async getAbilities() {
      return fixtures.abilities;
    },
    async getCredentialScope() {
      return { kind: "account", fullVisibility: true, note: "account-level REST API key" };
    },
    async listUsers() {
      return wrap(fixtures.users);
    },
    async listTeams() {
      return wrap(fixtures.teams);
    },
    async listTeamMembers() {
      return wrap(fixtures.teamMembers);
    },
    async listServices() {
      return wrap(fixtures.services);
    },
    async listEscalationPolicies() {
      return wrap(fixtures.escalationPolicies);
    },
    async listSchedules() {
      return wrap(fixtures.schedules);
    },
    async getSchedule() {
      return coveredSchedule("sched-1");
    },
    async listOncalls() {
      return wrap(fixtures.oncalls);
    },
    async listAuditRecords(since) {
      return wrap([auditRecord("audit-1", new Date(since.getTime() + DAY_MS).toISOString())]);
    },
    async listExtensions() {
      return wrap(fixtures.extensions);
    },
    async listWebhookSubscriptions() {
      return wrap(fixtures.webhookSubscriptions);
    },
    async listBusinessServices() {
      return wrap(fixtures.businessServices);
    },
    async getBusinessServiceDependencies() {
      return fixtures.businessServiceDependencies;
    },
    async listPriorities() {
      return wrap(fixtures.priorities);
    },
    async listIncidentWorkflows() {
      return wrap(fixtures.incidentWorkflows);
    },
    async listIncidentWorkflowTriggers() {
      return wrap(fixtures.incidentWorkflowTriggers);
    },
    async listChangeEvents() {
      return wrap(fixtures.changeEvents);
    },
    ...overrides,
  };
}

function failing(message) {
  return async () => {
    throw new Error(message);
  };
}

function forbiddenClient() {
  const deny = (path) => failing(`PagerDuty request failed (403 Forbidden) for ${path}: Access Denied`);
  return {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => NOW,
    getAbilities: deny("/abilities"),
    getCredentialScope: deny("/users/me"),
    listUsers: deny("/users"),
    listTeams: deny("/teams"),
    listTeamMembers: deny("/teams/{id}/members"),
    listServices: deny("/services"),
    listEscalationPolicies: deny("/escalation_policies"),
    listSchedules: deny("/schedules"),
    getSchedule: deny("/schedules/{id}"),
    listOncalls: deny("/oncalls"),
    listAuditRecords: deny("/audit/records"),
    listExtensions: deny("/extensions"),
    listWebhookSubscriptions: deny("/webhook_subscriptions"),
    listBusinessServices: deny("/business_services"),
    getBusinessServiceDependencies: deny("/service_dependencies/business_services/{id}"),
    listPriorities: deny("/priorities"),
    listIncidentWorkflows: deny("/incident_workflows"),
    listIncidentWorkflowTriggers: deny("/incident_workflows/triggers"),
    listChangeEvents: deny("/change_events"),
  };
}

function emptyClient() {
  const empty = async () => collectionOf([]);
  return healthyClient({
    getAbilities: async () => [],
    listUsers: empty,
    listTeams: empty,
    listTeamMembers: empty,
    listServices: empty,
    listEscalationPolicies: empty,
    listSchedules: empty,
    listOncalls: empty,
    listAuditRecords: empty,
    listExtensions: empty,
    listWebhookSubscriptions: empty,
    listBusinessServices: empty,
    getBusinessServiceDependencies: async () => [],
    listPriorities: empty,
    listIncidentWorkflows: empty,
    listIncidentWorkflowTriggers: empty,
    listChangeEvents: empty,
  });
}

function partialClient() {
  return healthyClient(
    {
      async getCredentialScope() {
        return {
          kind: "user",
          userId: "me-1",
          email: "me@example.com",
          role: "user",
          fullVisibility: false,
          note: "user-level credential for me@example.com with role user only returns the objects that user can see",
        };
      },
    },
    (items) => collectionOf(items, {
      complete: false,
      total: 2500,
      truncation: `stopped at the requested limit of ${items.length} with more results available`,
    }),
  );
}

async function runAllAssessments(client) {
  const results = await Promise.all([
    runPagerdutyAccessControlAssessment(client, { maxAdmins: 3 }),
    runPagerdutyIncidentResponseAssessment(client),
    runPagerdutyOncallCoverageAssessment(client, { coverageDays: 30 }),
    runPagerdutyAuditLoggingAssessment(client),
    runPagerdutyIntegrationSecurityAssessment(client),
  ]);
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 25);
  return { results, findings };
}

test("PAGERDUTY_CONTROLS defines all 25 spec controls with eight framework mappings each", () => {
  assert.equal(PAGERDUTY_CONTROLS.length, 25);
  const numbers = [...ALL_CONTROLS].sort((left, right) => left - right);
  assert.deepEqual(numbers, Array.from({ length: 25 }, (_, index) => index + 1));
  for (const item of PAGERDUTY_CONTROLS) {
    assert.equal(Object.keys(item.mappings).length, 8, `control ${item.control} mappings`);
  }
  assert.equal(findingId(7), "PD-07");
  assert.equal(findingId(25), "PD-25");
});

test("resolvePagerdutyConfiguration prefers explicit args over environment values", () => {
  const resolved = resolvePagerdutyConfiguration(
    {
      api_token: "arg-token",
      region: "eu",
      from_email: "auditor@example.com",
      timeout_seconds: 9,
      config_file: "/nonexistent/pagerduty.json",
    },
    {
      PAGERDUTY_API_TOKEN: "env-token",
      PAGERDUTY_REGION: "us",
    },
  );

  assert.equal(resolved.authMode, "api_token");
  assert.equal(resolved.apiToken, "arg-token");
  assert.equal(resolved.region, "eu");
  assert.equal(resolved.baseUrl, "https://api.eu.pagerduty.com");
  assert.equal(resolved.fromEmail, "auditor@example.com");
  assert.equal(resolved.timeoutMs, 9000);
  assert.ok(resolved.sourceChain.includes("arguments-api-token"));
  assert.ok(resolved.sourceChain.includes("arguments-region"));
});

test("resolvePagerdutyConfiguration maps environment regions and base URLs", () => {
  const fromEnv = resolvePagerdutyConfiguration({}, { ...EMPTY_ENV, PAGERDUTY_API_KEY: "env-key", PAGERDUTY_SERVICE_REGION: "EU" });
  assert.equal(fromEnv.apiToken, "env-key");
  assert.equal(fromEnv.region, "eu");
  assert.equal(fromEnv.baseUrl, "https://api.eu.pagerduty.com");
  assert.ok(fromEnv.sourceChain.includes("environment-api-token"));

  const defaults = resolvePagerdutyConfiguration({}, { ...EMPTY_ENV, PD_API_KEY: "legacy-key" });
  assert.equal(defaults.region, "us");
  assert.equal(defaults.baseUrl, "https://api.pagerduty.com");
  assert.equal(defaults.timeoutMs, 30000);

  const explicitBase = resolvePagerdutyConfiguration(
    {},
    { ...EMPTY_ENV, PAGERDUTY_TOKEN: "token", PAGERDUTY_BASE_URL: "https://api.eu.pagerduty.com/" },
  );
  assert.equal(explicitBase.region, "eu");
  assert.equal(explicitBase.baseUrl, "https://api.eu.pagerduty.com");

  assert.throws(
    () => resolvePagerdutyConfiguration({}, { ...EMPTY_ENV, PAGERDUTY_API_TOKEN: "token", PAGERDUTY_REGION: "apac" }),
    /Unsupported PagerDuty service region/,
  );
});

test("resolvePagerdutyConfiguration selects OAuth auth modes and reads config files", () => {
  const bearer = resolvePagerdutyConfiguration({}, { ...EMPTY_ENV, PAGERDUTY_ACCESS_TOKEN: "oauth-bearer" });
  assert.equal(bearer.authMode, "oauth_bearer");
  assert.equal(bearer.accessToken, "oauth-bearer");

  const clientCredentials = resolvePagerdutyConfiguration({}, {
    ...EMPTY_ENV,
    PAGERDUTY_CLIENT_ID: "client-id",
    PAGERDUTY_CLIENT_SECRET: "client-secret",
    PAGERDUTY_SUBDOMAIN: "acme",
  });
  assert.equal(clientCredentials.authMode, "oauth_client_credentials");
  assert.equal(clientCredentials.subdomain, "acme");

  const base = createTempBase("grclanker-pagerduty-config-");
  const configPath = join(base, "pagerduty.json");
  writeFileSync(configPath, JSON.stringify({ api_token: "file-token", region: "eu", timeout_seconds: 12 }));
  const fromFile = resolvePagerdutyConfiguration({}, { PAGERDUTY_CONFIG_FILE: configPath });
  assert.equal(fromFile.apiToken, "file-token");
  assert.equal(fromFile.region, "eu");
  assert.equal(fromFile.timeoutMs, 12000);
  assert.ok(fromFile.sourceChain.includes("config-file-api-token"));

  const envOverFile = resolvePagerdutyConfiguration({}, { PAGERDUTY_CONFIG_FILE: configPath, PAGERDUTY_API_TOKEN: "env-token" });
  assert.equal(envOverFile.apiToken, "env-token");

  assert.throws(() => resolvePagerdutyConfiguration({}, EMPTY_ENV), /PagerDuty credentials are required/);
});

test("PagerdutyApiClient sends the versioned Accept header, Token auth, and follows classic pagination to completion", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      params: Object.fromEntries(url.searchParams.entries()),
      includes: url.searchParams.getAll("include[]"),
      accept: headerValue(init.headers, "accept"),
      auth: headerValue(init.headers, "authorization"),
    });
    const offset = Number(url.searchParams.get("offset") ?? "0");
    if (offset === 0) {
      return jsonResponse({ users: [{ id: "user-1" }], limit: 1, offset: 0, more: true, total: 2 });
    }
    return jsonResponse({ users: [{ id: "user-2" }], limit: 1, offset: 1, more: false, total: 2 });
  };

  const client = new PagerdutyApiClient(sampleConfig(), { fetchImpl });
  const users = await client.listUsers(5);

  assert.deepEqual(users.items.map((item) => item.id), ["user-1", "user-2"]);
  assert.equal(users.complete, true);
  assert.equal(users.total, 2);
  assert.equal(users.truncation, undefined);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].pathname, "/users");
  assert.equal(seen[0].accept, "application/vnd.pagerduty+json;version=2");
  assert.equal(seen[0].auth, "Token token=pd-secret-token");
  assert.equal(seen[0].params.offset, "0");
  assert.equal(seen[0].params.total, "true");
  assert.equal(seen[1].params.offset, "1");
  assert.ok(seen[0].includes.includes("contact_methods"));
  assert.ok(seen[0].includes.includes("notification_rules"));
});

test("PagerdutyApiClient follows cursor pagination for audit records and honors the EU base URL", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ host: url.host, pathname: url.pathname, cursor: url.searchParams.get("cursor") });
    if (!url.searchParams.get("cursor")) {
      return jsonResponse({ records: [{ id: "rec-1" }], next_cursor: "cursor-2" });
    }
    return jsonResponse({ records: [{ id: "rec-2" }], next_cursor: null });
  };

  const client = new PagerdutyApiClient(sampleConfig({ region: "eu", baseUrl: "https://api.eu.pagerduty.com" }), { fetchImpl });
  const records = await client.listAuditRecords(new Date("2026-09-01T00:00:00Z"), NOW, 10);

  assert.deepEqual(records.items.map((item) => item.id), ["rec-1", "rec-2"]);
  assert.equal(records.complete, true);
  assert.equal(seen[0].host, "api.eu.pagerduty.com");
  assert.equal(seen[0].pathname, "/audit/records");
  assert.equal(seen[0].cursor, null);
  assert.equal(seen[1].cursor, "cursor-2");
});

test("PagerdutyApiClient retries 429 and 5xx responses using ratelimit headers", async () => {
  let attempts = 0;
  const sleeps = [];
  const fetchImpl = async () => {
    attempts += 1;
    if (attempts === 1) {
      return jsonResponse({ error: { message: "Rate limited", code: 2020 } }, { status: 429, headers: { "ratelimit-reset": "2" } });
    }
    if (attempts === 2) {
      return jsonResponse({ error: { message: "Server error" } }, { status: 503 });
    }
    return jsonResponse({ abilities: ["sso", "teams"] });
  };

  const client = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  const abilities = await client.getAbilities();

  assert.deepEqual(abilities, ["sso", "teams"]);
  assert.equal(attempts, 3);
  assert.deepEqual(sleeps, [2000, 2000]);
});

test("PagerdutyApiClient surfaces API errors with redacted tokens", async () => {
  const fetchImpl = async () =>
    jsonResponse(
      { error: { message: "Access denied for token pd-secret-token", code: 2010, errors: ["insufficient scope"] } },
      { status: 403, statusText: "Forbidden" },
    );

  const client = new PagerdutyApiClient(sampleConfig(), { fetchImpl, maxRetries: 0 });
  await assert.rejects(client.listTeams(), (error) => {
    assert.equal(error.status, 403);
    assert.match(error.message, /403 Forbidden/);
    assert.match(error.message, /insufficient scope/);
    assert.ok(!error.message.includes("pd-secret-token"));
    assert.ok(error.message.includes("[REDACTED]"));
    return true;
  });
});

test("PagerdutyApiClient exchanges Scoped OAuth client credentials before calling the API", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ host: url.host, pathname: url.pathname, method: init.method ?? "GET", auth: headerValue(init.headers, "authorization"), body: init.body });
    if (url.host === "identity.pagerduty.com") {
      return jsonResponse({ access_token: "oauth-access", expires_in: 3600, token_type: "bearer" });
    }
    return jsonResponse({ teams: [{ id: "team-1" }], more: false });
  };

  const config = resolvePagerdutyConfiguration({}, {
    ...EMPTY_ENV,
    PAGERDUTY_CLIENT_ID: "client-id",
    PAGERDUTY_CLIENT_SECRET: "client-secret",
    PAGERDUTY_SUBDOMAIN: "acme",
    PAGERDUTY_REGION: "eu",
  });
  const client = new PagerdutyApiClient(config, { fetchImpl, now: () => NOW });
  const teams = await client.listTeams(5);

  assert.deepEqual(teams.items.map((item) => item.id), ["team-1"]);
  assert.equal(seen[0].pathname, "/oauth/token");
  assert.equal(seen[0].method, "POST");
  assert.match(String(seen[0].body), /grant_type=client_credentials/);
  assert.match(String(seen[0].body), /as_account-eu\.acme/);
  assert.equal(seen[1].host, "api.eu.pagerduty.com");
  assert.equal(seen[1].auth, "Bearer oauth-access");

  const scope = await client.getCredentialScope();
  assert.equal(scope.kind, "account");
  assert.equal(scope.fullVisibility, true);
  assert.equal(seen.filter((request) => request.pathname === "/users/me").length, 0);
});

test("PagerdutyApiClient classifies credential scope from GET /users/me", async () => {
  const accountKey = new PagerdutyApiClient(sampleConfig(), {
    maxRetries: 0,
    fetchImpl: async () =>
      jsonResponse({ error: { message: "Requested users/me but the request was not authenticated as a user.", code: 2002 } }, { status: 400, statusText: "Bad Request" }),
  });
  const account = await accountKey.getCredentialScope();
  assert.equal(account.kind, "account");
  assert.equal(account.fullVisibility, true);

  const limitedKey = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ user: { id: "me-1", email: "me@example.com", role: "user" } }),
  });
  const limited = await limitedKey.getCredentialScope();
  assert.equal(limited.kind, "user");
  assert.equal(limited.role, "user");
  assert.equal(limited.fullVisibility, false);
  assert.match(limited.note, /only returns the objects that user can see/);

  const adminKey = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ user: { id: "me-2", email: "admin@example.com", role: "admin" } }),
  });
  const admin = await adminKey.getCredentialScope();
  assert.equal(admin.kind, "user");
  assert.equal(admin.fullVisibility, true);

  const broken = new PagerdutyApiClient(sampleConfig(), {
    maxRetries: 0,
    fetchImpl: async () => jsonResponse({ error: { message: "nope" } }, { status: 403, statusText: "Forbidden" }),
  });
  await assert.rejects(broken.getCredentialScope(), /403 Forbidden/);
});

test("checkPagerdutyAccess reports healthy when every read surface responds", async () => {
  const result = await checkPagerdutyAccess(healthyClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.region, "us");
  assert.equal(result.authMode, "api_token");
  assert.equal(result.surfaces.length, 14);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(result.missingPermissions, []);
  assert.ok(result.notes.some((note) => note.startsWith("Credential scope: account-level")));
  assert.match(result.recommendedNextStep, /pagerduty_export_audit_bundle/);
});

test("checkPagerdutyAccess reports limited access, missing permissions, and partial credential scope", async () => {
  const result = await checkPagerdutyAccess(healthyClient({
    listUsers: failing("PagerDuty request failed (403 Forbidden) for /users: Access Denied"),
    listAuditRecords: failing("PagerDuty request failed (402 Payment Required) for /audit/records"),
    listExtensions: failing("PagerDuty request failed (403 Forbidden) for /extensions"),
  }));

  assert.equal(result.status, "limited");
  assert.equal(result.surfaces.filter((surface) => surface.status === "not_readable").length, 3);
  assert.equal(result.missingPermissions.length, 3);
  assert.ok(result.missingPermissions.some((item) => item.startsWith("/users: users.read")));
  assert.ok(result.missingPermissions.some((item) => item.startsWith("/audit/records: audit_records.read")));
  assert.match(result.recommendedNextStep, /read-only account-level REST API key/);
  assert.ok(result.notes.some((note) => note.startsWith("Missing read access")));

  const limitedScope = await checkPagerdutyAccess(partialClient());
  assert.equal(limitedScope.status, "limited");
  assert.ok(limitedScope.notes.some((note) => /partial visibility/.test(note)));
});

test("assessPagerdutyAccessControl passes on a well governed tenant", () => {
  const result = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso", "teams", "advanced_analytics"]),
    users: list([user("owner-1", { role: "owner" }), user("admin-1", { role: "admin" }), user("user-1"), user("user-2", { role: "read_only_user" })]),
    teams: list([{ id: "team-1", name: "Platform" }]),
    teamMembers: snapshot({ "team-1": [{ user: { id: "owner-1" }, role: "manager" }] }),
  }, { maxAdmins: 3 });

  assert.equal(result.category, "access_control");
  assert.equal(result.findings.length, 5);
  assertStatuses(result, { 1: "manual", 2: "pass", 3: "pass", 4: "pass", 24: "manual" });
  assert.match(findingById(result, 1).summary, /Account Settings > Single Sign-On/);
  assert.match(findingById(result, 2).summary, /2 of 4 users hold owner or admin roles/);
  assert.match(findingById(result, 24).summary, /Analytics/);
  assert.deepEqual(result.errors, []);
  for (const item of result.findings) {
    assert.equal(item.mappings.length, 8, `${item.id} should carry eight framework mappings`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")), `${item.id} mappings: ${item.mappings.join(", ")}`);
  }
  assert.deepEqual(findingById(result, 1).mappings, [
    "FedRAMP IA-2",
    "CMMC IA.L2-3.5.1",
    "SOC 2 CC6.1",
    "CIS 4.1",
    "PCI-DSS 8.3.1",
    "STIG SRG-APP-000148",
    "IRAP ISM-1557",
    "ISMAP 8.2.1",
  ]);
  assert.ok(findingById(result, 2).mappings.includes("CMMC AC.L2-3.1.5"));
});

test("assessPagerdutyAccessControl fails without SSO, with excess admins, and without teams", () => {
  const result = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["advanced_analytics"]),
    users: list([
      user("owner-1", { role: "owner", created_via_sso: false, teams: [] }),
      user("owner-2", { role: "owner", created_via_sso: false, teams: [] }),
      user("admin-1", { role: "admin", created_via_sso: false, teams: [] }),
      user("admin-2", { role: "admin", created_via_sso: false, teams: [] }),
    ]),
    teams: list([]),
    teamMembers: snapshot({}),
  }, { maxAdmins: 2 });

  assertStatuses(result, { 1: "fail", 2: "fail", 3: "fail", 4: "fail", 24: "manual" });
  assert.deepEqual(findingById(result, 3).evidence.owners, ["owner-1@example.com", "owner-2@example.com"]);
  assert.match(findingById(result, 4).summary, /empty team list fails this control/);
  assert.equal(result.summary.fail, 4);
  assert.equal(result.summary.manual, 1);
});

test("assessPagerdutyAccessControl falls back to manual findings when users cannot be read", () => {
  const result = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot([], "PagerDuty request failed (403 Forbidden) for /abilities"),
    users: list([], "PagerDuty request failed (403 Forbidden) for /users"),
    teams: list([]),
    teamMembers: snapshot({}),
  });

  assertStatuses(result, { 1: "manual", 2: "manual", 3: "manual", 4: "manual", 24: "manual" });
  assert.equal(result.errors.length, 2);
  assert.match(result.errors[0], /^access_control\.abilities: /);
});

test("assessPagerdutyIncidentResponse passes when services, policies, and automation are configured", () => {
  const result = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([service("svc-1"), service("svc-2", { incident_urgency_rule: { type: "constant", urgency: "high" } })]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([{ id: "p1", name: "P1", summary: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", name: "Page leadership", is_enabled: true }]),
    workflowTriggers: list([{ id: "trig-1", services: [{ id: "svc-1" }] }]),
  });

  assert.equal(result.category, "incident_response");
  assert.equal(result.findings.length, 8);
  assertStatuses(result, { 5: "pass", 6: "pass", 7: "pass", 10: "pass", 19: "pass", 20: "pass", 22: "pass", 23: "pass" });
});

test("assessPagerdutyIncidentResponse flags missing policies, single levels, and disabled timeouts", () => {
  const result = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([
      service("svc-1", {
        escalation_policy: undefined,
        incident_urgency_rule: undefined,
        acknowledgement_timeout: null,
        auto_resolve_timeout: null,
      }),
      service("svc-disabled", { status: "disabled", escalation_policy: undefined }),
    ]),
    escalationPolicies: list([
      escalationPolicy("ep-single", { num_loops: 0, escalation_rules: [{ escalation_delay_in_minutes: 30, targets: [] }] }),
    ]),
    priorities: list([]),
    incidentWorkflows: list([]),
    workflowTriggers: list([]),
  });

  assertStatuses(result, { 5: "fail", 6: "warn", 7: "fail", 10: "fail", 19: "fail", 20: "fail", 22: "warn", 23: "warn" });
  assert.deepEqual(findingById(result, 5).evidence.services_without_policy, ["Service svc-1"]);
  assert.equal(findingById(result, 5).evidence.disabled_services, 1);
  assert.match(findingById(result, 10).summary, /emptiness fails this control/);
  assert.match(findingById(result, 20).summary, /emptiness fails this control/);
});

test("assessPagerdutyIncidentResponse warns on constant high urgency and non repeating policies", () => {
  const result = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([service("svc-1", { incident_urgency_rule: { type: "constant", urgency: "high" } })]),
    escalationPolicies: list([escalationPolicy("ep-1", { num_loops: 0 })]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", is_enabled: false }]),
    workflowTriggers: list([]),
  });

  assertStatuses(result, { 7: "warn", 10: "warn", 19: "warn" });
  assert.match(findingById(result, 7).summary, /never repeat/);
});

test("assessPagerdutyIncidentResponse becomes manual when services cannot be read", () => {
  const result = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([], "PagerDuty request failed (403 Forbidden) for /services"),
    escalationPolicies: list([], "PagerDuty request failed (403 Forbidden) for /escalation_policies"),
    priorities: list([], "PagerDuty request failed (403 Forbidden) for /priorities"),
    incidentWorkflows: list([], "PagerDuty request failed (403 Forbidden) for /incident_workflows"),
    workflowTriggers: list([]),
  });

  assertStatuses(result, { 5: "manual", 6: "manual", 7: "manual", 10: "manual", 19: "manual", 20: "manual", 22: "manual", 23: "manual" });
  assert.equal(result.errors.length, 4);
});

test("scheduleCoverageGaps detects uncovered windows and buckets entries missing dates", () => {
  const until = new Date(NOW.getTime() + 3 * DAY_MS);
  const dayOne = new Date(NOW.getTime() + DAY_MS);
  const dayTwo = new Date(NOW.getTime() + 2 * DAY_MS);

  const covered = scheduleCoverageGaps({
    final_schedule: { rendered_schedule_entries: [{ start: NOW.toISOString(), end: until.toISOString() }] },
  }, NOW, until);
  assert.deepEqual(covered.gaps, []);
  assert.equal(covered.entriesMissingDates, 0);
  assert.equal(covered.entries, 1);

  const gapped = scheduleCoverageGaps({
    final_schedule: {
      rendered_schedule_entries: [
        { start: NOW.toISOString(), end: dayOne.toISOString() },
        { start: dayTwo.toISOString(), end: until.toISOString() },
      ],
    },
  }, NOW, until);
  assert.equal(gapped.gaps.length, 1);
  assert.equal(new Date(gapped.gaps[0].start).getTime(), dayOne.getTime());
  assert.equal(new Date(gapped.gaps[0].end).getTime(), dayTwo.getTime());

  const empty = scheduleCoverageGaps({ final_schedule: { rendered_schedule_entries: [] } }, NOW, until);
  assert.equal(empty.gaps.length, 1);

  const undated = scheduleCoverageGaps({
    final_schedule: { rendered_schedule_entries: [{ start: NOW.toISOString(), end: null }] },
  }, NOW, until);
  assert.equal(undated.entriesMissingDates, 1);
  assert.equal(undated.gaps.length, 1, "an entry without an end never counts as coverage");
});

test("assessPagerdutyOncallCoverage passes with continuous coverage and verified responders", () => {
  const result = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: list([{ user: { id: "user-1" }, schedule: { id: "sched-1" } }]),
    users: list([user("user-1"), user("user-2"), user("ro-1", { role: "read_only_user", notification_rules: [] })]),
    coverageWindow: COVERAGE_WINDOW,
  });

  assert.equal(result.category, "oncall_coverage");
  assert.equal(result.findings.length, 4);
  assertStatuses(result, { 8: "pass", 9: "pass", 17: "pass", 18: "pass" });
  assert.equal(result.summary.responders, 2);
  assert.match(findingById(result, 18).summary, /enabled true and blacklisted false/);
});

test("assessPagerdutyOncallCoverage fails on gaps, single participants, and missing contact methods", () => {
  const midpoint = new Date(NOW.getTime() + 15 * DAY_MS);
  const result = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([
      coveredSchedule("sched-1", {
        users: [{ id: "user-1" }],
        schedule_layers: [{ users: [{ user: { id: "user-1" } }] }],
        final_schedule: {
          rendered_coverage_percentage: 50,
          rendered_schedule_entries: [{ start: NOW.toISOString(), end: midpoint.toISOString(), user: { id: "user-1" } }],
        },
      }),
    ]),
    oncalls: list([{ user: { id: "user-1" } }, { user: { id: "user-2" } }]),
    users: list([
      user("user-1", { contact_methods: [], notification_rules: [] }),
      user("user-2", { contact_methods: [{ type: "email_contact_method", enabled: true }], notification_rules: [{ urgency: "low" }] }),
      user("user-3", { notification_rules: [] }),
      user("user-4", { notification_rules: [] }),
    ]),
    coverageWindow: COVERAGE_WINDOW,
  });

  assertStatuses(result, { 8: "fail", 9: "fail", 17: "fail", 18: "fail" });
  assert.equal(findingById(result, 8).evidence.schedules_with_gaps.length, 1);
  assert.equal(findingById(result, 8).evidence.schedules_with_gaps[0].gaps.length, 1);
  assert.deepEqual(findingById(result, 18).evidence.oncall_without_contact_methods, ["user-1@example.com"]);
  assert.deepEqual(findingById(result, 18).evidence.oncall_email_only, ["user-2@example.com"]);
});

test("assessPagerdutyOncallCoverage warns on email-only responders and manual when unreadable", () => {
  const warned = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: list([{ user: { id: "user-1" } }]),
    users: list([
      user("user-1", { contact_methods: [{ type: "email_contact_method", enabled: true }], notification_rules: [{ urgency: "low" }] }),
      user("user-2"),
      user("user-3"),
      user("user-4"),
      user("user-5"),
    ]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(warned, { 17: "warn", 18: "warn" });

  const manual = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([], "PagerDuty request failed (403 Forbidden) for /schedules"),
    scheduleDetails: snapshot([]),
    oncalls: list([], "PagerDuty request failed (403 Forbidden) for /oncalls"),
    users: list([], "PagerDuty request failed (403 Forbidden) for /users"),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(manual, { 8: "manual", 9: "manual", 17: "manual", 18: "manual" });
  assert.equal(manual.errors.length, 3);
});

test("assessPagerdutyAuditLogging passes with dated recent records and a dated retention probe", () => {
  const result = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: list([
      auditRecord("a1", "2026-09-20T10:00:00Z", { actors: [{ id: "user-1" }] }),
      auditRecord("a2", "2026-09-19T10:00:00Z", { method: { type: "browser" }, actors: [{ id: "user-2" }] }),
    ]),
    retentionProbe: list([auditRecord("old-1", "2025-10-01T00:00:00Z")]),
    windows: AUDIT_WINDOWS,
  });

  assert.equal(result.category, "audit_logging");
  assert.equal(result.findings.length, 3);
  assertStatuses(result, { 11: "pass", 12: "pass", 13: "manual" });
  assert.equal(findingById(result, 13).evidence.api_tokens_observed.length, 1);
  assert.equal(findingById(result, 13).evidence.api_tokens_observed[0].truncated_token, "...abcd");
  assert.match(findingById(result, 13).summary, /Integrations > API Access Keys/);
});

test("assessPagerdutyAuditLogging goes manual on 402 plan errors and warns on empty retention probes", () => {
  const noPlan = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: list([], "PagerDuty request failed (402 Payment Required) for /audit/records: Audit Trail not enabled"),
    retentionProbe: list([], "PagerDuty request failed (402 Payment Required) for /audit/records"),
    windows: AUDIT_WINDOWS,
  });
  assertStatuses(noPlan, { 11: "manual", 12: "manual", 13: "manual" });
  assert.match(findingById(noPlan, 11).summary, /not included in this account's plan/);

  const forbidden = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: list([], "PagerDuty request failed (403 Forbidden) for /audit/records"),
    retentionProbe: list([]),
    windows: AUDIT_WINDOWS,
  });
  assertStatuses(forbidden, { 11: "manual", 12: "manual", 13: "manual" });

  const quiet = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: list([]),
    retentionProbe: list([]),
    windows: AUDIT_WINDOWS,
  });
  assertStatuses(quiet, { 11: "warn", 12: "warn", 13: "manual" });

  const longRetention = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: list([auditRecord("a1", "2026-09-20T10:00:00Z", { method: { type: "browser" } })]),
    retentionProbe: list([auditRecord("old-1", "2025-10-01T00:00:00Z")]),
    windows: AUDIT_WINDOWS,
  }, { minRetentionDays: 730 });
  assertStatuses(longRetention, { 11: "pass", 12: "manual" });
  assert.match(findingById(longRetention, 12).summary, /SIEM or archive/);
});

test("assessPagerdutyIntegrationSecurity passes with https endpoints and mapped dependencies", () => {
  const result = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([service("svc-1")]),
    extensions: list([{ id: "ext-1", summary: "Slack", endpoint_url: "https://hooks.example.com/slack", extension_schema: { summary: "Slack V2" } }]),
    webhookSubscriptions: list([{ id: "wh-1", active: true, delivery_method: { url: "https://siem.example.com/pd" } }]),
    businessServices: list([{ id: "bs-1", name: "Checkout" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }] }),
    changeEvents: list([{ id: "chg-1", timestamp: "2026-09-15T00:00:00Z", services: [{ id: "svc-1" }] }]),
    changeWindow: CHANGE_WINDOW,
  });

  assert.equal(result.category, "integration_security");
  assert.equal(result.findings.length, 5);
  assertStatuses(result, { 14: "pass", 15: "pass", 16: "pass", 21: "pass", 25: "pass" });
  assert.match(findingById(result, 15).summary, /X-PagerDuty-Signature/);
  assert.match(findingById(result, 15).summary, /1 extensions were read/);
});

test("assessPagerdutyIntegrationSecurity flags http webhooks, legacy integrations, and missing dependencies", () => {
  const result = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([
      service("svc-1", {
        integrations: [
          { id: "int-1", summary: "Nagios", type: "nagios_inbound_integration" },
          { id: "int-2", summary: "Email", type: "generic_email_inbound_integration", email_filter_mode: "all-email" },
        ],
      }),
    ]),
    extensions: list([
      { id: "ext-1", summary: "Legacy webhook", endpoint_url: "http://hooks.example.com/legacy", extension_schema: { summary: "Generic V2 Webhook" } },
    ]),
    webhookSubscriptions: list([{ id: "wh-1", active: true, delivery_method: { url: "http://siem.example.com/pd" } }]),
    businessServices: list([]),
    businessServiceDependencies: snapshot({}),
    changeEvents: list([]),
    changeWindow: CHANGE_WINDOW,
  });

  assertStatuses(result, { 14: "fail", 15: "warn", 16: "warn", 21: "fail", 25: "fail" });
  assert.equal(findingById(result, 14).evidence.insecure_extensions.length, 1);
  assert.equal(findingById(result, 14).evidence.insecure_subscriptions.length, 1);
  assert.equal(findingById(result, 16).evidence.legacy_integrations.length, 1);
  assert.equal(findingById(result, 16).evidence.unfiltered_email_integrations.length, 1);
  assert.match(findingById(result, 21).summary, /emptiness fails this control/);
  assert.match(findingById(result, 25).summary, /emptiness fails this control/);
});

test("assessPagerdutyIntegrationSecurity warns on unmapped business services and idle change events", () => {
  const warned = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([service("svc-1")]),
    extensions: list([]),
    webhookSubscriptions: list([]),
    businessServices: list([{ id: "bs-1", name: "Checkout" }, { id: "bs-2", name: "Search" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }], "bs-2": [] }),
    changeEvents: list([]),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(warned, { 14: "manual", 15: "manual", 21: "warn", 25: "warn" });
  assert.deepEqual(findingById(warned, 21).evidence.unmapped_business_services, ["Search"]);

  const manual = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([], "PagerDuty request failed (403 Forbidden) for /services"),
    extensions: list([], "PagerDuty request failed (403 Forbidden) for /extensions"),
    webhookSubscriptions: list([]),
    businessServices: list([], "PagerDuty request failed (403 Forbidden) for /business_services"),
    businessServiceDependencies: snapshot({}),
    changeEvents: list([], "PagerDuty request failed (403 Forbidden) for /change_events"),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(manual, { 14: "manual", 15: "manual", 16: "manual", 21: "manual", 25: "manual" });
  assert.equal(manual.errors.length, 4);
});

test("run*Assessment helpers collect from the client and together cover all 25 controls", async () => {
  const { results, findings } = await runAllAssessments(healthyClient());

  const ids = findings.map((item) => item.id).sort();
  assert.deepEqual(ids, PAGERDUTY_CONTROLS.map((item) => findingId(item.control)).sort());
  assert.deepEqual(results.flatMap((result) => result.errors), []);
  const manualIds = findings.filter((item) => item.status === "manual").map((item) => item.id);
  assert.deepEqual(manualIds.sort(), ["PD-01", "PD-13", "PD-24"]);
  assert.deepEqual(findings.filter((item) => item.status === "warn" || item.status === "fail"), []);
});

test("verdict rule 1: forbidden or errored endpoints yield manual verdicts that name the cause and the evidence to collect", () => {
  const forbidden = "PagerDuty request failed (403 Forbidden) for /users: Access Denied";
  const result = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso", "teams"]),
    users: list([], forbidden),
    teams: list([{ id: "team-1" }]),
    teamMembers: snapshot({}),
  });
  assertStatuses(result, { 2: "manual", 3: "manual", 4: "manual" });
  for (const control of [2, 3, 4]) {
    assert.match(findingById(result, control).summary, /users could not be read \(PagerDuty request failed \(403 Forbidden\)/);
    assert.match(findingById(result, control).summary, /Users page|Teams/);
  }

  const teamsForbidden = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso", "teams"]),
    users: list([user("owner-1", { role: "owner" }), user("user-1")]),
    teams: list([], "PagerDuty request failed (403 Forbidden) for /teams"),
    teamMembers: snapshot({}),
  });
  assertStatuses(teamsForbidden, { 2: "pass", 4: "manual" });
  assert.match(findingById(teamsForbidden, 4).summary, /teams could not be read/);

  const triggersDown = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([service("svc-1")]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", is_enabled: true }]),
    workflowTriggers: list([], "PagerDuty request failed (500 Internal Server Error) for /incident_workflows/triggers"),
  });
  assertStatuses(triggersDown, { 10: "manual" });
  assert.match(findingById(triggersDown, 10).summary, /incident workflow triggers could not be read \(PagerDuty request failed \(500/);

  const oncallsDown = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: list([], "PagerDuty request failed (401 Unauthorized) for /oncalls"),
    users: list([user("user-1"), user("user-2")]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(oncallsDown, { 8: "pass", 17: "pass", 18: "manual" });
  assert.match(findingById(oncallsDown, 18).summary, /on-call entries could not be read \(PagerDuty request failed \(401/);
});

test("verdict rule 2: empty inventories never pass by default and each summary states why", () => {
  const noUsers = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso", "teams"]),
    users: list([]),
    teams: list([{ id: "team-1" }]),
    teamMembers: snapshot({}),
  });
  assertStatuses(noUsers, { 2: "manual", 3: "manual", 4: "manual" });
  assert.match(findingById(noUsers, 2).summary, /Zero users were returned/);

  const emptyAbilities = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot([]),
    users: list([user("owner-1", { role: "owner" })]),
    teams: list([{ id: "team-1" }]),
    teamMembers: snapshot({}),
  });
  assertStatuses(emptyAbilities, { 1: "manual" });
  assert.match(findingById(emptyAbilities, 1).summary, /empty ability list/);

  const noServices = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([]),
    escalationPolicies: list([]),
    priorities: list([]),
    incidentWorkflows: list([]),
    workflowTriggers: list([]),
  });
  assertStatuses(noServices, { 5: "manual", 6: "manual", 7: "manual", 10: "fail", 19: "manual", 20: "fail", 22: "manual", 23: "manual" });
  assert.match(findingById(noServices, 5).summary, /zero services/);
  assert.match(findingById(noServices, 6).summary, /zero policies/);

  const unattachedPolicies = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([service("svc-1")]),
    escalationPolicies: list([escalationPolicy("ep-1", { services: [] })]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", is_enabled: true }]),
    workflowTriggers: list([{ id: "trig-1" }]),
  });
  assertStatuses(unattachedPolicies, { 6: "manual", 7: "manual" });
  assert.match(findingById(unattachedPolicies, 6).summary, /none is attached to a service/);

  const noSchedules = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([]),
    scheduleDetails: snapshot([]),
    oncalls: list([]),
    users: list([]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(noSchedules, { 8: "manual", 9: "manual", 17: "manual", 18: "manual" });
  assert.match(findingById(noSchedules, 8).summary, /zero schedules/);

  const nobodyOnCall = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: list([]),
    users: list([user("user-1"), user("user-2")]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(nobodyOnCall, { 18: "manual" });
  assert.match(findingById(nobodyOnCall, 18).summary, /no one on call right now/);

  const noWebhooks = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([]),
    extensions: list([]),
    webhookSubscriptions: list([]),
    businessServices: list([]),
    businessServiceDependencies: snapshot({}),
    changeEvents: list([]),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(noWebhooks, { 14: "manual", 15: "manual", 16: "manual", 21: "fail", 25: "manual" });
  assert.match(findingById(noWebhooks, 15).summary, /not applicable until a webhook exists/);
  assert.match(findingById(noWebhooks, 21).summary, /emptiness fails this control/);

  const zeroLegacyExtensions = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([service("svc-1")]),
    extensions: list([]),
    webhookSubscriptions: list([{ id: "wh-1", active: true, delivery_method: { url: "https://siem.example.com/pd" } }]),
    businessServices: list([{ id: "bs-1" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }] }),
    changeEvents: list([{ id: "chg-1", timestamp: "2026-09-15T00:00:00Z", services: [{ id: "svc-1" }] }]),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(zeroLegacyExtensions, { 15: "pass" });
  assert.match(findingById(zeroLegacyExtensions, 15).summary, /^0 extensions were read and none is a legacy generic webhook; 1 of 1 webhook subscriptions have active true/);

  const extensionsUnreadable = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([service("svc-1")]),
    extensions: list([], "PagerDuty request failed (403 Forbidden) for /extensions"),
    webhookSubscriptions: list([{ id: "wh-1", active: true, delivery_method: { url: "https://siem.example.com/pd" } }]),
    businessServices: list([{ id: "bs-1" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }] }),
    changeEvents: list([]),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(extensionsUnreadable, { 14: "manual", 15: "manual" });
});

test("verdict rule 3: out-of-scope controls and plan-gated features render manual with a plan or not applicable summary", () => {
  const audit = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: list([], "PagerDuty request failed (402 Payment Required) for /audit/records: Audit Trail is not available on your plan"),
    retentionProbe: list([], "PagerDuty request failed (402 Payment Required) for /audit/records"),
    windows: AUDIT_WINDOWS,
  });
  assertStatuses(audit, { 11: "manual", 12: "manual" });
  assert.match(findingById(audit, 11).summary, /plan/);
  assert.match(findingById(audit, 12).summary, /plan/);

  const workflows = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([service("svc-1")]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([], "PagerDuty request failed (402 Payment Required) for /priorities"),
    incidentWorkflows: list([], "PagerDuty request failed (402 Payment Required) for /incident_workflows"),
    workflowTriggers: list([]),
  });
  assertStatuses(workflows, { 10: "manual", 20: "manual" });
  assert.match(findingById(workflows, 10).summary, /not available on this account's plan/);
  assert.match(findingById(workflows, 10).summary, /not applicable/);
  assert.match(findingById(workflows, 20).summary, /plan/);

  const business = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([service("svc-1")]),
    extensions: list([{ id: "ext-1", endpoint_url: "https://hooks.example.com", extension_schema: { summary: "Slack V2" } }]),
    webhookSubscriptions: list([{ id: "wh-1", active: true, delivery_method: { url: "https://siem.example.com/pd" } }]),
    businessServices: list([], "PagerDuty request failed (402 Payment Required) for /business_services"),
    businessServiceDependencies: snapshot({}),
    changeEvents: list([{ id: "chg-1", timestamp: "2026-09-15T00:00:00Z", services: [{ id: "svc-1" }] }]),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(business, { 21: "manual" });
  assert.match(findingById(business, 21).summary, /not available on this account's plan/);

  const analytics = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso", "teams", "advanced_analytics"]),
    users: list([user("owner-1", { role: "owner" })]),
    teams: list([{ id: "team-1" }]),
    teamMembers: snapshot({}),
  });
  assertStatuses(analytics, { 1: "manual", 24: "manual" });
  assert.match(findingById(analytics, 24).summary, /outside the API's scope/);
});

test("verdict rule 4: items missing dates are bucketed separately and cap the verdict at warn", () => {
  const undatedSchedule = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([
      coveredSchedule("sched-1", {
        final_schedule: {
          rendered_schedule_entries: [
            { start: NOW.toISOString(), end: COVERAGE_UNTIL.toISOString(), user: { id: "user-1" } },
            { start: NOW.toISOString(), end: null, user: { id: "user-2" } },
          ],
        },
      }),
    ]),
    oncalls: list([{ user: { id: "user-1" } }]),
    users: list([user("user-1"), user("user-2")]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(undatedSchedule, { 8: "warn" });
  assert.deepEqual(findingById(undatedSchedule, 8).evidence.schedules_with_undated_entries, [{ schedule: "Schedule sched-1", entries_missing_dates: 1 }]);

  const onlyUndatedSchedule = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([
      coveredSchedule("sched-1", {
        final_schedule: { rendered_schedule_entries: [{ start: null, end: null, user: { id: "user-1" } }] },
      }),
    ]),
    oncalls: list([{ user: { id: "user-1" } }]),
    users: list([user("user-1"), user("user-2")]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assert.notEqual(findingById(onlyUndatedSchedule, 8).status, "pass");

  const undatedAudit = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: list([auditRecord("a1", null), auditRecord("a2", undefined)]),
    retentionProbe: list([auditRecord("old-1", null)]),
    windows: AUDIT_WINDOWS,
  });
  assertStatuses(undatedAudit, { 11: "warn", 12: "warn" });
  assert.equal(findingById(undatedAudit, 11).evidence.records_missing_execution_time, 2);
  assert.equal(findingById(undatedAudit, 11).evidence.records_dated_in_window, 0);
  assert.equal(findingById(undatedAudit, 12).evidence.probe_records_missing_execution_time, 1);

  const undatedChangeEvents = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([service("svc-1")]),
    extensions: list([{ id: "ext-1", endpoint_url: "https://hooks.example.com", extension_schema: { summary: "Slack V2" } }]),
    webhookSubscriptions: list([{ id: "wh-1", active: true, delivery_method: { url: "https://siem.example.com/pd" } }]),
    businessServices: list([{ id: "bs-1" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }] }),
    changeEvents: list([{ id: "chg-1", services: [{ id: "svc-1" }] }]),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(undatedChangeEvents, { 25: "warn" });
  assert.equal(findingById(undatedChangeEvents, 25).evidence.change_events_missing_timestamp, 1);
});

test("verdict rule 5: partial inventories and partially scoped credentials downgrade pass to warn with seen and total counts", () => {
  const truncatedUsers = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso", "teams"]),
    users: partialList([user("owner-1", { role: "owner" }), user("user-1")]),
    teams: list([{ id: "team-1" }]),
    teamMembers: snapshot({}),
  });
  assertStatuses(truncatedUsers, { 2: "warn", 3: "warn", 4: "warn" });
  assert.match(findingById(truncatedUsers, 2).summary, /Downgraded from pass to warn because the inventory is partial: users: 2 of 2500 seen \(stopped at the requested limit/);
  assert.deepEqual(findingById(truncatedUsers, 2).evidence.partial_view, ["users: 2 of 2500 seen (stopped at the requested limit of 2 with more results available)"]);

  const limitedKey = assessPagerdutyIncidentResponse({
    scope: userScope("user"),
    services: list([service("svc-1")]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", is_enabled: true }]),
    workflowTriggers: list([{ id: "trig-1" }]),
  });
  assertStatuses(limitedKey, { 5: "warn", 6: "warn", 7: "warn", 10: "warn", 19: "warn", 20: "warn", 22: "warn", 23: "warn" });
  assert.match(findingById(limitedKey, 5).summary, /user-level credential for me@example.com with role user only returns the objects that user can see/);

  const adminKey = assessPagerdutyIncidentResponse({
    scope: userScope("admin"),
    services: list([service("svc-1")]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", is_enabled: true }]),
    workflowTriggers: list([{ id: "trig-1" }]),
  });
  assertStatuses(adminKey, { 5: "pass", 20: "pass" });

  const unknownScope = assessPagerdutyAuditLogging({
    scope: snapshot({ kind: "unknown", fullVisibility: false }, "PagerDuty request failed (500 Internal Server Error) for /users/me"),
    recentRecords: list([auditRecord("a1", "2026-09-20T10:00:00Z")]),
    retentionProbe: list([auditRecord("old-1", "2025-10-01T00:00:00Z")]),
    windows: AUDIT_WINDOWS,
  });
  assertStatuses(unknownScope, { 11: "warn", 12: "warn" });
  assert.match(findingById(unknownScope, 11).summary, /credential scope could not be determined/);

  const failStaysFail = assessPagerdutyIncidentResponse({
    scope: userScope("user"),
    services: partialList([service("svc-1", { escalation_policy: undefined })]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", is_enabled: true }]),
    workflowTriggers: list([{ id: "trig-1" }]),
  });
  assertStatuses(failStaysFail, { 5: "fail" });
});

test("verdict rule 6: absent or false enabling flags never support pass", () => {
  const flags = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([service("svc-1", { integrations: undefined })]),
    extensions: list([{ id: "ext-1", endpoint_url: "https://hooks.example.com" }]),
    webhookSubscriptions: list([{ id: "wh-1", delivery_method: { url: "https://siem.example.com/pd" } }]),
    businessServices: list([{ id: "bs-1" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }] }),
    changeEvents: list([{ id: "chg-1", timestamp: "2026-09-15T00:00:00Z", services: [{ id: "svc-1" }] }]),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(flags, { 14: "pass", 15: "warn", 16: "warn" });
  assert.match(findingById(flags, 15).summary, /no extension_schema summary/);
  assert.equal(findingById(flags, 15).evidence.subscriptions_missing_active_flag, 1);
  assert.match(findingById(flags, 16).summary, /did not return the integrations expansion/);

  const inactiveSubscription = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list([service("svc-1")]),
    extensions: list([{ id: "ext-1", endpoint_url: "https://hooks.example.com", extension_schema: { summary: "Slack V2" } }]),
    webhookSubscriptions: list([{ id: "wh-1", active: false, delivery_method: { url: "https://siem.example.com/pd" } }]),
    businessServices: list([{ id: "bs-1" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }] }),
    changeEvents: list([{ id: "chg-1", timestamp: "2026-09-15T00:00:00Z", services: [{ id: "svc-1" }] }]),
    changeWindow: CHANGE_WINDOW,
  });
  assertStatuses(inactiveSubscription, { 15: "warn" });
  assert.match(findingById(inactiveSubscription, 15).summary, /zero with active true/);

  const contactFlags = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: list([{ user: { id: "user-1" } }, { user: { id: "user-2" } }]),
    users: list([
      user("user-1", { contact_methods: [{ type: "phone_contact_method" }] }),
      user("user-2", { contact_methods: [{ type: "phone_contact_method", enabled: true, blacklisted: true }, { type: "email_contact_method", enabled: true }] }),
    ]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(contactFlags, { 18: "warn" });
  assert.deepEqual(findingById(contactFlags, 18).evidence.oncall_unverifiable_methods, ["user-1@example.com"]);
  assert.deepEqual(findingById(contactFlags, 18).evidence.oncall_email_only, ["user-2@example.com"]);

  const escalationFlags = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([service("svc-1")]),
    escalationPolicies: list([
      escalationPolicy("ep-1", { num_loops: undefined }),
      escalationPolicy("ep-2", { escalation_rules: undefined }),
    ]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1" }]),
    workflowTriggers: list([{ id: "trig-1" }]),
  });
  assertStatuses(escalationFlags, { 6: "warn", 7: "fail", 10: "warn" });
  assert.match(findingById(escalationFlags, 7).summary, /no rules or rules with no notification targets/);
  assert.match(findingById(escalationFlags, 10).summary, /none is both enabled \(is_enabled true\)/);

  const roleFlags = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso"]),
    users: list([user("owner-1", { role: "owner" }), user("mystery-1", { role: undefined })]),
    teams: list([{ id: "team-1" }]),
    teamMembers: snapshot({}),
  });
  assertStatuses(roleFlags, { 2: "warn", 3: "warn", 4: "fail" });
  assert.match(findingById(roleFlags, 2).summary, /1 users have no role field/);
  assert.match(findingById(roleFlags, 4).summary, /"teams" ability is absent/);
});

test("verdict rule 7: pagination runs to completion or records truncation with totals", async () => {
  const truncatedFetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const offset = Number(url.searchParams.get("offset") ?? "0");
    const limit = Number(url.searchParams.get("limit") ?? "100");
    const users = Array.from({ length: limit }, (_, index) => ({ id: `user-${offset + index}` }));
    return jsonResponse({ users, limit, offset, more: true, total: 2500 });
  };
  const client = new PagerdutyApiClient(sampleConfig(), { fetchImpl: truncatedFetch });

  const truncated = await client.listUsers(150);
  assert.equal(truncated.items.length, 150);
  assert.equal(truncated.complete, false);
  assert.equal(truncated.total, 2500);
  assert.match(truncated.truncation, /stopped at the requested limit of 150 with more results available/);

  const ceiling = await client.listUsers(10000);
  assert.equal(ceiling.items.length, 10000);
  assert.equal(ceiling.complete, false);
  assert.match(ceiling.truncation, /10000 record pagination ceiling/);

  let cursorCalls = 0;
  const cursorClient = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async () => {
      cursorCalls += 1;
      return jsonResponse({ records: [{ id: `rec-${cursorCalls}` }], next_cursor: `cursor-${cursorCalls + 1}` });
    },
  });
  const cursorTruncated = await cursorClient.listAuditRecords(new Date("2026-09-01T00:00:00Z"), NOW, 3);
  assert.equal(cursorTruncated.items.length, 3);
  assert.equal(cursorTruncated.complete, false);
  assert.match(cursorTruncated.truncation, /next_cursor still available/);

  const paged = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const offset = Number(url.searchParams.get("offset") ?? "0");
      const page = [[{ id: "a" }], [{ id: "b" }], [{ id: "c" }]][offset] ?? [];
      return jsonResponse({ services: page, more: offset < 2, total: 3 });
    },
  });
  const complete = await paged.list("/services", "services", {}, { limit: 10, pageSize: 1 });
  assert.deepEqual(complete.items.map((item) => item.id), ["a", "b", "c"]);
  assert.equal(complete.complete, true);
  assert.equal(complete.total, 3);

  const assessment = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso", "teams"]),
    users: snapshot(truncated),
    teams: list([{ id: "team-1" }]),
    teamMembers: snapshot({}),
  });
  assert.notEqual(findingById(assessment, 3).status, "pass");
  assert.match(findingById(assessment, 3).evidence.partial_view[0], /users: 150 of 2500 seen/);
});

test("verdict rule 8: re-running an export allocates a paired directory and zip instead of overwriting", async () => {
  const base = createTempBase("grclanker-pagerduty-rerun-");
  const first = await exportPagerdutyAuditBundle(healthyClient(), sampleConfig(), base, { maxAdmins: 3 });
  const firstZipBytes = readFileSync(first.zipPath);
  const second = await exportPagerdutyAuditBundle(healthyClient(), sampleConfig(), base, { maxAdmins: 3 });

  assert.match(first.outputDir, /pagerduty-us-audit-bundle$/);
  assert.match(first.zipPath, /pagerduty-us-audit-bundle\.zip$/);
  assert.match(second.outputDir, /pagerduty-us-audit-bundle-2$/);
  assert.match(second.zipPath, /pagerduty-us-audit-bundle-2\.zip$/);
  assert.notEqual(first.zipPath, second.zipPath);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
  assert.deepEqual(readFileSync(first.zipPath), firstZipBytes, "the first archive must not be rewritten");

  const third = await exportPagerdutyAuditBundle(healthyClient(), sampleConfig(), base, { maxAdmins: 3 });
  assert.match(third.zipPath, /pagerduty-us-audit-bundle-3\.zip$/);
  assert.equal(readdirSync(base).filter((name) => name.endsWith(".zip")).length, 3);

  const orphanBase = createTempBase("grclanker-pagerduty-orphan-zip-");
  writeFileSync(join(orphanBase, "pagerduty-us-audit-bundle.zip"), "existing archive");
  const skipped = await exportPagerdutyAuditBundle(healthyClient(), sampleConfig(), orphanBase, { maxAdmins: 3 });
  assert.match(skipped.outputDir, /pagerduty-us-audit-bundle-2$/);
  assert.match(skipped.zipPath, /pagerduty-us-audit-bundle-2\.zip$/);
  assert.equal(readFileSync(join(orphanBase, "pagerduty-us-audit-bundle.zip"), "utf8"), "existing archive");
});

test("false-pass self-check (a): every endpoint forbidden yields 25 manual findings and zero passes", async () => {
  const { results, findings } = await runAllAssessments(forbiddenClient());
  assertNoPass(findings, "forbidden fixture");
  assert.equal(findings.filter((item) => item.status === "manual").length, 25);
  for (const item of findings) {
    assert.match(item.summary, /could not be read|has no endpoint|never exposes/, `${item.id} must name the cause: ${item.summary}`);
  }
  assert.ok(results.every((result) => result.errors.length > 0));
});

test("false-pass self-check (b): every list empty yields zero passes, with emptiness stated as fail or manual per control", async () => {
  const { findings } = await runAllAssessments(emptyClient());
  assertNoPass(findings, "empty fixture");
  const byId = Object.fromEntries(findings.map((item) => [item.id, item.status]));
  assert.deepEqual(byId, {
    "PD-01": "manual",
    "PD-02": "manual",
    "PD-03": "manual",
    "PD-04": "manual",
    "PD-05": "manual",
    "PD-06": "manual",
    "PD-07": "manual",
    "PD-08": "manual",
    "PD-09": "manual",
    "PD-10": "fail",
    "PD-11": "warn",
    "PD-12": "warn",
    "PD-13": "manual",
    "PD-14": "manual",
    "PD-15": "manual",
    "PD-16": "manual",
    "PD-17": "manual",
    "PD-18": "manual",
    "PD-19": "manual",
    "PD-20": "fail",
    "PD-21": "fail",
    "PD-22": "manual",
    "PD-23": "manual",
    "PD-24": "manual",
    "PD-25": "manual",
  });
  for (const id of ["PD-10", "PD-20", "PD-21"]) {
    assert.match(findings.find((item) => item.id === id).summary, /emptiness fails this control/);
  }
});

test("false-pass self-check (c): partial inventories from a user-scoped key yield zero passes", async () => {
  const { findings } = await runAllAssessments(partialClient());
  assertNoPass(findings, "partial fixture");
  const downgraded = findings.filter((item) => item.status === "warn");
  assert.ok(downgraded.length >= 20, `expected most findings to be downgraded to warn, saw ${downgraded.length}`);
  for (const item of downgraded) {
    assert.match(item.summary, /Downgraded from pass to warn because the inventory is partial/, item.id);
    assert.match(item.summary, /of 2500 seen|user-level credential/, item.id);
    assert.ok(Array.isArray(item.evidence.partial_view) && item.evidence.partial_view.length > 0, `${item.id} evidence.partial_view`);
  }
  assert.deepEqual(findings.filter((item) => item.status === "manual").map((item) => item.id).sort(), ["PD-01", "PD-13", "PD-24"]);
});

test("exportPagerdutyAuditBundle writes core data, analysis, compliance reports, and archive", async () => {
  const base = createTempBase("grclanker-pagerduty-export-");
  const result = await exportPagerdutyAuditBundle(healthyClient(), sampleConfig(), base, { maxAdmins: 3 });

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.match(result.zipPath, /pagerduty-us-audit-bundle\.zip$/);
  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 37, `expected at least 37 files, saw ${result.fileCount}`);

  const expectedFiles = [
    "core_data/access_check.json",
    "core_data/credential_scope.json",
    "core_data/abilities.json",
    "core_data/users.json",
    "core_data/teams.json",
    "core_data/services.json",
    "core_data/escalation_policies.json",
    "core_data/schedules.json",
    "core_data/schedule_details.json",
    "core_data/oncalls.json",
    "core_data/audit_records_recent.json",
    "core_data/extensions.json",
    "core_data/webhook_subscriptions.json",
    "core_data/business_services.json",
    "core_data/change_events.json",
    "analysis/findings.json",
    "analysis/metadata.json",
    "analysis/access_control.json",
    "analysis/incident_response.json",
    "analysis/oncall_coverage.json",
    "analysis/audit_logging.json",
    "analysis/integration_security.json",
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
    "QUICK_REFERENCE.md",
  ];
  for (const relativePath of expectedFiles) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 25);
  const users = JSON.parse(readFileSync(join(result.outputDir, "core_data", "users.json"), "utf8"));
  assert.equal(users.complete, true);
  assert.equal(users.items.length, 4);
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "analysis", "metadata.json"), "utf8"));
  assert.equal(metadata.region, "us");
  assert.equal(metadata.controls_total, 25);
  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /PD-01/);
  assert.match(matrix, /PD-25/);
  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.ok(!summary.includes("pd-secret-token"));
  assert.ok(!readFileSync(join(result.outputDir, "core_data", "access_check.json"), "utf8").includes("pd-secret-token"));
});

test("exportPagerdutyAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("grclanker-pagerduty-export-errors-");
  const client = healthyClient({
    listAuditRecords: failing("PagerDuty request failed (403 Forbidden) for /audit/records: Access Denied"),
    listExtensions: failing("PagerDuty request failed (403 Forbidden) for /extensions: Access Denied"),
  });

  const result = await exportPagerdutyAuditBundle(client, sampleConfig({ region: "eu", baseUrl: "https://api.eu.pagerduty.com" }), base);

  assert.ok(result.errorCount >= 2);
  assert.match(result.outputDir, /pagerduty-eu-audit-bundle$/);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /audit_logging\.recent_records: /);
  assert.match(errorLog, /integration_security\.extensions: /);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "PD-11").status, "manual");
  assert.equal(findings.find((item) => item.id === "PD-14").status, "manual");

  const second = await exportPagerdutyAuditBundle(client, sampleConfig({ region: "eu", baseUrl: "https://api.eu.pagerduty.com" }), base);
  assert.match(second.outputDir, /pagerduty-eu-audit-bundle-2$/);
  assert.match(second.zipPath, /pagerduty-eu-audit-bundle-2\.zip$/);
  assert.ok(readdirSync(base).includes("pagerduty-eu-audit-bundle.zip"));
  assert.ok(readdirSync(base).includes("pagerduty-eu-audit-bundle-2.zip"));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-pagerduty-path-");
  const outside = createTempBase("grclanker-pagerduty-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});

test("exportPagerdutyAuditBundle refuses to follow a symlinked bundle directory", async () => {
  const base = createTempBase("grclanker-pagerduty-symlink-root-");
  const outside = createTempBase("grclanker-pagerduty-symlink-target-");
  symlinkSync(outside, join(base, "pagerduty-us-audit-bundle"), "dir");

  await assert.rejects(
    exportPagerdutyAuditBundle(healthyClient(), sampleConfig(), base),
    /symlinked parent directory/,
  );
  assert.equal(readdirSync(outside).length, 0);
});

test("PagerDuty tools are registered in the tool catalog under the PagerDuty group", () => {
  const summaries = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("pagerduty_"));
  const names = summaries.map((tool) => tool.name).sort();
  assert.deepEqual(names, [
    "pagerduty_assess_access_control",
    "pagerduty_assess_audit_logging",
    "pagerduty_assess_incident_response",
    "pagerduty_assess_integration_security",
    "pagerduty_assess_oncall_coverage",
    "pagerduty_check_access",
    "pagerduty_export_audit_bundle",
  ]);
  for (const tool of summaries) {
    assert.equal(tool.group, "PagerDuty", `${tool.name} group`);
    assert.ok(tool.description.length > 20, `${tool.name} description`);
  }
});
