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
  DEFAULT_AUDIT_LIMIT,
  PAGERDUTY_CONTROLS,
  PagerdutyApiClient,
  PagerdutyRequestError,
  assessPagerdutyAccessControl,
  assessPagerdutyAuditLogging,
  assessPagerdutyIncidentResponse,
  assessPagerdutyIntegrationSecurity,
  assessPagerdutyOncallCoverage,
  checkPagerdutyAccess,
  collectPagerdutyAccessControlData,
  collectionOf,
  exportPagerdutyAuditBundle,
  findingId,
  redactSnapshot,
  reduceUrl,
  registerPagerdutyTools,
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
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import { assertConfigLoaderMatrix, configLoaderCases } from "./helpers/config-loader-matrix.mjs";
import { assertScrubBoundary } from "./helpers/scrub-boundary-matrix.mjs";

const NOW = new Date("2026-09-21T00:00:00.000Z");
// An explicit config path must exist (a missing explicit file is a read error), so isolation from
// the operator's ~/.config/grclanker/pagerduty.json uses an empty JSON object in a scratch directory.
const EMPTY_CONFIG_FILE = join(mkdtempSync(join(tmpdir(), "grclanker-pagerduty-empty-config-")), "pagerduty.json");
writeFileSync(EMPTY_CONFIG_FILE, "{}\n");
const EMPTY_ENV = { PAGERDUTY_CONFIG_FILE: EMPTY_CONFIG_FILE };
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
    incidentWorkflowTriggers: [{
      id: "trig-1",
      trigger_type: "conditional",
      is_disabled: false,
      workflow: { id: "wf-1", type: "workflow_reference" },
      services: [{ id: "svc-1" }],
    }],
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
      config_file: EMPTY_CONFIG_FILE,
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

test("addendum 6b: the JSON config loader reports read and parse failures with fixed text and never quotes the file, JSON.parse, or the fs error", async () => {
  const cases = configLoaderCases({ format: "json", displayName: "PagerDuty", fileNoun: "config file", extension: ".json" });
  assert.deepEqual(cases.map((item) => item.name), [
    "json unquoted value",
    "json short source",
    "json trailing comma with position",
    "EISDIR",
    "EACCES",
    "ENOENT on an explicit path",
  ]);
  const registered = [];
  registerPagerdutyTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "pagerduty_check_access");
  await assertConfigLoaderMatrix(cases, {
    resolve: (path) => resolvePagerdutyConfiguration({ config_file: path }, {}),
    checkAccess: (path) => checkAccess.execute("call-config", checkAccess.prepareArguments({ config_file: path })),
  });
  // The env-pointed path is explicit as well: the same defect there is a parse failure, and a missing file a read error.
  const [unquoted] = cases;
  assert.throws(() => resolvePagerdutyConfiguration({}, { PAGERDUTY_CONFIG_FILE: unquoted.path }), (error) => {
    assert.equal(error.message, unquoted.expectedMessage);
    assert.equal(error.code, "INVALID_JSON");
    return true;
  });
  const absent = join(createTempBase("grclanker-pagerduty-absent-"), "absent.json");
  assert.throws(() => resolvePagerdutyConfiguration({}, { PAGERDUTY_CONFIG_FILE: absent }), (error) => {
    assert.equal(error.message, `Unable to read PagerDuty config file ${absent} (ENOENT)`);
    assert.equal(error.code, "ENOENT");
    return true;
  });
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
    workflowTriggers: list([{ id: "trig-1", is_disabled: false, services: [{ id: "svc-1" }] }]),
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
    workflowTriggers: list([{ id: "trig-1", is_disabled: false }]),
  });
  assertStatuses(limitedKey, { 5: "warn", 6: "warn", 7: "warn", 10: "warn", 19: "warn", 20: "warn", 22: "warn", 23: "warn" });
  assert.match(findingById(limitedKey, 5).summary, /user-level credential for me@example.com with role user only returns the objects that user can see/);
  assert.match(findingById(limitedKey, 10).summary, /Downgraded from pass to warn/);

  const adminKey = assessPagerdutyIncidentResponse({
    scope: userScope("admin"),
    services: list([service("svc-1")]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", is_enabled: true }]),
    workflowTriggers: list([{ id: "trig-1", is_disabled: false }]),
  });
  assertStatuses(adminKey, { 5: "pass", 10: "pass", 20: "pass" });

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
    workflowTriggers: list([{ id: "trig-1", is_disabled: false }]),
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
  assert.match(findingById(escalationFlags, 10).summary, /0 with is_enabled true/);
  assert.match(findingById(escalationFlags, 10).summary, /0 enabled, 0 disabled, 1 unresolved/);

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

function incidentResponseWith(triggers, workflows = [{ id: "wf-1", is_enabled: true }]) {
  return assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([service("svc-1")]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list(workflows),
    workflowTriggers: list(triggers),
  });
}

test("review fix 1: PD-10 rejects is_disabled true and treats a trigger with no resolvable state as unverifiable", () => {
  const disabledTrigger = incidentResponseWith([{ id: "trig-1", is_disabled: true }]);
  assertStatuses(disabledTrigger, { 10: "warn" });
  assert.match(findingById(disabledTrigger, 10).summary, /1 with is_enabled true/);
  assert.match(findingById(disabledTrigger, 10).summary, /0 enabled, 1 disabled, 0 unresolved/);
  assert.equal(findingById(disabledTrigger, 10).evidence.enabled_triggers, 0);
  assert.equal(findingById(disabledTrigger, 10).evidence.disabled_triggers, 1);

  const missingFlag = incidentResponseWith([{ id: "trig-1" }]);
  assertStatuses(missingFlag, { 10: "warn" });
  assert.match(findingById(missingFlag, 10).summary, /0 enabled, 0 disabled, 1 unresolved/);
  assert.match(findingById(missingFlag, 10).summary, /could not be matched to a returned workflow with an is_enabled value/);
  assert.equal(findingById(missingFlag, 10).evidence.triggers_missing_is_disabled_flag, 1);
  assert.deepEqual(findingById(missingFlag, 10).evidence.unresolved_triggers, ["trig-1"]);

  const mixed = incidentResponseWith([{ id: "trig-1", is_disabled: false }, { id: "trig-2" }]);
  assertStatuses(mixed, { 10: "warn" });
  assert.match(findingById(mixed, 10).summary, /1 enabled, 0 disabled, 1 unresolved/);

  const disabledWorkflow = incidentResponseWith([{ id: "trig-1", is_disabled: false }], [{ id: "wf-1", is_enabled: false }]);
  assertStatuses(disabledWorkflow, { 10: "warn" });
  assert.match(findingById(disabledWorkflow, 10).summary, /0 with is_enabled true/);

  const verified = incidentResponseWith([{ id: "trig-1", is_disabled: false }, { id: "trig-2", is_disabled: true }]);
  assertStatuses(verified, { 10: "pass" });
  assert.match(findingById(verified, 10).summary, /1 incident workflows with is_enabled true \(of 1 incident workflows\) and 1 enabled triggers \(of 2 incident workflow triggers; 1 verified by is_disabled false, 0 by the parent workflow's is_enabled\)/);
  assert.equal(findingById(verified, 10).evidence.enabled_triggers, 1);
  assert.equal(findingById(verified, 10).evidence.disabled_triggers, 1);
  assert.deepEqual(findingById(verified, 10).evidence.unresolved_triggers, []);
  assert.equal(findingById(verified, 10).evidence.triggers_missing_is_disabled_flag, 0);
  assert.equal(verified.summary.workflow_triggers_seen, 2);
  assert.equal(verified.summary.enabled_workflow_triggers, 1);
});

test("review fix 5: PD-10 resolves a trigger without is_disabled through its parent workflow's is_enabled", async () => {
  const workflows = [{ id: "wf-1", is_enabled: true }, { id: "wf-2", is_enabled: true }];
  const reference = (id) => ({ id, type: "workflow_reference" });

  const documentedPayload = incidentResponseWith(
    [{ id: "trig-1", workflow: reference("wf-1") }, { id: "trig-2", workflow: reference("wf-2") }],
    workflows,
  );
  assertStatuses(documentedPayload, { 10: "pass" });
  assert.match(findingById(documentedPayload, 10).summary, /2 enabled triggers \(of 2 incident workflow triggers; 0 verified by is_disabled false, 2 by the parent workflow's is_enabled\)/);
  assert.equal(findingById(documentedPayload, 10).evidence.triggers_missing_is_disabled_flag, 2);
  assert.equal(findingById(documentedPayload, 10).evidence.triggers_verified_by_parent_workflow, 2);
  assert.deepEqual(findingById(documentedPayload, 10).evidence.unresolved_triggers, []);

  const unresolvableParent = incidentResponseWith(
    [{ id: "trig-1", workflow: reference("wf-1") }, { id: "trig-9", summary: "Orphan trigger", workflow: reference("wf-missing") }],
    workflows,
  );
  assertStatuses(unresolvableParent, { 10: "warn" });
  assert.match(findingById(unresolvableParent, 10).summary, /1 enabled, 0 disabled, 1 unresolved/);
  assert.match(findingById(unresolvableParent, 10).summary, /could not be matched to a returned workflow with an is_enabled value/);
  assert.deepEqual(findingById(unresolvableParent, 10).evidence.unresolved_triggers, ["Orphan trigger"]);

  const parentWithoutFlag = incidentResponseWith([{ id: "trig-1", workflow: reference("wf-1") }], [{ id: "wf-1" }]);
  assertStatuses(parentWithoutFlag, { 10: "warn" });
  assert.match(findingById(parentWithoutFlag, 10).summary, /0 enabled, 0 disabled, 1 unresolved/);

  const disabledParent = incidentResponseWith(
    [{ id: "trig-1", workflow: reference("wf-1") }, { id: "trig-2", is_disabled: false, workflow: reference("wf-1") }],
    [{ id: "wf-1", is_enabled: false }, { id: "wf-2", is_enabled: true }],
  );
  assertStatuses(disabledParent, { 10: "warn" });
  assert.match(findingById(disabledParent, 10).summary, /0 enabled, 2 disabled, 0 unresolved/);

  const explicitTrueStillRejected = incidentResponseWith([{ id: "trig-1", is_disabled: true, workflow: reference("wf-1") }], workflows);
  assertStatuses(explicitTrueStillRejected, { 10: "warn" });
  assert.match(findingById(explicitTrueStillRejected, 10).summary, /0 enabled, 1 disabled, 0 unresolved/);

  const fixtures = healthyFixtures();
  const documentedClient = healthyClient({
    async listIncidentWorkflowTriggers() {
      return collectionOf([{ id: "trig-1", trigger_type: "conditional", workflow: reference("wf-1"), services: [{ id: "svc-1" }] }]);
    },
  });
  const { findings } = await runAllAssessments(documentedClient);
  assert.equal(findings.filter((item) => item.status === "pass").length, 22, "a payload that omits is_disabled still reaches every automatable pass");
  assert.deepEqual(findings.filter((item) => item.status === "manual").map((item) => item.id).sort(), ["PD-01", "PD-13", "PD-24"]);
  assert.equal(fixtures.incidentWorkflows[0].is_enabled, true);
});

test("review fix 2: audit_limit tool parameter, DEFAULT_AUDIT_LIMIT, and the integration guide agree", () => {
  assert.equal(DEFAULT_AUDIT_LIMIT, 2000);
  const registered = [];
  registerPagerdutyTools({ registerTool: (tool) => registered.push(tool) });
  const withAuditLimit = registered.filter((tool) => tool.parameters.properties.audit_limit);
  assert.deepEqual(withAuditLimit.map((tool) => tool.name).sort(), ["pagerduty_assess_audit_logging", "pagerduty_export_audit_bundle"]);
  for (const tool of withAuditLimit) {
    const param = tool.parameters.properties.audit_limit;
    assert.equal(param.default, DEFAULT_AUDIT_LIMIT, `${tool.name} audit_limit default`);
    assert.match(param.description, new RegExp(`Defaults to ${DEFAULT_AUDIT_LIMIT}\\.`), `${tool.name} audit_limit description`);
    assert.doesNotMatch(param.description, /500/, `${tool.name} audit_limit description still mentions 500`);
  }
  const guide = readFileSync(new URL("../../src/content/docs/docs/integrations/pagerduty.md", import.meta.url), "utf8");
  assert.match(guide, new RegExp("`audit_limit` \\(default " + DEFAULT_AUDIT_LIMIT + "\\)"));
  assert.doesNotMatch(guide, /audit_limit[^\n]*default 500/);
});

test("review fix 3: PD-18 summaries describe push methods by the blacklisted flag only", () => {
  const pushOnly = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: list([{ user: { id: "user-1" }, schedule: { id: "sched-1" } }]),
    users: list([
      user("user-1", {
        contact_methods: [
          { id: "user-1-push", type: "push_notification_contact_method", device_type: "ios", blacklisted: false },
          { id: "user-1-email", type: "email_contact_method", enabled: true },
        ],
        notification_rules: [{ id: "user-1-rule-high", urgency: "high", contact_method: { id: "user-1-push" } }],
      }),
      user("user-2"),
    ]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(pushOnly, { 18: "pass" });
  const passSummary = findingById(pushOnly, 18).summary;
  assert.match(passSummary, /push method with blacklisted false \(the push contact method schema has no enabled flag\)/);
  assert.match(passSummary, /phone or SMS method with enabled true and blacklisted false/);
  assert.doesNotMatch(passSummary, /push contact method with enabled true/);

  const pushMissingFlag = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: list([{ user: { id: "user-1" }, schedule: { id: "sched-1" } }]),
    users: list([
      user("user-1", {
        contact_methods: [{ id: "user-1-push", type: "push_notification_contact_method", device_type: "android" }],
      }),
      user("user-2"),
    ]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(pushMissingFlag, { 18: "warn" });
  assert.deepEqual(findingById(pushMissingFlag, 18).evidence.oncall_unverifiable_methods, ["user-1@example.com"]);

  const blockedOnly = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: list([{ user: { id: "user-1" }, schedule: { id: "sched-1" } }]),
    users: list([
      user("user-1", { contact_methods: [{ id: "user-1-push", type: "push_notification_contact_method", blacklisted: true }] }),
      user("user-2"),
    ]),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(blockedOnly, { 18: "fail" });
  assert.match(findingById(blockedOnly, 18).summary, /no usable contact method: every method they have is blacklisted or disabled, or they have none/);
});

test("review fix 4: listChangeEvents pages past a full first page without a more flag and records completeness", async () => {
  const events = Array.from({ length: 250 }, (_, index) => ({ id: `chg-${index}`, timestamp: NOW.toISOString(), services: [{ id: "svc-1" }] }));
  let dataset = events;
  const requests = [];
  const changeEventsFetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const offset = Number(url.searchParams.get("offset") ?? "0");
    const limit = Number(url.searchParams.get("limit") ?? "100");
    requests.push({ offset, limit });
    return jsonResponse({ change_events: dataset.slice(offset, offset + limit) });
  };
  const client = new PagerdutyApiClient(sampleConfig(), { fetchImpl: changeEventsFetch });

  const complete = await client.listChangeEvents(new Date("2026-08-22T00:00:00Z"), NOW, 1000);
  assert.equal(complete.items.length, 250);
  assert.equal(complete.complete, true);
  assert.equal(complete.total, 250);
  assert.deepEqual(requests.map((request) => request.offset), [0, 100, 200], "a short third page ends the collection");

  requests.length = 0;
  dataset = events.slice(0, 200);
  const pageBoundary = await client.listChangeEvents(new Date("2026-08-22T00:00:00Z"), NOW, 1000);
  assert.equal(pageBoundary.items.length, 200);
  assert.equal(pageBoundary.complete, true);
  assert.deepEqual(requests.map((request) => request.offset), [0, 100, 200], "an empty page after two full pages ends the collection");

  requests.length = 0;
  dataset = events;
  const truncated = await client.listChangeEvents(new Date("2026-08-22T00:00:00Z"), NOW, 100);
  assert.equal(truncated.items.length, 100);
  assert.equal(truncated.complete, false);
  assert.equal(truncated.total, undefined);
  assert.match(truncated.truncation, /stopped at the requested limit of 100 after a full page; the response declares no more flag/);
  assert.deepEqual(requests.map((request) => request.offset), [0]);

  const declaredFlag = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const limit = Number(url.searchParams.get("limit") ?? "100");
      return jsonResponse({ change_events: events.slice(0, limit), more: false, total: limit });
    },
  });
  const honored = await declaredFlag.listChangeEvents(new Date("2026-08-22T00:00:00Z"), NOW, 100);
  assert.equal(honored.items.length, 100);
  assert.equal(honored.complete, true, "a declared more:false ends the collection even when the page is full");

  const fixtures = healthyFixtures();
  const assessment = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list(fixtures.services),
    extensions: list(fixtures.extensions),
    webhookSubscriptions: list(fixtures.webhookSubscriptions),
    businessServices: list(fixtures.businessServices),
    businessServiceDependencies: snapshot({ "bs-1": fixtures.businessServiceDependencies }),
    changeEvents: snapshot(truncated),
    changeWindow: CHANGE_WINDOW,
  });
  const changeTracking = findingById(assessment, 25);
  assert.equal(changeTracking.status, "warn");
  assert.equal(changeTracking.evidence.change_events_complete, false);
  assert.match(changeTracking.evidence.change_events_pagination, /declares no more or total field/);
  assert.match(changeTracking.evidence.partial_view[0], /change events: 100 seen of an unknown total \(stopped at the requested limit of 100 after a full page/);
  assert.match(changeTracking.summary, /Downgraded from pass to warn because the inventory is partial/);

  const completeAssessment = assessPagerdutyIntegrationSecurity({
    scope: accountScope(),
    services: list(fixtures.services),
    extensions: list(fixtures.extensions),
    webhookSubscriptions: list(fixtures.webhookSubscriptions),
    businessServices: list(fixtures.businessServices),
    businessServiceDependencies: snapshot({ "bs-1": fixtures.businessServiceDependencies }),
    changeEvents: snapshot(complete),
    changeWindow: CHANGE_WINDOW,
  });
  assert.equal(findingById(completeAssessment, 25).status, "pass");
  assert.equal(findingById(completeAssessment, 25).evidence.change_events_complete, true);
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

// Verdict safety rules 9 and 10 (export credential hygiene and pagination truncation), plus the rule 1 corollary.

const FAKE_PAGERDUTY_SECRETS = {
  integrationKey: "FAKE_PD_INTEGRATION_KEY_5f3a9c1e",
  integrationEmail: "fake-pd-inbound-7c2d@example.pagerduty.com",
  slackWebhookPath: "T0FAKE/B0FAKE/FAKE_PD_SLACK_PATH_SECRET",
  extensionUrlToken: "FAKE_PD_EXTENSION_URL_TOKEN",
  snowPassword: "FAKE_PD_SNOW_PASSWORD_9e8d",
  webhookPathSecret: "FAKE_PD_WEBHOOK_PATH_SECRET",
  webhookHeader: "FAKE_PD_WEBHOOK_HEADER_SECRET",
  deliverySecret: "FAKE_PD_DELIVERY_SIGNING_SECRET",
  workflowUrlToken: "FAKE_PD_WORKFLOW_URL_TOKEN",
  workflowHeader: "FAKE_PD_WORKFLOW_AUTH_HEADER",
  changeEventApiKey: "FAKE_PD_CHANGE_EVENT_API_KEY",
  changeEventLinkToken: "FAKE_PD_CHANGE_LINK_TOKEN",
  auditFieldUrlSecret: "FAKE_PD_AUDIT_FIELD_URL_SECRET",
  phoneNumber: "15550100FAKE",
  pushAddress: "FAKE_PD_PUSH_DEVICE_ADDRESS",
};

function secretBearingPagerdutyClient() {
  const fixtures = healthyFixtures();
  const secrets = FAKE_PAGERDUTY_SECRETS;
  return healthyClient({
    async listUsers() {
      return collectionOf(fixtures.users.map((item) => ({
        ...item,
        contact_methods: [
          { id: `${item.id}-email`, type: "email_contact_method", enabled: true, address: item.email },
          { id: `${item.id}-phone`, type: "phone_contact_method", enabled: true, blacklisted: false, address: secrets.phoneNumber, country_code: 1 },
          { id: `${item.id}-push`, type: "push_notification_contact_method", enabled: true, blacklisted: false, address: secrets.pushAddress, device_type: "ios" },
        ],
      })));
    },
    async listServices() {
      return collectionOf([
        service("svc-1", {
          integrations: [
            { id: "svc-1-int", summary: "Events API v2", type: "events_api_v2_inbound_integration", integration_key: secrets.integrationKey },
            { id: "svc-1-email", summary: "Email", type: "generic_email_inbound_integration", email_filter_mode: "or-rules-email", integration_email: secrets.integrationEmail },
          ],
        }),
        service("svc-2", { incident_urgency_rule: { type: "constant", urgency: "high" } }),
      ]);
    },
    async listExtensions() {
      return collectionOf([
        {
          id: "ext-1",
          summary: "Slack",
          endpoint_url: `https://hooks.slack.com/services/${secrets.slackWebhookPath}`,
          extension_schema: { summary: "Slack V2" },
          config: { channel: "#alerts", snow_user: "pagerduty", snow_password: secrets.snowPassword },
        },
        {
          id: "ext-2",
          summary: "Legacy receiver",
          endpoint_url: `http://receiver.example.com/hook?token=${secrets.extensionUrlToken}`,
          extension_schema: { summary: "Generic V2 Webhook" },
        },
      ]);
    },
    async listWebhookSubscriptions() {
      return collectionOf([{
        id: "wh-1",
        description: "SIEM",
        active: true,
        delivery_method: {
          type: "http_delivery_method",
          url: `https://siem.example.com/pd/${secrets.webhookPathSecret}`,
          custom_headers: [{ name: "Authorization", value: `Bearer ${secrets.webhookHeader}` }],
          secret: secrets.deliverySecret,
        },
      }]);
    },
    async listIncidentWorkflows() {
      return collectionOf([{
        id: "wf-1",
        name: "Page leadership",
        is_enabled: true,
        steps: [{
          id: "step-1",
          name: "Notify",
          action_configuration: {
            action_id: "pagerduty.com:http:send-request:1",
            inputs: [
              { name: "url", value: `https://automation.example.com/hook?token=${secrets.workflowUrlToken}` },
              { name: "headers", value: `Authorization: ${secrets.workflowHeader}` },
            ],
          },
        }],
      }]);
    },
    async listChangeEvents() {
      return collectionOf([{
        id: "chg-1",
        summary: "deploy 1.2.3",
        timestamp: new Date(NOW.getTime() - DAY_MS).toISOString(),
        services: [{ id: "svc-1" }],
        custom_details: { api_key: secrets.changeEventApiKey, build: "1.2.3" },
        links: [{ href: `https://ci.example.com/run/42?token=${secrets.changeEventLinkToken}` }],
      }]);
    },
    async listAuditRecords(since) {
      return collectionOf([
        auditRecord("audit-1", new Date(since.getTime() + DAY_MS).toISOString(), {
          details: {
            resource: { id: "ext-1", type: "extension_reference" },
            fields: [{ name: "endpoint_url", value: `https://hooks.slack.com/services/${secrets.auditFieldUrlSecret}` }],
          },
        }),
      ]);
    },
  });
}

test("verdict safety rule 9: redactSnapshot masks secret-named keys, name/value pairs, and URL query tokens while reduceUrl keeps only scheme and host", () => {
  const redacted = redactSnapshot({
    integration_key: "FAKE_KEY",
    Integration_Key: "FAKE_KEY_2",
    "routing-key": "FAKE_ROUTING",
    nested: { authorization: "Bearer FAKE", custom_headers: [{ name: "X-Api-Key", value: "FAKE_HEADER" }, { name: "Accept", value: "application/json" }] },
    inputs: [{ name: "webhook token", value: "FAKE_INPUT" }],
    html_url: "https://example.pagerduty.com/services/P123?access_token=FAKE_QUERY&page=2",
    truncated_token: "abcd",
    enabled: true,
    is_secret: false,
    secret_missing: null,
  });
  assert.equal(redacted.integration_key, "[REDACTED]");
  assert.equal(redacted.Integration_Key, "[REDACTED]");
  assert.equal(redacted["routing-key"], "[REDACTED]");
  assert.equal(redacted.nested.authorization, "[REDACTED]");
  assert.deepEqual(redacted.nested.custom_headers, [{ name: "X-Api-Key", value: "[REDACTED]" }, { name: "Accept", value: "application/json" }]);
  assert.deepEqual(redacted.inputs, [{ name: "webhook token", value: "[REDACTED]" }]);
  assert.equal(redacted.html_url, "https://example.pagerduty.com/services/P123?access_token=[REDACTED]&page=2");
  assert.equal(redacted.truncated_token, "abcd", "the vendor-truncated four character suffix PD-13 counts is not a secret");
  assert.equal(redacted.enabled, true);
  assert.equal(redacted.is_secret, false, "boolean flags keep their value even under a secret-named key");
  assert.equal(redacted.secret_missing, null);

  let deep = { leaf: "value" };
  for (let depth = 0; depth < 40; depth += 1) deep = { child: deep };
  assert.match(JSON.stringify(redactSnapshot(deep)), /"\[REDACTED\]"/, "recursion stops at the depth cap with the marker");

  assert.equal(reduceUrl("https://hooks.slack.com/services/T0/B0/SECRET"), "https://hooks.slack.com/[REDACTED]");
  assert.equal(reduceUrl("http://receiver.example.com/hook?token=SECRET"), "http://receiver.example.com/[REDACTED]");
  assert.equal(reduceUrl("https://user:pass@siem.example.com/"), "https://siem.example.com/[REDACTED]");
  assert.equal(reduceUrl("https://siem.example.com:8443/"), "https://siem.example.com:8443");
  assert.equal(reduceUrl("not a url"), "[REDACTED]");
  assert.equal(reduceUrl(undefined), undefined);
});

test("verdict safety rule 9: exportPagerdutyAuditBundle never writes integration keys, webhook URL secrets, extension config, header values, workflow inputs, change event details, or audit field values into the bundle, its zip, or the tool payloads", async () => {
  const base = createTempBase("grclanker-pagerduty-export-secrets-");
  const secrets = Object.values(FAKE_PAGERDUTY_SECRETS);
  const client = secretBearingPagerdutyClient();
  const result = await exportPagerdutyAuditBundle(client, sampleConfig(), base, { maxAdmins: 3 });
  assert.equal(result.errorCount, 0);
  assert.equal(result.findingCount, 25);

  const files = readBundleFiles(result.outputDir);
  for (const file of [
    "core_data/users.json",
    "core_data/services.json",
    "core_data/extensions.json",
    "core_data/webhook_subscriptions.json",
    "core_data/incident_workflows.json",
    "core_data/change_events.json",
    "core_data/audit_records_recent.json",
    "analysis/integration_security.json",
    "analysis/findings.json",
    "compliance/executive_summary.md",
  ]) {
    assert.ok(files.has(file), `expected ${file} in ${[...files.keys()].join(", ")}`);
  }
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assertSecretsAbsent(assert, zipEntries, secrets, "zip archive");

  const { results } = await runAllAssessments(client);
  const payloads = JSON.stringify([await checkPagerdutyAccess(client), ...results]);
  for (const secret of secrets) {
    assert.ok(!payloads.includes(secret), `tool payloads must not carry ${secret}`);
  }

  const services = JSON.parse(files.get("core_data/services.json"));
  assert.equal(services.items[0].integrations[0].integration_key, "[REDACTED]");
  assert.equal(services.items[0].integrations[0].type, "events_api_v2_inbound_integration");
  assert.equal(services.items[0].integrations[1].integration_email, "[REDACTED]");
  assert.equal(services.items[0].integrations[1].email_filter_mode, "or-rules-email");
  assert.equal(services.items[0].acknowledgement_timeout, 1800);

  const extensions = JSON.parse(files.get("core_data/extensions.json"));
  assert.equal(extensions.items[0].config, "[REDACTED]");
  assert.equal(extensions.items[0].endpoint_url, "https://hooks.slack.com/[REDACTED]");
  assert.equal(extensions.items[0].extension_schema.summary, "Slack V2");
  assert.equal(extensions.items[1].endpoint_url, "http://receiver.example.com/[REDACTED]");

  const subscriptions = JSON.parse(files.get("core_data/webhook_subscriptions.json"));
  assert.equal(subscriptions.items[0].delivery_method.url, "https://siem.example.com/[REDACTED]");
  assert.deepEqual(subscriptions.items[0].delivery_method.custom_headers, [{ name: "Authorization", value: "[REDACTED]" }]);
  assert.equal(subscriptions.items[0].delivery_method.secret, "[REDACTED]");
  assert.equal(subscriptions.items[0].active, true);

  const workflows = JSON.parse(files.get("core_data/incident_workflows.json"));
  assert.deepEqual(Object.keys(workflows.items[0]).sort(), ["id", "is_enabled", "name"]);
  const changeEvents = JSON.parse(files.get("core_data/change_events.json"));
  assert.deepEqual(Object.keys(changeEvents.items[0]).sort(), ["id", "services", "summary", "timestamp"]);
  const auditRecords = JSON.parse(files.get("core_data/audit_records_recent.json"));
  assert.deepEqual(Object.keys(auditRecords.items[0]).sort(), ["actors", "execution_time", "id", "method"]);
  assert.equal(auditRecords.items[0].method.truncated_token, "abcd");
  const users = JSON.parse(files.get("core_data/users.json"));
  assert.equal(users.items[0].email, "owner-1@example.com");
  assert.deepEqual(Object.keys(users.items[0].contact_methods[1]).sort(), ["blacklisted", "enabled", "id", "type"]);
  assert.deepEqual(Object.keys(users.items[0].contact_methods[2]).sort(), ["blacklisted", "device_type", "enabled", "id", "type"]);

  const integrationSecurity = JSON.parse(files.get("analysis/integration_security.json"));
  const webhookTransport = findingById(integrationSecurity, 14);
  assert.equal(webhookTransport.status, "fail");
  assert.deepEqual(webhookTransport.evidence.insecure_extensions, ["Legacy receiver -> http://receiver.example.com/[REDACTED]"]);
  assert.equal(findingById(integrationSecurity, 16).status, "pass", "projected integrations still carry the type and filter mode PD-16 reads");
  const auditLogging = JSON.parse(files.get("analysis/audit_logging.json"));
  assert.equal(findingById(auditLogging, 11).status, "pass");
  assert.deepEqual(findingById(auditLogging, 13).evidence.api_tokens_observed.map((item) => item.truncated_token), ["...abcd"]);
  const oncall = JSON.parse(files.get("analysis/oncall_coverage.json"));
  assert.equal(findingById(oncall, 18).status, "pass", "projected contact methods still carry the type and blacklisted flag PD-18 reads");
  assert.equal(JSON.parse(files.get("core_data/access_check.json")).status, "healthy");
});

test("verdict safety rule 10: list reports empty pages under more:true, totals above the items read, absent more flags on full pages, and oversize pages as truncated", async () => {
  const users = Array.from({ length: 100 }, (_, index) => ({ id: `user-${index}`, role: index === 0 ? "owner" : "user", created_via_sso: true, teams: [{ id: "team-1" }] }));
  const stalledUsers = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const offset = Number(url.searchParams.get("offset") ?? "0");
      return jsonResponse({ users: offset === 0 ? users : [], more: true, total: 2500 });
    },
  });
  const stalled = await stalledUsers.listUsers(150);
  assert.equal(stalled.items.length, 100);
  assert.equal(stalled.complete, false);
  assert.equal(stalled.total, 2500);
  assert.match(stalled.truncation, /empty page while reporting more results available/);

  const assessment = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso", "teams"]),
    users: snapshot(stalled),
    teams: list([{ id: "team-1" }]),
    teamMembers: snapshot({}),
  });
  for (const control of [2, 3, 4]) {
    assert.notEqual(findingById(assessment, control).status, "pass", `PD-0${control} must not pass on a stalled user listing`);
    assert.match(findingById(assessment, control).evidence.partial_view[0], /users: 100 of 2500 seen \(the API returned an empty page/);
  }
  assert.match(findingById(assessment, 3).summary, /Downgraded from pass to warn because the inventory is partial/);

  const totalAboveItems = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ teams: [{ id: "a" }, { id: "b" }, { id: "c" }], more: false, total: 10 }),
  });
  const shortOfTotal = await totalAboveItems.listTeams(100);
  assert.equal(shortOfTotal.items.length, 3);
  assert.equal(shortOfTotal.complete, false);
  assert.equal(shortOfTotal.total, 10);
  assert.match(shortOfTotal.truncation, /no more results after 3 records while declaring a total of 10/);

  const requests = [];
  const noMoreFlag = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const offset = Number(url.searchParams.get("offset") ?? "0");
      const limit = Number(url.searchParams.get("limit") ?? "100");
      requests.push(offset);
      return jsonResponse({ teams: offset === 0 ? Array.from({ length: limit }, (_, index) => ({ id: `team-${index}` })) : [] });
    },
  });
  const fullPageNoFlag = await noMoreFlag.listTeams(100);
  assert.equal(fullPageNoFlag.items.length, 100);
  assert.equal(fullPageNoFlag.complete, false);
  assert.equal(fullPageNoFlag.total, undefined);
  assert.match(fullPageNoFlag.truncation, /declares no more flag, so further results may exist/);
  assert.deepEqual(requests, [0], "a full page at the limit without a more flag is not trusted as the end");

  requests.length = 0;
  const followedNoFlag = await noMoreFlag.listTeams(200);
  assert.equal(followedNoFlag.items.length, 100);
  assert.equal(followedNoFlag.complete, true, "an empty page without a more flag ends the listing as complete");
  assert.deepEqual(requests, [0, 100]);

  const oversize = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ priorities: [{ id: "p1" }, { id: "p2" }, { id: "p3" }, { id: "p4" }, { id: "p5" }], more: false, total: 5 }),
  });
  const sliced = await oversize.listPriorities(2);
  assert.equal(sliced.items.length, 2);
  assert.equal(sliced.complete, false, "rows dropped by the client-side slice are reported as truncation");
  assert.match(sliced.truncation, /stopped at the requested limit of 2 with more results available/);
});

test("verdict safety rule 10: listCursor reports an empty page with a next_cursor and a repeated next_cursor as truncated and the audit findings demote with total unknown", async () => {
  const stalledCalls = [];
  const stalledCursor = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const cursor = url.searchParams.get("cursor");
      stalledCalls.push(cursor);
      return cursor === null
        ? jsonResponse({ records: [auditRecord("r1", "2026-09-20T10:00:00Z"), auditRecord("r2", "2026-09-19T10:00:00Z")], next_cursor: "cursor-2" })
        : jsonResponse({ records: [], next_cursor: "cursor-3" });
    },
  });
  const stalled = await stalledCursor.listAuditRecords(new Date(AUDIT_WINDOWS.recent.since), NOW, 2000);
  assert.deepEqual(stalledCalls, [null, "cursor-2"]);
  assert.equal(stalled.items.length, 2);
  assert.equal(stalled.complete, false);
  assert.equal(stalled.total, undefined);
  assert.match(stalled.truncation, /empty page with a next_cursor still present/);

  const repeatedCalls = [];
  const repeatedCursor = new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      repeatedCalls.push(url.searchParams.get("cursor"));
      return jsonResponse({ records: [auditRecord(`r-${repeatedCalls.length}`, "2026-09-20T10:00:00Z")], next_cursor: "cursor-repeat" });
    },
  });
  const repeated = await repeatedCursor.listAuditRecords(new Date(AUDIT_WINDOWS.recent.since), NOW, 2000);
  assert.deepEqual(repeatedCalls, [null, "cursor-repeat"], "a cursor the API already served is not followed again");
  assert.equal(repeated.items.length, 2);
  assert.equal(repeated.complete, false);
  assert.match(repeated.truncation, /next_cursor it had already served/);

  const triggers = await new PagerdutyApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      return url.searchParams.get("cursor") === null
        ? jsonResponse({ triggers: [{ id: "trig-1", is_disabled: false, workflow: { id: "wf-1" } }], next_cursor: "t-2" })
        : jsonResponse({ triggers: [], next_cursor: "t-3" });
    },
  }).listIncidentWorkflowTriggers();
  assert.equal(triggers.complete, false);

  const auditAssessment = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: snapshot(stalled),
    retentionProbe: list([auditRecord("old-1", "2025-10-01T00:00:00Z")]),
    windows: AUDIT_WINDOWS,
  });
  assertStatuses(auditAssessment, { 11: "warn", 12: "warn" });
  for (const control of [11, 12]) {
    assert.match(findingById(auditAssessment, control).summary, /Downgraded from pass to warn because the inventory is partial: audit records: 2 seen of an unknown total \(the API returned an empty page with a next_cursor still present/);
  }

  const automation = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([service("svc-1")]),
    escalationPolicies: list([escalationPolicy("ep-1")]),
    priorities: list([{ id: "p1", name: "P1" }]),
    incidentWorkflows: list([{ id: "wf-1", is_enabled: true }]),
    workflowTriggers: snapshot(triggers),
  });
  assertStatuses(automation, { 10: "warn" });
  assert.match(findingById(automation, 10).summary, /incident workflow triggers: 1 seen of an unknown total/);
});

test("verdict safety rule 10: truncated team member lists are carried into PD-04 instead of being dropped", async () => {
  const fixtures = healthyFixtures();
  const client = healthyClient({
    async listTeamMembers() {
      return collectionOf(fixtures.teamMembers, { complete: false, total: 40, truncation: "stopped at the requested limit of 2 with more results available" });
    },
  });
  const data = await collectPagerdutyAccessControlData(client, {});
  assert.deepEqual(data.teamMembersTruncated, ["Platform: 2 members seen of 40"]);

  const result = assessPagerdutyAccessControl(data, { maxAdmins: 3 });
  const teamScoping = findingById(result, 4);
  assert.match(teamScoping.summary, /member lists were truncated for 1 teams/);
  assert.deepEqual(teamScoping.evidence.team_member_lists_truncated, ["Platform: 2 members seen of 40"]);
  assert.equal(teamScoping.evidence.team_manager_assignments, 1);
});

test("rule 1 corollary: each secondary read forbidden one at a time with the primary healthy demotes the dependent finding and names the read", () => {
  const forbidden = (path) => `PagerDuty request failed (403 Forbidden) for ${path}: Access Denied`;
  const fixtures = healthyFixtures();

  const abilitiesForbidden = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot([], forbidden("/abilities")),
    users: list(fixtures.users),
    teams: list(fixtures.teams),
    teamMembers: snapshot({ "team-1": fixtures.teamMembers }),
  }, { maxAdmins: 3 });
  assertStatuses(abilitiesForbidden, { 1: "manual", 2: "pass", 3: "pass", 4: "warn" });
  const teamScoping = findingById(abilitiesForbidden, 4);
  assert.match(teamScoping.summary, /every one of 4 users belongs to at least one team/);
  assert.match(teamScoping.summary, /The "teams" ability could not be confirmed because the abilities list could not be read \(PagerDuty request failed \(403 Forbidden\) for \/abilities/);
  assert.match(teamScoping.summary, /verdict cannot exceed warn/);
  assert.equal(teamScoping.evidence.teams_ability, null);
  assert.match(teamScoping.evidence.abilities_status, /abilities list could not be read/);

  const abilitiesEmpty = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot([]),
    users: list(fixtures.users),
    teams: list(fixtures.teams),
    teamMembers: snapshot({}),
  }, { maxAdmins: 3 });
  assertStatuses(abilitiesEmpty, { 4: "warn" });
  assert.match(findingById(abilitiesEmpty, 4).summary, /GET \/abilities returned an empty ability list/);

  const abilitiesWithoutTeams = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(["sso"]),
    users: list(fixtures.users),
    teams: list(fixtures.teams),
    teamMembers: snapshot({}),
  }, { maxAdmins: 3 });
  assertStatuses(abilitiesWithoutTeams, { 4: "fail" });
  assert.match(findingById(abilitiesWithoutTeams, 4).summary, /"teams" ability is absent/);

  const membersForbidden = assessPagerdutyAccessControl({
    scope: accountScope(),
    abilities: snapshot(fixtures.abilities),
    users: list(fixtures.users),
    teams: list(fixtures.teams),
    teamMembers: snapshot({}, forbidden("/teams/team-1/members")),
  }, { maxAdmins: 3 });
  assertStatuses(membersForbidden, { 4: "pass" });
  assert.match(findingById(membersForbidden, 4).summary, /team membership listing failed \(PagerDuty request failed \(403 Forbidden\) for \/teams\/team-1\/members: Access Denied\), so manager assignments could not be sampled/);
  assert.equal(findingById(membersForbidden, 4).evidence.team_manager_assignments, null, "a manager count cannot be sampled from a denied member listing");
  assert.equal(findingById(membersForbidden, 4).evidence.team_member_lists_truncated, null);
  assert.match(membersForbidden.summary.inventories.team_members, /^team members: unread \(PagerDuty request failed \(403 Forbidden\) for \/teams\/team-1\/members/);

  const servicesForbidden = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([], forbidden("/services")),
    escalationPolicies: list(fixtures.escalationPolicies),
    priorities: list(fixtures.priorities),
    incidentWorkflows: list(fixtures.incidentWorkflows),
    workflowTriggers: list(fixtures.incidentWorkflowTriggers),
  });
  assertStatuses(servicesForbidden, { 5: "manual", 10: "warn" });
  const automation = findingById(servicesForbidden, 10);
  assert.match(automation.summary, /1 incident workflows with is_enabled true/);
  assert.match(automation.summary, /services could not be read \(PagerDuty request failed \(403 Forbidden\) for \/services/);
  assert.match(automation.summary, /cannot exceed warn until the service directory is readable/);
  assert.doesNotMatch(automation.summary, /0 services still reference one/);
  assert.match(automation.evidence.services_inventory, /^services: unread \(PagerDuty request failed \(403 Forbidden\) for \/services/);

  const servicesForbiddenNoAutomation = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list([], forbidden("/services")),
    escalationPolicies: list(fixtures.escalationPolicies),
    priorities: list(fixtures.priorities),
    incidentWorkflows: list([]),
    workflowTriggers: list([]),
  });
  assertStatuses(servicesForbiddenNoAutomation, { 10: "fail" });
  assert.match(findingById(servicesForbiddenNoAutomation, 10).summary, /response play references could not be checked because services could not be read/);
  assert.doesNotMatch(findingById(servicesForbiddenNoAutomation, 10).summary, /no service references a response play/);

  const servicesReadable = assessPagerdutyIncidentResponse({
    scope: accountScope(),
    services: list(fixtures.services),
    escalationPolicies: list(fixtures.escalationPolicies),
    priorities: list(fixtures.priorities),
    incidentWorkflows: list(fixtures.incidentWorkflows),
    workflowTriggers: list(fixtures.incidentWorkflowTriggers),
  });
  assertStatuses(servicesReadable, { 10: "pass" });
  assert.match(findingById(servicesReadable, 10).summary, /0 services still reference one/);

  const detailsForbidden = assessPagerdutyOncallCoverage({
    scope: accountScope(),
    schedules: list(fixtures.schedules),
    scheduleDetails: snapshot([], forbidden("/schedules/sched-1")),
    oncalls: list(fixtures.oncalls),
    users: list(fixtures.users),
    coverageWindow: COVERAGE_WINDOW,
  });
  assertStatuses(detailsForbidden, { 8: "manual", 9: "manual", 18: "pass" });
  for (const control of [8, 9]) {
    assert.match(findingById(detailsForbidden, control).summary, /Schedule details could not be rendered \(PagerDuty request failed \(403 Forbidden\) for \/schedules\/sched-1/);
  }

  const probeForbidden = assessPagerdutyAuditLogging({
    scope: accountScope(),
    recentRecords: list([auditRecord("a1", "2026-09-20T10:00:00Z")]),
    retentionProbe: list([], forbidden("/audit/records")),
    windows: AUDIT_WINDOWS,
  });
  assertStatuses(probeForbidden, { 11: "pass", 12: "warn" });
  assert.match(findingById(probeForbidden, 12).summary, /retention window could not be probed \(PagerDuty request failed \(403 Forbidden\) for \/audit\/records/);
});

// Fetch-level fixture serving the whole PagerDuty read surface with a request log, so a run can
// deny, empty, or truncate a single endpoint and every status code and path in the output can be
// checked against requests the run actually made.
const PAGERDUTY_LIST_ENDPOINTS = [
  ["/users", "users"],
  ["/teams", "teams"],
  ["/teams/team-1/members", "members"],
  ["/services", "services"],
  ["/escalation_policies", "escalation_policies"],
  ["/priorities", "priorities"],
  ["/incident_workflows", "incident_workflows"],
  ["/incident_workflows/triggers", "triggers"],
  ["/schedules", "schedules"],
  ["/oncalls", "oncalls"],
  ["/audit/records", "records"],
  ["/extensions", "extensions"],
  ["/webhook_subscriptions", "webhook_subscriptions"],
  ["/business_services", "business_services"],
  ["/change_events", "change_events"],
];
const PAGERDUTY_OBJECT_ENDPOINTS = ["/abilities", "/schedules/sched-1", "/service_dependencies/business_services/bs-1"];
const PAGERDUTY_CORE_DATA_FILES = {
  "/abilities": "core_data/abilities.json",
  "/users": "core_data/users.json",
  "/teams": "core_data/teams.json",
  "/teams/team-1/members": "core_data/team_members.json",
  "/services": "core_data/services.json",
  "/escalation_policies": "core_data/escalation_policies.json",
  "/priorities": "core_data/priorities.json",
  "/incident_workflows": "core_data/incident_workflows.json",
  "/incident_workflows/triggers": "core_data/incident_workflow_triggers.json",
  "/schedules": "core_data/schedules.json",
  "/schedules/sched-1": "core_data/schedule_details.json",
  "/oncalls": "core_data/oncalls.json",
  "/audit/records": "core_data/audit_records_recent.json",
  "/extensions": "core_data/extensions.json",
  "/webhook_subscriptions": "core_data/webhook_subscriptions.json",
  "/business_services": "core_data/business_services.json",
  "/service_dependencies/business_services/bs-1": "core_data/business_service_dependencies.json",
  "/change_events": "core_data/change_events.json",
};

const PD_CANARY = {
  bearer: "PDCANARY-BEARER-TOKEN-9f8e7d6c",
  session: "PDCANARY-SESSION-COOKIE-1a2b3c4d",
  apiKey: "PDCANARY-API-KEY-55667788",
  urlToken: "PDCANARY-URL-TOKEN-deadbeef",
  apiToken: "PDCANARY-REST-API-KEY-0001",
  clientSecret: "PDCANARY-CLIENT-SECRET-0001",
  accessToken: "pdcanary-oauth-access-token-0001",
};
const PD_CANARY_URL = `https://api.example.com/v1/x?token=${PD_CANARY.urlToken}`;

function pdCanaryHtml() {
  return [
    "<html><head><title>502 Bad Gateway</title></head><body>",
    `<p>The upstream request carried Authorization: Bearer ${PD_CANARY.bearer} and Set-Cookie: session=${PD_CANARY.session}.</p>`,
    `<p>Retry with x-api-key: ${PD_CANARY.apiKey}; the incident is tracked at ${PD_CANARY_URL} until resolved.</p>`,
    "</body></html>",
  ].join("");
}

// `fail` serves one path with a body that must never be echoed: { path, flavor: "html" | "json" },
// where html is a 502 proxy page carrying the canaries and json is a 403 PagerDuty error object whose
// message embeds the canary URL mid-sentence.
function pagerdutyApiFixture({ deny = [], empty = [], truncate = [], fail } = {}) {
  const fixtures = healthyFixtures();
  const requests = [];
  const listPayload = (key, items, url) => {
    const offset = Number(url.searchParams.get("offset") ?? "0");
    const limit = Number(url.searchParams.get("limit") ?? "100");
    if (truncate.includes(url.pathname)) {
      // First page claims more results, the next page comes back empty: the collector records truncation.
      return offset === 0
        ? { [key]: items, more: true, total: 2500, limit, offset }
        : { [key]: [], more: true, total: 2500, limit, offset };
    }
    return { [key]: items, more: false, total: items.length, limit, offset };
  };
  const listItems = (pathname, url) => {
    switch (pathname) {
      case "/users": return fixtures.users;
      case "/teams": return fixtures.teams;
      case "/teams/team-1/members": return fixtures.teamMembers;
      case "/services": return fixtures.services;
      case "/escalation_policies": return fixtures.escalationPolicies;
      case "/priorities": return fixtures.priorities;
      case "/incident_workflows": return fixtures.incidentWorkflows;
      case "/incident_workflows/triggers": return fixtures.incidentWorkflowTriggers;
      case "/schedules": return fixtures.schedules;
      case "/oncalls": return fixtures.oncalls;
      case "/audit/records": {
        const since = new Date(url.searchParams.get("since"));
        return [auditRecord(`audit-${since.getTime()}`, new Date(since.getTime() + DAY_MS).toISOString())];
      }
      case "/extensions": return fixtures.extensions;
      case "/webhook_subscriptions": return fixtures.webhookSubscriptions;
      case "/business_services": return fixtures.businessServices;
      case "/change_events": return fixtures.changeEvents;
      default: return undefined;
    }
  };
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    const respond = (value, status = 200, statusText = "OK") => {
      requests.push({ method: init.method ?? "GET", url: url.toString(), path: url.pathname, status });
      return jsonResponse(value, { status, statusText });
    };
    if (fail && url.pathname === fail.path) {
      if (fail.flavor === "html") {
        requests.push({ method: init.method ?? "GET", url: url.toString(), path: url.pathname, status: 502 });
        return new Response(pdCanaryHtml(), { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
      }
      if (url.pathname === "/oauth/token") {
        return respond({ error: "invalid_client", error_description: `client rejected; see ${PD_CANARY_URL} for the registration` }, 403, "Forbidden");
      }
      return respond({ error: { message: `Access Denied; see ${PD_CANARY_URL} for the missing scope`, code: 2010, errors: [`scope details at ${PD_CANARY_URL}`] } }, 403, "Forbidden");
    }
    if (url.pathname === "/oauth/token") {
      return respond({ access_token: PD_CANARY.accessToken, token_type: "bearer", expires_in: 3600 });
    }
    if (deny.includes(url.pathname)) {
      return respond({ error: { message: "Access Denied", code: 2010, errors: ["Access Denied"] } }, 403, "Forbidden");
    }
    if (url.pathname === "/users/me") {
      // An account-level REST API key has no user, and the API answers 400.
      return respond({ error: { message: "Account-level access token has no user", code: 2001 } }, 400, "Bad Request");
    }
    if (url.pathname === "/abilities") return respond({ abilities: fixtures.abilities });
    if (url.pathname === "/schedules/sched-1") return respond({ schedule: coveredSchedule("sched-1") });
    if (url.pathname === "/service_dependencies/business_services/bs-1") {
      return respond({ relationships: fixtures.businessServiceDependencies });
    }
    const listEntry = PAGERDUTY_LIST_ENDPOINTS.find(([path]) => path === url.pathname);
    if (listEntry) {
      const items = empty.includes(url.pathname) ? [] : listItems(url.pathname, url);
      if (url.pathname === "/audit/records" || url.pathname === "/incident_workflows/triggers") {
        return respond({ [listEntry[1]]: items, next_cursor: null });
      }
      return respond(listPayload(listEntry[1], items, url));
    }
    return respond({ error: { message: "Not Found", code: 2100 } }, 404, "Not Found");
  };
  return { fetchImpl, requests, fixtures };
}

function pagerdutyApiClient(options = {}) {
  const fixture = pagerdutyApiFixture(options);
  const client = new PagerdutyApiClient(sampleConfig(), { fetchImpl: fixture.fetchImpl, now: () => NOW, sleep: async () => {} });
  return { client, requests: fixture.requests, fixtures: fixture.fixtures };
}

function isAbsenceValue(value) {
  if (value === 0 || value === false) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (value !== null && typeof value === "object") return Object.keys(value).length === 0;
  return false;
}

function fieldLeaves(value, path, out) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    out.set(path, value);
    return out;
  }
  for (const [key, child] of Object.entries(value)) fieldLeaves(child, `${path}.${key}`, out);
  return out;
}

function assessmentLeaves(result) {
  const out = new Map();
  fieldLeaves(result.summary, `${result.category}.summary`, out);
  for (const item of result.findings) {
    out.set(`${item.id}.status`, item.status);
    out.set(`${item.id}.summary`, item.summary);
    fieldLeaves(item.evidence ?? {}, `${item.id}.evidence`, out);
  }
  return out;
}

const STATUS_COUNT_KEYS = new Set(["pass", "warn", "fail", "manual"]);

// Every leaf that carried a value in the all-readable baseline must, under a single denial, either
// keep that value, become null, or (for prose) change text; it must never fall to 0, [], {}, or false.
function assertNoDefaultedLeaves(baseline, current, label) {
  const nullAncestor = (path) => {
    const segments = path.split(".");
    for (let depth = segments.length - 1; depth > 0; depth -= 1) {
      const ancestor = segments.slice(0, depth).join(".");
      if (current.has(ancestor)) return current.get(ancestor) === null;
    }
    return false;
  };
  for (const [path, base] of baseline) {
    if (STATUS_COUNT_KEYS.has(path.split(".").at(-1)) && path.includes(".summary.")) continue;
    if (!current.has(path)) {
      assert.ok(nullAncestor(path), `${label}: leaf ${path} disappeared without its parent rendering null`);
      continue;
    }
    const value = current.get(path);
    if (base === null || isAbsenceValue(base)) continue;
    if (typeof base === "string") continue;
    if (value === null) continue;
    assert.ok(
      !isAbsenceValue(value),
      `${label}: leaf ${path} defaulted from ${JSON.stringify(base)} to ${JSON.stringify(value)}`,
    );
    assert.deepEqual(value, base, `${label}: leaf ${path} changed from ${JSON.stringify(base)} to ${JSON.stringify(value)} instead of rendering null`);
  }
}

function collectStrings(value, out = []) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, out);
  else if (value && typeof value === "object") for (const item of Object.values(value)) collectStrings(item, out);
  return out;
}

// Status codes appear in output as "(403 Forbidden)" or "HTTP 403"; endpoint paths as "/teams" or
// "/teams/team-1/members" after whitespace, a parenthesis, or "for ".
function mentionedStatusCodes(text) {
  return [...text.matchAll(/\((\d{3}) [A-Za-z]/g), ...text.matchAll(/\b(?:HTTP|status)\s+(\d{3})\b/gi)].map((match) => Number(match[1]));
}

function mentionedEndpoints(text) {
  return [...text.matchAll(/(?:^|[\s(]|for )(\/[a-z_]+(?:\/[A-Za-z0-9_\-{}]+)*)/g)].map((match) => match[1]);
}

function assertMentionsMatchRequests(outputs, requests, label) {
  const strings = collectStrings(outputs);
  const loggedStatuses = new Set(requests.map((request) => request.status));
  const loggedPaths = new Set(requests.map((request) => request.path));
  for (const text of strings) {
    for (const code of mentionedStatusCodes(text)) {
      assert.ok(loggedStatuses.has(code), `${label}: output names HTTP ${code} but no request returned it: ${text}`);
    }
    for (const endpoint of mentionedEndpoints(text)) {
      assert.ok(
        loggedPaths.has(endpoint) || [...loggedPaths].some((path) => path.startsWith(`${endpoint}/`)),
        `${label}: output names ${endpoint} but no request was made to it: ${text}`,
      );
    }
  }
}

function principalLabels(fixtures) {
  return fixtures.users.map((item) => item.email);
}

async function exportWithFixture(options) {
  const base = createTempBase("grclanker-pagerduty-sweep-");
  const { client, requests, fixtures } = pagerdutyApiClient(options);
  const result = await exportPagerdutyAuditBundle(client, sampleConfig(), base, { maxAdmins: 3, coverageDays: 30 });
  const files = readBundleFiles(result.outputDir);
  const analysis = ["access_control", "incident_response", "oncall_coverage", "audit_logging", "integration_security"]
    .map((category) => JSON.parse(files.get(`analysis/${category}.json`)));
  const accessCheck = JSON.parse(files.get("core_data/access_check.json"));
  const payloads = [await checkPagerdutyAccess(client), ...(await runAllAssessments(client)).results];
  return { result, files, analysis, accessCheck, payloads, requests, fixtures, errors: files.get("_errors.log") ?? "" };
}

test("collection status, request matching, and denied-list markers: each endpoint denied one at a time writes a marker, renders dependent counts null, names no principal from the denied set, and mentions only observed statuses and paths", async () => {
  // /extensions is served readable but empty throughout, so every run carries one dataset that must stay [].
  const baseline = await exportWithFixture({ empty: ["/extensions"] });
  assert.equal(baseline.result.errorCount, 0);
  assert.deepEqual(JSON.parse(baseline.files.get("core_data/extensions.json")).items, []);
  assert.equal(baseline.accessCheck.status, "healthy");
  const baselineLeaves = new Map(baseline.analysis.flatMap((item) => [...assessmentLeaves(item)]));
  for (const item of baseline.analysis) {
    for (const [name, state] of Object.entries(item.summary.inventories)) {
      assert.match(state, /^.+: complete \(\d+ seen\)$/, `${item.category}.inventories.${name} must be complete in the baseline`);
    }
  }
  assertMentionsMatchRequests([baseline.analysis, baseline.accessCheck, baseline.payloads], baseline.requests, "baseline");
  for (const file of Object.values(PAGERDUTY_CORE_DATA_FILES)) {
    assert.notEqual(JSON.parse(baseline.files.get(file)).collected, false, `${file} is collected in the baseline`);
  }

  const emails = principalLabels(baseline.fixtures);
  const deniable = [...PAGERDUTY_OBJECT_ENDPOINTS, ...PAGERDUTY_LIST_ENDPOINTS.map(([path]) => path)];
  for (const endpoint of deniable) {
    const label = `deny ${endpoint}`;
    const run = await exportWithFixture({ deny: [endpoint], empty: ["/extensions"] });
    const denied = run.requests.filter((request) => request.path === endpoint);
    assert.ok(denied.length > 0 && denied.every((request) => request.status === 403), `${label}: the fixture served 403 for the endpoint`);

    const marker = JSON.parse(run.files.get(PAGERDUTY_CORE_DATA_FILES[endpoint]));
    assert.equal(marker.collected, false, `${label}: core_data carries the not-collected marker`);
    assert.equal(marker.status, 403, `${label}: the marker status is the observed status`);
    assert.equal(marker.endpoint, endpoint, `${label}: the marker endpoint is the requested path`);
    assert.match(marker.error, /\(403 Forbidden\)/);
    assert.ok(!("items" in marker), `${label}: a denied dataset is never written as an item list`);
    const readableEmpty = JSON.parse(run.files.get("core_data/extensions.json"));
    if (endpoint !== "/extensions") {
      assert.deepEqual(readableEmpty.items, [], `${label}: a readable-but-empty dataset keeps an empty item list`);
      assert.equal(readableEmpty.complete, true);
      assert.notEqual(readableEmpty.collected, false);
    }

    const currentLeaves = new Map(run.analysis.flatMap((item) => [...assessmentLeaves(item)]));
    assertNoDefaultedLeaves(baselineLeaves, currentLeaves, label);
    const unreadStates = run.analysis.flatMap((item) => Object.values(item.summary.inventories)).filter((state) => /: unread \(/.test(state));
    assert.ok(unreadStates.length > 0, `${label}: at least one assessment summary names the unread inventory`);
    for (const state of unreadStates) assert.match(state, /\(403 Forbidden\)/, `${label}: the unread state carries the observed failure`);
    assert.ok(run.errors.includes("(403 Forbidden)") && run.errors.includes(endpoint), `${label}: _errors.log names the observed failure`);
    const mentionedText = collectStrings([run.analysis, run.errors]);
    assert.ok(mentionedText.flatMap(mentionedStatusCodes).includes(403), `${label}: the scanner sees the 403 the output names`);
    assert.ok(mentionedText.flatMap(mentionedEndpoints).includes(endpoint), `${label}: the scanner sees the denied path the output names`);
    assertMentionsMatchRequests([run.analysis, run.accessCheck, run.payloads, run.errors], run.requests, label);

    const surface = run.accessCheck.surfaces.find((item) => item.endpoint === endpoint);
    if (surface) {
      assert.equal(surface.status, "not_readable", label);
      assert.equal(surface.http_status, 403, label);
      assert.ok(!("count" in surface), `${label}: an unreadable surface carries no count`);
    }

    if (endpoint === "/users") {
      const text = JSON.stringify([run.analysis, run.payloads]);
      for (const email of emails) assert.ok(!text.includes(email), `${label}: ${email} must not be named from the denied user directory`);
      const accessControl = run.analysis.find((item) => item.category === "access_control");
      for (const key of ["users_seen", "users_total", "privileged_users", "owners", "users_without_teams"]) {
        assert.equal(accessControl.summary[key], null, `${label}: summary ${key} renders null`);
      }
      for (const control of [1, 2, 3, 4]) {
        const evidence = findingById(accessControl, control).evidence;
        assert.match(evidence.principals_withheld, /^users: unread \(PagerDuty request failed \(403 Forbidden\) for \/users/, `${label}: PD-${control} names the unread inventory`);
      }
      const oncall = run.analysis.find((item) => item.category === "oncall_coverage");
      assert.equal(oncall.summary.responders, null);
      assert.equal(oncall.summary.current_oncall_users, null);
    }
    if (endpoint === "/audit/records") {
      const audit = run.analysis.find((item) => item.category === "audit_logging");
      assert.equal(audit.summary.api_tokens_observed, null);
      assert.equal(findingById(audit, 13).evidence.api_tokens_observed, null);
      assert.ok(!JSON.stringify(audit).includes("abcd"), `${label}: no token suffix is named from the denied audit trail`);
    }
    if (endpoint === "/services") {
      const incident = run.analysis.find((item) => item.category === "incident_response");
      assert.equal(incident.summary.active_services, null);
      assert.equal(findingById(incident, 5).evidence.disabled_services, null);
      assert.equal(findingById(incident, 19).evidence.urgency_modes, null);
    }
    if (endpoint === "/change_events") {
      const integration = run.analysis.find((item) => item.category === "integration_security");
      assert.equal(findingById(integration, 25).evidence.change_events_complete, null, `${label}: a completeness flag never defaults on an unread inventory`);
    }
    if (endpoint === "/schedules/sched-1") {
      const oncall = run.analysis.find((item) => item.category === "oncall_coverage");
      for (const key of ["attached_schedules", "schedules_with_gaps", "single_participant_schedules"]) {
        assert.equal(oncall.summary[key], null, `${label}: summary ${key} renders null`);
      }
    }

    // Review round item 12: per-item reads keyed on a denied parent list are never issued, and the
    // dependent dataset is a marker naming the parent instead of a readable-but-empty {} or [].
    const dependent = PAGERDUTY_DEPENDENT_DATASETS[endpoint];
    if (dependent) {
      const skipped = JSON.parse(run.files.get(dependent.file));
      assert.equal(skipped.collected, false, `${label}: ${dependent.file} carries the not-collected marker`);
      assert.equal(skipped.status, null, `${label}: a skipped dependent borrows no status from the parent`);
      assert.equal(skipped.endpoint, null, `${label}: a skipped dependent names no endpoint of its own`);
      assert.match(skipped.error, new RegExp(`^not requested: the ${endpoint.replace(/\//g, "\\/")} list was not read \\(PagerDuty request failed \\(403 Forbidden\\) for ${endpoint.replace(/\//g, "\\/")}`), `${label}: ${skipped.error}`);
      assert.ok(!Array.isArray(skipped) && !("items" in skipped), `${label}: a skipped dependent is never an item list`);
      assert.ok(run.requests.every((request) => !request.path.startsWith(dependent.childPrefix)), `${label}: no ${dependent.childPrefix} request was issued`);
      const analysis = run.analysis.find((item) => item.category === dependent.category);
      assert.match(analysis.summary.inventories[dependent.inventory], /^.+: not requested \(the .+ list was not read/, `${label}: inventories.${dependent.inventory}`);
      assert.ok(run.errors.includes("not requested:"), `${label}: _errors.log records the skipped dependent`);
      const analysisSnapshot = analysis.snapshots?.[dependent.inventory];
      if (analysisSnapshot !== undefined) assert.equal(analysisSnapshot.error, skipped.error, `${label}: the analysis snapshot carries the same skip`);
    }
    if (endpoint === "/teams") {
      const accessControl = run.analysis.find((item) => item.category === "access_control");
      assert.equal(findingById(accessControl, 4).evidence.team_member_lists_truncated, null, `${label}: PD-04 renders no truncation list for lookups that never ran`);
      assert.equal(findingById(accessControl, 4).evidence.team_manager_assignments, null, label);
      assert.equal(findingById(accessControl, 4).status, "manual", label);
    }
    if (endpoint === "/schedules") {
      const oncall = run.analysis.find((item) => item.category === "oncall_coverage");
      for (const key of ["attached_schedules", "schedules_with_gaps", "single_participant_schedules"]) {
        assert.equal(oncall.summary[key], null, `${label}: summary ${key} renders null`);
      }
    }
    if (endpoint === "/business_services") {
      const integration = run.analysis.find((item) => item.category === "integration_security");
      assert.equal(findingById(integration, 21).evidence.unmapped_business_services, null, label);
      assert.equal(findingById(integration, 21).status, "manual", label);
    }
  }
});

const PAGERDUTY_DEPENDENT_DATASETS = {
  "/teams": { file: "core_data/team_members.json", childPrefix: "/teams/", category: "access_control", inventory: "team_members" },
  "/schedules": { file: "core_data/schedule_details.json", childPrefix: "/schedules/", category: "oncall_coverage", inventory: "schedule_details" },
  "/business_services": { file: "core_data/business_service_dependencies.json", childPrefix: "/service_dependencies/", category: "integration_security", inventory: "business_service_dependencies" },
};

// Addendum 4: on every PagerDuty surface (every access-check probe, every collector, the credential
// scope read, and the Scoped OAuth token endpoint), a 502 HTML body or a JSON error embedding a
// credential URL never reaches tool results, findings, summaries, or the bundle, and the recorded
// error carries a status-and-length note or the redacted URL instead.
const PAGERDUTY_CANARY_SURFACES = [
  "/users/me",
  ...PAGERDUTY_OBJECT_ENDPOINTS,
  ...PAGERDUTY_LIST_ENDPOINTS.map(([path]) => path),
];

function assertPdCanariesAbsent(text, context) {
  for (const [name, value] of Object.entries(PD_CANARY)) {
    assert.ok(!text.includes(value), `${context}: canary ${name} (${value}) leaked`);
  }
}

async function pdCanaryRun(config, fail) {
  const base = createTempBase("grclanker-pagerduty-canary-");
  const fixture = pagerdutyApiFixture({ fail });
  const client = new PagerdutyApiClient(config, { fetchImpl: fixture.fetchImpl, now: () => NOW, sleep: async () => {} });
  const context = `${fail.path} (${fail.flavor})`;
  const access = await checkPagerdutyAccess(client);
  const assessments = (await runAllAssessments(client)).results;
  const result = await exportPagerdutyAuditBundle(client, config, base, { maxAdmins: 3, coverageDays: 30 });
  const files = readBundleFiles(result.outputDir);
  const zipEntries = readZipEntries(result.zipPath);
  assert.ok(fixture.requests.some((request) => request.path === fail.path), `${context}: the failing surface was requested`);

  assertPdCanariesAbsent(JSON.stringify(access), `${context} check_access`);
  assertPdCanariesAbsent(JSON.stringify(assessments), `${context} assessments`);
  for (const [name, content] of files) assertPdCanariesAbsent(content, `${context} bundle ${name}`);
  for (const [name, content] of zipEntries) assertPdCanariesAbsent(content, `${context} zip ${name}`);

  const errorStrings = [
    ...access.surfaces.map((surface) => surface.error).filter(Boolean),
    ...access.notes.filter((note) => /could not be determined/.test(note)),
    ...assessments.flatMap((assessment) => assessment.errors),
    ...(files.get("_errors.log") ?? "").split("\n").filter(Boolean),
  ].filter((text) => !/^not requested:|: not requested: /.test(text));
  assert.ok(errorStrings.length > 0, `${context}: the failing surface must be exercised by the access check, an assessment, or the export`);
  for (const errorString of errorStrings) {
    if (fail.flavor === "html") {
      assert.match(errorString, /\(502(?: Bad Gateway)?\)[^\n]*: non-JSON body \(text\/html, \d+ bytes\)/, `${context}: ${errorString}`);
    } else {
      assert.match(errorString, /\(403(?: Forbidden)?\)[^\n]*https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/, `${context}: ${errorString}`);
      assert.ok(!errorString.includes("token="), `${context}: ${errorString}`);
    }
  }
  return { access, assessments, files, requests: fixture.requests };
}

test("addendum 4: on every PagerDuty surface a 502 HTML body or a JSON error embedding a credential URL never reaches results or the bundle, and the recorded error carries a status-and-length note", async () => {
  const config = sampleConfig({ apiToken: PD_CANARY.apiToken });
  let runs = 0;
  for (const path of PAGERDUTY_CANARY_SURFACES) {
    for (const flavor of ["html", "json"]) {
      const run = await pdCanaryRun(config, { path, flavor });
      if (path === "/users/me") {
        assert.match(run.access.notes.find((note) => /Credential scope/.test(note)), flavor === "html" ? /non-JSON body \(text\/html, \d+ bytes\)/ : /\?\[REDACTED\]/);
      }
      runs += 1;
    }
  }
  assert.equal(runs, PAGERDUTY_CANARY_SURFACES.length * 2);
});

test("addendum 4: a Scoped OAuth token endpoint that answers with a 502 HTML page or a JSON error embedding a credential URL never echoes the body, and the obtained bearer token is redacted from every error string", async () => {
  const config = sampleConfig({
    authMode: "oauth_client_credentials",
    apiToken: undefined,
    clientId: "pd-client-id",
    clientSecret: PD_CANARY.clientSecret,
    subdomain: "example",
  });
  for (const flavor of ["html", "json"]) {
    const run = await pdCanaryRun(config, { path: "/oauth/token", flavor });
    for (const surface of run.access.surfaces) {
      assert.equal(surface.status, "not_readable");
      assert.equal(surface.http_status, flavor === "html" ? 502 : 403);
      assert.match(surface.error, /^PagerDuty OAuth token request failed \(\d{3}\) for \/oauth\/token: /);
    }
    assert.ok(run.requests.every((request) => request.path === "/oauth/token"), `${flavor}: no API request is issued without a bearer token`);
  }

  // With the token endpoint healthy, the bearer it returns is remembered and redacted from a later error.
  const fixture = pagerdutyApiFixture({ fail: { path: "/users", flavor: "json" } });
  const client = new PagerdutyApiClient(config, { fetchImpl: fixture.fetchImpl, now: () => NOW, sleep: async () => {} });
  await assert.rejects(client.listUsers(5), (error) => {
    assert.ok(!error.message.includes(PD_CANARY.accessToken));
    assert.ok(!error.message.includes(PD_CANARY.urlToken));
    return true;
  });
  const redacted = client.redact(`header Bearer ${PD_CANARY.accessToken}, key Token token=${PD_CANARY.clientSecret}, at https://u:p@example.com/a?sid=1#frag`);
  assert.equal(redacted, "header Bearer [REDACTED], key Token token=[REDACTED], at https://[REDACTED]@example.com/a?[REDACTED]#[REDACTED]");
  assert.match(client.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"), /^Authorization: \[REDACTED\]/);
});

test("scrub boundary: bare name-shaped values stay, carriers and registered secrets (in every encoded form) and real token shapes go, in PagerdutyRequestError and on client.redact", () => {
  const fetchImpl = async () => jsonResponse({});
  const mustKeep = [
    "PagerDuty request failed (502 Bad Gateway) for /users: non-JSON body (text/html, 5120 bytes)",
    "PagerDuty request failed (403 Forbidden) for /audit/records: JSON body without documented error fields (application/json, 42 bytes)",
    "Unable to read PagerDuty config file /home/svc/.pagerduty/config.json (ENOENT)",
    "Unable to parse PagerDuty config file: invalid JSON in /tmp/grclanker-pagerduty-loader-Ab3dEf/short.json",
    "escalation policy Platform-Primary-2026 and schedule SRE_Weekend_Rotation on team Acme_Platform_Team",
  ];
  // The client constructor is the registration path (rememberSecrets on the configured REST API key); the error constructor is the pass.
  assertScrubBoundary({
    scrub: (text) => new PagerdutyRequestError(502, text, "/x").message,
    registerSecret: (secret) => new PagerdutyApiClient(sampleConfig({ apiToken: secret }), { fetchImpl }),
    mustKeep,
  });
  assertScrubBoundary({ scrub: (text) => new PagerdutyApiClient(sampleConfig(), { fetchImpl }).redact(text), mustKeep });
});

test("collection status: a truncated user directory keeps seen counts, renders principal-derived counts and lists null, and names no user from the partial set", async () => {
  const run = await exportWithFixture({ truncate: ["/users"] });
  const users = JSON.parse(run.files.get("core_data/users.json"));
  assert.equal(users.complete, false);
  assert.equal(users.total, 2500);
  assert.equal(users.items.length, 4);
  const accessControl = run.analysis.find((item) => item.category === "access_control");
  assert.equal(accessControl.summary.users_seen, 4);
  assert.equal(accessControl.summary.users_total, 2500);
  assert.equal(accessControl.summary.privileged_users, null);
  assert.equal(accessControl.summary.owners, null);
  assert.match(accessControl.summary.inventories.users, /^users: 4 of 2500 seen \(/);
  const text = JSON.stringify(run.analysis);
  for (const email of principalLabels(run.fixtures)) assert.ok(!text.includes(email), `${email} must not be named from a partly read directory`);
  for (const control of [1, 2, 3, 4]) {
    const item = findingById(accessControl, control);
    assert.notEqual(item.status, "pass", `PD-${control} cannot pass on a partial directory`);
    assert.match(item.evidence.principals_withheld, /^users: 4 of 2500 seen/);
  }
  const oncall = run.analysis.find((item) => item.category === "oncall_coverage");
  assert.equal(findingById(oncall, 17).evidence.responders_without_rules, null);
  assert.equal(findingById(oncall, 18).evidence.oncall_email_only, null);
  assertMentionsMatchRequests([run.analysis, run.accessCheck, run.payloads, run.errors], run.requests, "truncated users");
});
