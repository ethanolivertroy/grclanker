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
  const until = new Date(NOW.getTime() + 30 * 24 * 60 * 60 * 1000);
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
        { start: NOW.toISOString(), end: until.toISOString(), user: { id: "user-1" } },
      ],
    },
    ...overrides,
  };
}

function healthyClient(overrides = {}) {
  const since = new Date(NOW.getTime() - 5 * 24 * 60 * 60 * 1000);
  return {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => NOW,
    async getAbilities() {
      return ["sso", "teams", "advanced_analytics", "audit_trail"];
    },
    async listUsers() {
      return [
        user("owner-1", { role: "owner" }),
        user("admin-1", { role: "admin" }),
        user("user-1"),
        user("user-2"),
      ];
    },
    async listTeams() {
      return [{ id: "team-1", name: "Platform", summary: "Platform" }];
    },
    async listTeamMembers() {
      return [{ user: { id: "owner-1" }, role: "manager" }, { user: { id: "user-1" }, role: "responder" }];
    },
    async listServices() {
      return [service("svc-1"), service("svc-2", { incident_urgency_rule: { type: "constant", urgency: "high" } })];
    },
    async listEscalationPolicies() {
      return [escalationPolicy("ep-1")];
    },
    async listSchedules() {
      return [{ id: "sched-1", name: "Primary", summary: "Primary" }];
    },
    async getSchedule() {
      return coveredSchedule("sched-1");
    },
    async listOncalls() {
      return [{ user: { id: "user-1" }, schedule: { id: "sched-1" }, escalation_level: 1 }];
    },
    async listAuditRecords() {
      return [
        {
          id: "audit-1",
          execution_time: since.toISOString(),
          method: { type: "api_token", truncated_token: "abcd" },
          actors: [{ id: "owner-1", type: "user_reference" }],
        },
      ];
    },
    async listExtensions() {
      return [{ id: "ext-1", summary: "Slack", endpoint_url: "https://hooks.example.com/slack", extension_schema: { summary: "Slack V2" } }];
    },
    async listWebhookSubscriptions() {
      return [{ id: "wh-1", description: "SIEM", active: true, delivery_method: { type: "http_delivery_method", url: "https://siem.example.com/pd" } }];
    },
    async listBusinessServices() {
      return [{ id: "bs-1", name: "Checkout", summary: "Checkout" }];
    },
    async getBusinessServiceDependencies() {
      return [{ supporting_service: { id: "svc-1", type: "technical_service_reference" } }];
    },
    async listPriorities() {
      return [{ id: "p1", name: "P1", summary: "P1" }, { id: "p2", name: "P2", summary: "P2" }];
    },
    async listIncidentWorkflows() {
      return [{ id: "wf-1", name: "Page leadership", is_enabled: true }];
    },
    async listIncidentWorkflowTriggers() {
      return [{ id: "trig-1", trigger_type: "conditional_trigger", services: [{ id: "svc-1" }] }];
    },
    async listChangeEvents() {
      return [{ id: "chg-1", summary: "deploy 1.2.3", services: [{ id: "svc-1" }] }];
    },
    ...overrides,
  };
}

function failing(message) {
  return async () => {
    throw new Error(message);
  };
}

test("PAGERDUTY_CONTROLS defines all 25 spec controls with eight framework mappings each", () => {
  assert.equal(PAGERDUTY_CONTROLS.length, 25);
  const numbers = PAGERDUTY_CONTROLS.map((item) => item.control).sort((left, right) => left - right);
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

test("PagerdutyApiClient sends the versioned Accept header, Token auth, and follows classic pagination", async () => {
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
      return jsonResponse({ users: [{ id: "user-1" }], limit: 1, offset: 0, more: true });
    }
    return jsonResponse({ users: [{ id: "user-2" }], limit: 1, offset: 1, more: false });
  };

  const client = new PagerdutyApiClient(sampleConfig(), { fetchImpl });
  const users = await client.listUsers(5);

  assert.deepEqual(users.map((item) => item.id), ["user-1", "user-2"]);
  assert.equal(seen.length, 2);
  assert.equal(seen[0].pathname, "/users");
  assert.equal(seen[0].accept, "application/vnd.pagerduty+json;version=2");
  assert.equal(seen[0].auth, "Token token=pd-secret-token");
  assert.equal(seen[0].params.offset, "0");
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

  assert.deepEqual(records.map((item) => item.id), ["rec-1", "rec-2"]);
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

  assert.deepEqual(teams.map((item) => item.id), ["team-1"]);
  assert.equal(seen[0].pathname, "/oauth/token");
  assert.equal(seen[0].method, "POST");
  assert.match(String(seen[0].body), /grant_type=client_credentials/);
  assert.match(String(seen[0].body), /as_account-eu\.acme/);
  assert.equal(seen[1].host, "api.eu.pagerduty.com");
  assert.equal(seen[1].auth, "Bearer oauth-access");
});

test("checkPagerdutyAccess reports healthy when every read surface responds", async () => {
  const result = await checkPagerdutyAccess(healthyClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.region, "us");
  assert.equal(result.authMode, "api_token");
  assert.equal(result.surfaces.length, 14);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(result.missingPermissions, []);
  assert.match(result.recommendedNextStep, /pagerduty_export_audit_bundle/);
});

test("checkPagerdutyAccess reports limited access and missing permissions", async () => {
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
});

test("assessPagerdutyAccessControl passes on a well governed tenant", () => {
  const result = assessPagerdutyAccessControl({
    abilities: snapshot(["sso", "teams", "advanced_analytics"]),
    users: snapshot([user("owner-1", { role: "owner" }), user("admin-1", { role: "admin" }), user("user-1"), user("user-2", { role: "read_only_user" })]),
    teams: snapshot([{ id: "team-1", name: "Platform" }]),
    teamMembers: snapshot({ "team-1": [{ user: { id: "owner-1" }, role: "manager" }] }),
  }, { maxAdmins: 3 });

  assert.equal(result.category, "access_control");
  assert.equal(result.findings.length, 5);
  assertStatuses(result, { 1: "manual", 2: "pass", 3: "pass", 4: "pass", 24: "manual" });
  assert.match(findingById(result, 1).summary, /Account Settings > Single Sign-On/);
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
    abilities: snapshot(["advanced_analytics"]),
    users: snapshot([
      user("owner-1", { role: "owner", created_via_sso: false, teams: [] }),
      user("owner-2", { role: "owner", created_via_sso: false, teams: [] }),
      user("admin-1", { role: "admin", created_via_sso: false, teams: [] }),
      user("admin-2", { role: "admin", created_via_sso: false, teams: [] }),
    ]),
    teams: snapshot([]),
    teamMembers: snapshot({}),
  }, { maxAdmins: 2 });

  assertStatuses(result, { 1: "fail", 2: "fail", 3: "fail", 4: "fail", 24: "manual" });
  assert.deepEqual(findingById(result, 3).evidence.owners, ["owner-1@example.com", "owner-2@example.com"]);
  assert.equal(result.summary.fail, 4);
  assert.equal(result.summary.manual, 1);
});

test("assessPagerdutyAccessControl falls back to manual findings when users cannot be read", () => {
  const result = assessPagerdutyAccessControl({
    abilities: snapshot([], "PagerDuty request failed (403 Forbidden) for /abilities"),
    users: snapshot([], "PagerDuty request failed (403 Forbidden) for /users"),
    teams: snapshot([]),
    teamMembers: snapshot({}),
  });

  assertStatuses(result, { 1: "manual", 2: "manual", 3: "manual", 4: "manual", 24: "manual" });
  assert.equal(result.errors.length, 2);
  assert.match(result.errors[0], /^access_control\.abilities: /);
});

test("assessPagerdutyIncidentResponse passes when services, policies, and automation are configured", () => {
  const result = assessPagerdutyIncidentResponse({
    services: snapshot([service("svc-1"), service("svc-2", { incident_urgency_rule: { type: "constant", urgency: "high" } })]),
    escalationPolicies: snapshot([escalationPolicy("ep-1")]),
    priorities: snapshot([{ id: "p1", name: "P1", summary: "P1" }]),
    incidentWorkflows: snapshot([{ id: "wf-1", name: "Page leadership", is_enabled: true }]),
    workflowTriggers: snapshot([{ id: "trig-1", services: [{ id: "svc-1" }] }]),
  });

  assert.equal(result.category, "incident_response");
  assert.equal(result.findings.length, 8);
  assertStatuses(result, { 5: "pass", 6: "pass", 7: "pass", 10: "pass", 19: "pass", 20: "pass", 22: "pass", 23: "pass" });
});

test("assessPagerdutyIncidentResponse flags missing policies, single levels, and disabled timeouts", () => {
  const result = assessPagerdutyIncidentResponse({
    services: snapshot([
      service("svc-1", {
        escalation_policy: undefined,
        incident_urgency_rule: undefined,
        acknowledgement_timeout: null,
        auto_resolve_timeout: null,
      }),
      service("svc-disabled", { status: "disabled", escalation_policy: undefined }),
    ]),
    escalationPolicies: snapshot([
      escalationPolicy("ep-single", { num_loops: 0, escalation_rules: [{ escalation_delay_in_minutes: 30, targets: [] }] }),
    ]),
    priorities: snapshot([]),
    incidentWorkflows: snapshot([]),
    workflowTriggers: snapshot([]),
  });

  assertStatuses(result, { 5: "fail", 6: "warn", 7: "fail", 10: "fail", 19: "fail", 20: "fail", 22: "warn", 23: "warn" });
  assert.deepEqual(findingById(result, 5).evidence.services_without_policy, ["Service svc-1"]);
  assert.equal(findingById(result, 5).evidence.disabled_services, 1);
});

test("assessPagerdutyIncidentResponse warns on constant high urgency and non repeating policies", () => {
  const result = assessPagerdutyIncidentResponse({
    services: snapshot([service("svc-1", { incident_urgency_rule: { type: "constant", urgency: "high" } })]),
    escalationPolicies: snapshot([escalationPolicy("ep-1", { num_loops: 0 })]),
    priorities: snapshot([{ id: "p1", name: "P1" }]),
    incidentWorkflows: snapshot([{ id: "wf-1", is_enabled: false }]),
    workflowTriggers: snapshot([]),
  });

  assertStatuses(result, { 7: "warn", 10: "warn", 19: "warn" });
  assert.match(findingById(result, 7).summary, /never repeat/);
});

test("assessPagerdutyIncidentResponse becomes manual when services cannot be read", () => {
  const result = assessPagerdutyIncidentResponse({
    services: snapshot([], "PagerDuty request failed (403 Forbidden) for /services"),
    escalationPolicies: snapshot([], "PagerDuty request failed (403 Forbidden) for /escalation_policies"),
    priorities: snapshot([], "PagerDuty request failed (403 Forbidden) for /priorities"),
    incidentWorkflows: snapshot([], "PagerDuty request failed (403 Forbidden) for /incident_workflows"),
    workflowTriggers: snapshot([]),
  });

  assertStatuses(result, { 5: "manual", 6: "manual", 7: "manual", 10: "manual", 19: "manual", 20: "manual", 22: "manual", 23: "manual" });
  assert.equal(result.errors.length, 4);
});

test("scheduleCoverageGaps detects uncovered windows in rendered schedule entries", () => {
  const until = new Date(NOW.getTime() + 3 * 24 * 60 * 60 * 1000);
  const dayOne = new Date(NOW.getTime() + 24 * 60 * 60 * 1000);
  const dayTwo = new Date(NOW.getTime() + 2 * 24 * 60 * 60 * 1000);

  const covered = scheduleCoverageGaps({
    final_schedule: { rendered_schedule_entries: [{ start: NOW.toISOString(), end: until.toISOString() }] },
  }, NOW, until);
  assert.deepEqual(covered, []);

  const gapped = scheduleCoverageGaps({
    final_schedule: {
      rendered_schedule_entries: [
        { start: NOW.toISOString(), end: dayOne.toISOString() },
        { start: dayTwo.toISOString(), end: until.toISOString() },
      ],
    },
  }, NOW, until);
  assert.equal(gapped.length, 1);
  assert.equal(new Date(gapped[0].start).getTime(), dayOne.getTime());
  assert.equal(new Date(gapped[0].end).getTime(), dayTwo.getTime());

  const empty = scheduleCoverageGaps({ final_schedule: { rendered_schedule_entries: [] } }, NOW, until);
  assert.equal(empty.length, 1);
});

test("assessPagerdutyOncallCoverage passes with continuous coverage and verified responders", () => {
  const until = new Date(NOW.getTime() + 30 * 24 * 60 * 60 * 1000);
  const result = assessPagerdutyOncallCoverage({
    schedules: snapshot([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: snapshot([{ user: { id: "user-1" }, schedule: { id: "sched-1" } }]),
    users: snapshot([user("user-1"), user("user-2"), user("ro-1", { role: "read_only_user", notification_rules: [] })]),
    coverageWindow: { since: NOW.toISOString(), until: until.toISOString(), days: 30 },
  });

  assert.equal(result.category, "oncall_coverage");
  assert.equal(result.findings.length, 4);
  assertStatuses(result, { 8: "pass", 9: "pass", 17: "pass", 18: "pass" });
  assert.equal(result.summary.sampled_responders, 2);
});

test("assessPagerdutyOncallCoverage fails on gaps, single participants, and missing contact methods", () => {
  const until = new Date(NOW.getTime() + 30 * 24 * 60 * 60 * 1000);
  const midpoint = new Date(NOW.getTime() + 15 * 24 * 60 * 60 * 1000);
  const result = assessPagerdutyOncallCoverage({
    schedules: snapshot([{ id: "sched-1" }]),
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
    oncalls: snapshot([{ user: { id: "user-1" } }, { user: { id: "user-2" } }]),
    users: snapshot([
      user("user-1", { contact_methods: [], notification_rules: [] }),
      user("user-2", { contact_methods: [{ type: "email_contact_method" }], notification_rules: [{ urgency: "low" }] }),
      user("user-3", { notification_rules: [] }),
      user("user-4", { notification_rules: [] }),
    ]),
    coverageWindow: { since: NOW.toISOString(), until: until.toISOString(), days: 30 },
  });

  assertStatuses(result, { 8: "fail", 9: "fail", 17: "fail", 18: "fail" });
  assert.equal(findingById(result, 8).evidence.schedules_with_gaps.length, 1);
  assert.equal(findingById(result, 8).evidence.schedules_with_gaps[0].gaps.length, 1);
  assert.deepEqual(findingById(result, 18).evidence.oncall_without_contact_methods, ["user-1@example.com"]);
  assert.deepEqual(findingById(result, 18).evidence.oncall_email_only, ["user-2@example.com"]);
});

test("assessPagerdutyOncallCoverage warns on email-only responders and manual when unreadable", () => {
  const until = new Date(NOW.getTime() + 30 * 24 * 60 * 60 * 1000);
  const warned = assessPagerdutyOncallCoverage({
    schedules: snapshot([{ id: "sched-1" }]),
    scheduleDetails: snapshot([coveredSchedule("sched-1")]),
    oncalls: snapshot([{ user: { id: "user-1" } }]),
    users: snapshot([
      user("user-1", { contact_methods: [{ type: "email_contact_method", enabled: true }], notification_rules: [{ urgency: "low" }] }),
      user("user-2"),
      user("user-3"),
      user("user-4"),
      user("user-5"),
    ]),
    coverageWindow: { since: NOW.toISOString(), until: until.toISOString(), days: 30 },
  });
  assertStatuses(warned, { 17: "warn", 18: "warn" });

  const manual = assessPagerdutyOncallCoverage({
    schedules: snapshot([], "PagerDuty request failed (403 Forbidden) for /schedules"),
    scheduleDetails: snapshot([]),
    oncalls: snapshot([], "PagerDuty request failed (403 Forbidden) for /oncalls"),
    users: snapshot([], "PagerDuty request failed (403 Forbidden) for /users"),
    coverageWindow: { since: NOW.toISOString(), until: until.toISOString(), days: 30 },
  });
  assertStatuses(manual, { 8: "manual", 9: "manual", 17: "manual", 18: "manual" });
  assert.equal(manual.errors.length, 3);
});

test("assessPagerdutyAuditLogging passes with recent records and a retention probe", () => {
  const result = assessPagerdutyAuditLogging({
    recentRecords: snapshot([
      { id: "a1", execution_time: "2026-09-20T10:00:00Z", method: { type: "api_token", truncated_token: "abcd" }, actors: [{ id: "user-1" }] },
      { id: "a2", execution_time: "2026-09-19T10:00:00Z", method: { type: "browser" }, actors: [{ id: "user-2" }] },
    ]),
    retentionProbe: snapshot([{ id: "old-1" }]),
    windows: {
      recent: { since: "2026-08-22T00:00:00.000Z", until: NOW.toISOString() },
      retention: { since: "2025-09-21T00:00:00.000Z", until: "2025-10-21T00:00:00.000Z" },
    },
  });

  assert.equal(result.category, "audit_logging");
  assert.equal(result.findings.length, 3);
  assertStatuses(result, { 11: "pass", 12: "pass", 13: "manual" });
  assert.equal(findingById(result, 13).evidence.api_tokens_observed.length, 1);
  assert.equal(findingById(result, 13).evidence.api_tokens_observed[0].truncated_token, "...abcd");
  assert.match(findingById(result, 13).summary, /Integrations > API Access Keys/);
});

test("assessPagerdutyAuditLogging fails on 402 plan errors and warns on empty retention probes", () => {
  const windows = {
    recent: { since: "2026-08-22T00:00:00.000Z", until: NOW.toISOString() },
    retention: { since: "2025-09-21T00:00:00.000Z", until: "2025-10-21T00:00:00.000Z" },
  };

  const noPlan = assessPagerdutyAuditLogging({
    recentRecords: snapshot([], "PagerDuty request failed (402 Payment Required) for /audit/records: Audit Trail not enabled"),
    retentionProbe: snapshot([], "PagerDuty request failed (402 Payment Required) for /audit/records"),
    windows,
  });
  assertStatuses(noPlan, { 11: "fail", 12: "manual", 13: "manual" });

  const forbidden = assessPagerdutyAuditLogging({
    recentRecords: snapshot([], "PagerDuty request failed (403 Forbidden) for /audit/records"),
    retentionProbe: snapshot([]),
    windows,
  });
  assertStatuses(forbidden, { 11: "manual", 12: "manual", 13: "manual" });

  const quiet = assessPagerdutyAuditLogging({
    recentRecords: snapshot([]),
    retentionProbe: snapshot([]),
    windows,
  });
  assertStatuses(quiet, { 11: "warn", 12: "warn", 13: "manual" });

  const longRetention = assessPagerdutyAuditLogging({
    recentRecords: snapshot([{ id: "a1", method: { type: "browser" } }]),
    retentionProbe: snapshot([{ id: "old-1" }]),
    windows,
  }, { minRetentionDays: 730 });
  assertStatuses(longRetention, { 11: "pass", 12: "manual" });
  assert.match(findingById(longRetention, 12).summary, /SIEM or archive/);
});

test("assessPagerdutyIntegrationSecurity passes with https endpoints and mapped dependencies", () => {
  const result = assessPagerdutyIntegrationSecurity({
    services: snapshot([service("svc-1")]),
    extensions: snapshot([{ id: "ext-1", summary: "Slack", endpoint_url: "https://hooks.example.com/slack", extension_schema: { summary: "Slack V2" } }]),
    webhookSubscriptions: snapshot([{ id: "wh-1", active: true, delivery_method: { url: "https://siem.example.com/pd" } }]),
    businessServices: snapshot([{ id: "bs-1", name: "Checkout" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }] }),
    changeEvents: snapshot([{ id: "chg-1", services: [{ id: "svc-1" }] }]),
    changeWindow: { since: "2026-08-22T00:00:00.000Z", until: NOW.toISOString() },
  });

  assert.equal(result.category, "integration_security");
  assert.equal(result.findings.length, 5);
  assertStatuses(result, { 14: "pass", 15: "pass", 16: "pass", 21: "pass", 25: "pass" });
  assert.match(findingById(result, 15).summary, /X-PagerDuty-Signature/);
});

test("assessPagerdutyIntegrationSecurity flags http webhooks, legacy integrations, and missing dependencies", () => {
  const result = assessPagerdutyIntegrationSecurity({
    services: snapshot([
      service("svc-1", {
        integrations: [
          { id: "int-1", summary: "Nagios", type: "nagios_inbound_integration" },
          { id: "int-2", summary: "Email", type: "generic_email_inbound_integration", email_filter_mode: "all-email" },
        ],
      }),
    ]),
    extensions: snapshot([
      { id: "ext-1", summary: "Legacy webhook", endpoint_url: "http://hooks.example.com/legacy", extension_schema: { summary: "Generic V2 Webhook" } },
    ]),
    webhookSubscriptions: snapshot([{ id: "wh-1", active: true, delivery_method: { url: "http://siem.example.com/pd" } }]),
    businessServices: snapshot([]),
    businessServiceDependencies: snapshot({}),
    changeEvents: snapshot([]),
    changeWindow: { since: "2026-08-22T00:00:00.000Z", until: NOW.toISOString() },
  });

  assertStatuses(result, { 14: "fail", 15: "warn", 16: "warn", 21: "fail", 25: "fail" });
  assert.equal(findingById(result, 14).evidence.insecure_extensions.length, 1);
  assert.equal(findingById(result, 14).evidence.insecure_subscriptions.length, 1);
  assert.equal(findingById(result, 16).evidence.legacy_integrations.length, 1);
  assert.equal(findingById(result, 16).evidence.unfiltered_email_integrations.length, 1);
});

test("assessPagerdutyIntegrationSecurity warns on unmapped business services and idle change events", () => {
  const warned = assessPagerdutyIntegrationSecurity({
    services: snapshot([service("svc-1")]),
    extensions: snapshot([]),
    webhookSubscriptions: snapshot([]),
    businessServices: snapshot([{ id: "bs-1", name: "Checkout" }, { id: "bs-2", name: "Search" }]),
    businessServiceDependencies: snapshot({ "bs-1": [{ supporting_service: { id: "svc-1" } }], "bs-2": [] }),
    changeEvents: snapshot([]),
    changeWindow: { since: "2026-08-22T00:00:00.000Z", until: NOW.toISOString() },
  });
  assertStatuses(warned, { 21: "warn", 25: "warn" });
  assert.deepEqual(findingById(warned, 21).evidence.unmapped_business_services, ["Search"]);

  const manual = assessPagerdutyIntegrationSecurity({
    services: snapshot([], "PagerDuty request failed (403 Forbidden) for /services"),
    extensions: snapshot([], "PagerDuty request failed (403 Forbidden) for /extensions"),
    webhookSubscriptions: snapshot([]),
    businessServices: snapshot([], "PagerDuty request failed (403 Forbidden) for /business_services"),
    businessServiceDependencies: snapshot({}),
    changeEvents: snapshot([], "PagerDuty request failed (403 Forbidden) for /change_events"),
    changeWindow: { since: "2026-08-22T00:00:00.000Z", until: NOW.toISOString() },
  });
  assertStatuses(manual, { 14: "manual", 15: "manual", 16: "manual", 21: "manual", 25: "manual" });
  assert.equal(manual.errors.length, 4);
});

test("run*Assessment helpers collect from the client and together cover all 25 controls", async () => {
  const client = healthyClient();
  const results = await Promise.all([
    runPagerdutyAccessControlAssessment(client, { maxAdmins: 3 }),
    runPagerdutyIncidentResponseAssessment(client),
    runPagerdutyOncallCoverageAssessment(client, { coverageDays: 30 }),
    runPagerdutyAuditLoggingAssessment(client),
    runPagerdutyIntegrationSecurityAssessment(client),
  ]);

  const ids = results.flatMap((result) => result.findings.map((item) => item.id)).sort();
  assert.equal(ids.length, 25);
  assert.deepEqual(ids, PAGERDUTY_CONTROLS.map((item) => findingId(item.control)).sort());
  assert.deepEqual(results.flatMap((result) => result.errors), []);
  const manualIds = results.flatMap((result) => result.findings.filter((item) => item.status === "manual").map((item) => item.id));
  assert.deepEqual(manualIds.sort(), ["PD-01", "PD-13", "PD-24"]);
});

test("exportPagerdutyAuditBundle writes core data, analysis, compliance reports, and archive", async () => {
  const base = createTempBase("grclanker-pagerduty-export-");
  const result = await exportPagerdutyAuditBundle(healthyClient(), sampleConfig(), base, { maxAdmins: 3 });

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.match(result.zipPath, /pagerduty-us-audit-bundle\.zip$/);
  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 36, `expected at least 36 files, saw ${result.fileCount}`);

  const expectedFiles = [
    "core_data/access_check.json",
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
  assert.ok(readdirSync(base).includes("pagerduty-eu-audit-bundle.zip"));
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
