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
  KNOWBE4_CONTROLS,
  Knowbe4ApiClient,
  assessKnowbe4AccountGovernance,
  assessKnowbe4PhishingProgram,
  assessKnowbe4TrainingProgram,
  assessKnowbe4UserRisk,
  checkKnowbe4Access,
  collectKnowbe4Snapshot,
  exportKnowbe4AuditBundle,
  knowbe4ControlMappings,
  knowbe4ToolForArea,
  redactKnowbe4Pii,
  resolveKnowbe4Configuration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/knowbe4.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const NOW = new Date("2026-09-21T12:00:00Z");
const DAY_MS = 86_400_000;
const KNOWBE4_TOOL_NAMES = [
  "knowbe4_check_access",
  "knowbe4_assess_phishing_program",
  "knowbe4_assess_training_program",
  "knowbe4_assess_user_risk",
  "knowbe4_assess_account_governance",
  "knowbe4_export_audit_bundle",
];

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function daysAgo(days) {
  return new Date(NOW.getTime() - days * DAY_MS).toISOString();
}

function sampleConfig(overrides = {}) {
  return {
    apiToken: "reporting-token",
    region: "us",
    baseUrl: "https://us.api.knowbe4.com",
    phisherApiToken: undefined,
    phisherGraphqlUrl: "https://training.knowbe4.com/graphql",
    timeoutMs: 30000,
    redactPii: false,
    configFile: "/nonexistent/config.yaml",
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

function findingFor(result, control) {
  const item = result.findings.find((finding) => finding.control === control);
  assert.ok(item, `expected a finding for control ${control}`);
  return item;
}

function user(id, overrides = {}) {
  return {
    id,
    employee_number: `E${id}`,
    first_name: `First${id}`,
    last_name: `Last${id}`,
    email: `user${id}@acme.example`,
    status: "active",
    joined_on: "2024-01-15T00:00:00Z",
    last_sign_in: daysAgo(3),
    current_risk_score: 20 + id,
    phish_prone_percentage: 8,
    groups: [id <= 5 ? 100 : 101],
    ...overrides,
  };
}

function securityTest(pstId, startedAt, phishPronePercentage, overrides = {}) {
  return {
    campaign_id: 500,
    pst_id: pstId,
    status: "Closed",
    name: `Test ${pstId}`,
    groups: [{ group_id: 0, name: "All Users" }],
    phish_prone_percentage: phishPronePercentage,
    started_at: startedAt,
    duration: 3,
    categories: [{ category_id: 1, name: "Current Events" }],
    template: { id: 10, name: "Password Reset" },
    landing_page: { id: 20, name: "Generic Landing Page" },
    scheduled_count: 10,
    delivered_count: 10,
    opened_count: 4,
    clicked_count: 1,
    replied_count: 0,
    attachment_open_count: 0,
    macro_enabled_count: 0,
    data_entered_count: 0,
    qr_code_scanned_count: 0,
    reported_count: 6,
    bounced_count: 0,
    ...overrides,
  };
}

function recipient(pstId, userRecord, deliveredAt, overrides = {}) {
  return {
    recipient_id: Number(`${pstId}${userRecord.id}`),
    pst_id: pstId,
    user: { id: userRecord.id, first_name: userRecord.first_name, last_name: userRecord.last_name, email: userRecord.email },
    template: { id: 10, name: "Password Reset" },
    scheduled_at: deliveredAt,
    delivered_at: deliveredAt,
    opened_at: null,
    clicked_at: null,
    replied_at: null,
    attachment_opened_at: null,
    macro_enabled_at: null,
    data_entered_at: null,
    qr_code_scanned: null,
    reported_at: null,
    bounced_at: null,
    ip: "203.0.113.10",
    ip_location: "Tampa, FL",
    browser: "Chrome",
    browser_version: "140",
    os: "macOS",
    ...overrides,
  };
}

function enrollment(id, userRecord, campaignId, moduleName, enrollmentDate, overrides = {}) {
  return {
    enrollment_id: id,
    content_type: "Store Purchase",
    module_name: moduleName,
    user: { id: userRecord.id, first_name: userRecord.first_name, last_name: userRecord.last_name, email: userRecord.email },
    campaign_name: `Campaign ${campaignId}`,
    campaign_id: campaignId,
    store_purchase_id: 1,
    enrollment_date: enrollmentDate,
    start_date: enrollmentDate,
    completion_date: new Date(new Date(enrollmentDate).getTime() + 5 * DAY_MS).toISOString(),
    status: "Passed",
    time_spent: 900,
    policy_acknowledged: false,
    score: 95,
    ...overrides,
  };
}

function healthyFixture() {
  const users = [];
  for (let id = 1; id <= 8; id += 1) users.push(user(id));
  users.push(user(9, { joined_on: daysAgo(100) }));
  users.push(user(10, { joined_on: daysAgo(10) }));

  const testDates = [6, 37, 68, 99, 130, 161, 192, 223, 254, 285, 316, 347];
  const pppByAge = [0.08, 0.08, 0.09, 0.1, 0.11, 0.12, 0.12, 0.13, 0.13, 0.14, 0.14, 0.15];
  const securityTests = testDates.map((age, index) => securityTest(900 + index, daysAgo(age), pppByAge[index]));

  const recipientsByTest = new Map();
  for (const item of securityTests) {
    recipientsByTest.set(String(item.pst_id), users.map((record) => recipient(item.pst_id, record, item.started_at)));
  }
  const remedialTest = securityTests[1];
  const remedialRows = recipientsByTest.get(String(remedialTest.pst_id));
  remedialRows[2] = recipient(remedialTest.pst_id, users[2], remedialTest.started_at, {
    opened_at: remedialTest.started_at,
    clicked_at: new Date(new Date(remedialTest.started_at).getTime() + 3_600_000).toISOString(),
  });

  const trainingCampaigns = [
    {
      campaign_id: 700,
      name: "2026 Annual Security Awareness",
      groups: [{ group_id: 0, name: "All Users" }],
      status: "Completed",
      content: [
        { store_purchase_id: 1, content_type: "Store Purchase", name: "Security Awareness Fundamentals", publish_date: daysAgo(250), retired: false },
        { store_purchase_id: 2, content_type: "Store Purchase", name: "PCI DSS Compliance Basics", publish_date: daysAgo(230), retired: false },
      ],
      duration_type: "Specific End Date",
      start_date: daysAgo(200),
      end_date: daysAgo(140),
      relative_duration: null,
      auto_enroll: true,
      allow_multiple_enrollments: false,
      completion_percentage: 96,
    },
    {
      campaign_id: 701,
      name: "New Hire Security Onboarding",
      groups: [{ group_id: 0, name: "All Users" }],
      status: "In Progress",
      content: [
        { store_purchase_id: 1, content_type: "Store Purchase", name: "Security Awareness Fundamentals", publish_date: daysAgo(250), retired: false },
      ],
      duration_type: "Relative End Date",
      start_date: daysAgo(300),
      end_date: null,
      relative_duration: "2 weeks",
      auto_enroll: true,
      allow_multiple_enrollments: true,
      completion_percentage: 88,
    },
  ];

  const enrollments = [];
  let enrollmentId = 1;
  for (const record of users.slice(0, 8)) {
    enrollments.push(enrollment(enrollmentId++, record, 700, "Security Awareness Fundamentals", daysAgo(199)));
    enrollments.push(enrollment(enrollmentId++, record, 700, "PCI DSS Compliance Basics", daysAgo(198), { store_purchase_id: 2 }));
  }
  enrollments.push(enrollment(enrollmentId++, users[8], 701, "Security Awareness Fundamentals", daysAgo(98)));
  enrollments.push(enrollment(enrollmentId++, users[2], 701, "Security Awareness Fundamentals", daysAgo(35)));

  return {
    account: {
      name: "Acme Corp",
      type: "paid",
      domains: ["acme.example"],
      admins: [{ id: 1, first_name: "First1", last_name: "Last1", email: "user1@acme.example" }],
      subscription_level: "Diamond",
      subscription_end_date: "2027-01-01",
      number_of_seats: 100,
      current_risk_score: 28.4,
    },
    riskHistory: [
      { risk_score: 40.1, date: "2026-03-01" },
      { risk_score: 28.4, date: "2026-09-01" },
    ],
    users,
    groups: [
      { id: 100, name: "Finance", group_type: "console_group", adi_guid: null, member_count: 5, current_risk_score: 26, status: "active" },
      { id: 101, name: "Engineering", group_type: "console_group", adi_guid: null, member_count: 5, current_risk_score: 24, status: "active" },
    ],
    phishingCampaigns: [
      {
        campaign_id: 500,
        name: "Monthly Baseline",
        groups: [{ group_id: 0, name: "All Users" }],
        last_phish_prone_percentage: 0.08,
        last_run: daysAgo(6),
        status: "Active",
        hidden: false,
        send_duration: "3 Business Days",
        track_duration: "3 Days",
        frequency: "Monthly",
        difficulty_filter: [1, 2, 3],
        create_date: "2025-01-01T00:00:00Z",
        psts_count: securityTests.length,
        psts: securityTests.slice(0, 3).map((item) => ({ pst_id: item.pst_id, status: item.status, start_date: item.started_at, users_count: 10, phish_prone_percentage: item.phish_prone_percentage })),
      },
    ],
    securityTests,
    recipientsByTest,
    callbackTests: [securityTest(950, daysAgo(51), 0.05, { campaign_id: 501, name: "Callback Q3" })],
    trainingCampaigns,
    enrollments,
    storePurchases: [
      { store_purchase_id: 1, content_type: "Store Purchase", name: "Security Awareness Fundamentals", description: "Core module", type: "Training Module", duration: 15, retired: false, retirement_date: null, publish_date: daysAgo(250), publisher: "KnowBe4", purchase_date: daysAgo(260), policy_url: null },
      { store_purchase_id: 2, content_type: "Store Purchase", name: "PCI DSS Compliance Basics", description: "PCI", type: "Training Module", duration: 10, retired: false, retirement_date: null, publish_date: daysAgo(230), publisher: "KnowBe4", purchase_date: daysAgo(240), policy_url: null },
    ],
    trainingPolicies: [
      { policy_id: 1, content_type: "Uploaded Policy", name: "Acceptable Use Policy", minimum_time: 60, default_language: "en-us", published: true, status: "Published" },
    ],
    phisherMessages: [
      { id: "msg-1", reportedAt: daysAgo(2), reportedBy: "user4@acme.example", from: "attacker@evil.example", subject: "Invoice", category: "THREAT", severity: "HIGH", actionStatus: "RESOLVED", pipelineStatus: "PROCESSED" },
      { id: "msg-2", reportedAt: daysAgo(5), reportedBy: "user6@acme.example", from: "news@vendor.example", subject: "Newsletter", category: "CLEAN", severity: "LOW", actionStatus: "RESOLVED", pipelineStatus: "PROCESSED" },
    ],
  };
}

function failingFixture() {
  const users = [];
  for (let id = 1; id <= 8; id += 1) {
    users.push(user(id, { last_sign_in: "2025-01-01T00:00:00Z", current_risk_score: 60 + id * 3, phish_prone_percentage: 40 }));
  }
  users.push(user(9, { joined_on: daysAgo(100), last_sign_in: null, current_risk_score: 70, phish_prone_percentage: 40 }));
  users.push(user(10, { joined_on: daysAgo(140), last_sign_in: null, current_risk_score: 75, phish_prone_percentage: 40 }));

  const securityTests = [
    securityTest(901, daysAgo(82), 0.25, { reported_count: 1 }),
    securityTest(902, daysAgo(112), 0.2, { reported_count: 1 }),
    securityTest(903, daysAgo(143), 0.12, { reported_count: 1 }),
    securityTest(904, daysAgo(173), 0.1, { reported_count: 1 }),
    securityTest(905, daysAgo(294), 0.1, { reported_count: 1 }),
  ];
  const recipientsByTest = new Map();
  for (const item of securityTests) {
    recipientsByTest.set(String(item.pst_id), [
      recipient(item.pst_id, users[0], item.started_at, {
        opened_at: item.started_at,
        clicked_at: new Date(new Date(item.started_at).getTime() + 600_000).toISOString(),
      }),
    ]);
  }

  return {
    account: {
      name: "Acme Corp",
      type: "paid",
      domains: ["acme.example"],
      admins: [
        { id: 1, first_name: "First1", last_name: "Last1", email: "user1@acme.example" },
        { id: 2, first_name: "First2", last_name: "Last2", email: "user2@acme.example" },
        { id: 3, first_name: "First3", last_name: "Last3", email: "user3@acme.example" },
        { id: 4, first_name: "First4", last_name: "Last4", email: "user4@acme.example" },
        { id: 55, first_name: "Outside", last_name: "Consultant", email: "consultant@contractor.example" },
      ],
      subscription_level: "Gold",
      subscription_end_date: "2027-01-01",
      number_of_seats: 100,
      current_risk_score: 71.2,
    },
    riskHistory: [
      { risk_score: 55, date: "2026-03-01" },
      { risk_score: 71.2, date: "2026-09-01" },
    ],
    users,
    groups: [
      { id: 100, name: "Finance", group_type: "console_group", adi_guid: null, member_count: 5, current_risk_score: 70, status: "active" },
      { id: 101, name: "Engineering", group_type: "console_group", adi_guid: null, member_count: 5, current_risk_score: 72, status: "active" },
    ],
    phishingCampaigns: [
      {
        campaign_id: 500,
        name: "Finance Only",
        groups: [{ group_id: 100, name: "Finance" }],
        last_phish_prone_percentage: 0.25,
        last_run: daysAgo(82),
        status: "Active",
        hidden: false,
        send_duration: "1 Business Day",
        track_duration: "3 Days",
        frequency: "One Time",
        difficulty_filter: [1],
        create_date: "2025-01-01T00:00:00Z",
        psts_count: securityTests.length,
        psts: securityTests.map((item) => ({ pst_id: item.pst_id, status: item.status, start_date: item.started_at, users_count: 5, phish_prone_percentage: item.phish_prone_percentage })),
      },
    ],
    securityTests,
    recipientsByTest,
    callbackTests: [],
    trainingCampaigns: [
      {
        campaign_id: 700,
        name: "Legacy Awareness",
        groups: [{ group_id: 100, name: "Finance" }],
        status: "Completed",
        content: [
          { store_purchase_id: 1, content_type: "Store Purchase", name: "Security Basics 2019", publish_date: "2019-01-01T00:00:00Z", retired: true },
        ],
        duration_type: "Specific End Date",
        start_date: daysAgo(120),
        end_date: daysAgo(50),
        relative_duration: null,
        auto_enroll: false,
        allow_multiple_enrollments: false,
        completion_percentage: 55,
      },
    ],
    enrollments: [
      enrollment(1, users[1], 700, "Security Basics 2019", daysAgo(119), { status: "Not Started", start_date: null, completion_date: null }),
      enrollment(2, users[9], 700, "Security Basics 2019", daysAgo(60), { status: "In Progress", completion_date: null }),
    ],
    storePurchases: [
      { store_purchase_id: 1, content_type: "Store Purchase", name: "Security Basics 2019", description: "Old", type: "Training Module", duration: 15, retired: true, retirement_date: "2024-01-01", publish_date: "2019-01-01T00:00:00Z", publisher: "KnowBe4", purchase_date: "2019-02-01", policy_url: null },
    ],
    trainingPolicies: [],
    phisherMessages: [],
  };
}

function mockClient(fixture, options = {}) {
  const calls = [];
  const failures = options.failures ?? {};
  const phisher = options.phisher ?? false;
  const config = sampleConfig({ ...(phisher ? { phisherApiToken: "phisher-token" } : {}), ...(options.config ?? {}) });
  const guard = (name, result) => {
    calls.push(name);
    if (failures[name]) throw new Error(failures[name]);
    return result;
  };
  return {
    calls,
    getResolvedConfig: () => config,
    hasPhisherCredentials: () => phisher,
    async getAccount() {
      return guard("getAccount", fixture.account);
    },
    async getAccountRiskScoreHistory() {
      return guard("getAccountRiskScoreHistory", fixture.riskHistory);
    },
    async listUsers() {
      return guard("listUsers", fixture.users);
    },
    async listGroups() {
      return guard("listGroups", fixture.groups);
    },
    async listPhishingCampaigns() {
      return guard("listPhishingCampaigns", fixture.phishingCampaigns);
    },
    async listSecurityTests(listOptions = {}) {
      if (listOptions.campaignType === "callback") return guard("listCallbackSecurityTests", fixture.callbackTests);
      return guard("listSecurityTests", fixture.securityTests);
    },
    async listSecurityTestRecipients(pstId) {
      return guard(`listSecurityTestRecipients:${pstId}`, fixture.recipientsByTest.get(String(pstId)) ?? []);
    },
    async listTrainingCampaigns() {
      return guard("listTrainingCampaigns", fixture.trainingCampaigns);
    },
    async listTrainingEnrollments() {
      return guard("listTrainingEnrollments", fixture.enrollments);
    },
    async listStorePurchases() {
      return guard("listStorePurchases", fixture.storePurchases);
    },
    async listTrainingPolicies() {
      return guard("listTrainingPolicies", fixture.trainingPolicies);
    },
    async listPhisherMessages(listOptions = {}) {
      calls.push(`listPhisherMessages:${listOptions.query ?? ""}`);
      if (failures.listPhisherMessages) throw new Error(failures.listPhisherMessages);
      return fixture.phisherMessages;
    },
    async probe(path) {
      return guard(`probe:${path}`, [{}]);
    },
    async countPhisherMessages() {
      return guard("countPhisherMessages", fixture.phisherMessages.length);
    },
  };
}

test("resolveKnowbe4Configuration applies explicit args over env vars over the config file", () => {
  const home = createTempBase("grclanker-knowbe4-home-");
  const configPath = join(home, "config.yaml");
  writeFileSync(configPath, [
    "api_token: file-token",
    "region: eu",
    "phisher_api_token: file-phisher",
    "redact_pii: true",
    "timeout_seconds: 12",
  ].join("\n"));

  const resolved = resolveKnowbe4Configuration(
    { api_token: "arg-token", region: "ca", timeout_seconds: 9 },
    {
      KNOWBE4_API_TOKEN: "env-token",
      KNOWBE4_REGION: "uk",
      KNOWBE4_PHISHER_GRAPHQL_URL: "https://phisher.example/graphql/",
      KNOWBE4_CONFIG_FILE: configPath,
    },
    home,
  );

  assert.equal(resolved.apiToken, "arg-token");
  assert.equal(resolved.region, "ca");
  assert.equal(resolved.baseUrl, "https://ca.api.knowbe4.com");
  assert.equal(resolved.phisherApiToken, "file-phisher");
  assert.equal(resolved.phisherGraphqlUrl, "https://phisher.example/graphql");
  assert.equal(resolved.timeoutMs, 9000);
  assert.equal(resolved.redactPii, true);
  assert.equal(resolved.configFile, configPath);
  assert.ok(resolved.sourceChain.includes("arguments-token"));
  assert.ok(resolved.sourceChain.includes("arguments-region"));
  assert.ok(resolved.sourceChain.includes("environment-phisher-url"));
  assert.ok(resolved.sourceChain.includes("config-phisher-token"));
  assert.ok(resolved.sourceChain.includes(`config:${configPath}`));

  const envOverFile = resolveKnowbe4Configuration({}, { KNOWBE4_API_TOKEN: "env-token", KNOWBE4_CONFIG_FILE: configPath }, home);
  assert.equal(envOverFile.apiToken, "env-token");
  assert.equal(envOverFile.region, "eu");
  assert.equal(envOverFile.baseUrl, "https://eu.api.knowbe4.com");
  assert.equal(envOverFile.phisherGraphqlUrl, "https://eu.knowbe4.com/graphql");

  const fileOnly = resolveKnowbe4Configuration({ config_file: configPath }, {}, home);
  assert.equal(fileOnly.apiToken, "file-token");
  assert.equal(fileOnly.region, "eu");
  assert.equal(fileOnly.redactPii, true);
  assert.equal(fileOnly.timeoutMs, 12000);
});

test("resolveKnowbe4Configuration falls back to the default home config path and defaults", () => {
  const home = createTempBase("grclanker-knowbe4-home-");
  const defaults = resolveKnowbe4Configuration({ api_token: "arg-token" }, {}, home);
  assert.equal(defaults.region, "us");
  assert.equal(defaults.baseUrl, "https://us.api.knowbe4.com");
  assert.equal(defaults.phisherGraphqlUrl, "https://training.knowbe4.com/graphql");
  assert.equal(defaults.phisherApiToken, undefined);
  assert.equal(defaults.timeoutMs, 30000);
  assert.equal(defaults.redactPii, false);
  assert.equal(defaults.configFile, join(home, ".knowbe4-inspector", "config.yaml"));

  const regional = resolveKnowbe4Configuration({ api_token: "arg-token" }, { KNOWBE4_REGION: "DE" }, home);
  assert.equal(regional.region, "de");
  assert.equal(regional.baseUrl, "https://de.api.knowbe4.com");
  assert.equal(regional.phisherGraphqlUrl, "https://de.knowbe4.com/graphql");

  assert.throws(() => resolveKnowbe4Configuration({}, {}, home), /KNOWBE4_API_TOKEN/);
  assert.throws(() => resolveKnowbe4Configuration({ api_token: "x", region: "mars" }, {}, home), /Unsupported KnowBe4 region/);
});

test("Knowbe4ApiClient sends bearer auth, paginates with page and per_page, and retries 429 honoring Retry-After", async () => {
  const seen = [];
  const sleeps = [];
  let attempts = 0;
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      page: url.searchParams.get("page"),
      perPage: url.searchParams.get("per_page"),
      status: url.searchParams.get("status"),
      auth: headerValue(init.headers, "authorization"),
      accept: headerValue(init.headers, "accept"),
    });
    attempts += 1;
    if (attempts === 1) {
      return jsonResponse({ message: "Rate limit exceeded" }, { status: 429, statusText: "Too Many Requests", headers: { "retry-after": "2" } });
    }
    if (url.searchParams.get("page") === "1") {
      return jsonResponse([{ id: 1 }, { id: 2 }]);
    }
    return jsonResponse([{ id: 3 }]);
  };

  const client = new Knowbe4ApiClient(sampleConfig({ apiToken: "reporting-token" }), {
    fetchImpl,
    sleepImpl: async (ms) => {
      sleeps.push(ms);
    },
    minRequestIntervalMs: 0,
  });
  const users = await client.list("/v1/users", { status: "active" }, { limit: 10, pageSize: 2 });

  assert.deepEqual(users.map((item) => item.id), [1, 2, 3]);
  assert.equal(seen.length, 3);
  assert.ok(seen.every((item) => item.pathname === "/v1/users"));
  assert.ok(seen.every((item) => item.auth === "Bearer reporting-token"));
  assert.ok(seen.every((item) => item.accept === "application/json"));
  assert.ok(seen.every((item) => item.status === "active"));
  assert.deepEqual(seen.map((item) => item.page), ["1", "1", "2"]);
  assert.deepEqual(seen.map((item) => item.perPage), ["2", "2", "2"]);
  assert.deepEqual(sleeps, [2000]);
  assert.equal(client.getRequestCount(), 3);
});

test("Knowbe4ApiClient stops retrying after max retries and redacts tokens in errors", async () => {
  const always429 = async () => jsonResponse({ message: "slow down" }, { status: 429, statusText: "Too Many Requests" });
  const limited = new Knowbe4ApiClient(sampleConfig(), { fetchImpl: always429, sleepImpl: async () => {}, maxRetries: 1, minRequestIntervalMs: 0 });
  await assert.rejects(() => limited.getAccount(), /429 Too Many Requests.*slow down/);
  assert.equal(limited.getRequestCount(), 2);

  const leaking = new Knowbe4ApiClient(sampleConfig({ apiToken: "super-secret-token", phisherApiToken: "phisher-secret" }), {
    fetchImpl: async () => {
      throw new Error("connect failed while sending super-secret-token and phisher-secret");
    },
    minRequestIntervalMs: 0,
  });
  await assert.rejects(() => leaking.getAccount(), (error) => {
    assert.match(error.message, /KnowBe4 request to \/v1\/account failed/);
    assert.ok(!error.message.includes("super-secret-token"));
    assert.ok(!error.message.includes("phisher-secret"));
    assert.match(error.message, /\[REDACTED\]/);
    return true;
  });

  const unauthorized = new Knowbe4ApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ error: "Unauthorized" }, { status: 401, statusText: "Unauthorized" }),
    minRequestIntervalMs: 0,
  });
  await assert.rejects(() => unauthorized.getAccount(), /401 Unauthorized.*Unauthorized/);
});

test("Knowbe4ApiClient shapes Reporting API list requests with the documented query parameters", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(`${url.pathname}?${url.searchParams.toString()}`);
    return jsonResponse([]);
  };
  const client = new Knowbe4ApiClient(sampleConfig({ region: "eu", baseUrl: "https://eu.api.knowbe4.com" }), { fetchImpl, minRequestIntervalMs: 0 });

  await client.getAccountRiskScoreHistory(true);
  await client.listUsers({ status: "archived", limit: 5 });
  await client.listSecurityTests({ campaignType: "callback" });
  await client.listSecurityTestRecipients("42");
  await client.listTrainingCampaigns();
  await client.listTrainingEnrollments({ campaignId: "7" });
  await client.listGroupMembers("9");

  assert.equal(seen[0], "/v1/account/risk_score_history?full=true&page=1&per_page=500");
  assert.equal(seen[1], "/v1/users?status=archived&page=1&per_page=500");
  assert.equal(seen[2], "/v1/phishing/security_tests?campaign_type=callback&page=1&per_page=500");
  assert.equal(seen[3], "/v1/phishing/security_tests/42/recipients?page=1&per_page=500");
  assert.equal(seen[4], "/v1/training/campaigns?page=1&per_page=10");
  assert.equal(
    seen[5],
    "/v1/training/enrollments?campaign_id=7&exclude_archived_users=true&include_campaign_id=true&include_store_purchase_id=true&page=1&per_page=500",
  );
  assert.equal(seen[6], "/v1/groups/9/members?page=1&per_page=500");
});

test("Knowbe4ApiClient shapes PhishER GraphQL requests and paginates with per, page, and nextPageKey", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const body = JSON.parse(init.body);
    seen.push({
      url: typeof input === "string" ? input : input.toString(),
      method: init.method,
      auth: headerValue(init.headers, "authorization"),
      contentType: headerValue(init.headers, "content-type"),
      operation: body.query,
      variables: body.variables,
    });
    const page = body.variables.page;
    return jsonResponse({
      data: {
        phisherMessages: {
          nodes: page === 1 ? [{ id: "m1", category: "THREAT" }, { id: "m2", category: "CLEAN" }] : [{ id: "m3", category: "SPAM" }],
          pagination: { page, pages: 2, per: 2, totalCount: 3, nextPageKey: page === 1 ? "key-2" : null },
        },
      },
    });
  };

  const client = new Knowbe4ApiClient(sampleConfig({
    region: "eu",
    baseUrl: "https://eu.api.knowbe4.com",
    phisherApiToken: "phisher-token",
    phisherGraphqlUrl: "https://eu.knowbe4.com/graphql",
  }), { fetchImpl, minRequestIntervalMs: 0 });

  const messages = await client.listPhisherMessages({ query: "reported_at:[2026-06-23 TO *]", limit: 2000 });
  assert.deepEqual(messages.map((item) => item.id), ["m1", "m2", "m3"]);
  assert.equal(seen.length, 2);
  assert.ok(seen.every((item) => item.url === "https://eu.knowbe4.com/graphql"));
  assert.ok(seen.every((item) => item.method === "POST"));
  assert.ok(seen.every((item) => item.auth === "Bearer phisher-token"));
  assert.ok(seen.every((item) => item.contentType === "application/json"));
  assert.match(seen[0].operation, /phisherMessages\(query: \$query, per: \$per, page: \$page, nextPageKey: \$nextPageKey/);
  assert.equal(seen[0].variables.query, "reported_at:[2026-06-23 TO *]");
  assert.equal(seen[0].variables.per, 200);
  assert.equal(seen[0].variables.page, 1);
  assert.equal(seen[1].variables.page, 2);
  assert.equal(seen[1].variables.nextPageKey, "key-2");

  const erroring = new Knowbe4ApiClient(sampleConfig({ phisherApiToken: "phisher-token" }), {
    fetchImpl: async () => jsonResponse({ errors: [{ message: "Not authorized" }] }),
    minRequestIntervalMs: 0,
  });
  await assert.rejects(() => erroring.countPhisherMessages(""), /PhishER GraphQL returned errors: Not authorized/);

  const unconfigured = new Knowbe4ApiClient(sampleConfig(), { fetchImpl: async () => jsonResponse({}), minRequestIntervalMs: 0 });
  assert.equal(unconfigured.hasPhisherCredentials(), false);
  await assert.rejects(() => unconfigured.listPhisherMessages(), /PhishER API token is not configured/);
});

test("checkKnowbe4Access reports a healthy account when every Reporting API surface is readable", async () => {
  const client = mockClient(healthyFixture(), { phisher: true });
  const result = await checkKnowbe4Access(client);

  assert.equal(result.status, "healthy");
  assert.equal(result.region, "us");
  assert.equal(result.accountName, "Acme Corp");
  assert.equal(result.subscriptionLevel, "Diamond");
  assert.equal(result.surfaces.length, 10);
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 10);
  assert.equal(result.surfaces.find((surface) => surface.name === "account")?.count, 1);
  assert.equal(result.surfaces.find((surface) => surface.name === "phisher_messages")?.count, 2);
  assert.match(result.recommendedNextStep, /knowbe4_assess_phishing_program/);
  assert.ok(client.calls.includes("probe:/v1/training/enrollments"));
});

test("checkKnowbe4Access reports limited access when most surfaces are unreadable", async () => {
  const client = mockClient(healthyFixture(), {
    failures: {
      "probe:/v1/users": "KnowBe4 request failed (401 Unauthorized) for /v1/users",
      "probe:/v1/groups": "KnowBe4 request failed (401 Unauthorized) for /v1/groups",
      "probe:/v1/phishing/campaigns": "KnowBe4 request failed (403 Forbidden) for /v1/phishing/campaigns",
      "probe:/v1/phishing/security_tests": "KnowBe4 request failed (403 Forbidden) for /v1/phishing/security_tests",
    },
  });
  const result = await checkKnowbe4Access(client);

  assert.equal(result.status, "limited");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 5);
  assert.equal(result.surfaces.filter((surface) => surface.status === "not_readable").length, 4);
  assert.equal(result.surfaces.find((surface) => surface.name === "phisher_messages")?.status, "not_configured");
  assert.match(result.surfaces.find((surface) => surface.name === "users")?.error ?? "", /401/);
  assert.match(result.recommendedNextStep, /Regenerate the Reporting API key/);
});

test("collectKnowbe4Snapshot only loads the surfaces the requested scope needs", async () => {
  const client = mockClient(healthyFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["governance"], now: NOW });

  assert.equal(snapshot.trainingEnrollments.collected, false);
  assert.equal(snapshot.storePurchases.collected, false);
  assert.equal(snapshot.callbackSecurityTests.collected, true);
  assert.ok(client.calls.includes("listCallbackSecurityTests"));
  assert.ok(!client.calls.includes("listTrainingEnrollments"));
  assert.ok(!client.calls.some((call) => call.startsWith("listSecurityTestRecipients")));
  assert.deepEqual(snapshot.errors, []);
});

test("assessKnowbe4PhishingProgram passes a healthy program and enriches the report rate with PhishER", async () => {
  const client = mockClient(healthyFixture(), { phisher: true });
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["phishing"], now: NOW });
  const result = assessKnowbe4PhishingProgram(snapshot, { now: NOW });

  assert.equal(result.area, "phishing");
  assert.deepEqual(result.findings.map((item) => item.control), [1, 2, 6, 7, 9, 19, 20]);
  for (const control of [1, 2, 6, 7, 9, 19, 20]) {
    assert.equal(findingFor(result, control).status, "pass", `control ${control} should pass`);
  }
  assert.equal(findingFor(result, 2).evidence.coverage_pct, 100);
  assert.equal(findingFor(result, 19).evidence.report_rate_pct, 60);
  assert.equal(findingFor(result, 19).evidence.phisher.messages_in_window, 2);
  assert.deepEqual(findingFor(result, 19).evidence.phisher.by_category, { THREAT: 1, CLEAN: 1 });
  assert.ok(client.calls.some((call) => /^listPhisherMessages:reported_at:\[\d{4}-\d{2}-\d{2} TO \*\]$/.test(call)));
  assert.equal(result.summary.phisher_messages, 2);
  assert.deepEqual(result.errors, []);
});

test("assessKnowbe4PhishingProgram fails a stale, narrow, and worsening program", async () => {
  const client = mockClient(failingFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["phishing"], now: NOW });
  const result = assessKnowbe4PhishingProgram(snapshot, { now: NOW });

  for (const control of [1, 2, 6, 7, 9, 19, 20]) {
    assert.equal(findingFor(result, control).status, "fail", `control ${control} should fail`);
  }
  assert.equal(findingFor(result, 1).evidence.days_since_last_test, 82);
  assert.equal(findingFor(result, 2).evidence.coverage_pct, 10);
  assert.equal(findingFor(result, 6).evidence.current_phish_prone_pct, 25);
  assert.ok(findingFor(result, 7).evidence.delta_points > 2);
  assert.equal(findingFor(result, 9).evidence.estimated_coverage_pct, 50);
  assert.equal(findingFor(result, 19).evidence.phisher.status, "not_configured");
  assert.ok(findingFor(result, 20).evidence.max_gap_days > 45);
});

test("assessKnowbe4PhishingProgram degrades to warn findings when security tests are unreadable", async () => {
  const client = mockClient(healthyFixture(), { failures: { listSecurityTests: "KnowBe4 request failed (403 Forbidden) for /v1/phishing/security_tests" } });
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["phishing"], now: NOW });
  const result = assessKnowbe4PhishingProgram(snapshot, { now: NOW });

  assert.ok(snapshot.errors.some((error) => error.startsWith("security_tests:")));
  for (const control of [1, 2, 6, 7, 19, 20]) {
    const item = findingFor(result, control);
    assert.equal(item.status, "warn", `control ${control} should warn`);
    assert.match(item.summary, /not readable/);
    assert.match(item.evidence.collection_error, /403/);
  }
  assert.ok(result.errors.length > 0);
});

test("assessKnowbe4TrainingProgram passes a well-run training program", async () => {
  const client = mockClient(healthyFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["training"], now: NOW });
  const result = assessKnowbe4TrainingProgram(snapshot, { now: NOW });

  assert.equal(result.area, "training");
  assert.deepEqual(result.findings.map((item) => item.control), [3, 4, 10, 11, 17]);
  for (const control of [3, 4, 10, 11, 17]) {
    assert.equal(findingFor(result, control).status, "pass", `control ${control} should pass`);
  }
  assert.equal(findingFor(result, 3).evidence.campaigns_evaluated.length, 1);
  assert.equal(findingFor(result, 3).evidence.campaigns_evaluated[0].completion_pct, 96);
  assert.equal(findingFor(result, 4).evidence.new_users_evaluated, 1);
  assert.equal(findingFor(result, 10).evidence.remediated_users, 1);
  assert.equal(findingFor(result, 11).evidence.modules_reviewed, 3);
  assert.ok(findingFor(result, 17).evidence.topics[0].assigned_modules.includes("PCI DSS Compliance Basics"));
});

test("assessKnowbe4TrainingProgram fails low completion, late enrollment, missing remediation, and stale content", async () => {
  const client = mockClient(failingFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["training"], now: NOW });
  const result = assessKnowbe4TrainingProgram(snapshot, { now: NOW, requiredComplianceTopics: ["HIPAA", "PCI"] });

  for (const control of [3, 4, 10, 11, 17]) {
    assert.equal(findingFor(result, control).status, "fail", `control ${control} should fail`);
  }
  assert.equal(findingFor(result, 3).evidence.campaigns_evaluated[0].completion_pct, 55);
  assert.equal(findingFor(result, 4).evidence.late_or_missing_enrollments, 2);
  assert.equal(findingFor(result, 10).evidence.remediated_users, 0);
  assert.equal(findingFor(result, 11).evidence.retired_modules.length, 1);
  assert.deepEqual(findingFor(result, 17).evidence.topics.map((item) => item.topic), ["HIPAA", "PCI"]);

  const autoDetect = assessKnowbe4TrainingProgram(snapshot, { now: NOW });
  assert.equal(findingFor(autoDetect, 17).status, "warn");
});

test("assessKnowbe4UserRisk passes balanced risk, full group coverage, and active users", async () => {
  const client = mockClient(healthyFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["risk"], now: NOW });
  const result = assessKnowbe4UserRisk(snapshot, { now: NOW });

  assert.equal(result.area, "risk");
  assert.deepEqual(result.findings.map((item) => item.control), [5, 8, 18]);
  for (const control of [5, 8, 18]) {
    assert.equal(findingFor(result, control).status, "pass", `control ${control} should pass`);
  }
  assert.equal(findingFor(result, 5).evidence.users_scored, 10);
  assert.equal(findingFor(result, 5).evidence.mean_risk_score, 25.5);
  assert.equal(findingFor(result, 8).evidence.phishing_targets_all_users, true);
  assert.equal(findingFor(result, 18).evidence.inactive_users, 0);
});

test("assessKnowbe4UserRisk fails high risk, uncovered groups, and inactive users", async () => {
  const client = mockClient(failingFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["risk"], now: NOW });
  const result = assessKnowbe4UserRisk(snapshot, { now: NOW });

  for (const control of [5, 8, 18]) {
    assert.equal(findingFor(result, control).status, "fail", `control ${control} should fail`);
  }
  assert.ok(findingFor(result, 5).evidence.mean_risk_score > 50);
  assert.deepEqual(findingFor(result, 8).evidence.groups_missing_phishing.map((group) => group.name), ["Engineering"]);
  assert.deepEqual(findingFor(result, 8).evidence.groups_missing_training.map((group) => group.name), ["Engineering"]);
  assert.equal(findingFor(result, 18).evidence.inactive_users, 7);
  assert.equal(findingFor(result, 18).evidence.partial_activity_data, false);
});

test("assessKnowbe4AccountGovernance passes admin hygiene and callback tests while flagging manual controls", async () => {
  const client = mockClient(healthyFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["governance"], now: NOW });
  const result = assessKnowbe4AccountGovernance(snapshot, { now: NOW });

  assert.equal(result.area, "governance");
  assert.deepEqual(result.findings.map((item) => item.control), [12, 13, 14, 15, 16]);
  assert.equal(findingFor(result, 12).status, "pass");
  assert.equal(findingFor(result, 16).status, "pass");
  for (const control of [13, 14, 15]) {
    const item = findingFor(result, control);
    assert.equal(item.status, "manual", `control ${control} should be manual`);
    assert.match(item.manualEvidence, /console/i);
    assert.equal(item.evidence.api_visibility, "not_exposed_by_reporting_api");
  }
  assert.deepEqual(result.summary.manual_controls, ["KNOWBE4-13", "KNOWBE4-14", "KNOWBE4-15"]);

  const relaxed = assessKnowbe4AccountGovernance(snapshot, { now: NOW, requireUsbTests: false, requireVishingTests: false });
  assert.equal(findingFor(relaxed, 15).status, "pass");
  assert.equal(findingFor(relaxed, 16).status, "pass");
});

test("assessKnowbe4AccountGovernance fails excessive admins and missing callback tests", async () => {
  const client = mockClient(failingFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["governance"], now: NOW });
  const result = assessKnowbe4AccountGovernance(snapshot, { now: NOW });

  assert.equal(findingFor(result, 12).status, "fail");
  assert.equal(findingFor(result, 12).evidence.admin_count, 5);
  assert.deepEqual(findingFor(result, 12).evidence.external_domain_admins, ["consultant@contractor.example"]);
  assert.equal(findingFor(result, 16).status, "fail");
  assert.equal(findingFor(result, 16).evidence.callback_tests_all_time, 0);

  const tightened = assessKnowbe4AccountGovernance(snapshot, { now: NOW, maxAdminCount: 10 });
  assert.equal(findingFor(tightened, 12).status, "warn");
});

test("KnowBe4 findings carry the full framework crosswalk and cover all twenty spec controls", async () => {
  const client = mockClient(healthyFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { now: NOW });
  const findings = [
    ...assessKnowbe4PhishingProgram(snapshot, { now: NOW }).findings,
    ...assessKnowbe4TrainingProgram(snapshot, { now: NOW }).findings,
    ...assessKnowbe4UserRisk(snapshot, { now: NOW }).findings,
    ...assessKnowbe4AccountGovernance(snapshot, { now: NOW }).findings,
  ];

  assert.equal(KNOWBE4_CONTROLS.length, 20);
  assert.equal(findings.length, 20);
  assert.deepEqual(
    [...new Set(findings.map((item) => item.control))].sort((left, right) => left - right),
    Array.from({ length: 20 }, (_, index) => index + 1),
  );
  for (const item of findings) {
    assert.match(item.id, /^KNOWBE4-\d{2}$/);
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
    assert.equal(item.mappings.length, 8);
    assert.deepEqual(item.mappings, knowbe4ControlMappings(item.control));
  }
  assert.deepEqual(knowbe4ControlMappings(1), [
    "FedRAMP AT-2(1)",
    "CMMC L2 3.2.1",
    "SOC 2 CC1.4",
    "CIS Controls v8 14.1",
    "PCI-DSS 12.6.2",
    "DISA STIG SRG-APP-000516",
    "IRAP ISM-0252",
    "ISMAP HR-01",
  ]);
  assert.deepEqual(knowbe4ControlMappings(12), [
    "FedRAMP AC-6(5)",
    "CMMC L2 3.1.5",
    "SOC 2 CC6.3",
    "CIS Controls v8 5.4",
    "PCI-DSS 7.2.2",
    "DISA STIG SRG-APP-000340",
    "IRAP ISM-0432",
    "ISMAP AC-01",
  ]);
  assert.equal(knowbe4ToolForArea("phishing"), "knowbe4_assess_phishing_program");
  assert.equal(knowbe4ToolForArea("governance"), "knowbe4_assess_account_governance");
});

test("redactKnowbe4Pii pseudonymizes emails and masks names when redaction is enabled", async () => {
  const redacted = redactKnowbe4Pii({
    email: "User4@Acme.example",
    first_name: "First4",
    phone_number: "555-0100",
    nested: [{ email: "user5@acme.example", id: 5 }],
    keep: "visible",
  });
  assert.match(redacted.email, /^user-[0-9a-f]{12}$/);
  assert.equal(redacted.email, redactKnowbe4Pii({ email: "user4@acme.example" }).email);
  assert.equal(redacted.first_name, "[redacted]");
  assert.equal(redacted.phone_number, "[redacted]");
  assert.match(redacted.nested[0].email, /^user-[0-9a-f]{12}$/);
  assert.equal(redacted.nested[0].id, 5);
  assert.equal(redacted.keep, "visible");

  const client = mockClient(failingFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["risk", "governance"], now: NOW });
  const risk = assessKnowbe4UserRisk(snapshot, { now: NOW, redactPii: true });
  const governance = assessKnowbe4AccountGovernance(snapshot, { now: NOW, redactPii: true });
  const serialized = JSON.stringify([risk, governance]);
  assert.ok(!serialized.includes("@acme.example"));
  assert.ok(!serialized.includes("@contractor.example"));
  assert.ok(findingFor(risk, 18).evidence.inactive_user_sample.every((label) => label.startsWith("user-")));
});

test("exportKnowbe4AuditBundle writes core data, analysis, compliance reports, and a zip archive", async () => {
  const base = createTempBase("grclanker-knowbe4-export-");
  const client = mockClient(healthyFixture(), { phisher: true });
  const result = await exportKnowbe4AuditBundle(client, client.getResolvedConfig(), base, { now: NOW });

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.match(result.outputDir, /acme-corp-knowbe4-audit-bundle$/);
  assert.equal(result.findingCount, 20);
  assert.equal(result.manualCount, 3);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 30);

  const expectedFiles = [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "core_data/account.json",
    "core_data/account_risk_score_history.json",
    "core_data/users_active.json",
    "core_data/groups.json",
    "core_data/phishing_campaigns.json",
    "core_data/security_tests.json",
    "core_data/security_test_recipients.json",
    "core_data/callback_security_tests.json",
    "core_data/training_campaigns.json",
    "core_data/training_enrollments.json",
    "core_data/store_purchases.json",
    "core_data/training_policies.json",
    "core_data/phisher_messages.json",
    "analysis/findings.json",
    "analysis/control_coverage.json",
    "analysis/access_check.md",
    "analysis/phishing.json",
    "analysis/phishing.md",
    "analysis/training.json",
    "analysis/training.md",
    "analysis/risk.json",
    "analysis/risk.md",
    "analysis/governance.json",
    "analysis/governance.md",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis_controls/cis_controls_v8_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
  ];
  for (const relativePath of expectedFiles) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `expected ${relativePath}`);
  }
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.account_name, "Acme Corp");
  assert.equal(metadata.region, "us");
  assert.equal(metadata.phisher_configured, true);
  assert.ok(!JSON.stringify(metadata).includes("reporting-token"));

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 20);
  const coverage = JSON.parse(readFileSync(join(result.outputDir, "analysis", "control_coverage.json"), "utf8"));
  assert.equal(coverage.length, 20);
  assert.ok(coverage.every((item) => item.status !== "not_evaluated"));
  assert.ok(coverage.every((item) => KNOWBE4_TOOL_NAMES.includes(item.tool)));

  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /Controls: 20 evaluated, Pass 17, Warn 0, Fail 0, Manual 3/);
  assert.match(summary, /KNOWBE4-13/);
  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /\| KNOWBE4-01 \| Phishing simulation frequency \| AT-2\(1\) \| L2 3\.2\.1 \| CC1\.4 \| 14\.1 \| 12\.6\.2 \| SRG-APP-000516 \| ISM-0252 \| HR-01 \| PASS \|/);
  const fedramp = readFileSync(join(result.outputDir, "compliance", "fedramp", "fedramp_compliance_report.md"), "utf8");
  assert.match(fedramp, /# FedRAMP Compliance Report/);
  assert.match(fedramp, /KNOWBE4-12 \| Admin role audit \| AC-6\(5\)/);
  assert.equal(readdirSync(join(result.outputDir, "compliance")).filter((entry) => !entry.endsWith(".md")).length, 8);
  assert.ok(!existsSync(`${result.outputDir}-2`));
});

test("exportKnowbe4AuditBundle records partial collection failures and honors PII redaction", async () => {
  const base = createTempBase("grclanker-knowbe4-export-partial-");
  const client = mockClient(healthyFixture(), {
    config: { redactPii: true },
    failures: {
      listTrainingEnrollments: "KnowBe4 request failed (500 Internal Server Error) for /v1/training/enrollments",
      listStorePurchases: "KnowBe4 request failed (503 Service Unavailable) for /v1/training/store_purchases",
    },
  });
  const result = await exportKnowbe4AuditBundle(client, client.getResolvedConfig(), base, { now: NOW });

  assert.ok(existsSync(result.zipPath));
  assert.equal(result.errorCount, 2);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /training_enrollments: .*500/);
  assert.match(errorLog, /store_purchases: .*503/);
  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /Partial Collection Warnings/);
  assert.match(summary, /PII redaction: enabled/);

  const users = readFileSync(join(result.outputDir, "core_data", "users_active.json"), "utf8");
  assert.ok(!users.includes("@acme.example"));
  assert.ok(users.includes("[redacted]"));
  const recipients = readFileSync(join(result.outputDir, "core_data", "security_test_recipients.json"), "utf8");
  assert.ok(!recipients.includes("@acme.example"));
  assert.ok(!recipients.includes("203.0.113.10"));
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.control === 4).status, "warn");
  assert.ok(!JSON.stringify(findings).includes("@acme.example"));

  const second = await exportKnowbe4AuditBundle(client, client.getResolvedConfig(), base, { now: NOW });
  assert.match(second.outputDir, /acme-corp-knowbe4-audit-bundle-2$/);
});

test("resolveSecureOutputPath rejects traversal and symlinked parents", () => {
  const base = createTempBase("grclanker-knowbe4-path-");
  const outside = createTempBase("grclanker-knowbe4-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, join("..", "..", "etc", "passwd")), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  assert.throws(() => resolveSecureOutputPath(base, join("linked", "nested", "file.txt")), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("compliance", "safe.md"));
  assert.match(safe, /compliance\/safe\.md$/);
});

test("KnowBe4 tools are registered in the tool catalog under the KnowBe4 group", () => {
  const summaries = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("knowbe4_"));
  assert.deepEqual(summaries.map((tool) => tool.name).sort(), [...KNOWBE4_TOOL_NAMES].sort());
  assert.ok(summaries.every((tool) => tool.group === "KnowBe4"));
  assert.ok(summaries.every((tool) => tool.kind === "domain"));
  assert.ok(summaries.every((tool) => tool.description.length > 40));
  const exportTool = summaries.find((tool) => tool.name === "knowbe4_export_audit_bundle");
  const exportParams = exportTool.parameterSummaries.map((parameter) => parameter.name);
  for (const expected of ["api_token", "region", "phisher_api_token", "config_file", "redact_pii", "output_dir", "required_compliance_topics", "max_admin_count"]) {
    assert.ok(exportParams.includes(expected), `expected export parameter ${expected}`);
  }
  assert.ok(exportTool.parameterSummaries.every((parameter) => !parameter.required));
  const regionParam = exportTool.parameterSummaries.find((parameter) => parameter.name === "region");
  assert.deepEqual(regionParam.enumValues, ["us", "eu", "ca", "uk", "de"]);
  const checkAccess = summaries.find((tool) => tool.name === "knowbe4_check_access");
  assert.equal(checkAccess.parameterSummaries.length, 8);
});
