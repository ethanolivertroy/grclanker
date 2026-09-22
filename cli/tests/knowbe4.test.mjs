import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

import {
  KNOWBE4_CONTROLS,
  KNOWBE4_INVENTORIES,
  Knowbe4ApiClient,
  assessKnowbe4AccountGovernance,
  assessKnowbe4PhishingProgram,
  assessKnowbe4TrainingProgram,
  assessKnowbe4UserRisk,
  checkKnowbe4Access,
  collectKnowbe4Snapshot,
  exportKnowbe4AuditBundle,
  knowbe4CollectionStatus,
  knowbe4ControlMappings,
  knowbe4ToolForArea,
  projectKnowbe4User,
  redactCredentialValues,
  redactKnowbe4Pii,
  registerKnowbe4Tools,
  resolveKnowbe4Configuration,
  resolveSecureOutputPath,
  scrubErrorText,
} from "../dist/extensions/grc-tools/knowbe4.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import { assertCanaryFixture, assertCanaryWindowsAbsent } from "./helpers/canary-windows.mjs";
import { scrubAlterations } from "./helpers/scrub-survival.mjs";

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
  // A failure keyed by the bare method name (for example listSecurityTestRecipients) fails every per-record read too.
  const guard = (name, result) => {
    calls.push(name);
    const failure = failures[name] ?? failures[name.split(":")[0]];
    if (failure) throw new Error(failure);
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
    async listUsers(listOptions = {}) {
      return guard("listUsers", listOptions.limit ? fixture.users.slice(0, listOptions.limit) : fixture.users);
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
    async listTrainingEnrollments(listOptions = {}) {
      return guard("listTrainingEnrollments", listOptions.limit ? fixture.enrollments.slice(0, listOptions.limit) : fixture.enrollments);
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

  assert.deepEqual(users.items.map((item) => item.id), [1, 2, 3]);
  assert.equal(users.truncated, false, "a short final page means the listing is complete");
  assert.equal(users.pages, 2);
  assert.equal(users.limit, 10);
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

test("foreign-origin next link: KnowBe4 paging is a client-side page counter on the configured base, so a payload carrying a URL-shaped field cannot redirect the next request", async () => {
  const FOREIGN = "https://collector.attacker.example/v1/users?page=2";
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(url);
    // The Reporting API returns bare arrays; a next link in any shape the server might add is not part of the contract.
    return url.searchParams.get("page") === "1"
      ? jsonResponse([{ id: 1, next: FOREIGN, links: { next: FOREIGN } }, { id: 2 }])
      : jsonResponse([{ id: 3 }]);
  };
  const client = new Knowbe4ApiClient(sampleConfig({ apiToken: "reporting-token" }), { fetchImpl, minRequestIntervalMs: 0 });

  const users = await client.list("/v1/users", { status: "active" }, { limit: 10, pageSize: 2 });

  assert.deepEqual(users.items.map((item) => item.id), [1, 2, 3]);
  assert.equal(seen.length, 2);
  assert.ok(seen.every((url) => url.origin === "https://us.api.knowbe4.com" && url.pathname === "/v1/users"), "every page request went to the configured origin");
  assert.deepEqual(seen.map((url) => url.searchParams.get("page")), ["1", "2"], "the next page is the client's own counter, not a server value");
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
    assert.match(error.message, /KnowBe4 request failed: GET \/v1\/account/);
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
  assert.deepEqual(messages.items.map((item) => item.id), ["m1", "m2", "m3"]);
  assert.equal(messages.total, 3);
  assert.equal(messages.truncated, false);
  assert.equal(seen.length, 2);
  assert.ok(seen.every((item) => item.url === "https://eu.knowbe4.com/graphql"));
  assert.ok(seen.every((item) => item.method === "POST"));
  assert.ok(seen.every((item) => item.auth === "Bearer phisher-token"));
  assert.ok(seen.every((item) => item.contentType === "application/json"));
  assert.match(seen[0].operation, /phisherMessages\(query: \$query, per: \$per, page: \$page, nextPageKey: \$nextPageKey/);
  // Argument names come from the public schema at POST https://training.knowbe4.com/graphql?scope=phisher (introspection, no auth).
  const schemaArguments = ["per", "page", "all", "query", "sortField", "sortDirection", "nextPageKey"];
  const usedArguments = [...seen[0].operation.match(/phisherMessages\(([^)]*)\)/)[1].matchAll(/(\w+):/g)].map((match) => match[1]);
  assert.ok(usedArguments.length > 0);
  assert.ok(usedArguments.every((name) => schemaArguments.includes(name)), `unknown phisherMessages arguments: ${usedArguments.join(", ")}`);
  assert.ok(!/per_page/.test(seen[0].operation), "per_page is a Reporting API query parameter, not a PhishER GraphQL argument");
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
  assert.equal(findingFor(result, 6).evidence.current_source, "security_tests");
  assert.equal(findingFor(result, 20).evidence.days_since_latest_test, 6);
  assert.equal(findingFor(result, 20).evidence.gaps.at(-1).boundary, "now");
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

test("assessKnowbe4PhishingProgram turns security-test controls manual when security tests are unreadable", async () => {
  const client = mockClient(healthyFixture(), { failures: { listSecurityTests: "KnowBe4 request failed (403 Forbidden) for /v1/phishing/security_tests" } });
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["phishing"], now: NOW });
  const result = assessKnowbe4PhishingProgram(snapshot, { now: NOW });

  assert.ok(snapshot.errors.some((error) => error.startsWith("security_tests:")));
  for (const control of [1, 2, 6, 7, 19, 20]) {
    const item = findingFor(result, control);
    assert.equal(item.status, "manual", `control ${control} cannot be judged without security tests`);
    assert.match(item.summary, /^Unreadable inventory: security_tests \(GET \/v1\/phishing\/security_tests: KnowBe4 request failed \(403 Forbidden\)/);
    assert.match(item.summary, /Collect manually: the phishing security test list/);
    assert.match(item.evidence.collection_error, /403/);
    assert.equal(item.evidence.unreadable_inventories[0].inventory, "security_tests");
    assert.match(item.manualEvidence, /Phishing > Reports > Security Tests/);
  }
  // Campaign targeting is judged from the campaign list itself; the missing tests only demote it.
  const targeting = findingFor(result, 9);
  assert.equal(targeting.status, "warn");
  assert.match(targeting.summary, /target All Users.*Unreadable inventory: security_tests/);
  assert.ok(result.errors.length > 0);
});

test("assessKnowbe4PhishingProgram warns instead of passing phish-prone percentage when no test ran in the window", async () => {
  // A never-tested account: no security tests, and the Reporting API reports 0% for users who were never phished.
  const fixture = healthyFixture();
  fixture.securityTests = [];
  fixture.recipientsByTest = new Map();
  fixture.phishingCampaigns = [];
  fixture.users = fixture.users.map((record) => ({ ...record, phish_prone_percentage: 0 }));
  const snapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["phishing"], now: NOW });
  const item = findingFor(assessKnowbe4PhishingProgram(snapshot, { now: NOW }), 6);

  assert.equal(item.status, "warn");
  assert.match(item.summary, /No phishing security tests ran in the last 90 days/);
  assert.match(item.summary, /cannot be verified from test results/);
  assert.match(item.summary, /not used for the verdict/);
  assert.equal(item.evidence.security_tests_in_window, 0);
  assert.equal(item.evidence.current_phish_prone_pct, null);
  assert.equal(item.evidence.current_source, "unverified");
  assert.equal(item.evidence.user_average_phish_prone_pct, 0);

  // Tests that exist only outside the window do not back a verdict either.
  const stale = healthyFixture();
  stale.securityTests = [securityTest(901, daysAgo(200), 0.05)];
  stale.recipientsByTest = new Map();
  const staleSnapshot = await collectKnowbe4Snapshot(mockClient(stale), { scopes: ["phishing"], now: NOW });
  const staleItem = findingFor(assessKnowbe4PhishingProgram(staleSnapshot, { now: NOW }), 6);
  assert.equal(staleItem.status, "warn");
  assert.equal(staleItem.evidence.security_tests_in_window, 0);
  assert.equal(staleItem.evidence.security_tests_all_time, 1);

  // Tests in the window without delivered counts cannot produce a rate and stay inconclusive.
  const undelivered = healthyFixture();
  undelivered.securityTests = [securityTest(901, daysAgo(10), null, { delivered_count: 0, scheduled_count: 0 })];
  undelivered.recipientsByTest = new Map();
  const undeliveredSnapshot = await collectKnowbe4Snapshot(mockClient(undelivered), { scopes: ["phishing"], now: NOW });
  const undeliveredItem = findingFor(assessKnowbe4PhishingProgram(undeliveredSnapshot, { now: NOW }), 6);
  assert.equal(undeliveredItem.status, "warn");
  assert.match(undeliveredItem.summary, /none reported a phish-prone percentage with delivered counts/);
  assert.equal(undeliveredItem.evidence.security_tests_in_window, 1);
});

test("assessKnowbe4PhishingProgram fails schedule regularity when the program stopped running tests", async () => {
  // A monthly cadence that stopped 200 days ago: consecutive gaps are 30 days, but nothing has run since.
  const fixture = healthyFixture();
  fixture.securityTests = [200, 230, 260, 290, 320].map((age, index) => securityTest(900 + index, daysAgo(age), 0.08));
  fixture.recipientsByTest = new Map();
  const snapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["phishing"], now: NOW });

  const item = findingFor(assessKnowbe4PhishingProgram(snapshot, { now: NOW, lookbackDays: 365 }), 20);
  assert.equal(item.status, "fail");
  assert.equal(item.evidence.lookback_days, 365);
  assert.equal(item.evidence.security_tests_in_window, 5);
  assert.equal(item.evidence.days_since_latest_test, 200);
  assert.equal(item.evidence.max_gap_days, 200);
  assert.deepEqual(item.evidence.gaps.filter((gap) => gap.boundary !== "now").map((gap) => gap.days), [30, 30, 30, 30]);
  assert.ok(item.evidence.gaps_over_threshold.some((gap) => gap.boundary === "now" && gap.days === 200));
  assert.match(item.summary, /including the 200 days since the most recent test/);

  // The configured lookback is honored instead of a hardcoded year: nothing is inside 90 days, and the gap to now still fails.
  const defaultWindow = findingFor(assessKnowbe4PhishingProgram(snapshot, { now: NOW }), 20);
  assert.equal(defaultWindow.status, "fail");
  assert.equal(defaultWindow.evidence.lookback_days, 90);
  assert.equal(defaultWindow.evidence.security_tests_in_window, 0);
  assert.equal(defaultWindow.evidence.days_since_latest_test, 200);

  // The last test before the window anchors the series so the gap into the window is measured too.
  const gapIntoWindow = healthyFixture();
  gapIntoWindow.securityTests = [securityTest(901, daysAgo(6), 0.08), securityTest(902, daysAgo(200), 0.08)];
  gapIntoWindow.recipientsByTest = new Map();
  const gapSnapshot = await collectKnowbe4Snapshot(mockClient(gapIntoWindow), { scopes: ["phishing"], now: NOW });
  const gapItem = findingFor(assessKnowbe4PhishingProgram(gapSnapshot, { now: NOW }), 20);
  assert.equal(gapItem.status, "fail");
  assert.equal(gapItem.evidence.security_tests_in_window, 1);
  assert.equal(gapItem.evidence.max_gap_days, 194);
  assert.equal(gapItem.evidence.days_since_latest_test, 6);

  // A program with no tests at all has no cadence and fails outright.
  const empty = healthyFixture();
  empty.securityTests = [];
  empty.recipientsByTest = new Map();
  const emptySnapshot = await collectKnowbe4Snapshot(mockClient(empty), { scopes: ["phishing"], now: NOW });
  const emptyItem = findingFor(assessKnowbe4PhishingProgram(emptySnapshot, { now: NOW }), 20);
  assert.equal(emptyItem.status, "fail");
  assert.equal(emptyItem.evidence.security_tests_all_time, 0);
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

test("assessKnowbe4TrainingProgram warns on modules with no publish date instead of treating them as fresh", async () => {
  const fixture = healthyFixture();
  fixture.trainingCampaigns[0].content.push({ store_purchase_id: 3, content_type: "Store Purchase", name: "Undated Module", publish_date: null, retired: false });
  const snapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW });
  const item = findingFor(assessKnowbe4TrainingProgram(snapshot, { now: NOW }), 11);

  assert.equal(item.status, "warn");
  assert.match(item.summary, /1 have no publish date/);
  assert.match(item.summary, /currency cannot be verified/);
  assert.equal(item.evidence.modules_reviewed, 4);
  assert.equal(item.evidence.modules_with_publish_date, 3);
  assert.equal(item.evidence.undated_module_count, 1);
  assert.deepEqual(item.evidence.undated_modules, [{ campaign: "2026 Annual Security Awareness", module: "Undated Module" }]);
  assert.deepEqual(item.evidence.stale_modules, []);
  assert.deepEqual(item.evidence.retired_modules, []);

  // The store catalog's publish date is consulted before a module is declared undated.
  const catalogued = healthyFixture();
  catalogued.trainingCampaigns[0].content.push({ store_purchase_id: 3, content_type: "Store Purchase", name: "Catalogued Module", publish_date: null, retired: false });
  catalogued.storePurchases.push({ store_purchase_id: 3, content_type: "Store Purchase", name: "Catalogued Module", description: "", type: "Training Module", duration: 10, retired: false, retirement_date: null, publish_date: daysAgo(100), publisher: "KnowBe4", purchase_date: daysAgo(90), policy_url: null });
  const cataloguedSnapshot = await collectKnowbe4Snapshot(mockClient(catalogued), { scopes: ["training"], now: NOW });
  const cataloguedItem = findingFor(assessKnowbe4TrainingProgram(cataloguedSnapshot, { now: NOW }), 11);
  assert.equal(cataloguedItem.status, "pass");
  assert.equal(cataloguedItem.evidence.undated_module_count, 0);
  assert.equal(cataloguedItem.evidence.modules_with_publish_date, 4);
});

test("assessKnowbe4TrainingProgram fails required compliance topics that are assigned but have no enrollments", async () => {
  const fixture = healthyFixture();
  fixture.enrollments = fixture.enrollments.filter((item) => item.module_name !== "PCI DSS Compliance Basics");
  const snapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW });

  const required = findingFor(assessKnowbe4TrainingProgram(snapshot, { now: NOW, requiredComplianceTopics: ["PCI"] }), 17);
  assert.equal(required.status, "fail");
  assert.match(required.summary, /zero training enrollments/);
  assert.deepEqual(required.evidence.topics_without_enrollments, ["PCI"]);
  assert.deepEqual(required.evidence.topics[0].assigned_modules, ["PCI DSS Compliance Basics"]);
  assert.equal(required.evidence.topics[0].enrollments, 0);
  assert.equal(required.evidence.topics[0].completion_pct, null);
  assert.equal(required.evidence.enrollments_available, true);
  assert.equal(required.evidence.enrollment_limit_reached, false);

  // Auto-detected compliance content with no enrollments warns rather than passing.
  const detected = findingFor(assessKnowbe4TrainingProgram(snapshot, { now: NOW }), 17);
  assert.equal(detected.status, "warn");
  assert.match(detected.summary, /zero training enrollments/);

  // When the enrollment list was truncated, zero enrollments is inconclusive and degrades to warn instead of fail.
  const truncatedSnapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW, enrollmentLimit: 4 });
  assert.equal(truncatedSnapshot.enrollmentLimit, 4);
  assert.equal(truncatedSnapshot.enrollmentLimitReached, true);
  const truncated = findingFor(assessKnowbe4TrainingProgram(truncatedSnapshot, { now: NOW, requiredComplianceTopics: ["PCI"] }), 17);
  assert.equal(truncated.status, "warn");
  assert.match(truncated.summary, /truncated at enrollment_limit/);
  assert.equal(truncated.evidence.enrollment_limit_reached, true);

  // Unreadable enrollments are also inconclusive rather than a fail.
  const unreadableClient = mockClient(fixture, { failures: { listTrainingEnrollments: "KnowBe4 request failed (500 Internal Server Error) for /v1/training/enrollments" } });
  const unreadableSnapshot = await collectKnowbe4Snapshot(unreadableClient, { scopes: ["training"], now: NOW });
  const unreadable = findingFor(assessKnowbe4TrainingProgram(unreadableSnapshot, { now: NOW, requiredComplianceTopics: ["PCI"] }), 17);
  assert.equal(unreadable.status, "warn");
  assert.match(unreadable.summary, /enrollment data is unavailable/);
  assert.equal(unreadable.evidence.enrollments_available, false);
});

test("assessKnowbe4TrainingProgram degrades remedial training to warn when tests in the window were not sampled", async () => {
  const fixture = healthyFixture();
  // Two of the three tests in the window are sampled; the failure and its remediation sit in the second test.
  const snapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW, securityTestSampleLimit: 2 });
  const item = findingFor(assessKnowbe4TrainingProgram(snapshot, { now: NOW }), 10);

  assert.equal(item.status, "warn");
  assert.match(item.summary, /1 of 3 tests in the window were not sampled/);
  assert.equal(item.evidence.security_tests_in_window, 3);
  assert.deepEqual(item.evidence.sampled_security_tests, ["900", "901"]);
  assert.equal(item.evidence.unsampled_security_tests, 1);
  assert.equal(item.evidence.remediated_users, 1);
  assert.equal(item.evidence.remediated_pct, 100);

  // With only the newest test sampled there are no observed failures, which still cannot pass on a partial sample, and
  // the window-wide failure count is unknown rather than 0 because two tests were never read.
  const thinSnapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW, securityTestSampleLimit: 1 });
  const thin = findingFor(assessKnowbe4TrainingProgram(thinSnapshot, { now: NOW }), 10);
  assert.equal(thin.status, "warn");
  assert.equal(thin.evidence.failed_users_in_window, null);
  assert.equal(thin.evidence.failed_users_in_sampled_tests, 0);
  assert.equal(thin.evidence.recipient_reads_complete, false);
  assert.equal(thin.evidence.violation_observed, null);
  assert.equal(thin.evidence.unsampled_security_tests, 2);
  assert.match(thin.summary, /2 additional tests in the window were not sampled/);

  // A fully sampled window keeps passing and says so.
  const fullSnapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW });
  const full = findingFor(assessKnowbe4TrainingProgram(fullSnapshot, { now: NOW }), 10);
  assert.equal(full.status, "pass");
  assert.equal(full.evidence.unsampled_security_tests, 0);
  assert.equal(full.evidence.sampled_security_tests.length, 3);
});

test("assessKnowbe4TrainingProgram treats a -1 completion sentinel with truncated enrollments as unmeasurable", async () => {
  const fixture = healthyFixture();
  // The documented "too large to calculate" sentinel forces the enrollment fallback; the first three enrollments passed and the next three never started.
  fixture.trainingCampaigns[0].completion_percentage = -1;
  fixture.enrollments = [
    ...fixture.users.slice(0, 3).map((record, index) => enrollment(index + 1, record, 700, "Security Awareness Fundamentals", daysAgo(199))),
    ...fixture.users.slice(3, 6).map((record, index) => enrollment(index + 4, record, 700, "Security Awareness Fundamentals", daysAgo(199), { status: "Not Started", start_date: null, completion_date: null })),
  ];

  const truncatedSnapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW, enrollmentLimit: 3 });
  assert.equal(truncatedSnapshot.enrollmentLimitReached, true);
  const truncated = findingFor(assessKnowbe4TrainingProgram(truncatedSnapshot, { now: NOW }), 3);
  assert.equal(truncated.status, "warn");
  assert.match(truncated.summary, /-1 completion sentinel/);
  assert.match(truncated.summary, /truncated at enrollment_limit \(3\)/);
  assert.equal(truncated.evidence.enrollment_limit_reached, true);
  assert.deepEqual(truncated.evidence.campaigns_evaluated, []);
  assert.equal(truncated.evidence.campaigns_with_truncated_enrollments.length, 1);
  assert.equal(truncated.evidence.campaigns_with_truncated_enrollments[0].name, "2026 Annual Security Awareness");
  assert.equal(truncated.evidence.campaigns_with_truncated_enrollments[0].partial_completion_pct, 100);
  assert.equal(truncated.evidence.campaigns_with_truncated_enrollments[0].enrollments_loaded, 3);

  // The full enrollment list measures the same campaign at 50% and fails it.
  const fullSnapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW });
  const full = findingFor(assessKnowbe4TrainingProgram(fullSnapshot, { now: NOW }), 3);
  assert.equal(full.status, "fail");
  assert.equal(full.evidence.enrollment_limit_reached, false);
  assert.deepEqual(full.evidence.campaigns_with_truncated_enrollments, []);
  assert.equal(full.evidence.campaigns_evaluated[0].completion_pct, 50);
  assert.equal(full.evidence.campaigns_evaluated[0].source, "enrollments");

  // A reported completion_percentage is still trusted when the enrollment list is truncated.
  fixture.trainingCampaigns[0].completion_percentage = 96;
  const reportedSnapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW, enrollmentLimit: 3 });
  const reported = findingFor(assessKnowbe4TrainingProgram(reportedSnapshot, { now: NOW }), 3);
  assert.equal(reported.status, "pass");
  assert.equal(reported.evidence.campaigns_evaluated[0].source, "completion_percentage");
  assert.deepEqual(reported.evidence.campaigns_with_truncated_enrollments, []);
});

test("assessKnowbe4TrainingProgram never passes compliance completion computed over a truncated enrollment list", async () => {
  const fixture = healthyFixture();
  // The first three PCI enrollments passed and the next three never started, so a cap of three sees 100% while the full list is 50%.
  fixture.enrollments = [
    ...fixture.users.slice(0, 3).map((record, index) => enrollment(index + 1, record, 700, "PCI DSS Compliance Basics", daysAgo(198), { store_purchase_id: 2 })),
    ...fixture.users.slice(3, 6).map((record, index) => enrollment(index + 4, record, 700, "PCI DSS Compliance Basics", daysAgo(198), { store_purchase_id: 2, status: "Not Started", start_date: null, completion_date: null })),
    ...fixture.users.slice(0, 8).map((record, index) => enrollment(index + 7, record, 700, "Security Awareness Fundamentals", daysAgo(199))),
  ];

  const truncatedSnapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW, enrollmentLimit: 3 });
  const truncated = findingFor(assessKnowbe4TrainingProgram(truncatedSnapshot, { now: NOW, requiredComplianceTopics: ["PCI"] }), 17);
  assert.equal(truncated.status, "warn");
  assert.match(truncated.summary, /truncated at enrollment_limit \(3\)/);
  assert.match(truncated.summary, /cannot be verified/);
  // Population figures are unknown over a truncated list; only the "_loaded" figures describe the records read.
  assert.equal(truncated.evidence.topics[0].enrollments, null);
  assert.equal(truncated.evidence.topics[0].completion_pct, null);
  assert.equal(truncated.evidence.topics[0].enrollments_loaded, 3);
  assert.equal(truncated.evidence.topics[0].completion_pct_loaded, 100);
  assert.equal(truncated.evidence.enrollment_limit_reached, true);
  assert.equal(truncated.evidence.completion_data_partial, true);
  assert.equal(truncated.evidence.topics_without_enrollments, null);
  assert.deepEqual(truncated.evidence.topics_without_loaded_enrollments, []);

  // Without the cap the same topic is measured at 50% and warns on low completion instead.
  const fullSnapshot = await collectKnowbe4Snapshot(mockClient(fixture), { scopes: ["training"], now: NOW });
  const full = findingFor(assessKnowbe4TrainingProgram(fullSnapshot, { now: NOW, requiredComplianceTopics: ["PCI"] }), 17);
  assert.equal(full.status, "warn");
  assert.match(full.summary, /below 90%/);
  assert.equal(full.evidence.topics[0].completion_pct, 50);
  assert.equal(full.evidence.topics[0].enrollments, 6);
  assert.deepEqual(full.evidence.topics_without_enrollments, []);
  assert.equal(full.evidence.completion_data_partial, false);

  // The auto-detect path is guarded the same way.
  const detected = findingFor(assessKnowbe4TrainingProgram(truncatedSnapshot, { now: NOW }), 17);
  assert.equal(detected.status, "warn");
  assert.equal(detected.evidence.completion_data_partial, true);
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

test("user-set controls warn instead of passing when the Reporting API returns no active users", async () => {
  // Anonymized accounts cannot retrieve user data, so /v1/users returns [] without an error.
  const fixture = healthyFixture();
  fixture.users = [];
  const snapshot = await collectKnowbe4Snapshot(mockClient(fixture), { now: NOW });
  assert.equal(snapshot.activeUsers.error, undefined);
  assert.equal(snapshot.activeUsers.data.length, 0);
  assert.equal(snapshot.userLimitReached, false);

  const phishing = assessKnowbe4PhishingProgram(snapshot, { now: NOW });
  const training = assessKnowbe4TrainingProgram(snapshot, { now: NOW });
  const risk = assessKnowbe4UserRisk(snapshot, { now: NOW });

  const timeliness = findingFor(training, 4);
  assert.equal(timeliness.status, "warn");
  assert.match(timeliness.summary, /returned no active users/);
  assert.match(timeliness.summary, /Anonymized KnowBe4 accounts cannot retrieve user data/);
  assert.equal(timeliness.evidence.user_list_empty, true);
  assert.equal(timeliness.evidence.new_users_evaluated, 0);

  const inactive = findingFor(risk, 18);
  assert.equal(inactive.status, "warn");
  assert.match(inactive.summary, /returned no active users/);
  assert.equal(inactive.evidence.user_list_empty, true);
  assert.equal(inactive.evidence.users_evaluated, 0);

  const coverage = findingFor(phishing, 2);
  assert.equal(coverage.status, "warn");
  assert.equal(coverage.evidence.user_list_empty, true);
  assert.equal(coverage.evidence.security_tests_in_window, 3);

  assert.equal(findingFor(risk, 5).status, "warn");
  for (const [result, control] of [[phishing, 2], [training, 4], [risk, 5], [risk, 18]]) {
    assert.notEqual(findingFor(result, control).status, "pass", `control ${control} must not pass on zero users`);
    assert.equal(findingFor(result, control).evidence.active_users, 0);
  }

  // An unreadable user list still reports the collection error rather than the empty-list guard.
  const unreadable = await collectKnowbe4Snapshot(mockClient(fixture, { failures: { listUsers: "KnowBe4 request failed (403 Forbidden) for /v1/users" } }), { now: NOW });
  const unreadableTimeliness = findingFor(assessKnowbe4TrainingProgram(unreadable, { now: NOW }), 4);
  assert.equal(unreadableTimeliness.status, "manual");
  assert.match(unreadableTimeliness.summary, /Unreadable inventory: users \(GET \/v1\/users\?status=active: .*403 Forbidden/);
  assert.equal(unreadableTimeliness.evidence.user_list_empty, undefined);
});

test("collectKnowbe4Snapshot flags user_limit truncation and user-set controls degrade to warn", async () => {
  const fixture = healthyFixture();
  const full = await collectKnowbe4Snapshot(mockClient(fixture), { now: NOW });
  assert.equal(full.userLimit, 5000);
  assert.equal(full.userLimitReached, false);
  assert.equal(full.enrollmentLimit, 20000);
  assert.equal(full.enrollmentLimitReached, false);
  assert.equal(findingFor(assessKnowbe4PhishingProgram(full, { now: NOW }), 2).evidence.user_limit_reached, false);

  const snapshot = await collectKnowbe4Snapshot(mockClient(fixture), { now: NOW, userLimit: 5 });
  assert.equal(snapshot.activeUsers.data.length, 5);
  assert.equal(snapshot.userLimit, 5);
  assert.equal(snapshot.userLimitReached, true);

  const phishing = assessKnowbe4PhishingProgram(snapshot, { now: NOW });
  const training = assessKnowbe4TrainingProgram(snapshot, { now: NOW });
  const risk = assessKnowbe4UserRisk(snapshot, { now: NOW });
  for (const [result, control] of [[phishing, 2], [phishing, 9], [training, 4], [risk, 5], [risk, 18]]) {
    const item = findingFor(result, control);
    assert.equal(item.status, "warn", `control ${control} should warn when the user list is truncated`);
    assert.equal(item.evidence.user_limit_reached, true);
    assert.equal(item.evidence.user_limit, 5);
    assert.match(item.summary, /truncated at user_limit \(5\)/);
  }
  assert.equal(phishing.summary.user_limit_reached, true);
  assert.equal(training.summary.user_limit_reached, true);
  assert.equal(risk.summary.user_limit_reached, true);
  // Controls that do not depend on the user list keep their own verdicts.
  assert.equal(findingFor(phishing, 1).status, "pass");
  assert.equal(findingFor(phishing, 20).status, "pass");
  assert.equal(findingFor(risk, 8).status, "pass");
  // Coverage over a capped user list is unknown; only the figures over the users actually read render.
  const coverage = findingFor(phishing, 2);
  assert.equal(coverage.evidence.coverage_pct, null);
  assert.equal(coverage.evidence.active_users, null);
  assert.equal(coverage.evidence.tested_users, null);
  assert.equal(coverage.evidence.users_read, 5);
  assert.equal(coverage.evidence.tested_users_in_read_samples, 5);
  assert.equal(coverage.evidence.untested_user_sample, null);
  assert.match(coverage.summary, /5 of the 5 active users read appear in the 3 sampled security tests, so coverage over the full population is unknown\. Truncated listing: users \(5 of unknown loaded, truncated at user_limit \(5\)\)/);
  assert.equal(findingFor(risk, 18).evidence.inactive_users, null);
  assert.equal(findingFor(risk, 18).evidence.inactive_user_sample, null);
  assert.equal(findingFor(risk, 5).evidence.users_scored, null);
  assert.equal(findingFor(risk, 5).evidence.users_scored_read, 5);
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

});

test("assessKnowbe4AccountGovernance renders scoped-out USB and vishing controls as manual, never pass", async () => {
  const client = mockClient(healthyFixture());
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["governance"], now: NOW });
  const relaxed = assessKnowbe4AccountGovernance(snapshot, { now: NOW, requireUsbTests: false, requireVishingTests: false });

  for (const control of [15, 16]) {
    const item = findingFor(relaxed, control);
    assert.equal(item.status, "manual", `control ${control} should be manual when scoped out`);
    assert.match(item.summary, /scoped out by configuration/);
    assert.match(item.summary, /not satisfied by the API/);
    assert.match(item.manualEvidence, /risk-acceptance record/);
    assert.equal(item.evidence.scoped_out_by_configuration, true);
  }
  assert.equal(findingFor(relaxed, 15).evidence.require_usb_tests, false);
  assert.equal(findingFor(relaxed, 16).evidence.require_vishing_tests, false);
  assert.deepEqual(relaxed.summary.manual_controls, ["KNOWBE4-13", "KNOWBE4-14", "KNOWBE4-15", "KNOWBE4-16"]);
  assert.ok(!relaxed.findings.some((item) => item.control === 15 && item.status === "pass"));
  assert.ok(!relaxed.findings.some((item) => item.control === 16 && item.status === "pass"));
  assert.deepEqual(new Set(relaxed.findings.map((item) => item.status)), new Set(["pass", "manual"]));
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
    "core_data/collection_status.json",
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
  assert.equal(findings.find((item) => item.control === 4).status, "manual", "enrollment timeliness cannot be judged without enrollments");
  assert.equal(findings.find((item) => item.control === 3).status, "warn", "reported completion still judges the campaigns; the missing enrollment fallback demotes");
  assert.ok(!JSON.stringify(findings).includes("@acme.example"));
  const status = JSON.parse(readFileSync(join(result.outputDir, "core_data", "collection_status.json"), "utf8"));
  const enrollmentRow = status.inventories.find((row) => row.inventory === "training_enrollments");
  assert.equal(enrollmentRow.readable, false);
  assert.match(enrollmentRow.error, /500/);
  // Nothing about the failed read defaults: completeness, truncation, and counts are unknown, not false or 0.
  assert.deepEqual(
    { collected: enrollmentRow.collected, complete: enrollmentRow.complete, truncated: enrollmentRow.truncated, seen: enrollmentRow.seen, total: enrollmentRow.total },
    { collected: false, complete: null, truncated: null, seen: null, total: null },
  );
  const usersRow = status.inventories.find((row) => row.inventory === "users");
  assert.equal(usersRow.readable, true);
  assert.equal(usersRow.truncated, false);
  assert.equal(usersRow.seen, 10);
  assert.equal(status.totals.not_readable, 2);
  assert.equal(status.totals.not_requested, 1, "PhishER was not configured, so its inventory was never requested");
  assert.equal(status.totals.truncation_unknown, 3, "denied and never-requested inventories are neither complete nor truncated");

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

function forbidden(path) {
  return `KnowBe4 request failed (403 Forbidden) for ${path}`;
}

// Every KnowBe4 finding whose verdict reads two or more collected inventories, with each secondary inventory forbidden
// in turn while the primary stays healthy. `status` is the verdict the finding must report and `names` the summary
// text that must name the unreadable inventory. Controls 1, 12, 16, and 20 read a single inventory; 13, 14, and 15
// are always manual.
const KNOWBE4_MULTI_INVENTORY_CASES = [
  { control: 2, area: "phishing", secondary: "users", failure: "listUsers", path: "/v1/users", status: "manual", names: /Unreadable inventory: users \(GET \/v1\/users\?status=active: KnowBe4 request failed \(403 Forbidden\)/ },
  { control: 2, area: "phishing", secondary: "security_test_recipients", failure: "listSecurityTestRecipients", path: "/v1/phishing/security_tests/900/recipients", status: "warn", names: /recipient results could not be read.*Unreadable inventory: security_test_recipients \(GET \/v1\/phishing\/security_tests\/900\/recipients, GET \/v1\/phishing\/security_tests\/901\/recipients, [^)]*: security_test_recipients\[900\]: KnowBe4 request failed \(403 Forbidden\)/ },
  { control: 6, area: "phishing", secondary: "users", failure: "listUsers", path: "/v1/users", status: "warn", names: /within the 15% ceiling.*Unreadable inventory: users \(GET \/v1\/users\?status=active: .*403 Forbidden.*\), so the per-user phish-prone average was not computed/ },
  { control: 6, area: "phishing", secondary: "account", failure: "getAccount", path: "/v1/account", status: "warn", names: /Unreadable inventory: account \(GET \/v1\/account: .*403 Forbidden.*\), so the account risk score was not attached/ },
  { control: 7, area: "phishing", secondary: "account_risk_score_history", failure: "getAccountRiskScoreHistory", path: "/v1/account/risk_score_history", status: "warn", names: /stable or improving.*Unreadable inventory: account_risk_score_history \(GET \/v1\/account\/risk_score_history\?full=true: .*403 Forbidden/ },
  { control: 9, area: "phishing", secondary: "security_tests", failure: "listSecurityTests", path: "/v1/phishing/security_tests", status: "warn", names: /target All Users.*Unreadable inventory: security_tests \(GET \/v1\/phishing\/security_tests: .*403 Forbidden.*\), so campaigns were classed as active from their status and last run alone/ },
  { control: 9, area: "phishing", secondary: "users", failure: "listUsers", path: "/v1/users", status: "warn", names: /Unreadable inventory: users \(GET \/v1\/users\?status=active: .*403 Forbidden.*\), so the active user count behind the coverage estimate was not available/ },
  { control: 9, area: "phishing", secondary: "groups", failure: "listGroups", path: "/v1/groups", status: "warn", names: /Unreadable inventory: groups \(GET \/v1\/groups\?status=active: .*403 Forbidden.*\), so group member counts behind the coverage estimate were not available/ },
  { control: 19, area: "phishing", phisher: true, secondary: "phisher_messages", failure: "listPhisherMessages", path: "PhishER GraphQL", status: "warn", names: /reported with the Phish Alert Button.*Unreadable inventory: phisher_messages \(PhishER GraphQL phisherMessages: .*403 Forbidden.*\), so PhishER inbox categories and reporter counts were not cross-checked/ },
  { control: 3, area: "training", secondary: "training_enrollments", failure: "listTrainingEnrollments", path: "/v1/training/enrollments", status: "warn", names: /met the 90% completion target.*Unreadable inventory: training_enrollments \(GET \/v1\/training\/enrollments: .*403 Forbidden.*\), so campaigns reporting the -1 completion sentinel could not be measured/ },
  { control: 4, area: "training", secondary: "training_enrollments", failure: "listTrainingEnrollments", path: "/v1/training/enrollments", status: "manual", names: /^Unreadable inventory: training_enrollments \(GET \/v1\/training\/enrollments: .*403 Forbidden.*\), so training enrollment timeliness could not be evaluated from the API\. Collect manually: the training enrollment report/ },
  { control: 4, area: "training", secondary: "users", failure: "listUsers", path: "/v1/users", status: "manual", names: /^Unreadable inventory: users \(GET \/v1\/users\?status=active: .*403 Forbidden/ },
  { control: 10, area: "training", secondary: "training_enrollments", failure: "listTrainingEnrollments", path: "/v1/training/enrollments", status: "manual", names: /^Unreadable inventory: training_enrollments \(GET \/v1\/training\/enrollments: .*403 Forbidden/ },
  { control: 10, area: "training", secondary: "security_test_recipients", failure: "listSecurityTestRecipients", path: "/v1/phishing/security_tests/900/recipients", status: "warn", names: /had recipient results available.*Unreadable inventory: security_test_recipients \(GET \/v1\/phishing\/security_tests\/900\/recipients, GET \/v1\/phishing\/security_tests\/901\/recipients, [^)]*: .*403 Forbidden/ },
  { control: 10, area: "training", secondary: "training_campaigns", failure: "listTrainingCampaigns", path: "/v1/training/campaigns", status: "warn", names: /were enrolled in training after the failure.*Unreadable inventory: training_campaigns \(GET \/v1\/training\/campaigns: .*403 Forbidden.*\), so auto-enroll remedial campaigns were not listed/ },
  { control: 11, area: "training", secondary: "store_purchases", failure: "listStorePurchases", path: "/v1/training/store_purchases", status: "warn", names: /none are marked retired in the campaign content; the ModStore catalog was not read.*Unreadable inventory: store_purchases \(GET \/v1\/training\/store_purchases: .*403 Forbidden.*\), so assigned modules were not cross-checked against the ModStore catalog/ },
  { control: 17, area: "training", secondary: "training_enrollments", failure: "listTrainingEnrollments", path: "/v1/training/enrollments", status: "warn", names: /enrollment data is unavailable.*Unreadable inventory: training_enrollments \(GET \/v1\/training\/enrollments: .*403 Forbidden/ },
  { control: 17, area: "training", secondary: "training_policies", failure: "listTrainingPolicies", path: "/v1/training/policies", status: "warn", names: /completion at or above 90%.*Unreadable inventory: training_policies \(GET \/v1\/training\/policies: .*403 Forbidden.*\), so uploaded policy documents were not counted/ },
  { control: 5, area: "risk", secondary: "account", failure: "getAccount", path: "/v1/account", status: "warn", names: /mean user risk score is 25\.5.*Unreadable inventory: account \(GET \/v1\/account: .*403 Forbidden.*\), so the organization risk score was not attached/ },
  { control: 5, area: "risk", secondary: "account_risk_score_history", failure: "getAccountRiskScoreHistory", path: "/v1/account/risk_score_history", status: "warn", names: /Unreadable inventory: account_risk_score_history \(GET \/v1\/account\/risk_score_history\?full=true: .*403 Forbidden.*\), so the organization risk score trend was not attached/ },
  { control: 8, area: "risk", secondary: "phishing_campaigns", failure: "listPhishingCampaigns", path: "/v1/phishing/campaigns", status: "manual", names: /^Unreadable inventory: phishing_campaigns \(GET \/v1\/phishing\/campaigns: .*403 Forbidden.*\), so group coverage analysis could not be evaluated from the API\. Collect manually: the phishing campaign list/ },
  { control: 8, area: "risk", secondary: "training_campaigns", failure: "listTrainingCampaigns", path: "/v1/training/campaigns", status: "manual", names: /^Unreadable inventory: training_campaigns \(GET \/v1\/training\/campaigns: .*403 Forbidden/ },
  { control: 18, area: "risk", secondary: "security_tests", failure: "listSecurityTests", path: "/v1/phishing/security_tests", status: "warn", names: /show phishing, training, or sign-in activity.*Unreadable inventory: security_tests \(GET \/v1\/phishing\/security_tests: .*403 Forbidden.*\), so phishing participation could not be used as an activity signal/ },
  { control: 18, area: "risk", secondary: "security_test_recipients", failure: "listSecurityTestRecipients", path: "/v1/phishing/security_tests/900/recipients", status: "warn", names: /Unreadable inventory: security_test_recipients \(GET \/v1\/phishing\/security_tests\/900\/recipients, GET \/v1\/phishing\/security_tests\/901\/recipients, [^)]*: .*403 Forbidden.*\), so deliveries in the security tests whose recipient results did not load were not counted as activity/ },
  { control: 18, area: "risk", secondary: "training_enrollments", failure: "listTrainingEnrollments", path: "/v1/training/enrollments", status: "warn", names: /Unreadable inventory: training_enrollments \(GET \/v1\/training\/enrollments: .*403 Forbidden.*\), so training activity could not be used as an activity signal/ },
];

const ASSESS_BY_AREA = {
  phishing: assessKnowbe4PhishingProgram,
  training: assessKnowbe4TrainingProgram,
  risk: assessKnowbe4UserRisk,
};

test("verdict rule 1 corollary: KnowBe4 findings that read several inventories never pass while a secondary inventory is forbidden", async () => {
  const baselines = new Map();
  for (const item of KNOWBE4_MULTI_INVENTORY_CASES) {
    const assess = ASSESS_BY_AREA[item.area];
    const baselineKey = `${item.area}:${Boolean(item.phisher)}`;
    if (!baselines.has(baselineKey)) {
      const healthy = await collectKnowbe4Snapshot(mockClient(healthyFixture(), { phisher: Boolean(item.phisher) }), { scopes: [item.area], now: NOW });
      baselines.set(baselineKey, assess(healthy, { now: NOW }));
    }
    assert.equal(findingFor(baselines.get(baselineKey), item.control).status, "pass", `control ${item.control} baseline on the healthy fixture`);

    const label = `control ${item.control} with ${item.secondary} forbidden`;
    const client = mockClient(healthyFixture(), { phisher: Boolean(item.phisher), failures: { [item.failure]: forbidden(item.path) } });
    const snapshot = await collectKnowbe4Snapshot(client, { scopes: [item.area], now: NOW });
    assert.ok(snapshot.errors.length > 0 && snapshot.errors.every((error) => error.startsWith(item.secondary)), `${label}: only the secondary inventory failed (${snapshot.errors.join(" | ")})`);

    const found = findingFor(assess(snapshot, { now: NOW }), item.control);
    assert.notEqual(found.status, "pass", `${label} must not pass`);
    assert.equal(found.status, item.status, `${label} status`);
    assert.match(found.summary, item.names, `${label} must name the unreadable inventory`);
    assert.match(found.summary, /403 Forbidden/, `${label} must carry the HTTP error`);
    assert.match(found.summary, /Collect manually: /, `${label} must tell the human what to collect`);
    const gaps = found.evidence.unreadable_inventories;
    assert.ok(Array.isArray(gaps) && gaps.some((gap) => gap.inventory === item.secondary), `${label} evidence lists the gap`);
    assert.ok(gaps.every((gap) => gap.endpoint && gap.error && gap.not_checked && gap.collect_manually), `${label} gap entries are complete`);
    if (item.status === "manual") {
      assert.match(found.manualEvidence ?? "", /^Collect the /, `${label} names the console evidence to collect`);
    }
  }
});

test("verdict rule 1 corollary: KnowBe4 findings keep judging the readable inventories and still fail on them", async () => {
  // Control 9 with partial-targeting campaigns cannot estimate coverage without users, so it is manual rather than a false fail.
  const partial = failingFixture();
  const noUsers = await collectKnowbe4Snapshot(mockClient(partial, { failures: { listUsers: forbidden("/v1/users") } }), { scopes: ["phishing"], now: NOW });
  const targeting = findingFor(assessKnowbe4PhishingProgram(noUsers, { now: NOW }), 9);
  assert.equal(targeting.status, "manual");
  assert.match(targeting.summary, /^Unreadable inventory: users/);
  const noGroups = await collectKnowbe4Snapshot(mockClient(partial, { failures: { listGroups: forbidden("/v1/groups") } }), { scopes: ["phishing"], now: NOW });
  assert.equal(findingFor(assessKnowbe4PhishingProgram(noGroups, { now: NOW }), 9).status, "manual");

  // A failing verdict on readable data stands, with the gap appended rather than masking it.
  const failing = await collectKnowbe4Snapshot(mockClient(failingFixture(), { failures: { listStorePurchases: forbidden("/v1/training/store_purchases") } }), { scopes: ["training"], now: NOW });
  const currency = findingFor(assessKnowbe4TrainingProgram(failing, { now: NOW }), 11);
  assert.equal(currency.status, "fail", "the retired module on the campaign itself still fails");
  assert.match(currency.summary, /retired by the publisher.*Unreadable inventory: store_purchases/);

  // Controls that never read the failed inventory keep their verdicts.
  const noHistory = await collectKnowbe4Snapshot(mockClient(healthyFixture(), { failures: { getAccountRiskScoreHistory: forbidden("/v1/account/risk_score_history") } }), { scopes: ["risk"], now: NOW });
  const risk = assessKnowbe4UserRisk(noHistory, { now: NOW });
  assert.equal(findingFor(risk, 5).status, "warn");
  assert.equal(findingFor(risk, 8).status, "pass", "group coverage does not read the risk history");
  assert.equal(findingFor(risk, 18).status, "pass", "inactive users do not read the risk history");
});

test("verdict rule 10: Knowbe4ApiClient reports Reporting API listings truncated when the cap stops a still-full page", async () => {
  const pageOf = (page, size) => Array.from({ length: size }, (_, index) => ({ id: (page - 1) * size + index + 1 }));
  const fullPages = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    return jsonResponse(pageOf(Number(url.searchParams.get("page")), Number(url.searchParams.get("per_page"))));
  };
  const client = new Knowbe4ApiClient(sampleConfig(), { fetchImpl: fullPages, minRequestIntervalMs: 0 });

  const atCap = await client.list("/v1/users", {}, { limit: 4, pageSize: 2 });
  assert.deepEqual(atCap.items.map((item) => item.id), [1, 2, 3, 4]);
  assert.equal(atCap.truncated, true, "the cap was reached while the last page was still full");
  assert.equal(atCap.pages, 2);
  assert.equal(client.getRequestCount(), 2, "the loop stops at the cap instead of fetching a page it would drop");

  const overfull = await client.list("/v1/users", {}, { limit: 3, pageSize: 2 });
  assert.deepEqual(overfull.items.map((item) => item.id), [1, 2, 3]);
  assert.equal(overfull.truncated, true, "records dropped from the final page mark the listing truncated");

  const exact = new Knowbe4ApiClient(sampleConfig(), {
    fetchImpl: async (input) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      return jsonResponse(url.searchParams.get("page") === "1" ? pageOf(1, 2) : []);
    },
    minRequestIntervalMs: 0,
  });
  const complete = await exact.list("/v1/groups", {}, { limit: 10, pageSize: 2 });
  assert.deepEqual(complete.items.map((item) => item.id), [1, 2]);
  assert.equal(complete.truncated, false, "an empty page after a full page means the listing is complete");
  assert.equal(complete.pages, 2);

  const listing = await client.listUsers({ limit: 4 });
  assert.equal(listing.limit, 4);
  assert.equal(listing.truncated, true);
});

test("verdict rule 10: Knowbe4ApiClient reports PhishER connections truncated on caps, stuck page keys, and unreached totals", async () => {
  const phisherClient = (respond, field = "phisherMessages") => new Knowbe4ApiClient(sampleConfig({ phisherApiToken: "phisher-token" }), {
    fetchImpl: async (_input, init = {}) => jsonResponse({ data: { [field]: respond(JSON.parse(init.body).variables) } }),
    minRequestIntervalMs: 0,
  });

  const capped = phisherClient(({ page }) => ({
    nodes: [{ id: `m${page}a` }, { id: `m${page}b` }],
    pagination: { page, pages: 3, per: 2, totalCount: 5, nextPageKey: `key-${page + 1}` },
  }));
  const atCap = await capped.listPhisherMessages({ query: "reported_at:[2026-06-23 TO *]", limit: 2 });
  assert.deepEqual(atCap.items.map((item) => item.id), ["m1a", "m1b"]);
  assert.equal(atCap.truncated, true);
  assert.equal(atCap.total, 5, "the server total is kept so the summary can say seen versus total");
  assert.equal(capped.getRequestCount(), 1);

  const stuck = phisherClient(({ page }) => ({
    nodes: [{ id: `m${page}` }],
    pagination: { page, per: 1, nextPageKey: "same-key" },
  }));
  const stuckListing = await stuck.listPhisherMessages({ limit: 10 });
  assert.deepEqual(stuckListing.items.map((item) => item.id), ["m1", "m2"]);
  assert.equal(stuckListing.truncated, true, "a nextPageKey that never advances ends the loop as truncated");
  assert.equal(stuck.getRequestCount(), 2);

  const shortfall = phisherClient(() => ({ nodes: [], pagination: { page: 1, pages: 1, per: 200, totalCount: 7, nextPageKey: null } }));
  const empty = await shortfall.listPhisherMessages({ limit: 10 });
  assert.equal(empty.items.length, 0);
  assert.equal(empty.total, 7);
  assert.equal(empty.truncated, true, "an empty page while totalCount says more exist is not a complete read");

  const complete = phisherClient(({ page }) => ({
    nodes: page === 1 ? [{ id: "r1" }, { id: "r2" }] : [{ id: "r3" }],
    pagination: { page, pages: 2, per: 2, totalCount: 3 },
  }), "phisherRules");
  const rules = await complete.listPhisherRules({ limit: 10 });
  assert.deepEqual(rules.items.map((item) => item.id), ["r1", "r2", "r3"]);
  assert.equal(rules.truncated, false);
  assert.equal(rules.total, 3);
});

test("verdict rule 10: truncated KnowBe4 inventories demote the findings that judge them and state seen versus total", async () => {
  const fixture = healthyFixture();
  const client = mockClient(fixture, { phisher: true });
  client.listSecurityTests = async (listOptions = {}) => {
    if (listOptions.campaignType === "callback") return fixture.callbackTests;
    return { items: fixture.securityTests, truncated: true, limit: 20000, pages: 40 };
  };
  client.listPhisherMessages = async () => ({ items: fixture.phisherMessages, truncated: true, limit: 1000, pages: 5, total: 1500 });
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["phishing"], now: NOW });
  assert.equal(snapshot.securityTests.truncated, true);
  assert.equal(snapshot.phisherMessages.total, 1500);

  const result = assessKnowbe4PhishingProgram(snapshot, { now: NOW });
  for (const control of [1, 2, 6, 7, 9, 20]) {
    const item = findingFor(result, control);
    assert.equal(item.status, "warn", `control ${control} cannot pass on a truncated security test list`);
    assert.match(item.summary, /Truncated listing: security_tests \(12 of unknown loaded, truncated at the collection cap \(20000\)\), so this verdict only covers the records that were loaded\./);
    assert.deepEqual(item.evidence.truncated_inventories.find((entry) => entry.inventory === "security_tests"), { inventory: "security_tests", seen: 12, total: null, limit: 20000, argument: null });
  }
  const reportRate = findingFor(result, 19);
  assert.equal(reportRate.status, "warn");
  assert.match(reportRate.summary, /PhishER inbox: 2 user-reported messages in the window \(2 of 1500 loaded, truncated at phisher_message_limit \(1000\)\)\./);
  assert.equal(reportRate.evidence.phisher.messages_total, 1500);
  assert.equal(reportRate.evidence.phisher.truncated, true);

  const status = knowbe4CollectionStatus(snapshot);
  assert.deepEqual(status.inventories.map((row) => row.inventory), KNOWBE4_INVENTORIES);
  const tests = status.inventories.find((row) => row.inventory === "security_tests");
  assert.equal(tests.truncated, true);
  assert.equal(tests.complete, false);
  assert.equal(tests.seen, 12);
  assert.equal(tests.limit, 20000);
  const phisher = status.inventories.find((row) => row.inventory === "phisher_messages");
  assert.deepEqual({ seen: phisher.seen, total: phisher.total, limit: phisher.limit, limit_argument: phisher.limit_argument }, { seen: 2, total: 1500, limit: 1000, limit_argument: "phisher_message_limit" });
  // The phishing scope never requested enrollments: no endpoint, status, or flag is invented for that inventory.
  const enrollments = status.inventories.find((row) => row.inventory === "training_enrollments");
  assert.deepEqual(
    { status: enrollments.status, collected: enrollments.collected, readable: enrollments.readable, endpoint: enrollments.endpoint, complete: enrollments.complete, truncated: enrollments.truncated, seen: enrollments.seen, limit: enrollments.limit },
    { status: "not_requested", collected: false, readable: null, endpoint: null, complete: null, truncated: null, seen: null, limit: null },
  );
  assert.equal(status.totals.truncated, 2);
  assert.equal(status.totals.not_requested, 5);
  assert.equal(status.totals.truncation_unknown, 5);

  // Only the enrichment inventory truncated: the report rate still stands on the test counters but says what was cut.
  const enrichmentOnly = mockClient(healthyFixture(), { phisher: true });
  enrichmentOnly.listPhisherMessages = async () => ({ items: fixture.phisherMessages, truncated: true, limit: 1000, pages: 5, total: 1500 });
  const enrichment = findingFor(assessKnowbe4PhishingProgram(await collectKnowbe4Snapshot(enrichmentOnly, { scopes: ["phishing"], now: NOW }), { now: NOW }), 19);
  assert.equal(enrichment.status, "pass");
  assert.match(enrichment.summary, /2 of 1500 loaded, truncated at phisher_message_limit \(1000\)/);
  assert.equal(enrichment.evidence.truncated_inventories[0].inventory, "phisher_messages");
});

test("verdict rule 9: Knowbe4ApiClient describes non-JSON error bodies instead of echoing them", async () => {
  const token = "reporting-token";
  const page = `<html><body>Forbidden. Request headers: Authorization: Bearer ${token}</body></html>`;
  const client = new Knowbe4ApiClient(sampleConfig({ apiToken: token }), {
    fetchImpl: async () => new Response(page, { status: 403, statusText: "Forbidden", headers: { "content-type": "text/html; charset=utf-8" } }),
    minRequestIntervalMs: 0,
  });
  await assert.rejects(() => client.getAccount(), (error) => {
    assert.match(error.message, /^KnowBe4 request failed \(403 Forbidden\) GET \/v1\/account: 403 Forbidden: non-JSON body \(text\/html, \d+ bytes, not echoed\)$/);
    assert.ok(!error.message.includes("Bearer"), "the reflected header is not echoed");
    assert.ok(!error.message.includes("<html>"));
    assert.equal(error.status, 403);
    assert.equal(error.endpoint, "GET /v1/account");
    return true;
  });

  const longMessage = "x".repeat(1000);
  const verbose = new Knowbe4ApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ message: longMessage }, { status: 400, statusText: "Bad Request" }),
    minRequestIntervalMs: 0,
  });
  await assert.rejects(() => verbose.getAccount(), (error) => {
    assert.ok(error.message.length < 400, "structured error messages are capped");
    return true;
  });
});

test("verdict rule 9: redactCredentialValues masks credential-shaped keys and reduces URLs while keeping structure", () => {
  const redacted = redactCredentialValues({
    id: 7,
    name: "SIEM export",
    apiKey: "FAKE_CAMEL_1",
    client_secret: "FAKE_SNAKE_2",
    tokens: ["FAKE_PLURAL_3"],
    group_key: "finance",
    policy_url: "https://files.example.com/policies/acme.pdf?X-Amz-Signature=FAKE_SIG_4",
    webhookUrl: "https://hooks.example.com/services/T0/FAKE_PATH_5",
    settings: [{ name: "download_token", value: "FAKE_PAIR_6" }, { name: "retention_days", value: "90" }],
    nested: { authorization: "Bearer FAKE_NESTED_7", enabled: true, count: 3 },
    relative_link: "/download?token=FAKE_QUERY_8",
  });

  assert.equal(redacted.id, 7);
  assert.equal(redacted.name, "SIEM export");
  assert.equal(redacted.apiKey, "[REDACTED]");
  assert.equal(redacted.client_secret, "[REDACTED]");
  assert.equal(redacted.tokens, "[REDACTED]", "a list under a plural credential key is dropped whole");
  assert.equal(redacted.group_key, "finance", "a non-credential key ending in key is kept");
  assert.equal(redacted.policy_url, "https://files.example.com");
  assert.equal(redacted.webhookUrl, "https://hooks.example.com");
  assert.equal(redacted.settings[0].value, "[REDACTED]");
  assert.equal(redacted.settings[1].value, "90");
  assert.equal(redacted.nested.authorization, "[REDACTED]");
  assert.equal(redacted.nested.enabled, true);
  assert.equal(redacted.nested.count, 3);
  assert.equal(redacted.relative_link, "[REDACTED]", "a relative URL carrying a token-shaped query is dropped");

  const projected = projectKnowbe4User({ id: 1, email: "user1@acme.example", comment: "vpn pw FAKE", custom_field_1: "FAKE", custom_date_1: "2026-01-01", joined_on: "2024-01-15" });
  assert.deepEqual(Object.keys(projected), ["id", "email", "joined_on"]);
});

// Credential values planted in collected objects, in order: policy URL signature, user custom field, user comment,
// account shared secret, webhook URL path, recipient user custom field, name/value pair setting, policy password,
// PhishER attachment URL token. Alphanumeric and random-looking so that every 6-to-24-character window can be asserted absent.
const KNOWBE4_FAKE_SECRETS = [
  "X3FbUbhhGiSFX6sHkNrUAhpHF8a6TnB8",
  "QDSPmGmVxtX97SmGyfKAmDW86Uf5CoVK",
  "toTBF45nFScEQMMpSQdrJ7xiAYW6dhSR",
  "jeWBe7qRoxo2ECEUbwRNb99qKecZ7Pzu",
  "nNfBgmJKWaZ5uxWc8bpWgV7XNkUFPbfp",
  "J5tUD9FFHNhjFCYQKUWBAaRpeq3p4Q9T",
  "X7dGVP2XHLR6Na7nD3e8vgwAJUvL34bA",
  "tUYsX4ybRbBMD9qRG6Jsc8nLQRGTEKaB",
  "QVzH3EeJNJyVKuza4iSEnrasY5UxSheU",
];

function secretBearingKnowbe4Fixture() {
  const fixture = healthyFixture();
  fixture.storePurchases[0].policy_url = `https://policies.knowbe4.example/download/acme.pdf?X-Amz-Signature=${KNOWBE4_FAKE_SECRETS[0]}`;
  fixture.users[0].custom_field_1 = KNOWBE4_FAKE_SECRETS[1];
  fixture.users[0].comment = `shared vpn password ${KNOWBE4_FAKE_SECRETS[2]}`;
  fixture.account.integrations = [{ name: "SIEM webhook", webhook_url: `https://hooks.example.com/services/${KNOWBE4_FAKE_SECRETS[4]}`, shared_secret: KNOWBE4_FAKE_SECRETS[3] }];
  const rows = fixture.recipientsByTest.get(String(fixture.securityTests[0].pst_id));
  rows[0] = { ...rows[0], user: { ...rows[0].user, custom_field_2: KNOWBE4_FAKE_SECRETS[5] } };
  fixture.trainingPolicies[0].settings = [{ name: "download_token", value: KNOWBE4_FAKE_SECRETS[6] }, { name: "minimum_time", value: "60" }];
  fixture.trainingPolicies[0].policy_password = KNOWBE4_FAKE_SECRETS[7];
  fixture.phisherMessages[0].attachmentUrl = `https://phisher.knowbe4.example/attachments/1?token=${KNOWBE4_FAKE_SECRETS[8]}`;
  return fixture;
}

test("verdict rule 9: the KnowBe4 bundle and its zip never carry credential-shaped values, token-bearing URLs, or free-form user fields", async () => {
  const base = createTempBase("grclanker-knowbe4-secrets-");
  const tokens = { apiToken: KB_TEST_TOKEN, phisherApiToken: KB_PHISHER_TOKEN };
  // Self-check: the planted values share no 6-character window with each other or with the healthy fixture's own output.
  const baseline = await exportKnowbe4AuditBundle(mockClient(healthyFixture(), { phisher: true, config: tokens }), sampleConfig(tokens), createTempBase("grclanker-knowbe4-secrets-baseline-"), { now: NOW });
  assertCanaryFixture(assert, [...KNOWBE4_FAKE_SECRETS, KB_TEST_TOKEN, KB_PHISHER_TOKEN], readBundleFiles(baseline.outputDir), "collected-object canaries");

  const client = mockClient(secretBearingKnowbe4Fixture(), { phisher: true, config: tokens });
  const result = await exportKnowbe4AuditBundle(client, client.getResolvedConfig(), base, { now: NOW });

  assert.equal(result.findingCount, 20);
  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size >= 30, "the bundle directory was written");
  assert.equal(entries.size, files.size, "the zip archive carries every bundle file");
  const planted = [...KNOWBE4_FAKE_SECRETS, KB_TEST_TOKEN, KB_PHISHER_TOKEN];
  assertCanaryWindowsAbsent(assert, files, planted, "bundle file");
  assertCanaryWindowsAbsent(assert, entries, planted, "zip entry");

  const purchases = JSON.parse(files.get(join("core_data", "store_purchases.json")));
  assert.equal(purchases[0].policy_url, "https://policies.knowbe4.example", "the policy download URL keeps only scheme and host");
  const users = JSON.parse(files.get(join("core_data", "users_active.json")));
  assert.ok(!("custom_field_1" in users[0]) && !("comment" in users[0]), "free-form user fields are dropped at collection time");
  assert.equal(users[0].email, "user1@acme.example", "assessment fields survive without PII redaction enabled");
  const account = JSON.parse(files.get(join("core_data", "account.json")));
  assert.equal(account.integrations[0].shared_secret, "[REDACTED]");
  assert.equal(account.integrations[0].webhook_url, "https://hooks.example.com");
  assert.equal(account.integrations[0].name, "SIEM webhook");
  const recipients = JSON.parse(files.get(join("core_data", "security_test_recipients.json")));
  assert.ok(recipients.every((sample) => sample.recipients.every((row) => !("custom_field_2" in row.user))), "embedded recipient users are projected too");
  const policies = JSON.parse(files.get(join("core_data", "training_policies.json")));
  assert.equal(policies[0].settings[0].value, "[REDACTED]");
  assert.equal(policies[0].settings[1].value, "60");
  assert.equal(policies[0].policy_password, "[REDACTED]");
  const messages = JSON.parse(files.get(join("core_data", "phisher_messages.json")));
  assert.equal(messages[0].attachmentUrl, "https://phisher.knowbe4.example");

  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  assert.equal(findings.find((item) => item.control === 11).status, "pass", "reducing policy_url does not change content currency");
  assert.equal(findings.filter((item) => item.status === "pass").length, 17, "redaction leaves the healthy verdicts intact");
});

// ---------------------------------------------------------------------------------------------------------------
// Addenda 2 to 6: the real client over an HTTP router that records every request the run makes.
// ---------------------------------------------------------------------------------------------------------------

// Every planted credential is alphanumeric and random-looking; helpers/canary-windows.mjs asserts every 6-to-24-character
// window of each one absent, and the fixture self-check below proves no window occurs in the fixture's own values.
const KB_TEST_TOKEN = "tTy4it2NbNVWLjmDrDgg4E5wiQxg7SDp";
const KB_PHISHER_TOKEN = "4WVSdSG5bXWSpcsYrJWDqWoVbkoC6E6v";
const KB_CANARIES = {
  bearer: "4GMSvvHWpGX5UfGVS2GiWLCeUno3jBeN",
  cookie: "ShdPECF3iZ73AsrqRCDSNBJndtHq8LUs",
  apiKey: "CUD9ejYDya5wZQ7QnHUY2WsuhQQM8F3X",
  urlToken: "zgLBVJZ37SdoNdbZfBfHeSQAkGYNYYfj",
  jwtHeader: "hiEroWQpcidJArLSq7tEQG4LQt9AvEAR",
  jwtPayload: "wVHitqDurMm9EnikZhoLd42URdFJbT6j",
  jwtSignature: "JPrA66Ms5PDVBbHkKWRXnQVa4UwknUbW",
};
const KB_JWT_CANARY = `eyJ${KB_CANARIES.jwtHeader}.${KB_CANARIES.jwtPayload}.${KB_CANARIES.jwtSignature}`;

const KB_HTML_ERROR_BODY = `<html><body><h1>502 Bad Gateway</h1><p>upstream sent Authorization: Bearer ${KB_CANARIES.bearer}; Set-Cookie: session=${KB_CANARIES.cookie}; api_key=${KB_CANARIES.apiKey}; retry at https://api.example.com/v1/x?token=${KB_CANARIES.urlToken} later; jwt ${KB_JWT_CANARY}</p></body></html>`;

/** A proxy error page: non-JSON, carrying every credential class in its body. */
function htmlGateway() {
  return () => new Response(KB_HTML_ERROR_BODY, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

/** KnowBe4's documented JSON error shape whose message embeds a URL with a credential in its query string. */
function jsonForbiddenWithUrl() {
  return () => jsonResponse({ message: `Forbidden; see https://api.example.com/v1/x?token=${KB_CANARIES.urlToken} for details` }, { status: 403, statusText: "Forbidden" });
}

const KB_RECIPIENTS_ROUTE = "GET /v1/phishing/security_tests/{pst_id}/recipients";
const KB_PHISHER_ROUTE = "POST /graphql";

function pageOf(items, url) {
  const per = Number(url.searchParams.get("per_page") ?? "500");
  const page = Number(url.searchParams.get("page") ?? "1");
  return jsonResponse(items.slice((page - 1) * per, page * per));
}

function phisherResponse(fixture, init) {
  const body = JSON.parse(init.body);
  const messages = fixture.phisherMessages;
  if (/GrclankerPhisherMessageCount/.test(body.query)) {
    return jsonResponse({ data: { phisherMessages: { pagination: { totalCount: messages.length } } } });
  }
  const per = body.variables.per ?? 100;
  const page = body.variables.page ?? 1;
  const nodes = messages.slice((page - 1) * per, page * per);
  const pages = Math.max(1, Math.ceil(messages.length / per));
  return jsonResponse({ data: { phisherMessages: { nodes, pagination: { page, pages, per, totalCount: messages.length, nextPageKey: null } } } });
}

/** One route per KnowBe4 surface, serving the fixture with the Reporting API's page/per_page pagination and the PhishER connection shape. */
function kbRoutes(fixture) {
  return {
    "GET /v1/account": () => jsonResponse(fixture.account),
    "GET /v1/account/risk_score_history": (url) => pageOf(fixture.riskHistory, url),
    "GET /v1/users": (url) => pageOf(fixture.users, url),
    "GET /v1/groups": (url) => pageOf(fixture.groups, url),
    "GET /v1/phishing/campaigns": (url) => pageOf(fixture.phishingCampaigns, url),
    "GET /v1/phishing/security_tests": (url) => pageOf(url.searchParams.get("campaign_type") === "callback" ? fixture.callbackTests : fixture.securityTests, url),
    [KB_RECIPIENTS_ROUTE]: (url, pstId) => pageOf(fixture.recipientsByTest.get(pstId) ?? [], url),
    "GET /v1/training/campaigns": (url) => pageOf(fixture.trainingCampaigns, url),
    "GET /v1/training/enrollments": (url) => pageOf(fixture.enrollments, url),
    "GET /v1/training/store_purchases": (url) => pageOf(fixture.storePurchases, url),
    "GET /v1/training/policies": (url) => pageOf(fixture.trainingPolicies, url),
    [KB_PHISHER_ROUTE]: (url, pstId, init) => phisherResponse(fixture, init),
  };
}

/** The real Knowbe4ApiClient over a fetch router that records the method, path, URL, and status of every request served. */
function httpKnowbe4(fixture, options = {}) {
  const routes = { ...kbRoutes(fixture), ...(options.routes ?? {}) };
  const log = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    const method = (init.method ?? "GET").toUpperCase();
    const recipients = url.pathname.match(/^\/v1\/phishing\/security_tests\/([^/]+)\/recipients$/);
    const key = recipients ? KB_RECIPIENTS_ROUTE : `${method} ${url.pathname}`;
    const handler = routes[key];
    const response = handler
      ? await handler(url, recipients ? decodeURIComponent(recipients[1]) : undefined, init)
      : jsonResponse({ message: "Not Found" }, { status: 404, statusText: "Not Found" });
    log.push({ method, path: url.pathname, url: url.toString(), status: response.status });
    return response;
  };
  const config = sampleConfig({ apiToken: KB_TEST_TOKEN, phisherApiToken: options.phisher === false ? undefined : KB_PHISHER_TOKEN, ...(options.config ?? {}) });
  const client = new Knowbe4ApiClient(config, { fetchImpl, sleepImpl: async () => {}, maxRetries: 0, minRequestIntervalMs: 0 });
  return { client, config, log };
}

const KB_AREAS = [
  ["phishing", assessKnowbe4PhishingProgram],
  ["training", assessKnowbe4TrainingProgram],
  ["risk", assessKnowbe4UserRisk],
  ["governance", assessKnowbe4AccountGovernance],
];

/** What the four assess tools return: one snapshot per area, assessed with the default options. */
async function runAllKnowbe4Assessments(client) {
  const results = [];
  for (const [area, assess] of KB_AREAS) {
    const snapshot = await collectKnowbe4Snapshot(client, { scopes: [area], now: NOW });
    results.push(assess(snapshot, { now: NOW }));
  }
  return results;
}

function kbMentionedEndpoints(text) {
  return [...text.matchAll(/\b(GET|POST|PUT|PATCH|DELETE)\s+(\/[A-Za-z0-9_./?=&{}[\]-]+)/g)]
    .map((match) => ({ method: match[1], path: match[2].split("?")[0].replace(/[.,;:)]+$/, "") }));
}

function kbMentionedStatusCodes(text) {
  const codes = new Set();
  for (const match of text.matchAll(/\b([1-5]\d\d) (?:OK|Forbidden|Unauthorized|Bad Request|Not Found|Too Many Requests|Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout|Error)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/request failed \(([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/"(?:http_)?status":\s*([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/\bHTTP ([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  return [...codes];
}

/** Asserts every endpoint and status code named anywhere in `outputs` was requested and observed according to `log`. */
function assertKbOutputMatchesRequestLog(outputs, log, label) {
  const requested = new Set(log.map((entry) => `${entry.method} ${entry.path}`));
  const statuses = new Set(log.map((entry) => entry.status));
  let endpointMentions = 0;
  let statusMentions = 0;
  for (const [name, text] of outputs) {
    for (const { method, path } of kbMentionedEndpoints(text)) {
      endpointMentions += 1;
      assert.ok(requested.has(`${method} ${path}`), `${label}: ${name} names ${method} ${path} but the run never requested it; requested: ${[...requested].sort().join(", ")}`);
    }
    for (const code of kbMentionedStatusCodes(text)) {
      statusMentions += 1;
      assert.ok(statuses.has(code), `${label}: ${name} names HTTP ${code} but no request observed it; observed: ${[...statuses]}`);
    }
  }
  return { endpointMentions, statusMentions };
}

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

/** Every error string a KnowBe4 run can record, gathered from the access check, the assess payloads, and the bundle. */
function kbRecordedErrorStrings(access, assessments, files) {
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

test("canary fixture self-check: every planted KnowBe4 credential is alphanumeric, random-looking, and shares no 6-character window with the fixture's legitimate values", async () => {
  const { client, config } = httpKnowbe4(healthyFixture());
  const access = await checkKnowbe4Access(client);
  const assessments = await runAllKnowbe4Assessments(client);
  const exported = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-self-check-"), { now: NOW });
  const legitimate = new Map([
    ...readBundleFiles(exported.outputDir),
    ["fixture", JSON.stringify(healthyFixture())],
    ["principal fixture", JSON.stringify(principalFixture())],
    ["check_access", JSON.stringify(access)],
    ["assessments", JSON.stringify(assessments)],
    ["config", JSON.stringify({ ...config, apiToken: null, phisherApiToken: null })],
  ]);
  const canaries = [...Object.values(KB_CANARIES), KB_TEST_TOKEN, KB_PHISHER_TOKEN, ...KNOWBE4_FAKE_SECRETS, ...Object.values(KB_CONFIG_CANARIES), KB_PARSER_SNIPPET_CANARY];
  assertCanaryFixture(assert, canaries, legitimate, "KnowBe4 canaries");
});

test("verdict rule 9 / addendum 2: the KnowBe4 bundle, its zip, every assess payload, and the access check never carry any window of a canary from an error body, and errors carry the status-and-length note", async () => {
  const { client, config, log } = httpKnowbe4(healthyFixture(), {
    routes: { "GET /v1/groups": htmlGateway(), "GET /v1/training/store_purchases": jsonForbiddenWithUrl() },
  });

  const access = await checkKnowbe4Access(client);
  const result = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-canary-"), { now: NOW });
  const assessments = await runAllKnowbe4Assessments(client);

  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size >= 25 && entries.size === files.size, `expected the zip to mirror ${files.size} files, got ${entries.size}`);
  const planted = [...Object.values(KB_CANARIES), KB_JWT_CANARY, config.apiToken, config.phisherApiToken];
  assertCanaryWindowsAbsent(assert, files, planted, "bundle file");
  assertCanaryWindowsAbsent(assert, entries, planted, "zip entry");
  assertCanaryWindowsAbsent(assert, new Map([["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), planted, "tool payload");
  assert.ok(log.some((entry) => entry.status === 502) && log.some((entry) => entry.status === 403), "both failing surfaces were requested");

  // The non-JSON body is described by status and length; the JSON error is quoted with its URL query scrubbed.
  const errors = files.get("_errors.log");
  assert.match(errors, /^groups: KnowBe4 request failed \(502 Bad Gateway\) GET \/v1\/groups: 502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)$/m);
  assert.match(errors, /^store_purchases: KnowBe4 request failed \(403 Forbidden\) GET \/v1\/training\/store_purchases: Forbidden; see https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for details$/m);
  assert.equal(result.errorCount, 2, `only the two failing surfaces are recorded:\n${errors}`);

  // The observed status flows into the marker, the finding, the access surface, and the collection status; no "403" is
  // invented for the 502 path and no endpoint is named from a constant.
  const groups = JSON.parse(files.get("core_data/groups.json"));
  assert.deepEqual(
    { collected: groups.collected, status: groups.status, endpoint: groups.endpoint, reason: groups.reason },
    { collected: false, status: 502, endpoint: "GET /v1/groups", reason: "not_readable" },
  );
  assert.match(groups.error, /non-JSON body \(text\/html/);
  const purchases = JSON.parse(files.get("core_data/store_purchases.json"));
  assert.deepEqual({ collected: purchases.collected, status: purchases.status, endpoint: purchases.endpoint }, { collected: false, status: 403, endpoint: "GET /v1/training/store_purchases" });

  const risk = assessments[2];
  const coverage = findingFor(risk, 8);
  assert.equal(coverage.status, "manual");
  assert.match(coverage.summary, /^Unreadable inventory: groups \(GET \/v1\/groups: KnowBe4 request failed \(502 Bad Gateway\) GET \/v1\/groups: 502 Bad Gateway: non-JSON body/);
  assert.doesNotMatch(coverage.summary, /403/);
  assert.equal(coverage.evidence.unreadable_inventories[0].http_status, 502);
  const currency = findingFor(assessments[1], 11);
  assert.notEqual(currency.status, "pass");
  assert.match(currency.summary, /Unreadable inventory: store_purchases \(GET \/v1\/training\/store_purchases: KnowBe4 request failed \(403 Forbidden\).*\[REDACTED\]/);

  const groupsProbe = access.surfaces.find((surface) => surface.name === "groups");
  assert.deepEqual(
    { status: groupsProbe.status, collected: groupsProbe.collected, http_status: groupsProbe.http_status, count: groupsProbe.count },
    { status: "not_readable", collected: false, http_status: 502, count: null },
  );
  assert.match(groupsProbe.error, /502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/);
  const purchasesProbe = access.surfaces.find((surface) => surface.name === "store_purchases");
  assert.deepEqual({ status: purchasesProbe.status, http_status: purchasesProbe.http_status }, { status: "not_readable", http_status: 403 });

  const status = JSON.parse(files.get("core_data/collection_status.json"));
  const groupsRow = status.inventories.find((row) => row.inventory === "groups");
  assert.deepEqual(
    { status: groupsRow.status, collected: groupsRow.collected, readable: groupsRow.readable, http_status: groupsRow.http_status, complete: groupsRow.complete, truncated: groupsRow.truncated, seen: groupsRow.seen, endpoint: groupsRow.endpoint },
    { status: "not_readable", collected: false, readable: false, http_status: 502, complete: null, truncated: null, seen: null, endpoint: "GET /v1/groups" },
  );
  assert.equal(status.totals.not_readable, 2);
  assert.equal(status.totals.truncation_unknown, 2);
  // Readable rows name the request the listing made, never the templated documentation path.
  const recipientsRow = status.inventories.find((row) => row.inventory === "security_test_recipients");
  assert.match(recipientsRow.endpoint, /^GET \/v1\/phishing\/security_tests\/900\/recipients, GET \/v1\/phishing\/security_tests\/901\/recipients/);
  assert.ok(!JSON.stringify([...files.values()]).includes("{pst_id}"), "no templated endpoint reaches the bundle");
  const groupsState = risk.summary.inventories.find((row) => row.inventory === "groups");
  assert.deepEqual({ status: groupsState.status, read: groupsState.read, http_status: groupsState.http_status, endpoint: groupsState.endpoint }, { status: "not_readable", read: false, http_status: 502, endpoint: "GET /v1/groups" });
});

/** A 403 body echoing weak human-chosen pairs (no digits, symbols, or length a shape gate would catch) under vendor env names and a config key. */
const WEAK_PAIR_BODY = "Access denied: LAUNCHDARKLY_API_TOKEN=monkey LD_ACCESS_TOKEN=Sunshine DB_PASSWORD=letmein DD_APP_KEY=p@ss BOX_CLIENT_SECRET=football KNOWBE4_API_TOKEN=qwerty ELASTIC_PASSWORD=iloveyou developer_token: letmein2024";
const WEAK_PAIR_VALUES = ["monkey", "Sunshine", "letmein", "p@ss", "football", "qwerty", "iloveyou", "letmein2024"];
const WEAK_PAIR_KEYS = ["LAUNCHDARKLY_API_TOKEN", "LD_ACCESS_TOKEN", "DB_PASSWORD", "DD_APP_KEY", "BOX_CLIENT_SECRET", "KNOWBE4_API_TOKEN", "ELASTIC_PASSWORD", "developer_token"];

test("row (a): a KnowBe4 403 body echoing weak values under credential-named keys reaches the access check with every value gone and every key kept", async () => {
  const { client, log } = httpKnowbe4(healthyFixture(), {
    routes: { "GET /v1/training/store_purchases": () => jsonResponse({ message: WEAK_PAIR_BODY }, { status: 403, statusText: "Forbidden" }) },
  });
  const access = await checkKnowbe4Access(client);
  const purchases = access.surfaces.find((surface) => surface.name === "store_purchases");
  assert.equal(purchases.http_status, 403);
  assert.ok(log.some((entry) => entry.status === 403), "the 403 was observed on the wire");
  assert.match(purchases.error, /KnowBe4 request failed \(403 Forbidden\) GET \/v1\/training\/store_purchases: Access denied: /);
  for (const key of WEAK_PAIR_KEYS) assert.ok(purchases.error.includes(`${key}=[REDACTED]`) || purchases.error.includes(`${key}: [REDACTED]`), `${key} keeps its name and gets the marker: ${purchases.error}`);
  assertCanaryWindowsAbsent(assert, JSON.stringify(access), WEAK_PAIR_VALUES, "check_access payload");
});

test("addendum 5: every endpoint and status code named in KnowBe4 output corresponds to a request the run made and observed", async () => {
  const fixture = healthyFixture();
  const base = kbRoutes(fixture);
  const { client, config, log } = httpKnowbe4(fixture, {
    routes: {
      "GET /v1/groups": htmlGateway(),
      "GET /v1/training/store_purchases": jsonForbiddenWithUrl(),
      "GET /v1/account/risk_score_history": () => jsonResponse({ message: "Not Found" }, { status: 404, statusText: "Not Found" }),
      // Only one security test's recipient results are denied; the other per-test reads succeed.
      [KB_RECIPIENTS_ROUTE]: (url, pstId, init) => (pstId === "901" ? jsonForbiddenWithUrl()() : base[KB_RECIPIENTS_ROUTE](url, pstId, init)),
    },
  });

  const access = await checkKnowbe4Access(client);
  const result = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-request-log-"), { now: NOW });
  const assessments = await runAllKnowbe4Assessments(client);
  const outputs = [...readBundleFiles(result.outputDir), ["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]];

  assert.deepEqual([...new Set(log.map((entry) => entry.status))].sort(), [200, 403, 404, 502], "the fixture served 200, 403, 404, and 502");
  assert.ok(log.some((entry) => entry.path === "/v1/phishing/security_tests/901/recipients" && entry.status === 403), "the per-test recipients request was made and denied");
  const { endpointMentions, statusMentions } = assertKbOutputMatchesRequestLog(outputs, log, "mixed denials");
  assert.ok(endpointMentions > 40, `expected endpoint mentions across the bundle, got ${endpointMentions}`);
  assert.ok(statusMentions > 5, `expected status mentions across the bundle, got ${statusMentions}`);
  assert.ok(!JSON.stringify(outputs).includes("{pst_id}"), "no templated endpoint reaches the output");

  // The per-test gap names the request the run made and the status it observed, alongside the tests that did load.
  const phishing = assessments[0];
  const coverage = findingFor(phishing, 2);
  assert.notEqual(coverage.status, "pass");
  assert.match(coverage.summary, /Unreadable inventory: security_test_recipients \(GET \/v1\/phishing\/security_tests\/901\/recipients: security_test_recipients\[901\]: KnowBe4 request failed \(403 Forbidden\) GET \/v1\/phishing\/security_tests\/901\/recipients: Forbidden; see https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\] for details\)/);
  const recipients = JSON.parse(readFileSync(join(result.outputDir, "core_data", "security_test_recipients.json"), "utf8"));
  const failed = recipients.find((entry) => entry.collected === false);
  assert.deepEqual({ pst_id: failed.pst_id, status: failed.status, endpoint: failed.endpoint, reason: failed.reason }, { pst_id: "901", status: 403, endpoint: "GET /v1/phishing/security_tests/901/recipients", reason: "not_readable" });
  assert.equal(recipients.filter((entry) => entry.collected !== false).length, 5, "the five other tests inside the 180-day export window keep their samples");
  const history = JSON.parse(readFileSync(join(result.outputDir, "core_data", "account_risk_score_history.json"), "utf8"));
  assert.deepEqual({ collected: history.collected, status: history.status, endpoint: history.endpoint }, { collected: false, status: 404, endpoint: "GET /v1/account/risk_score_history" });
  const trend = findingFor(phishing, 7);
  assert.match(trend.summary, /account_risk_score_history \(GET \/v1\/account\/risk_score_history: KnowBe4 request failed \(404 Not Found\)/);
  assert.doesNotMatch(trend.summary, /403/);
});

/** Every list dataset written to core_data, the route that fills it, and the file a readable-but-empty read leaves as `[]`. */
const KB_CORE_DATA_DATASETS = [
  { inventory: "account_risk_score_history", route: "GET /v1/account/risk_score_history", file: "core_data/account_risk_score_history.json" },
  { inventory: "users", route: "GET /v1/users", file: "core_data/users_active.json" },
  { inventory: "groups", route: "GET /v1/groups", file: "core_data/groups.json" },
  { inventory: "phishing_campaigns", route: "GET /v1/phishing/campaigns", file: "core_data/phishing_campaigns.json" },
  { inventory: "security_tests", route: "GET /v1/phishing/security_tests", file: "core_data/security_tests.json", callback: false },
  { inventory: "callback_security_tests", route: "GET /v1/phishing/security_tests", file: "core_data/callback_security_tests.json", callback: true },
  { inventory: "security_test_recipients", route: KB_RECIPIENTS_ROUTE, file: "core_data/security_test_recipients.json" },
  { inventory: "training_campaigns", route: "GET /v1/training/campaigns", file: "core_data/training_campaigns.json" },
  { inventory: "training_enrollments", route: "GET /v1/training/enrollments", file: "core_data/training_enrollments.json" },
  { inventory: "store_purchases", route: "GET /v1/training/store_purchases", file: "core_data/store_purchases.json" },
  { inventory: "training_policies", route: "GET /v1/training/policies", file: "core_data/training_policies.json" },
  { inventory: "phisher_messages", route: KB_PHISHER_ROUTE, file: "core_data/phisher_messages.json" },
];

/** The healthy fixture with several inventories legitimately empty, so a readable-but-empty `[]` sits beside every denial. */
function sparseFixture() {
  return { ...healthyFixture(), riskHistory: [], groups: [], callbackTests: [], storePurchases: [], trainingPolicies: [], phisherMessages: [] };
}

/** Denies one dataset; the security test listing is split by campaign_type so the callback and standard reads deny independently. */
function denyDataset(base, denial) {
  const forbidden = jsonForbiddenWithUrl();
  if (denial.callback === undefined) return forbidden;
  return (url, pstId, init) => ((url.searchParams.get("campaign_type") === "callback") === denial.callback ? forbidden() : base[denial.route](url, pstId, init));
}

test("addendum 5: under each single-inventory denial the denied dataset's core_data file is a not-collected marker while readable-but-empty datasets stay []", async () => {
  for (const denial of KB_CORE_DATA_DATASETS) {
    const fixture = sparseFixture();
    const { client, config, log } = httpKnowbe4(fixture, { routes: { [denial.route]: denyDataset(kbRoutes(fixture), denial) } });
    const result = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-marker-"), { now: NOW });
    const files = readBundleFiles(result.outputDir);
    const label = `${denial.inventory} denied`;

    const denied = JSON.parse(files.get(denial.file));
    assert.ok(!Array.isArray(denied), `${label}: ${denial.file} must be a marker object, not an array`);
    assert.equal(denied.collected, false, label);
    assert.equal(denied.status, 403, `${label}: the marker carries the observed status`);
    assert.equal(denied.reason, "not_readable", label);
    assert.match(denied.error, /KnowBe4 request failed \(403 Forbidden\)/, label);
    assertCanaryWindowsAbsent(assert, JSON.stringify(denied), [KB_CANARIES.urlToken], `${label} marker`);
    const requested = new Set(log.filter((entry) => entry.status === 403).map((entry) => `${entry.method} ${entry.path}`));
    for (const endpoint of denied.endpoint.split(", ")) {
      assert.ok(requested.has(endpoint.split("?")[0].replace(/ phisherMessages$/, "")), `${label}: marker names ${endpoint}, which was not the denied request (${[...requested].join(", ")})`);
    }
    if (denial.inventory === "security_test_recipients") {
      const deniedReads = log.filter((entry) => /\/recipients$/.test(entry.path) && entry.status === 403).length;
      assert.ok(Array.isArray(denied.failed_reads) && deniedReads > 0 && denied.failed_reads.length === deniedReads, `${label}: one failed read per sampled test (${deniedReads} denied requests)`);
      assert.ok(denied.failed_reads.every((read) => read.collected === false && read.status === 403 && /^GET \/v1\/phishing\/security_tests\/\d+\/recipients$/.test(read.endpoint)), label);
    }
    if (denial.inventory === "security_tests") {
      // No per-test read is attempted when the test listing is denied, so the recipients file is a not-requested marker naming no endpoint.
      const recipients = JSON.parse(files.get("core_data/security_test_recipients.json"));
      assert.deepEqual({ collected: recipients.collected, status: recipients.status, endpoint: recipients.endpoint, reason: recipients.reason }, { collected: false, status: "not-collected", endpoint: null, reason: "not_requested" });
    }

    const emptyFile = denial.inventory === "training_policies" ? "core_data/store_purchases.json" : "core_data/training_policies.json";
    assert.deepEqual(JSON.parse(files.get(emptyFile)), [], `${label}: a readable-but-empty dataset stays []`);
    const status = JSON.parse(files.get("core_data/collection_status.json"));
    const row = status.inventories.find((entry) => entry.inventory === denial.inventory);
    assert.deepEqual({ status: row.status, collected: row.collected, readable: row.readable, http_status: row.http_status, complete: row.complete, truncated: row.truncated, seen: row.seen }, { status: "not_readable", collected: false, readable: false, http_status: 403, complete: null, truncated: null, seen: null }, label);
    const emptyRow = status.inventories.find((entry) => entry.inventory === (denial.inventory === "training_policies" ? "store_purchases" : "training_policies"));
    assert.deepEqual({ status: emptyRow.status, complete: emptyRow.complete, truncated: emptyRow.truncated, seen: emptyRow.seen }, { status: "readable", complete: true, truncated: false, seen: 0 }, `${label}: the empty inventory is a complete, untruncated read of zero records`);
  }

  // The account is a single record, not a list, and gets the same marker when denied.
  const { client, config } = httpKnowbe4(sparseFixture(), { routes: { "GET /v1/account": jsonForbiddenWithUrl() } });
  const result = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-marker-"), { now: NOW });
  const account = JSON.parse(readBundleFiles(result.outputDir).get("core_data/account.json"));
  assert.deepEqual({ collected: account.collected, status: account.status, endpoint: account.endpoint, reason: account.reason }, { collected: false, status: 403, endpoint: "GET /v1/account", reason: "not_readable" });
});

/**
 * Principals that only one inventory (or one combination of inventories) can name. Each is asserted present in the
 * all-readable baseline and absent from every assess payload and the bundle when any listed inventory is denied.
 * A `control` scopes the check to that finding's evidence: the inactive user is still a legitimately named high-risk
 * user from the readable user list, but may not be called inactive once phishing or training participation is unread.
 */
const KB_PRINCIPAL_CANARIES = [
  { canary: "AcmeCanaryAccountNameQz", inventories: ["account"] },
  { canary: "admin-canary-q7x@acme.example", inventories: ["account"] },
  { canary: "inactive-canary-u11@acme.example", inventories: ["users"] },
  { canary: "inactive-canary-u11@acme.example", inventories: ["security_tests", "security_test_recipients", "training_enrollments"], control: 18 },
  { canary: "CanaryUncoveredGroupZq", inventories: ["groups", "phishing_campaigns", "training_campaigns"] },
  { canary: "Canary Security Test Vw", inventories: ["security_tests"] },
  { canary: "recipient-canary-r9@acme.example", inventories: ["security_test_recipients", "training_enrollments", "security_tests"] },
  { canary: "Canary Training Campaign Tk", inventories: ["training_campaigns"] },
  { canary: "Canary Stale Module Mj", inventories: ["training_campaigns"] },
  { canary: "late-canary-l3@acme.example", inventories: ["users"] },
  { canary: "late-canary-l3@acme.example", inventories: ["training_enrollments"], control: 4 },
  { canary: "Canary Callback Test Cb", inventories: ["callback_security_tests"] },
];

/** The healthy fixture with one principal per inventory that no other inventory carries, and campaigns targeting named groups. */
function principalFixture() {
  const fixture = healthyFixture();
  fixture.account.name = "AcmeCanaryAccountNameQz";
  fixture.account.admins.push({ id: 77, first_name: "AdminCanary", last_name: "Qx", email: "admin-canary-q7x@acme.example" });
  // A user who never signed in, was never phished, and was never enrolled: inactive, and named only by the users inventory.
  fixture.users.push(user(11, { first_name: "InactiveCanary", last_name: "Ueleven", email: "inactive-canary-u11@acme.example", joined_on: daysAgo(400), last_sign_in: null, groups: [101] }));
  // A recent joiner enrolled well after the grace period: late, named by the users and enrollments inventories.
  const lateUser = user(12, { first_name: "LateCanary", last_name: "Lthree", email: "late-canary-l3@acme.example", joined_on: daysAgo(100), groups: [100] });
  fixture.users.push(lateUser);
  fixture.enrollments.push(enrollment(500, lateUser, 701, "Security Awareness Fundamentals", daysAgo(50)));
  for (const item of fixture.securityTests) fixture.recipientsByTest.get(String(item.pst_id)).push(recipient(item.pst_id, lateUser, item.started_at));
  // Campaigns target the two console groups by name, so a third group no campaign targets is uncovered and named.
  const targeted = [{ group_id: 100, name: "Finance" }, { group_id: 101, name: "Engineering" }];
  for (const campaign of [...fixture.phishingCampaigns, ...fixture.trainingCampaigns]) campaign.groups = targeted;
  fixture.groups.push({ id: 102, name: "CanaryUncoveredGroupZq", group_type: "console_group", adi_guid: null, member_count: 2, current_risk_score: 30, status: "active" });
  // The latest security test carries a name only the security_tests inventory holds.
  fixture.securityTests[0].name = "Canary Security Test Vw";
  // A recipient who clicked, past the remedial window, in neither the user list nor the enrollments: unremediated, named only by recipient results.
  const failedTest = fixture.securityTests[1];
  const canaryRecipient = { id: 91, first_name: "RecipientCanary", last_name: "Rnine", email: "recipient-canary-r9@acme.example" };
  fixture.recipientsByTest.get(String(failedTest.pst_id)).push(recipient(failedTest.pst_id, canaryRecipient, failedTest.started_at, {
    opened_at: failedTest.started_at,
    clicked_at: new Date(new Date(failedTest.started_at).getTime() + 1_800_000).toISOString(),
  }));
  // A completed training campaign whose only module is years old: stale content named only by the training_campaigns inventory.
  fixture.trainingCampaigns.push({
    campaign_id: 702,
    name: "Canary Training Campaign Tk",
    groups: targeted,
    status: "Completed",
    content: [{ store_purchase_id: 3, content_type: "Store Purchase", name: "Canary Stale Module Mj", publish_date: "2021-01-01T00:00:00Z", retired: false }],
    duration_type: "Specific End Date",
    start_date: daysAgo(80),
    end_date: daysAgo(40),
    relative_duration: null,
    auto_enroll: true,
    allow_multiple_enrollments: false,
    completion_percentage: 97,
  });
  fixture.callbackTests[0].name = "Canary Callback Test Cb";
  return fixture;
}

const KB_SINGLE_INVENTORY_DENIALS = KB_CORE_DATA_DATASETS.concat([{ inventory: "account", route: "GET /v1/account", file: "core_data/account.json" }]);

const KB_FALLBACK_VALUES = new Set([0, false, "none", "[]", "{}"]);

/** Fields that describe the read itself (read-state flags, inventory states, gaps, caveats) and legitimately flip under a denial. */
const KB_READ_STATE_PATHS = [
  /(^|\.)[a-z_]*(complete|readable|observed|loaded|read|sampled|available)$/,
  /^inventories(\.|$)/,
  /^unreadable_inventories(\.|$)/,
  /^truncated_inventories(\.|$)/,
  /^collection_error$/,
  /^(pass|warn|fail|manual)$/,
];

/** True when a denied-run value is a zero, false, or empty fallback where the all-readable baseline held real data. */
function isKbFallback(path, value, baselineValue) {
  if (!KB_FALLBACK_VALUES.has(value)) return false;
  if (baselineValue === undefined || baselineValue === null || KB_FALLBACK_VALUES.has(baselineValue)) return false;
  if (Array.isArray(baselineValue) && baselineValue.length === 0) return false;
  if (typeof baselineValue === "object" && !Array.isArray(baselineValue) && Object.keys(baselineValue).length === 0) return false;
  return !KB_READ_STATE_PATHS.some((pattern) => pattern.test(path));
}

test("addendum 3: under every single-inventory denial no KnowBe4 finding, summary, or tool payload falls back to a zero, false, or empty value, and no principal is named from the denied inventory", async () => {
  const baselineRun = httpKnowbe4(principalFixture());
  const baseline = await runAllKnowbe4Assessments(baselineRun.client);
  const baselineExport = await exportKnowbe4AuditBundle(baselineRun.client, baselineRun.config, createTempBase("grclanker-knowbe4-principal-baseline-"), { now: NOW });
  const baselineText = JSON.stringify(baseline) + [...readBundleFiles(baselineExport.outputDir).values()].join("\n");
  for (const { canary } of KB_PRINCIPAL_CANARIES) {
    assert.ok(JSON.stringify(baseline).includes(canary), `${canary} must be named by an all-readable assess payload for its gating check to mean anything`);
  }
  assert.ok(baselineText.length > 0);

  const offenders = [];
  let comparedLeaves = 0;
  for (const denial of KB_SINGLE_INVENTORY_DENIALS) {
    const fixture = principalFixture();
    const { client, config } = httpKnowbe4(fixture, { routes: { [denial.route]: denyDataset(kbRoutes(fixture), denial) } });
    const denied = await runAllKnowbe4Assessments(client);
    const exported = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-principal-"), { now: NOW });
    const files = readBundleFiles(exported.outputDir);
    const label = `${denial.inventory} denied`;
    // Raw core_data records are the readable inventories themselves; the gating rule covers what the run asserts about
    // principals, so the analysis, compliance, and quick-reference files are scanned alongside the tool payloads.
    const derived = [...files].filter(([name]) => !name.startsWith("core_data/"));
    const deniedText = JSON.stringify(denied) + derived.map(([, text]) => text).join("\n");
    for (const { canary, inventories, control } of KB_PRINCIPAL_CANARIES) {
      if (!inventories.includes(denial.inventory)) continue;
      if (control !== undefined) {
        const item = denied.flatMap((result) => result.findings).find((candidate) => candidate.control === control);
        assert.ok(!JSON.stringify(item).includes(canary), `${label}: control ${control} still names ${canary} from the denied inventory: ${JSON.stringify(item.evidence)}`);
        continue;
      }
      const where = [
        ...leafEntries(denied).filter(([, value]) => typeof value === "string" && value.includes(canary)).map(([path]) => `assessments.${path}`),
        ...derived.filter(([, text]) => text.includes(canary)).map(([name]) => name),
      ];
      assert.ok(!deniedText.includes(canary), `${label}: ${canary} is still named from the denied inventory at ${where.join(", ")}`);
    }
    for (const [areaIndex, result] of denied.entries()) {
      const baselineResult = baseline[areaIndex];
      for (const [path, value] of leafEntries(result.summary)) {
        comparedLeaves += 1;
        const baselineValue = pluckPath(baselineResult.summary, path);
        if (isKbFallback(path, value, baselineValue)) offenders.push(`${label}: ${result.area} summary.${path} = ${JSON.stringify(value)} (baseline ${JSON.stringify(baselineValue)})`);
      }
      for (const item of result.findings) {
        const baselineFinding = findingFor(baselineResult, item.control);
        for (const [path, value] of leafEntries(item.evidence ?? {})) {
          comparedLeaves += 1;
          const baselineValue = pluckPath(baselineFinding.evidence ?? {}, path);
          if (isKbFallback(path, value, baselineValue)) offenders.push(`${label}: control ${item.control} evidence.${path} = ${JSON.stringify(value)} (baseline ${JSON.stringify(baselineValue)})`);
        }
      }
    }
    // The bundle's assessment-level summaries get the same treatment as the tool payloads.
    const baselineAnalysis = readBundleFiles(baselineExport.outputDir);
    for (const name of ["analysis/phishing.json", "analysis/training.json", "analysis/risk.json", "analysis/governance.json"]) {
      if (!files.has(name)) continue;
      const summary = JSON.parse(files.get(name)).summary ?? {};
      const baselineSummary = JSON.parse(baselineAnalysis.get(name)).summary ?? {};
      for (const [path, value] of leafEntries(summary)) {
        comparedLeaves += 1;
        if (isKbFallback(path, value, pluckPath(baselineSummary, path))) offenders.push(`${label}: ${name} summary.${path} = ${JSON.stringify(value)}`);
      }
    }
  }
  assert.ok(comparedLeaves > 3000, `expected the sweep to compare thousands of leaves, got ${comparedLeaves}`);
  assert.deepEqual(offenders, [], `values that fell back to zero, false, or empty under a denial:\n${offenders.join("\n")}`);
});

// ---------------------------------------------------------------------------------------------------------------
// Addendum 4: every surface fails in turn with a 502 HTML page and a JSON error carrying canaries.
// ---------------------------------------------------------------------------------------------------------------

/** How each route is named in an error string, so the strings about a failing surface can be picked out. */
function kbSurfacePattern(route) {
  if (route === KB_RECIPIENTS_ROUTE) return /GET \/v1\/phishing\/security_tests\/\d+\/recipients/;
  return new RegExp(route.replace(/[/]/g, "\\/"));
}

test("addendum 4: a 502 HTML page or a JSON error message carrying credentials on any KnowBe4 surface never reaches the access check, an assess payload, or the bundle, and every recorded error carries the status-and-length note", async () => {
  const surfaces = Object.keys(kbRoutes(healthyFixture()));
  assert.equal(surfaces.length, 12, "every collector and access probe route");
  const variants = [
    { name: "html502", handler: htmlGateway, note: /502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/ },
    { name: "json403", handler: jsonForbiddenWithUrl, note: /\(403 Forbidden\)/ },
  ];
  let notedSurfaces = 0;
  for (const surface of surfaces) {
    for (const variant of variants) {
      const { client, config } = httpKnowbe4(healthyFixture(), { routes: { [surface]: variant.handler() } });
      const label = `${surface} ${variant.name}`;
      const planted = [...Object.values(KB_CANARIES), KB_JWT_CANARY, config.apiToken, config.phisherApiToken];

      const access = await checkKnowbe4Access(client);
      const assessments = await runAllKnowbe4Assessments(client);
      const result = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-surface-canary-"), { now: NOW });
      const files = readBundleFiles(result.outputDir);
      const entries = readZipEntries(result.zipPath);

      assertCanaryWindowsAbsent(assert, files, planted, `${label} bundle file`);
      assertCanaryWindowsAbsent(assert, entries, planted, `${label} zip entry`);
      assertCanaryWindowsAbsent(assert, new Map([["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), planted, `${label} tool payload`);

      const pattern = kbSurfacePattern(surface);
      const aboutSurface = kbRecordedErrorStrings(access, assessments, files).filter((text) => pattern.test(text) && /request failed|timed out/.test(text));
      assert.ok(aboutSurface.length > 0, `${label}: the failure is recorded somewhere`);
      notedSurfaces += 1;
      for (const text of aboutSurface) {
        assert.match(text, variant.note, `${label}: error string lacks the status note: ${text}`);
        assert.ok(!/<html|Bad Gateway<\/|upstream sent/.test(text), `${label}: error string echoes the body: ${text}`);
        if (variant.name === "json403") assertCanaryWindowsAbsent(assert, text, [KB_CANARIES.urlToken], `${label} error string`);
      }
    }
  }
  assert.equal(notedSurfaces, surfaces.length * variants.length);
});

// ---------------------------------------------------------------------------------------------------------------
// Addenda 6 and 6b: config loader errors are fixed text carrying only the path, a validated code, and a line.
// ---------------------------------------------------------------------------------------------------------------

const KB_CONFIG_CANARIES = {
  nestedKey: "UfJ5c4A7p6pL5VJpnbCyGKExThjgzGZV",
  nestedValue: "Wi2seuvnQDjpk2UxuJBrwco7B4tCrzqN",
  alias: "sehnBAdXx2kHYN8SfAk9HfdMM6UEYrnS",
  unreadable: "9WWhhs4NH3gsi2oJGCcfZkWbDMrPq7jB",
};
const KB_PARSER_SNIPPET_CANARY = "sFp3XJQYXRyCxM7KH9e4mnZXTzaHVQQk";

const LIBRARY_WORDING = ["Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "no such file"];

/** Asserts a message carries neither any window of a canary nor the parser's or filesystem's own wording. */
function assertFixedTextOnly(message, canaries, label) {
  assertCanaryWindowsAbsent(assert, message, canaries, label);
  for (const wording of LIBRARY_WORDING) assert.ok(!message.includes(wording), `${label}: carries library wording "${wording}": ${message}`);
}

test("config loader errors: a KnowBe4 config file that cannot be read or parsed yields fixed text with only the path, a validated code, and the parser's line, from the resolver and from check_access", async () => {
  const registered = [];
  registerKnowbe4Tools({ registerTool: (tool) => registered.push(tool) });
  const checkTool = registered.find((tool) => tool.name === "knowbe4_check_access");
  const exportTool = registered.find((tool) => tool.name === "knowbe4_export_audit_bundle");
  const canaries = Object.values(KB_CONFIG_CANARIES);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("no request may be made while the config file is unreadable"); };
  try {
    const base = createTempBase("grclanker-knowbe4-config-errors-");
    const cases = [];

    // YAML nested mapping: the parser quotes the whole source line, key, value, and bearer token included.
    const nested = join(base, "nested.yaml");
    writeFileSync(nested, `api_token: ${KB_CONFIG_CANARIES.nestedKey}: Bearer ${KB_CONFIG_CANARIES.nestedValue}\n`, "utf8");
    assert.throws(() => parseYaml(readFileSync(nested, "utf8")), (error) => error.message.includes(KB_CONFIG_CANARIES.nestedKey) && error.message.includes("Nested mappings"), "positive control: yaml.parse quotes the line");
    cases.push({ name: "yaml nested mapping", path: nested, code: "INVALID_YAML", line: 1, message: `Unable to parse KnowBe4 config file: invalid YAML in ${nested} at line 1` });

    // YAML alias: a plain ReferenceError (no linePos) whose message leads with the value and no key name.
    const alias = join(base, "alias.yaml");
    writeFileSync(alias, `api_token: *${KB_CONFIG_CANARIES.alias}\n`, "utf8");
    assert.throws(() => parseYaml(readFileSync(alias, "utf8")), (error) => error instanceof ReferenceError && error.message.includes(KB_CONFIG_CANARIES.alias) && error.message.includes("Unresolved alias"), "positive control: yaml.parse throws a ReferenceError carrying the value");
    cases.push({ name: "yaml alias", path: alias, code: "INVALID_YAML", line: undefined, message: `Unable to parse KnowBe4 config file: invalid YAML in ${alias}` });

    // EISDIR: a directory at the path is a read failure, not a parse failure.
    const directory = join(base, "config-dir");
    mkdirSync(directory);
    assert.throws(() => readFileSync(directory, "utf8"), (error) => error.code === "EISDIR" && /illegal operation/.test(error.message), "positive control: the filesystem message carries its own wording");
    cases.push({ name: "EISDIR", path: directory, code: "EISDIR", line: undefined, message: `Unable to read KnowBe4 config file ${directory} (EISDIR)` });

    // EACCES: an unreadable file (root reads everything, so the case is skipped when running as root).
    if (typeof process.getuid === "function" && process.getuid() !== 0) {
      const unreadable = join(base, "unreadable.yaml");
      writeFileSync(unreadable, `api_token: ${KB_CONFIG_CANARIES.unreadable}\n`, "utf8");
      chmodSync(unreadable, 0o000);
      assert.throws(() => readFileSync(unreadable, "utf8"), (error) => error.code === "EACCES" && /permission denied/.test(error.message), "positive control");
      cases.push({ name: "EACCES", path: unreadable, code: "EACCES", line: undefined, message: `Unable to read KnowBe4 config file ${unreadable} (EACCES)` });
    }

    // ENOENT on an explicit path: a missing file named by argument or environment is an error, not a silent default.
    const missing = join(base, "missing.yaml");
    cases.push({ name: "ENOENT", path: missing, code: "ENOENT", line: undefined, message: `Unable to read KnowBe4 config file ${missing} (ENOENT)` });

    for (const item of cases) {
      let thrown;
      try {
        resolveKnowbe4Configuration({ config_file: item.path }, {}, base, base);
      } catch (error) {
        thrown = error;
      }
      assert.ok(thrown, `${item.name}: the resolver must reject the file`);
      assert.equal(thrown.name, "Knowbe4ConfigFileError", item.name);
      assert.equal(thrown.message, item.message, `${item.name}: fixed text only`);
      assert.equal(thrown.code, item.code, item.name);
      assert.equal(thrown.line, item.line, item.name);
      assert.equal(thrown.path, item.path, item.name);
      assertFixedTextOnly(thrown.message, canaries, `${item.name} resolver`);

      const access = await checkTool.execute("call-config", checkTool.prepareArguments({ config_file: item.path }));
      assert.equal(access.isError, true, item.name);
      assert.equal(access.content[0].text, `KnowBe4 access check failed: ${item.message}`, item.name);
      assertFixedTextOnly(JSON.stringify(access), canaries, `${item.name} check_access`);

      const outputDir = join(base, `export-${item.code}`);
      const exported = await exportTool.execute("call-config-export", exportTool.prepareArguments({ config_file: item.path, output_dir: outputDir }));
      assert.equal(exported.isError, true, item.name);
      assert.equal(exported.content[0].text, `KnowBe4 audit bundle export failed: ${item.message}`, item.name);
      assert.equal(existsSync(outputDir), false, `${item.name}: nothing is written when the config file is unreadable`);
    }

    // The environment variable is an explicit path too, and a missing default file is still simply absent.
    assert.throws(() => resolveKnowbe4Configuration({ api_token: "t" }, { KNOWBE4_CONFIG_FILE: missing }, base, base), { message: `Unable to read KnowBe4 config file ${missing} (ENOENT)` });
    assert.equal(resolveKnowbe4Configuration({ api_token: "t" }, {}, base, base).apiToken, "t");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("config loader errors: a SyntaxError raised by the transport is recorded by name only, never by the parser's message that quotes the body", async () => {
  const snippet = `<html>${KB_PARSER_SNIPPET_CANARY}</html>`;
  const client = new Knowbe4ApiClient(sampleConfig(), {
    fetchImpl: async () => { throw new SyntaxError(`Unexpected token '<', "${snippet}"... is not valid JSON`); },
    minRequestIntervalMs: 0,
    maxRetries: 0,
  });
  await assert.rejects(() => client.getAccount(), (error) => {
    assert.equal(error.message, "KnowBe4 request failed: GET /v1/account: SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body");
    assert.equal(error.status, null);
    return true;
  });
  const access = await checkKnowbe4Access(client);
  assertCanaryWindowsAbsent(assert, JSON.stringify(access), [KB_PARSER_SNIPPET_CANARY], "check_access");
  assert.ok(access.surfaces.every((surface) => surface.status !== "readable" || surface.name === "phisher_messages"));
  const snapshot = await collectKnowbe4Snapshot(client, { scopes: ["risk"], now: NOW });
  assert.ok(snapshot.errors.length > 0 && snapshot.errors.every((text) => text.includes("SyntaxError: response could not be parsed as JSON")), snapshot.errors.join("\n"));
  assertCanaryWindowsAbsent(assert, JSON.stringify(snapshot), [KB_PARSER_SNIPPET_CANARY], "snapshot");
});

// ---------------------------------------------------------------------------------------------------------------
// Scrub boundary: fixed message text and every string a run records about legitimate data survive the scrubber.
// ---------------------------------------------------------------------------------------------------------------

/** Every fixed-text message the KnowBe4 integration emits that a fixture run does not already produce. */
const KB_FIXED_TEXT_MESSAGES = [
  "Unable to read KnowBe4 config file /home/auditor/.knowbe4-inspector/config.yaml (ENOENT)",
  "Unable to read KnowBe4 config file /home/auditor/.knowbe4-inspector/config.yaml (EACCES)",
  "Unable to parse KnowBe4 config file: invalid YAML in /home/auditor/.knowbe4-inspector/config.yaml at line 3",
  "Unable to parse KnowBe4 config file: invalid YAML in /home/auditor/.knowbe4-inspector/config.yaml",
  "KnowBe4 Reporting API token is required. Pass api_token, set KNOWBE4_API_TOKEN, or add api_token to ~/.knowbe4-inspector/config.yaml.",
  'Unsupported KnowBe4 region "mars". Use one of: us, eu, ca, uk, de.',
  "502 Bad Gateway: non-JSON body (text/html, 5120 bytes, not echoed)",
  "403 Forbidden: JSON body without a documented error field (64 bytes, not echoed)",
  "KnowBe4 request failed (502 Bad Gateway) GET /v1/groups: 502 Bad Gateway: non-JSON body (text/html, 5120 bytes, not echoed)",
  "KnowBe4 request failed (403 Forbidden) GET /v1/training/store_purchases: Forbidden; see https://api.example.com/v1/x?[REDACTED] for details",
  "KnowBe4 request timed out after 30000ms: GET /v1/users?page=1&per_page=500",
  "KnowBe4 request failed: GET /v1/account: SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
  "Using KnowBe4 region us (https://us.api.knowbe4.com).",
  "Regenerate the Reporting API key in the KnowBe4 console (Account Settings, API section) and confirm the region matches where the account is hosted.",
  "Config precedence resolved from: environment-api-token -> config-region -> config-file-present.",
  "Account Settings > API: the Reporting API key's creation date and the admin who owns it",
  "Users > Groups: membership of every console group targeted by a phishing or training campaign",
  JSON.stringify({ collected: false, status: "not-collected", endpoint: null, error: null, reason: "not_requested" }),
  JSON.stringify({ collected: false, status: 403, endpoint: "GET /v1/groups", error: "KnowBe4 request failed (403 Forbidden) GET /v1/groups: Forbidden", reason: "not_readable" }),
];

test("scrub boundary: every fixed-text message the KnowBe4 integration emits survives its own scrubber unchanged, including every string a healthy or partially denied run records", async () => {
  for (const message of KB_FIXED_TEXT_MESSAGES) {
    assert.equal(scrubErrorText(message), message, `fixed text was altered by the scrubber: ${message}`);
  }

  // Every string a run writes about legitimate data is fixed text from the run's point of view: the scrubber must not
  // rewrite a finding summary, a manual-evidence instruction, an inventory gap, or a bundle document. The principal
  // fixture is used so every named user, group, campaign, and test the run can mention is part of the sweep.
  const runs = [httpKnowbe4(principalFixture())];
  for (const denial of KB_SINGLE_INVENTORY_DENIALS) {
    const fixture = principalFixture();
    runs.push(httpKnowbe4(fixture, { routes: { [denial.route]: denyDataset(kbRoutes(fixture), denial) } }));
  }
  let checked = 0;
  const altered = new Set();
  for (const { client, config } of runs) {
    const access = await checkKnowbe4Access(client);
    const assessments = await runAllKnowbe4Assessments(client);
    const exported = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-scrub-survival-"), { now: NOW });
    const files = readBundleFiles(exported.outputDir);
    const texts = [
      ...kbRecordedErrorStrings(access, assessments, files),
      ...[...files].filter(([name]) => !name.startsWith("core_data/")).map(([, text]) => text),
      ...leafEntries(assessments).map(([, value]) => value).filter((value) => typeof value === "string"),
    ];
    checked += texts.length;
    for (const alteration of scrubAlterations(texts, scrubErrorText)) altered.add(alteration);
  }
  assert.ok(checked > 2000, `expected thousands of recorded strings, got ${checked}`);
  assert.deepEqual([...altered], [], `legitimate run text altered by the scrubber:\n${[...altered].join("\n")}`);
});

// ---------------------------------------------------------------------------------------------------------------
// Review round 1: base URL userinfo, scrub before the detail cut, silent success.
// ---------------------------------------------------------------------------------------------------------------

const KB_USERINFO_PASSWORD = "Wq7pLz3KfR9vT2mXc8NbH4yJ";

test("rule 9: a user:password@ userinfo in the base URL is dropped at resolution and its password reaches no surface, request label, or bundle file", async () => {
  const config = resolveKnowbe4Configuration(
    { base_url: `https://audit:${KB_USERINFO_PASSWORD}@us.api.knowbe4.com/` },
    { KNOWBE4_API_TOKEN: KB_TEST_TOKEN, KNOWBE4_REGION: "us" },
    createTempBase("grclanker-knowbe4-userinfo-home-"),
  );
  assert.equal(config.baseUrl, "https://us.api.knowbe4.com", "scheme and host only");
  assertCanaryWindowsAbsent(assert, JSON.stringify(config), [KB_USERINFO_PASSWORD], "resolved configuration");

  // Every read fails with a body that echoes the request URL with its userinfo, the way a proxy would.
  const fixture = healthyFixture();
  const routes = Object.fromEntries(Object.keys(kbRoutes(fixture)).map((route) => [route, () => jsonResponse({ message: `denied for https://audit:${KB_USERINFO_PASSWORD}@us.api.knowbe4.com/v1/users` }, { status: 403, statusText: "Forbidden" })]));
  const { client, log } = httpKnowbe4(fixture, { routes, config: { baseUrl: config.baseUrl } });
  const access = await checkKnowbe4Access(client);
  const assessments = await runAllKnowbe4Assessments(client);
  const exported = await exportKnowbe4AuditBundle(client, client.getResolvedConfig(), createTempBase("grclanker-knowbe4-userinfo-"), { now: NOW });
  const files = readBundleFiles(exported.outputDir);
  assert.ok(log.length > 0 && log.every((entry) => !entry.url.includes("@")), "no request carried the userinfo");
  assertCanaryWindowsAbsent(assert, JSON.stringify(access), [KB_USERINFO_PASSWORD], "check_access result");
  assertCanaryWindowsAbsent(assert, JSON.stringify(assessments), [KB_USERINFO_PASSWORD], "assess results");
  for (const [name, text] of files) assertCanaryWindowsAbsent(assert, text, [KB_USERINFO_PASSWORD], `bundle file ${name}`);
  for (const [name, text] of readZipEntries(exported.zipPath)) assertCanaryWindowsAbsent(assert, text, [KB_USERINFO_PASSWORD], `zip entry ${name}`);
});

test("rule 9: a configured token straddling the 300-character error detail cut is scrubbed at full length before the cut, so no fragment survives", async () => {
  for (const offset of [290, 295, 299, 300]) {
    const message = `${"denied ".repeat(60).slice(0, offset)}${KB_TEST_TOKEN} was rejected by the Reporting API`;
    const { client } = httpKnowbe4(healthyFixture(), { routes: { "GET /v1/users": () => jsonResponse({ message }, { status: 403, statusText: "Forbidden" }) } });
    await assert.rejects(() => client.listUsers(), (error) => {
      assertCanaryWindowsAbsent(assert, error.message, [KB_TEST_TOKEN], `detail cut at offset ${offset}`);
      assert.match(error.message, /^KnowBe4 request failed \(403 Forbidden\) GET \/v1\/users: denied /, "the documented message is still quoted up to the cut");
      assert.ok(error.message.length <= 120 + MAX_KB_DETAIL, `the detail is still cut (${error.message.length} characters)`);
      return true;
    });
  }
});
const MAX_KB_DETAIL = 300;

const KB_SILENT_BODIES = [
  ["empty", () => new Response("", { status: 200, statusText: "OK" }), /returned 200 OK with an empty body \(0 bytes\)/],
  ["html", () => new Response("<html><body>Sign in to KnowBe4</body></html>", { status: 200, statusText: "OK", headers: { "content-type": "text/html" } }), /returned a 200 OK: non-JSON body \(text\/html, \d+ bytes, not echoed\)/],
  ["foreign", () => jsonResponse({ status: "ok", service: "status-page" }), /returned 200 OK with a JSON body that is not the documented JSON array \(\d+ bytes, not echoed\)/],
];

test("silent success: a 2xx whose body is empty, an HTML page, or JSON of another shape is a failed read with http_status 200, a marker in core_data, and manual dependents, never an empty inventory", async () => {
  const healthy = httpKnowbe4(healthyFixture());
  const baselineExport = await exportKnowbe4AuditBundle(healthy.client, healthy.config, createTempBase("grclanker-knowbe4-silent-baseline-"), { now: NOW });
  const baseline = JSON.parse(readBundleFiles(baselineExport.outputDir).get("analysis/findings.json"));
  for (const [kind, body, expected] of KB_SILENT_BODIES) {
    const fixture = healthyFixture();
    const { client, config, log } = httpKnowbe4(fixture, { routes: { "GET /v1/users": body } });
    const label = `users served a ${kind} 200`;
    const access = await checkKnowbe4Access(client);
    const usersSurface = access.surfaces.find((surface) => /users/i.test(surface.name) || /\/v1\/users/.test(surface.endpoint ?? ""));
    assert.ok(usersSurface, `${label}: an access surface reads /v1/users`);
    assert.equal(usersSurface.status, "not_readable", `${label}: the surface is not readable`);
    assert.match(usersSurface.error, expected, label);
    assert.equal(usersSurface.http_status, 200, `${label}: the observed status is the 200 the server sent`);

    const exported = await exportKnowbe4AuditBundle(client, config, createTempBase("grclanker-knowbe4-silent-"), { now: NOW });
    const files = readBundleFiles(exported.outputDir);
    const status = JSON.parse(files.get("core_data/collection_status.json"));
    const row = status.inventories.find((entry) => entry.inventory === "users");
    assert.deepEqual({ status: row.status, collected: row.collected, readable: row.readable, http_status: row.http_status, complete: row.complete, truncated: row.truncated, seen: row.seen }, { status: "not_readable", collected: false, readable: false, http_status: 200, complete: null, truncated: null, seen: null }, label);
    const written = JSON.parse(files.get("core_data/users_active.json"));
    assert.deepEqual({ collected: written.collected, status: written.status, reason: written.reason }, { collected: false, status: 200, reason: "not_readable" }, `${label}: core_data carries a marker, not []`);
    assert.match(written.error, expected, label);

    // Against the all-readable baseline, a finding may only move to manual or warn; the reviewer's false fails
    // (KNOWBE4-01/02/09/20 and KNOWBE4-16 on unobserved data) go manual.
    const findings = JSON.parse(files.get("analysis/findings.json"));
    for (const finding of findings) {
      const before = baseline.find((item) => item.control === finding.control);
      if (before.status === finding.status) continue;
      assert.ok(["manual", "warn"].includes(finding.status), `${label}: KNOWBE4-${finding.control} moved ${before.status} -> ${finding.status}; only manual or warn may follow an unobserved read: ${finding.summary}`);
    }
    const moved = findings.filter((finding) => baseline.find((item) => item.control === finding.control).status !== finding.status);
    assert.ok(moved.length >= 3, `${label}: the user-dependent findings demote (${moved.length} moved)`);
    assert.ok(log.some((entry) => entry.path === "/v1/users" && entry.status === 200), `${label}: the 200 was observed`);

    // Every endpoint silent: nothing was observed, so no finding may pass or fail; the reviewer's false fails
    // (KNOWBE4-01/02/09/20 on empty lists, KNOWBE4-16 on an unobserved account) are manual.
    const silentRoutes = Object.fromEntries(Object.keys(kbRoutes(healthyFixture())).map((route) => [route, body]));
    const allSilent = httpKnowbe4(healthyFixture(), { routes: silentRoutes });
    const allExport = await exportKnowbe4AuditBundle(allSilent.client, allSilent.config, createTempBase("grclanker-knowbe4-silent-all-"), { now: NOW });
    const allFiles = readBundleFiles(allExport.outputDir);
    const allFindings = JSON.parse(allFiles.get("analysis/findings.json"));
    for (const finding of allFindings) {
      assert.equal(finding.status, "manual", `${label} on every endpoint: KNOWBE4-${finding.control} is ${finding.status}: ${finding.summary}`);
    }
    const allStatus = JSON.parse(allFiles.get("core_data/collection_status.json"));
    for (const row of allStatus.inventories) {
      if (row.status === "not_configured" || row.status === "not_requested") continue;
      assert.deepEqual({ status: row.status, http_status: row.http_status, seen: row.seen }, { status: "not_readable", http_status: 200, seen: null }, `${label} on every endpoint: ${row.inventory}`);
    }
  }

  // A single resource (the account) and the PhishER GraphQL endpoint apply the same guard with their own documented shapes.
  const account = httpKnowbe4(healthyFixture(), { routes: { "GET /v1/account": () => jsonResponse({}) } });
  await assert.rejects(() => account.client.getAccount(), /returned 200 OK with a JSON body that is not the documented JSON object \(one of name, type, domains, admins, subscription_level, subscription_end_date, number_of_seats, current_risk_score\) \(\d+ bytes, not echoed\)/);
  const phisher = httpKnowbe4(healthyFixture(), { routes: { [KB_PHISHER_ROUTE]: () => jsonResponse({ hello: "world" }) } });
  await assert.rejects(() => phisher.client.graphql("query { x }"), /returned 200 OK with a JSON body that is not the documented GraphQL response object \(data or errors\) \(\d+ bytes, not echoed\)/);
});
