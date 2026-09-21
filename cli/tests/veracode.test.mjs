import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  VeracodeApiClient,
  VERACODE_CONTROLS,
  assessVeracodeAccessControls,
  assessVeracodeFindingsHygiene,
  assessVeracodePolicyCompliance,
  assessVeracodeScaPosture,
  assessVeracodeScanCoverage,
  buildVeracodeAuthorizationHeader,
  checkVeracodeAccess,
  computeVeracodeSignature,
  exportVeracodeAuditBundle,
  parseIniProfiles,
  resolveSecureOutputPath,
  resolveVeracodeConfiguration,
} from "../dist/extensions/grc-tools/veracode.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const NOW = new Date("2026-09-21T12:00:00Z");
const API_ID = "dbb6f2a2ed0b6890bbd32e949f72c8c8";
const API_SECRET = "530da152f87e5530c82f786907fbc74b09a6894785a78bab3891632ba69325400a40713bdc11d2a6d2d1c3969431281c0a73f455a53c0ed5ea0756e9c54f366c";

function daysAgo(days) {
  return new Date(NOW.getTime() - days * 86_400_000).toISOString();
}

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    apiKeyId: API_ID,
    apiKeySecret: API_SECRET,
    region: "us",
    baseUrl: "https://api.veracode.com",
    timeoutMs: 30000,
    retries: 2,
    profile: "default",
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: { "content-type": "application/json" },
  });
}

function list(items, extra = {}) {
  return { items, pagesFetched: 1, totalPages: 1, totalElements: items.length, complete: true, ...extra };
}

function forbidden(path) {
  const error = new Error(`Veracode request failed (403 Forbidden) for ${path}`);
  error.name = "VeracodeApiError";
  error.statusCode = 403;
  return error;
}

function healthyFixture() {
  const applications = [
    {
      guid: "app-1",
      last_completed_scan_date: daysAgo(5),
      profile: {
        name: "Payments",
        business_criticality: "VERY_HIGH",
        business_unit: { name: "Finance" },
        upload_and_scan_sca_enabled: true,
        policies: [{ guid: "pol-1", name: "Custom Policy", is_default: false, policy_compliance_status: "PASSED" }],
        teams: [{ team_id: 1, team_name: "Team A", guid: "t1" }],
      },
      scans: [{ scan_type: "STATIC", status: "PUBLISHED", modified_date: daysAgo(5) }],
    },
    {
      guid: "app-2",
      last_completed_scan_date: daysAgo(10),
      profile: {
        name: "Portal",
        business_criticality: "HIGH",
        business_unit: { name: "Finance" },
        upload_and_scan_sca_enabled: false,
        policies: [{ guid: "pol-1", name: "Custom Policy", is_default: false, policy_compliance_status: "PASSED" }],
        teams: [{ team_id: 1, team_name: "Team A", guid: "t1" }],
      },
      scans: [{ scan_type: "STATIC", status: "PUBLISHED", modified_date: daysAgo(10) }],
    },
  ];
  return {
    applications,
    policies: [{
      guid: "pol-1",
      name: "Custom Policy",
      type: "CUSTOMER",
      finding_rules: [{ type: "MAX_SEVERITY", scan_type: ["STATIC"], value: "4" }],
      scan_frequency_rules: [{ scan_type: "STATIC", frequency: "MONTHLY" }],
      sev5_grace_period: 30,
      sev4_grace_period: 60,
    }],
    sandboxes: [{ guid: "sb-1", name: "dev", created: daysAgo(40), modified: daysAgo(3) }],
    findings: [{
      issue_id: 101,
      scan_type: "STATIC",
      violates_policy: false,
      finding_status: { status: "OPEN", resolution: "UNRESOLVED", resolution_status: "NONE", first_found_date: daysAgo(5), last_seen_date: daysAgo(1), new: false },
      finding_details: { severity: 5, cwe: { id: 80, name: "XSS" } },
      annotations: [],
    }],
    summaryReport: {
      policy_compliance_status: "Pass",
      static_analysis: { published_date: daysAgo(5), modules: { module: [{ name: "app.jar", loc: 20000, numflawssev5: 1, numflawssev4: 0 }] } },
    },
    workspaces: [{ id: "ws-1", name: "Workspace A", projects_count: 1 }],
    vulnerabilityIssues: [],
    licenseIssues: [],
    libraries: [{ id: "lib-1", name: "lodash", version: "4.17.21", latest_version: "4.17.21" }],
    scaProjects: { application: { guid: "app-2", name: "Portal" }, linked_projects: [{ id: "proj-1", site_id: "12345", name: "portal", last_scan_date: daysAgo(4), languages: ["JAVA"], workspace: { id: "ws-1", site_id: "lDDIW5l", name: "Workspace A" } }] },
    analyses: [{ analysis_id: "an-1", name: "Portal DAST", latest_occurrence_status: { status_type: "FINISHED_RESULTS_AVAILABLE" } }],
    scans: [{ scan_id: "scan-1", target_url: "https://portal.example.com", analysis_id: "an-1" }],
    scanConfiguration: { target_url: { url: "https://portal.example.com" }, auth_configuration: { authentications: { FORM: { username: "svc" } } }, crawl_configuration: { disabled: false } },
    users: [
      { user_id: "u-1", user_name: "alice", email_address: "alice@example.com", active: true, login_enabled: true, account_type: "USER", saml_user: true, last_login: daysAgo(3), roles: [{ role_id: "r-admin", role_name: "Administrator" }], teams: [{ team_id: "t1", team_name: "Team A" }] },
      { user_id: "u-2", user_name: "svc-api", active: true, login_enabled: false, account_type: "API", api_user: true, roles: [{ role_id: "r-results", role_name: "Results API" }], teams: [{ team_id: "t1", team_name: "Team A" }] },
    ],
    teams: [{ team_id: "t1", team_name: "Team A", user_count: 2 }],
    roles: [
      { role_id: "r-admin", role_name: "Administrator", ignore_team_restrictions: true },
      { role_id: "r-results", role_name: "Results API", ignore_team_restrictions: false },
    ],
    self: { user_id: "u-2", user_name: "svc-api", roles: [{ role_name: "Results API" }, { role_name: "Administrator" }] },
    credentials: { api_id: "abc123", created_ts: daysAgo(30), expiration_ts: new Date(NOW.getTime() + 300 * 86_400_000).toISOString() },
  };
}

function mockClient(fixture = healthyFixture(), overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getSelf() { return fixture.self; },
    async getSelfApiCredentials() { return fixture.credentials; },
    async listApplications() { return list(fixture.applications); },
    async listSandboxes() { return list(fixture.sandboxes); },
    async listFindings() { return list(fixture.findings); },
    async getSummaryReport() { return fixture.summaryReport; },
    async listPolicies() { return list(fixture.policies); },
    async listUsers() { return list(fixture.users); },
    async listTeams() { return list(fixture.teams); },
    async listRoles() { return list(fixture.roles); },
    async getUserApiCredentials() { return fixture.credentials; },
    async listScaWorkspaces() { return list(fixture.workspaces); },
    async listScaWorkspaceIssues(_id, type) { return list(type === "vulnerability" ? fixture.vulnerabilityIssues : fixture.licenseIssues); },
    async listScaWorkspaceLibraries() { return list(fixture.libraries); },
    async getScaApplicationProjects() { return fixture.scaProjects; },
    async listDynamicAnalyses() { return list(fixture.analyses); },
    async listDynamicAnalysisScans() { return list(fixture.scans); },
    async getDynamicScanConfiguration() { return fixture.scanConfiguration; },
    ...overrides,
  };
}

function forbiddenClient() {
  const reject = (path) => async () => { throw forbidden(path); };
  return mockClient(healthyFixture(), {
    getSelf: reject("/api/authn/v2/users/self"),
    getSelfApiCredentials: reject("/api/authn/v2/api_credentials"),
    listApplications: reject("/appsec/v1/applications"),
    listSandboxes: reject("/appsec/v1/applications/x/sandboxes"),
    listFindings: reject("/appsec/v2/applications/x/findings"),
    getSummaryReport: reject("/appsec/v2/applications/x/summary_report"),
    listPolicies: reject("/appsec/v1/policies"),
    listUsers: reject("/api/authn/v2/users"),
    listTeams: reject("/api/authn/v2/teams"),
    listRoles: reject("/api/authn/v2/roles"),
    getUserApiCredentials: reject("/api/authn/v2/api_credentials/user_id/x"),
    listScaWorkspaces: reject("/srcclr/v3/workspaces"),
    listScaWorkspaceIssues: reject("/srcclr/v3/workspaces/x/issues"),
    listScaWorkspaceLibraries: reject("/srcclr/v3/workspaces/x/libraries"),
    getScaApplicationProjects: reject("/srcclr/v3/applications/x/projects"),
    listDynamicAnalyses: reject("/was/configservice/v1/analyses"),
    listDynamicAnalysisScans: reject("/was/configservice/v1/analyses/x/scans"),
    getDynamicScanConfiguration: reject("/was/configservice/v1/scans/x/configuration"),
  });
}

function emptyClient() {
  const fixture = healthyFixture();
  return mockClient({
    ...fixture,
    applications: [],
    policies: [],
    sandboxes: [],
    findings: [],
    summaryReport: {},
    workspaces: [],
    libraries: [],
    scaProjects: { application: { guid: "app-2", name: "Portal" }, linked_projects: [] },
    analyses: [],
    scans: [],
    users: [],
    teams: [],
    roles: [],
    self: {},
    credentials: {},
  });
}

function partialClient() {
  const fixture = healthyFixture();
  const partialList = (items) => list(items, { pagesFetched: 1, totalPages: 3, totalElements: items.length * 3, complete: false });
  return mockClient(fixture, {
    async listApplications() { return partialList(fixture.applications); },
    async listPolicies() { return partialList(fixture.policies); },
    async listUsers() { return partialList(fixture.users); },
    async listTeams() { return partialList(fixture.teams); },
    async listScaWorkspaces() { return partialList(fixture.workspaces); },
    async listDynamicAnalyses() { return partialList(fixture.analyses); },
  });
}

async function runAllAssessments(client) {
  const results = await Promise.all([
    assessVeracodeScanCoverage(client, { now: NOW }),
    assessVeracodePolicyCompliance(client, {}),
    assessVeracodeFindingsHygiene(client, { now: NOW }),
    assessVeracodeScaPosture(client, {}),
    assessVeracodeAccessControls(client, { now: NOW }),
  ]);
  return results.flatMap((result) => result.findings);
}

function statusOf(findings, number) {
  return findings.find((item) => item.id === `VERACODE-${String(number).padStart(2, "0")}`)?.status;
}

test("resolveVeracodeConfiguration prefers arguments, then environment, then the credentials profile", () => {
  const home = createTempBase("grclanker-veracode-home-");
  mkdirSync(join(home, ".veracode"));
  writeFileSync(join(home, ".veracode", "credentials"), [
    "[default]",
    `veracode_api_key_id = default-id`,
    `veracode_api_key_secret = ${API_SECRET}`,
    "",
    "[production]",
    "veracode_api_key_id = prod-id",
    "veracode_api_key_secret = abcdef",
  ].join("\n"));

  const fromArgs = resolveVeracodeConfiguration({ api_key_id: "arg-id", api_key_secret: "aabb", region: "eu" }, { VERACODE_API_KEY_ID: "env-id", VERACODE_API_KEY_SECRET: "ccdd" }, { homeDir: home });
  assert.equal(fromArgs.apiKeyId, "arg-id");
  assert.equal(fromArgs.apiKeySecret, "aabb");
  assert.equal(fromArgs.baseUrl, "https://api.veracode.eu");
  assert.ok(fromArgs.sourceChain.includes("arguments-api-key-id"));

  const fromEnv = resolveVeracodeConfiguration({}, { VERACODE_API_KEY_ID: "env-id", VERACODE_API_KEY_SECRET: "ccdd", VERACODE_REGION: "us-fed" }, { homeDir: home });
  assert.equal(fromEnv.apiKeyId, "env-id");
  assert.equal(fromEnv.baseUrl, "https://api.veracode.us");
  assert.ok(fromEnv.sourceChain.includes("environment-api-key-secret"));

  const fromFile = resolveVeracodeConfiguration({}, {}, { homeDir: home });
  assert.equal(fromFile.apiKeyId, "default-id");
  assert.equal(fromFile.apiKeySecret, API_SECRET);
  assert.equal(fromFile.baseUrl, "https://api.veracode.com");
  assert.ok(fromFile.sourceChain.some((item) => item.startsWith("credentials-file-api-key-id")));

  const fromProfile = resolveVeracodeConfiguration({}, { VERACODE_API_PROFILE: "production" }, { homeDir: home });
  assert.equal(fromProfile.apiKeyId, "prod-id");
  assert.equal(fromProfile.profile, "production");

  assert.throws(() => resolveVeracodeConfiguration({}, {}, { homeDir: createTempBase("grclanker-veracode-empty-") }), /credentials are required/);
  assert.throws(() => resolveVeracodeConfiguration({ api_key_id: "x", api_key_secret: "aabb", region: "mars" }, {}, { homeDir: home }), /Unknown Veracode region/);
  assert.deepEqual(Object.keys(parseIniProfiles("[a]\nk = v\n; comment\n[b]\nx=y")), ["a", "b"]);
});

test("computeVeracodeSignature matches the documented HMAC-SHA-256 chain and header format", () => {
  const timestampMs = 1700000000000;
  const nonceHex = "0123456789abcdef0123456789abcdef";
  const host = "api.veracode.com";
  const urlPathWithQuery = "/appsec/v1/applications?page=0&size=50";
  const data = `id=${API_ID}&host=${host}&url=${urlPathWithQuery}&method=GET`;
  const keyBytes = Buffer.from(API_SECRET, "hex");
  const encryptedNonce = createHmac("sha256", keyBytes).update(Buffer.from(nonceHex, "hex")).digest();
  const encryptedTimestamp = createHmac("sha256", encryptedNonce).update(String(timestampMs)).digest();
  const signingKey = createHmac("sha256", encryptedTimestamp).update("vcode_request_version_1").digest();
  const expected = createHmac("sha256", signingKey).update(data).digest("hex");

  const actual = computeVeracodeSignature({ apiKeyId: API_ID, apiKeySecret: API_SECRET, host, urlPathWithQuery, method: "get", timestampMs, nonceHex });
  assert.equal(actual, expected);
  assert.match(actual, /^[0-9a-f]{64}$/);

  const header = buildVeracodeAuthorizationHeader({ apiKeyId: API_ID, apiKeySecret: API_SECRET, host, urlPathWithQuery, method: "GET", timestampMs, nonceHex });
  assert.equal(header, `VERACODE-HMAC-SHA-256 id=${API_ID},ts=${timestampMs},nonce=${nonceHex},sig=${expected}`);

  const other = computeVeracodeSignature({ apiKeyId: API_ID, apiKeySecret: API_SECRET, host, urlPathWithQuery: "/appsec/v1/applications", method: "GET", timestampMs, nonceHex });
  assert.notEqual(other, expected);
});

test("VeracodeApiClient signs requests, paginates HAL pages to completion, retries 429, and redacts the secret", async () => {
  const seen = [];
  let attempts = 0;
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    seen.push({ path: url.pathname, page: url.searchParams.get("page"), auth: init.headers.authorization });
    attempts += 1;
    if (attempts === 1) return jsonResponse({ message: "slow down" }, { status: 429 });
    if (url.pathname === "/api/authn/v2/users/self") return jsonResponse({ message: `secret ${API_SECRET} leaked` }, { status: 500 });
    const page = Number(url.searchParams.get("page"));
    return jsonResponse({ _embedded: { applications: [{ guid: `app-${page}` }] }, page: { number: page, size: 100, total_elements: 3, total_pages: 3 } });
  };
  const client = new VeracodeApiClient(sampleConfig({ retries: 1 }), { fetchImpl, sleep: async () => {} });
  const result = await client.listApplications();
  assert.deepEqual(result.items.map((item) => item.guid), ["app-0", "app-1", "app-2"]);
  assert.equal(result.complete, true);
  assert.equal(result.pagesFetched, 3);
  assert.match(seen[0].auth, /^VERACODE-HMAC-SHA-256 id=dbb6f2a2ed0b6890bbd32e949f72c8c8,ts=\d+,nonce=[0-9a-f]{32},sig=[0-9a-f]{64}$/);
  assert.ok(seen.every((item) => item.path === "/appsec/v1/applications"));

  await assert.rejects(() => client.getSelf(), (error) => {
    assert.equal(error.statusCode, 500);
    assert.ok(!error.message.includes(API_SECRET));
    assert.match(error.message, /\[REDACTED\]/);
    return true;
  });

  const truncated = await new VeracodeApiClient(sampleConfig(), { fetchImpl: async (input) => {
    const page = Number(new URL(input).searchParams.get("page"));
    return jsonResponse({ _embedded: { users: [{ user_id: `u-${page}` }] }, page: { number: page, size: 1, totalElements: 5, totalPages: 5 } });
  } }).listUsers({ maxPages: 2 });
  assert.equal(truncated.complete, false);
  assert.equal(truncated.totalPages, 5);
  assert.equal(truncated.items.length, 2);
});

test("checkVeracodeAccess reports healthy access and names missing roles when degraded", async () => {
  const healthy = await checkVeracodeAccess(mockClient());
  assert.equal(healthy.status, "healthy");
  assert.equal(healthy.principal, "svc-api");
  assert.equal(healthy.surfaces.filter((item) => item.status === "readable").length, 9);
  assert.match(healthy.recommendedNextStep, /veracode_assess_scan_coverage/);

  const degraded = await checkVeracodeAccess(mockClient(healthyFixture(), {
    async listUsers() { throw forbidden("/api/authn/v2/users"); },
    async listScaWorkspaces() { throw forbidden("/srcclr/v3/workspaces"); },
  }));
  assert.equal(degraded.status, "limited");
  assert.deepEqual(degraded.missingRoles, ["Administrator"]);
  assert.ok(degraded.notes.some((note) => /sca_workspaces/.test(note)));
});

test("assessments pass on the healthy fixture and register every control exactly once", async () => {
  const findings = await runAllAssessments(mockClient());
  assert.equal(findings.length, VERACODE_CONTROLS.length);
  assert.deepEqual([...new Set(findings.map((item) => item.id))].length, 20);
  const manualControls = findings.filter((item) => item.status === "manual").map((item) => item.id).sort();
  assert.deepEqual(manualControls, ["VERACODE-11", "VERACODE-14", "VERACODE-20"]);
  for (const number of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 16, 17, 18, 19]) {
    assert.equal(statusOf(findings, number), "pass", `control ${number} should pass on healthy fixture`);
  }
  for (const item of findings) {
    assert.equal(item.mappings.length, 8, `${item.id} carries all eight framework mappings`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")));
  }
});

test("assessVeracodeScanCoverage fails on stale scans and failed scan statuses and warns on missing dates", async () => {
  const fixture = healthyFixture();
  fixture.applications[0].last_completed_scan_date = daysAgo(200);
  fixture.applications[0].scans[0].modified_date = daysAgo(200);
  fixture.applications[1].scans = [{ scan_type: "STATIC", status: "ANALYSIS_ERRORS" }];
  fixture.sandboxes = [];
  fixture.scanConfiguration = { auth_configuration: { authentications: {} }, crawl_configuration: { disabled: false } };
  const result = await assessVeracodeScanCoverage(mockClient(fixture), { now: NOW });
  assert.equal(statusOf(result.findings, 1), "fail");
  assert.equal(statusOf(result.findings, 4), "fail");
  assert.equal(statusOf(result.findings, 10), "warn");
  assert.equal(statusOf(result.findings, 13), "fail");
  assert.equal(statusOf(result.findings, 19), "fail");

  const missing = healthyFixture();
  missing.applications[0].last_completed_scan_date = null;
  missing.applications[0].scans = [{ scan_type: "STATIC", status: "PUBLISHED" }];
  const missingResult = await assessVeracodeScanCoverage(mockClient(missing), { now: NOW });
  assert.equal(statusOf(missingResult.findings, 1), "warn");
  assert.match(missingResult.findings.find((item) => item.id === "VERACODE-01").summary, /no modified_date on their published static scan/);
  assert.equal(statusOf(missingResult.findings, 4), "warn");

  const noRecords = healthyFixture();
  noRecords.applications[0].scans = [];
  const noRecordsResult = await assessVeracodeScanCoverage(mockClient(noRecords), { now: NOW });
  assert.equal(statusOf(noRecordsResult.findings, 19), "warn");
  assert.equal(statusOf(noRecordsResult.findings, 1), "fail");

  const noDast = await assessVeracodeScanCoverage(mockClient(healthyFixture(), { async listDynamicAnalyses() { const error = forbidden("/was/configservice/v1/analyses"); error.statusCode = 404; throw error; } }), { now: NOW });
  assert.equal(statusOf(noDast.findings, 13), "manual");
  assert.match(noDast.findings.find((item) => item.id === "VERACODE-13").summary, /not applicable/);
});

test("assessVeracodeScanCoverage judges control 1 on published static scans rather than the scan-type agnostic date", async () => {
  const dastOnly = healthyFixture();
  dastOnly.applications[1].scans = [{ scan_type: "DYNAMIC", status: "PUBLISHED", modified_date: daysAgo(3) }];
  dastOnly.applications[1].last_completed_scan_date = daysAgo(3);
  const result = await assessVeracodeScanCoverage(mockClient(dastOnly), { now: NOW });
  assert.equal(statusOf(result.findings, 1), "fail");
  const finding1 = result.findings.find((item) => item.id === "VERACODE-01");
  assert.match(finding1.summary, /expose no static scan at all/);
  assert.deepEqual(finding1.evidence.applications_without_static_scan[0].scan_types_present, ["DYNAMIC"]);

  const inProgress = healthyFixture();
  inProgress.applications[1].scans = [{ scan_type: "STATIC", status: "IN_PROGRESS", modified_date: daysAgo(1) }];
  const inProgressResult = await assessVeracodeScanCoverage(mockClient(inProgress), { now: NOW });
  assert.equal(statusOf(inProgressResult.findings, 1), "warn");
  assert.match(inProgressResult.findings.find((item) => item.id === "VERACODE-01").summary, /not in a published status/);

  const staleStatic = healthyFixture();
  staleStatic.applications[1].scans = [
    { scan_type: "STATIC", status: "PUBLISHED", modified_date: daysAgo(120) },
    { scan_type: "DYNAMIC", status: "PUBLISHED", modified_date: daysAgo(2) },
  ];
  staleStatic.applications[1].last_completed_scan_date = daysAgo(2);
  const staleResult = await assessVeracodeScanCoverage(mockClient(staleStatic), { now: NOW });
  assert.equal(statusOf(staleResult.findings, 1), "fail");
  assert.equal(staleResult.findings.find((item) => item.id === "VERACODE-01").evidence.stale_applications[0].days_since_published_static_scan, 120);
});

test("assessVeracodePolicyCompliance flags failing, unassigned, and default policies", async () => {
  const fixture = healthyFixture();
  fixture.applications[0].profile.policies = [{ guid: "pol-builtin", name: "Veracode Recommended", is_default: true, policy_compliance_status: "DID_NOT_PASS" }];
  fixture.applications[1].profile.policies = [];
  fixture.policies = [{ guid: "pol-builtin", name: "Veracode Recommended", type: "BUILTIN", finding_rules: [] }];
  const result = await assessVeracodePolicyCompliance(mockClient(fixture));
  assert.equal(statusOf(result.findings, 2), "fail");
  assert.equal(statusOf(result.findings, 15), "fail");
  assert.equal(statusOf(result.findings, 20), "manual");

  const conditional = healthyFixture();
  conditional.applications[0].profile.policies[0].policy_compliance_status = "CONDITIONAL_PASS";
  conditional.applications[1].profile.policies[0].policy_compliance_status = "NOT_ASSESSED";
  const conditionalResult = await assessVeracodePolicyCompliance(mockClient(conditional));
  assert.equal(statusOf(conditionalResult.findings, 2), "warn");
});

test("assessVeracodeFindingsHygiene fails on aged flaws, unreviewed mitigations, and density and warns on missing dates", async () => {
  const fixture = healthyFixture();
  fixture.findings = [
    { issue_id: 1, finding_status: { status: "OPEN", resolution: "UNRESOLVED", resolution_status: "NONE", first_found_date: daysAgo(45) }, finding_details: { severity: 5 }, annotations: [] },
    { issue_id: 2, finding_status: { status: "OPEN", resolution: "PROPOSED_FALSE_POSITIVE", resolution_status: "PROPOSED" }, finding_details: { severity: 4 }, annotations: [{ action: "FP", comment: "" }] },
    { issue_id: 3, finding_status: { status: "CLOSED", resolution: "POTENTIAL_FALSE_POSITIVE", resolution_status: "APPROVED" }, finding_details: { severity: 3 }, annotations: [{ action: "FP", comment: "Encoded input" }] },
  ];
  fixture.summaryReport = { static_analysis: { modules: { module: [{ loc: 1000, numflawssev5: 3, numflawssev4: 2 }] } } };
  const result = await assessVeracodeFindingsHygiene(mockClient(fixture), { now: NOW });
  assert.equal(statusOf(result.findings, 3), "fail");
  assert.equal(statusOf(result.findings, 12), "fail");
  assert.equal(statusOf(result.findings, 16), "warn");
  assert.equal(statusOf(result.findings, 17), "fail");

  const missing = healthyFixture();
  missing.findings[0].finding_status.first_found_date = null;
  missing.summaryReport = { static_analysis: {} };
  const missingResult = await assessVeracodeFindingsHygiene(mockClient(missing), { now: NOW });
  assert.equal(statusOf(missingResult.findings, 3), "warn");
  assert.equal(statusOf(missingResult.findings, 17), "manual");
});

test("assessVeracodeScaPosture fails on high CVSS and HIGH risk licenses and treats unlicensed SCA as manual", async () => {
  const fixture = healthyFixture();
  fixture.vulnerabilityIssues = [{ id: "i1", issue_type: "vulnerability", severity: 9.8, library: { name: "log4j" }, vulnerability: { cve: "CVE-2021-44228", cvss3_score: 10 } }];
  fixture.licenseIssues = [{ id: "i2", issue_type: "license", license: { name: "GPL-3.0", risk: "HIGH" }, library: { name: "gpl-lib" } }];
  fixture.applications[1].profile.upload_and_scan_sca_enabled = false;
  fixture.scaProjects = { application: { guid: "app-2", name: "Portal" }, linked_projects: [] };
  const result = await assessVeracodeScaPosture(mockClient(fixture));
  assert.equal(statusOf(result.findings, 5), "fail");
  assert.equal(statusOf(result.findings, 6), "fail");
  assert.equal(statusOf(result.findings, 18), "warn");

  const unlicensed = await assessVeracodeScaPosture(mockClient(healthyFixture(), { async listScaWorkspaces() { throw forbidden("/srcclr/v3/workspaces"); } }));
  assert.equal(statusOf(unlicensed.findings, 5), "manual");
  assert.equal(statusOf(unlicensed.findings, 6), "manual");
  assert.match(unlicensed.findings[0].summary, /unlicensed|not applicable/);
});

test("assessVeracodeScaPosture reads linked_projects from the documented LinkedProjects shape for agent-only tenants", async () => {
  const fixture = healthyFixture();
  for (const app of fixture.applications) app.profile.upload_and_scan_sca_enabled = false;
  const result = await assessVeracodeScaPosture(mockClient(fixture));
  assert.equal(statusOf(result.findings, 18), "pass");
  const evidence = result.findings.find((item) => item.id === "VERACODE-18").evidence;
  assert.equal(evidence.covered_applications, 2);
  assert.deepEqual(evidence.linked_projects_by_application.Portal, [{ name: "portal", workspace: "Workspace A", last_scan_date: fixture.scaProjects.linked_projects[0].last_scan_date }]);

  const undocumented = await assessVeracodeScaPosture(mockClient(fixture, { async getScaApplicationProjects() { return { _embedded: { projects: [{ id: "proj-1", name: "portal" }] } }; } }));
  assert.equal(statusOf(undocumented.findings, 18), "warn");
  assert.match(undocumented.findings.find((item) => item.id === "VERACODE-18").summary, /neither upload-and-scan SCA enabled nor a linked SCA agent project/);
});

test("VeracodeApiClient requests users with include_roles and include_teams and teams with all_for_org, recording a refused flag", async () => {
  const requests = [];
  const client = new VeracodeApiClient(sampleConfig(), { fetchImpl: async (input) => {
    const url = new URL(input);
    requests.push(url);
    if (url.pathname === "/api/authn/v2/users") {
      return jsonResponse({ _embedded: { users: [{ user_id: "u-1", roles: [{ role_name: "Administrator" }], teams: [{ team_id: "t1" }] }] }, page: { number: 0, size: 100, total_elements: 1, total_pages: 1 } });
    }
    if (url.pathname === "/api/authn/v2/teams" && url.searchParams.get("all_for_org") === "true") {
      return jsonResponse({ message: "all_for_org is not permitted for this user" }, { status: 403 });
    }
    return jsonResponse({ _embedded: { teams: [{ team_id: "t1", team_name: "Team A" }] }, page: { number: 0, size: 100, total_elements: 1, total_pages: 1 } });
  }, sleep: async () => {} });

  const users = await client.listUsers();
  const usersUrl = requests.find((url) => url.pathname === "/api/authn/v2/users");
  assert.equal(usersUrl.searchParams.get("detailed"), "true");
  assert.equal(usersUrl.searchParams.get("include_roles"), "true");
  assert.equal(usersUrl.searchParams.get("include_teams"), "true");
  assert.deepEqual(users.items[0].roles.map((role) => role.role_name), ["Administrator"]);
  assert.equal(users.items[0].teams.length, 1);

  const teams = await client.listTeams();
  const teamRequests = requests.filter((url) => url.pathname === "/api/authn/v2/teams");
  assert.equal(teamRequests.length, 2);
  assert.equal(teamRequests[0].searchParams.get("all_for_org"), "true");
  assert.equal(teamRequests[1].searchParams.has("all_for_org"), false);
  assert.equal(teams.items.length, 1);
  assert.match(teams.notes[0], /all_for_org=true was refused \(403\)/);

  const accepted = await new VeracodeApiClient(sampleConfig(), { fetchImpl: async (input) => {
    const url = new URL(input);
    assert.equal(url.searchParams.get("all_for_org"), "true");
    return jsonResponse({ _embedded: { teams: [{ team_id: "t1" }, { team_id: "t2" }] }, page: { number: 0, size: 100, total_elements: 2, total_pages: 1 } });
  } }).listTeams();
  assert.equal(accepted.notes, undefined);
  assert.equal(accepted.items.length, 2);

  await assert.rejects(() => new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl: async () => jsonResponse({ message: "boom" }, { status: 500 }), sleep: async () => {} }).listTeams(), (error) => error.statusCode === 500);
});

test("assessVeracodeAccessControls never passes control 7 on a member-only team list", async () => {
  const note = "all_for_org=true was refused (403), so only teams the API user is a member of were listed and the team inventory is a partial view.";
  const memberOnly = await assessVeracodeAccessControls(mockClient(healthyFixture(), { async listTeams() { return list(healthyFixture().teams, { notes: [note] }); } }), { now: NOW });
  assert.equal(statusOf(memberOnly.findings, 7), "warn");
  const finding7 = memberOnly.findings.find((item) => item.id === "VERACODE-07");
  assert.match(finding7.summary, /all_for_org=true was refused/);
  assert.equal(finding7.evidence.teams_scope, "member_only");

  const noMembership = await assessVeracodeAccessControls(mockClient(healthyFixture(), { async listTeams() { return list([], { notes: [note] }); } }), { now: NOW });
  assert.equal(statusOf(noMembership.findings, 7), "manual");
  assert.match(noMembership.findings.find((item) => item.id === "VERACODE-07").summary, /could not be verified/);

  const access = await checkVeracodeAccess(mockClient(healthyFixture(), { async listTeams() { return list(healthyFixture().teams, { notes: [note] }); } }));
  assert.ok(access.notes.some((item) => /all_for_org=true was refused/.test(item)));
});

test("assessVeracodeAccessControls fails on admin sprawl, inactive users, and aged credentials and warns on missing dates", async () => {
  const fixture = healthyFixture();
  fixture.users.push(
    { user_id: "u-3", user_name: "stale", active: true, login_enabled: true, account_type: "USER", saml_user: false, last_login: daysAgo(400), roles: [{ role_name: "Administrator" }], teams: [] },
    { user_id: "u-4", user_name: "orphan-api", active: true, login_enabled: false, account_type: "API", api_user: true, roles: [{ role_name: "Results API" }], teams: [] },
  );
  fixture.credentials = { api_id: "old", created_ts: daysAgo(500), expiration_ts: daysAgo(10) };
  fixture.teams = [];
  const result = await assessVeracodeAccessControls(mockClient(fixture), { now: NOW, maxAdmins: 1 });
  assert.equal(statusOf(result.findings, 7), "fail");
  assert.equal(statusOf(result.findings, 8), "fail");
  assert.equal(statusOf(result.findings, 9), "fail");

  const missing = healthyFixture();
  missing.users[0].last_login = null;
  missing.credentials = { api_id: "nodate" };
  const missingResult = await assessVeracodeAccessControls(mockClient(missing), { now: NOW });
  assert.equal(statusOf(missingResult.findings, 8), "warn");
  assert.equal(statusOf(missingResult.findings, 9), "warn");
});

test("false-pass self-check (a): every endpoint forbidden yields only manual verdicts that name the cause", async () => {
  const findings = await runAllAssessments(forbiddenClient());
  assert.equal(findings.length, 20);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0);
  assert.equal(findings.filter((item) => item.status === "manual").length, 20);
  for (const item of findings) {
    assert.match(item.summary, /Manual evidence required/);
  }
  assert.match(findings.find((item) => item.id === "VERACODE-01").summary, /forbidden \(403\)/);
  assert.match(findings.find((item) => item.id === "VERACODE-08").summary, /forbidden \(403\)/);
});

test("false-pass self-check (b): empty inventories never pass and state why emptiness is not compliant", async () => {
  const findings = await runAllAssessments(emptyClient());
  assert.equal(findings.length, 20);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0);
  assert.equal(findings.filter((item) => item.status === "fail").length, 0);
  assert.equal(findings.filter((item) => item.status === "manual").length, 20);
  assert.match(findings.find((item) => item.id === "VERACODE-01").summary, /zero application profiles/);
  assert.match(findings.find((item) => item.id === "VERACODE-15").summary, /cannot be a complete inventory/);
  assert.match(findings.find((item) => item.id === "VERACODE-05").summary, /not applicable rather than compliant/);
  assert.match(findings.find((item) => item.id === "VERACODE-08").summary, /unverifiable rather than compliant/);
});

test("false-pass self-check (c): partial inventories downgrade every would-be pass to warn with seen and total counts", async () => {
  const findings = await runAllAssessments(partialClient());
  assert.equal(findings.length, 20);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0);
  const warned = findings.filter((item) => item.status === "warn");
  assert.ok(warned.length >= 15, `expected most controls to warn, got ${warned.length}`);
  for (const item of warned) {
    assert.match(item.summary, /Only 2 of 6 applications|Only 1 of 3|partial inventory|partial view/);
  }
  const truncatedFindings = await assessVeracodeFindingsHygiene(mockClient(healthyFixture(), {
    async listFindings() { return list(healthyFixture().findings, { totalPages: 4, complete: false }); },
  }), { now: NOW });
  assert.equal(statusOf(truncatedFindings.findings, 3), "warn");
  assert.match(truncatedFindings.findings[0].summary, /truncated/);
});

test("exportVeracodeAuditBundle writes the layout, logs errors, and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-veracode-export-");
  const client = mockClient(healthyFixture(), { async listScaWorkspaces() { throw forbidden("/srcclr/v3/workspaces"); } });
  const first = await exportVeracodeAuditBundle(client, sampleConfig(), base, { now: NOW });
  assert.ok(existsSync(first.outputDir));
  assert.ok(existsSync(first.zipPath));
  assert.equal(first.findingCount, 20);
  assert.ok(first.errorCount >= 1);
  for (const file of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "_errors.log",
    "core_data/access.json",
    "core_data/scan-coverage.json",
    "core_data/access-controls.json",
    "analysis/findings.json",
    "analysis/scan-coverage.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp.md",
    "compliance/cmmc.md",
    "compliance/soc2.md",
    "compliance/cis-controls-v8.md",
    "compliance/pci-dss.md",
    "compliance/stig.md",
    "compliance/irap.md",
    "compliance/ismap.md",
  ]) {
    assert.ok(existsSync(join(first.outputDir, file)), `${file} should exist`);
  }
  const bundleText = readFileSync(join(first.outputDir, "analysis", "findings.json"), "utf8") + readFileSync(join(first.outputDir, "metadata.json"), "utf8");
  assert.ok(!bundleText.includes(API_SECRET));
  assert.match(readFileSync(join(first.outputDir, "_errors.log"), "utf8"), /sca workspaces/);
  assert.equal(first.zipPath, `${first.outputDir}.zip`);

  const second = await exportVeracodeAuditBundle(mockClient(), sampleConfig(), base, { now: NOW });
  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.ok(existsSync(first.zipPath));
  assert.ok(!existsSync(join(second.outputDir, "_errors.log")));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-veracode-path-");
  const outside = createTempBase("grclanker-veracode-outside-");
  symlinkSync(outside, join(base, "linked"), "dir");
  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  assert.match(resolveSecureOutputPath(base, join("compliance", "safe.md")), /compliance\/safe\.md$/);
});

test("Veracode tools are registered in the tool catalog under the Veracode group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("veracode_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "veracode_assess_access_controls",
    "veracode_assess_findings_hygiene",
    "veracode_assess_policy_compliance",
    "veracode_assess_sca_posture",
    "veracode_assess_scan_coverage",
    "veracode_check_access",
    "veracode_export_audit_bundle",
  ]);
  assert.ok(tools.every((tool) => tool.group === "Veracode" && tool.kind === "domain"));
});
