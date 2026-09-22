import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
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
  registerVeracodeTools,
  resolveSecureOutputPath,
  resolveVeracodeConfiguration,
  scrubErrorText,
} from "../dist/extensions/grc-tools/veracode.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

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

/** Canaries planted on malformed credentials lines; every 8-character window of each is distinct so a partial quote is caught too. */
const CONFIG_CANARIES = {
  bareLine: "Bp6TzX3kW9nQ2sRc",
  unterminatedSection: "Lf9BwD4sN7hVe3Ky",
  readable: "Zx4HnV7qK2mYt9Pw",
};
const LIBRARY_ERROR_WORDING = [
  "Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "no such file",
  "not a directory", "Unexpected token",
];

function fragmentsOf(value, size = 8) {
  const fragments = [];
  for (let index = 0; index + size <= value.length; index += 1) fragments.push(value.slice(index, index + size));
  return fragments;
}

function assertConfigErrorText(text, { path, code, canaries }, label) {
  for (const canary of canaries) {
    for (const fragment of fragmentsOf(canary)) assert.ok(!text.includes(fragment), `${label} carries a fragment (${fragment}) of ${canary}: ${text}`);
  }
  for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!text.includes(wording), `${label} repeats library wording "${wording}": ${text}`);
  assert.ok(text.includes(path), `${label} names the path ${path}: ${text}`);
  if (code) assert.ok(text.includes(`(${code})`), `${label} carries the code ${code}: ${text}`);
  assert.doesNotMatch(text, / at line \d+/, `${label} invents no line: ${text}`);
}

function thrownBy(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail("expected the call to throw");
}

async function withoutVeracodeEnvironment(run) {
  const names = ["VERACODE_API_KEY_ID", "VERACODE_API_KEY_SECRET", "VERACODE_API_CREDENTIALS_FILE", "VERACODE_API_PROFILE"];
  const saved = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  for (const name of names) delete process.env[name];
  try {
    return await run();
  } finally {
    for (const name of names) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  }
}

test("rule 9: Veracode credentials file errors carry only the path and code, never a credentials line or filesystem wording", async () => {
  const dir = createTempBase("grclanker-veracode-config-errors-");
  const registered = [];
  registerVeracodeTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "veracode_check_access");
  const exportBundle = registered.find((tool) => tool.name === "veracode_export_audit_bundle");
  const allCanaries = Object.values(CONFIG_CANARIES);

  const malformed = join(dir, "malformed-credentials");
  writeFileSync(malformed, [
    "[default]",
    `veracode_api_key_id ${CONFIG_CANARIES.bareLine}`,
    `[unterminated ${CONFIG_CANARIES.unterminatedSection}`,
    "veracode_api_key_secret = aabb",
    "",
  ].join("\n"));
  const profiles = parseIniProfiles(readFileSync(malformed, "utf8"));
  assert.equal(profiles.default.veracode_api_key_id, undefined, "a line without = is skipped, not stored under a guessed key");
  const skipped = thrownBy(() => resolveVeracodeConfiguration({ credentials_file: malformed }, {}, { homeDir: dir }));
  assert.match(skipped.message, /^Veracode API credentials are required/);
  assertConfigErrorText(skipped.message, { path: malformed, canaries: allCanaries }, "resolver error for a malformed profile");
  const skippedResult = await withoutVeracodeEnvironment(() => checkAccess.execute("call", checkAccess.prepareArguments({ credentials_file: malformed })));
  assertConfigErrorText(JSON.stringify(skippedResult), { path: malformed, canaries: allCanaries }, "check_access payload for a malformed profile");

  const readCases = [
    { name: "EISDIR", path: join(dir, "directory-credentials"), setup: (path) => mkdirSync(path), control: /illegal operation/ },
    { name: "ENOTDIR", path: join(dir, "plain-file", "credentials"), setup: () => writeFileSync(join(dir, "plain-file"), `[default]\nveracode_api_key_secret = ${CONFIG_CANARIES.readable}\n`), control: /not a directory/ },
  ];
  if (process.getuid?.() !== 0) {
    readCases.push({ name: "EACCES", path: join(dir, "locked-credentials"), setup: (path) => { writeFileSync(path, `[default]\nveracode_api_key_secret = ${CONFIG_CANARIES.readable}\n`); chmodSync(path, 0o000); }, control: /permission denied/ });
  }
  for (const testCase of readCases) {
    testCase.setup(testCase.path);
    assert.match(thrownBy(() => readFileSync(testCase.path, "utf8")).message, testCase.control, `${testCase.name}: positive control uses the filesystem message`);
    const expected = { path: testCase.path, code: testCase.name, canaries: allCanaries };
    const thrown = thrownBy(() => resolveVeracodeConfiguration({ credentials_file: testCase.path }, {}, { homeDir: dir }));
    assert.equal(thrown.message, `Unable to read Veracode credentials file ${testCase.path} (${testCase.name})`);
    assertConfigErrorText(thrown.message, expected, `${testCase.name} resolver error`);
    const fromEnv = thrownBy(() => resolveVeracodeConfiguration({}, { VERACODE_API_CREDENTIALS_FILE: testCase.path }, { homeDir: dir }));
    assert.equal(fromEnv.message, thrown.message, `${testCase.name}: the environment path takes the same guard`);
    const result = await withoutVeracodeEnvironment(() => checkAccess.execute("call", checkAccess.prepareArguments({ credentials_file: testCase.path })));
    assertConfigErrorText(JSON.stringify(result), expected, `${testCase.name} check_access payload`);
  }

  const outputRoot = join(dir, "export");
  const exported = await withoutVeracodeEnvironment(() => exportBundle.execute("call", exportBundle.prepareArguments({ credentials_file: join(dir, "directory-credentials"), output_dir: outputRoot })));
  assertConfigErrorText(JSON.stringify(exported), { path: join(dir, "directory-credentials"), code: "EISDIR", canaries: allCanaries }, "export payload");
  assert.equal(existsSync(outputRoot), false, "a credentials file error writes no bundle");

  const missing = join(dir, "missing-credentials");
  const absent = thrownBy(() => resolveVeracodeConfiguration({ credentials_file: missing }, {}, { homeDir: dir }));
  assert.match(absent.message, /^Veracode API credentials are required/, "a missing credentials file is absent, not a read failure");
  assertConfigErrorText(absent.message, { path: missing, canaries: allCanaries }, "resolver error for a missing file");
  const absentResult = JSON.stringify(await withoutVeracodeEnvironment(() => checkAccess.execute("call", checkAccess.prepareArguments({ credentials_file: missing }))));
  assertConfigErrorText(absentResult, { path: missing, canaries: allCanaries }, "check_access payload for a missing file");
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

test("assessVeracodeScanCoverage applies the business criticality tier to control 4", async () => {
  const fixture = healthyFixture();
  fixture.applications[0].profile.business_criticality = "VERY_HIGH";
  fixture.applications[0].last_completed_scan_date = daysAgo(20);
  fixture.applications[0].scans[0].modified_date = daysAgo(20);
  const weekly = await assessVeracodeScanCoverage(mockClient(fixture), { now: NOW });
  assert.equal(statusOf(weekly.findings, 4), "fail");
  const finding4 = weekly.findings.find((item) => item.id === "VERACODE-04");
  assert.match(finding4.evidence.overdue_applications[0].details[0], /business criticality VERY_HIGH requires a scan every 7 days; the last completed scan was 20 days ago/);
  assert.equal(finding4.evidence.critical_scan_interval_days, 7);

  const relaxed = await assessVeracodeScanCoverage(mockClient(fixture), { now: NOW, criticalScanIntervalDays: 30 });
  assert.equal(statusOf(relaxed.findings, 4), "pass");

  const standard = healthyFixture();
  standard.applications[1].profile.business_criticality = "LOW";
  standard.applications[1].last_completed_scan_date = daysAgo(45);
  standard.applications[1].scans[0].modified_date = daysAgo(45);
  standard.policies[0].scan_frequency_rules = [{ scan_type: "STATIC", frequency: "QUARTERLY" }];
  const standardResult = await assessVeracodeScanCoverage(mockClient(standard), { now: NOW });
  assert.equal(statusOf(standardResult.findings, 4), "fail");
  assert.match(standardResult.findings.find((item) => item.id === "VERACODE-04").evidence.overdue_applications[0].details[0], /business criticality LOW requires a scan every 31 days/);

  const noCriticality = healthyFixture();
  for (const app of noCriticality.applications) delete app.profile.business_criticality;
  noCriticality.policies[0].scan_frequency_rules = [];
  const noRequirement = await assessVeracodeScanCoverage(mockClient(noCriticality), { now: NOW });
  assert.equal(statusOf(noRequirement.findings, 4), "warn");
  assert.match(noRequirement.findings.find((item) => item.id === "VERACODE-04").summary, /neither a policy scan frequency rule nor a business criticality tier/);
});

test("assessVeracodeScanCoverage judges control 4 against the strictest assigned policy and scan type", async () => {
  const fixture = healthyFixture();
  fixture.policies = [
    { guid: "pol-quarterly", name: "Quarterly", type: "CUSTOMER", finding_rules: [{ type: "MAX_SEVERITY", value: "4" }], scan_frequency_rules: [{ scan_type: "STATIC", frequency: "QUARTERLY" }] },
    { guid: "pol-weekly", name: "Weekly", type: "CUSTOMER", finding_rules: [{ type: "MAX_SEVERITY", value: "4" }], scan_frequency_rules: [{ scan_type: "STATIC", frequency: "WEEKLY" }] },
  ];
  for (const app of fixture.applications) {
    app.profile.business_criticality = "MEDIUM";
    app.profile.policies = [
      { guid: "pol-quarterly", name: "Quarterly", is_default: false, policy_compliance_status: "PASSED" },
      { guid: "pol-weekly", name: "Weekly", is_default: false, policy_compliance_status: "PASSED" },
    ];
    app.last_completed_scan_date = daysAgo(20);
    app.scans = [{ scan_type: "STATIC", status: "PUBLISHED", modified_date: daysAgo(20) }];
  }
  const result = await assessVeracodeScanCoverage(mockClient(fixture), { now: NOW });
  assert.equal(statusOf(result.findings, 4), "fail");
  const finding4 = result.findings.find((item) => item.id === "VERACODE-04");
  assert.equal(finding4.evidence.overdue_applications.length, 2);
  assert.match(finding4.evidence.overdue_applications[0].details[0], /policy Weekly \(WEEKLY\) requires a STATIC scan every 7 days; the last published STATIC scan was 20 days ago/);
  assert.deepEqual(finding4.evidence.requirements_by_application.Payments, ["STATIC every 7 days from policy Weekly (WEEKLY)", "ANY every 31 days from business criticality MEDIUM"]);

  const dynamicRule = healthyFixture();
  dynamicRule.policies[0].scan_frequency_rules = [{ scan_type: "STATIC", frequency: "MONTHLY" }, { scan_type: "DYNAMIC", frequency: "QUARTERLY" }, { scan_type: "SCA", frequency: "NOT_REQUIRED" }];
  const dynamicResult = await assessVeracodeScanCoverage(mockClient(dynamicRule), { now: NOW });
  assert.equal(statusOf(dynamicResult.findings, 4), "fail");
  assert.match(dynamicResult.findings.find((item) => item.id === "VERACODE-04").evidence.overdue_applications[0].details[0], /requires a DYNAMIC scan every 92 days but the profile exposes no DYNAMIC scan/);

  const onceRule = healthyFixture();
  onceRule.policies[0].scan_frequency_rules = [{ scan_type: "STATIC", frequency: "ONCE" }];
  const onceResult = await assessVeracodeScanCoverage(mockClient(onceRule), { now: NOW });
  assert.equal(statusOf(onceResult.findings, 4), "pass");
  assert.deepEqual(onceResult.findings.find((item) => item.id === "VERACODE-04").evidence.requirements_by_application.Payments, ["STATIC at least once from policy Custom Policy (ONCE)", "ANY every 7 days from business criticality VERY_HIGH"]);

  const unresolved = healthyFixture();
  unresolved.applications[0].profile.policies.push({ guid: "pol-missing", name: "Unlisted", is_default: false, policy_compliance_status: "PASSED" });
  const unresolvedResult = await assessVeracodeScanCoverage(mockClient(unresolved), { now: NOW });
  assert.equal(statusOf(unresolvedResult.findings, 4), "warn");
  assert.match(unresolvedResult.findings.find((item) => item.id === "VERACODE-04").evidence.unconfirmed_applications[0].details[0], /1 assigned policies were not found/);
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
    { issue_id: 2, finding_status: { status: "OPEN", resolution_status: "PROPOSED" }, finding_details: { severity: 4 }, annotations: [{ action: "FP", comment: "" }] },
    { issue_id: 3, finding_status: { status: "CLOSED", resolution_status: "APPROVED" }, finding_details: { severity: 3 }, annotations: [{ action: "FP", comment: "Encoded input" }, { action: "APPROVED", comment: "Reviewed" }] },
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

test("assessVeracodeFindingsHygiene counts false positives from FP annotations and keeps resolution as evidence only", async () => {
  const fixture = healthyFixture();
  fixture.findings = [
    { issue_id: 1, finding_status: { status: "OPEN", resolution: "POTENTIAL_FALSE_POSITIVE", resolution_status: "NONE", first_found_date: daysAgo(2) }, finding_details: { severity: 3 }, annotations: [] },
    { issue_id: 2, finding_status: { status: "OPEN", resolution: "POTENTIAL_FALSE_POSITIVE", resolution_status: "NONE", first_found_date: daysAgo(2) }, finding_details: { severity: 3 }, annotations: [{ action: "COMMENT", comment: "triage note" }] },
  ];
  const withoutFp = await assessVeracodeFindingsHygiene(mockClient(fixture), { now: NOW });
  assert.equal(statusOf(withoutFp.findings, 16), "pass");
  const evidence = withoutFp.findings.find((item) => item.id === "VERACODE-16").evidence;
  assert.equal(evidence.per_application[0].fp_annotated_findings, 0);
  assert.deepEqual(evidence.per_application[0].resolution_values, { POTENTIAL_FALSE_POSITIVE: 2 });
  assert.match(evidence.signal, /annotations\[\]\.action FP/);

  fixture.findings[0].annotations = [{ action: "FP", comment: "Not exploitable", created: daysAgo(1) }, { action: "APPROVED", comment: "Agreed", created: daysAgo(1) }];
  const withFp = await assessVeracodeFindingsHygiene(mockClient(fixture), { now: NOW });
  assert.equal(statusOf(withFp.findings, 16), "warn");
  const fpEvidence = withFp.findings.find((item) => item.id === "VERACODE-16").evidence;
  assert.equal(fpEvidence.applications_exceeding[0].rate_percent, 50);
  assert.equal(fpEvidence.per_application[0].fp_approved_findings, 1);
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

  const projectRequests = [];
  const unlicensed = await assessVeracodeScaPosture(mockClient(healthyFixture(), {
    async listScaWorkspaces() { throw forbidden("/srcclr/v3/workspaces"); },
    async getScaApplicationProjects(guid) { projectRequests.push(guid); return { linked_projects: [] }; },
  }));
  assert.equal(statusOf(unlicensed.findings, 5), "manual");
  assert.equal(statusOf(unlicensed.findings, 6), "manual");
  assert.match(unlicensed.findings[0].summary, /unlicensed|not applicable/);

  const coverage = unlicensed.findings.find((item) => item.id === "VERACODE-18");
  assert.deepEqual(projectRequests, [], "no linked project list is requested while the SCA Agent API is unreadable");
  assert.equal(coverage.status, "warn");
  assert.equal(coverage.summary, "1/2 sampled applications have no upload-and-scan SCA and their linked SCA agent projects were not checked because the SCA Agent API workspace list was forbidden (403), so their coverage is unknown.");
  assert.doesNotMatch(coverage.summary, /neither upload-and-scan SCA enabled nor a linked SCA agent project/, "an unchecked application is never reported as uncovered");
  assert.equal(coverage.evidence.uncovered_applications, null, "the uncovered set was never determined");
  assert.deepEqual(coverage.evidence.unchecked_applications, ["Portal"]);
  assert.deepEqual(coverage.evidence.unreadable_applications, []);
  assert.equal(coverage.evidence.linked_projects_by_application, null);
  assert.equal(coverage.evidence.covered_applications, 1);
  assert.equal(coverage.evidence.sca_agent_api_available, false);
  assert.equal(coverage.evidence.sca_agent_api_status, 403);
  assert.equal(unlicensed.rawData.sca_projects_by_application.collected, false);
  assert.match(unlicensed.rawData.sca_projects_by_application.error, /^Not requested: the SCA Agent API was not readable/);

  const projectsDenied = await assessVeracodeScaPosture(mockClient(healthyFixture(), { async getScaApplicationProjects() { throw forbidden("/srcclr/v3/applications/app-2/projects"); } }));
  const denied = projectsDenied.findings.find((item) => item.id === "VERACODE-18");
  assert.equal(denied.status, "warn");
  assert.deepEqual(denied.evidence.unreadable_applications, ["Portal"], "a failed per-application request is unreadable, not uncovered");
  assert.deepEqual(denied.evidence.uncovered_applications, [], "a readable Agent API with every list read leaves the uncovered set determined and empty");
  assert.deepEqual(denied.evidence.unchecked_applications, []);
  assert.equal(denied.evidence.sca_agent_api_status, null);
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

const FAKE_SECRETS = {
  customFieldToken: "FAKE_CUSTOM_FIELD_TOKEN_1",
  customFieldJwtPayload: "FAKE_JWT_PAYLOAD_1",
  repoUserinfoToken: "FAKE_REPO_TOKEN_1",
  repoQueryToken: "FAKE_REPO_QUERY_TOKEN_1",
  dastPassword: "FAKE_DAST_PASSWORD_1",
  loginScript: "FAKE_LOGIN_SCRIPT_BODY_1",
  clientCertificate: "FAKE_CLIENT_CERTIFICATE_1",
  certificatePassword: "FAKE_CERT_PASSWORD_1",
  crawlScript: "FAKE_CRAWL_SCRIPT_BODY_1",
  configurationSession: "FAKE_SESSION_TOKEN_1",
  scanListSession: "FAKE_SESSION_TOKEN_2",
  scanRequestPassword: "FAKE_SCAN_REQUEST_PASSWORD_1",
  apiSecret: "FAKE_API_SECRET_1",
};

/** Every collected object that can carry a credential per the vendor API carries a distinctive fake one. */
function secretFixture() {
  const fixture = healthyFixture();
  fixture.applications[0].profile.custom_fields = [
    { name: "Deploy API Token", value: FAKE_SECRETS.customFieldToken },
    { name: "ci_session", value: `eyJhbGciOiJIUzI1NiJ9.${FAKE_SECRETS.customFieldJwtPayload}.FAKE_JWT_SIGNATURE_1` },
  ];
  fixture.applications[0].profile.git_repo_url = `https://svc:${FAKE_SECRETS.repoUserinfoToken}@git.example.com/org/payments.git`;
  fixture.applications[1].profile.git_repo_url = `https://git.example.com/org/portal.git?access_token=${FAKE_SECRETS.repoQueryToken}`;
  fixture.scans = [{
    scan_id: "scan-1",
    analysis_id: "an-1",
    target_url: `https://portal.example.com/?sid=${FAKE_SECRETS.scanListSession}`,
    scan_config_request: { auth_configuration: { authentications: { AUTO: { username: "svc", password: FAKE_SECRETS.scanRequestPassword } } } },
  }];
  fixture.scanConfiguration = {
    target_url: { url: `https://portal.example.com/login?session=${FAKE_SECRETS.configurationSession}` },
    auth_configuration: {
      authentications: {
        AUTO: { username: "svc", password: FAKE_SECRETS.dastPassword },
        FORM: { login_script_data: { script_body: FAKE_SECRETS.loginScript } },
        CERT: { client_certificate: FAKE_SECRETS.clientCertificate, password: FAKE_SECRETS.certificatePassword },
      },
    },
    crawl_configuration: { disabled: true, crawl_script_data: { script_body: FAKE_SECRETS.crawlScript } },
    scan_setting: { allowed_hosts: [{ url: "https://portal.example.com" }] },
  };
  fixture.credentials = { ...fixture.credentials, api_secret: FAKE_SECRETS.apiSecret };
  return fixture;
}

test("rule 9: the exported bundle, the zip, the assess payloads, and the access check never carry custom field tokens, repository tokens, DAST credentials, login scripts, or API secrets", async () => {
  const base = createTempBase("grclanker-veracode-secrets-");
  const client = mockClient(secretFixture(), { async listSandboxes() { throw forbidden("/appsec/v1/applications/app-1/sandboxes"); } });
  const secrets = [...Object.values(FAKE_SECRETS), API_SECRET];

  const result = await exportVeracodeAuditBundle(client, sampleConfig(), base, { now: NOW });
  const files = readBundleFiles(result.outputDir);
  for (const file of ["core_data/scan-coverage.json", "core_data/access-controls.json", "core_data/access.json", "analysis/findings.json", "analysis/summary.md", "_errors.log"]) {
    assert.ok(files.has(file), `${file} should exist`);
  }
  assertSecretsAbsent(assert, files, secrets, "bundle files");
  assertSecretsAbsent(assert, readZipEntries(result.zipPath), secrets, "zip entries");

  const access = await checkVeracodeAccess(client);
  const payloads = await Promise.all([
    assessVeracodeScanCoverage(client, { now: NOW }),
    assessVeracodePolicyCompliance(client, {}),
    assessVeracodeFindingsHygiene(client, { now: NOW }),
    assessVeracodeScaPosture(client, {}),
    assessVeracodeAccessControls(client, { now: NOW }),
  ]);
  const toolPayloads = JSON.stringify([access, ...payloads.map((item) => ({ title: item.title, summary: item.summary, findings: item.findings, errors: item.errors }))]);
  for (const secret of secrets) {
    assert.ok(!toolPayloads.includes(secret), `${secret} must not appear in the tool payloads`);
  }

  const fileNamed = (name) => JSON.parse(files.get(name));
  const scanCoverage = fileNamed("core_data/scan-coverage.json");
  const [payments, portal] = scanCoverage.applications.items;
  assert.deepEqual(payments.profile.custom_fields, [
    { name: "Deploy API Token", value: "[REDACTED]" },
    { name: "ci_session", value: "[REDACTED]" },
  ], "credential-named and JWT-shaped custom field values are redacted while the field names stay legible");
  assert.equal(payments.profile.git_repo_url, "https://[REDACTED]@git.example.com/org/payments.git");
  assert.equal(portal.profile.git_repo_url, "https://git.example.com/org/portal.git?[REDACTED]");
  assert.equal(payments.profile.name, "Payments", "non-credential profile fields stay verbatim");
  const [configuration] = scanCoverage.dynamic_analysis.scan_configurations;
  assert.deepEqual(configuration, {
    analysis_id: "an-1",
    scan_id: "scan-1",
    target_url: "https://portal.example.com/login?[REDACTED]",
    authentication_types: ["AUTO", "FORM", "CERT"],
    authentication_details: "[REDACTED]",
    crawl_disabled: true,
    crawl_script_present: true,
    allowed_host_count: 1,
  }, "the DAST configuration is projected to verdict fields with the authentication tree redacted");
  const control13 = payloads[0].findings.find((item) => item.id === "VERACODE-13");
  assert.equal(control13.status, "fail");
  assert.deepEqual(control13.evidence.crawl_disabled_scans, ["Portal DAST:https://portal.example.com/?[REDACTED]"], "the scan label scrubs the target URL query string");

  const accessControls = fileNamed("core_data/access-controls.json");
  const credentialRecord = accessControls.api_credentials_by_user["u-2"];
  assert.equal(credentialRecord.api_id, "abc123");
  assert.ok(!("api_secret" in credentialRecord), "API credential records are projected to identifiers and timestamps only");
  assert.equal(fileNamed("core_data/access.json").surfaces.find((item) => item.name === "api_credentials").count, 1);
});

test("rule 9: VeracodeApiError keeps only the vendor message from a JSON error body and describes a non-JSON body by size", async () => {
  const responses = {
    "/appsec/v1/policies": new Response(JSON.stringify({ message: "role Security Insights required", access_token: "FAKE_BODY_TOKEN_1" }), { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } }),
    "/api/authn/v2/users/self": new Response("<html>FAKE_HTML_TOKEN_1</html>", { status: 400, statusText: "Bad Request", headers: { "content-type": "text/html" } }),
  };
  const client = new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl: async (input) => responses[new URL(input).pathname] });
  await assert.rejects(() => client.listPolicies(), (error) => {
    assert.match(error.message, /403 Forbidden.*role Security Insights required/);
    assert.ok(!error.message.includes("FAKE_BODY_TOKEN_1"), "only the message field of the error body is kept");
    return true;
  });
  await assert.rejects(() => client.getSelf(), (error) => {
    assert.match(error.message, /non-JSON response body \(30 bytes, not recorded\)/);
    assert.ok(!error.message.includes("FAKE_HTML_TOKEN_1"));
    return true;
  });
});

function halPage(embeddedKey, items, page = {}) {
  return jsonResponse({ _embedded: { [embeddedKey]: items }, ...(Object.keys(page).length > 0 ? { page } : {}) });
}

test("rule 10: listHal reports a page-cap exit without page metadata, a repeating page, and a total that outruns the items as incomplete, and a short last page as complete", async () => {
  const requested = [];
  const endless = new VeracodeApiClient(sampleConfig(), { fetchImpl: async (input) => {
    const url = new URL(input);
    requested.push(Number(url.searchParams.get("page")));
    const page = Number(url.searchParams.get("page"));
    return halPage("users", [{ user_id: `u-${page}-a` }, { user_id: `u-${page}-b` }]);
  } });
  const capped = await endless.listUsers({ maxPages: 3, pageSize: 2 });
  assert.equal(capped.complete, false, "a full last page with no page metadata cannot be reported as complete");
  assert.equal(capped.pagesFetched, 3);
  assert.equal(capped.items.length, 6);
  assert.equal(capped.totalElements, undefined, "the total stays unknown on the cap so the note prints an unknown total");
  assert.equal(capped.totalPages, undefined);
  assert.deepEqual(requested, [0, 1, 2]);

  const repeating = new VeracodeApiClient(sampleConfig(), { fetchImpl: async () => halPage("applications", [{ guid: "app-1" }, { guid: "app-2" }], { number: 0, size: 2, total_elements: 10, total_pages: 5 }) });
  const stuck = await repeating.listApplications({ maxPages: 50, pageSize: 2 });
  assert.equal(stuck.complete, false);
  assert.equal(stuck.pagesFetched, 2, "the walk stops as soon as the server repeats a page instead of running to the cap");
  assert.equal(stuck.items.length, 2);
  assert.match(stuck.notes[0], /returned the same page twice, so pagination stopped after 2 items/);

  const shortLastPage = new VeracodeApiClient(sampleConfig(), { fetchImpl: async (input) => {
    const page = Number(new URL(input).searchParams.get("page"));
    return halPage("roles", page === 0 ? [{ role_id: "r-1" }, { role_id: "r-2" }] : [{ role_id: "r-3" }]);
  } });
  const finished = await shortLastPage.listRoles({ maxPages: 50, pageSize: 2 });
  assert.equal(finished.complete, true, "a short page without metadata is the natural end of the walk");
  assert.equal(finished.items.length, 3);

  const outrun = new VeracodeApiClient(sampleConfig(), { fetchImpl: async (input) => {
    const page = Number(new URL(input).searchParams.get("page"));
    return halPage("teams", page === 0 ? [{ team_id: "t-1" }] : [], { number: page, size: 1, total_elements: 3, total_pages: 2 });
  } });
  const fewer = await outrun.listTeams({ maxPages: 50, pageSize: 1 });
  assert.equal(fewer.complete, false, "fewer items than total_elements is reported as incomplete");
  assert.equal(fewer.totalElements, 3);
});

test("rule 10: a page-capped inventory without a total demotes every dependent finding to warn with an unknown total, and the access check marks the probe count as first page only", async () => {
  const fixture = healthyFixture();
  const cappedList = (items) => list(items, { pagesFetched: 3, totalPages: undefined, totalElements: undefined, complete: false });
  const client = mockClient(fixture, {
    async listApplications() { return cappedList(fixture.applications); },
    async listPolicies() { return cappedList(fixture.policies); },
    async listUsers() { return cappedList(fixture.users); },
    async listTeams() { return cappedList(fixture.teams); },
    async listRoles() { return cappedList(fixture.roles); },
    async listScaWorkspaces() { return cappedList(fixture.workspaces); },
    async listDynamicAnalyses() { return cappedList(fixture.analyses); },
    async listDynamicAnalysisScans() { return cappedList(fixture.scans); },
    async listFindings() { return cappedList(fixture.findings); },
    async listScaWorkspaceLibraries() { return cappedList(fixture.libraries); },
  });
  const findings = await runAllAssessments(client);
  assert.equal(findings.length, 20);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0, "no control may pass on a page-capped inventory");
  for (const number of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 16, 17, 18, 19]) {
    const item = findings.find((candidate) => candidate.id === `VERACODE-${String(number).padStart(2, "0")}`);
    assert.equal(item.status, "warn", `${item.id} should warn, got ${item.status}: ${item.summary}`);
    assert.match(item.summary, /of an unknown total of .* were read \(3\/\? pages\)|truncated/, `${item.id} should state the unknown total: ${item.summary}`);
  }
  const roles = findings.find((item) => item.id === "VERACODE-07");
  assert.match(roles.summary, /Only 2 of an unknown total of roles were read/);
  assert.equal(roles.evidence.roles_complete, false);
  const dynamic = findings.find((item) => item.id === "VERACODE-13");
  assert.match(dynamic.summary, /Only 1 of an unknown total of scans of Portal DAST were read/);
  assert.deepEqual(dynamic.evidence.scan_coverage, [{ analysis_id: "an-1", scans_inspected: 1, scans_seen: 1, scans_total: null, scan_list_complete: false }]);
  const falsePositives = findings.find((item) => item.id === "VERACODE-16");
  assert.match(falsePositives.summary, /2 finding lists were truncated, so the rate was computed over the findings seen \(total unknown or larger\)/);
  assert.equal(falsePositives.evidence.per_application[0].list_complete, false);
  const sca = findings.find((item) => item.id === "VERACODE-05");
  assert.match(sca.summary, /1 library lists were truncated, so libraries_seen is a lower bound/);
  assert.equal(sca.evidence.library_lists_truncated, 1);

  const access = await checkVeracodeAccess(client);
  const applications = access.surfaces.find((item) => item.name === "applications");
  assert.equal(applications.count, 2);
  assert.equal(applications.countNote, "first page only, total unknown");
  const healthyAccess = await checkVeracodeAccess(mockClient());
  assert.equal(healthyAccess.surfaces.find((item) => item.name === "applications").countNote, undefined, "a probe whose page carries the total reports it without a caveat");
});

test("rule 10: more than ten dynamic scans per analysis are sampled and the sampling is named in the verdict instead of passing silently", async () => {
  const fixture = healthyFixture();
  fixture.scans = Array.from({ length: 12 }, (_, index) => ({ scan_id: `scan-${index}`, target_url: `https://portal-${index}.example.com`, analysis_id: "an-1" }));
  const requestedScans = [];
  const client = mockClient(fixture, { async getDynamicScanConfiguration(scanId) { requestedScans.push(scanId); return fixture.scanConfiguration; } });
  const result = await assessVeracodeScanCoverage(client, { now: NOW });
  const dynamic = result.findings.find((item) => item.id === "VERACODE-13");
  assert.equal(requestedScans.length, 10, "only the first ten scans of an analysis are inspected");
  assert.equal(dynamic.status, "warn");
  assert.match(dynamic.summary, /Only 10 of 12 scans of Portal DAST were sampled, so the verdict reflects a partial view/);
  assert.deepEqual(dynamic.evidence.scan_coverage, [{ analysis_id: "an-1", scans_inspected: 10, scans_seen: 12, scans_total: 12, scan_list_complete: true }]);
});

test("rule 1 corollary: unreadable library lists and an unavailable SCA Agent API are named in the SCA verdicts instead of passing silently", async () => {
  const fixture = healthyFixture();
  fixture.workspaces = [{ id: "ws-1", name: "Workspace A", projects_count: 1 }, { id: "ws-2", name: "Workspace B", projects_count: 1 }];
  const libraries = await assessVeracodeScaPosture(mockClient(fixture, {
    async listScaWorkspaceLibraries(id) {
      if (id === "ws-2") throw forbidden("/srcclr/v3/workspaces/ws-2/libraries");
      return list(fixture.libraries);
    },
  }), {});
  const currency = libraries.findings.find((item) => item.id === "VERACODE-05");
  assert.equal(currency.status, "warn");
  assert.match(currency.summary, /1 workspace library lists were unreadable, so libraries_seen undercounts the scanned libraries/);
  assert.equal(currency.evidence.library_lists_unreadable, 1);
  assert.ok(libraries.errors.some((error) => /sca libraries Workspace B.*403/.test(error)));

  const covered = healthyFixture();
  for (const app of covered.applications) app.profile.upload_and_scan_sca_enabled = true;
  const agentless = await assessVeracodeScaPosture(mockClient(covered, { async listScaWorkspaces() { throw forbidden("/srcclr/v3/workspaces"); } }), {});
  const coverage = agentless.findings.find((item) => item.id === "VERACODE-18");
  assert.equal(coverage.status, "pass", "upload-and-scan SCA on every sampled application does not depend on the SCA Agent API");
  assert.match(coverage.summary, /Linked agent projects were not checked because the SCA Agent API workspace list was forbidden \(403\); every sampled application is covered by upload-and-scan SCA alone/);
  assert.equal(coverage.evidence.sca_agent_api_available, false);
  assert.equal(coverage.evidence.sca_agent_api_status, 403);
  assert.equal(coverage.evidence.uncovered_applications, null);
  assert.deepEqual(coverage.evidence.unchecked_applications, []);
});

test("null standard: evidence counters derived from an unread inventory render null, never 0 or [] (VERACODE-07, 09, 10, 13, 15)", async () => {
  const reject = (path) => async () => { throw forbidden(path); };
  const findingOf = (result, number) => result.findings.find((item) => item.id === `VERACODE-${String(number).padStart(2, "0")}`);

  const noApplications = mockClient(healthyFixture(), { listApplications: reject("/appsec/v1/applications") });
  const policies = findingOf(await assessVeracodePolicyCompliance(noApplications, {}), 15);
  assert.equal(policies.status, "warn");
  assert.equal(policies.evidence.applications_on_custom_policies, null);
  assert.equal(policies.evidence.applications_on_default_policies, null);
  assert.match(policies.summary, /1 custom policies with finding rules exist and the assignment per application is unknown\. The application inventory was unreadable/);
  assert.doesNotMatch(policies.summary, /all 0 applications/);
  const teams = findingOf(await assessVeracodeAccessControls(noApplications, { now: NOW }), 7);
  assert.equal(teams.evidence.applications_without_team, null);
  assert.match(teams.summary, /The application inventory was unreadable, so application team assignment was not verified/);
  const readApplications = findingOf(await assessVeracodePolicyCompliance(mockClient(healthyFixture()), {}), 15);
  assert.equal(readApplications.evidence.applications_on_custom_policies, 2, "a read inventory keeps its real count");
  assert.deepEqual(readApplications.evidence.applications_on_default_policies, []);

  const noSandboxes = findingOf(await assessVeracodeScanCoverage(mockClient(healthyFixture(), { listSandboxes: reject("/appsec/v1/applications/x/sandboxes") }), { now: NOW }), 10);
  assert.equal(noSandboxes.status, "manual");
  assert.equal(noSandboxes.evidence.applications_with_sandboxes, null);
  assert.equal(noSandboxes.evidence.applications_without_sandboxes, null);
  assert.equal(noSandboxes.evidence.unreadable_applications, 2);

  const noScanLists = findingOf(await assessVeracodeScanCoverage(mockClient(healthyFixture(), { listDynamicAnalysisScans: reject("/was/configservice/v1/analyses/x/scans") }), { now: NOW }), 13);
  assert.equal(noScanLists.status, "manual");
  for (const key of ["scan_coverage", "configured_scans", "unauthenticated_scans", "crawl_disabled_scans"]) assert.equal(noScanLists.evidence[key], null, key);
  assert.deepEqual(noScanLists.evidence.unreadable, ["Portal DAST"]);

  const noConfigurations = findingOf(await assessVeracodeScanCoverage(mockClient(healthyFixture(), { getDynamicScanConfiguration: reject("/was/configservice/v1/scans/x/configuration") }), { now: NOW }), 13);
  assert.equal(noConfigurations.status, "manual");
  assert.deepEqual(noConfigurations.evidence.scan_coverage, [{ analysis_id: "an-1", scans_inspected: 1, scans_seen: 1, scans_total: 1, scan_list_complete: true }], "the scan lists were read, so their coverage is real");
  for (const key of ["configured_scans", "unauthenticated_scans", "crawl_disabled_scans"]) assert.equal(noConfigurations.evidence[key], null, key);

  const emptyScans = findingOf(await assessVeracodeScanCoverage(mockClient({ ...healthyFixture(), scans: [] }), { now: NOW }), 13);
  assert.equal(emptyScans.evidence.configured_scans, 0, "a readable but empty scan inventory keeps its real zero");
  assert.deepEqual(emptyScans.evidence.unauthenticated_scans, []);
  assert.deepEqual(emptyScans.evidence.scan_coverage, [{ analysis_id: "an-1", scans_inspected: 0, scans_seen: 0, scans_total: 0, scan_list_complete: true }]);

  const noCredentials = findingOf(await assessVeracodeAccessControls(mockClient(healthyFixture(), { getUserApiCredentials: reject("/api/authn/v2/api_credentials/user_id/x") }), { now: NOW }), 9);
  assert.equal(noCredentials.status, "manual");
  assert.equal(noCredentials.evidence.credentials_readable, 0, "the count of records read is honest");
  for (const key of ["credentials_current", "credentials_over_max_age", "credentials_over_max_age_count", "credentials_expired", "credentials_missing_dates"]) assert.equal(noCredentials.evidence[key], null, key);
  const readCredentials = findingOf(await assessVeracodeAccessControls(mockClient(healthyFixture()), { now: NOW }), 9);
  assert.equal(readCredentials.evidence.credentials_current, 1);
  assert.deepEqual(readCredentials.evidence.credentials_over_max_age, []);
});

/** The healthy fixture served as HAL pages by path, so a real VeracodeApiClient walks it exactly as it would the vendor API. */
function veracodeRoutes(fixture) {
  const page = (key, items) => ({ _embedded: { [key]: items }, page: { number: 0, size: Math.max(items.length, 1), total_elements: items.length, total_pages: 1 } });
  return [
    [/^\/api\/authn\/v2\/users\/self$/, () => fixture.self],
    [/^\/api\/authn\/v2\/api_credentials$/, () => fixture.credentials],
    [/^\/api\/authn\/v2\/api_credentials\/user_id\/[^/]+$/, () => fixture.credentials],
    [/^\/api\/authn\/v2\/users$/, () => page("users", fixture.users)],
    [/^\/api\/authn\/v2\/teams$/, () => page("teams", fixture.teams)],
    [/^\/api\/authn\/v2\/roles$/, () => page("roles", fixture.roles)],
    [/^\/appsec\/v1\/applications$/, () => page("applications", fixture.applications)],
    [/^\/appsec\/v1\/applications\/[^/]+\/sandboxes$/, () => page("sandboxes", fixture.sandboxes)],
    [/^\/appsec\/v2\/applications\/[^/]+\/findings$/, () => page("findings", fixture.findings)],
    [/^\/appsec\/v2\/applications\/[^/]+\/summary_report$/, () => fixture.summaryReport],
    [/^\/appsec\/v1\/policies$/, () => page("policy_versions", fixture.policies)],
    [/^\/srcclr\/v3\/workspaces$/, () => page("workspaces", fixture.workspaces)],
    [/^\/srcclr\/v3\/workspaces\/[^/]+\/issues$/, (url) => page("issues", url.searchParams.get("type") === "vulnerability" ? fixture.vulnerabilityIssues : fixture.licenseIssues)],
    [/^\/srcclr\/v3\/workspaces\/[^/]+\/libraries$/, () => page("libraries", fixture.libraries)],
    [/^\/srcclr\/v3\/applications\/[^/]+\/projects$/, () => fixture.scaProjects],
    [/^\/was\/configservice\/v1\/analyses$/, () => page("analyses", fixture.analyses)],
    [/^\/was\/configservice\/v1\/analyses\/[^/]+\/scans$/, () => page("scans", fixture.scans)],
    [/^\/was\/configservice\/v1\/scans\/[^/]+\/configuration$/, () => fixture.scanConfiguration],
  ];
}

/**
 * Serves the route table, denies every path matching `denied` with a 403 JSON
 * body, and records every request it answered so the outputs can be checked
 * against what the run observed.
 */
function recordingVeracodeFetch({ denied = [], fixture = healthyFixture() } = {}) {
  const routes = veracodeRoutes(fixture);
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    let response;
    if (denied.some((pattern) => pattern.test(url.pathname))) {
      response = new Response(JSON.stringify({ message: "Access denied" }), { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } });
    } else {
      const route = routes.find(([pattern]) => pattern.test(url.pathname));
      assert.ok(route, `unexpected request to ${url.pathname}`);
      response = jsonResponse(route[1](url));
    }
    requests.push({ method: init.method ?? "GET", path: url.pathname, status: response.status });
    return response;
  };
  return { fetchImpl, requests };
}

// Every dataset the assessments collect: the path it reads, the core_data file
// it lands in, where it sits inside that file, and the access probe (if any)
// that reads the same path.
const VERACODE_DATASETS = [
  ["applications", /^\/appsec\/v1\/applications$/, "scan-coverage.json", (data) => data.applications, "applications"],
  ["policies", /^\/appsec\/v1\/policies$/, "policy-compliance.json", (data) => data.policies, "policies"],
  ["sandboxes", /^\/appsec\/v1\/applications\/[^/]+\/sandboxes$/, "scan-coverage.json", (data) => data.sandboxes_by_application["app-1"]],
  ["findings", /^\/appsec\/v2\/applications\/[^/]+\/findings$/, "findings-hygiene.json", (data) => data.findings_by_application["app-1"]],
  ["summary_report", /^\/appsec\/v2\/applications\/[^/]+\/summary_report$/, "findings-hygiene.json", (data) => data.summary_reports_by_application["app-1"]],
  ["users", /^\/api\/authn\/v2\/users$/, "access-controls.json", (data) => data.users, "users"],
  ["teams", /^\/api\/authn\/v2\/teams$/, "access-controls.json", (data) => data.teams, "teams"],
  ["roles", /^\/api\/authn\/v2\/roles$/, "access-controls.json", (data) => data.roles, "roles"],
  ["api_credentials", /^\/api\/authn\/v2\/api_credentials\/user_id\/[^/]+$/, "access-controls.json", (data) => data.api_credentials_by_user["u-2"]],
  ["sca_workspaces", /^\/srcclr\/v3\/workspaces$/, "sca-posture.json", (data) => data.sca_workspaces, "sca_workspaces"],
  ["sca_issues", /^\/srcclr\/v3\/workspaces\/[^/]+\/issues$/, "sca-posture.json", (data) => data.sca_issues_by_workspace["ws-1"].vulnerabilities],
  ["sca_libraries", /^\/srcclr\/v3\/workspaces\/[^/]+\/libraries$/, "sca-posture.json", (data) => data.sca_issues_by_workspace["ws-1"].libraries],
  ["sca_projects", /^\/srcclr\/v3\/applications\/[^/]+\/projects$/, "sca-posture.json", (data) => data.sca_projects_by_application["app-2"]],
  ["dynamic_analyses", /^\/was\/configservice\/v1\/analyses$/, "scan-coverage.json", (data) => data.dynamic_analysis.analyses, "dynamic_analyses"],
  ["dynamic_scans", /^\/was\/configservice\/v1\/analyses\/[^/]+\/scans$/, "scan-coverage.json", (data) => data.dynamic_analysis.scans_by_analysis["an-1"]],
  ["dynamic_scan_configuration", /^\/was\/configservice\/v1\/scans\/[^/]+\/configuration$/, "scan-coverage.json", (data) => data.dynamic_analysis.scan_configurations[0]],
];

// Sub-datasets whose requests are skipped, not denied, when the inventory they hang off is unreadable.
const VERACODE_SKIPPED_ON_DENIAL = {
  applications: [["scan-coverage.json", (data) => data.sandboxes_by_application], ["findings-hygiene.json", (data) => data.findings_by_application], ["findings-hygiene.json", (data) => data.summary_reports_by_application]],
  users: [["access-controls.json", (data) => data.api_credentials_by_user]],
  sca_workspaces: [["sca-posture.json", (data) => data.sca_issues_by_workspace], ["sca-posture.json", (data) => data.sca_projects_by_application]],
  dynamic_analyses: [["scan-coverage.json", (data) => data.dynamic_analysis.scans_by_analysis], ["scan-coverage.json", (data) => data.dynamic_analysis.scan_configurations]],
};

const MENTIONED_STATUS_PATTERNS = [
  /\((\d{3})(?: [A-Za-z][A-Za-z ]*)?\)/g,
  /"(?:status_code|statusCode|status)":\s*(\d{3})\b/g,
  /\b(?:HTTP|status|returned|refused)\s+(\d{3})\b/gi,
];
const MENTIONED_ENDPOINT_PATTERN = /\/(?:api\/authn|appsec|srcclr|was\/configservice)\/v\d[A-Za-z0-9_./{}-]*[A-Za-z0-9}]/g;

/**
 * Every 4xx or 5xx status code and every API path named anywhere in the
 * outputs must belong to a request the fixture actually served: a code or
 * endpoint that never appears in the request log is a claim the run did not
 * observe.
 */
function assertOutputsNameOnlyObservedRequests(outputs, requests, label) {
  const observedStatuses = new Set(requests.map((request) => request.status));
  const observedPaths = requests.map((request) => request.path);
  for (const [name, text] of outputs) {
    for (const pattern of MENTIONED_STATUS_PATTERNS) {
      for (const match of text.matchAll(pattern)) {
        const status = Number(match[1]);
        if (status < 400 || status > 599) continue;
        assert.ok(observedStatuses.has(status), `${label} ${name}: mentions status ${status} but the run observed only ${[...observedStatuses].join(", ")} (in: ${match[0]})`);
      }
    }
    for (const match of text.matchAll(MENTIONED_ENDPOINT_PATTERN)) {
      const mention = match[0].replace(/[.)]+$/, "");
      const template = new RegExp(`^${mention.replace(/[.*+?^$()|[\]\\]/g, "\\$&").replace(/\\\{[^}]*\\\}|\{[^}]*\}/g, "[^/]+")}$`);
      assert.ok(observedPaths.some((path) => template.test(path)), `${label} ${name}: names endpoint ${mention} but the run requested only ${[...new Set(observedPaths)].join(", ")}`);
    }
  }
}

function veracodeOutputs(access, results, exported) {
  return new Map([
    ["check_access", JSON.stringify(access)],
    ...results.map((result) => [`assess ${result.title}`, JSON.stringify(result)]),
    ...[...readBundleFiles(exported.outputDir)].map(([name, content]) => [`bundle ${name}`, content]),
  ]);
}

async function runVeracodeAssessments(client) {
  return Promise.all([
    assessVeracodeScanCoverage(client, { now: NOW }),
    assessVeracodePolicyCompliance(client, {}),
    assessVeracodeFindingsHygiene(client, { now: NOW }),
    assessVeracodeScaPosture(client, {}),
    assessVeracodeAccessControls(client, { now: NOW }),
  ]);
}

function assertNotCollectedMarker(entry, label, expected) {
  assert.ok(entry && typeof entry === "object" && !Array.isArray(entry), `${label}: a dataset that was not collected is never written as an array or scalar, got ${JSON.stringify(entry)}`);
  assert.equal(entry.collected, false, `${label}: carries collected: false`);
  assert.equal(entry.status, expected.status, `${label}: status is the observed HTTP status or null`);
  if (expected.endpoint) assert.match(entry.endpoint, expected.endpoint, `${label}: names the endpoint whose request failed`);
  else assert.equal(entry.endpoint, null, `${label}: names no endpoint when no request was issued`);
  assert.match(entry.error, expected.error, `${label}: carries the recorded error`);
}

test("collection status: a denied dataset is written to core_data and the assess payload as a not-collected marker, skipped sub-datasets carry a not-requested marker, counts render null, and every status code and endpoint named in any output was actually observed", async () => {
  const base = createTempBase("grclanker-veracode-denied-markers-");

  for (const [dataset, pattern, coreFile, locate, probeName] of VERACODE_DATASETS) {
    const { fetchImpl, requests } = recordingVeracodeFetch({ denied: [pattern] });
    const client = new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl, sleep: async () => {} });
    const access = await checkVeracodeAccess(client);
    const results = await runVeracodeAssessments(client);
    const exported = await exportVeracodeAuditBundle(client, sampleConfig(), join(base, dataset), { now: NOW });

    const snapshot = JSON.parse(readFileSync(join(exported.outputDir, "core_data", coreFile), "utf8"));
    const entry = locate(snapshot);
    assertNotCollectedMarker(entry, `${dataset} core_data/${coreFile}`, { status: 403, endpoint: pattern, error: /Veracode request failed \(403 Forbidden\) for \// });
    const payloadEntry = results.map((result) => { try { return locate(result.rawData); } catch { return undefined; } }).find(Boolean);
    assert.deepEqual(payloadEntry, entry, `${dataset}: the assess payload carries the same marker as core_data`);
    assert.ok(requests.some((request) => pattern.test(request.path) && request.status === 403), `${dataset}: the denied request was actually issued`);

    for (const [skippedFile, locateSkipped] of VERACODE_SKIPPED_ON_DENIAL[dataset] ?? []) {
      const skipped = locateSkipped(JSON.parse(readFileSync(join(exported.outputDir, "core_data", skippedFile), "utf8")));
      assertNotCollectedMarker(skipped, `${dataset} skipped sub-dataset in core_data/${skippedFile}`, { status: null, endpoint: null, error: /^Not requested: / });
    }

    if (probeName) {
      const surface = access.surfaces.find((item) => item.name === probeName);
      assert.equal(surface.status, "not_readable");
      assert.equal(surface.count, null, `${dataset}: the access check count is null, not 0, when the probe failed`);
      assert.equal(surface.statusCode, 403);
      assert.match(surface.endpoint, pattern, `${dataset}: the surface names the endpoint that failed, got ${surface.endpoint}`);
      assert.match(surface.error, /403 Forbidden/);
    }

    assertOutputsNameOnlyObservedRequests(veracodeOutputs(access, results, exported), requests, `${dataset} denied`);
  }

  // Summary counters derived from a denied inventory render null rather than 0.
  const denied = async (pattern) => {
    const { fetchImpl } = recordingVeracodeFetch({ denied: [pattern] });
    return runVeracodeAssessments(new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl, sleep: async () => {} }));
  };
  const [scanCoverage, policyCompliance, findingsHygiene] = await denied(/^\/appsec\/v1\/applications$/);
  assert.equal(scanCoverage.summary.applications_seen, null);
  assert.equal(scanCoverage.summary.applications_total, null);
  assert.equal(policyCompliance.summary.applications_seen, null);
  assert.equal(findingsHygiene.summary.applications_seen, null);
  assert.equal(findingsHygiene.summary.applications_sampled, null);
  const [, , , scaPosture] = await denied(/^\/srcclr\/v3\/workspaces$/);
  assert.equal(scaPosture.summary.workspaces_seen, null);
  assert.equal(scaPosture.summary.workspaces_sampled, null);
  const [, , , , accessControls] = await denied(/^\/api\/authn\/v2\/users$/);
  assert.equal(accessControls.summary.users_seen, null);
  assert.equal(typeof accessControls.summary.roles_seen, "number", "a readable inventory keeps its count");

  // Readable but empty lists stay [] with a zero count, and the healthy run names no status or endpoint it did not observe.
  const fixture = healthyFixture();
  fixture.sandboxes = [];
  fixture.scans = [];
  fixture.licenseIssues = [];
  const { fetchImpl, requests } = recordingVeracodeFetch({ fixture });
  const client = new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl, sleep: async () => {} });
  const access = await checkVeracodeAccess(client);
  const results = await runVeracodeAssessments(client);
  const exported = await exportVeracodeAuditBundle(client, sampleConfig(), join(base, "empty"), { now: NOW });
  const scan = JSON.parse(readFileSync(join(exported.outputDir, "core_data", "scan-coverage.json"), "utf8"));
  const sca = JSON.parse(readFileSync(join(exported.outputDir, "core_data", "sca-posture.json"), "utf8"));
  assert.deepEqual(scan.sandboxes_by_application["app-1"], [], "a readable empty sandbox list stays []");
  assert.deepEqual(scan.dynamic_analysis.scans_by_analysis["an-1"], [], "a readable empty scan list stays []");
  assert.deepEqual(scan.dynamic_analysis.scan_configurations, [], "no scan means no configuration was requested and nothing was denied");
  assert.deepEqual(sca.sca_issues_by_workspace["ws-1"].vulnerabilities.items, [], "a readable empty issue list stays []");
  assert.equal(sca.sca_issues_by_workspace["ws-1"].vulnerabilities.complete, true);
  assert.equal(sca.sca_issues_by_workspace["ws-1"].licenses.totalElements, 0);
  for (const surface of access.surfaces) {
    assert.equal(surface.status, "readable", `${surface.name} is readable on the healthy fixture`);
    assert.equal(typeof surface.count, "number");
    assert.equal(surface.statusCode, undefined, "a readable surface carries no failure status");
  }
  assertOutputsNameOnlyObservedRequests(veracodeOutputs(access, results, exported), requests, "healthy with empty lists");
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

test("collection status: counters derived from a denied inventory render null in finding evidence (VERACODE-15, 10, 13, 09, 07), never 0 or []", async () => {
  const denied = async (pattern) => {
    const { fetchImpl } = recordingVeracodeFetch({ denied: [pattern] });
    return runVeracodeAssessments(new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl, sleep: async () => {} }));
  };
  const findingIn = (results, id) => results.flatMap((result) => result.findings).find((item) => item.id === id);

  const noApplications = await denied(/^\/appsec\/v1\/applications$/);
  const policies = findingIn(noApplications, "VERACODE-15");
  assert.notEqual(policies.status, "pass");
  assert.equal(policies.evidence.applications_on_custom_policies, null, "policy assignment per application is unknown without the application list");
  assert.equal(policies.evidence.applications_on_default_policies, null);
  assert.match(policies.summary, /the assignment per application is unknown\. The application inventory was unreadable/);
  assert.doesNotMatch(policies.summary, /all 0 applications/);
  const teams = findingIn(noApplications, "VERACODE-07");
  assert.notEqual(teams.status, "pass");
  assert.equal(teams.evidence.applications_without_team, null);
  assert.equal(typeof teams.evidence.users_seen, "number", "the readable user list keeps its count");
  assert.match(teams.summary, /The application inventory was unreadable, so application team assignment was not verified/);

  const sandboxes = findingIn(await denied(/^\/appsec\/v1\/applications\/[^/]+\/sandboxes$/), "VERACODE-10");
  assert.equal(sandboxes.status, "manual");
  assert.equal(sandboxes.evidence.applications_with_sandboxes, null, "no sandbox list was readable, so the count is unknown");
  assert.equal(sandboxes.evidence.applications_without_sandboxes, null);
  assert.equal(sandboxes.evidence.applications_sampled, 2, "the application list itself was read");
  assert.equal(sandboxes.evidence.unreadable_applications, 2);

  const noConfigurations = findingIn(await denied(/^\/was\/configservice\/v1\/scans\/[^/]+\/configuration$/), "VERACODE-13");
  assert.equal(noConfigurations.status, "manual");
  for (const key of ["configured_scans", "unauthenticated_scans", "crawl_disabled_scans"]) {
    assert.equal(noConfigurations.evidence[key], null, `${key} is unknown when no configuration was readable`);
  }
  assert.ok(Array.isArray(noConfigurations.evidence.scan_coverage), "the scan lists themselves were read");
  const noScans = findingIn(await denied(/^\/was\/configservice\/v1\/analyses\/[^/]+\/scans$/), "VERACODE-13");
  assert.equal(noScans.status, "manual");
  for (const key of ["scan_coverage", "configured_scans", "unauthenticated_scans", "crawl_disabled_scans"]) {
    assert.equal(noScans.evidence[key], null, `${key} is unknown when no scan list was readable`);
  }

  const credentials = findingIn(await denied(/^\/api\/authn\/v2\/api_credentials\/user_id\/[^/]+$/), "VERACODE-09");
  assert.equal(credentials.status, "manual");
  for (const key of ["credentials_current", "credentials_over_max_age", "credentials_over_max_age_count", "credentials_expired", "credentials_missing_dates"]) {
    assert.equal(credentials.evidence[key], null, `${key} is unknown when no credential record was readable`);
  }
  assert.equal(credentials.evidence.credentials_readable, 0, "the number of successful reads is a real observation");
  assert.equal(credentials.evidence.api_accounts_sampled, 1);
});

test("rule 9: scrub boundary: a name-shaped value stays bare in prose and is removed inside every carrier, as a configured secret in every encoding, and whenever it has a real token shape", () => {
  const name = "prod-us-east-2026";
  const bare = `Veracode request failed for tenant ${name} owned by sess-canary-COOKIE-31415926535897`;
  assert.equal(scrubErrorText(bare), bare, "a name-shaped value bare in prose is indistinguishable from a resource name");
  assert.equal(scrubErrorText(bare, [name]), "Veracode request failed for tenant [REDACTED] owned by sess-canary-COOKIE-31415926535897", "the same value registered as a configured secret is removed");
  const carriers = [
    [`Cookie: sid=${name}; Path=/`, "Cookie: [REDACTED]"],
    [`Set-Cookie: session=${name}; HttpOnly`, "Set-Cookie: [REDACTED]"],
    [`X-Api-Key: ${name} rejected`, "X-Api-Key: [REDACTED] rejected"],
    [`Authorization: Basic ${name} rejected`, "Authorization: Basic [REDACTED] rejected"],
    [`token=${name} rejected`, "token=[REDACTED] rejected"],
    [`{"client_secret": "${name}"} rejected`, '{"client_secret": "[REDACTED]"} rejected'],
    [`(session_id: ${name}) rejected`, "(session_id: [REDACTED]) rejected"],
    [`https://svc:${name}@host/p?k=${name} rejected`, "https://host/p?[REDACTED] rejected"],
    [`Bearer ${name} rejected`, "Bearer [REDACTED] rejected"],
    [`SSWS ${name} rejected`, "SSWS [REDACTED] rejected"],
    ["Basic authentication is required", "Basic authentication is required"],
    ["InvalidAuthenticationToken: Access token has expired", "InvalidAuthenticationToken: Access token has expired"],
  ];
  for (const [input, expected] of carriers) assert.equal(scrubErrorText(input), expected, input);
  const secret = 'top secret/value+1"x';
  const forms = {
    raw: secret,
    json: JSON.stringify(secret).slice(1, -1),
    url: encodeURIComponent(secret),
    base64: Buffer.from(secret).toString("base64"),
    base64url: Buffer.from(secret).toString("base64url"),
  };
  const encoded = Object.entries(forms).map(([label, form]) => `${label}=${form}`).join(" ");
  assert.equal(scrubErrorText(encoded, [secret]), "raw=[REDACTED] json=[REDACTED] url=[REDACTED] base64=[REDACTED] base64url=[REDACTED]");
  assert.equal(
    scrubErrorText("bare shapes eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2lnbmF0dXJl 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 QmFzZTY0K1N5bWJvbHM= aB3xZ9qL2mN8pR4tV7wY1 ABCD-EFGH-1234-5678 xKqZvBnMwLpRtYsHdG stay-01 name_with_words-2026 ERR_MODULE_NOT_FOUND"),
    "bare shapes [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] [REDACTED] stay-01 name_with_words-2026 ERR_MODULE_NOT_FOUND",
    "a JWT, a hex digest, a padded base64 run, scattered digits, a second numeric segment, and token casing are removed bare; short runs, names, and uppercase codes stay",
  );
  assert.equal(
    scrubErrorText("failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/credentials and https://hooks.example.com/services/T0/aB3xZ9qL2mN8pR4tV7wY1"),
    "failed for /api/v1/users/aB3xZ9qL2mN8pR4tV7wY1/factors from /tmp/run-9b6rz9m4l55zg7/credentials and https://hooks.example.com/services/T0/[REDACTED]",
    "a token-shaped segment of a bare request target or file path is an identifier the run named; inside a URL it is a webhook token",
  );
});
