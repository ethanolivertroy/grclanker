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
  redactSnapshot,
  registerVeracodeTools,
  resolveSecureOutputPath,
  resolveVeracodeConfiguration,
  scrubDataText,
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

/** Canaries planted on malformed credentials lines: random alphanumerics, so no 6-character window of one occurs in a legitimate fixture value or in another canary. */
const CONFIG_CANARIES = {
  bareLine: "Bp6TzX3kW9nQ2sRc",
  unterminatedSection: "Lf9BwD4sN7hVe3Ky",
  readable: "Zx4HnV7qK2mYt9Pw",
};
const LIBRARY_ERROR_WORDING = [
  "Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "no such file",
  "not a directory", "Unexpected token",
];

/** Every substring of a planted credential at lengths 6 through 24 (sliding windows), so a partial echo such as a truncated token or a quoted line fragment cannot pass a leak assertion. */
function windowsOf(value, { min = 6, max = 24 } = {}) {
  const windows = new Set();
  for (let size = Math.min(min, value.length); size <= Math.min(max, value.length); size += 1) {
    for (let index = 0; index + size <= value.length; index += 1) windows.add(value.slice(index, index + size));
  }
  return [...windows];
}

/** The window set of every planted secret, for bundle, zip, and payload scans through assertSecretsAbsent. */
function leakWindows(secrets) {
  return [...new Set(secrets.flatMap((secret) => windowsOf(secret)))];
}

function assertNoWindowOf(text, secret, label) {
  for (const window of windowsOf(secret)) assert.ok(!text.includes(window), `${label} carries a window (${window}) of the planted credential: ${text.slice(0, 300)}`);
}

/**
 * Fixture self-check: the legitimate values of a fixture (everything it serves
 * with the planted canaries themselves removed, longest first) contain no
 * 6-character window of any canary, so a window hit in an output can only be a leak.
 */
function assertFixtureFreeOfCanaryWindows(legitimateText, canaries, label) {
  let legitimate = legitimateText;
  for (const canary of [...canaries].sort((a, b) => b.length - a.length)) legitimate = legitimate.split(canary).join("");
  for (const canary of canaries) {
    for (const window of windowsOf(canary, { min: 6, max: 6 })) {
      assert.ok(!legitimate.includes(window), `${label}: legitimate fixture text contains the window ${window} of canary ${canary}`);
    }
  }
}

function assertConfigErrorText(text, { path, code, canaries }, label) {
  for (const canary of canaries) assertNoWindowOf(text, canary, `${label} (${canary})`);
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
  assertFixtureFreeOfCanaryWindows(`${readFileSync(malformed, "utf8")} ${dir} ${API_ID} ${API_SECRET}`, allCanaries, "credentials file canaries");
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
    assertNoWindowOf(error.message, API_SECRET, "error message with the configured secret echoed by the server");
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
  assert.equal(denied.evidence.linked_projects_by_application, null, "a map derived from lookups that all failed renders null, never {}");
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

test("VERACODE-18 renders linked_projects_by_application as null when no linked project list was read, keeps read lists beside a not-collected marker when some were denied, names the unread lists with count, endpoint, and observed status in every summary, and keeps the populated map when every list was read", async () => {
  const findingOf = (result) => result.findings.find((item) => item.id === "VERACODE-18");
  const projectsPath = (guid) => `/srcclr/v3/applications/${guid}/projects`;
  const portalProjects = [{ name: "portal", workspace: "Workspace A", last_scan_date: healthyFixture().scaProjects.linked_projects[0].last_scan_date }];

  // Baseline: the SCA Agent API is available and every sampled application's list is read, so the map is populated.
  const fixture = healthyFixture();
  for (const app of fixture.applications) app.profile.upload_and_scan_sca_enabled = false;
  const populated = findingOf(await assessVeracodeScaPosture(mockClient(fixture)));
  assert.equal(populated.status, "pass");
  assert.deepEqual(Object.keys(populated.evidence.linked_projects_by_application).sort(), ["Payments", "Portal"]);
  assert.deepEqual(populated.evidence.linked_projects_by_application.Portal, portalProjects);
  assert.deepEqual(populated.evidence.unreadable_applications, []);

  // Every requested list denied (Payments covered by upload-and-scan, Portal's list forbidden): no list was read, so the map is null while unreadable_applications names the application and the verdict and summary are unchanged.
  const requested = [];
  const allDenied = findingOf(await assessVeracodeScaPosture(mockClient(healthyFixture(), {
    async getScaApplicationProjects(guid) { requested.push(guid); throw forbidden(projectsPath(guid)); },
  })));
  assert.deepEqual(requested, ["app-2"], "the covered application needs no list; the other's list was requested and denied");
  assert.equal(allDenied.status, "warn");
  assert.equal(allDenied.summary, "1 of 2 sampled applications have upload-and-scan SCA enabled or a linked SCA agent project (linked_projects from the SCA Agent API). 1 of 1 requested linked project lists could not be read (the requests returned 403 Forbidden).", "the covered count is stated against the sample, and the caveat counts the unread lists against those requested with the observed status");
  assert.deepEqual(allDenied.evidence.unreadable_applications, ["Portal"]);
  assert.deepEqual(allDenied.evidence.unreadable_linked_project_lists, [{ application: "Portal", status: 403, endpoint: null }], "the mock client reports no endpoint, so the evidence carries the observed status and a null endpoint");
  assert.equal(allDenied.evidence.linked_project_lists_requested, 1);
  assert.equal(allDenied.evidence.linked_projects_by_application, null, "a map derived from lookups that all failed renders null, never {}");
  assert.equal(allDenied.evidence.sca_agent_api_available, true);

  // Both sampled applications need a list and both are denied: no application could be evaluated, the manual summary names the unread lists with their count and observed status, and the map is still null.
  const noneRead = findingOf(await assessVeracodeScaPosture(mockClient(fixture, {
    async getScaApplicationProjects(guid) { throw forbidden(projectsPath(guid)); },
  })));
  assert.equal(noneRead.status, "manual");
  assert.equal(noneRead.summary, "No application could be evaluated for SCA coverage: every linked project list requested was unreadable (2 of 2; the requests returned 403 Forbidden). Manual evidence required: Map each application to an SCA workspace.");
  assert.equal(noneRead.evidence.covered_applications, 0);
  assert.deepEqual(noneRead.evidence.unreadable_applications, ["Payments", "Portal"]);
  assert.deepEqual(noneRead.evidence.unreadable_linked_project_lists, [{ application: "Payments", status: 403, endpoint: null }, { application: "Portal", status: 403, endpoint: null }]);
  assert.equal(noneRead.evidence.linked_project_lists_requested, 2);
  assert.equal(noneRead.evidence.linked_projects_by_application, null);

  // The same shape through the real client: the summary names the endpoint family and the 403 the run observed, the evidence keeps each list's real endpoint and status, and a sampled inventory keeps its scope caveat before the manual evidence line.
  const noneReadFetch = recordingVeracodeFetch({ fixture, denied: [/^\/srcclr\/v3\/applications\/[^/]+\/projects$/] });
  const noneReadObserved = findingOf(await assessVeracodeScaPosture(new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl: noneReadFetch.fetchImpl, sleep: async () => {} }), {}));
  assert.equal(noneReadObserved.status, "manual");
  assert.equal(noneReadObserved.summary, "No application could be evaluated for SCA coverage: every linked project list requested was unreadable (2 of 2; GET /srcclr/v3/applications/{guid}/projects returned 403 Forbidden). Manual evidence required: Map each application to an SCA workspace.");
  assert.deepEqual(noneReadObserved.evidence.unreadable_linked_project_lists, [
    { application: "Payments", status: 403, endpoint: "/srcclr/v3/applications/app-1/projects" },
    { application: "Portal", status: 403, endpoint: "/srcclr/v3/applications/app-2/projects" },
  ]);
  assert.equal(noneReadFetch.requests.filter((request) => /\/projects$/.test(request.path) && request.status === 403).length, 2, "both denied requests were actually issued");
  assertOutputsNameOnlyObservedRequests(new Map([["VERACODE-18", JSON.stringify(noneReadObserved)]]), noneReadFetch.requests, "all linked project lists denied");
  const sampledFetch = recordingVeracodeFetch({ fixture, denied: [/^\/srcclr\/v3\/applications\/[^/]+\/projects$/] });
  const sampledObserved = findingOf(await assessVeracodeScaPosture(new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl: sampledFetch.fetchImpl, sleep: async () => {} }), { maxApplications: 1 }));
  assert.equal(sampledObserved.status, "manual");
  assert.equal(sampledObserved.summary, "No application could be evaluated for SCA coverage: every linked project list requested was unreadable (1 of 1; GET /srcclr/v3/applications/app-1/projects returned 403 Forbidden). Only 1 of 2 applications were sampled, so the verdict reflects a partial view. Manual evidence required: Map each application to an SCA workspace.", "a single unread list names its own endpoint, and the scope caveat reaches the manual summary");

  // No list needed at all (every sampled application has upload-and-scan SCA): nothing was read, so the map is null rather than an empty {}.
  const covered = healthyFixture();
  for (const app of covered.applications) app.profile.upload_and_scan_sca_enabled = true;
  const noneNeeded = findingOf(await assessVeracodeScaPosture(mockClient(covered, { async getScaApplicationProjects() { throw new Error("no list should be requested"); } })));
  assert.equal(noneNeeded.status, "pass");
  assert.equal(noneNeeded.evidence.linked_projects_by_application, null);

  // Mixed: Payments' list denied, Portal's read. The read list is kept and the denied one is the not-collected marker, so neither reads as "no linked projects".
  const mixed = findingOf(await assessVeracodeScaPosture(mockClient(fixture, {
    async getScaApplicationProjects(guid) { if (guid === "app-1") throw forbidden(projectsPath(guid)); return fixture.scaProjects; },
  })));
  assert.equal(mixed.status, "warn");
  assert.equal(mixed.summary, "1 of 2 sampled applications have upload-and-scan SCA enabled or a linked SCA agent project (linked_projects from the SCA Agent API). 1 of 2 requested linked project lists could not be read (the requests returned 403 Forbidden).");
  assert.deepEqual(mixed.evidence.unreadable_applications, ["Payments"]);
  assert.deepEqual(Object.keys(mixed.evidence.linked_projects_by_application).sort(), ["Payments", "Portal"]);
  assert.deepEqual(mixed.evidence.linked_projects_by_application.Portal, portalProjects);
  assertNotCollectedMarker(mixed.evidence.linked_projects_by_application.Payments, "mixed linked_projects_by_application.Payments", { status: 403, endpoint: null, error: /^Veracode request failed \(403 Forbidden\) for \/srcclr\/v3\/applications\/app-1\/projects$/ });

  // Through the real client the marker carries the observed status and endpoint of the request that failed, and the finding names no request the run did not make.
  const { fetchImpl, requests } = recordingVeracodeFetch({ fixture, denied: [/^\/srcclr\/v3\/applications\/app-1\/projects$/] });
  const client = new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl, sleep: async () => {} });
  const observed = findingOf(await assessVeracodeScaPosture(client, {}));
  assert.equal(observed.status, "warn");
  assert.match(observed.summary, /1 of 2 requested linked project lists could not be read \(GET \/srcclr\/v3\/applications\/app-1\/projects returned 403 Forbidden\)\.$/, "the caveat names the real endpoint and status the run observed");
  assert.deepEqual(observed.evidence.unreadable_linked_project_lists, [{ application: "Payments", status: 403, endpoint: "/srcclr/v3/applications/app-1/projects" }]);
  assert.deepEqual(observed.evidence.linked_projects_by_application.Portal, portalProjects);
  assertNotCollectedMarker(observed.evidence.linked_projects_by_application.Payments, "observed linked_projects_by_application.Payments", { status: 403, endpoint: /^\/srcclr\/v3\/applications\/app-1\/projects$/, error: /403 Forbidden/ });
  assert.ok(requests.some((request) => request.path === "/srcclr/v3/applications/app-1/projects" && request.status === 403), "the denied request was actually issued");
  assertOutputsNameOnlyObservedRequests(new Map([["VERACODE-18", JSON.stringify(observed)]]), requests, "mixed linked project lists");
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

/** The reviewer's hiding cap: the first entry only, with the whole population claimed behind unfetched pages. */
function hidingList(items) {
  return list(items.slice(0, 1), { pagesFetched: 1, totalPages: 3, totalElements: items.length, complete: false });
}

/** Every scalar leaf of a JSON value as [dotted path, value] pairs. */
function scalarLeaves(value, prefix = "") {
  if (value === null || typeof value !== "object") return [[prefix, value]];
  return Object.entries(value).flatMap(([key, entry]) => scalarLeaves(entry, prefix ? `${prefix}.${key}` : key));
}

test("reviewer C final verdict, item I: VERACODE-09 calls an API account inventory that a partial user list left empty unread rather than absent, and api_accounts renders null over a partially read user list", async () => {
  const findingOf = (result, number) => result.findings.find((item) => item.id === `VERACODE-${String(number).padStart(2, "0")}`);
  const fixture = healthyFixture();
  const hiddenUsers = mockClient(fixture, { async listUsers() { return hidingList(fixture.users); } });
  const credentials = findingOf(await assessVeracodeAccessControls(hiddenUsers, { now: NOW }), 9);
  assert.equal(credentials.status, "manual");
  assert.equal(credentials.summary, "No active API service account was among the users read, so the credential inventory is unread rather than empty; read the full user list before judging it. Only 1 of 2 users were read (1/3 pages), so the verdict reflects a partial inventory. Manual evidence required: Export API credential creation and expiration dates per API service account from the Platform.");
  assert.doesNotMatch(credentials.summary, /were returned|unverifiable/);
  assert.equal(credentials.evidence.users_seen, 1);
  assert.equal(credentials.evidence.users_total, 2);
  assert.equal(credentials.evidence.users_complete, false);

  const apiFirst = mockClient(fixture, { async listUsers() { return hidingList([...fixture.users].reverse()); } });
  const partialAccounts = findingOf(await assessVeracodeAccessControls(apiFirst, { now: NOW }), 9);
  assert.equal(partialAccounts.status, "warn");
  assert.equal(partialAccounts.evidence.api_accounts, null, "the API account count over a partial user list is not the count of the part read");
  assert.equal(partialAccounts.evidence.api_accounts_sampled, 1);
  assert.equal(partialAccounts.evidence.credentials_readable, 1);
  assert.match(partialAccounts.summary, /Only 1 of 2 users were read \(1\/3 pages\), so the verdict reflects a partial inventory\./);

  const complete = findingOf(await assessVeracodeAccessControls(mockClient(fixture), { now: NOW }), 9);
  assert.equal(complete.status, "pass");
  assert.equal(complete.evidence.api_accounts, 1, "a complete user list keeps its real count");
  const completeWithoutApi = findingOf(await assessVeracodeAccessControls(mockClient({ ...fixture, users: fixture.users.slice(0, 1) }), { now: NOW }), 9);
  assert.equal(completeWithoutApi.status, "manual");
  assert.match(completeWithoutApi.summary, /^No active API service accounts were returned even though this request is authenticated with API credentials, so the credential inventory is unverifiable\./);
  assert.equal(completeWithoutApi.evidence.users_seen, 1);
});

test("reviewer C final verdict, item I: no evidence leaf that a complete read rendered positive or true renders 0 or false under a hiding cap on any list method", async () => {
  const fixture = healthyFixture();
  const completeFindings = await runAllAssessments(mockClient(fixture));
  const completeLeaves = new Map(completeFindings.flatMap((item) => scalarLeaves(item.evidence).map(([path, value]) => [`${item.id}.${path}`, value])));
  const listMethods = Object.keys(mockClient(fixture)).filter((name) => name.startsWith("list"));
  assert.equal(listMethods.length, 12);
  const defaulted = [];
  for (const method of listMethods) {
    const hidden = mockClient(fixture, {
      async [method](...args) {
        const served = await mockClient(fixture)[method](...args);
        return hidingList(served.items);
      },
    });
    for (const item of await runAllAssessments(hidden)) {
      for (const [path, value] of scalarLeaves(item.evidence)) {
        // A *_complete flag turning false is the disclosure itself, and a *_requested count records what the tool asked for, not what the tenant holds.
        if (/_complete$|_requested$/.test(path)) continue;
        const before = completeLeaves.get(`${item.id}.${path}`);
        const positive = (typeof before === "number" && before > 0) || before === true;
        if (positive && (value === 0 || value === false)) defaulted.push(`${method}: ${item.id}.${path} ${before} -> ${value}`);
      }
    }
  }
  assert.deepEqual(defaulted, []);
});

/** Planted credentials: random alphanumerics, so no 6-character window of one occurs in a legitimate fixture value (checked by assertFixtureFreeOfCanaryWindows) or in another canary. */
const FAKE_SECRETS = {
  customFieldToken: "AX9Ajv33cV74xYBtFWjbQQvyLw4T2LkSH9BdWsRy",
  customFieldJwtPayload: "jAMmVWnurbAAt6j2tA77Qxa6LTypgdBfpUU3Tjch",
  customFieldJwtSignature: "jhKD4cugwG2VHZUthDqqALxdCjfzDjnvHVYYtgG6",
  repoUserinfoToken: "pGWNtV2BmepjRQH4fBgLvxbPFHdxV6qWJmcdyZqY",
  repoQueryToken: "7xrxUx6g5sUrQB26s5JySTb5pXQ2QSfcNDfZzhSM",
  dastPassword: "NFjheYRmvsxWLttZk7",
  loginScript: "v35pgSekRNVczKeNnCvr4wXavCYn8SumAeXCFcZq",
  clientCertificate: "GUrj3eYAu6JKD7repGDgDmdRAUgjrFETN6LTBLdn",
  certificatePassword: "njAV3RP8LRBFpXTaGr",
  crawlScript: "BDdEwZnFman9uajLZDymGhyCfhqFC9AMjz3a5KSY",
  configurationSession: "dY2uQe2vf3NaQ5QavNjeksHChdm7GNdrqFAhYJH7",
  scanListSession: "U3SWh2gaRXQEmg2KpWxWEHb2gezPMAa3KPwNf2sf",
  scanRequestPassword: "F9UDKhAWZvwMQdLNHh",
  apiSecret: "Gy4Sr2nthWewBaLdX3CNSKuSQ2dajbJh5ht77mWw",
  pairAccessKey: "Z7J4pAhJr9F4H33emp2fLkHuUV68ZpbKGfuenF6G",
  pairSecretKey: "cTEF3JvzumskuFUSrpnujEU2Xjf9jPqXnj9Px23p",
  settingsAccessKey: "A4urKDYCG35ubTm9v54aKCfTwDUYD4r5YFP7Lr99",
  settingsSecretKey: "6mckJxBg2BmjE9GKTpz5KeWXxHXcHtwkSm8Le9Gj",
  runbookFragmentToken: "RBTsRfDATVHez2jXNJh7sBB5nDQkU9hs9Weyyjpb",
  spaFragmentToken: "TRcHmKPJYAfFQftqKaPQWjhu2M5qT8YCvdCjTHT3",
};

/** Every collected object that can carry a credential per the vendor API carries a distinctive fake one. */
function secretFixture() {
  const fixture = healthyFixture();
  fixture.applications[0].profile.custom_fields = [
    { name: "Deploy API Token", value: FAKE_SECRETS.customFieldToken },
    { name: "ci_session", value: `eyJhbGciOiJIUzI1NiJ9.${FAKE_SECRETS.customFieldJwtPayload}.${FAKE_SECRETS.customFieldJwtSignature}` },
    // A URL whose only sensitive part is the fragment (no userinfo, no query).
    { name: "Runbook", value: `https://wiki.example.com/runbooks/payments#access_token=${FAKE_SECRETS.runbookFragmentToken}` },
  ];
  fixture.applications[0].profile.git_repo_url = `https://svc:${FAKE_SECRETS.repoUserinfoToken}@git.example.com/org/payments.git`;
  fixture.applications[1].profile.git_repo_url = `https://git.example.com/org/portal.git?access_token=${FAKE_SECRETS.repoQueryToken}`;
  // Keys whose normalized form ends in `accesskey` or `secretkey`, in pair shape (space- and underscore-separated names) and as direct keys.
  fixture.applications[1].profile.custom_fields = [
    { name: "AWS Access Key", value: FAKE_SECRETS.pairAccessKey },
    { name: "deploy_secret_key", value: FAKE_SECRETS.pairSecretKey },
    { name: "Cost Center", value: "CC-4410" },
  ];
  fixture.applications[1].profile.settings = { sca_enabled: true, access_key: FAKE_SECRETS.settingsAccessKey, "secret-key": FAKE_SECRETS.settingsSecretKey };
  fixture.scans = [{
    scan_id: "scan-1",
    analysis_id: "an-1",
    target_url: `https://portal.example.com/?sid=${FAKE_SECRETS.scanListSession}`,
    scan_config_request: { auth_configuration: { authentications: { AUTO: { username: "svc", password: FAKE_SECRETS.scanRequestPassword } } } },
  }, {
    scan_id: "scan-2",
    analysis_id: "an-1",
    // A single-page application target whose fragment carries the token and which has no query string.
    target_url: `https://spa.example.com/app#id_token=${FAKE_SECRETS.spaFragmentToken}`,
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
  const fixture = secretFixture();
  const client = mockClient(fixture, { async listSandboxes() { throw forbidden("/appsec/v1/applications/app-1/sandboxes"); } });
  const secrets = [...Object.values(FAKE_SECRETS), API_SECRET, API_ID];
  // Self-check: nothing the fixture legitimately serves (or the config, the output path, or the clock) shares a 6-character window with a planted credential.
  assertFixtureFreeOfCanaryWindows(`${JSON.stringify(fixture)} ${JSON.stringify(sampleConfig())} ${base} ${NOW.toISOString()}`, secrets, "secret fixture");

  const result = await exportVeracodeAuditBundle(client, sampleConfig(), base, { now: NOW });
  const files = readBundleFiles(result.outputDir);
  for (const file of ["core_data/scan-coverage.json", "core_data/access-controls.json", "core_data/access.json", "analysis/findings.json", "analysis/summary.md", "_errors.log"]) {
    assert.ok(files.has(file), `${file} should exist`);
  }
  assertSecretsAbsent(assert, files, leakWindows(secrets), "bundle files");
  assertSecretsAbsent(assert, readZipEntries(result.zipPath), leakWindows(secrets), "zip entries");

  const access = await checkVeracodeAccess(client);
  const payloads = await Promise.all([
    assessVeracodeScanCoverage(client, { now: NOW }),
    assessVeracodePolicyCompliance(client, {}),
    assessVeracodeFindingsHygiene(client, { now: NOW }),
    assessVeracodeScaPosture(client, {}),
    assessVeracodeAccessControls(client, { now: NOW }),
  ]);
  const toolPayloads = JSON.stringify([access, ...payloads.map((item) => ({ title: item.title, summary: item.summary, findings: item.findings, errors: item.errors }))]);
  for (const secret of secrets) assertNoWindowOf(toolPayloads, secret, "tool payloads");

  const fileNamed = (name) => JSON.parse(files.get(name));
  const scanCoverage = fileNamed("core_data/scan-coverage.json");
  const [payments, portal] = scanCoverage.applications.items;
  assert.deepEqual(payments.profile.custom_fields, [
    { name: "Deploy API Token", value: "[REDACTED]" },
    { name: "ci_session", value: "[REDACTED]" },
    { name: "Runbook", value: "https://wiki.example.com/runbooks/payments" },
  ], "credential-named and JWT-shaped custom field values are redacted while the field names stay legible, and a URL whose only sensitive part is the fragment keeps scheme, host, and path only");
  assert.deepEqual(scanCoverage.dynamic_analysis.scans_by_analysis["an-1"].map((scan) => scan.target_url), [
    "https://portal.example.com/?[REDACTED]",
    "https://spa.example.com/app",
  ], "the per-analysis scan list drops a fragment-only target's fragment as well as a query string");
  assert.equal(payments.profile.git_repo_url, "https://[REDACTED]@git.example.com/org/payments.git");
  assert.equal(portal.profile.git_repo_url, "https://git.example.com/org/portal.git?[REDACTED]");
  assert.deepEqual(portal.profile.custom_fields, [
    { name: "AWS Access Key", value: "[REDACTED]" },
    { name: "deploy_secret_key", value: "[REDACTED]" },
    { name: "Cost Center", value: "CC-4410" },
  ], "pair names that normalize to accesskey or secretkey are credential-shaped, and a non-credential pair keeps its value");
  assert.deepEqual(portal.profile.settings, { sca_enabled: true, access_key: "[REDACTED]", "secret-key": "[REDACTED]" }, "access_key and secret-key are redacted as direct keys with the key names kept");
  assert.equal(payments.profile.name, "Payments", "non-credential profile fields stay verbatim");
  const [configuration, spaConfiguration] = scanCoverage.dynamic_analysis.scan_configurations;
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
  assert.equal(spaConfiguration.scan_id, "scan-2");
  const control13 = payloads[0].findings.find((item) => item.id === "VERACODE-13");
  assert.equal(control13.status, "fail");
  assert.deepEqual(control13.evidence.crawl_disabled_scans, [
    "Portal DAST:https://portal.example.com/?[REDACTED]",
    "Portal DAST:https://spa.example.com/app",
  ], "the scan label scrubs the target URL query string and drops a fragment");

  const accessControls = fileNamed("core_data/access-controls.json");
  const credentialRecord = accessControls.api_credentials_by_user["u-2"];
  assert.equal(credentialRecord.api_id, "abc123");
  assert.ok(!("api_secret" in credentialRecord), "API credential records are projected to identifiers and timestamps only");
  assert.equal(fileNamed("core_data/access.json").surfaces.find((item) => item.name === "api_credentials").count, 1);
});

/** Canaries planted in error bodies: random alphanumerics with no 6-character window in the vendor message or the HTML wrapper around them. */
const ERROR_BODY_CANARIES = { bodyToken: "7zsXBTgCW2Xmxk8LwH", htmlToken: "PGUysLcBuHSWdW9AZY" };

test("rule 9: VeracodeApiError keeps only the vendor message from a JSON error body and describes a non-JSON body by size", async () => {
  const jsonBody = JSON.stringify({ message: "role Security Insights required", access_token: ERROR_BODY_CANARIES.bodyToken });
  const htmlBody = `<html>${ERROR_BODY_CANARIES.htmlToken}</html>`;
  assertFixtureFreeOfCanaryWindows(`${jsonBody} ${htmlBody} ${JSON.stringify(sampleConfig())}`, Object.values(ERROR_BODY_CANARIES), "error body canaries");
  const responses = {
    "/appsec/v1/policies": new Response(jsonBody, { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } }),
    "/api/authn/v2/users/self": new Response(htmlBody, { status: 400, statusText: "Bad Request", headers: { "content-type": "text/html" } }),
  };
  const client = new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl: async (input) => responses[new URL(input).pathname] });
  await assert.rejects(() => client.listPolicies(), (error) => {
    assert.match(error.message, /403 Forbidden.*role Security Insights required/);
    assertNoWindowOf(error.message, ERROR_BODY_CANARIES.bodyToken, "JSON error body (only the message field is kept)");
    return true;
  });
  await assert.rejects(() => client.getSelf(), (error) => {
    assert.match(error.message, new RegExp(`non-JSON response body \\(${Buffer.byteLength(htmlBody)} bytes, not recorded\\)`));
    assertNoWindowOf(error.message, ERROR_BODY_CANARIES.htmlToken, "non-JSON error body");
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

test("foreign-origin next link: listHal never follows a HAL _links.next.href, so a link off the configured base origin produces no request and the walk advances by page number on the configured base", async () => {
  const foreignParts = { host: "collector.evil-example.net", path: "/harvest/veracode-hmac", query: "sink=hmac&page=1" };
  const foreign = `https://${foreignParts.host}${foreignParts.path}?${foreignParts.query}`;
  const requested = [];
  const client = new VeracodeApiClient(sampleConfig(), { fetchImpl: async (input, init = {}) => {
    const url = new URL(input);
    requested.push({ url, authorization: new Headers(init.headers ?? {}).get("authorization") ?? "" });
    const page = Number(url.searchParams.get("page"));
    return jsonResponse({
      _embedded: { users: page === 0 ? [{ user_id: "u-1" }, { user_id: "u-2" }] : [{ user_id: "u-3" }] },
      _links: { self: { href: url.toString() }, next: { href: foreign }, last: { href: foreign } },
      page: { number: page, size: 2, total_elements: 3, total_pages: 2 },
    });
  } });

  const walk = await client.listUsers({ maxPages: 50, pageSize: 2 });
  assert.equal(walk.complete, true);
  assert.equal(walk.items.length, 3);
  assert.equal(walk.pagesFetched, 2);
  assert.equal(requested.length, 2);
  assert.ok(requested.every((request) => request.url.origin === "https://api.veracode.com"), "every request went to the configured base origin");
  assert.ok(requested.every((request) => request.url.pathname === "/api/authn/v2/users"), "the walk never left the declared path");
  assert.deepEqual(requested.map((request) => request.url.searchParams.get("page")), ["0", "1"], "the walk advances by page number, never by the server-supplied link");
  assert.ok(requested.every((request) => request.authorization.startsWith("VERACODE-HMAC-SHA-256 ")), "the signed header went to the configured origin only");
  for (const part of Object.values(foreignParts)) assert.ok(!JSON.stringify(walk).includes(part), `the list result carries no ${part}`);
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
  assert.deepEqual(Object.keys(sca.sca_projects_by_application), ["app-2"], "a requested and read list is keyed by application guid");

  // No linked project list needed (every sampled application has upload_and_scan_sca_enabled): nothing was requested and nothing failed, so the dataset is the not-requested marker naming that cause in core_data and in the assess payload, never {}, while VERACODE-18 passes.
  const allUploadAndScan = healthyFixture();
  for (const app of allUploadAndScan.applications) app.profile.upload_and_scan_sca_enabled = true;
  const noneNeeded = recordingVeracodeFetch({ fixture: allUploadAndScan });
  const noneNeededClient = new VeracodeApiClient(sampleConfig({ retries: 0 }), { fetchImpl: noneNeeded.fetchImpl, sleep: async () => {} });
  const noneNeededAccess = await checkVeracodeAccess(noneNeededClient);
  const noneNeededPosture = await assessVeracodeScaPosture(noneNeededClient, {});
  const noneNeededExport = await exportVeracodeAuditBundle(noneNeededClient, sampleConfig(), join(base, "none-needed"), { now: NOW });
  const noneNeededSca = JSON.parse(readFileSync(join(noneNeededExport.outputDir, "core_data", "sca-posture.json"), "utf8"));
  assert.equal(noneNeeded.requests.some((request) => /\/projects$/.test(request.path)), false, "no linked project list was requested");
  for (const [label, value] of [["core_data/sca-posture.json", noneNeededSca.sca_projects_by_application], ["assess rawData", noneNeededPosture.rawData.sca_projects_by_application]]) {
    assertNotCollectedMarker(value, `${label} sca_projects_by_application when no list was needed`, { status: null, endpoint: null, error: /^Not requested: every sampled application has upload_and_scan_sca_enabled, so no linked project list was requested\.$/ });
  }
  const noneNeededFinding = noneNeededPosture.findings.find((item) => item.id === "VERACODE-18");
  assert.equal(noneNeededFinding.status, "pass");
  assert.equal(noneNeededFinding.evidence.linked_project_lists_requested, 0);
  assert.equal(noneNeededFinding.evidence.linked_projects_by_application, null);
  assertOutputsNameOnlyObservedRequests(veracodeOutputs(noneNeededAccess, [noneNeededPosture], noneNeededExport), noneNeeded.requests, "no linked project list needed");
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
  assertNoWindowOf(bundleText, API_SECRET, "findings.json and metadata.json");
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
    // Reviewer C, item G: the word after a credential-named "key:" is the pair's value whatever its shape, prose included.
    ["InvalidAuthenticationToken: Access token has expired", "InvalidAuthenticationToken: [REDACTED] token has expired"],
  ];
  for (const [input, expected] of carriers) {
    const scrubbed = scrubErrorText(input);
    assert.equal(scrubbed, expected, input);
    if (input.includes(name) && !expected.includes(name)) assertNoWindowOf(scrubbed, name, `carrier ${input}`);
  }
  assertNoWindowOf(scrubErrorText(bare, [name]), name, "configured secret in prose");

  // Quoted header values (the Codex P1 carrier class): the value goes whatever its quote style (plain, single, JSON-escaped), separator, or frame; the quote and any scheme word stay; quoted non-credential headers come back unchanged.
  const quotedExpectations = [
    [`Cookie: sid="${name}"; Path=/`, "Cookie: [REDACTED]"],
    [`Cookie: sid=\\"${name}\\"`, "Cookie: [REDACTED]"],
    [`Set-Cookie: session='${name}'; HttpOnly`, "Set-Cookie: [REDACTED]"],
    [`Authorization: Bearer "${name}" rejected`, 'Authorization: Bearer "[REDACTED]" rejected'],
    [`Authorization: VERACODE-HMAC-SHA-256 '${name}' rejected`, "Authorization: VERACODE-HMAC-SHA-256 '[REDACTED]' rejected"],
    [`Authorization: "Bearer ${name}" rejected`, 'Authorization: "Bearer [REDACTED]" rejected'],
    [`\\"Authorization\\": \\"Bearer ${name}\\"`, '\\"Authorization\\": \\"Bearer [REDACTED]\\"'],
    [`X-Api-Key: \\"Ab3dEf9hIj2k\\", next`, 'X-Api-Key: \\"[REDACTED]\\", next'],
    [`X-Auth-Token: "Ab3dEf9hIj2k"`, 'X-Auth-Token: "[REDACTED]"'],
    [`Bearer "${name}" rejected`, 'Bearer "[REDACTED]" rejected'],
  ];
  for (const [input, expected] of quotedExpectations) assert.equal(scrubErrorText(input), expected, input);
  // The signed header itself: the id, nonce, and signature go, the scheme word and the quote stay, and a second pass changes nothing.
  const signedParts = { id: "dbb6f2a2ed0b6890bbd32e949f72c8c8", nonce: "0123456789abcdef0123456789abcdef", sig: "a1".repeat(32) };
  const signedHeader = `VERACODE-HMAC-SHA-256 id=${signedParts.id},ts=1700000000000,nonce=${signedParts.nonce},sig=${signedParts.sig}`;
  const signedScrubbed = "VERACODE-HMAC-SHA-256 [REDACTED],ts=1700000000000,nonce=[REDACTED],sig=[REDACTED]";
  const signedExpectations = [
    [signedHeader, signedScrubbed],
    [`Authorization: ${signedHeader}`, `Authorization: ${signedScrubbed}`],
    [`Authorization: "${signedHeader}"`, `Authorization: "${signedScrubbed}"`],
    [`\\"Authorization\\": \\"${signedHeader}\\"`, `\\"Authorization\\": \\"${signedScrubbed}\\"`],
    ["VERACODE-HMAC-SHA-256 id=ab,ts=1,nonce=cd,sig=ef", "VERACODE-HMAC-SHA-256 [REDACTED]"],
  ];
  for (const [input, expected] of signedExpectations) {
    const scrubbed = scrubErrorText(input);
    assert.equal(scrubbed, expected, input);
    assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${input}`);
    for (const part of Object.values(signedParts)) assertNoWindowOf(scrubbed, part, `signed header ${input}`);
  }
  // Compound header lines (reviewer B's shape): a quoted value ends at its closing quote, an unquoted cookie or header value ends at ";" or "," before the next "Name:" token or at the end of the line, and the following header keeps its name and gets its own carrier treatment.
  const requestId = "3f2b6a1e-9c4d-4e8f-b1a2-6d7c8e9f0a1b";
  const compoundExpectations = [
    [`Cookie: sid="${name}"; X-Api-Key: "${name}"; Content-Type: "application/json"`, 'Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
    [`Cookie: sid=${name}; X-Api-Key: ${name}; Content-Type: application/json`, "Cookie: [REDACTED]; X-Api-Key: [REDACTED]; Content-Type: application/json"],
    [`Cookie: "sid=${name}; Path=/"; X-Api-Key: "${name}"; Content-Type: "application/json"`, 'Cookie: "[REDACTED]"; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
    [`Set-Cookie: session=${name}; Path=/; HttpOnly, X-Api-Key: ${name}, Content-Type: text/html`, "Set-Cookie: [REDACTED], X-Api-Key: [REDACTED], Content-Type: text/html"],
    [`X-Api-Key: "${name}"; X-Auth-Token: "${name}"`, 'X-Api-Key: "[REDACTED]"; X-Auth-Token: "[REDACTED]"'],
    [`X-Api-Key: ${name}; X-Auth-Token: ${name}; Content-Type: application/json`, "X-Api-Key: [REDACTED]; X-Auth-Token: [REDACTED]; Content-Type: application/json"],
    [`Authorization: Bearer "${name}", X-Api-Key: "${name}", Content-Type: "application/json"`, 'Authorization: Bearer "[REDACTED]", X-Api-Key: "[REDACTED]", Content-Type: "application/json"'],
    [`Cookie: sid=${name}; {"error": "invalid_token", "client_secret": "${name}", "request_id": "${requestId}"}`, `Cookie: [REDACTED]; {"error": "invalid_token", "client_secret": "[REDACTED]", "request_id": "${requestId}"}`],
    [`Cookie: sid="${name}" {"error": "invalid_token", "request_id": "${requestId}"}`, `Cookie: [REDACTED] {"error": "invalid_token", "request_id": "${requestId}"}`],
    [`Cookie: sid=\\"${name}\\"; X-Api-Key: \\"${name}\\"; Content-Type: \\"application/json\\"`, 'Cookie: [REDACTED]; X-Api-Key: \\"[REDACTED]\\"; Content-Type: \\"application/json\\"'],
    [`{\\"Cookie\\": \\"sid=${name}; Path=/\\", \\"X-Api-Key\\": \\"${name}\\", \\"Content-Type\\": \\"application/json\\"}`, '{\\"Cookie\\": \\"[REDACTED]\\", \\"X-Api-Key\\": \\"[REDACTED]\\", \\"Content-Type\\": \\"application/json\\"}'],
  ];
  const gatewayBody = (line) => `Veracode request failed (502 Bad Gateway) for /appsec/v1/applications: <html><body><h1>502 Bad Gateway</h1><p>upstream headers: ${line}</p></body></html>`;
  for (const [input, expected] of compoundExpectations) {
    for (const [label, rendered, expectedRendered] of [["bare", input, expected], ["502 body", gatewayBody(input), gatewayBody(expected)]]) {
      const scrubbed = scrubErrorText(rendered);
      assert.equal(scrubbed, expectedRendered, `${label}: ${rendered}`);
      assertNoWindowOf(scrubbed, name, `compound ${label} ${rendered}`);
      for (const following of ["X-Api-Key", "X-Auth-Token", "Content-Type"]) {
        if (rendered.includes(`${following}`)) assert.ok(scrubbed.includes(following), `${following} keeps its name in ${scrubbed}`);
      }
      if (rendered.includes("application/json")) assert.ok(scrubbed.includes("application/json"), `Content-Type keeps its value in ${scrubbed}`);
      if (rendered.includes(requestId)) assert.ok(scrubbed.includes(requestId), `the request id stays in ${scrubbed}`);
      assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${rendered}`);
    }
  }
  const quotedCarriers = [
    (value, separator) => `Cookie${separator}sid=${value}; Path=/`,
    (value, separator) => `Cookie${separator}sid = ${value}`,
    (value, separator) => `Set-Cookie${separator}session=${value}; HttpOnly`,
    (value, separator) => `X-Api-Key${separator}${value}`,
    (value, separator) => `X-Auth-Token${separator}${value}`,
    (value, separator) => `Authorization${separator}${value}`,
    (value, separator) => `Authorization${separator}Bearer ${value}`,
    (value, separator) => `Authorization${separator}Basic ${value}`,
    (value, separator) => `Authorization${separator}VERACODE-HMAC-SHA-256 ${value}`,
    (value, separator) => `Proxy-Authorization${separator}Bearer ${value}`,
    (value, separator, raw, quote) => `Authorization${separator}${quote}Bearer ${raw}${quote}`,
  ];
  const quotedFrames = [
    (line) => line,
    (line) => `Veracode request failed (401 Unauthorized) for /appsec/v1/applications: the request carried ${line} and was rejected`,
    (line) => `{"http_code":401,"http_status":"Unauthorized","message":"Invalid header: ${line}"}`,
  ];
  for (const raw of [name, "Ab3dEf9hIj2k"]) {
    for (const carrier of quotedCarriers) {
      for (const separator of [": ", ":", " : ", " :"]) {
        for (const frame of quotedFrames) {
          for (const quote of ['"', "'", '\\"']) {
            const input = frame(carrier(`${quote}${raw}${quote}`, separator, raw, quote));
            assertNoWindowOf(scrubErrorText(input), raw, `quoted carrier ${input}`);
          }
          const control = frame(carrier(raw, separator, raw, ""));
          assertNoWindowOf(scrubErrorText(control), raw, `unquoted carrier ${control}`);
        }
      }
    }
  }
  for (const header of VERACODE_QUOTED_HEADERS_KEPT) {
    assert.equal(scrubErrorText(header), header, `must keep quoted header: ${header}`);
    const sentence = `Veracode request failed (400 Bad Request) for /appsec/v1/applications: the response carried ${header}`;
    assert.equal(scrubErrorText(sentence), sentence, `must keep quoted header in a sentence: ${sentence}`);
  }
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
  assert.equal(
    scrubErrorText("casing policyComplianceStatus lastCompletedScanDate ignoreTeamRestrictions QaZwSxEdCrFvTgByHn aBcDeFgHiJkLmNoPqRs ABcdEFghIJklMNopQR"),
    "casing policyComplianceStatus lastCompletedScanDate ignoreTeamRestrictions [REDACTED] [REDACTED] [REDACTED]",
    "camelCase identifiers whose words average three or more letters stay; alternating capitalized fragments and doubled-case runs are tokens",
  );
  assert.equal(
    scrubErrorText("veracode_api_key_secret=4f9c2b7e1d3a4c5b8e6f7a9b0c1d2e3f and client_certificate_password=hunter2x9 rejected"),
    "veracode_api_key_secret=[REDACTED] and client_certificate_password=[REDACTED] rejected",
    "a credential-named key keeps its name once its value is replaced; the trailing = is not read as base64 padding",
  );

  assert.equal(
    scrubErrorText("Veracode request failed (403 Forbidden) for /api/authn/v2/api_credentials: Insufficient privileges for this operation"),
    "Veracode request failed (403 Forbidden) for /api/authn/v2/api_credentials: Insufficient privileges for this operation",
    "the last segment of a bare request path used as a label is not a pair key, so the vendor detail after it stays",
  );

  // Must-keep table (addendum 7): every identifying string a summary may carry survives alone and inside a realistic sentence.
  for (const [kind, values] of Object.entries(VERACODE_MUST_KEEP)) {
    for (const value of values) {
      assert.equal(scrubErrorText(value), value, `must keep bare: ${value}`);
      assert.equal(scrubErrorText(value, [API_ID, API_SECRET]), value, `must keep bare with the configured credentials registered: ${value}`);
      for (const sentence of veracodeSummarySentences(kind, value)) assert.equal(scrubErrorText(sentence), sentence, `must keep in a sentence: ${sentence}`);
    }
  }
});

/** Reviewer C's 15 value shape classes (item G): the plain words that no shape rule catches are the point of the pair rule. */
const PAIR_VALUE_SHAPES = [
  "hunter2", "Summer2026!", "correcthorsebatterystaple", "letmein2024", "monkey", "qwerty", "letmein", "iloveyou",
  "football", "Sunshine", "starwarsfan", "footballteam", "abc12", "p@ss", "guest",
];
/** The pair forms of item G: "=", ": ", ":", compact JSON, and spaced JSON. */
const PAIR_FORMS = [
  (key, value) => `${key}=${value}`,
  (key, value) => `${key}: ${value}`,
  (key, value) => `${key}:${value}`,
  (key, value) => `{"${key}":"${value}"}`,
  (key, value) => `{"${key}": "${value}"}`,
];
/** The frames of item G: a bare line, prose, a colon-terminated banner with the pair on the next line, a JSON string member, a 502 JSON body, and a double-escaped raw member. */
const PAIR_FRAMES = [
  ["line", (pair) => pair],
  ["sentence", (pair) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: upstream echoed ${pair} while proxying`],
  ["502-text", (pair) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:\n${pair}`],
  ["json-escaped", (pair) => `{"message":${JSON.stringify(pair)}}`],
  ["502-json", (pair) => `{"status":502,"error":"Bad Gateway","message":${JSON.stringify(`The upstream rejected the request; environment: ${pair}`)},"request":{"env":${JSON.stringify(pair)}}}`],
  ["502-json-raw", (pair) => `{"status":502,"raw":${JSON.stringify(JSON.stringify({ env: [pair] }))}}`],
];
const SAMPLE_UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

test("reviewer C final verdict, item G: the value under a credential-named key is removed whatever its shape in every pair form and frame; settings, identifiers, bearer ids, and webhooks follow the key classes", () => {
  const credentialKeys = [
    "DB_PASSWORD", "API_KEY", "client_secret", "access_token", "password", "AUTH_TOKEN",
    "VERACODE_API_KEY_SECRET", "OKTA_CLIENT_TOKEN", "OKTA_CLIENT_PRIVATEKEY", "SPLUNK_PASSWORD", "SUMOLOGIC_ACCESS_KEY", "SNOWFLAKE_TOKEN", "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE",
  ];
  for (const key of credentialKeys) {
    for (const value of PAIR_VALUE_SHAPES) {
      for (const form of PAIR_FORMS) {
        const pair = form(key, value);
        for (const [frameName, frame] of PAIR_FRAMES) {
          const input = frame(pair);
          const scrubbed = scrubErrorText(input);
          const label = `${frameName}: ${input}`;
          assertNoWindowOf(scrubbed, value, label);
          assert.ok(scrubbed.includes(key), `the key name stays in ${label} -> ${scrubbed}`);
          assert.ok(scrubbed.includes("[REDACTED]"), `the value is replaced by the marker in ${label} -> ${scrubbed}`);
          if (frameName === "sentence") assert.ok(scrubbed.endsWith(" while proxying"), `the prose after the pair stays in ${label} -> ${scrubbed}`);
          assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${label}`);
        }
      }
      assert.equal(scrubErrorText(`${key}=${value}`), `${key}=[REDACTED]`);
      assert.equal(scrubErrorText(`${key}: ${value}`), `${key}: [REDACTED]`);
      assert.equal(scrubErrorText(`{"${key}": "${value}"}`), `{"${key}": "[REDACTED]"}`);
    }
  }

  // Bearer ids: a key ending in secret_id or naming a session id loses its value whatever the shape, a UUID included, in every form.
  for (const key of ["secret_id", "VAULT_SECRET_ID", "role_secret_id", "secretId", "secret-id", "session_id", "sessionId", "sid", "JSESSIONID", "PHPSESSID"]) {
    for (const value of [SAMPLE_UUID, "xKqZvBnMwLpRtYsHdG", "monkey", "hunter2"]) {
      for (const form of PAIR_FORMS) {
        const scrubbed = scrubErrorText(form(key, value));
        assertNoWindowOf(scrubbed, value, `bearer id ${form(key, value)}`);
        assert.ok(scrubbed.includes(key), `bearer id key stays: ${scrubbed}`);
      }
    }
  }

  // Identifiers: a key without a credential word is not a pair under the rule; its value is judged by shape alone, so a UUID or a name stays.
  for (const key of ["OKTA_CLIENT_ID", "OKTA_CLIENT_CLIENTID", "client_id", "SUMO_ACCESS_ID", "SUMOLOGIC_ACCESS_ID", "SNOWFLAKE_ACCOUNT", "SNOWFLAKE_USER", "SPLUNK_USERNAME", "X-Request-Id", "request_id", "user_id", "kid"]) {
    for (const value of [SAMPLE_UUID, "acme-prod-2026", "audit.bot"]) {
      for (const form of PAIR_FORMS) assert.equal(scrubErrorText(form(key, value)), form(key, value), `identifier kept: ${form(key, value)}`);
    }
  }

  // Settings: a credential-named key whose final segment names a setting keeps a value that is not token-shaped, in every form; a token-shaped value still goes.
  const settingPairs = [
    ["token_endpoint", "https://example.okta.com/oauth2/v1/token"],
    ["token_uri", "https://example.okta.com/oauth2/v1/token"],
    ["auth_method", "private_key_jwt"],
    ["token_endpoint_auth_method", "private_key_jwt"],
    ["signing_algorithm", "RS256"],
    ["token_audience", "api://default"],
    ["token_issuer", "https://example.okta.com/oauth2/default"],
    ["key_shape", "rsa"],
    ["token_type", "Bearer"],
    ["SNOWFLAKE_TOKEN_TYPE", "KEYPAIR_JWT"],
    ["X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT"],
    ["credential_mode", "PrivateKey"],
    ["token_limit", "200"],
    ["token_count", "3"],
    ["api_key_id", SAMPLE_UUID],
    ["VERACODE_API_KEY_ID", SAMPLE_UUID],
    ["OKTA_CLIENT_PRIVATEKEYID", "kid-2026-primary"],
    ["token_name", "audit-token"],
    ["api_key_name", "primary-key-2026"],
  ];
  for (const [key, value] of settingPairs) {
    for (const form of PAIR_FORMS) assert.equal(scrubErrorText(form(key, value)), form(key, value), `setting kept: ${form(key, value)}`);
    for (const shape of PAIR_VALUE_SHAPES) assert.equal(scrubErrorText(`${key}=${shape}`), `${key}=${shape}`, `a plain setting value stays: ${key}=${shape}`);
  }
  for (const [key, value] of [["token_type", "QmFzZTY0K1N5bWJvbHM="], ["api_key_id", "xKqZvBnMwLpRtYsHdG"], ["token_name", "aB3xZ9qL2mN8pR4tV7wY1"]]) {
    for (const form of PAIR_FORMS) assertNoWindowOf(scrubErrorText(form(key, value)), value, `token-shaped setting value ${form(key, value)}`);
  }

  // Webhooks: webhook*, *hook_url, and callback_url keep the origin and lose the path and query; a webhook secret goes whole.
  const webhookPath = "services/T0AB12CD/B0EF34GH/xKqZvBnMwLpRtYsHdG";
  assert.equal(scrubErrorText(`webhook_url=https://hooks.example.com/${webhookPath}`), "webhook_url=https://hooks.example.com/[REDACTED]");
  assert.equal(scrubErrorText(`webhookUrl: https://hooks.example.com/${webhookPath}?token=abc`), "webhookUrl: https://hooks.example.com/[REDACTED]");
  assert.equal(scrubErrorText(`slack_hook_url: "https://hooks.example.com/${webhookPath}"`), 'slack_hook_url: "https://hooks.example.com/[REDACTED]"');
  assert.equal(scrubErrorText("callback_url: https://app.example.com/oauth/callback?code=abc123def456"), "callback_url: https://app.example.com/[REDACTED]");
  assert.equal(scrubErrorText("webhook_secret=monkey"), "webhook_secret=[REDACTED]");
  for (const line of ["webhook_url=https://hooks.example.com/[REDACTED]", "callback_url: https://app.example.com/[REDACTED]"]) assert.equal(scrubErrorText(line), line, `second pass over ${line}`);
});

/** Reviewer C's literal escapes (item H): the two- and six-character sequences as they sit inside error text, not the control characters. */
const LITERAL_ESCAPES = ["\\n", "\\r\\n", "\\t", "\\b", "\\f", "\\/", "\\u000a", "\\u0009", "\\u000d\\u000a"];
/** The header lines of rows (b) and (ii) glued to an escape; each gives the line and its expected rendering, or null where the scrubber's HMAC rendering differs by integration. */
const ESCAPED_HEADER_LINES = [
  (value) => [`api_key=${value}`, "api_key=[REDACTED]"],
  (value) => [`password: ${value}`, "password: [REDACTED]"],
  (value) => [`X-Api-Key: ${value}`, "X-Api-Key: [REDACTED]"],
  (value) => [`Cookie: sid=${value}`, "Cookie: [REDACTED]"],
  (value) => [`Authorization: Bearer ${value}`, "Authorization: Bearer [REDACTED]"],
  (value) => [`Authorization: SSWS ${value}`, "Authorization: SSWS [REDACTED]"],
  (value) => [`Authorization: Splunk ${value}`, "Authorization: Splunk [REDACTED]"],
  (value) => [`Authorization: Basic ${value}`, "Authorization: Basic [REDACTED]"],
  (value) => [`Authorization: VERACODE-HMAC-SHA-256 id=${value},ts=1758560000000,nonce=${value},sig=${value}`, null],
  (value) => [`X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT\\u000aAuthorization: Bearer ${value}`, "X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT\\u000aAuthorization: Bearer [REDACTED]"],
];
/** The text before the escape: a colon-terminated word is the case that used to swallow the header line as its value. */
const ESCAPE_PREFIXES = ["request failed", "request headers:"];
/** The frames of item H: a bare line, a 502 banner ending in a colon, a JSON string member holding the literal escapes, and a double-escaped raw member (each with the encoding the frame applies to its inner text). */
const ESCAPE_FRAMES = [
  ["line", (text) => text, (text) => text],
  ["502-text", (text) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:${text}`, (text) => text],
  ["json-member", (text) => `{"message":"${text}"}`, (text) => text],
  ["502-json-raw", (text) => `{"status":502,"raw":${JSON.stringify(JSON.stringify({ env: [text] }))}}`, (text) => JSON.stringify(JSON.stringify(text).slice(1, -1)).slice(1, -1)],
];

test("reviewer C final verdict, item H: a literal JSON escape is a boundary before every carrier opener, so a header line glued to an escape is scrubbed as a header line and never as the value of the word before it", () => {
  for (const escape of LITERAL_ESCAPES) {
    for (const prefix of ESCAPE_PREFIXES) {
      for (const value of PAIR_VALUE_SHAPES) {
        for (const headerLine of ESCAPED_HEADER_LINES) {
          const [line, expectedLine] = headerLine(value);
          for (const [frameName, frame, encode] of ESCAPE_FRAMES) {
            const input = frame(`${prefix}${escape}${line}`);
            const scrubbed = scrubErrorText(input);
            const label = `${frameName}: ${input}`;
            assertNoWindowOf(scrubbed, value, label);
            assert.ok(scrubbed.includes("[REDACTED]"), `the value is replaced by the marker in ${label} -> ${scrubbed}`);
            assert.ok(scrubbed.includes(encode(`${prefix}${escape}${line.split(/[ =]/)[0]}`)), `the prefix, the escape, and the header name stay in ${label} -> ${scrubbed}`);
            if (expectedLine !== null) assert.equal(scrubbed, frame(`${prefix}${escape}${expectedLine}`), label);
            else assert.ok(scrubbed.includes("Authorization: VERACODE-HMAC-SHA-256 "), `the HMAC scheme word stays in ${label} -> ${scrubbed}`);
            assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${label}`);
          }
        }
      }
    }
  }

  // The reviewer's literal rows (b) and (ii).
  assert.equal(scrubErrorText("request headers:\\u000aAuthorization: Splunk abcdefghijklmnop"), "request headers:\\u000aAuthorization: Splunk [REDACTED]");
  assert.equal(scrubErrorText('{"message":"request headers:\\u000aAuthorization: Splunk abcdefghijklmnop"}'), '{"message":"request headers:\\u000aAuthorization: Splunk [REDACTED]"}');
  assert.equal(scrubErrorText("request headers:\\u0009X-Api-Key: hunter2"), "request headers:\\u0009X-Api-Key: [REDACTED]");
  assert.equal(scrubErrorText("request headers:\\u000aAuthorization: SSWS p@ss"), "request headers:\\u000aAuthorization: SSWS [REDACTED]");
  assert.equal(scrubErrorText("request headers:\\u000d\\u000aAuthorization: Bearer abc12"), "request headers:\\u000d\\u000aAuthorization: Bearer [REDACTED]");
  assert.equal(
    scrubErrorText("Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:\\tpassword: hunter2"),
    "Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:\\tpassword: [REDACTED]",
  );
  for (const banner of ["proxy:", "proxy.", "proxy"]) assert.equal(scrubErrorText(`${banner}\\n\\nX-Api-Key: hunter2`), `${banner}\\n\\nX-Api-Key: [REDACTED]`);
  assert.equal(scrubErrorText("upstream said\\nAuthorization: Bearer hunter2"), "upstream said\\nAuthorization: Bearer [REDACTED]");
  assert.equal(scrubErrorText('{\\n  \\"password\\": \\"monkey\\"\\n}'), '{\\n  \\"password\\": \\"[REDACTED]\\"\\n}');

  // Every anchored token shape starts after the escape and never on its letter; a value, URL, or query pair ends at the backslash of the next escape.
  const shapes = [
    ["eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2lnbmF0dXJl", "a JWT"],
    ["AKIAIOSFODNN7EXAMPLE", "an AWS access key id"],
    ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "an AWS secret access key"],
    ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "a hex digest"],
    ["xKqZvBnMwLpRtYsHdG", "a run with token casing"],
    ["sk_live_abcdefghij1234567890", "a vendor-prefixed token"],
    ["ghp_abcdefghijklmnopqrstuvwxyz0123", "a GitHub token"],
  ];
  for (const escape of LITERAL_ESCAPES) {
    for (const [shape, description] of shapes) {
      assert.equal(scrubErrorText(`trace${escape}${shape} end`), `trace${escape}[REDACTED] end`, `${description} after ${escape}`);
      assert.equal(scrubErrorText(`{"message":"trace${escape}${shape}${escape}end"}`), `{"message":"trace${escape}[REDACTED]${escape}end"}`, `${description} between two ${escape}`);
    }
    assert.equal(scrubErrorText(`trace${escape}name_with_words-2026 and${escape}ERR_MODULE_NOT_FOUND`), `trace${escape}name_with_words-2026 and${escape}ERR_MODULE_NOT_FOUND`, `a name after ${escape} stays whole`);
    assert.equal(scrubErrorText(`note${escape}https://example.com/a?token=abc123def456${escape}next`), `note${escape}https://example.com/a?[REDACTED]${escape}next`, `a URL after ${escape}`);
    assert.equal(scrubErrorText(`Bearer abcdefghijklmnop${escape}X-Api-Key: guest`), `Bearer [REDACTED]${escape}X-Api-Key: [REDACTED]`, `a scheme value ends at ${escape}`);
    assert.equal(scrubErrorText(`Cookie: sid=hunter2${escape}X-Api-Key: guest`), `Cookie: [REDACTED]${escape}X-Api-Key: [REDACTED]`, `a cookie value ends at ${escape}`);
  }
  // A "\/" escape is a boundary rather than a path separator: a key or token after it is judged on its own, while a plain "/" still names a bare path segment.
  assert.equal(scrubErrorText("path \\/api\\/v1\\/users\\/00u1abcd2EFGH3ijk4x5\\/factors"), "path \\/api\\/v1\\/users\\/[REDACTED]\\/factors");
  assert.equal(scrubErrorText("path /api/v1/users/00u1abcd2EFGH3ijk4x5/factors"), "path /api/v1/users/00u1abcd2EFGH3ijk4x5/factors");
  // A lone backslash is not an opening quote and does not hide the value after it.
  assert.equal(scrubErrorText("password: \\hunter2"), "password: [REDACTED]");
  assert.equal(scrubErrorText("Authorization: Bearer \\hunter2"), "Authorization: Bearer [REDACTED]");
});

/** Reviewer C's compound header lines (items F and L): several carriers on one line. Each builder takes distinct planted values and gives the line, its credential slots, the header names that must survive as often as they appeared, and the fragments that must survive verbatim. */
const COMPOUND_HEADER_LINES = [
  (a, b) => [`Cookie: sid="${a}"; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: sid=${a}; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: sid="${a}", X-Api-Key: "${b}", Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: sid=${a}, X-Api-Key: "${b}", Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: theme=light; sid=${a}; lang=en; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Set-Cookie: sid="${a}"; Path=/; HttpOnly, X-Api-Key: "${b}", Content-Type: "application/json"`, [a, b], ["Set-Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Cookie: sid='${a}'; X-Api-Key: '${b}'; Content-Type: 'application/json'`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Authorization: Bearer "${a}"; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Authorization", "X-Api-Key", "Content-Type"], ["Bearer", "application/json"]],
  (a, b) => [`X-Api-Key: "${a}", Authorization: "Bearer ${b}", Content-Type: "application/json"`, [a, b], ["X-Api-Key", "Authorization", "Content-Type"], ["Bearer", "application/json"]],
  (a, b) => [`X-Api-Key: "${a}"; Cookie: sid="${b}"; Content-Type: "application/json"`, [a, b], ["X-Api-Key", "Cookie", "Content-Type"], ["application/json"]],
  (a, b, c) => [`Cookie: sid="${a}", Authorization: Bearer "${b}", X-Api-Key: "${c}", Content-Type: "application/json"`, [a, b, c], ["Cookie", "Authorization", "X-Api-Key", "Content-Type"], ["Bearer", "application/json"]],
  (a, b) => [`Cookie: sid="${a}" {"X-Api-Key": "${b}", "Content-Type": "application/json"}`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Authorization: Bearer "${a}" {"Cookie": "sid=${b}", "Content-Type": "application/json"}`, [a, b], ["Authorization", "Cookie", "Content-Type"], ["Bearer", "application/json"]],
  (a, b) => [`{"Cookie": "sid=${a}"} X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`Authorization: SSWS "${a}"; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Authorization", "X-Api-Key", "Content-Type"], ["SSWS", "application/json"]],
  (a, b) => [`Authorization: Splunk "${a}"; Cookie: sid=${b}; Content-Type: "application/json"`, [a, b], ["Authorization", "Cookie", "Content-Type"], ["Splunk", "application/json"]],
  (a, b) => [`Authorization: Snowflake Token="${a}", X-Api-Key: "${b}", Content-Type: "application/json"`, [a, b], ["Authorization", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b, c) => [`Authorization: VERACODE-HMAC-SHA-256 id=${a},ts=1700000000,nonce=${b},sig=${c}; Content-Type: "application/json"`, [a, b, c], ["Authorization", "Content-Type"], ["VERACODE-HMAC-SHA-256", "ts=1700000000", "application/json"]],
  (a, b) => [`Authorization: Basic "${a}"; Cookie: AWSALB="${b}"; Content-Type: "application/json"`, [a, b], ["Authorization", "Cookie", "Content-Type"], ["Basic", "application/json"]],
  // An unterminated quote ends before the next "Name:" token, which keeps its name (item F).
  (a, b) => [`Cookie: sid="${a}; X-Api-Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`X-Api-Key: "${a}; Cookie: sid=${b}; Content-Type: "application/json"`, [a, b], ["X-Api-Key", "Cookie", "Content-Type"], ["application/json"]],
  // A JSON-object header whose value carries escaped inner quotes (item F).
  (a, b) => [`{"Cookie": "sid=\\"${a}\\"", "X-Api-Key": "${b}", "Content-Type": "application/json"}`, [a, b], ["Cookie", "X-Api-Key", "Content-Type"], ["application/json"]],
  (a, b) => [`{"X-Api-Key": "\\"${a}\\"", "Cookie": "sid=${b}", "Content-Type": "application/json"}`, [a, b], ["X-Api-Key", "Cookie", "Content-Type"], ["application/json"]],
  (a, b) => [`{"Authorization": "Bearer \\"${a}\\"", "X-Api-Key": "${b}", "Content-Type": "application/json"}`, [a, b], ["Authorization", "X-Api-Key", "Content-Type"], ["Bearer", "application/json"]],
  // A following header whose name carries RFC 7230 token punctuation is recognised as the next header (item L).
  (a, b) => [`Cookie: theme=dark; my.sid=${a}; X.Api.Key: "${b}"`, [a, b], ["Cookie", "X.Api.Key"], []],
  (a, b) => [`Cookie: sid=${a}; X_Api_Key: "${b}"; Content-Type: "application/json"`, [a, b], ["Cookie", "X_Api_Key", "Content-Type"], ["application/json"]],
];
/** The two value shapes of the compound matrix: pairwise distinct canaries sharing no 6-character window with any line or frame text. */
const COMPOUND_VALUE_SHAPES = [
  ["name-shaped", ["prod-iidsre-itdpqey", "prod-yzrupn-efussqe", "prod-hnxttf-anwlqzo"]],
  ["token-shaped", ["K7pQz2VxN9mR4tYw8LbC1dFgH6jS==", "Wq3Zt8Hv5Nc2Xf9Lm4Rp7Bd1Gk6Ty==", "Jx5Cn2Vb8Mq4Wz7Rt1Hp9Kf3Ld6Sg=="]],
];
/** The frames of the compound matrix: a bare line, a sentence, a 502 banner, a JSON string member, a 502 JSON body, and a double-escaped raw member. */
const COMPOUND_FRAMES = [
  ["line", (text) => text],
  ["sentence", (text) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: ${text} while proxying`],
  ["502-text", (text) => `Vendor request failed (502 Bad Gateway) for /api/v1/items: Environment as echoed by the proxy:\n${text}`],
  ["json-escaped", (text) => `{"message":${JSON.stringify(text)}}`],
  ["502-json", (text) => `{"status":502,"error":"Bad Gateway","message":${JSON.stringify(`The upstream rejected the request; ${text}`)}}`],
  ["502-json-raw", (text) => `{"status":502,"raw":${JSON.stringify(JSON.stringify({ headers: text }))}}`],
];

/** How often `fragment` occurs in `text`. */
function occurrencesOf(text, fragment) {
  return text.split(fragment).length - 1;
}

test("reviewer C final verdict, items F and L: on a compound header line every carrier value goes at every JSON depth, an escaped inner quote is inner content, an unterminated quote ends before the next header token, and every following header keeps its name", () => {
  for (const [shapeName, values] of COMPOUND_VALUE_SHAPES) {
    for (const build of COMPOUND_HEADER_LINES) {
      const [line, credentials, names, keeps] = build(...values);
      for (const [frameName, frame] of COMPOUND_FRAMES) {
        const input = frame(line);
        const scrubbed = scrubErrorText(input);
        const label = `${shapeName} ${frameName}: ${input}`;
        for (const credential of credentials) assertNoWindowOf(scrubbed, credential, label);
        for (const name of names) assert.ok(occurrencesOf(scrubbed, name) >= occurrencesOf(input, name), `the header name ${name} survives in ${label} -> ${scrubbed}`);
        for (const keep of keeps) assert.ok(occurrencesOf(scrubbed, keep) >= occurrencesOf(input, keep), `${keep} survives in ${label} -> ${scrubbed}`);
        assert.equal(scrubErrorText(scrubbed), scrubbed, `second pass over ${label}`);
      }
    }
  }

  // The reviewer's edge rows, rendered: the following header keeps its name and its own carrier treatment.
  assert.equal(scrubErrorText('Cookie: sid="prod-iidsre-itdpqey; X-Api-Key: "prod-yzrupn-efussqe"; Content-Type: "application/json"'), 'Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"');
  assert.equal(scrubErrorText('X-Api-Key: "prod-iidsre-itdpqey; Cookie: sid=prod-yzrupn-efussqe; Content-Type: "application/json"'), 'X-Api-Key: "[REDACTED]; Cookie: [REDACTED]; Content-Type: "application/json"');
  assert.equal(scrubErrorText('{"Cookie": "sid=\\"prod-iidsre-itdpqey\\"", "X-Api-Key": "prod-yzrupn-efussqe", "Content-Type": "application/json"}'), '{"Cookie": "[REDACTED]", "X-Api-Key": "[REDACTED]", "Content-Type": "application/json"}');
  assert.equal(scrubErrorText('{"X-Api-Key": "\\"prod-iidsre-itdpqey\\"", "Cookie": "sid=prod-yzrupn-efussqe", "Content-Type": "application/json"}'), '{"X-Api-Key": "[REDACTED]", "Cookie": "[REDACTED]", "Content-Type": "application/json"}');
  assert.equal(scrubErrorText('{"Authorization": "Bearer \\"prod-iidsre-itdpqey\\"", "X-Api-Key": "prod-yzrupn-efussqe", "Content-Type": "application/json"}'), '{"Authorization": "Bearer [REDACTED]", "X-Api-Key": "[REDACTED]", "Content-Type": "application/json"}');
  assert.equal(scrubErrorText('Cookie: theme=dark; my.sid=prod-iidsre-itdpqey; X.Api.Key: "prod-yzrupn-efussqe"'), 'Cookie: [REDACTED]; X.Api.Key: "[REDACTED]"');
  // Inside a double-escaped raw JSON string every quoted carrier goes and the quote units at that depth stay.
  const rawMember = (headers) => `{"status":502,"raw":${JSON.stringify(JSON.stringify({ headers }))}}`;
  assert.equal(
    scrubErrorText(rawMember('Cookie: sid="prod-iidsre-itdpqey"; X-Api-Key: "prod-yzrupn-efussqe"; Content-Type: "application/json"')),
    rawMember('Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'),
  );
  assert.equal(
    scrubErrorText(rawMember('{"Cookie": "sid=\\"prod-iidsre-itdpqey\\"", "X-Api-Key": "\\"prod-yzrupn-efussqe\\""}')),
    rawMember('{"Cookie": "[REDACTED]", "X-Api-Key": "[REDACTED]"}'),
  );
  // Reading to the matching closer keeps a quoted value whole: spaces, "=", and ";" inside the quotes go with it.
  assert.equal(scrubErrorText('"password": "correct horse battery staple"'), '"password": "[REDACTED]"');
  assert.equal(scrubErrorText('Cookie: "sid=a=b; theme=dark"; X-Api-Key: guest'), 'Cookie: "[REDACTED]"; X-Api-Key: [REDACTED]');
});

/** Every endpoint the Veracode client requests (applications, identity, SCA Agent, and Dynamic Analysis APIs), with the sample identifiers the fixtures use. */
const VERACODE_REQUESTED_PATHS = [
  "/api/authn/v2/users/self",
  "/api/authn/v2/api_credentials",
  "/api/authn/v2/api_credentials/user_id/u-2",
  "/api/authn/v2/users",
  "/api/authn/v2/users?detailed=true&include_roles=true&include_teams=true&page=0&size=100",
  "/api/authn/v2/teams",
  "/api/authn/v2/teams?all_for_org=true",
  "/api/authn/v2/roles",
  "/appsec/v1/applications",
  "/appsec/v1/applications?page=1&size=100",
  "/appsec/v1/applications/app-1/sandboxes",
  "/appsec/v2/applications/app-1/findings",
  "/appsec/v2/applications/app-1/findings?page=0&size=500",
  "/appsec/v2/applications/app-1/summary_report",
  "/appsec/v1/policies",
  "/srcclr/v3/workspaces",
  "/srcclr/v3/workspaces/ws-1/issues?type=vulnerability&status=open",
  "/srcclr/v3/workspaces/ws-1/libraries",
  "/srcclr/v3/applications/app-2/projects",
  "/was/configservice/v1/analyses",
  "/was/configservice/v1/analyses/an-1/scans",
  "/was/configservice/v1/scans/scan-1/configuration",
];
/** Quoted non-credential headers (the Codex P1 must-keep rows): a quote alone never makes a header value a credential. */
const VERACODE_QUOTED_HEADERS_KEPT = [
  'Content-Type: "application/json"',
  'Content-Type:"application/json; charset=utf-8"',
  "Accept: 'application/json'",
  'Content-Length: "42"',
  'X-Request-Id: "3f2b6a1e-9c4d-4e8f-b1a2-6d7c8e9f0a1b"',
  'X-Rate-Limit-Remaining: "599"',
  'User-Agent: "grclanker-cli/0.4.1"',
  'Cache-Control: "no-store"',
  'Location: "/appsec/v1/applications"',
  '{"Content-Type": "application/json", "Accept": "application/json"}',
  '{\\"Content-Type\\": \\"application/json\\", \\"Accept\\": \\"application/json\\"}',
];

const VERACODE_MUST_KEEP = {
  path: [...VERACODE_REQUESTED_PATHS, ...VERACODE_REQUESTED_PATHS.map((path) => `GET ${path}`)],
  host: ["https://api.veracode.com", "https://api.veracode.eu", "https://api.veracode.us", "api.veracode.com", "acme-prod.example.gov"],
  name: [
    "us-fed", "prod-us-east-2026", "svc-api", "alice", "alice@example.com", "jane.doe@acme-prod.example.gov", "Payments", "Portal DAST", "Workspace A", "Team A",
    "Security Insights", "Reviewer", "Administrator", "Results API", "Workspace Administrator", "Workspace Editor", "sca_workspaces", "dynamic_analyses", "api_credentials",
    "VERY_HIGH", "FINISHED_RESULTS_AVAILABLE", "PUBLISHED", "MAX_SEVERITY", "policy_compliance_status", "last_completed_scan_date", "ignore_team_restrictions",
    "all_for_org=true", "include_roles=true",
  ],
  status: ["200 OK", "400 Bad Request", "401 Unauthorized", "403 Forbidden", "404 Not Found", "429 Too Many Requests", "500 Internal Server Error", "502 Bad Gateway", "503 Service Unavailable"],
  id: VERACODE_CONTROLS.map((control) => `VERACODE-${String(control.number).padStart(2, "0")}`),
  source: ["arguments-api-key-id", "environment-api-key-secret", "credentials-file-api-key-id (default)", "region-us", "explicit-base-url"],
  code: ["INVALID_INI", "EACCES", "ENOTDIR", "EISDIR", "UNREADABLE"],
  text: ["/home/auditor/.veracode/credentials", "first page only, total unknown"],
};

/** Realistic Veracode summary and error sentences with an identifying value in the slot such a value occupies. */
function veracodeSummarySentences(kind, value) {
  switch (kind) {
    case "path":
      return [
        `Veracode request failed (403 Forbidden) for ${value}: role Security Insights required`,
        `Veracode request failed (403 Forbidden) for ${value}: Insufficient privileges for this operation`,
        `The ${value} endpoint was forbidden (403), so the control could not be verified: Veracode request failed (403 Forbidden) for ${value}`,
        `sandboxes (Payments): Veracode request failed (403 Forbidden) for ${value}`,
        `2026-09-21T12:00:00.000Z api credentials (svc-api): Veracode request failed (403 Forbidden) for ${value}`,
      ];
    case "host":
      return [`Using Veracode API base ${value} (region us, credentials from environment-api-key-id -> environment-api-key-secret -> region-us).`, `Veracode request failed for ${value}/appsec/v1/applications: fetch failed`];
    case "name":
      return [
        `Authenticated as ${value} with roles ${value}, Administrator.`,
        `Only 2 of 6 ${value} were read (1/3 pages), so the verdict reflects a partial inventory.`,
        `Not requested: the ${value} inventory was not readable, so no per-application list was requested.`,
        `sandboxes (${value}): Veracode request failed (403 Forbidden) for /appsec/v1/applications/app-1/sandboxes`,
        `Optional license-gated surfaces not readable: ${value} (their controls will render as manual).`,
        `Grant the API service account the missing roles (${value}) and confirm the region matches the account.`,
      ];
    case "status":
      return [`Veracode request failed (${value}) for /appsec/v1/policies: role Security Insights required`, `Veracode request to /appsec/v1/applications returned an unreadable response (${value}): non-JSON response body (5120 bytes, not recorded)`];
    case "id":
      return [`${value} is manual because the applications endpoint was forbidden (403).`, `| ${value} | HIGH | MANUAL | Policy assignment | The policies endpoint was forbidden (403), so the control could not be verified. |`];
    case "source":
      return [`Using Veracode API base https://api.veracode.com (region us, credentials from ${value} -> region-us).`, `- Credential source: ${value}`];
    case "code":
      return [`Unable to read Veracode credentials file /home/auditor/.veracode/credentials (${value})`, `Unable to parse Veracode credentials file: invalid INI in /home/auditor/.veracode/credentials (${value})`];
    default:
      return [`${value} was reported by veracode_check_access.`];
  }
}

/** Every fixed text the Veracode integration emits, with sample paths and names, passes its scrubber unchanged (GWS note 1). */
const VERACODE_FIXED_TEXTS = [
  "Unable to read Veracode credentials file /home/auditor/.veracode/credentials (EACCES)",
  "Unable to read Veracode credentials file /home/auditor/.veracode/credentials (UNREADABLE)",
  "Unable to parse Veracode credentials file: invalid INI in /home/auditor/.veracode/credentials (INVALID_INI)",
  "Veracode API credentials are required: pass api_key_id and api_key_secret, set VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET, or add veracode_api_key_id and veracode_api_key_secret to the [default] profile in /home/auditor/.veracode/credentials.",
  "The Veracode API key secret must be a hex string; check the credential value.",
  'Unknown Veracode region "mars". Use us, eu, or us-fed.',
  "Veracode request failed (403 Forbidden) for /appsec/v1/policies: role Security Insights required",
  "Veracode request failed (401 Unauthorized) for /api/authn/v2/users/self",
  "Veracode request failed (500 Internal Server Error) for /api/authn/v2/users/self: JSON response body (24 bytes) carried no message field",
  "Veracode request failed (400 Bad Request) for /api/authn/v2/users/self: non-JSON response body (30 bytes, not recorded)",
  "Veracode request to /appsec/v1/applications returned an unreadable response (200 OK): non-JSON response body (5120 bytes, not recorded)",
  "Veracode request failed for /appsec/v1/applications: The operation was aborted due to timeout",
  "all_for_org=true was refused (403), so only teams the API user is a member of were listed and the team inventory is a partial view.",
  "Not requested: the application inventory was not readable, so no sandbox list was requested.",
  "Not requested: the Dynamic Analysis list was not readable, so no scan list or scan configuration was requested.",
  "Not requested: no scan list was readable, so no scan configuration was requested.",
  "Not requested: the application inventory was not readable or empty, so no per-application list was requested.",
  "Not requested: the application inventory was not readable, so no linked project list was requested.",
  "Not requested: the SCA Agent API was not readable, so no linked project list was requested.",
  "Not requested: every sampled application has upload_and_scan_sca_enabled, so no linked project list was requested.",
  "Not requested: the SCA workspace list was not readable, so no workspace issue or library list was requested.",
  "Not requested: the user list was not readable, so no credential record was requested.",
  "Not requested: the user list was empty, so no credential record was requested.",
  "Not requested: the user list carried no active API account, so no credential record was requested.",
  "The applications (Security Insights or Reviewer role) endpoint was forbidden (403), so the control could not be verified: Veracode request failed (403 Forbidden) for /appsec/v1/applications",
  "The users (Administrator role) endpoint returned an error (500), so the control could not be verified: Veracode request failed (500 Internal Server Error) for /api/authn/v2/users",
  "The api_credentials (Administrator role) endpoint could not be read, so the control could not be verified: Veracode request failed for /api/authn/v2/api_credentials/user_id/u-2: The operation was aborted due to timeout",
  "The policies surface was not read.",
  "The Dynamic Analysis API was not available to this credential (403); Dynamic Analysis may be unlicensed or the API user lacks a Dynamic Analysis role, so the control is not applicable through the API.",
  "The SCA Agent API was not available to this credential (404); agent-based SCA may be unlicensed or the API user lacks a Workspace role, so the control is not applicable through the API.",
  "the SCA Agent API workspace list returned an error (403)",
  "the SCA Agent API workspace list could not be read",
  "The application inventory was unreadable, so policy assignment per application was not verified.",
  "The application inventory was unreadable, so application team assignment was not verified.",
  "Only 2 of 6 applications were read (1/3 pages), so the verdict reflects a partial inventory.",
  "Only 2 of an unknown total of applications were read (1/? pages), so the verdict reflects a partial inventory.",
  "Only 10 of 25 API accounts were sampled, so the verdict reflects a partial view.",
  "2 scan configurations were unreadable.",
  "2 application finding lists were unreadable.",
  "3 finding lists were truncated before the last page.",
  "1 workspace license lists were unreadable.",
  "1 of 2 requested linked project lists could not be read (GET /srcclr/v3/applications/app-1/projects returned 403 Forbidden).",
  "2 of 2 requested linked project lists could not be read (GET /srcclr/v3/applications/{guid}/projects returned 403 Forbidden (1) and 500 Internal Server Error (1)).",
  "1 of 1 requested linked project lists could not be read (the requests returned no status).",
  "No application could be evaluated for SCA coverage: every linked project list requested was unreadable (2 of 2; GET /srcclr/v3/applications/{guid}/projects returned 403 Forbidden). Manual evidence required: Map each application to an SCA workspace.",
  "1 of 2 sampled applications have upload-and-scan SCA enabled or a linked SCA agent project (linked_projects from the SCA Agent API).",
  "2 credential records were unreadable.",
  "The policies endpoint returned zero policies, which cannot be a complete inventory because every Veracode account exposes the built-in policies; the empty list is treated as unverifiable rather than compliant.",
  "The users endpoint returned zero users, which cannot be a complete inventory because the API credential belongs to a user; the empty list is treated as unverifiable rather than compliant.",
  "The roles endpoint returned zero roles, which cannot be a complete inventory because Veracode ships built-in roles; the empty list is treated as unverifiable rather than compliant.",
  "No active API service accounts were returned even though this request is authenticated with API credentials, so the credential inventory is unverifiable.",
  "No active API service account was among the users read, so the credential inventory is unread rather than empty; read the full user list before judging it. Only 1 of 2 users were read (1/3 pages), so the verdict reflects a partial inventory.",
  "No Dynamic Analysis configurations exist, so there is no DAST configuration to evaluate; the empty inventory is treated as not applicable rather than compliant.",
  "No Dynamic Analysis scan configuration could be read, so authentication and crawl settings are unknown.",
  "No open vulnerability issues were returned, but no libraries were readable in the sampled workspaces, so it is unknown whether any scan has populated them.",
  "sandboxes (Payments): Veracode request failed (403 Forbidden) for /appsec/v1/applications/app-1/sandboxes",
  "api credentials (svc-api): Veracode request failed (403 Forbidden) for /api/authn/v2/api_credentials/user_id/u-2",
  "dynamic scan configuration scan-1: Veracode request failed (403 Forbidden) for /was/configservice/v1/scans/scan-1/configuration",
  "sca workspaces: Veracode request failed (403 Forbidden) for /srcclr/v3/workspaces",
  "self: Veracode request failed (401 Unauthorized) for /api/authn/v2/users/self",
  "Using Veracode API base https://api.veracode.com (region us, credentials from environment-api-key-id -> environment-api-key-secret -> region-us).",
  "Authenticated as svc-api with roles Results API, Administrator.",
  "The principal could not be read from /api/authn/v2/users/self.",
  "5/7 core audit surfaces are readable.",
  "Optional license-gated surfaces not readable: sca_workspaces, dynamic_analyses (their controls will render as manual).",
  "Run veracode_assess_scan_coverage, veracode_assess_policy_compliance, veracode_assess_findings_hygiene, veracode_assess_sca_posture, veracode_assess_access_controls, or veracode_export_audit_bundle.",
  "Grant the API service account the missing roles (Security Insights or Reviewer, Administrator) and confirm the region matches the account.",
  "first page only, total unknown",
];

const VERACODE_SOURCE_URL = new URL("../extensions/grc-tools/veracode.ts", import.meta.url);

/**
 * The static segments of every `new Error(...)` template inside the named top-level functions of
 * the integration source, so a reworded or added resolver message fails the fixed-text test until a
 * fixed text or a live rendering covers it.
 */
function errorTemplateSegments(sourceUrl, functionNames) {
  const source = readFileSync(sourceUrl, "utf8");
  const segments = [];
  for (const name of functionNames) {
    const start = source.search(new RegExp(`^(?:export )?(?:async )?function ${name}\\(`, "m"));
    assert.notEqual(start, -1, `${name} is a top-level function of the integration source`);
    const body = source.slice(start, source.indexOf("\n}\n", start) + 2);
    for (const match of body.matchAll(/new Error\(/g)) {
      let depth = 1;
      let end = match.index + match[0].length;
      while (depth > 0 && end < body.length) {
        if (body[end] === "(") depth += 1;
        else if (body[end] === ")") depth -= 1;
        end += 1;
      }
      const argument = body.slice(match.index + match[0].length, end - 1);
      for (const literal of argument.matchAll(/"((?:[^"\\]|\\.)*)"/g)) segments.push(literal[1].replace(/\\"/g, '"'));
      for (const template of argument.matchAll(/`((?:[^`\\]|\\.)*)`/g)) segments.push(...template[1].split(/\$\{(?:[^{}]|\{[^{}]*\})*\}/));
    }
  }
  return [...new Set(segments.map((segment) => segment.trim()).filter((segment) => segment.length >= 8))];
}

/**
 * The resolver messages rendered live for the no credentials, partial credentials, bad credential
 * shape, and credentials file failure cases, each against a real temp path; the malformed profile
 * and the rejected secret carry config canaries so the messages prove they hold no credential value.
 */
function liveVeracodeResolverMessages() {
  const home = createTempBase("grclanker-veracode-live-resolver-");
  const defaultCredentials = join(home, ".veracode", "credentials");
  const directoryCredentials = join(home, "directory-credentials");
  mkdirSync(directoryCredentials);
  const malformedCredentials = join(home, "malformed-credentials");
  writeFileSync(malformedCredentials, `[default]\nveracode_api_key_id ${CONFIG_CANARIES.bareLine}\n[unterminated ${CONFIG_CANARIES.unterminatedSection}\nveracode_api_key_secret = aabb\n`);
  const resolve = (input, env) => thrownBy(() => resolveVeracodeConfiguration(input, env, { homeDir: home })).message;
  return {
    paths: { defaultCredentials, directoryCredentials, malformedCredentials },
    messages: {
      "no credentials": resolve({}, {}),
      "partial credentials: key ID without a secret": resolve({}, { VERACODE_API_KEY_ID: API_ID }),
      "partial credentials: a named profile without a secret": resolve({ profile: "audit" }, { VERACODE_API_KEY_ID: API_ID }),
      "bad credential shape: a secret that is not hex": resolve({}, { VERACODE_API_KEY_ID: API_ID, VERACODE_API_KEY_SECRET: CONFIG_CANARIES.readable }),
      "credentials file failure: directory at the path": resolve({ credentials_file: directoryCredentials }, {}),
      "credentials file failure: malformed profile": resolve({ credentials_file: malformedCredentials }, {}),
    },
  };
}

test("rule 9: every fixed text the Veracode integration emits, including the live resolver messages, passes its scrubber unchanged", () => {
  const live = liveVeracodeResolverMessages();
  const credentialsRequired = (profile, path) => `Veracode API credentials are required: pass api_key_id and api_key_secret, set VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET, or add veracode_api_key_id and veracode_api_key_secret to the [${profile}] profile in ${path}.`;
  const expected = {
    "no credentials": credentialsRequired("default", live.paths.defaultCredentials),
    "partial credentials: key ID without a secret": credentialsRequired("default", live.paths.defaultCredentials),
    "partial credentials: a named profile without a secret": credentialsRequired("audit", live.paths.defaultCredentials),
    "bad credential shape: a secret that is not hex": "The Veracode API key secret must be a hex string; check the credential value.",
    "credentials file failure: directory at the path": `Unable to read Veracode credentials file ${live.paths.directoryCredentials} (EISDIR)`,
    "credentials file failure: malformed profile": credentialsRequired("default", live.paths.malformedCredentials),
  };
  assert.deepEqual(Object.keys(live.messages), Object.keys(expected));
  for (const [label, message] of Object.entries(live.messages)) {
    assert.equal(message, expected[label], label);
    for (const canary of Object.values(CONFIG_CANARIES)) assertNoWindowOf(message, canary, `live resolver message (${label})`);
    for (const wording of LIBRARY_ERROR_WORDING) assert.ok(!message.includes(wording), `${label} repeats library wording "${wording}": ${message}`);
    assert.equal(scrubErrorText(message), message, `live resolver message survives the scrubber (${label})`);
    assert.equal(scrubErrorText(message, [API_ID, API_SECRET]), message, `live resolver message survives with the configured credentials registered (${label})`);
  }

  // Every message template the resolver and its loaders can throw is pinned by a fixed text or a live rendering, so a reworded message fails here until the set is updated.
  const corpus = [...VERACODE_FIXED_TEXTS, ...Object.values(live.messages)];
  const segments = errorTemplateSegments(VERACODE_SOURCE_URL, ["resolveVeracodeConfiguration", "readCredentialsFileText", "readCredentialsProfile"]);
  assert.ok(segments.length >= 6, `the template scan found the two resolver messages and the two loader messages (${segments.length})`);
  for (const segment of segments) assert.ok(corpus.some((text) => text.includes(segment)), `resolver template segment is pinned by a fixed text or a live rendering: ${segment}`);

  for (const text of VERACODE_FIXED_TEXTS) assert.equal(scrubErrorText(text), text, text);
  for (const text of VERACODE_FIXED_TEXTS) assert.equal(scrubErrorText(text, [API_ID, API_SECRET]), text, `${text} (with the configured credentials registered)`);
});

test("resolveVeracodeConfiguration keeps environment credentials when an unrelated argument is passed (GWS note 2)", () => {
  const home = createTempBase("grclanker-veracode-env-args-");
  const credentialsFile = join(home, "credentials");
  writeFileSync(credentialsFile, "[default]\nveracode_api_key_id = file-id\nveracode_api_key_secret = abcdef\n");
  const env = { VERACODE_API_KEY_ID: API_ID, VERACODE_API_KEY_SECRET: API_SECRET, VERACODE_API_CREDENTIALS_FILE: credentialsFile, VERACODE_REGION: "eu" };

  const resolved = resolveVeracodeConfiguration({ timeout_seconds: 9 }, env, { homeDir: home });
  assert.equal(resolved.apiKeyId, API_ID, "the environment key ID survives an argument overlay that names no credential");
  assert.equal(resolved.apiKeySecret, API_SECRET);
  assert.equal(resolved.baseUrl, "https://api.veracode.eu");
  assert.equal(resolved.timeoutMs, 9000);
  assert.deepEqual(resolved.sourceChain, ["environment-api-key-id", "environment-api-key-secret", "region-eu"]);

  const withUndefinedArguments = resolveVeracodeConfiguration({ api_key_id: undefined, api_key_secret: undefined, region: undefined }, env, { homeDir: home });
  assert.equal(withUndefinedArguments.apiKeyId, API_ID, "an argument overlay whose credential keys are undefined does not shadow the environment");
  assert.equal(withUndefinedArguments.apiKeySecret, API_SECRET);
  assert.deepEqual(withUndefinedArguments.sourceChain, ["environment-api-key-id", "environment-api-key-secret", "region-eu"]);

  const fileOnly = resolveVeracodeConfiguration({ timeout_seconds: 9 }, { VERACODE_API_CREDENTIALS_FILE: credentialsFile }, { homeDir: home });
  assert.equal(fileOnly.apiKeyId, "file-id", "the credentials file named through the environment still supplies the credential");
  assert.deepEqual(fileOnly.sourceChain, ["credentials-file-api-key-id (default)", "credentials-file-api-key-secret (default)", "region-us"]);
});

/** A 32-character random run: any 6 to 24 character window of it in an output is a leak. */
const PLANTED_TOKEN = "Xq7Vw2Lm9Tp4Rb8Kd3Fh6Jn1Zs5Yc0Ag";
/** A Stripe-shaped live key: the vendor prefix makes it an unambiguous credential shape on both sides. */
const PLANTED_STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
/** The distinctive segments of the planted JWT; the header is the common RS256 prefix and is not a canary. */
const PLANTED_JWT_PAYLOAD = "Zm9vYmFyLXByb2JlLXBheWxvYWQtOTgxMjM0NTY3ODkw";
const PLANTED_JWT_SIGNATURE = "c2lnbmF0dXJlLXBhcnQtb2YtdGhlLWpvdC1nb2VzLWhlcmU";
const PLANTED_JWT = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.${PLANTED_JWT_PAYLOAD}.${PLANTED_JWT_SIGNATURE}`;
const PLANTED_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----";
const PLANTED_CANARIES = [PLANTED_TOKEN, PLANTED_STRIPE_KEY, PLANTED_JWT_PAYLOAD, PLANTED_JWT_SIGNATURE];
const BEARER_ID_UUID = "6f1c2b3a-4d5e-4f60-8a9b-0c1d2e3f4a5b";
/** The free-text note planted in the export probe: two unambiguous shapes, a header carrier, and an identifier that must survive. */
const PLANTED_NOTE = `Runbook: key ${PLANTED_STRIPE_KEY} end; bearer ${PLANTED_JWT}; Authorization: Bearer ${PLANTED_TOKEN}; cluster prod-us-east-2026-cluster was read`;
const REDACTED_NOTE = "Runbook: key [REDACTED] end; bearer [REDACTED]; Authorization: Bearer [REDACTED]; cluster prod-us-east-2026-cluster was read";

/**
 * Scheme-word order (CodeRabbit r4078025849): a credential-named key loses its value before any
 * scheme word is read, so "VERACODE_API_KEY_SECRET=VERACODE-HMAC-SHA-256 rejected" is a secret whose
 * value starts with a scheme name, not an HMAC header. Scheme words act under Authorization-style
 * keys and bare in prose; auth-params and prose mentions of a scheme stay.
 */
const SCHEME_ORDER_ROWS = [
  ["sslPassword=splunk rejected", "sslPassword=[REDACTED] rejected"],
  ["db_password: token", "db_password: [REDACTED]"],
  ['sslPassword="splunk rejected"', 'sslPassword="[REDACTED]"'],
  ['"db_password": "token"', '"db_password": "[REDACTED]"'],
  ["SPLUNK_PASSWORD=bearer expired", "SPLUNK_PASSWORD=[REDACTED] expired"],
  ["VERACODE_API_KEY_SECRET=VERACODE-HMAC-SHA-256 rejected", "VERACODE_API_KEY_SECRET=[REDACTED] rejected"],
  ["VERACODE_API_KEY_SECRET: VERACODE-HMAC-SHA-256 rejected", "VERACODE_API_KEY_SECRET: [REDACTED] rejected"],
  ['VERACODE_API_KEY_SECRET="VERACODE-HMAC-SHA-256 rejected"', 'VERACODE_API_KEY_SECRET="[REDACTED]"'],
  ['"VERACODE_API_KEY_SECRET": "VERACODE-HMAC-SHA-256"', '"VERACODE_API_KEY_SECRET": "[REDACTED]"'],
  [`Authorization: VERACODE-HMAC-SHA-256 ${PLANTED_TOKEN}`, "Authorization: VERACODE-HMAC-SHA-256 [REDACTED]"],
  ["Authorization: Splunk 4eC39HqLyjWDarjtT1zdp7dc", "Authorization: Splunk [REDACTED]"],
  [`Proxy-Authorization: Basic ${PLANTED_TOKEN}==`, "Proxy-Authorization: Basic [REDACTED]"],
  [`Authorization: bearer ${PLANTED_TOKEN}`, "Authorization: bearer [REDACTED]"],
  [`Authorization: sNoWfLaKe ${PLANTED_TOKEN}`, "Authorization: sNoWfLaKe [REDACTED]"],
  ["Authorization: SSWS prod-us-east-2026", "Authorization: SSWS [REDACTED]"],
  [`replayed BASIC ${PLANTED_TOKEN} upstream`, "replayed BASIC [REDACTED] upstream"],
  [`replayed splunk ${PLANTED_TOKEN} upstream`, "replayed splunk [REDACTED] upstream"],
  ["Bearer abcdefghijkl rejected", "Bearer [REDACTED] rejected"],
  ['WWW-Authenticate: Bearer realm="api"', 'WWW-Authenticate: Bearer realm="api"'],
  ['Bearer realm="api", error="invalid_token"', 'Bearer realm="api", error="invalid_token"'],
  ["Snowflake statement failed", "Snowflake statement failed"],
  ["Splunk Enterprise rejected the request", "Splunk Enterprise rejected the request"],
  ["the bearer presented an expired token", "the bearer presented an expired token"],
  ["Basic authentication failed", "Basic authentication failed"],
  ["OAuth 2.0 introspection", "OAuth 2.0 introspection"],
  ["token_type=Bearer", "token_type=Bearer"],
];

/** The key audit: bearer ids go whatever their shape, setting suffixes and URL-valued webhook keys keep their values, identifiers are judged by shape. */
const KEY_AUDIT_ROWS = [
  [`token_id=${BEARER_ID_UUID}`, "token_id=[REDACTED]"],
  [`tokenId: ${BEARER_ID_UUID}`, "tokenId: [REDACTED]"],
  [`role_secret_id=${BEARER_ID_UUID}`, "role_secret_id=[REDACTED]"],
  ["secret_id_ttl=3600 secret_id_num_uses=5 token_max_ttl=7200 token_bound_cidrs=10.0.0.0/8", "secret_id_ttl=3600 secret_id_num_uses=5 token_max_ttl=7200 token_bound_cidrs=10.0.0.0/8"],
  [`secret_id_accessor=${BEARER_ID_UUID}`, `secret_id_accessor=${BEARER_ID_UUID}`],
  ["webhook_count=3", "webhook_count=3"],
  [`webhook_url=https://hooks.example.com/services/T/B/${PLANTED_TOKEN}?ts=1`, "webhook_url=https://hooks.example.com/[REDACTED]"],
  [`client_id=svc-audit-2026 tenant_id=${BEARER_ID_UUID}`, `client_id=svc-audit-2026 tenant_id=${BEARER_ID_UUID}`],
  ["access_key_id=svc-audit-2026 key_id=kid-primary private_key_id=kid-primary secret_name=db-credentials-prod", "access_key_id=svc-audit-2026 key_id=kid-primary private_key_id=kid-primary secret_name=db-credentials-prod"],
  [`token_type=${PLANTED_TOKEN}`, "token_type=[REDACTED]"],
];

/** Flag, path-label, slash-escaped URL, and cookie carriers: the value goes and the prose around it stays. */
const CARRIER_ROWS = [
  [`psql --password ${PLANTED_TOKEN} -h db`, "psql --password [REDACTED] -h db"],
  [`mysql --password=${PLANTED_TOKEN} -h db`, "mysql --password=[REDACTED] -h db"],
  [`java -Dspring.datasource.password=${PLANTED_TOKEN} -jar app.jar`, "java -Dspring.datasource.password=[REDACTED] -jar app.jar"],
  [`helm --set db.password=${PLANTED_TOKEN} upgrade`, "helm --set db.password=[REDACTED] upgrade"],
  [`kv/password: ${PLANTED_TOKEN}`, "kv/password: [REDACTED]"],
  ["/oauth/token-request: invalid_client", "/oauth/token-request: invalid_client"],
  ["/api/v1/api-tokens: request failed with 403", "/api/v1/api-tokens: request failed with 403"],
  [`kv/password: ${PLANTED_TOKEN} [code 003001, sqlState 42501]`, "kv/password: [REDACTED] [code 003001, sqlState 42501]"],
  [`kv/password: ${PLANTED_TOKEN} (requestId abc-123)`, "kv/password: [REDACTED] (requestId abc-123)"],
  ["config/prod/password: hunter2 was echoed by the proxy", "config/prod/password: [REDACTED] was echoed by the proxy"],
  [`secrets/data/api_key: ${PLANTED_TOKEN}, then retried`, "secrets/data/api_key: [REDACTED], then retried"],
  ["/api/v1/secrets: request failed with 403", "/api/v1/secrets: request failed with 403"],
  ["/v1/auth/approle/passwords: listing denied", "/v1/auth/approle/passwords: listing denied"],
  [`/api_key=${PLANTED_TOKEN}`, "/api_key=[REDACTED]"],
  [`SPLUNK_ACS_TOKEN='${PLANTED_TOKEN}'`, "SPLUNK_ACS_TOKEN='[REDACTED]'"],
  [`httpEventCollectorToken="${PLANTED_TOKEN}"`, 'httpEventCollectorToken="[REDACTED]"'],
  [`X-Api-Key: "${PLANTED_TOKEN}"`, 'X-Api-Key: "[REDACTED]"'],
  [`note https:\\/\\/hooks.example.com\\/a?token=${PLANTED_TOKEN} next`, "note https:\\/\\/hooks.example.com\\/a?[REDACTED] next"],
  [`Cookie: theme=dark; my'pref=${PLANTED_TOKEN}`, "Cookie: [REDACTED]"],
  [`Cookie: sid=O'${PLANTED_TOKEN}; X-Api-Key: ${PLANTED_TOKEN}`, "Cookie: [REDACTED]; X-Api-Key: [REDACTED]"],
  [`Cookie: my&sid=${PLANTED_TOKEN}; Content-Type: application/json`, "Cookie: [REDACTED]; Content-Type: application/json"],
];

/** The data side: unambiguous shapes and carriers go, identifiers and bare runs survive (the generic long-run rule is off there). */
const DATA_SIDE_ROWS = [
  [`key ${PLANTED_STRIPE_KEY} end`, "key [REDACTED] end"],
  [`note ${PLANTED_JWT} end`, "note [REDACTED] end"],
  [`Authorization: Bearer ${PLANTED_TOKEN}`, "Authorization: Bearer [REDACTED]"],
  [`pem ${PLANTED_PEM} end`, "pem [REDACTED] end"],
  ["xoxb-1234567890-abcdefghijklmnop", "[REDACTED]"],
  ["AKIAIOSFODNN7EXAMPLE", "[REDACTED]"],
  ["ghp_16C7e42F292c6912E7710c838347Ae178B4a", "[REDACTED]"],
  ["cluster prod-us-east-2026-cluster was read", "cluster prod-us-east-2026-cluster was read"],
  [`run ${PLANTED_TOKEN} end`, `run ${PLANTED_TOKEN} end`],
];

function assertRows(scrub, rows, label) {
  for (const [input, expected] of rows) {
    const scrubbed = scrub(input);
    assert.equal(scrubbed, expected, `${label}: ${input}`);
    assert.equal(scrub(scrubbed), scrubbed, `${label}, second pass: ${input}`);
    for (const canary of PLANTED_CANARIES) {
      if (input.includes(canary) && !expected.includes(canary)) assertNoWindowOf(scrubbed, canary, `${label}: ${input}`);
    }
  }
}

test("reviewer C final verdict, scheme-word order (r4078025849) and the key audit: a credential-named key loses its value before any scheme word is read in both spellings, scheme words act only under Authorization-style keys and bare in prose, bearer ids go, setting suffixes and URL-valued webhook keys keep their values, and the flag, path, escaped-URL, and cookie carriers are read", () => {
  assertRows(scrubErrorText, SCHEME_ORDER_ROWS, "scheme-word order");
  assertRows(scrubErrorText, KEY_AUDIT_ROWS, "key audit");
  assertRows(scrubErrorText, CARRIER_ROWS, "carrier");
  assert.equal(scrubErrorText(`run ${PLANTED_TOKEN} end`), "run [REDACTED] end", "the error side keeps the generic long-run rule");
});

test("data-side ruling: vendor-prefixed tokens, JWTs, PEM blocks, and credential carriers are removed on the data side while identifiers and bare runs survive, in scrubDataText, in redactSnapshot, and in the exported Veracode bundle", async () => {
  assertRows(scrubDataText, DATA_SIDE_ROWS, "data side");

  const record = {
    id: "rec-1",
    description: `note: key ${PLANTED_STRIPE_KEY} end`,
    tags: [{ notes: [`also ${PLANTED_JWT}`] }],
    webhook_url: `https://hooks.example.com/services/T/B/${PLANTED_TOKEN}?ts=1`,
    password: PLANTED_TOKEN,
    name: "benign",
    count: 3,
    enabled: true,
    empty: null,
  };
  const walked = redactSnapshot(record);
  assert.deepEqual(walked, {
    id: "rec-1",
    description: "note: key [REDACTED] end",
    tags: [{ notes: ["also [REDACTED]"] }],
    webhook_url: "https://hooks.example.com/[REDACTED]",
    password: "[REDACTED]",
    name: "benign",
    count: 3,
    enabled: true,
    empty: null,
  }, "the walker reaches every string leaf and keeps the origin of a webhook URL");
  assert.deepEqual(redactSnapshot(walked), walked, "second pass over the walked record");

  const fixture = healthyFixture();
  fixture.applications[0].profile.description = PLANTED_NOTE;
  assertFixtureFreeOfCanaryWindows(`${JSON.stringify(fixture)} ${JSON.stringify(sampleConfig())} ${NOW.toISOString()}`, PLANTED_CANARIES, "data-side probe fixture");
  const secrets = leakWindows(PLANTED_CANARIES);
  const client = mockClient(fixture);
  const base = createTempBase("grclanker-veracode-data-side-");
  const result = await exportVeracodeAuditBundle(client, sampleConfig(), base, { now: NOW });
  const files = readBundleFiles(result.outputDir);
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  assertSecretsAbsent(assert, readZipEntries(result.zipPath), secrets, "zip archive");
  assertSecretsAbsent(assert, new Map([["assess results and access check", JSON.stringify([await runAllAssessments(client), await checkVeracodeAccess(client)])]]), secrets, "tool payloads");
  const scanCoverage = JSON.parse(files.get("core_data/scan-coverage.json"));
  assert.equal(scanCoverage.applications.items[0].profile.description, REDACTED_NOTE, "the application description keeps its prose and the cluster name around the removed shapes");
});
